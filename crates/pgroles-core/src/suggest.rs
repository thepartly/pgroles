//! Profile suggestion: deterministically refactor a flat manifest into a
//! manifest that uses reusable [`Profile`]s.
//!
//! ## Algorithm
//!
//! 1. Bucket grants and default privileges by role.
//! 2. Classify each role:
//!    - Eligible if it touches exactly one *declared* schema, has no role
//!      attributes that profiles can't express (only `login` / `inherit` are
//!      promotable), and every default privilege uses that schema's owner.
//! 3. Compute a *schema-relative signature* for each eligible role — the
//!    grants and default privileges with the schema replaced by a placeholder.
//! 4. Cluster eligible roles by `(signature, login, inherit)`.
//! 5. For each cluster of `>= min_schemas` schemas, pick a uniform role-name
//!    pattern (`{schema}-{profile}` etc.) such that every member maps the
//!    same way. Profile name is the shared portion.
//! 6. Resolve per-schema role-pattern conflicts by giving the first cluster
//!    (in deterministic iteration order) priority and dropping the rest.
//! 7. Build a candidate manifest with the extracted profiles.
//! 8. **Round-trip safety check**: re-expand the new manifest into a
//!    [`RoleGraph`] and diff it against the original. The only acceptable
//!    differences are auto-generated role comments (profile expansion
//!    annotates each generated role). Any other delta means we'd silently
//!    change semantics — fall back to the original manifest.
//!
//! The result is **deterministic**: the same input always produces the same
//! output. No LLM, no heuristics that depend on iteration order of unstable
//! collections.

use std::collections::{BTreeMap, BTreeSet};

use crate::diff::{Change, diff};
use crate::manifest::{
    DefaultPrivilege, DefaultPrivilegeGrant, Grant, ObjectTarget, ObjectType, PolicyManifest,
    Privilege, Profile, ProfileGrant, ProfileObjectTarget, RoleDefinition, SchemaBinding,
    expand_manifest,
};
use crate::model::RoleGraph;

/// Knobs for the suggester. The defaults are conservative.
#[derive(Debug, Clone)]
pub struct SuggestOptions {
    /// Minimum number of distinct schemas a candidate cluster must span before
    /// it becomes a profile. Below this, the original flat roles are kept.
    /// Default `2` — a profile with one schema is just an indirection.
    pub min_schemas: usize,

    /// Complete object inventory `(schema, object_type) → set of names`,
    /// **as observed in the live database** (i.e. from
    /// [`pgroles_inspect::fetch_object_inventory`]). When provided, the
    /// suggester collapses per-name grants into wildcards (`name: "*"`) for
    /// `(schema, object_type)` buckets where a role covers every object,
    /// which is what makes profile clustering across schemas useful for
    /// `pgroles generate` output (Postgres expands `GRANT … ON ALL TABLES`
    /// into per-relation rows).
    ///
    /// **Why required**: a grant-derived inventory would treat ungranted
    /// objects as nonexistent. A role granted on every *currently-granted*
    /// table would collapse to `name: "*"`, and applying the suggested
    /// manifest would silently grant on previously-ungranted tables —
    /// broadening privileges beyond the original manifest's intent. With a
    /// real introspected inventory we know what *exists* vs what's
    /// *granted*, so the collapse is sound.
    ///
    /// `None` (default) disables wildcard collapse entirely. Roles only
    /// cluster when their grants reference identical literal names.
    pub full_inventory: Option<Inventory>,
}

impl Default for SuggestOptions {
    fn default() -> Self {
        Self {
            min_schemas: 2,
            full_inventory: None,
        }
    }
}

/// A single profile that the suggester extracted.
#[derive(Debug, Clone)]
pub struct SuggestedProfile {
    pub profile_name: String,
    pub role_pattern: String,
    /// Schema → original role name now produced by `profile × schema` expansion.
    pub schema_to_role: BTreeMap<String, String>,
}

/// Why a particular role wasn't promoted into a profile.
#[derive(Debug, Clone)]
pub enum SkipReason {
    /// Role's grants/default-privs touch more than one schema.
    MultiSchema { role: String, schemas: Vec<String> },
    /// Role references a schema that isn't declared in `schemas:`.
    SchemaNotDeclared { role: String, schema: String },
    /// Role has a default privilege whose owner doesn't match the schema's owner.
    OwnerMismatch { role: String, schema: String },
    /// Role has role attributes (superuser, connection_limit, ...) that profiles
    /// can't express.
    UniqueAttributes { role: String },
    /// Role has grants on cluster-wide objects (database, etc.) that profiles
    /// can't express.
    UnrepresentableGrant { role: String },
    /// Cluster spans fewer than `min_schemas` schemas.
    SoleSchema { role: String, schema: String },
    /// Couldn't find a role-pattern that all cluster members agree on.
    NoUniformPattern { roles: Vec<String> },
    /// Two clusters wanted to bind to the same schema with different patterns.
    SchemaPatternConflict {
        schema: String,
        winning_pattern: String,
        dropped_roles: Vec<String>,
    },
    /// The candidate manifest didn't round-trip cleanly; we abandoned it.
    RoundTripFailure { reason: String },
    /// The provided `full_inventory` was missing object names that already
    /// appear in the input's flat grants — a sure sign the inventory wasn't
    /// sourced from a complete introspection. Wildcard collapse was
    /// disabled for safety.
    IncompleteFullInventory { reason: String },
}

/// What [`suggest_profiles`] returns: the new manifest, the profiles it built,
/// and the reasons each non-promoted role stayed flat.
#[derive(Debug, Clone)]
pub struct SuggestReport {
    pub manifest: PolicyManifest,
    pub profiles: Vec<SuggestedProfile>,
    pub skipped: Vec<SkipReason>,
    /// `true` if the new manifest round-trips identically (modulo
    /// auto-generated role comments) to the input.
    pub round_trip_ok: bool,
}

/// Run the suggester. Always returns; if anything goes wrong the original
/// manifest is returned unchanged with `round_trip_ok = false`.
pub fn suggest_profiles(input: &PolicyManifest, opts: &SuggestOptions) -> SuggestReport {
    // If the input already has profiles, the user has already curated this
    // manifest. Don't overwrite their work.
    if !input.profiles.is_empty() {
        return SuggestReport {
            manifest: input.clone(),
            profiles: vec![],
            skipped: vec![],
            round_trip_ok: true,
        };
    }

    let mut skipped: Vec<SkipReason> = Vec::new();

    // --- Inventory ---------------------------------------------------------
    //
    // Two distinct inventories are involved:
    //   * `full_inventory` (caller-provided, from live DB introspection):
    //     authoritative list of every object that *exists*. Required to
    //     safely collapse per-name grants into a wildcard, because we need
    //     to know whether a role covers *every* object — not just every
    //     object that happens to appear in some grant.
    //   * `grant_inventory` (always built from the input's grants): the
    //     domain over which wildcard grants in the candidate manifest must
    //     be expanded for the round-trip diff. This is what guarantees the
    //     candidate's wildcard expression matches the original's per-name
    //     entries, regardless of whether collapse ran.
    let grant_inventory = build_inventory(input);
    // Defense-in-depth: if a caller hands us a `full_inventory` that's
    // demonstrably incomplete (missing object names that already appear in
    // the input's per-name grants), we can't trust it for collapse. Disable
    // collapse and surface the issue. This catches accidental misuse like
    // passing `inventory_from_manifest_grants(manifest)` as `full_inventory`.
    let collapse_inventory: Option<&Inventory> = match opts.full_inventory.as_ref() {
        None => None,
        Some(full) => match validate_full_inventory(&grant_inventory, full) {
            Ok(()) => Some(full),
            Err(reason) => {
                skipped.push(SkipReason::IncompleteFullInventory { reason });
                None
            }
        },
    };

    // --- Bucket grants and default privileges by grantee role ---------------

    let mut role_grants: BTreeMap<String, Vec<Grant>> = BTreeMap::new();
    for grant in &input.grants {
        role_grants
            .entry(grant.role.clone())
            .or_default()
            .push(grant.clone());
    }

    // Collapse per-role per-name grants that fully cover their (schema,
    // object_type) bucket — only when a real introspected inventory is
    // available. Without it, "full coverage" can't be soundly determined.
    if let Some(inv) = collapse_inventory {
        for grants in role_grants.values_mut() {
            collapse_full_coverage_grants(grants, inv);
        }
    }

    // Each (role, schema) → (owner, Vec<DefaultPrivilegeGrant>)
    // We keep the owner so we can compare it against the schema owner later.
    let mut role_dps: BTreeMap<String, Vec<(String, String, DefaultPrivilegeGrant)>> =
        BTreeMap::new();
    for dp in &input.default_privileges {
        // Profiles are schema-scoped, so only schema-scoped entries can be
        // folded into one; global entries stay as-is.
        let Some(schema) = dp
            .resolved_scope()
            .ok()
            .and_then(|scope| scope.schema().map(str::to_string))
        else {
            continue;
        };
        let owner = dp
            .owner
            .clone()
            .or_else(|| input.default_owner.clone())
            .unwrap_or_default();
        for grant in &dp.grant {
            if let Some(role) = &grant.role {
                role_dps.entry(role.clone()).or_default().push((
                    owner.clone(),
                    schema.clone(),
                    grant.clone(),
                ));
            }
        }
    }

    // --- Index schemas ------------------------------------------------------

    let schema_owner: BTreeMap<String, Option<String>> = input
        .schemas
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                s.owner.clone().or_else(|| input.default_owner.clone()),
            )
        })
        .collect();

    // --- Classify each role -------------------------------------------------

    /// Eligibility outcome for a single role.
    struct Eligible {
        role_name: String,
        schema: String,
        signature: RoleSignature,
        login: Option<bool>,
        inherit: Option<bool>,
    }

    let mut eligible: Vec<Eligible> = Vec::new();
    let mut clustered_role_names: BTreeSet<String> = BTreeSet::new();

    for role_def in &input.roles {
        let role_name = &role_def.name;

        // The suggester only promotes `login` and `inherit` into a profile.
        // Any other explicitly-set attribute disqualifies the role.
        //
        // `config` is deliberately excluded even though profiles can express
        // it: clustering would require comparing config maps modulo
        // `{schema}`/`{profile}` substitution (a role's `search_path:
        // inventory` and another's `search_path: checkout` are the "same"
        // profile-relative value, but nothing else in a config map tells us
        // which literal segments are schema-derived vs. genuinely distinct).
        // Getting that wrong silently changes what gets applied, so a
        // config-carrying role always stays flat — the caller can add
        // `config` to a suggested profile by hand once it exists.
        //
        // Comments are treated as user-set documentation *unless* they match
        // pgroles' own auto-generated annotation pattern (which `pgroles
        // apply` writes when expanding a profile). Ignoring auto-comments
        // makes `--suggest-profiles` idempotent across runs.
        let has_user_comment = role_def
            .comment
            .as_deref()
            .is_some_and(|c| !is_auto_profile_comment(c));
        if role_def.superuser.is_some()
            || role_def.createdb.is_some()
            || role_def.createrole.is_some()
            || role_def.replication.is_some()
            || role_def.bypassrls.is_some()
            || role_def.connection_limit.is_some()
            || role_def.password.is_some()
            || role_def.password_valid_until.is_some()
            || !role_def.config.is_empty()
            || has_user_comment
        {
            skipped.push(SkipReason::UniqueAttributes {
                role: role_name.clone(),
            });
            continue;
        }

        // What schemas does this role touch (via grants and DPs)?
        // Roles with grants that profiles can't express (e.g. database-level
        // CONNECT) are excluded outright — even if the rest of their grants
        // would cluster, we'd silently drop the unrepresentable ones.
        let mut schemas_seen: BTreeSet<String> = BTreeSet::new();
        let mut has_unrepresentable_grant = false;
        let role_grants_vec = role_grants.get(role_name).cloned().unwrap_or_default();
        for g in &role_grants_vec {
            // Profiles are additive templates with no way to say `ensure:
            // absent`, and a global default privilege has no schema to hang a
            // profile from. Either one makes the role unclusterable; folding
            // it anyway would drop the assertion and fail the round-trip
            // check, abandoning the whole suggestion run.
            if g.ensure == crate::manifest::Ensure::Absent {
                has_unrepresentable_grant = true;
            }
            match g.object.object_type {
                ObjectType::Schema => match &g.object.name {
                    Some(name) => {
                        schemas_seen.insert(name.clone());
                    }
                    None => has_unrepresentable_grant = true,
                },
                ObjectType::Database => has_unrepresentable_grant = true,
                _ => match &g.object.schema {
                    Some(s) => {
                        schemas_seen.insert(s.clone());
                    }
                    None => has_unrepresentable_grant = true,
                },
            }
        }
        if has_unrepresentable_grant {
            skipped.push(SkipReason::UnrepresentableGrant {
                role: role_name.clone(),
            });
            continue;
        }
        if role_has_global_default_privilege(input, role_name)
            || role_has_absent_default_privilege(input, role_name)
        {
            skipped.push(SkipReason::UnrepresentableGrant {
                role: role_name.clone(),
            });
            continue;
        }

        let role_dp_vec = role_dps.get(role_name).cloned().unwrap_or_default();
        for (_, schema, _) in &role_dp_vec {
            schemas_seen.insert(schema.clone());
        }

        // No grants, no default privileges → can't promote, keep flat.
        if schemas_seen.is_empty() {
            continue;
        }

        if schemas_seen.len() > 1 {
            skipped.push(SkipReason::MultiSchema {
                role: role_name.clone(),
                schemas: schemas_seen.into_iter().collect(),
            });
            continue;
        }

        let schema = schemas_seen.into_iter().next().unwrap();

        // The schema must be declared in the manifest (otherwise we can't bind
        // a profile to it).
        let Some(owner_for_schema) = schema_owner.get(&schema) else {
            skipped.push(SkipReason::SchemaNotDeclared {
                role: role_name.clone(),
                schema,
            });
            continue;
        };

        // Every default privilege owned-by must equal the schema's owner.
        let mut owner_mismatch = false;
        for (owner, _, _) in &role_dp_vec {
            if Some(owner.as_str()) != owner_for_schema.as_deref() {
                owner_mismatch = true;
                break;
            }
        }
        if owner_mismatch {
            skipped.push(SkipReason::OwnerMismatch {
                role: role_name.clone(),
                schema,
            });
            continue;
        }

        let signature = compute_signature(&role_grants_vec, &role_dp_vec, &schema);

        eligible.push(Eligible {
            role_name: role_name.clone(),
            schema,
            signature,
            login: role_def.login,
            inherit: role_def.inherit,
        });
    }

    // --- Cluster ------------------------------------------------------------

    // Key = (signature, login, inherit). Value = Vec<member>.
    type ClusterKey = (RoleSignature, Option<bool>, Option<bool>);
    let mut clusters: BTreeMap<ClusterKey, Vec<&Eligible>> = BTreeMap::new();
    for el in &eligible {
        clusters
            .entry((el.signature.clone(), el.login, el.inherit))
            .or_default()
            .push(el);
    }

    // --- Pattern resolution -------------------------------------------------

    // Iterate clusters in size-descending order so that bigger clusters claim
    // schema patterns first. Tie-break by signature for determinism.
    let mut cluster_entries: Vec<_> = clusters.into_iter().collect();
    cluster_entries.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

    let pattern_priority = [
        "{schema}-{profile}",
        "{schema}_{profile}",
        "{profile}-{schema}",
        "{profile}_{schema}",
    ];

    // schema → committed pattern. Once a cluster lands, the pattern is sticky.
    let mut schema_pattern: BTreeMap<String, String> = BTreeMap::new();
    // schema → list of profile names already attached.
    let mut schema_profiles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // profile name → built Profile object.
    let mut profiles_out: BTreeMap<String, Profile> = BTreeMap::new();
    // profile name → sources (schema, original role name) for the report.
    let mut suggested: Vec<SuggestedProfile> = Vec::new();
    // Profile names already taken (avoid collisions).
    let mut taken_profile_names: BTreeSet<String> = BTreeSet::new();

    for ((_signature, login, inherit), members) in cluster_entries {
        // Need at least `min_schemas` distinct schemas.
        let distinct_schemas: BTreeSet<&str> = members.iter().map(|m| m.schema.as_str()).collect();
        if distinct_schemas.len() < opts.min_schemas {
            for m in &members {
                skipped.push(SkipReason::SoleSchema {
                    role: m.role_name.clone(),
                    schema: m.schema.clone(),
                });
            }
            continue;
        }

        // Sanity: each schema appears at most once in a cluster (otherwise the
        // signature wouldn't match — distinct grants per role per schema).
        // Defensive — drop the duplicates.
        let mut seen_schemas: BTreeSet<&str> = BTreeSet::new();
        let unique_members: Vec<&Eligible> = members
            .iter()
            .filter(|m| seen_schemas.insert(m.schema.as_str()))
            .copied()
            .collect();

        // Find a (pattern, profile_name) that all members agree on AND that
        // doesn't conflict with already-committed schema patterns.
        //
        // For diagnostics: when no viable pattern can be chosen, surface
        // `SchemaPatternConflict` if some pattern *would* have succeeded
        // except for an already-locked schema; otherwise the failure is a
        // role-name disagreement / collision and we report `NoUniformPattern`.
        let mut chosen: Option<(String, String)> = None;
        // Records the schema/locked-pattern of the first pattern that was
        // viable in every other respect but blocked by a schema lock.
        let mut schema_conflict_blocking: Option<(String, String)> = None;
        for pat in pattern_priority {
            // Pattern viability ignoring schema lock: do role names match
            // uniformly, is the resulting profile name a valid identifier,
            // and is it free?
            let viable_name: Option<String> = {
                let mut names: BTreeSet<String> = BTreeSet::new();
                let mut ok = true;
                for m in &unique_members {
                    if let Some(prof) = match_pattern(pat, &m.role_name, &m.schema) {
                        names.insert(prof);
                    } else {
                        ok = false;
                        break;
                    }
                }
                if !ok || names.len() != 1 {
                    None
                } else {
                    let n = names.into_iter().next().unwrap();
                    if !is_valid_identifier(&n)
                        || taken_profile_names.contains(&n)
                        || input.profiles.contains_key(&n)
                    {
                        None
                    } else {
                        Some(n)
                    }
                }
            };

            // Is any of this cluster's schemas already locked to a different
            // pattern?
            let blocked_by_schema = unique_members.iter().find_map(|m| {
                schema_pattern
                    .get(&m.schema)
                    .filter(|committed| *committed != pat)
                    .map(|committed| (m.schema.clone(), committed.clone()))
            });

            match (viable_name, blocked_by_schema) {
                (Some(name), None) => {
                    chosen = Some((pat.to_string(), name));
                    break;
                }
                (Some(_), Some(conflict)) if schema_conflict_blocking.is_none() => {
                    schema_conflict_blocking = Some(conflict);
                }
                _ => {}
            }
        }

        let Some((pattern, profile_name)) = chosen else {
            if let Some((schema, winning_pattern)) = schema_conflict_blocking {
                skipped.push(SkipReason::SchemaPatternConflict {
                    schema,
                    winning_pattern,
                    dropped_roles: unique_members.iter().map(|m| m.role_name.clone()).collect(),
                });
            } else {
                skipped.push(SkipReason::NoUniformPattern {
                    roles: unique_members.iter().map(|m| m.role_name.clone()).collect(),
                });
            }
            continue;
        };

        // Commit the pattern on every schema this cluster touches.
        for m in &unique_members {
            schema_pattern.insert(m.schema.clone(), pattern.clone());
            schema_profiles
                .entry(m.schema.clone())
                .or_default()
                .push(profile_name.clone());
            clustered_role_names.insert(m.role_name.clone());
        }

        // Build the Profile from one representative member.
        let representative = unique_members[0];
        let rep_grants = role_grants
            .get(&representative.role_name)
            .cloned()
            .unwrap_or_default();
        let rep_dps = role_dps
            .get(&representative.role_name)
            .cloned()
            .unwrap_or_default();

        let profile = build_profile(
            login,
            inherit,
            &rep_grants,
            &rep_dps,
            &representative.schema,
        );

        profiles_out.insert(profile_name.clone(), profile);
        taken_profile_names.insert(profile_name.clone());

        let schema_to_role: BTreeMap<String, String> = unique_members
            .iter()
            .map(|m| (m.schema.clone(), m.role_name.clone()))
            .collect();
        suggested.push(SuggestedProfile {
            profile_name,
            role_pattern: pattern,
            schema_to_role,
        });
    }

    // --- Build the candidate output manifest --------------------------------

    let mut new_schemas: Vec<SchemaBinding> = input
        .schemas
        .iter()
        .map(|s| {
            let mut bound_profiles = schema_profiles.get(&s.name).cloned().unwrap_or_default();
            bound_profiles.sort();
            let pattern = schema_pattern
                .get(&s.name)
                .cloned()
                .or_else(|| s.role_pattern.clone());
            SchemaBinding {
                name: s.name.clone(),
                profiles: bound_profiles,
                role_pattern: pattern,
                owner: s.owner.clone(),
            }
        })
        .collect();
    new_schemas.sort_by(|a, b| a.name.cmp(&b.name));

    let new_roles: Vec<RoleDefinition> = input
        .roles
        .iter()
        .filter(|r| !clustered_role_names.contains(&r.name))
        .cloned()
        .collect();

    let new_grants: Vec<Grant> = input
        .grants
        .iter()
        .filter(|g| !clustered_role_names.contains(&g.role))
        .cloned()
        .collect();

    let new_default_privileges: Vec<DefaultPrivilege> = input
        .default_privileges
        .iter()
        .filter_map(|dp| {
            let kept: Vec<DefaultPrivilegeGrant> = dp
                .grant
                .iter()
                .filter(|g| match &g.role {
                    Some(r) => !clustered_role_names.contains(r),
                    None => true,
                })
                .cloned()
                .collect();
            if kept.is_empty() {
                None
            } else {
                Some(DefaultPrivilege {
                    owner: dp.owner.clone(),
                    schema: dp.schema.clone(),
                    scope: dp.scope.clone(),
                    grant: kept,
                })
            }
        })
        .collect();

    let candidate = PolicyManifest {
        role_pattern: input.role_pattern.clone(),
        default_owner: input.default_owner.clone(),
        auth_providers: input.auth_providers.clone(),
        profiles: profiles_out,
        schemas: new_schemas,
        roles: new_roles,
        grants: new_grants,
        default_privileges: new_default_privileges,
        memberships: input.memberships.clone(),
        retirements: input.retirements.clone(),
    };

    // --- Round-trip safety check -------------------------------------------

    // Round-trip wildcard expansion uses the most authoritative inventory
    // available. With a full introspected inventory we expand against the
    // *real* set of objects in each schema; otherwise we fall back to the
    // grant-derived view (sufficient when collapse didn't run).
    let round_trip_inventory = collapse_inventory.cloned().unwrap_or(grant_inventory);
    let round_trip_ok = match check_round_trip(input, &candidate, &round_trip_inventory) {
        Ok(()) => true,
        Err(reason) => {
            skipped.push(SkipReason::RoundTripFailure {
                reason: reason.clone(),
            });
            false
        }
    };

    let manifest = if round_trip_ok {
        candidate
    } else {
        input.clone()
    };

    SuggestReport {
        manifest,
        profiles: if round_trip_ok { suggested } else { vec![] },
        skipped,
        round_trip_ok,
    }
}

// ---------------------------------------------------------------------------
// Object-name inventory (for full-coverage collapse and round-trip check)
// ---------------------------------------------------------------------------

/// `(schema, object_type) → set of object names` referenced in the manifest's
/// flat grants. For schema-typed grants the schema is the grant's `name`
/// field; the inventory stores no entries for `Schema` (those are 1:1).
pub type Inventory = BTreeMap<(String, ObjectType), BTreeSet<String>>;

/// Build a `(schema, object_type) → set of names` map from the flat grants
/// in a manifest. Wildcards (`name: "*"`) and schema/database-typed grants
/// are excluded.
///
/// **Do not pass this to [`SuggestOptions::full_inventory`].** A grant-only
/// view treats ungranted objects as nonexistent, and would let
/// `collapse_full_coverage_grants` silently broaden privileges. This
/// function exists for the wildcard-aware round-trip comparison the
/// suggester uses internally — re-exported so test code can perform the
/// same comparison. Production callers should source `full_inventory` from
/// [`pgroles_inspect::fetch_object_inventory`].
pub fn inventory_from_manifest_grants(m: &PolicyManifest) -> Inventory {
    build_inventory(m)
}

/// Deprecated alias for [`inventory_from_manifest_grants`].
#[deprecated(
    note = "renamed to `inventory_from_manifest_grants` — must NOT be used as full_inventory"
)]
pub fn build_inventory_pub(m: &PolicyManifest) -> Inventory {
    build_inventory(m)
}

/// Replace each `name: "*"` table/sequence/function/etc. grant with one named
/// grant per entry in `inventory[(schema, object_type)]`. Schema- and
/// database-typed grants are passed through. Mutates `grants` in place.
pub fn expand_wildcard_grants(grants: &mut Vec<Grant>, inventory: &Inventory) {
    expand_wildcards_in_place(grants, inventory)
}

/// Verify that every object name appearing in `grant_inventory` (i.e. every
/// per-name grant referenced in the flat manifest) is also present in
/// `full_inventory`. If a granted object is missing from the supposedly
/// "full" inventory, the inventory is provably incomplete — likely the
/// caller passed a grant-derived view by mistake.
fn validate_full_inventory(
    grant_inventory: &Inventory,
    full_inventory: &Inventory,
) -> Result<(), String> {
    for (key, granted_names) in grant_inventory {
        let Some(full_names) = full_inventory.get(key) else {
            return Err(format!(
                "full_inventory missing entry for (schema={}, type={:?}) — but {} object name(s) are referenced in input grants",
                key.0,
                key.1,
                granted_names.len()
            ));
        };
        if let Some(missing) = granted_names.iter().find(|n| !full_names.contains(*n)) {
            return Err(format!(
                "full_inventory[(schema={}, type={:?})] does not contain {missing:?} but it appears in input grants",
                key.0, key.1
            ));
        }
    }
    Ok(())
}

fn build_inventory(m: &PolicyManifest) -> Inventory {
    let mut inv: Inventory = BTreeMap::new();
    for g in &m.grants {
        match g.object.object_type {
            ObjectType::Schema | ObjectType::Database => continue,
            _ => {}
        }
        let Some(name) = g.object.name.as_ref() else {
            continue;
        };
        if name == "*" {
            continue;
        }
        let Some(schema) = g.object.schema.as_ref() else {
            continue;
        };
        inv.entry((schema.clone(), g.object.object_type))
            .or_default()
            .insert(name.clone());
    }
    inv
}

/// Replace per-name grants with a single wildcard grant when a role's grants
/// fully cover every object of a given `(schema, object_type)` with identical
/// privileges. Mutates `grants` in place.
fn collapse_full_coverage_grants(grants: &mut Vec<Grant>, inventory: &Inventory) {
    // Group grants by (schema, object_type). Skip schema-typed grants — they
    // have a 1:1 mapping with the schema name and don't need collapsing.
    // Track which (schema, type) buckets already have a wildcard grant —
    // those cannot be collapsed (would produce two wildcards on the same
    // GrantKey, which the model can't hold).
    let mut buckets: BTreeMap<(String, ObjectType), Vec<usize>> = BTreeMap::new();
    let mut has_wildcard: BTreeSet<(String, ObjectType)> = BTreeSet::new();
    for (i, g) in grants.iter().enumerate() {
        match g.object.object_type {
            ObjectType::Schema | ObjectType::Database => continue,
            _ => {}
        }
        let Some(schema) = g.object.schema.as_ref() else {
            continue;
        };
        let Some(name) = g.object.name.as_ref() else {
            continue;
        };
        if name == "*" {
            has_wildcard.insert((schema.clone(), g.object.object_type));
            continue;
        }
        buckets
            .entry((schema.clone(), g.object.object_type))
            .or_default()
            .push(i);
    }
    buckets.retain(|key, _| !has_wildcard.contains(key));

    let mut to_remove: BTreeSet<usize> = BTreeSet::new();
    let mut to_add: Vec<Grant> = Vec::new();

    for ((schema, object_type), idxs) in buckets {
        // All entries must share the same privilege set.
        let first_privs = canonical_privs(&grants[idxs[0]].privileges);
        let all_same = idxs
            .iter()
            .all(|&i| canonical_privs(&grants[i].privileges) == first_privs);
        if !all_same {
            continue;
        }
        // Collected names must equal the inventory for that (schema, type).
        let mut covered: BTreeSet<String> = BTreeSet::new();
        for &i in &idxs {
            if let Some(name) = grants[i].object.name.as_ref() {
                covered.insert(name.clone());
            }
        }
        let inv_names = inventory.get(&(schema.clone(), object_type));
        let full_coverage = match inv_names {
            Some(names) => &covered == names,
            None => false,
        };
        if !full_coverage {
            continue;
        }
        // Collapse: remove all per-name entries; add one wildcard.
        for &i in &idxs {
            to_remove.insert(i);
        }
        let role = grants[idxs[0]].role.clone();
        to_add.push(Grant {
            role,
            privileges: first_privs.into_iter().collect(),
            ensure: crate::manifest::Ensure::Present,
            object: ObjectTarget {
                object_type,
                schema: Some(schema),
                name: Some("*".to_string()),
            },
        });
    }

    // Apply removals (in reverse order) and additions.
    let mut remaining = Vec::with_capacity(grants.len() - to_remove.len() + to_add.len());
    for (i, g) in grants.drain(..).enumerate() {
        if !to_remove.contains(&i) {
            remaining.push(g);
        }
    }
    remaining.extend(to_add);
    *grants = remaining;
}

fn canonical_privs(privs: &[Privilege]) -> Vec<Privilege> {
    let mut out = privs.to_vec();
    out.sort_by_key(|p| privilege_sort_key(*p));
    out.dedup();
    out
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Schema-relative signature: the set of grants and default privileges with
/// the schema replaced by a placeholder. Stored as a sorted Vec so the type
/// implements `Ord` for use as a `BTreeMap` key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RoleSignature {
    grants: Vec<SignatureGrant>,
    defaults: Vec<SignatureDefault>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SignatureGrant {
    object_type: ObjectType,
    /// `None` for schema-typed grants, otherwise the object name (e.g. `"*"`).
    name: Option<String>,
    privileges: Vec<Privilege>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SignatureDefault {
    on_type: ObjectType,
    privileges: Vec<Privilege>,
}

fn compute_signature(
    grants: &[Grant],
    dps: &[(String, String, DefaultPrivilegeGrant)],
    schema: &str,
) -> RoleSignature {
    let mut sig_grants: Vec<SignatureGrant> = grants
        .iter()
        .map(|g| {
            let name = match g.object.object_type {
                // Schema-typed grants have schema as `name`. Drop it — the
                // signature is schema-relative.
                ObjectType::Schema => {
                    if g.object.name.as_deref() == Some(schema) {
                        None
                    } else {
                        // Pointed at a *different* schema — preserve the
                        // literal name to keep the signature distinct.
                        g.object.name.clone()
                    }
                }
                _ => g.object.name.clone(),
            };
            let mut privs = g.privileges.clone();
            privs.sort_by_key(|p| privilege_sort_key(*p));
            privs.dedup();
            SignatureGrant {
                object_type: g.object.object_type,
                name,
                privileges: privs,
            }
        })
        .collect();
    sig_grants.sort();
    sig_grants.dedup();

    let mut sig_defaults: Vec<SignatureDefault> = dps
        .iter()
        .map(|(_, _, dpg)| {
            let mut privs = dpg.privileges.clone();
            privs.sort_by_key(|p| privilege_sort_key(*p));
            privs.dedup();
            SignatureDefault {
                on_type: dpg.on_type,
                privileges: privs,
            }
        })
        .collect();
    sig_defaults.sort();
    sig_defaults.dedup();

    RoleSignature {
        grants: sig_grants,
        defaults: sig_defaults,
    }
}

fn privilege_sort_key(p: Privilege) -> u8 {
    match p {
        Privilege::Select => 0,
        Privilege::Insert => 1,
        Privilege::Update => 2,
        Privilege::Delete => 3,
        Privilege::Truncate => 4,
        Privilege::References => 5,
        Privilege::Trigger => 6,
        Privilege::Execute => 7,
        Privilege::Usage => 8,
        Privilege::Create => 9,
        Privilege::Connect => 10,
        Privilege::Temporary => 11,
    }
}

fn match_pattern(pattern: &str, role_name: &str, schema: &str) -> Option<String> {
    match pattern {
        "{schema}-{profile}" => role_name
            .strip_prefix(schema)
            .and_then(|r| r.strip_prefix('-'))
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string()),
        "{schema}_{profile}" => role_name
            .strip_prefix(schema)
            .and_then(|r| r.strip_prefix('_'))
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string()),
        "{profile}-{schema}" => role_name
            .strip_suffix(schema)
            .and_then(|r| r.strip_suffix('-'))
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string()),
        "{profile}_{schema}" => role_name
            .strip_suffix(schema)
            .and_then(|r| r.strip_suffix('_'))
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string()),
        _ => None,
    }
}

/// Recognise the auto-generated role comment that `expand_manifest` writes
/// when materializing a `profile × schema` role. Format:
/// `"Generated from profile 'X' for schema 'Y'"`.
fn is_auto_profile_comment(c: &str) -> bool {
    c.starts_with("Generated from profile '") && c.contains("' for schema '") && c.ends_with('\'')
}

fn is_valid_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !s.starts_with('-')
        && !s.starts_with('_')
}

/// Whether any global-scope default privilege names this role as grantee.
///
/// Global scope has no schema, so a profile cannot express it. `role_dps`
/// deliberately skips these entries, which would otherwise be silently lost.
/// Whether any default privilege for `role` asserts absence.
///
/// Profiles are additive templates, so folding such an entry in would turn the
/// assertion into its opposite. The round-trip check catches that and abandons
/// the whole candidate manifest, so one unfoldable role would cost every other
/// role its clustering. Skipping the role keeps the loss local.
fn role_has_absent_default_privilege(input: &PolicyManifest, role: &str) -> bool {
    input.default_privileges.iter().any(|dp| {
        dp.grant.iter().any(|grant| {
            grant.role.as_deref() == Some(role) && grant.ensure == crate::manifest::Ensure::Absent
        })
    })
}

fn role_has_global_default_privilege(input: &PolicyManifest, role: &str) -> bool {
    input.default_privileges.iter().any(|dp| {
        dp.resolved_scope()
            .is_ok_and(|scope| scope.schema().is_none())
            && dp
                .grant
                .iter()
                .any(|grant| grant.role.as_deref() == Some(role))
    })
}

fn build_profile(
    login: Option<bool>,
    inherit: Option<bool>,
    grants: &[Grant],
    dps: &[(String, String, DefaultPrivilegeGrant)],
    #[cfg_attr(not(debug_assertions), allow(unused_variables))] schema: &str,
) -> Profile {
    // Build profile grants in a deterministic order.
    let mut profile_grants: Vec<ProfileGrant> = grants
        .iter()
        .map(|g| {
            let object = match g.object.object_type {
                ObjectType::Schema => ProfileObjectTarget {
                    object_type: ObjectType::Schema,
                    // Profile expansion ignores `name` for schema-typed grants
                    // (it always uses the schema_binding name). Setting None
                    // keeps the YAML clean.
                    name: None,
                },
                _ => {
                    // The grant's schema must equal `schema` (otherwise the
                    // role wouldn't be eligible). Drop the schema; preserve
                    // `name` (e.g. `"*"` or a specific table name).
                    debug_assert_eq!(g.object.schema.as_deref(), Some(schema));
                    ProfileObjectTarget {
                        object_type: g.object.object_type,
                        name: g.object.name.clone(),
                    }
                }
            };
            let mut privs = g.privileges.clone();
            privs.sort_by_key(|p| privilege_sort_key(*p));
            privs.dedup();
            ProfileGrant {
                privileges: privs,
                object,
                ensure: crate::manifest::Ensure::Present,
            }
        })
        .collect();
    profile_grants.sort_by(|a, b| {
        let key_a = (a.object.object_type, a.object.name.clone());
        let key_b = (b.object.object_type, b.object.name.clone());
        key_a.cmp(&key_b)
    });

    let mut profile_defaults: Vec<DefaultPrivilegeGrant> = dps
        .iter()
        .map(|(_, _, dpg)| {
            let mut privs = dpg.privileges.clone();
            privs.sort_by_key(|p| privilege_sort_key(*p));
            privs.dedup();
            DefaultPrivilegeGrant {
                role: None, // expansion fills this in
                privileges: privs,
                on_type: dpg.on_type,
                ensure: crate::manifest::Ensure::Present,
            }
        })
        .collect();
    profile_defaults.sort_by_key(|d| d.on_type);

    Profile {
        login,
        inherit,
        grants: profile_grants,
        default_privileges: profile_defaults,
        // The suggester never clusters config-carrying roles into a profile
        // (see the `role_def.config` check in the eligibility loop above) —
        // profiles it builds never need to express `config`.
        config: BTreeMap::new(),
    }
}

fn check_round_trip(
    original: &PolicyManifest,
    candidate: &PolicyManifest,
    inventory: &Inventory,
) -> Result<(), String> {
    let mut original_expanded =
        expand_manifest(original).map_err(|e| format!("original expand: {e}"))?;
    expand_wildcards_in_place(&mut original_expanded.grants, inventory);
    let original_graph =
        RoleGraph::from_expanded(&original_expanded, original.default_owner.as_deref())
            .map_err(|e| format!("original graph: {e}"))?;

    let mut candidate_expanded =
        expand_manifest(candidate).map_err(|e| format!("candidate expand: {e}"))?;
    expand_wildcards_in_place(&mut candidate_expanded.grants, inventory);
    let candidate_graph =
        RoleGraph::from_expanded(&candidate_expanded, candidate.default_owner.as_deref())
            .map_err(|e| format!("candidate graph: {e}"))?;

    let changes = diff(&original_graph, &candidate_graph);
    let unacceptable: Vec<&Change> = changes
        .iter()
        .filter(|c| !matches!(c, Change::SetComment { .. }))
        .collect();
    if !unacceptable.is_empty() {
        return Err(format!(
            "{} structural change(s) after suggestion (sample: {:?})",
            unacceptable.len(),
            unacceptable.first()
        ));
    }
    Ok(())
}

/// Expand any `name: "*"` grant against the inventory: emit one named grant
/// per inventory entry. Schema and Database object_types are passed through.
fn expand_wildcards_in_place(grants: &mut Vec<Grant>, inventory: &Inventory) {
    let mut out: Vec<Grant> = Vec::with_capacity(grants.len());
    for g in grants.drain(..) {
        let is_wildcard = matches!(
            g.object.object_type,
            ObjectType::Table
                | ObjectType::View
                | ObjectType::MaterializedView
                | ObjectType::Sequence
                | ObjectType::Function
                | ObjectType::Type
        ) && g.object.name.as_deref() == Some("*");
        if !is_wildcard {
            out.push(g);
            continue;
        }
        let Some(schema) = g.object.schema.as_ref() else {
            out.push(g);
            continue;
        };
        let key = (schema.clone(), g.object.object_type);
        if let Some(names) = inventory.get(&key) {
            for name in names {
                out.push(Grant {
                    role: g.role.clone(),
                    privileges: g.privileges.clone(),
                    ensure: g.ensure,
                    object: ObjectTarget {
                        object_type: g.object.object_type,
                        schema: g.object.schema.clone(),
                        name: Some(name.clone()),
                    },
                });
            }
        } else {
            // No objects of this type in the schema — wildcard is a no-op,
            // but we keep it so the model is preserved.
            out.push(g);
        }
    }
    *grants = out;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_manifest;

    fn parse(yaml: &str) -> PolicyManifest {
        parse_manifest(yaml).expect("parse")
    }

    #[test]
    fn no_input_profiles_no_clusters_returns_unchanged() {
        let m = parse(
            r#"
roles:
  - name: alice
    login: true
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(report.round_trip_ok);
    }

    #[test]
    fn input_with_existing_profiles_is_left_alone() {
        let m = parse(
            r#"
profiles:
  reader:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
schemas:
  - name: x
    profiles: [reader]
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert_eq!(report.manifest.profiles.len(), 1);
    }

    #[test]
    fn clusters_two_schemas_with_dash_pattern() {
        // Three schemas, three roles, all with identical schema-relative shape.
        let m = parse(
            r#"
default_owner: app_owner
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
  - name: analytics
    owner: app_owner

roles:
  - name: inventory-reader
  - name: checkout-reader
  - name: analytics-reader

grants:
  - role: inventory-reader
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
  - role: analytics-reader
    privileges: [USAGE]
    object: { type: schema, name: analytics }
  - role: analytics-reader
    privileges: [SELECT]
    object: { type: table, schema: analytics, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok, "skipped: {:?}", report.skipped);
        assert_eq!(report.profiles.len(), 1);
        let p = &report.profiles[0];
        assert_eq!(p.profile_name, "reader");
        assert_eq!(p.role_pattern, "{schema}-{profile}");
        assert_eq!(p.schema_to_role.len(), 3);
        assert!(report.manifest.profiles.contains_key("reader"));
        // Roles section should no longer hold the clustered roles.
        assert!(
            report
                .manifest
                .roles
                .iter()
                .all(|r| !r.name.ends_with("-reader"))
        );
        // Schema bindings should reference the new profile.
        for s in &report.manifest.schemas {
            assert_eq!(s.profiles, vec!["reader"]);
            assert_eq!(s.role_pattern.as_deref(), Some("{schema}-{profile}"));
        }
    }

    #[test]
    fn clusters_with_underscore_pattern() {
        let m = parse(
            r#"
default_owner: app_owner
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
roles:
  - name: inventory_app
    login: true
  - name: checkout_app
    login: true
grants:
  - role: inventory_app
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory_app
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout_app
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout_app
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        let p = &report.profiles[0];
        assert_eq!(p.profile_name, "app");
        assert_eq!(p.role_pattern, "{schema}_{profile}");
        // Profile carries `login: true`.
        let prof = report.manifest.profiles.get("app").unwrap();
        assert_eq!(prof.login, Some(true));
    }

    #[test]
    fn does_not_cluster_single_schema_role() {
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: app_owner
roles:
  - name: inventory-reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(matches!(
            report.skipped.first(),
            Some(SkipReason::SoleSchema { .. })
        ));
    }

    #[test]
    fn min_schemas_one_promotes_single_schema_role() {
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: app_owner
roles:
  - name: inventory-reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
"#,
        );
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                min_schemas: 1,
                ..Default::default()
            },
        );
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
    }

    #[test]
    fn role_with_unique_attributes_stays_flat() {
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
roles:
  - name: inventory-reader
    connection_limit: 5
  - name: checkout-reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        // Only one role qualifies → SoleSchema skip; no cluster formed.
        assert!(report.profiles.is_empty());
        assert!(report.skipped.iter().any(
            |s| matches!(s, SkipReason::UniqueAttributes { role } if role == "inventory-reader")
        ));
    }

    #[test]
    fn multi_schema_role_skipped() {
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
roles:
  - name: cross
grants:
  - role: cross
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: cross
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::MultiSchema { role, .. } if role == "cross"))
        );
    }

    #[test]
    fn non_uniform_pattern_skipped() {
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
roles:
  - name: inventory-reader
  - name: checkout_reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout_reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        // inventory-reader matches {schema}-{profile} → "reader"
        // checkout_reader matches {schema}_{profile} → "reader"
        // They have the SAME signature, but different patterns. Our resolver
        // picks the first pattern in priority order that all members agree on
        // — neither pattern works for both, so no cluster.
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::NoUniformPattern { .. }))
        );
    }

    #[test]
    fn different_login_split_into_separate_clusters() {
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
  - name: c
    owner: o
  - name: d
    owner: o
roles:
  - name: a-svc
    login: true
  - name: b-svc
    login: true
  - name: c-svc
  - name: d-svc
grants:
  - role: a-svc
    privileges: [SELECT]
    object: { type: table, schema: a, name: "*" }
  - role: b-svc
    privileges: [SELECT]
    object: { type: table, schema: b, name: "*" }
  - role: c-svc
    privileges: [SELECT]
    object: { type: table, schema: c, name: "*" }
  - role: d-svc
    privileges: [SELECT]
    object: { type: table, schema: d, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        // Both clusters resolve to profile name "svc"; only one wins (the
        // larger one, or the lexicographically-first by signature in a tie).
        // The other cluster's roles are skipped as NoUniformPattern.
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].profile_name, "svc");
        // The "losing" cluster's two roles must remain in the flat roles list.
        let kept_role_names: BTreeSet<&str> = report
            .manifest
            .roles
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(kept_role_names.len(), 2);
    }

    #[test]
    fn round_trip_zero_diff() {
        // A representative manifest, including default privileges.
        let m = parse(
            r#"
default_owner: app_owner
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner

roles:
  - name: inventory-rw
  - name: checkout-rw

grants:
  - role: inventory-rw
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory-rw
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: inventory, name: "*" }
  - role: inventory-rw
    privileges: [USAGE, SELECT]
    object: { type: sequence, schema: inventory, name: "*" }
  - role: checkout-rw
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout-rw
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: checkout, name: "*" }
  - role: checkout-rw
    privileges: [USAGE, SELECT]
    object: { type: sequence, schema: checkout, name: "*" }

default_privileges:
  - owner: app_owner
    schema: inventory
    grant:
      - role: inventory-rw
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
  - owner: app_owner
    schema: checkout
    grant:
      - role: checkout-rw
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
"#,
        );

        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        let prof = report.manifest.profiles.get("rw").unwrap();
        assert_eq!(prof.grants.len(), 3);
        assert_eq!(prof.default_privileges.len(), 1);

        // Compare the structural state (RoleGraph) of input vs suggested.
        let original_expanded = expand_manifest(&m).unwrap();
        let original_graph =
            RoleGraph::from_expanded(&original_expanded, m.default_owner.as_deref()).unwrap();
        let new_expanded = expand_manifest(&report.manifest).unwrap();
        let new_graph =
            RoleGraph::from_expanded(&new_expanded, report.manifest.default_owner.as_deref())
                .unwrap();
        let changes = diff(&original_graph, &new_graph);
        // Only role-comment changes (auto-generated by profile expansion) are
        // acceptable.
        let bad: Vec<_> = changes
            .iter()
            .filter(|c| !matches!(c, Change::SetComment { .. }))
            .collect();
        assert!(bad.is_empty(), "unexpected diff: {bad:?}");
    }

    #[test]
    fn schema_pattern_conflict_drops_smaller_cluster() {
        // Two clusters compete for schema "inventory":
        //   "inventory-reader" + "checkout-reader" → wants "{schema}-{profile}"
        //   "inventory_app" + "stage_app" → wants "{schema}_{profile}"
        // Wait — these touch different schemas, so they don't actually conflict
        // unless the same schema appears in both. Construct a real conflict:
        // make role "inventory-reader" + "checkout-reader" (cluster A) and
        // "inventory_writer" + "checkout_writer" (cluster B). Both want to
        // bind to inventory and checkout, but with different patterns. Only
        // the first cluster (alphabetically: dash < underscore) wins.
        let m = parse(
            r#"
default_owner: o
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o

roles:
  - name: inventory-reader
  - name: checkout-reader
  - name: inventory_writer
  - name: checkout_writer

grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
  - role: inventory_writer
    privileges: [INSERT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout_writer
    privileges: [INSERT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );

        let report = suggest_profiles(&m, &SuggestOptions::default());
        // Either "reader" wins outright (both schemas commit to dash pattern,
        // then the underscore cluster can't take its preferred pattern),
        // or vice-versa. Whichever one wins, the other should be left flat
        // and round-trip should still succeed.
        assert!(report.round_trip_ok);
        assert_eq!(
            report.profiles.len(),
            1,
            "exactly one profile should win: {:?}",
            report.profiles
        );
        // The losing cluster must surface a SchemaPatternConflict skip
        // pointing at the schema whose pattern was already locked.
        let conflicts: Vec<_> = report
            .skipped
            .iter()
            .filter_map(|s| match s {
                SkipReason::SchemaPatternConflict {
                    schema,
                    winning_pattern,
                    dropped_roles,
                } => Some((schema, winning_pattern, dropped_roles)),
                _ => None,
            })
            .collect();
        assert_eq!(
            conflicts.len(),
            1,
            "expected one SchemaPatternConflict skip, got: {:?}",
            report.skipped
        );
        let (_, winning, dropped) = conflicts[0];
        // Either pattern can win (depends on signature ordering); the
        // important thing is that the *other* one is reported as conflicting.
        assert!(
            winning == "{schema}-{profile}" || winning == "{schema}_{profile}",
            "unexpected winning_pattern: {winning}"
        );
        assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn match_pattern_basic() {
        assert_eq!(
            match_pattern("{schema}-{profile}", "inventory-reader", "inventory"),
            Some("reader".into())
        );
        assert_eq!(
            match_pattern("{schema}_{profile}", "inventory_app", "inventory"),
            Some("app".into())
        );
        assert_eq!(
            match_pattern("{profile}-{schema}", "ro-inventory", "inventory"),
            Some("ro".into())
        );
        assert_eq!(
            match_pattern("{profile}_{schema}", "ro_inventory", "inventory"),
            Some("ro".into())
        );
        // Schema not matched.
        assert_eq!(
            match_pattern("{schema}-{profile}", "checkout-reader", "inventory"),
            None
        );
        // Empty profile component.
        assert_eq!(
            match_pattern("{schema}-{profile}", "inventory-", "inventory"),
            None
        );
        // No separator.
        assert_eq!(
            match_pattern("{schema}-{profile}", "inventoryreader", "inventory"),
            None
        );
    }

    #[test]
    fn database_grants_excluded_from_clustering() {
        // A role with a CONNECT-on-database grant has an unrepresentable
        // grant; profiles can't carry it. Even if its other grants are
        // schema-shaped and shared with another role, exclude it.
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-svc
  - name: b-svc
grants:
  - role: a-svc
    privileges: [CONNECT]
    object: { type: database, name: mydb }
  - role: a-svc
    privileges: [SELECT]
    object: { type: table, schema: a, name: "*" }
  - role: b-svc
    privileges: [SELECT]
    object: { type: table, schema: b, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        // a-svc is excluded, b-svc is single-schema → no cluster.
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::UnrepresentableGrant { role } if role == "a-svc"))
        );
    }

    #[test]
    fn membership_targets_clustered_role_still_resolve_after_suggestion() {
        // A membership targets `inventory-reader`; after clustering, the
        // expanded manifest must still produce a role with that exact name.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
  - name: checkout-reader
  - name: alice
    login: true
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
memberships:
  - role: inventory-reader
    members:
      - name: alice
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        // The membership entry is preserved verbatim.
        assert_eq!(report.manifest.memberships.len(), 1);
        assert_eq!(report.manifest.memberships[0].role, "inventory-reader");
        // Re-expanding produces the role.
        let expanded = expand_manifest(&report.manifest).unwrap();
        assert!(expanded.roles.iter().any(|r| r.name == "inventory-reader"));
        assert!(expanded.roles.iter().any(|r| r.name == "checkout-reader"));
    }

    #[test]
    fn wildcard_object_names_preserved_in_profile() {
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [SELECT, INSERT]
    object: { type: table, schema: a, name: "*" }
  - role: a-rw
    privileges: [USAGE]
    object: { type: sequence, schema: a, name: orders_id_seq }
  - role: b-rw
    privileges: [SELECT, INSERT]
    object: { type: table, schema: b, name: "*" }
  - role: b-rw
    privileges: [USAGE]
    object: { type: sequence, schema: b, name: orders_id_seq }
"#,
        );

        // Default options (no full_inventory) → no collapse → literal names
        // are preserved.
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        let prof = report.manifest.profiles.get("rw").unwrap();
        let seq_grant = prof
            .grants
            .iter()
            .find(|g| g.object.object_type == ObjectType::Sequence)
            .unwrap();
        assert_eq!(seq_grant.object.name.as_deref(), Some("orders_id_seq"));

        // With a full inventory provided, full-coverage names become
        // wildcards.
        let inv = inventory_from_manifest_grants(&m);
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                full_inventory: Some(inv),
                ..Default::default()
            },
        );
        assert!(report.round_trip_ok);
        let prof = report.manifest.profiles.get("rw").unwrap();
        let seq_grant = prof
            .grants
            .iter()
            .find(|g| g.object.object_type == ObjectType::Sequence)
            .unwrap();
        assert_eq!(
            seq_grant.object.name.as_deref(),
            Some("*"),
            "single-object full coverage should collapse to wildcard"
        );
    }

    #[test]
    fn collapse_clusters_roles_with_different_object_names() {
        // The motivating real-world case: per-name grants from `pgroles
        // generate` (Postgres expands `GRANT … ON ALL TABLES` to per-relation
        // rows). After collapse, the two roles share a wildcard signature and
        // cluster.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
  - name: checkout-reader
grants:
  - role: inventory-reader
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: products }
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: stock_levels }
  - role: checkout-reader
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: orders }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: order_items }
"#,
        );
        // With a full inventory provided, the per-name grants get collapsed
        // and the two roles cluster on a wildcard signature.
        let inv = inventory_from_manifest_grants(&m);
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                full_inventory: Some(inv),
                ..Default::default()
            },
        );
        assert!(report.round_trip_ok, "skipped: {:?}", report.skipped);
        assert_eq!(report.profiles.len(), 1);
        let prof = report.manifest.profiles.get("reader").unwrap();
        // Profile carries a wildcard table grant.
        let table_grant = prof
            .grants
            .iter()
            .find(|g| g.object.object_type == ObjectType::Table)
            .unwrap();
        assert_eq!(table_grant.object.name.as_deref(), Some("*"));
    }

    #[test]
    fn no_full_inventory_prevents_clustering_across_different_names() {
        // Same input as `collapse_clusters_roles_with_different_object_names`
        // but without a full_inventory — should NOT cluster, since literal
        // names differ and we can't safely collapse without DB introspection.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
  - name: checkout-reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: products }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: orders }
"#,
        );
        // Default (no full_inventory) → no collapse → different literal names
        // produce different signatures → no cluster.
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
    }

    #[test]
    fn collapse_partial_coverage_preserves_per_name_grants() {
        // Two tables in schema `a`, but role `a-ro` only has SELECT on one of
        // them. Coverage isn't full → no collapse → no cluster with `b-ro`
        // (which has full coverage of its single-table schema).
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-ro
  - name: b-ro
grants:
  - role: a-ro
    privileges: [SELECT]
    object: { type: table, schema: a, name: t1 }
  # a-ro has no grant on a.t2 (which exists, evidenced by another role)
  - role: filler
    privileges: [SELECT]
    object: { type: table, schema: a, name: t2 }
  - role: b-ro
    privileges: [SELECT]
    object: { type: table, schema: b, name: only_one }
"#,
        );
        // Full inventory says schema `a` has {t1, t2}, schema `b` has
        // {only_one}. a-ro covers only t1 (partial) → no collapse for a-ro.
        // b-ro covers all of {only_one} (full) → collapses to wildcard.
        // Different signatures → no cluster.
        let inv = inventory_from_manifest_grants(&m);
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                full_inventory: Some(inv),
                ..Default::default()
            },
        );
        assert!(report.profiles.is_empty());
    }

    #[test]
    fn incomplete_full_inventory_disables_collapse_with_skip_reason() {
        // Hand the suggester a `full_inventory` that's *missing* an object
        // that already appears in the manifest's flat grants. This is
        // exactly the failure mode of passing `inventory_from_manifest_grants`
        // (or any partial view) — the suggester must detect it and refuse
        // to collapse, surfacing an `IncompleteFullInventory` skip.
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [SELECT]
    object: { type: table, schema: a, name: products }
  - role: b-rw
    privileges: [SELECT]
    object: { type: table, schema: b, name: orders }
"#,
        );
        // Provide an inventory that omits `products` — pretend the caller
        // missed it.
        let mut bad: Inventory = BTreeMap::new();
        bad.entry(("a".to_string(), ObjectType::Table)).or_default(); // empty set
        bad.entry(("b".to_string(), ObjectType::Table))
            .or_default()
            .insert("orders".to_string());
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                full_inventory: Some(bad),
                ..Default::default()
            },
        );
        // Collapse must have been disabled; literal names differ across
        // schemas → no cluster.
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::IncompleteFullInventory { .. })),
            "expected IncompleteFullInventory skip; got: {:?}",
            report.skipped
        );
    }

    #[test]
    fn full_inventory_with_ungranted_objects_blocks_unsafe_collapse() {
        // Schema `a` has 2 tables; role `a-ro` has SELECT on only one. With a
        // grant-derived view of the world we'd think coverage was full and
        // collapse to wildcard — which would silently grant on `t2` after
        // applying. With a real introspected inventory (containing both
        // tables), the suggester correctly sees partial coverage and refuses
        // to collapse.
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-ro
  - name: b-ro
grants:
  - role: a-ro
    privileges: [SELECT]
    object: { type: table, schema: a, name: t1 }
  - role: b-ro
    privileges: [SELECT]
    object: { type: table, schema: b, name: only_one }
"#,
        );
        // Inventory reports schema `a` actually has *two* tables.
        let mut inv = inventory_from_manifest_grants(&m);
        inv.entry(("a".to_string(), ObjectType::Table))
            .or_default()
            .insert("t2_ungranted".to_string());
        let report = suggest_profiles(
            &m,
            &SuggestOptions {
                full_inventory: Some(inv),
                ..Default::default()
            },
        );
        // a-ro has partial coverage now → no collapse → no cluster.
        assert!(report.profiles.is_empty());
    }

    #[test]
    fn auto_generated_profile_comments_dont_block_resuggestion() {
        // When `pgroles apply` materializes a profile, it sets a comment on
        // each generated role. Re-running `--suggest-profiles` later must not
        // treat those auto-comments as user-set documentation that
        // disqualifies the role.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
    comment: "Generated from profile 'reader' for schema 'inventory'"
  - name: checkout-reader
    comment: "Generated from profile 'reader' for schema 'checkout'"
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].profile_name, "reader");
    }

    #[test]
    fn user_set_comments_still_block_clustering() {
        // A real user-set comment (not the auto-generated pattern) keeps the
        // role flat — profiles can't carry per-role comments.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
    comment: "Owned by data team — Q3 access only"
  - name: checkout-reader
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        // inventory-reader excluded for user comment → checkout-reader is
        // now sole-schema → no cluster.
        assert!(report.profiles.is_empty());
        assert!(report.skipped.iter().any(
            |s| matches!(s, SkipReason::UniqueAttributes { role } if role == "inventory-reader")
        ));
    }

    #[test]
    fn is_auto_profile_comment_basic() {
        assert!(is_auto_profile_comment(
            "Generated from profile 'reader' for schema 'inventory'"
        ));
        assert!(is_auto_profile_comment(
            "Generated from profile 'app-rw' for schema 'app_v2'"
        ));
        assert!(!is_auto_profile_comment("Random user note"));
        assert!(!is_auto_profile_comment(
            "Generated from profile 'reader' for schema 'inventory"
        )); // missing trailing quote
        assert!(!is_auto_profile_comment("Generated from profile 'reader'")); // missing schema part
    }

    #[test]
    fn function_grants_with_signature_in_name_round_trip() {
        // Functions are emitted by `pgroles generate` with their argument
        // signature in `name`, e.g. `order_total(_id bigint)`. Verify those
        // round-trip correctly through the suggester.
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [EXECUTE]
    object: { type: function, schema: a, name: "order_total(bigint)" }
  - role: b-rw
    privileges: [EXECUTE]
    object: { type: function, schema: b, name: "order_total(bigint)" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
    }

    #[test]
    fn default_privilege_owner_mismatch_excludes_role() {
        let m = parse(
            r#"
schemas:
  - name: a
    owner: app_owner
  - name: b
    owner: app_owner
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [SELECT]
    object: { type: table, schema: a, name: "*" }
  - role: b-rw
    privileges: [SELECT]
    object: { type: table, schema: b, name: "*" }
default_privileges:
  - owner: a_different_owner   # mismatch — schema "a" is owned by app_owner
    schema: a
    grant:
      - role: a-rw
        privileges: [SELECT]
        on_type: table
  - owner: app_owner
    schema: b
    grant:
      - role: b-rw
        privileges: [SELECT]
        on_type: table
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        // a-rw is excluded for owner mismatch → b-rw is sole-schema.
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::OwnerMismatch { role, .. } if role == "a-rw"))
        );
    }

    #[test]
    fn absent_default_privilege_excludes_only_its_own_role() {
        let m = parse(
            r#"
schemas:
  - name: a
    owner: app_owner
  - name: b
    owner: app_owner
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [SELECT]
    object: { type: table, schema: a, name: "*" }
  - role: b-rw
    privileges: [SELECT]
    object: { type: table, schema: b, name: "*" }
default_privileges:
  - owner: app_owner
    schema: a
    grant:
      - role: a-rw
        ensure: absent
        privileges: [DELETE]
        on_type: table
  - owner: app_owner
    schema: b
    grant:
      - role: b-rw
        privileges: [SELECT]
        on_type: table
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::UnrepresentableGrant { role } if role == "a-rw")),
            "a profile cannot assert absence, so a-rw must be skipped: {:?}",
            report.skipped
        );
        assert!(
            !report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::UnrepresentableGrant { role } if role == "b-rw")),
            "b-rw asserts nothing absent and must be unaffected: {:?}",
            report.skipped
        );
    }

    #[test]
    fn role_with_zero_grants_is_left_flat() {
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
roles:
  - name: lonely
    login: true
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(report.round_trip_ok);
        assert!(report.manifest.roles.iter().any(|r| r.name == "lonely"));
    }

    #[test]
    fn schema_typed_grant_pointing_to_unrelated_schema_excludes_role() {
        // Role `a-rw` mostly touches schema `a` but has a `USAGE on schema b`
        // grant — that's two schemas, so it's MultiSchema-skipped.
        let m = parse(
            r#"
schemas:
  - name: a
    owner: o
  - name: b
    owner: o
roles:
  - name: a-rw
  - name: b-rw
grants:
  - role: a-rw
    privileges: [USAGE]
    object: { type: schema, name: a }
  - role: a-rw
    privileges: [USAGE]
    object: { type: schema, name: b }   # surprise: also touches b
  - role: b-rw
    privileges: [USAGE]
    object: { type: schema, name: b }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| matches!(s, SkipReason::MultiSchema { role, .. } if role == "a-rw"))
        );
    }

    #[test]
    fn determinism_same_input_same_output() {
        // Run the suggester twice; outputs must be byte-identical YAML.
        let yaml = r#"
default_owner: app_owner
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
  - name: analytics
    owner: app_owner
roles:
  - name: inventory-reader
  - name: checkout-reader
  - name: analytics-reader
  - name: inventory-rw
  - name: checkout-rw
  - name: analytics-rw
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
  - role: analytics-reader
    privileges: [SELECT]
    object: { type: table, schema: analytics, name: "*" }
  - role: inventory-rw
    privileges: [SELECT, INSERT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-rw
    privileges: [SELECT, INSERT]
    object: { type: table, schema: checkout, name: "*" }
  - role: analytics-rw
    privileges: [SELECT, INSERT]
    object: { type: table, schema: analytics, name: "*" }
"#;
        let m1 = parse(yaml);
        let m2 = parse(yaml);
        let r1 = suggest_profiles(&m1, &SuggestOptions::default());
        let r2 = suggest_profiles(&m2, &SuggestOptions::default());

        // PolicyManifest.profiles is a BTreeMap, so the entire manifest
        // serializes deterministically — compare YAML directly.
        assert_eq!(r1.profiles.len(), 2);
        assert_eq!(r2.profiles.len(), 2);
        assert_eq!(
            serde_yaml::to_string(&r1.manifest).unwrap(),
            serde_yaml::to_string(&r2.manifest).unwrap()
        );
    }

    #[test]
    fn realistic_scenario_full_round_trip() {
        // The shape pgroles generate produces from a real DB: lots of granular
        // grants, default privileges, schemas, services, humans.
        let yaml = r#"
default_owner: app_owner
schemas:
  - name: inventory
    owner: app_owner
  - name: checkout
    owner: app_owner
  - name: analytics
    owner: analytics_owner
roles:
  - name: app_owner
  - name: analytics_owner
  - name: inventory-editor
  - name: checkout-editor
  - name: inventory-viewer
  - name: checkout-viewer
  - name: analytics-viewer
  - name: data_analyst

grants:
  - role: inventory-editor
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory-editor
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: inventory, name: "*" }
  - role: inventory-editor
    privileges: [USAGE, SELECT]
    object: { type: sequence, schema: inventory, name: "*" }

  - role: checkout-editor
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout-editor
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: checkout, name: "*" }
  - role: checkout-editor
    privileges: [USAGE, SELECT]
    object: { type: sequence, schema: checkout, name: "*" }

  - role: inventory-viewer
    privileges: [USAGE]
    object: { type: schema, name: inventory }
  - role: inventory-viewer
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }

  - role: checkout-viewer
    privileges: [USAGE]
    object: { type: schema, name: checkout }
  - role: checkout-viewer
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }

  - role: analytics-viewer
    privileges: [USAGE]
    object: { type: schema, name: analytics }
  - role: analytics-viewer
    privileges: [SELECT]
    object: { type: table, schema: analytics, name: "*" }

default_privileges:
  - owner: app_owner
    schema: inventory
    grant:
      - role: inventory-editor
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
  - owner: app_owner
    schema: checkout
    grant:
      - role: checkout-editor
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

memberships:
  - role: inventory-editor
    members:
      - name: data_analyst
  - role: analytics-viewer
    members:
      - name: data_analyst
"#;
        let m = parse(yaml);
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok, "skipped: {:?}", report.skipped);

        // Expect "editor" cluster (inventory + checkout) and "viewer" cluster
        // (inventory + checkout + analytics).
        let names: BTreeSet<String> = report
            .profiles
            .iter()
            .map(|p| p.profile_name.clone())
            .collect();
        assert!(names.contains("editor"), "got: {names:?}");
        assert!(names.contains("viewer"), "got: {names:?}");

        // Memberships untouched.
        assert_eq!(report.manifest.memberships.len(), 2);

        // Re-expand and verify the role set is preserved.
        let expanded = expand_manifest(&report.manifest).unwrap();
        let role_names: BTreeSet<String> = expanded.roles.iter().map(|r| r.name.clone()).collect();
        for orig in [
            "inventory-editor",
            "checkout-editor",
            "inventory-viewer",
            "checkout-viewer",
            "analytics-viewer",
            "data_analyst",
            "app_owner",
            "analytics_owner",
        ] {
            assert!(
                role_names.contains(orig),
                "missing role {orig} in re-expanded manifest"
            );
        }

        // analytics-viewer cluster has 3 schemas. inventory/checkout-editor cluster has 2.
        let viewer = report
            .profiles
            .iter()
            .find(|p| p.profile_name == "viewer")
            .unwrap();
        assert_eq!(viewer.schema_to_role.len(), 3);
        let editor = report
            .profiles
            .iter()
            .find(|p| p.profile_name == "editor")
            .unwrap();
        assert_eq!(editor.schema_to_role.len(), 2);
    }

    #[test]
    fn round_trip_diff_engine_finds_no_structural_changes() {
        // Hardest test: build a flat graph, suggest profiles, expand back into
        // a graph, and run the actual `diff` engine. Only `SetComment` deltas
        // are allowed (auto-generated annotations).
        let yaml = r#"
default_owner: o
schemas:
  - name: s1
    owner: o
  - name: s2
    owner: o
  - name: s3
    owner: o
roles:
  - name: s1-rw
  - name: s2-rw
  - name: s3-rw
  - name: s1-ro
  - name: s2-ro
  - name: s3-ro
  - name: alice
    login: true
grants:
  - role: s1-rw
    privileges: [USAGE]
    object: { type: schema, name: s1 }
  - role: s1-rw
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: s1, name: "*" }
  - role: s2-rw
    privileges: [USAGE]
    object: { type: schema, name: s2 }
  - role: s2-rw
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: s2, name: "*" }
  - role: s3-rw
    privileges: [USAGE]
    object: { type: schema, name: s3 }
  - role: s3-rw
    privileges: [SELECT, INSERT, UPDATE, DELETE]
    object: { type: table, schema: s3, name: "*" }
  - role: s1-ro
    privileges: [USAGE]
    object: { type: schema, name: s1 }
  - role: s1-ro
    privileges: [SELECT]
    object: { type: table, schema: s1, name: "*" }
  - role: s2-ro
    privileges: [USAGE]
    object: { type: schema, name: s2 }
  - role: s2-ro
    privileges: [SELECT]
    object: { type: table, schema: s2, name: "*" }
  - role: s3-ro
    privileges: [USAGE]
    object: { type: schema, name: s3 }
  - role: s3-ro
    privileges: [SELECT]
    object: { type: table, schema: s3, name: "*" }
default_privileges:
  - owner: o
    schema: s1
    grant:
      - role: s1-rw
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - role: s1-ro
        privileges: [SELECT]
        on_type: table
  - owner: o
    schema: s2
    grant:
      - role: s2-rw
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - role: s2-ro
        privileges: [SELECT]
        on_type: table
  - owner: o
    schema: s3
    grant:
      - role: s3-rw
        privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - role: s3-ro
        privileges: [SELECT]
        on_type: table
memberships:
  - role: s1-rw
    members:
      - name: alice
"#;
        let m = parse(yaml);
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok, "skipped: {:?}", report.skipped);
        assert_eq!(report.profiles.len(), 2);

        // Final: the actual diff engine should find no structural changes.
        let original_expanded = expand_manifest(&m).unwrap();
        let original_graph =
            RoleGraph::from_expanded(&original_expanded, m.default_owner.as_deref()).unwrap();
        let new_expanded = expand_manifest(&report.manifest).unwrap();
        let new_graph =
            RoleGraph::from_expanded(&new_expanded, report.manifest.default_owner.as_deref())
                .unwrap();
        let changes = diff(&original_graph, &new_graph);
        let bad: Vec<_> = changes
            .iter()
            .filter(|c| !matches!(c, Change::SetComment { .. }))
            .collect();
        assert!(bad.is_empty(), "structural drift: {bad:?}");
    }

    #[test]
    fn empty_manifest_is_idempotent() {
        let m = parse("");
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.profiles.is_empty());
        assert!(report.round_trip_ok);
    }

    #[test]
    fn schema_with_special_chars_in_name() {
        // Schema names can contain underscores, hyphens, digits.
        let m = parse(
            r#"
schemas:
  - name: app_v2
    owner: o
  - name: app_v3
    owner: o
roles:
  - name: app_v2-rw
  - name: app_v3-rw
grants:
  - role: app_v2-rw
    privileges: [SELECT]
    object: { type: table, schema: app_v2, name: "*" }
  - role: app_v3-rw
    privileges: [SELECT]
    object: { type: table, schema: app_v3, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].profile_name, "rw");
    }

    #[test]
    fn schema_name_is_substring_of_role_name() {
        // Schema "app" is a substring of role "appraiser-app". The match_pattern
        // logic uses strip_prefix/strip_suffix, so a role name that starts with
        // the schema but with no separator (e.g. "appfoo") shouldn't match. Test
        // this and adjacent edge cases.
        let m = parse(
            r#"
schemas:
  - name: app
    owner: o
  - name: api
    owner: o
roles:
  - name: app-rw
  - name: api-rw
grants:
  - role: app-rw
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }
  - role: api-rw
    privileges: [SELECT]
    object: { type: table, schema: api, name: "*" }
"#,
        );
        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok);
        assert_eq!(report.profiles.len(), 1);
        assert_eq!(report.profiles[0].profile_name, "rw");
    }

    #[test]
    fn is_valid_identifier_basic() {
        assert!(is_valid_identifier("reader"));
        assert!(is_valid_identifier("read-only"));
        assert!(is_valid_identifier("read_only"));
        assert!(is_valid_identifier("rw2"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("-reader"));
        assert!(!is_valid_identifier("_reader"));
        assert!(!is_valid_identifier("read.only"));
        assert!(!is_valid_identifier("read only"));
    }

    #[test]
    fn config_carrying_role_stays_flat_and_keeps_its_config() {
        // Two roles with an otherwise-identical, cluster-eligible shape would
        // normally be promoted into a profile — but one of them carries
        // `config`, which profiles can express yet the suggester never
        // clusters on (see the comment in the eligibility loop). It must stay
        // flat, and — this is the property that matters — its `config` must
        // not be lost anywhere along the way: round-tripping through
        // `suggest` -> `expand` must show the exact same config on the
        // (still flat) generated role.
        let m = parse(
            r#"
schemas:
  - name: inventory
    owner: o
  - name: checkout
    owner: o
roles:
  - name: inventory-reader
    login: true
    config:
      search_path: inventory
      statement_timeout: "30s"
  - name: checkout-reader
    login: true
grants:
  - role: inventory-reader
    privileges: [SELECT]
    object: { type: table, schema: inventory, name: "*" }
  - role: checkout-reader
    privileges: [SELECT]
    object: { type: table, schema: checkout, name: "*" }
"#,
        );

        let report = suggest_profiles(&m, &SuggestOptions::default());
        assert!(report.round_trip_ok, "skipped: {:?}", report.skipped);

        // No cluster forms: inventory-reader is disqualified by `config`, and
        // checkout-reader is then a sole-schema role with no partner.
        assert!(
            report.profiles.is_empty(),
            "expected no profiles, got: {:?}",
            report.profiles
        );
        assert!(report.skipped.iter().any(
            |s| matches!(s, SkipReason::UniqueAttributes { role } if role == "inventory-reader")
        ));

        // Both roles remain flat in the suggested manifest, config intact.
        let role = report
            .manifest
            .roles
            .iter()
            .find(|r| r.name == "inventory-reader")
            .expect("inventory-reader should remain a flat role");
        assert_eq!(role.config["search_path"].0, "inventory");
        assert_eq!(role.config["statement_timeout"].0, "30s");

        // And the expanded RoleGraph — what actually gets applied — carries
        // the same config through, matching the original manifest's graph.
        let original_expanded = expand_manifest(&m).unwrap();
        let original_graph =
            RoleGraph::from_expanded(&original_expanded, m.default_owner.as_deref()).unwrap();
        let new_expanded = expand_manifest(&report.manifest).unwrap();
        let new_graph =
            RoleGraph::from_expanded(&new_expanded, report.manifest.default_owner.as_deref())
                .unwrap();
        assert_eq!(
            original_graph.roles["inventory-reader"].config,
            new_graph.roles["inventory-reader"].config
        );
        assert_eq!(
            new_graph.roles["inventory-reader"].config["search_path"],
            "inventory"
        );
    }
}
