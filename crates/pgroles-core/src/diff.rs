//! Convergent diff engine.
//!
//! Compares two [`RoleGraph`] instances (current vs desired) and produces an
//! ordered list of [`Change`] operations needed to bring the database from
//! its current state to the desired state.
//!
//! The model is convergent: anything present in the current state but absent
//! from the desired state is revoked/dropped. This is the Terraform-style
//! "manifest is the entire truth" approach.

use std::collections::{BTreeMap, BTreeSet};

use crate::manifest::{
    Membership, ObjectType, Privilege, RoleDefinition, RoleRetirement, is_predefined_role,
};
use crate::model::{
    DefaultPrivKey, DefaultPrivilegeScope, GrantKey, Grantee, MembershipEdge, RoleAttribute,
    RoleGraph, RoleState, default_schema_owner_privileges,
};

// ---------------------------------------------------------------------------
// Change enum
// ---------------------------------------------------------------------------

/// A single change to be applied to the database.
///
/// Changes are produced in dependency order by [`diff`]:
/// 1. Create roles (before granting anything to them)
/// 2. Alter roles (attribute changes)
/// 3. Grant privileges
/// 4. Set default privileges
/// 5. Revoke privileges (before membership removals: a grantor-targeted
///    revoke runs `SET ROLE <grantor>`, and removing memberships first could
///    strip the executor's path to that grantor mid-plan)
/// 6. Remove memberships
/// 7. Add memberships
/// 8. Revoke default privileges
/// 9. Drop roles (after revoking everything from them)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Change {
    /// Create a new role with the given attributes.
    CreateRole { name: String, state: RoleState },

    /// Create a schema, optionally assigning an owner up front.
    CreateSchema { name: String, owner: Option<String> },

    /// Change an existing schema's owner.
    AlterSchemaOwner { name: String, owner: String },

    /// Restore the schema owner's ordinary CREATE/USAGE privileges.
    EnsureSchemaOwnerPrivileges {
        name: String,
        owner: String,
        privileges: BTreeSet<Privilege>,
    },

    /// Alter an existing role's attributes.
    AlterRole {
        name: String,
        attributes: Vec<RoleAttribute>,
    },

    /// Update a role's comment (via COMMENT ON ROLE).
    SetComment {
        name: String,
        comment: Option<String>,
    },

    /// Grant privileges on an object to a grantee.
    Grant {
        role: Grantee,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },

    /// Revoke privileges on an object from a grantee.
    ///
    /// `grantor` targets the ACL entry to remove. PostgreSQL's plain REVOKE
    /// removes only the entry of the one grantor it selects for the executor
    /// (a superuser acts as the owner), so an entry attributed to another
    /// grantor survives silently — rendering the revoke as
    /// `SET ROLE <grantor>; REVOKE ...;` (restoring the connection's
    /// configured execution role, or `RESET ROLE` when none is set) removes
    /// exactly the inspected entry (it requires the executor to be able to
    /// become the grantor, which the preflight checks). `None` renders a plain REVOKE:
    /// grantor-less inspection and desired-side callers. Skipped in
    /// serialization when `None`, so digests and JSON output of grantor-less
    /// plans are unchanged.
    Revoke {
        role: Grantee,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        grantor: Option<String>,
    },

    /// Set default privileges (ALTER DEFAULT PRIVILEGES ... GRANT ...).
    SetDefaultPrivilege {
        owner: String,
        scope: DefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: Grantee,
        privileges: BTreeSet<Privilege>,
    },

    /// Revoke default privileges (ALTER DEFAULT PRIVILEGES ... REVOKE ...).
    RevokeDefaultPrivilege {
        owner: String,
        scope: DefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: Grantee,
        privileges: BTreeSet<Privilege>,
    },

    /// Grant membership (GRANT role TO member).
    AddMember {
        role: String,
        member: String,
        inherit: bool,
        admin: bool,
    },

    /// Revoke membership (REVOKE role FROM member).
    ///
    /// `grantor` targets the specific membership edge to remove. Since
    /// PostgreSQL 16 each edge records its grantor and a plain REVOKE removes
    /// only the edge attributed to the revoker, so an edge granted by someone
    /// else survives with just a WARNING — rendering `GRANTED BY <grantor>`
    /// removes exactly the inspected edge instead (it requires the grantor's
    /// privileges, which the preflight checks). `None` renders a plain
    /// REVOKE: pre-16 servers (no per-edge attribution) and callers without
    /// grantor knowledge. Skipped in serialization when `None`, so digests
    /// and JSON output of grantor-less plans are unchanged.
    RemoveMember {
        role: String,
        member: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        grantor: Option<String>,
    },

    /// Reassign owned objects to a successor role before drop.
    ReassignOwned { from_role: String, to_role: String },

    /// Drop owned objects and revoke remaining privileges before drop.
    DropOwned { role: String },

    /// Terminate other active sessions before dropping a role.
    TerminateSessions { role: String },

    /// Set a role's password using a SCRAM-SHA-256 verifier.
    ///
    /// The `password` field contains a pre-computed SCRAM-SHA-256 verifier
    /// string (not cleartext). PostgreSQL detects the `SCRAM-SHA-256$` prefix
    /// and stores it directly without re-hashing.
    ///
    /// This change is injected by [`inject_password_changes`] after the core
    /// diff engine runs. The diff engine itself does not handle passwords
    /// because they cannot be read back from the database for comparison.
    SetPassword { name: String, password: String },

    /// Drop a role.
    DropRole { name: String },
}

// ---------------------------------------------------------------------------
// Reconciliation modes
// ---------------------------------------------------------------------------

/// Controls how aggressively pgroles converges the database to the manifest.
///
/// The diff engine always computes the full set of changes. The reconciliation
/// mode acts as a **post-filter** on the resulting `Vec<Change>`, stripping
/// out changes that the operator does not want applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum ReconciliationMode {
    /// Full convergence — the manifest is the entire truth.
    ///
    /// All changes (creates, alters, grants, revokes, drops) are applied.
    /// Anything present in the database but absent from the manifest is
    /// revoked or dropped.
    #[default]
    Authoritative,

    /// Only grant, never revoke — safe for incremental adoption.
    ///
    /// Additive mode filters out all destructive changes:
    /// - `Revoke` / `RevokeDefaultPrivilege`
    /// - `RemoveMember`
    /// - `DropRole` and its retirement steps (`TerminateSessions`,
    ///   `ReassignOwned`, `DropOwned`)
    ///
    /// Use this when onboarding pgroles into an existing environment where
    /// you want to guarantee that no existing access is removed.
    Additive,

    /// Manage declared resources fully, but never drop undeclared roles.
    ///
    /// Adopt mode is identical to authoritative **except** that it filters out
    /// `DropRole` and associated retirement steps (`TerminateSessions`,
    /// `ReassignOwned`, `DropOwned`). Revokes within the managed scope are
    /// still applied.
    ///
    /// Use this for brownfield onboarding where you want full privilege
    /// convergence for declared roles but don't want pgroles to drop roles
    /// it doesn't know about.
    Adopt,
}

impl std::fmt::Display for ReconciliationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconciliationMode::Authoritative => write!(f, "authoritative"),
            ReconciliationMode::Additive => write!(f, "additive"),
            ReconciliationMode::Adopt => write!(f, "adopt"),
        }
    }
}

/// Filter a list of changes according to the reconciliation mode.
///
/// - **Authoritative**: returns all changes unmodified.
/// - **Additive**: strips revokes, membership removals, owner transfers,
///   role rewrites, role drops, and retirement cleanup steps.
/// - **Adopt**: strips role drops and retirement cleanup steps, but keeps
///   revokes and membership removals.
pub fn filter_changes(changes: Vec<Change>, mode: ReconciliationMode) -> Vec<Change> {
    match mode {
        ReconciliationMode::Authoritative => changes,
        ReconciliationMode::Additive => filter_additive_changes(changes),
        ReconciliationMode::Adopt => changes
            .into_iter()
            .filter(|change| !is_role_drop_or_retirement(change))
            .collect(),
    }
}

/// Whether additive reconciliation will ignore declarative absence assertions.
///
/// The desired graph retains absence assertions — `ensure: absent` grants and
/// default privileges, and `exclusive: true` membership stanzas — even though
/// [`filter_changes`] removes their revocations in additive mode. Callers use
/// this predicate to make that safety-relevant no-op visible before presenting
/// or applying a filtered plan.
pub fn additive_ignores_absence_assertions(desired: &RoleGraph, mode: ReconciliationMode) -> bool {
    mode == ReconciliationMode::Additive
        && (!desired.grant_absences.is_empty()
            || !desired.default_privilege_absences.is_empty()
            || !desired.exclusive_membership_roles.is_empty())
}

/// Remove changes pgroles must not own for external and predefined roles.
///
/// External (`external: true`) and predefined (`pg_*`) roles are valid
/// references for grants, schema ownership, and memberships, but their role
/// object is owned elsewhere: lifecycle changes (create/alter/drop, comments,
/// passwords, retirement operations) are always filtered.
///
/// Memberships granted *from* such a role follow declared intent:
///
/// - An edge declared in the manifest converges — grants, and the
///   revoke-and-regrant pair when its `inherit`/`admin` options change.
/// - An undeclared live member is left untouched by default, so adopting
///   pgroles never strips provider-granted memberships (for example
///   `pg_monitor` grants made by a cloud platform).
/// - A membership stanza with `exclusive: true` asserts its member list is
///   complete, opting undeclared members into revocation — except members
///   that are themselves predefined roles: PostgreSQL ships built-in
///   `pg_*` → `pg_*` edges (for example `pg_monitor`'s membership in
///   `pg_read_all_stats`), and revoking those would break the built-in
///   hierarchy cluster-wide.
pub fn filter_external_role_changes(
    changes: Vec<Change>,
    roles: &[RoleDefinition],
    memberships: &[Membership],
) -> Vec<Change> {
    let external_roles: BTreeSet<&str> = roles
        .iter()
        .filter(|role| role.external)
        .map(|role| role.name.as_str())
        .collect();
    let exclusive_roles: BTreeSet<&str> = memberships
        .iter()
        .filter(|membership| membership.exclusive)
        .map(|membership| membership.role.as_str())
        .collect();
    let declared_edges: BTreeSet<(&str, &str)> = memberships
        .iter()
        .flat_map(|membership| {
            membership
                .members
                .iter()
                .map(move |member| (membership.role.as_str(), member.name.as_str()))
        })
        .collect();

    let unmanaged = |name: &str| external_roles.contains(name) || is_predefined_role(name);

    changes
        .into_iter()
        .filter(|change| match change {
            Change::CreateRole { name, .. }
            | Change::AlterRole { name, .. }
            | Change::SetComment { name, .. }
            | Change::SetPassword { name, .. }
            | Change::DropRole { name } => !unmanaged(name),
            Change::TerminateSessions { role }
            | Change::DropOwned { role }
            | Change::ReassignOwned {
                from_role: role, ..
            } => !unmanaged(role),
            Change::AddMember { role, member, .. } => {
                !unmanaged(role) || declared_edges.contains(&(role.as_str(), member.as_str()))
            }
            Change::RemoveMember { role, member, .. } => {
                !unmanaged(role)
                    || declared_edges.contains(&(role.as_str(), member.as_str()))
                    || (exclusive_roles.contains(role.as_str()) && !is_predefined_role(member))
            }
            _ => true,
        })
        .collect()
}

/// Drop object-grant revokes against roles that declare `preserve_undeclared_grants`.
///
/// The flag marks a brownfield role whose grant surface pgroles should adopt
/// before it is fully declared: missing declared privileges are granted, and
/// undeclared object grants in scope are preserved — including excess
/// privileges on grant targets the manifest does declare. Default-privilege
/// revocations, memberships, and other changes are unaffected. Explicit
/// `ensure: absent` assertions still apply — an asserted absence is a
/// declaration, not drift discovery.
pub fn filter_preserved_grant_revokes(
    changes: Vec<Change>,
    roles: &[RoleDefinition],
    desired: &RoleGraph,
) -> Vec<Change> {
    let preserved: BTreeSet<&str> = roles
        .iter()
        .filter(|role| role.preserve_undeclared_grants)
        .map(|role| role.name.as_str())
        .collect();

    if preserved.is_empty() {
        return changes;
    }

    changes
        .into_iter()
        .flat_map(|change| {
            let Change::Revoke {
                role,
                privileges,
                object_type,
                schema,
                name,
                grantor,
            } = &change
            else {
                return vec![change];
            };
            if !preserved.contains(role.as_str()) {
                return vec![change];
            }
            let key = crate::model::GrantKey {
                role: role.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            };

            let wildcard_key = crate::model::GrantKey {
                name: Some("*".to_string()),
                ..key.clone()
            };
            let wildcard_enforced = desired
                .grant_absences
                .get(&wildcard_key)
                .map(|absent| {
                    privileges
                        .intersection(absent)
                        .copied()
                        .collect::<BTreeSet<Privilege>>()
                })
                .unwrap_or_default();

            if name.as_deref() != Some("*") {
                let mut enforced = wildcard_enforced;
                if let Some(absent) = desired.grant_absences.get(&key) {
                    enforced.extend(privileges.intersection(absent).copied());
                }
                return (!enforced.is_empty())
                    .then(|| Change::Revoke {
                        role: role.clone(),
                        privileges: enforced,
                        object_type: *object_type,
                        schema: schema.clone(),
                        name: name.clone(),
                        grantor: grantor.clone(),
                    })
                    .into_iter()
                    .collect();
            }

            // Inspection can normalize privileges held on every object into
            // one wildcard key, while an absence assertion still names one
            // object. Keep a wildcard revoke only for wildcard assertions;
            // split exact assertions back into exact revokes so preservation
            // neither discards them nor broadens them to the whole schema.
            let mut enforced = Vec::new();
            if !wildcard_enforced.is_empty() {
                enforced.push(Change::Revoke {
                    role: role.clone(),
                    privileges: wildcard_enforced.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: name.clone(),
                    grantor: grantor.clone(),
                });
            }
            for (absence_key, absent) in &desired.grant_absences {
                if absence_key.role != *role
                    || absence_key.object_type != *object_type
                    || absence_key.schema != *schema
                    || absence_key.name.as_deref().is_none_or(|value| value == "*")
                {
                    continue;
                }
                let exact: BTreeSet<Privilege> = privileges
                    .intersection(absent)
                    .copied()
                    .filter(|privilege| !wildcard_enforced.contains(privilege))
                    .collect();
                if !exact.is_empty() {
                    enforced.push(Change::Revoke {
                        role: role.clone(),
                        privileges: exact,
                        object_type: *object_type,
                        schema: schema.clone(),
                        name: absence_key.name.clone(),
                        grantor: grantor.clone(),
                    });
                }
            }
            enforced
        })
        .collect()
}

/// Messages for `ensure: absent` assertions that can never converge because
/// the asserted-against grantee owns the target object — its privileges are
/// inherent. Exact keys are detected directly; wildcard assertions warn when
/// they overlap any inherently-held entry under their (role, type, schema).
pub fn unenforceable_absence_warnings(current: &RoleGraph, desired: &RoleGraph) -> Vec<String> {
    let mut out = Vec::new();
    for (key, absent) in &desired.grant_absences {
        if key.name.as_deref() == Some("*") {
            let range_start = GrantKey {
                role: key.role.clone(),
                object_type: key.object_type,
                schema: key.schema.clone(),
                name: None,
            };
            for (held_key, state) in current.grants.range(range_start..).take_while(|(k, _)| {
                k.role == key.role && k.object_type == key.object_type && k.schema == key.schema
            }) {
                if current.inherent_grants.contains(held_key)
                    && state
                        .privileges
                        .iter()
                        .any(|privilege| absent.contains(privilege))
                {
                    out.push(format!(
                        "ensure: absent of {} on {} \"{}\".\"*\" for \"{}\" cannot be fully enforced — the grantee owns some covered objects, so those privileges are inherent",
                        crate::sql::format_privileges(absent),
                        key.object_type,
                        key.schema.as_deref().unwrap_or(""),
                        key.role.as_str()
                    ));
                    break;
                }
            }
        } else if current.inherent_grants.contains(key)
            && current.grants.get(key).is_some_and(|state| {
                state
                    .privileges
                    .iter()
                    .any(|privilege| absent.contains(privilege))
            })
        {
            out.push(format!(
                "ensure: absent of {} on {} for \"{}\" cannot be enforced — the grantee owns the object, so those privileges are inherent",
                crate::sql::format_privileges(absent),
                key.object_type,
                key.role.as_str()
            ));
        }
    }
    out
}

fn filter_additive_changes(changes: Vec<Change>) -> Vec<Change> {
    let skipped_owner_transfers: BTreeSet<(String, String)> = changes
        .iter()
        .filter_map(|change| match change {
            Change::AlterSchemaOwner { name, owner } => Some((name.clone(), owner.clone())),
            _ => None,
        })
        .collect();

    // Roles created in this same plan: their config-only follow-up alters are
    // part of the creation, not a mutation of a pre-existing role, so
    // additive mode keeps them.
    let created_roles: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::CreateRole { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();

    changes
        .into_iter()
        .filter(|change| match change {
            Change::EnsureSchemaOwnerPrivileges { name, owner, .. } => {
                !skipped_owner_transfers.contains(&(name.clone(), owner.clone()))
            }
            Change::SetDefaultPrivilege {
                scope: DefaultPrivilegeScope::Schema { schema },
                owner,
                ..
            } => !skipped_owner_transfers.contains(&(schema.clone(), owner.clone())),
            Change::AlterRole { name, attributes } => {
                created_roles.contains(name)
                    && attributes
                        .iter()
                        .all(|attr| matches!(attr, RoleAttribute::SetConfig(..)))
            }
            Change::SetComment { .. } => false,
            _ => !is_destructive(change),
        })
        .collect()
}

/// Returns `true` for any change that removes access or drops a role.
fn is_destructive(change: &Change) -> bool {
    matches!(
        change,
        Change::AlterSchemaOwner { .. }
            | Change::Revoke { .. }
            | Change::RevokeDefaultPrivilege { .. }
            | Change::RemoveMember { .. }
            | Change::DropRole { .. }
            | Change::DropOwned { .. }
            | Change::ReassignOwned { .. }
            | Change::TerminateSessions { .. }
    )
}

/// Returns `true` for role drops and their associated retirement cleanup steps.
fn is_role_drop_or_retirement(change: &Change) -> bool {
    matches!(
        change,
        Change::DropRole { .. }
            | Change::DropOwned { .. }
            | Change::ReassignOwned { .. }
            | Change::TerminateSessions { .. }
    )
}

// ---------------------------------------------------------------------------
// Diff function
// ---------------------------------------------------------------------------

/// Compute the list of changes needed to bring `current` to `desired`.
///
/// Changes are ordered so that dependencies are respected:
/// creates before grants, revokes before drops, etc.
pub fn diff(current: &RoleGraph, desired: &RoleGraph) -> Vec<Change> {
    let mut creates = Vec::new();
    let mut alters = Vec::new();
    let mut schema_changes = Vec::new();
    let mut schema_grants = Vec::new();
    let mut grants = Vec::new();
    let mut set_defaults = Vec::new();
    let mut add_members = Vec::new();
    let mut remove_members = Vec::new();
    let mut revoke_defaults = Vec::new();
    let mut revokes = Vec::new();
    let mut drops = Vec::new();

    // ----- Roles -----

    // Roles in desired but not in current → CREATE
    for (name, desired_state) in &desired.roles {
        match current.roles.get(name) {
            None => {
                creates.push(Change::CreateRole {
                    name: name.clone(),
                    state: desired_state.clone(),
                });
                // Config defaults are applied as a follow-up alter so the
                // statements land after all CREATE ROLEs — a `role` setting
                // may reference another role created in this same plan.
                if !desired_state.config.is_empty() {
                    alters.push(Change::AlterRole {
                        name: name.clone(),
                        attributes: desired_state
                            .config
                            .iter()
                            .map(|(parameter, value)| {
                                RoleAttribute::SetConfig(parameter.clone(), value.clone())
                            })
                            .collect(),
                    });
                }
            }
            Some(current_state) => {
                // Role exists — check for attribute changes
                let attribute_changes = current_state.changed_attributes(desired_state);
                if !attribute_changes.is_empty() {
                    alters.push(Change::AlterRole {
                        name: name.clone(),
                        attributes: attribute_changes,
                    });
                }
                // Check comment change
                if current_state.comment != desired_state.comment {
                    alters.push(Change::SetComment {
                        name: name.clone(),
                        comment: desired_state.comment.clone(),
                    });
                }
            }
        }
    }

    // Roles in current but not in desired → DROP
    for name in current.roles.keys() {
        if !desired.roles.contains_key(name) {
            drops.push(Change::DropRole { name: name.clone() });
        }
    }

    // ----- Schemas -----

    diff_schemas(current, desired, &mut schema_changes, &mut schema_grants);

    // ----- Grants -----

    diff_grants(current, desired, &mut grants, &mut revokes);

    // ----- Default privileges -----

    diff_default_privileges(current, desired, &mut set_defaults, &mut revoke_defaults);

    // ----- Memberships -----

    diff_memberships(current, desired, &mut add_members, &mut remove_members);

    // A schema-owner transfer absorbs the incoming owner's pre-existing
    // explicit ACL entry into the new owner entry (`ALTER SCHEMA ... OWNER TO
    // z` merges `z=U/old` into `z=UC/z`). A revoke planned against that stale
    // explicit grant would therefore strip the NEW OWNER's privilege — the
    // single-pass convergence bug in issue #140. Suppress schema revokes whose
    // grantee is the schema's incoming owner in this same plan; the follow-up
    // inspection folds the owner's privileges into `SchemaState`, so the
    // suppressed revoke's target no longer exists as an explicit grant.
    let incoming_owners: BTreeSet<(&str, &str)> = schema_changes
        .iter()
        .filter_map(|change| match change {
            Change::AlterSchemaOwner { name, owner } => Some((name.as_str(), owner.as_str())),
            _ => None,
        })
        .collect();
    if !incoming_owners.is_empty() {
        revokes.retain(|change| match change {
            Change::Revoke {
                role,
                object_type: ObjectType::Schema,
                name: Some(schema_name),
                ..
            } => !incoming_owners.contains(&(schema_name.as_str(), role.as_str())),
            _ => true,
        });
    }

    // ----- Assemble in dependency order -----
    let mut changes = Vec::new();
    changes.extend(creates);
    changes.extend(alters);
    changes.extend(schema_changes);
    changes.extend(schema_grants);
    changes.extend(grants);
    changes.extend(set_defaults);
    // Object revokes run before membership removals: a grantor-targeted
    // revoke becomes its grantor via `SET ROLE`, and the preflight verifies
    // that against the *current* membership graph — an earlier membership
    // removal in the same plan could strip that path mid-transaction.
    changes.extend(revokes);
    changes.extend(remove_members);
    changes.extend(add_members);
    changes.extend(revoke_defaults);
    changes.extend(drops);
    changes
}

fn diff_schemas(
    current: &RoleGraph,
    desired: &RoleGraph,
    schema_out: &mut Vec<Change>,
    grant_out: &mut Vec<Change>,
) {
    for (name, desired_state) in &desired.schemas {
        let owner_changed = current
            .schemas
            .get(name)
            .is_some_and(|current_state| current_state.owner != desired_state.owner);
        match current.schemas.get(name) {
            None => schema_out.push(Change::CreateSchema {
                name: name.clone(),
                owner: desired_state.owner.clone(),
            }),
            Some(current_state) => {
                if current_state.owner != desired_state.owner
                    && let Some(owner) = &desired_state.owner
                {
                    schema_out.push(Change::AlterSchemaOwner {
                        name: name.clone(),
                        owner: owner.clone(),
                    });
                }
            }
        }

        let Some(owner) = desired_state.owner.as_deref() else {
            continue;
        };

        if !current.schemas.contains_key(name) {
            continue;
        }

        let expected_privileges = default_schema_owner_privileges(owner);
        // Inspected owner privileges belong to the current owner. They say
        // nothing about the ACL entry PostgreSQL will retain or merge for an
        // incoming owner, and that transfer behavior differs across supported
        // server versions. Reassert the complete owner privilege set after a
        // transfer instead of comparing the new owner against the old owner's
        // privileges.
        let current_privileges = if owner_changed {
            BTreeSet::new()
        } else {
            current
                .schemas
                .get(name)
                .map(|state| state.owner_privileges.clone())
                .unwrap_or_default()
        };
        let missing_privileges: BTreeSet<Privilege> = expected_privileges
            .difference(&current_privileges)
            .copied()
            .collect();

        if !missing_privileges.is_empty() {
            grant_out.push(Change::EnsureSchemaOwnerPrivileges {
                name: name.clone(),
                owner: owner.to_string(),
                privileges: missing_privileges,
            });
        }
    }
}

/// Augment a diff plan with explicit role-retirement actions.
///
/// Retirement steps are inserted immediately before the matching `DropRole`
/// so the final plan remains dependency-safe:
/// `TERMINATE SESSIONS` → `REASSIGN OWNED` → `DROP OWNED` → `DROP ROLE`.
pub fn apply_role_retirements(changes: Vec<Change>, retirements: &[RoleRetirement]) -> Vec<Change> {
    if retirements.is_empty() {
        return changes;
    }

    let retirement_by_role: std::collections::BTreeMap<&str, &RoleRetirement> = retirements
        .iter()
        .map(|retirement| (retirement.role.as_str(), retirement))
        .collect();

    let mut planned = Vec::with_capacity(changes.len());
    for change in changes {
        if let Change::DropRole { name } = &change
            && let Some(retirement) = retirement_by_role.get(name.as_str())
        {
            if retirement.terminate_sessions {
                planned.push(Change::TerminateSessions { role: name.clone() });
            }
            if let Some(successor) = &retirement.reassign_owned_to {
                planned.push(Change::ReassignOwned {
                    from_role: name.clone(),
                    to_role: successor.clone(),
                });
            }
            if retirement.drop_owned {
                planned.push(Change::DropOwned { role: name.clone() });
            }
        }
        planned.push(change);
    }

    planned
}

// ---------------------------------------------------------------------------
// Password injection
// ---------------------------------------------------------------------------

/// Resolve password sources from environment variables.
///
/// Returns a map of role name → resolved password for every managed role that
/// declares a `password.from_env` source. External roles are reference-only and
/// never participate in password management.
#[cfg(feature = "passwords")]
pub fn resolve_passwords(
    roles: &[crate::manifest::RoleDefinition],
) -> Result<std::collections::BTreeMap<String, String>, PasswordResolutionError> {
    let mut resolved = std::collections::BTreeMap::new();
    for role in roles {
        if role.external {
            continue;
        }
        if let Some(source) = &role.password {
            let value = std::env::var(&source.from_env).map_err(|_| {
                PasswordResolutionError::MissingEnvVar {
                    role: role.name.clone(),
                    env_var: source.from_env.clone(),
                }
            })?;
            if value.is_empty() {
                return Err(PasswordResolutionError::EmptyPassword {
                    role: role.name.clone(),
                    env_var: source.from_env.clone(),
                });
            }
            resolved.insert(role.name.clone(), value);
        }
    }
    Ok(resolved)
}

/// Errors that can occur during password resolution.
#[cfg(feature = "passwords")]
#[derive(Debug, thiserror::Error)]
pub enum PasswordResolutionError {
    #[error("environment variable \"{env_var}\" for role \"{role}\" password is not set")]
    MissingEnvVar { role: String, env_var: String },

    #[error("environment variable \"{env_var}\" for role \"{role}\" password is empty")]
    EmptyPassword { role: String, env_var: String },
}

/// Inject `SetPassword` changes into a plan for roles that declare passwords.
///
/// For newly created roles, the `SetPassword` is inserted immediately after the
/// `CreateRole`. For existing roles with a password source, a `SetPassword` is
/// appended after all creates/alters (ensuring the role exists).
///
/// Cleartext passwords are converted to SCRAM-SHA-256 verifiers before being
/// placed in `SetPassword` changes, so the cleartext never appears in generated
/// SQL. PostgreSQL detects the `SCRAM-SHA-256$` prefix and stores the verifier
/// directly.
///
/// This function should be called after `diff()` and `apply_role_retirements()`.
#[cfg(feature = "passwords")]
pub fn inject_password_changes(
    changes: Vec<Change>,
    resolved_passwords: &std::collections::BTreeMap<String, String>,
) -> Vec<Change> {
    if resolved_passwords.is_empty() {
        return changes;
    }

    // Track which roles have CreateRole in the plan (newly created roles).
    let created_roles: std::collections::BTreeSet<String> = changes
        .iter()
        .filter_map(|c| match c {
            Change::CreateRole { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();

    let mut result = Vec::with_capacity(changes.len() + resolved_passwords.len());

    // Insert SetPassword immediately after CreateRole for new roles.
    for change in changes {
        if let Change::CreateRole { ref name, .. } = change
            && let Some(password) = resolved_passwords.get(name.as_str())
        {
            let role_name = name.clone();
            let verifier =
                crate::scram::compute_verifier(password, crate::scram::DEFAULT_ITERATIONS);
            result.push(change);
            result.push(Change::SetPassword {
                name: role_name,
                password: verifier,
            });
            continue;
        }
        result.push(change);
    }

    // For existing roles (not newly created), append SetPassword after all creates/alters.
    for (role_name, password) in resolved_passwords {
        if !created_roles.contains(role_name) {
            let verifier =
                crate::scram::compute_verifier(password, crate::scram::DEFAULT_ITERATIONS);
            result.push(Change::SetPassword {
                name: role_name.clone(),
                password: verifier,
            });
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Grant diffing
// ---------------------------------------------------------------------------

fn diff_grants(
    current: &RoleGraph,
    desired: &RoleGraph,
    grants_out: &mut Vec<Change>,
    revokes_out: &mut Vec<Change>,
) {
    // Index desired wildcard grants for shadow-revoke filtering below. A
    // desired wildcard `(role, schema, type, "*")` declares "every object of
    // this type in this schema gets these privileges", so for any per-name
    // entry surviving in `current` for the same (role, schema, type), the
    // wildcard's privileges are implicitly covered. Revoking those privileges
    // per-name would just be undone by the wildcard GRANT in the same plan
    // — and because GRANTs are applied before REVOKEs, the net effect is to
    // strip privileges from exactly the objects the inspector knew about,
    // leaving the recently-recreated objects with grants. The next reconcile
    // observes the inverted set, and the controller flaps forever.
    //
    // The shadowing applies to BOTH branches that produce per-name REVOKEs:
    //   - the matched-key branch (desired and current both have the per-name
    //     entry, e.g. desired=`widgets:INSERT` plus wildcard `*:SELECT`,
    //     current=`widgets:SELECT+INSERT` → without filtering, `to_remove`
    //     for the matched key would be `{SELECT}` and apply would strip a
    //     privilege the wildcard still declares).
    //   - the absent-key branch (current has a per-name entry that desired
    //     covers only via wildcard).
    let desired_wildcards: BTreeMap<(&Grantee, &Option<String>, ObjectType), &BTreeSet<Privilege>> =
        desired
            .grants
            .iter()
            .filter(|(k, _)| k.name.as_deref() == Some("*") && k.schema.is_some())
            .map(|(k, v)| ((&k.role, &k.schema, k.object_type), &v.privileges))
            .collect();

    // Absence wildcards collect their own concrete revokes below. Suppress
    // the ordinary per-name path so it does not emit duplicate statements.
    let absence_wildcards: BTreeMap<(&Grantee, &Option<String>, ObjectType), &BTreeSet<Privilege>> =
        desired
            .grant_absences
            .iter()
            .filter(|(k, _)| k.name.as_deref() == Some("*") && k.schema.is_some())
            .map(|(k, v)| ((&k.role, &k.schema, k.object_type), v))
            .collect();

    // Returns the subset of `candidate` not shadowed by a desired wildcard
    // (present or absent) for the same (role, schema, type). The wildcard
    // itself is never shadowed (it has name="*", not a specific object name).
    let shadow_filter = |key: &GrantKey, candidate: BTreeSet<Privilege>| -> BTreeSet<Privilege> {
        if key.name.as_deref() == Some("*") {
            return candidate;
        }
        let mut filtered = candidate;
        let selector = (&key.role, &key.schema, key.object_type);
        if let Some(wildcard_privileges) = desired_wildcards.get(&selector) {
            filtered = filtered.difference(wildcard_privileges).copied().collect();
        }
        if let Some(absent_privileges) = absence_wildcards.get(&selector) {
            filtered = filtered.difference(absent_privileges).copied().collect();
        }
        filtered
    };

    // Revokes accumulate per key so a key hit by both a convergence branch
    // and an absence assertion emits one merged REVOKE.
    let mut revokes: BTreeMap<GrantKey, BTreeSet<Privilege>> = BTreeMap::new();

    // Grants in desired but not in current → GRANT (full set)
    // Grants in both → diff the privilege sets
    for (key, desired_state) in &desired.grants {
        match current.grants.get(key) {
            None => {
                // Entirely new grant target — grant the full set
                grants_out.push(change_grant(key, &desired_state.privileges));
            }
            Some(current_state) => {
                // Grant target exists — find privileges to add/remove
                let to_add: BTreeSet<Privilege> = desired_state
                    .privileges
                    .difference(&current_state.privileges)
                    .copied()
                    .collect();
                if !to_add.is_empty() {
                    grants_out.push(change_grant(key, &to_add));
                }

                // PUBLIC state is assertion-driven: only an `ensure: absent`
                // rule may revoke from PUBLIC, never mere absence from the
                // desired set.
                if key.role.is_public() {
                    continue;
                }

                // An owner-grantee entry carries the owner's inherent
                // privileges; none of it is revocable state.
                if current.inherent_grants.contains(key) {
                    continue;
                }

                let to_remove: BTreeSet<Privilege> = current_state
                    .privileges
                    .difference(&desired_state.privileges)
                    .copied()
                    .collect();
                let to_remove = shadow_filter(key, to_remove);
                if !to_remove.is_empty() {
                    revokes.entry(key.clone()).or_default().extend(to_remove);
                }
            }
        }
    }

    // Grant targets in current but not in desired → REVOKE the privileges
    // that aren't shadowed by a desired wildcard for the same scope. PUBLIC
    // keys are exempt: unmentioned PUBLIC ACLs are unmanaged, not drift.
    for (key, current_state) in &current.grants {
        if desired.grants.contains_key(key) || key.role.is_public() {
            continue;
        }

        // Owner-inherent entries are not revocable state.
        if current.inherent_grants.contains(key) {
            continue;
        }

        let to_revoke = shadow_filter(key, current_state.privileges.clone());
        if !to_revoke.is_empty() {
            revokes.entry(key.clone()).or_default().extend(to_revoke);
        }
    }

    // Absence assertions: revoke `absent ∩ current`. A wildcard assertion
    // range-scans every current key under its (grantee, type, schema) prefix,
    // then expands into object/grantor-targeted revokes. An empty range is
    // vacuously converged. Owner-inherent
    // entries are excluded throughout: an owner's privileges are intrinsic,
    // so an absence assertion cannot be enforced against them and revoking
    // would only break owner access.
    for (key, absent_privileges) in &desired.grant_absences {
        let held: BTreeSet<Privilege> = if key.name.as_deref() == Some("*") {
            let range_start = GrantKey {
                role: key.role.clone(),
                object_type: key.object_type,
                schema: key.schema.clone(),
                name: None,
            };
            current
                .grants
                .range(range_start..)
                .take_while(|(k, _)| {
                    k.role == key.role && k.object_type == key.object_type && k.schema == key.schema
                })
                .filter(|(k, _)| !current.inherent_grants.contains(k))
                .flat_map(|(_, state)| state.privileges.iter().copied())
                .collect()
        } else if current.inherent_grants.contains(key) {
            BTreeSet::new()
        } else {
            current
                .grants
                .get(key)
                .map(|state| state.privileges.clone())
                .unwrap_or_default()
        };

        let to_revoke: BTreeSet<Privilege> =
            absent_privileges.intersection(&held).copied().collect();
        if !to_revoke.is_empty() {
            revokes.entry(key.clone()).or_default().extend(to_revoke);
        }
    }

    for (key, privileges) in &revokes {
        push_revokes_split_by_grantor(current, desired, key, privileges, revokes_out);
    }
}

/// Emit the revokes for one grant target, split per ACL-entry grantor.
///
/// PostgreSQL's plain REVOKE removes only the entry of the one grantor it
/// selects for the executor, so a privilege held via entries from several
/// grantors must be revoked from each. When inspection recorded the target's
/// per-grantor breakdown, emit one grantor-targeted revoke per grantor whose
/// entry holds any of the privileges (rendered as `SET ROLE grantor`), plus a
/// plain revoke for any remainder the breakdown does not cover. Without a
/// breakdown — pre-existing snapshots or the desired
/// side — fall back to a single plain revoke, the status quo.
fn push_revokes_split_by_grantor(
    current: &RoleGraph,
    desired: &RoleGraph,
    key: &GrantKey,
    privileges: &BTreeSet<Privilege>,
    revokes_out: &mut Vec<Change>,
) {
    // Normalization compacts shared privileges, but ACL attribution remains
    // concrete: objects in one wildcard can have different owners/grantors.
    // Expand revokes against that inventory, never run a broad revoke as each
    // grantor (which could touch objects it cannot administer or owner ACLs).
    if key.name.as_deref() == Some("*") {
        let start = GrantKey {
            name: None,
            ..key.clone()
        };
        let in_scope = |candidate: &GrantKey| {
            candidate.role == key.role
                && candidate.object_type == key.object_type
                && candidate.schema == key.schema
        };
        let mut concrete: BTreeMap<GrantKey, BTreeSet<Privilege>> = BTreeMap::new();
        for (target, grantors) in current
            .grant_entry_grantors
            .range(start.clone()..)
            .take_while(|(target, _)| in_scope(target))
        {
            if target.name.as_deref() != Some("*") {
                concrete
                    .entry(target.clone())
                    .or_default()
                    .extend(grantors.values().flatten().copied());
            }
        }
        for (target, state) in current
            .grants
            .range(start.clone()..)
            .take_while(|(target, _)| in_scope(target))
        {
            if target.name.as_deref() != Some("*") {
                concrete
                    .entry(target.clone())
                    .or_default()
                    .extend(&state.privileges);
            }
        }
        // An all-owner scope has no revocable grantor metadata. Its concrete
        // inherent tags still prove that a wildcard revoke must not run.
        let has_inherent = current
            .inherent_grants
            .range(start..)
            .take_while(|target| in_scope(target))
            .next()
            .is_some();
        if !concrete.is_empty() || has_inherent {
            for (target, held) in concrete {
                if current.inherent_grants.contains(&target) {
                    continue;
                }
                let subset = privileges.intersection(&held).copied().collect();
                if !BTreeSet::is_empty(&subset) {
                    push_revokes_split_by_grantor(current, desired, &target, &subset, revokes_out);
                }
            }
            return;
        }
        // Legacy/caller-built graphs without concrete inspection metadata
        // retain their existing grantor-less behavior.
    }
    // `ALTER SCHEMA ... OWNER TO` rewrites the ACL's attribution (old-owner
    // entries become new-owner entries), so a grantor recorded at inspection
    // time is stale once the same plan transfers the schema's owner — and a
    // `SET ROLE <old owner>` revoke would fail outright. Fall back to a plain
    // revoke there: after the transfer the entries are owner-attributed, which
    // is exactly what a plain revoke by an owner-acting executor removes.
    if key.object_type == ObjectType::Schema
        && let Some(name) = &key.name
        && let (Some(current_schema), Some(desired_schema)) =
            (current.schemas.get(name), desired.schemas.get(name))
        && desired_schema.owner.is_some()
        && desired_schema.owner != current_schema.owner
    {
        revokes_out.push(change_revoke(key, privileges, None));
        return;
    }
    let Some(per_grantor) = current.grant_entry_grantors.get(key) else {
        revokes_out.push(change_revoke(key, privileges, None));
        return;
    };
    let mut covered: BTreeSet<Privilege> = BTreeSet::new();
    for (grantor, grantor_privileges) in per_grantor {
        let subset: BTreeSet<Privilege> = privileges
            .intersection(grantor_privileges)
            .copied()
            .collect();
        if !subset.is_empty() {
            covered.extend(subset.iter().copied());
            revokes_out.push(change_revoke(key, &subset, Some(grantor.clone())));
        }
    }
    let remainder: BTreeSet<Privilege> = privileges.difference(&covered).copied().collect();
    if !remainder.is_empty() {
        revokes_out.push(change_revoke(key, &remainder, None));
    }
}

fn change_grant(key: &GrantKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::Grant {
        role: key.role.clone(),
        privileges: privileges.clone(),
        object_type: key.object_type,
        schema: key.schema.clone(),
        name: key.name.clone(),
    }
}

fn change_revoke(
    key: &GrantKey,
    privileges: &BTreeSet<Privilege>,
    grantor: Option<String>,
) -> Change {
    Change::Revoke {
        role: key.role.clone(),
        privileges: privileges.clone(),
        object_type: key.object_type,
        schema: key.schema.clone(),
        name: key.name.clone(),
        grantor,
    }
}

// ---------------------------------------------------------------------------
// Default privilege diffing
// ---------------------------------------------------------------------------

fn diff_default_privileges(
    current: &RoleGraph,
    desired: &RoleGraph,
    set_out: &mut Vec<Change>,
    revoke_out: &mut Vec<Change>,
) {
    // Revokes accumulate per key so a key hit by both a convergence branch
    // and an absence assertion emits one merged REVOKE.
    let mut revokes: BTreeMap<DefaultPrivKey, BTreeSet<Privilege>> = BTreeMap::new();

    for (key, desired_state) in &desired.default_privileges {
        match current.default_privileges.get(key) {
            None => {
                set_out.push(change_set_default(key, &desired_state.privileges));
            }
            Some(current_state) => {
                let to_add: BTreeSet<Privilege> = desired_state
                    .privileges
                    .difference(&current_state.privileges)
                    .copied()
                    .collect();
                if !to_add.is_empty() {
                    set_out.push(change_set_default(key, &to_add));
                }

                // PUBLIC defaults are assertion-driven: only `ensure: absent`
                // may revoke them.
                if key.grantee.is_public() {
                    continue;
                }

                let to_remove: BTreeSet<Privilege> = current_state
                    .privileges
                    .difference(&desired_state.privileges)
                    .copied()
                    .collect();
                if !to_remove.is_empty() {
                    revokes.entry(key.clone()).or_default().extend(to_remove);
                }
            }
        }
    }

    for (key, current_state) in &current.default_privileges {
        if desired.default_privileges.contains_key(key) || key.grantee.is_public() {
            continue;
        }
        revokes
            .entry(key.clone())
            .or_default()
            .extend(current_state.privileges.iter().copied());
    }

    // Absence assertions: revoke `absent ∩ current`. Keys here are exact —
    // default privileges have no wildcard selector. A role created by this
    // plan is not present in the inspected graph yet, but PostgreSQL gives a
    // new owner built-in global PUBLIC defaults. Model those defaults here so
    // the CREATE and REVOKE land in the same transaction instead of leaving a
    // one-reconcile exposure window.
    for (key, absent_privileges) in &desired.default_privilege_absences {
        let current_privileges = current
            .default_privileges
            .get(key)
            .map(|state| state.privileges.clone())
            .unwrap_or_else(|| builtin_defaults_for_new_owner(current, desired, key));
        let to_revoke: BTreeSet<Privilege> = absent_privileges
            .intersection(&current_privileges)
            .copied()
            .collect();
        if !to_revoke.is_empty() {
            revokes.entry(key.clone()).or_default().extend(to_revoke);
        }
    }

    for (key, privileges) in &revokes {
        revoke_out.push(change_revoke_default(key, privileges));
    }
}

fn builtin_defaults_for_new_owner(
    current: &RoleGraph,
    desired: &RoleGraph,
    key: &DefaultPrivKey,
) -> BTreeSet<Privilege> {
    if current.roles.contains_key(&key.owner)
        || !desired.roles.contains_key(&key.owner)
        || key.scope != DefaultPrivilegeScope::Global
        || !key.grantee.is_public()
    {
        return BTreeSet::new();
    }

    match key.on_type {
        ObjectType::Function => BTreeSet::from([Privilege::Execute]),
        ObjectType::Type => BTreeSet::from([Privilege::Usage]),
        _ => BTreeSet::new(),
    }
}

fn change_set_default(key: &DefaultPrivKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::SetDefaultPrivilege {
        owner: key.owner.clone(),
        scope: key.scope.clone(),
        on_type: key.on_type,
        grantee: key.grantee.clone(),
        privileges: privileges.clone(),
    }
}

fn change_revoke_default(key: &DefaultPrivKey, privileges: &BTreeSet<Privilege>) -> Change {
    Change::RevokeDefaultPrivilege {
        owner: key.owner.clone(),
        scope: key.scope.clone(),
        on_type: key.on_type,
        grantee: key.grantee.clone(),
        privileges: privileges.clone(),
    }
}

// ---------------------------------------------------------------------------
// Membership diffing
// ---------------------------------------------------------------------------

fn diff_memberships(
    current: &RoleGraph,
    desired: &RoleGraph,
    add_out: &mut Vec<Change>,
    remove_out: &mut Vec<Change>,
) {
    // We compare memberships by (role, member) as the key.
    // If inherit/admin flags changed, we remove and re-add.

    // Build lookup maps: (role, member) → MembershipEdge
    let current_map: std::collections::BTreeMap<(&str, &str), &MembershipEdge> = current
        .memberships
        .iter()
        .map(|edge| ((edge.role.as_str(), edge.member.as_str()), edge))
        .collect();
    let desired_map: std::collections::BTreeMap<(&str, &str), &MembershipEdge> = desired
        .memberships
        .iter()
        .map(|edge| ((edge.role.as_str(), edge.member.as_str()), edge))
        .collect();

    // Removing a membership means removing every live edge behind it: since
    // PostgreSQL 16 one (role, member) pair can carry several edges with
    // distinct grantors, and a plain REVOKE removes only the edge attributed
    // to the revoker. When inspection recorded the grantors, emit one
    // grantor-targeted RemoveMember per edge; otherwise a single plain one.
    let remove_all_edges = |role: &str, member: &str, remove_out: &mut Vec<Change>| match current
        .membership_edge_grantors
        .get(&(role.to_string(), member.to_string()))
    {
        Some(grantors) if !grantors.is_empty() => {
            for grantor in grantors {
                remove_out.push(Change::RemoveMember {
                    role: role.to_string(),
                    member: member.to_string(),
                    grantor: Some(grantor.clone()),
                });
            }
        }
        _ => remove_out.push(Change::RemoveMember {
            role: role.to_string(),
            member: member.to_string(),
            grantor: None,
        }),
    };

    // Desired but not current → add
    // Desired and current but different flags → remove + add
    for (&(role, member), &desired_edge) in &desired_map {
        match current_map.get(&(role, member)) {
            None => {
                add_out.push(Change::AddMember {
                    role: desired_edge.role.clone(),
                    member: desired_edge.member.clone(),
                    inherit: desired_edge.inherit,
                    admin: desired_edge.admin,
                });
            }
            Some(current_edge) => {
                if current_edge.inherit != desired_edge.inherit
                    || current_edge.admin != desired_edge.admin
                {
                    // Flags changed — revoke every edge and re-grant one.
                    remove_all_edges(role, member, remove_out);
                    add_out.push(Change::AddMember {
                        role: desired_edge.role.clone(),
                        member: desired_edge.member.clone(),
                        inherit: desired_edge.inherit,
                        admin: desired_edge.admin,
                    });
                }
            }
        }
    }

    // Current but not desired → remove
    for &(role, member) in current_map.keys() {
        if !desired_map.contains_key(&(role, member)) {
            remove_all_edges(role, member, remove_out);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DefaultPrivState, GrantState, SchemaState, default_schema_owner_privileges,
    };

    /// Helper: build an empty graph.
    fn empty_graph() -> RoleGraph {
        RoleGraph::default()
    }

    fn managed_schema(owner: &str) -> SchemaState {
        SchemaState {
            owner: Some(owner.to_string()),
            owner_privileges: default_schema_owner_privileges(owner),
        }
    }

    fn role_definition(name: &str, external: bool) -> RoleDefinition {
        RoleDefinition {
            name: name.to_string(),
            external,
            preserve_undeclared_grants: false,
            login: None,
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
            password: None,
            password_valid_until: None,
            config: Default::default(),
        }
    }

    #[test]
    fn diff_empty_to_empty_is_empty() {
        let changes = diff(&empty_graph(), &empty_graph());
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_creates_new_roles() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired
            .roles
            .insert("new-role".to_string(), RoleState::default());

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::CreateRole { name, .. } if name == "new-role"));
    }

    #[test]
    fn diff_drops_removed_roles() {
        let mut current = empty_graph();
        current
            .roles
            .insert("old-role".to_string(), RoleState::default());
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::DropRole { name } if name == "old-role"));
    }

    #[test]
    fn diff_alters_changed_role_attributes() {
        let mut current = empty_graph();
        current
            .roles
            .insert("role1".to_string(), RoleState::default());

        let mut desired = empty_graph();
        desired.roles.insert(
            "role1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "role1");
                assert!(attributes.contains(&RoleAttribute::Login(true)));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }

    #[test]
    fn owner_transfer_suppresses_revoke_of_incoming_owners_stale_grant() {
        // Issue #140: a stale explicit schema grant to the role that becomes
        // the schema's owner in the same plan must NOT be revoked — the
        // transfer absorbs the grantee's ACL entry into the owner entry, so
        // the revoke would strip the NEW OWNER's privilege.
        let mut current = empty_graph();
        for role in ["w", "z", "bystander"] {
            current.roles.insert(role.to_string(), RoleState::default());
        }
        current.schemas.insert(
            "s".to_string(),
            SchemaState {
                owner: Some("w".to_string()),
                owner_privileges: default_schema_owner_privileges("w"),
            },
        );
        for grantee in ["z", "bystander"] {
            current.grants.insert(
                GrantKey {
                    role: grantee.into(),
                    object_type: ObjectType::Schema,
                    schema: None,
                    name: Some("s".to_string()),
                },
                GrantState {
                    privileges: [Privilege::Usage].into_iter().collect(),
                },
            );
        }

        let mut desired = empty_graph();
        for role in ["w", "z", "bystander"] {
            desired.roles.insert(role.to_string(), RoleState::default());
        }
        desired.schemas.insert(
            "s".to_string(),
            SchemaState {
                owner: Some("z".to_string()),
                owner_privileges: default_schema_owner_privileges("z"),
            },
        );

        let changes = diff(&current, &desired);

        assert!(
            changes.iter().any(|c| matches!(
                c,
                Change::AlterSchemaOwner { name, owner } if name == "s" && owner == "z"
            )),
            "expected owner transfer in plan: {changes:?}"
        );
        // The incoming owner's stale grant is absorbed by the transfer, not
        // revoked...
        assert!(
            !changes.iter().any(|c| matches!(
                c,
                Change::Revoke { role, object_type: ObjectType::Schema, name: Some(n), .. }
                    if role.as_str() == "z" && n == "s"
            )),
            "revoke against incoming owner must be suppressed: {changes:?}"
        );
        // ...while unrelated revokes on the same schema still happen.
        assert!(
            changes.iter().any(|c| matches!(
                c,
                Change::Revoke { role, object_type: ObjectType::Schema, name: Some(n), .. }
                    if role.as_str() == "bystander" && n == "s"
            )),
            "bystander's stale grant must still be revoked: {changes:?}"
        );
    }

    #[test]
    fn diff_converges_role_config_via_manifest_pipeline() {
        // The issue-132 blue/green scenario: login roles blue and green both
        // SET ROLE to a shared "combined" owner role on connect.
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      role: combined
  - name: green
    login: true
    config:
      role: combined
  - name: combined

memberships:
  - role: combined
    members:
      - name: blue
      - name: green
"#;
        let manifest = crate::manifest::parse_manifest(yaml).unwrap();
        let expanded = crate::manifest::expand_manifest(&manifest).unwrap();
        let desired = RoleGraph::from_expanded(&expanded, None).unwrap();

        // Fresh database: everything is created, including config statements.
        let changes = diff(&empty_graph(), &desired);
        let sql = crate::sql::render_all(&changes);
        assert!(sql.contains("ALTER ROLE \"blue\" SET \"role\" = 'combined';"));
        assert!(sql.contains("ALTER ROLE \"green\" SET \"role\" = 'combined';"));
        assert!(sql.contains("GRANT \"combined\" TO \"blue\""));

        // Converged database: config matches, no changes.
        let changes = diff(&desired, &desired);
        assert!(changes.is_empty());

        // Drifted database: green lost its setting, blue has a stray one.
        let mut current = desired.clone();
        current.roles.get_mut("green").unwrap().config.clear();
        current
            .roles
            .get_mut("blue")
            .unwrap()
            .config
            .insert("statement_timeout".to_string(), "10s".to_string());
        let changes = diff(&current, &desired);
        let sql = crate::sql::render_all(&changes);
        assert!(sql.contains("ALTER ROLE \"green\" SET \"role\" = 'combined';"));
        assert!(sql.contains("ALTER ROLE \"blue\" RESET \"statement_timeout\";"));
        assert!(!sql.contains("ALTER ROLE \"blue\" SET"));
    }

    #[test]
    fn external_role_filter_suppresses_lifecycle_and_granted_role_memberships() {
        let external = "analytics-admin@example.com";
        let mut current = empty_graph();
        current.roles.insert(
            external.to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );
        current.memberships.insert(MembershipEdge {
            role: external.to_string(),
            member: "cloudsqlsuperuser".to_string(),
            inherit: true,
            admin: false,
        });

        let mut desired = empty_graph();
        desired
            .roles
            .insert(external.to_string(), RoleState::default());

        let changes = diff(&current, &desired);
        assert!(changes.iter().any(|change| {
            matches!(
                change,
                Change::AlterRole { name, attributes }
                    if name == external && attributes.contains(&RoleAttribute::Login(false))
            )
        }));
        assert!(changes.iter().any(|change| {
            matches!(
                change,
                Change::RemoveMember { role, member , .. }
                    if role == external && member == "cloudsqlsuperuser"
            )
        }));

        let filtered =
            filter_external_role_changes(changes, &[role_definition(external, true)], &[]);
        assert!(filtered.is_empty());
    }

    #[test]
    fn external_role_filter_keeps_external_role_as_managed_member() {
        let external = "team@example.com";
        let changes = vec![Change::RemoveMember {
            grantor: None,
            role: "kv-editor".to_string(),
            member: external.to_string(),
        }];

        let filtered =
            filter_external_role_changes(changes.clone(), &[role_definition(external, true)], &[]);
        assert_eq!(filtered, changes);
    }

    fn membership(role: &str, members: &[&str], exclusive: bool) -> Membership {
        Membership {
            role: role.to_string(),
            members: members
                .iter()
                .map(|name| crate::manifest::MemberSpec {
                    name: name.to_string(),
                    inherit: None,
                    admin: None,
                })
                .collect(),
            exclusive,
        }
    }

    #[test]
    fn declared_membership_in_external_role_converges() {
        // GRANT rds_iam-style edges: declared members of an external role are
        // granted (and re-granted on option changes), not filtered.
        let changes = vec![
            Change::AddMember {
                role: "rds_iam".to_string(),
                member: "app_user".to_string(),
                inherit: true,
                admin: false,
            },
            Change::RemoveMember {
                grantor: None,
                role: "rds_iam".to_string(),
                member: "app_user".to_string(),
            },
        ];
        let filtered = filter_external_role_changes(
            changes.clone(),
            &[role_definition("rds_iam", true)],
            &[membership("rds_iam", &["app_user"], false)],
        );
        assert_eq!(filtered, changes);
    }

    #[test]
    fn predefined_role_memberships_follow_declared_intent_without_declaration() {
        // pg_* roles need no roles: entry at all. Declared member converges;
        // the undeclared provider-granted member is left untouched.
        let changes = vec![
            Change::AddMember {
                role: "pg_read_all_data".to_string(),
                member: "auditor".to_string(),
                inherit: true,
                admin: false,
            },
            Change::RemoveMember {
                grantor: None,
                role: "pg_read_all_data".to_string(),
                member: "rds_superuser".to_string(),
            },
        ];
        let filtered = filter_external_role_changes(
            changes,
            &[],
            &[membership("pg_read_all_data", &["auditor"], false)],
        );
        assert_eq!(
            filtered,
            vec![Change::AddMember {
                role: "pg_read_all_data".to_string(),
                member: "auditor".to_string(),
                inherit: true,
                admin: false,
            }]
        );
    }

    #[test]
    fn exclusive_membership_revokes_undeclared_predefined_members() {
        let changes = vec![Change::RemoveMember {
            grantor: None,
            role: "pg_read_all_data".to_string(),
            member: "forgotten_contractor".to_string(),
        }];
        let filtered = filter_external_role_changes(
            changes.clone(),
            &[],
            &[membership("pg_read_all_data", &["auditor"], true)],
        );
        assert_eq!(filtered, changes);
    }

    /// Exhaustive model check of the unmanaged-role change filter.
    ///
    /// Enumerates every combination of granted-role kind (ordinary managed,
    /// `external: true`, predefined `pg_*`), change shape (each lifecycle
    /// variant, each retirement variant, membership add/remove, and an
    /// unrelated change), declared-edge status, and stanza exclusivity, and
    /// compares the filter against an independently written oracle of the
    /// documented semantics table.
    #[test]
    fn unmanaged_role_filter_model_check() {
        #[derive(Clone, Copy, Debug, PartialEq)]
        enum RoleKind {
            Managed,
            External,
            Predefined,
        }
        let role_name = |kind: RoleKind| match kind {
            RoleKind::Managed => "managed_role",
            RoleKind::External => "external_role",
            RoleKind::Predefined => "pg_read_all_data",
        };
        type ChangeShape = (&'static str, fn(&str, &str) -> Change);
        let change_shapes: Vec<ChangeShape> = vec![
            ("create", |r, _| Change::CreateRole {
                name: r.to_string(),
                state: crate::model::RoleState::default(),
            }),
            ("alter", |r, _| Change::AlterRole {
                name: r.to_string(),
                attributes: vec![RoleAttribute::Login(true)],
            }),
            ("comment", |r, _| Change::SetComment {
                name: r.to_string(),
                comment: None,
            }),
            ("drop", |r, _| Change::DropRole {
                name: r.to_string(),
            }),
            ("terminate", |r, _| Change::TerminateSessions {
                role: r.to_string(),
            }),
            ("drop_owned", |r, _| Change::DropOwned {
                role: r.to_string(),
            }),
            ("reassign", |r, _| Change::ReassignOwned {
                from_role: r.to_string(),
                to_role: "successor".to_string(),
            }),
            ("add_member", |r, m| Change::AddMember {
                role: r.to_string(),
                member: m.to_string(),
                inherit: true,
                admin: false,
            }),
            ("remove_member", |r, m| Change::RemoveMember {
                grantor: None,
                role: r.to_string(),
                member: m.to_string(),
            }),
            ("unrelated", |_, _| Change::CreateSchema {
                name: "s".to_string(),
                owner: None,
            }),
        ];

        // The member's own kind matters for exclusive revocation: PostgreSQL's
        // built-in pg_* -> pg_* hierarchy edges must never be revoked.
        for kind in [RoleKind::Managed, RoleKind::External, RoleKind::Predefined] {
            for (shape_name, make_change) in &change_shapes {
                for member in ["some_member", "pg_monitor"] {
                    for declared in [false, true] {
                        for exclusive in [false, true] {
                            let role = role_name(kind);
                            let change = make_change(role, member);
                            let roles = match kind {
                                RoleKind::External => vec![role_definition(role, true)],
                                _ => vec![],
                            };
                            let memberships = if declared {
                                vec![membership(role, &[member], exclusive)]
                            } else if exclusive {
                                vec![membership(role, &[], true)]
                            } else {
                                vec![]
                            };

                            // Independent oracle of the semantics table.
                            let unmanaged = kind != RoleKind::Managed;
                            let member_is_predefined = member.starts_with("pg_");
                            let expected_kept = match *shape_name {
                                "unrelated" => true,
                                "add_member" => !unmanaged || declared,
                                "remove_member" => {
                                    !unmanaged || declared || (exclusive && !member_is_predefined)
                                }
                                // Every lifecycle and retirement shape.
                                _ => !unmanaged,
                            };

                            let kept = !filter_external_role_changes(
                                vec![change.clone()],
                                &roles,
                                &memberships,
                            )
                            .is_empty();
                            assert_eq!(
                                kept, expected_kept,
                                "kind={kind:?} shape={shape_name} member={member} \
                                 declared={declared} exclusive={exclusive} change={change:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn predefined_role_lifecycle_is_always_filtered() {
        let changes = vec![
            Change::DropRole {
                name: "pg_read_all_data".to_string(),
            },
            Change::AlterRole {
                name: "pg_monitor".to_string(),
                attributes: vec![RoleAttribute::Login(true)],
            },
        ];
        let filtered = filter_external_role_changes(
            changes,
            &[],
            &[membership("pg_read_all_data", &["auditor"], true)],
        );
        assert!(filtered.is_empty());
    }

    #[test]
    fn diff_creates_missing_schema() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("inventory_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::CreateSchema { name, owner }
                if name == "inventory" && owner.as_deref() == Some("inventory_owner")
        ));
    }

    #[test]
    fn diff_alters_schema_owner_when_different() {
        let mut current = empty_graph();
        current
            .schemas
            .insert("inventory".to_string(), managed_schema("old_owner"));

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("new_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            &changes[0],
            Change::AlterSchemaOwner { name, owner }
                if name == "inventory" && owner == "new_owner"
        ));
        assert!(matches!(
            &changes[1],
            Change::EnsureSchemaOwnerPrivileges { name, owner, privileges }
                if name == "inventory"
                    && owner == "new_owner"
                    && privileges == &BTreeSet::from([Privilege::Create, Privilege::Usage])
        ));
    }

    #[test]
    fn diff_does_not_alter_schema_owner_when_unmanaged() {
        let mut current = empty_graph();
        current
            .schemas
            .insert("inventory".to_string(), managed_schema("old_owner"));

        let mut desired = empty_graph();
        desired.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: None,
                owner_privileges: BTreeSet::new(),
            },
        );

        let changes = diff(&current, &desired);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_restores_missing_owner_schema_privileges() {
        let mut current = empty_graph();
        current.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: Some("inventory_owner".to_string()),
                owner_privileges: BTreeSet::from([Privilege::Usage]),
            },
        );

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("inventory_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::EnsureSchemaOwnerPrivileges {
                name,
                owner,
                privileges,
            } if name == "inventory"
                && owner == "inventory_owner"
                && privileges == &BTreeSet::from([Privilege::Create])
        ));
    }

    #[test]
    fn diff_restores_owner_schema_privileges_after_transfer() {
        let mut current = empty_graph();
        current.schemas.insert(
            "inventory".to_string(),
            SchemaState {
                owner: Some("old_owner".to_string()),
                owner_privileges: BTreeSet::from([Privilege::Usage]),
            },
        );

        let mut desired = empty_graph();
        desired
            .schemas
            .insert("inventory".to_string(), managed_schema("new_owner"));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            &changes[0],
            Change::AlterSchemaOwner { name, owner }
                if name == "inventory" && owner == "new_owner"
        ));
        assert!(matches!(
            &changes[1],
            Change::EnsureSchemaOwnerPrivileges {
                name,
                owner,
                privileges,
            } if name == "inventory"
                && owner == "new_owner"
                && privileges == &BTreeSet::from([Privilege::Create, Privilege::Usage])
        ));
    }

    #[test]
    fn diff_grants_new_privileges() {
        let current = empty_graph();
        let mut desired = empty_graph();
        let key = GrantKey {
            role: "r1".into(),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };
        desired.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Grant {
                role, privileges, ..
            } => {
                assert_eq!(role.as_str(), "r1");
                assert!(privileges.contains(&Privilege::Select));
                assert!(privileges.contains(&Privilege::Insert));
            }
            other => panic!("expected Grant, got: {other:?}"),
        }
    }

    #[test]
    fn unenforceable_absence_warnings_require_actual_overlap() {
        let key = GrantKey {
            role: "app_owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let mut current = empty_graph();
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        current.inherent_grants.insert(key.clone());

        // Asserting an actually-held inherent privilege warns.
        let mut desired = empty_graph();
        desired
            .grant_absences
            .insert(key.clone(), BTreeSet::from([Privilege::Select]));
        let warnings = unenforceable_absence_warnings(&current, &desired);
        assert_eq!(warnings.len(), 1);
        // Message renders the privilege set readably and carries no literal
        // backslash from a botched line continuation — it ships into k8s
        // status objects verbatim.
        assert!(warnings[0].contains("SELECT"), "got: {}", warnings[0]);
        assert!(!warnings[0].contains('\\'), "got: {}", warnings[0]);

        // Asserting a privilege the entry does not carry stays silent.
        let mut satisfied = empty_graph();
        satisfied
            .grant_absences
            .insert(key, BTreeSet::from([Privilege::Delete]));
        assert!(unenforceable_absence_warnings(&current, &satisfied).is_empty());
    }

    #[test]
    fn preserved_role_keeps_undeclared_revokes() {
        let mut preserved_role = role_definition("brownfield", false);
        preserved_role.preserve_undeclared_grants = true;
        let plain_role = role_definition("managed", false);

        let revoke = Change::Revoke {
            grantor: None,
            role: "brownfield".into(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let other = Change::Revoke {
            grantor: None,
            role: "managed".into(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("gadgets".to_string()),
        };

        let changes = filter_preserved_grant_revokes(
            vec![revoke, other],
            &[preserved_role, plain_role],
            &empty_graph(),
        );

        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Revoke { role, .. } => assert_eq!(role.as_str(), "managed"),
            other => panic!("expected Revoke, got: {other:?}"),
        }
    }

    #[test]
    fn preserve_flag_keeps_object_grants_but_revokes_defaults_and_memberships() {
        let mut preserved_role = role_definition("brownfield", false);
        preserved_role.preserve_undeclared_grants = true;

        let mut current = empty_graph();
        current.grants.insert(
            GrantKey {
                role: "brownfield".into(),
                object_type: ObjectType::Table,
                schema: Some("app".into()),
                name: Some("widgets".into()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        current.default_privileges.insert(
            DefaultPrivKey {
                owner: "app_owner".into(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "app".into(),
                },
                on_type: ObjectType::Table,
                grantee: "brownfield".into(),
            },
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        current.memberships.insert(MembershipEdge {
            role: "readers".into(),
            member: "brownfield".into(),
            inherit: true,
            admin: false,
        });
        let desired = empty_graph();
        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 3);
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::Revoke { .. }))
        );

        let changes = filter_preserved_grant_revokes(changes, &[preserved_role], &desired);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|change| matches!(
            change,
            Change::RevokeDefaultPrivilege { grantee, privileges, .. }
                if grantee.to_string() == "brownfield"
                    && privileges == &BTreeSet::from([Privilege::Select])
        )));
        assert!(changes.iter().any(|change| matches!(
            change,
            Change::RemoveMember { role, member, .. }
                if role == "readers" && member == "brownfield"
        )));
    }

    #[test]
    fn preserve_flag_respects_absence_assertions() {
        let mut preserved_role = role_definition("brownfield", false);
        preserved_role.preserve_undeclared_grants = true;

        let key = GrantKey {
            role: "brownfield".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let mut desired = empty_graph();
        desired
            .grant_absences
            .insert(key, BTreeSet::from([Privilege::Delete]));

        let revoke = Change::Revoke {
            grantor: None,
            role: "brownfield".into(),
            // SELECT is not asserted absent → preserved. DELETE is → revoked.
            privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };

        let changes = filter_preserved_grant_revokes(vec![revoke], &[preserved_role], &desired);
        match &changes[0] {
            Change::Revoke { privileges, .. } => {
                assert_eq!(*privileges, BTreeSet::from([Privilege::Delete]))
            }
            other => panic!("expected Revoke, got: {other:?}"),
        }
    }

    #[test]
    fn preserve_flag_splits_normalized_wildcard_revoke_for_exact_absence() {
        let mut preserved_role = role_definition("brownfield", false);
        preserved_role.preserve_undeclared_grants = true;

        let mut desired = empty_graph();
        desired.grant_absences.insert(
            GrantKey {
                role: "brownfield".into(),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            },
            BTreeSet::from([Privilege::Delete]),
        );

        let changes = filter_preserved_grant_revokes(
            vec![Change::Revoke {
                grantor: None,
                role: "brownfield".into(),
                privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("*".to_string()),
            }],
            &[preserved_role],
            &desired,
        );

        assert_eq!(
            changes,
            vec![Change::Revoke {
                grantor: None,
                role: "brownfield".into(),
                privileges: BTreeSet::from([Privilege::Delete]),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            }]
        );
    }

    #[test]
    fn preserve_flag_applies_wildcard_absence_to_exact_revoke() {
        let mut preserved_role = role_definition("brownfield", false);
        preserved_role.preserve_undeclared_grants = true;

        let mut desired = empty_graph();
        desired.grant_absences.insert(
            GrantKey {
                role: "brownfield".into(),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("*".to_string()),
            },
            BTreeSet::from([Privilege::Delete]),
        );

        let changes = filter_preserved_grant_revokes(
            vec![Change::Revoke {
                grantor: None,
                role: "brownfield".into(),
                privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            }],
            &[preserved_role],
            &desired,
        );

        assert_eq!(
            changes,
            vec![Change::Revoke {
                grantor: None,
                role: "brownfield".into(),
                privileges: BTreeSet::from([Privilege::Delete]),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            }]
        );
    }

    #[test]
    fn owner_inherent_entry_is_never_revoked() {
        let key = GrantKey {
            role: "app_owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let mut current = empty_graph();
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([
                    Privilege::Select,
                    Privilege::Insert,
                    Privilege::Truncate,
                ]),
            },
        );
        current.inherent_grants.insert(key);

        // Nothing in the manifest covers the owner's table entry.
        let changes = diff(&current, &empty_graph());
        assert!(
            changes.iter().all(|change| !matches!(
                change,
                Change::Revoke { role, .. } if role.as_str() == "app_owner"
            )),
            "owner-inherent entries must not be revoked, got: {changes:?}"
        );
    }

    #[test]
    fn owner_inherent_entry_covers_declared_grant() {
        // The owner inherently holds every privilege, so a manifest declaring
        // a subset on the owner's own table needs no GRANT and no REVOKE.
        let key = GrantKey {
            role: "app_owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let mut current = empty_graph();
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );
        current.inherent_grants.insert(key);
        let mut desired = empty_graph();
        desired.grants.insert(
            GrantKey {
                role: "app_owner".into(),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );

        assert!(diff(&current, &desired).is_empty());
    }

    #[test]
    fn absence_assertions_cannot_target_owner_inherent_privileges() {
        let key = GrantKey {
            role: "app_owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("widgets".to_string()),
        };
        let mut current = empty_graph();
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        current.inherent_grants.insert(key.clone());
        let mut desired = empty_graph();
        desired
            .grant_absences
            .insert(key, BTreeSet::from([Privilege::Select]));

        assert!(diff(&current, &desired).is_empty());
    }

    #[test]
    fn diff_revokes_removed_privileges() {
        let mut current = empty_graph();
        let key = GrantKey {
            role: "r1".into(),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let mut desired = empty_graph();
        desired.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::Revoke {
                role, privileges, ..
            } => {
                assert_eq!(role.as_str(), "r1");
                assert!(privileges.contains(&Privilege::Insert));
                assert!(!privileges.contains(&Privilege::Select));
            }
            other => panic!("expected Revoke, got: {other:?}"),
        }
    }

    #[test]
    fn diff_revokes_entire_grant_target_when_absent_from_desired() {
        let mut current = empty_graph();
        let key = GrantKey {
            role: "r1".into(),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("myschema".to_string()),
        };
        current.grants.insert(
            key,
            GrantState {
                privileges: BTreeSet::from([Privilege::Usage]),
            },
        );
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], Change::Revoke { role, .. } if role.as_str() == "r1"));
    }

    #[test]
    fn diff_adds_memberships() {
        let current = empty_graph();
        let mut desired = empty_graph();
        desired.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AddMember {
                role,
                member,
                inherit,
                admin,
            } => {
                assert_eq!(role, "editors");
                assert_eq!(member, "user@example.com");
                assert!(*inherit);
                assert!(!admin);
            }
            other => panic!("expected AddMember, got: {other:?}"),
        }
    }

    #[test]
    fn diff_removes_memberships() {
        let mut current = empty_graph();
        current.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "old@example.com".to_string(),
            inherit: true,
            admin: false,
        });
        let desired = empty_graph();

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        assert!(
            matches!(&changes[0], Change::RemoveMember { role, member, .. } if role == "editors" && member == "old@example.com")
        );
    }

    #[test]
    fn diff_re_grants_membership_when_flags_change() {
        let mut current = empty_graph();
        current.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let mut desired = empty_graph();
        desired.memberships.insert(MembershipEdge {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: true, // changed!
        });

        let changes = diff(&current, &desired);
        // Should produce remove + add
        assert_eq!(changes.len(), 2);
        assert!(matches!(
            &changes[0],
            Change::RemoveMember { role, member , .. }
                if role == "editors" && member == "user@example.com"
        ));
        assert!(matches!(
            &changes[1],
            Change::AddMember {
                role,
                member,
                admin: true,
                ..
            } if role == "editors" && member == "user@example.com"
        ));
    }

    #[test]
    fn diff_default_privileges_add_and_revoke() {
        let mut current = empty_graph();
        let key = DefaultPrivKey {
            owner: "app_owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "inventory".to_string(),
            },
            on_type: ObjectType::Table,
            grantee: "inventory-editor".into(),
        };
        current.default_privileges.insert(
            key.clone(),
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
            },
        );

        let mut desired = empty_graph();
        desired.default_privileges.insert(
            key,
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        let changes = diff(&current, &desired);
        // Should add INSERT and revoke DELETE
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().any(|c| matches!(
            c,
            Change::SetDefaultPrivilege { privileges, .. } if privileges.contains(&Privilege::Insert)
        )));
        assert!(changes.iter().any(|c| matches!(
            c,
            Change::RevokeDefaultPrivilege { privileges, .. } if privileges.contains(&Privilege::Delete)
        )));
    }

    #[test]
    fn diff_ordering_creates_before_drops() {
        let mut current = empty_graph();
        current
            .roles
            .insert("old-role".to_string(), RoleState::default());

        let mut desired = empty_graph();
        desired
            .roles
            .insert("new-role".to_string(), RoleState::default());

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2);

        // Creates should come before drops
        let create_idx = changes
            .iter()
            .position(|c| matches!(c, Change::CreateRole { .. }))
            .unwrap();
        let schema_idx = changes
            .iter()
            .position(|c| matches!(c, Change::CreateSchema { .. }))
            .unwrap_or(create_idx);
        let drop_idx = changes
            .iter()
            .position(|c| matches!(c, Change::DropRole { .. }))
            .unwrap();
        assert!(create_idx <= schema_idx);
        assert!(schema_idx < drop_idx);
    }

    #[test]
    fn diff_identical_graphs_produce_no_changes() {
        let mut graph = empty_graph();
        graph
            .roles
            .insert("role1".to_string(), RoleState::default());
        graph.grants.insert(
            GrantKey {
                role: "role1".into(),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        graph.memberships.insert(MembershipEdge {
            role: "role1".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        });

        let changes = diff(&graph, &graph);
        assert!(
            changes.is_empty(),
            "identical graphs should produce no changes"
        );
    }

    /// Integration test: round-trip from manifest → expand → model → diff
    #[test]
    fn manifest_to_diff_integration() {
        use crate::manifest::{expand_manifest, parse_manifest};
        use crate::model::RoleGraph;

        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table

schemas:
  - name: inventory
    owner: inventory_owner
    profiles: [editor]

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let desired =
            RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();

        // Current state is empty — everything should be created
        let current = RoleGraph::default();
        let changes = diff(&current, &desired);

        // Should have: 1 CreateRole, 1 CreateSchema, 2 Grants, 1 SetDefaultPrivilege, 1 AddMember
        let create_count = changes
            .iter()
            .filter(|c| matches!(c, Change::CreateRole { .. }))
            .count();
        let create_schema_count = changes
            .iter()
            .filter(|c| matches!(c, Change::CreateSchema { .. }))
            .count();
        let grant_count = changes
            .iter()
            .filter(|c| matches!(c, Change::Grant { .. }))
            .count();
        let dp_count = changes
            .iter()
            .filter(|c| matches!(c, Change::SetDefaultPrivilege { .. }))
            .count();
        let member_count = changes
            .iter()
            .filter(|c| matches!(c, Change::AddMember { .. }))
            .count();

        assert_eq!(create_count, 1);
        assert_eq!(create_schema_count, 1);
        assert_eq!(grant_count, 2); // schema USAGE + table *
        assert_eq!(dp_count, 1);
        assert_eq!(member_count, 1);

        // Diffing desired against itself should produce no changes
        let no_changes = diff(&desired, &desired);
        assert!(no_changes.is_empty());
    }

    // -----------------------------------------------------------------------
    // filter_changes — ReconciliationMode tests
    // -----------------------------------------------------------------------

    /// Build a representative change list covering every Change variant.
    fn all_change_variants() -> Vec<Change> {
        vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: RoleState::default(),
            },
            Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
            Change::AlterSchemaOwner {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
            },
            Change::EnsureSchemaOwnerPrivileges {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
                privileges: BTreeSet::from([Privilege::Create, Privilege::Usage]),
            },
            Change::AlterRole {
                name: "altered-role".to_string(),
                attributes: vec![RoleAttribute::Login(true)],
            },
            Change::SetComment {
                name: "commented-role".to_string(),
                comment: Some("hello".to_string()),
            },
            Change::Grant {
                role: "r1".into(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::Revoke {
                grantor: None,
                role: "r1".into(),
                privileges: BTreeSet::from([Privilege::Insert]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::SetDefaultPrivilege {
                owner: "owner".to_string(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "public".to_string(),
                },
                on_type: ObjectType::Table,
                grantee: "r1".into(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::RevokeDefaultPrivilege {
                owner: "owner".to_string(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "public".to_string(),
                },
                on_type: ObjectType::Table,
                grantee: "r1".into(),
                privileges: BTreeSet::from([Privilege::Delete]),
            },
            Change::AddMember {
                role: "editors".to_string(),
                member: "user@example.com".to_string(),
                inherit: true,
                admin: false,
            },
            Change::RemoveMember {
                grantor: None,
                role: "editors".to_string(),
                member: "old@example.com".to_string(),
            },
            Change::TerminateSessions {
                role: "retired-role".to_string(),
            },
            Change::ReassignOwned {
                from_role: "retired-role".to_string(),
                to_role: "successor".to_string(),
            },
            Change::DropOwned {
                role: "retired-role".to_string(),
            },
            Change::DropRole {
                name: "retired-role".to_string(),
            },
        ]
    }

    #[test]
    fn filter_authoritative_keeps_all_changes() {
        let changes = all_change_variants();
        let original_len = changes.len();
        let filtered = filter_changes(changes, ReconciliationMode::Authoritative);
        assert_eq!(filtered.len(), original_len);
    }

    #[test]
    fn filter_additive_keeps_only_constructive_changes() {
        let filtered = filter_changes(all_change_variants(), ReconciliationMode::Additive);

        // Should keep: CreateRole, CreateSchema, Grant, SetDefaultPrivilege, AddMember
        assert_eq!(filtered.len(), 5);

        // Verify no destructive changes remain
        for change in &filtered {
            assert!(
                !matches!(
                    change,
                    Change::AlterSchemaOwner { .. }
                        | Change::EnsureSchemaOwnerPrivileges { .. }
                        | Change::AlterRole { .. }
                        | Change::SetComment { .. }
                        | Change::Revoke { .. }
                        | Change::RevokeDefaultPrivilege { .. }
                        | Change::RemoveMember { .. }
                        | Change::DropRole { .. }
                        | Change::DropOwned { .. }
                        | Change::ReassignOwned { .. }
                        | Change::TerminateSessions { .. }
                ),
                "additive mode should not contain destructive change: {change:?}"
            );
        }

        // Verify constructive changes are present
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::CreateRole { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::CreateSchema { .. }))
        );
        assert!(
            filtered
                .iter()
                .all(|c| !matches!(c, Change::AlterRole { .. } | Change::SetComment { .. }))
        );
        assert!(filtered.iter().any(|c| matches!(c, Change::Grant { .. })));
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::SetDefaultPrivilege { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::AddMember { .. }))
        );
    }

    #[test]
    fn filter_additive_keeps_config_alters_for_roles_created_in_same_plan() {
        // Config for a new role is emitted as a follow-up AlterRole with only
        // SetConfig attributes. It is part of the creation, so additive mode
        // must keep it — otherwise additive-created roles would silently lose
        // their declared config.
        let changes = vec![
            Change::CreateRole {
                name: "blue".to_string(),
                state: RoleState::default(),
            },
            Change::AlterRole {
                name: "blue".to_string(),
                attributes: vec![RoleAttribute::SetConfig(
                    "role".to_string(),
                    "combined".to_string(),
                )],
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert_eq!(filtered.len(), 2);
        assert!(matches!(&filtered[1], Change::AlterRole { name, .. } if name == "blue"));
    }

    #[test]
    fn filter_additive_drops_config_alters_for_pre_existing_roles() {
        // No CreateRole for "blue" in this plan — the role pre-exists, so
        // additive mode must not mutate its config.
        let changes = vec![Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![
                RoleAttribute::SetConfig("role".to_string(), "combined".to_string()),
                RoleAttribute::ResetConfig("statement_timeout".to_string()),
            ],
        }];

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_additive_drops_mixed_attribute_and_config_alters_even_for_created_roles() {
        // The diff engine only emits pure-SetConfig follow-ups for created
        // roles; anything mixing attribute rewrites stays filtered so the
        // exemption cannot widen additive mode's alter surface.
        let changes = vec![
            Change::CreateRole {
                name: "blue".to_string(),
                state: RoleState::default(),
            },
            Change::AlterRole {
                name: "blue".to_string(),
                attributes: vec![
                    RoleAttribute::Login(true),
                    RoleAttribute::SetConfig("role".to_string(), "combined".to_string()),
                ],
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert_eq!(filtered.len(), 1);
        assert!(matches!(&filtered[0], Change::CreateRole { .. }));
    }

    #[test]
    fn filter_additive_skips_owner_bound_follow_ups_when_transfer_is_skipped() {
        let changes = vec![
            Change::AlterSchemaOwner {
                name: "inventory".to_string(),
                owner: "new_owner".to_string(),
            },
            Change::EnsureSchemaOwnerPrivileges {
                name: "inventory".to_string(),
                owner: "new_owner".to_string(),
                privileges: BTreeSet::from([Privilege::Create, Privilege::Usage]),
            },
            Change::SetDefaultPrivilege {
                owner: "new_owner".to_string(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "inventory".to_string(),
                },
                on_type: ObjectType::Table,
                grantee: "inventory-editor".into(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::Grant {
                role: "inventory-editor".into(),
                privileges: BTreeSet::from([Privilege::Usage]),
                object_type: ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert_eq!(filtered.len(), 1);
        assert!(
            matches!(&filtered[0], Change::Grant { role, .. } if role.as_str() == "inventory-editor")
        );
    }

    #[test]
    fn filter_adopt_keeps_revokes_but_not_drops() {
        let filtered = filter_changes(all_change_variants(), ReconciliationMode::Adopt);

        // Should keep everything except: DropRole, DropOwned, ReassignOwned, TerminateSessions
        assert_eq!(filtered.len(), 12);

        // Verify no role-drop/retirement changes remain
        for change in &filtered {
            assert!(
                !matches!(
                    change,
                    Change::DropRole { .. }
                        | Change::DropOwned { .. }
                        | Change::ReassignOwned { .. }
                        | Change::TerminateSessions { .. }
                ),
                "adopt mode should not contain drop/retirement change: {change:?}"
            );
        }

        // Verify revokes ARE still present (unlike additive)
        assert!(filtered.iter().any(|c| matches!(c, Change::Revoke { .. })));
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::RevokeDefaultPrivilege { .. }))
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, Change::RemoveMember { .. }))
        );
    }

    #[test]
    fn filter_additive_with_empty_input() {
        let filtered = filter_changes(vec![], ReconciliationMode::Additive);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_additive_only_destructive_changes_yields_empty() {
        let changes = vec![
            Change::Revoke {
                grantor: None,
                role: "r1".into(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
        ];
        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_adopt_preserves_ordering() {
        let changes = vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: RoleState::default(),
            },
            Change::Grant {
                role: "new-role".into(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::Revoke {
                grantor: None,
                role: "existing-role".into(),
                privileges: BTreeSet::from([Privilege::Insert]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
        ];

        let filtered = filter_changes(changes, ReconciliationMode::Adopt);
        assert_eq!(filtered.len(), 3);
        assert!(matches!(&filtered[0], Change::CreateRole { name, .. } if name == "new-role"));
        assert!(matches!(&filtered[1], Change::Grant { .. }));
        assert!(matches!(&filtered[2], Change::Revoke { .. }));
    }

    #[test]
    fn reconciliation_mode_display() {
        assert_eq!(
            ReconciliationMode::Authoritative.to_string(),
            "authoritative"
        );
        assert_eq!(ReconciliationMode::Additive.to_string(), "additive");
        assert_eq!(ReconciliationMode::Adopt.to_string(), "adopt");
    }

    #[test]
    fn reconciliation_mode_default_is_authoritative() {
        assert_eq!(
            ReconciliationMode::default(),
            ReconciliationMode::Authoritative
        );
    }

    // -----------------------------------------------------------------------
    // apply_role_retirements tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_role_retirements_inserts_cleanup_before_drop() {
        let changes = vec![
            Change::Grant {
                role: "analytics".into(),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            Change::DropRole {
                name: "old-app".to_string(),
            },
        ];

        let planned = apply_role_retirements(
            changes,
            &[crate::manifest::RoleRetirement {
                role: "old-app".to_string(),
                reassign_owned_to: Some("successor".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
        );

        assert!(matches!(planned[0], Change::Grant { .. }));
        assert!(matches!(
            planned[1],
            Change::TerminateSessions { ref role } if role == "old-app"
        ));
        assert!(matches!(
            planned[2],
            Change::ReassignOwned {
                ref from_role,
                ref to_role
            } if from_role == "old-app" && to_role == "successor"
        ));
        assert!(matches!(
            planned[3],
            Change::DropOwned { ref role } if role == "old-app"
        ));
        assert!(matches!(
            planned[4],
            Change::DropRole { ref name } if name == "old-app"
        ));
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn inject_password_for_new_role() {
        let changes = vec![Change::CreateRole {
            name: "app-svc".to_string(),
            state: RoleState::default(),
        }];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("app-svc".to_string(), "secret123".to_string());

        let result = inject_password_changes(changes, &passwords);
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[0], Change::CreateRole { name, .. } if name == "app-svc"));
        assert!(
            matches!(&result[1], Change::SetPassword { name, password } if name == "app-svc" && password.starts_with("SCRAM-SHA-256$"))
        );
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn inject_password_for_existing_role() {
        // No CreateRole — role already exists. Only grants change.
        let changes = vec![Change::Grant {
            role: "app-svc".into(),
            privileges: BTreeSet::from([crate::manifest::Privilege::Select]),
            object_type: crate::manifest::ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        }];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("app-svc".to_string(), "secret123".to_string());

        let result = inject_password_changes(changes, &passwords);
        assert_eq!(result.len(), 2);
        assert!(matches!(&result[0], Change::Grant { .. }));
        assert!(
            matches!(&result[1], Change::SetPassword { name, password } if name == "app-svc" && password.starts_with("SCRAM-SHA-256$"))
        );
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn inject_password_empty_passwords_is_noop() {
        let changes = vec![Change::CreateRole {
            name: "app-svc".to_string(),
            state: RoleState::default(),
        }];

        let passwords = std::collections::BTreeMap::new();
        let result = inject_password_changes(changes.clone(), &passwords);
        assert_eq!(result.len(), 1);
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn resolve_passwords_missing_env_var() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_MISSING_VAR_9a8b7c6d".to_string(),
            }),
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // Ensure the env var does not exist.
        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::remove_var("PGROLES_TEST_MISSING_VAR_9a8b7c6d") };

        let result = resolve_passwords(&roles);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PasswordResolutionError::MissingEnvVar { ref role, ref env_var }
                if role == "app-svc" && env_var == "PGROLES_TEST_MISSING_VAR_9a8b7c6d"),
            "expected MissingEnvVar, got: {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn resolve_passwords_empty_env_var() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_EMPTY_VAR_1a2b3c4d".to_string(),
            }),
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // Set the env var to an empty string.
        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::set_var("PGROLES_TEST_EMPTY_VAR_1a2b3c4d", "") };

        let result = resolve_passwords(&roles);

        // Clean up.
        unsafe { std::env::remove_var("PGROLES_TEST_EMPTY_VAR_1a2b3c4d") };

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, PasswordResolutionError::EmptyPassword { ref role, ref env_var }
                if role == "app-svc" && env_var == "PGROLES_TEST_EMPTY_VAR_1a2b3c4d"),
            "expected EmptyPassword, got: {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn resolve_passwords_happy_path() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "app-svc".to_string(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_RESOLVE_VAR_5e6f7g8h".to_string(),
            }),
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::set_var("PGROLES_TEST_RESOLVE_VAR_5e6f7g8h", "my_secret_pw") };

        let result = resolve_passwords(&roles);

        unsafe { std::env::remove_var("PGROLES_TEST_RESOLVE_VAR_5e6f7g8h") };

        let resolved = result.expect("should succeed");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved["app-svc"], "my_secret_pw");
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn resolve_passwords_skips_external_roles() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "external-svc".to_string(),
            external: true,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: Some(crate::manifest::PasswordSource {
                from_env: "PGROLES_TEST_EXTERNAL_MISSING_VAR_2b4d6f8h".to_string(),
            }),
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        // SAFETY: test-only, unique var name avoids conflicts with parallel tests.
        unsafe { std::env::remove_var("PGROLES_TEST_EXTERNAL_MISSING_VAR_2b4d6f8h") };

        let resolved = resolve_passwords(&roles).expect("external role passwords are ignored");
        assert!(resolved.is_empty());
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn resolve_passwords_skips_roles_without_password() {
        let roles = vec![crate::manifest::RoleDefinition {
            name: "no-password".to_string(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: None,
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];

        let result = resolve_passwords(&roles);
        let resolved = result.expect("should succeed");
        assert!(resolved.is_empty());
    }

    #[test]
    #[cfg(feature = "passwords")]
    fn inject_password_multiple_roles() {
        let changes = vec![
            Change::CreateRole {
                name: "role-a".to_string(),
                state: RoleState::default(),
            },
            Change::CreateRole {
                name: "role-b".to_string(),
                state: RoleState::default(),
            },
            Change::Grant {
                role: "role-c".into(),
                privileges: BTreeSet::from([crate::manifest::Privilege::Select]),
                object_type: crate::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
        ];

        let mut passwords = std::collections::BTreeMap::new();
        passwords.insert("role-a".to_string(), "pw-a".to_string());
        passwords.insert("role-b".to_string(), "pw-b".to_string());
        passwords.insert("role-c".to_string(), "pw-c".to_string());

        let result = inject_password_changes(changes, &passwords);

        // role-a: CreateRole, SetPassword (inline)
        // role-b: CreateRole, SetPassword (inline)
        // role-c: Grant (existing role — SetPassword appended at end)
        assert_eq!(result.len(), 6, "expected 6 changes, got: {result:?}");
        assert!(matches!(&result[0], Change::CreateRole { name, .. } if name == "role-a"));
        assert!(matches!(&result[1], Change::SetPassword { name, .. } if name == "role-a"));
        assert!(matches!(&result[2], Change::CreateRole { name, .. } if name == "role-b"));
        assert!(matches!(&result[3], Change::SetPassword { name, .. } if name == "role-b"));
        assert!(matches!(&result[4], Change::Grant { .. }));
        assert!(matches!(&result[5], Change::SetPassword { name, .. } if name == "role-c"));
    }

    #[test]
    fn diff_detects_valid_until_change() {
        let mut current = empty_graph();
        current.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let mut desired = empty_graph();
        desired.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
                config: Default::default(),
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "r1");
                assert!(attributes.contains(&RoleAttribute::ValidUntil(Some(
                    "2025-12-31T00:00:00Z".to_string()
                ))));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }

    /// Reproduces a production reconcile flap: when the desired
    /// graph has a wildcard grant `(role, schema, type, "*")` and `current`
    /// has only per-name entries (because the inspector's wildcard collapse
    /// failed — typically because at least one inventory object lacks the
    /// privilege, e.g. a function that was DROPped+CREATEd between reconciles
    /// resetting its proacl to NULL), `diff()` must NOT emit per-name REVOKEs
    /// for objects covered by the desired wildcard. Otherwise apply order
    /// (GRANTs before REVOKEs) re-grants on ALL ROUTINES and then strips
    /// privileges from the previously-granted set, producing a permanent
    /// oscillation between two stable states.
    #[test]
    fn diff_does_not_revoke_per_name_grants_covered_by_desired_wildcard() {
        let role: Grantee = "cdc-editor".into();
        let schema = "cdc".to_string();
        let object_type = ObjectType::Function;

        // current: per-name EXECUTE grants for f1 and f3 only — f2 was
        // recreated externally (proacl=NULL) so the inspector did not produce
        // a row for it, the wildcard collapse failed, and per-name entries
        // remain in the graph.
        let mut current = empty_graph();
        for fn_name in ["f1()", "f3()"] {
            current.grants.insert(
                GrantKey {
                    role: role.clone(),
                    object_type,
                    schema: Some(schema.clone()),
                    name: Some(fn_name.to_string()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Execute]),
                },
            );
        }

        // desired: a single wildcard grant declaring EXECUTE on every function
        // in the schema.
        let mut desired = empty_graph();
        desired.grants.insert(
            GrantKey {
                role: role.clone(),
                object_type,
                schema: Some(schema.clone()),
                name: Some("*".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Execute]),
            },
        );

        let changes = diff(&current, &desired);

        let revokes: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Revoke { .. }))
            .collect();
        assert!(
            revokes.is_empty(),
            "must not revoke per-name grants covered by desired wildcard \
             (would cause apply-order flap); got: {revokes:#?}"
        );

        let grants: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Grant { .. }))
            .collect();
        assert_eq!(
            grants.len(),
            1,
            "expected a single wildcard GRANT to materialise ACLs on all functions; got: {grants:#?}"
        );
        match grants[0] {
            Change::Grant {
                role: r,
                name,
                privileges,
                ..
            } => {
                assert_eq!(r, &role);
                assert_eq!(name.as_deref(), Some("*"));
                assert!(privileges.contains(&Privilege::Execute));
            }
            other => panic!("expected wildcard Grant, got: {other:?}"),
        }
    }

    /// Companion to the absent-key flap test above: the matched-key branch
    /// of `diff_grants` (where current and desired share a per-name entry)
    /// must also subtract desired-wildcard privileges from the revoke set.
    /// Concrete shape: a manifest combines `table * SELECT` (wildcard) with
    /// `widgets INSERT` (per-object extra). If wildcard collapse fails and
    /// `current` carries `widgets {SELECT, INSERT}`, the matched-key diff
    /// computes `to_remove = {SELECT}` against desired `widgets {INSERT}`
    /// — but SELECT is still declared by the wildcard, so revoking it here
    /// produces the same apply-order hazard (GRANT * SELECT, then
    /// REVOKE widgets SELECT → widgets ends up with INSERT only, the
    /// wildcard is unsatisfied, the next reconcile inverts again).
    #[test]
    fn diff_does_not_revoke_extra_privileges_covered_by_desired_wildcard() {
        let role: Grantee = "viewer".into();
        let schema = "myschema".to_string();
        let object_type = ObjectType::Table;

        // current: widgets has the wildcard's SELECT plus the extra INSERT.
        // The wildcard's `(*)` key is absent from current (collapse failed).
        let mut current = empty_graph();
        current.grants.insert(
            GrantKey {
                role: role.clone(),
                object_type,
                schema: Some(schema.clone()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            },
        );

        // desired: wildcard SELECT plus per-object widgets INSERT.
        let mut desired = empty_graph();
        desired.grants.insert(
            GrantKey {
                role: role.clone(),
                object_type,
                schema: Some(schema.clone()),
                name: Some("*".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        desired.grants.insert(
            GrantKey {
                role: role.clone(),
                object_type,
                schema: Some(schema.clone()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Insert]),
            },
        );

        let changes = diff(&current, &desired);

        let revokes: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Revoke { .. }))
            .collect();
        assert!(
            revokes.is_empty(),
            "must not revoke widgets SELECT — covered by desired wildcard; got: {revokes:#?}"
        );

        // Should still emit the wildcard GRANT to materialise SELECT on
        // every table (the reason the wildcard is unsatisfied in current).
        let grants: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Grant { .. }))
            .collect();
        let has_wildcard_select_grant = grants.iter().any(|c| {
            matches!(
                c,
                Change::Grant {
                    name,
                    privileges,
                    ..
                } if name.as_deref() == Some("*")
                    && privileges.contains(&Privilege::Select)
            )
        });
        assert!(
            has_wildcard_select_grant,
            "expected wildcard GRANT for SELECT; got: {grants:#?}"
        );
    }

    #[test]
    fn diff_detects_valid_until_removal() {
        let mut current = empty_graph();
        current.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
                config: Default::default(),
                ..RoleState::default()
            },
        );

        let mut desired = empty_graph();
        desired.roles.insert(
            "r1".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            Change::AlterRole { name, attributes } => {
                assert_eq!(name, "r1");
                assert!(attributes.contains(&RoleAttribute::ValidUntil(None)));
            }
            other => panic!("expected AlterRole, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Absence assertions (ensure: absent)
    // -----------------------------------------------------------------------

    fn public_function_key(schema: &str, name: &str) -> GrantKey {
        GrantKey {
            role: Grantee::Public,
            object_type: ObjectType::Function,
            schema: Some(schema.to_string()),
            name: Some(name.to_string()),
        }
    }

    fn graph_with_public_grant(schema: &str, name: &str, privileges: &[Privilege]) -> RoleGraph {
        let mut graph = RoleGraph::default();
        graph.grants.insert(
            public_function_key(schema, name),
            GrantState {
                privileges: privileges.iter().copied().collect(),
            },
        );
        graph
    }

    #[test]
    fn absence_revokes_only_the_privileges_actually_held() {
        let current = graph_with_public_grant("api", "f()", &[Privilege::Execute]);
        let mut desired = RoleGraph::default();
        desired.grant_absences.insert(
            public_function_key("api", "f()"),
            [Privilege::Execute, Privilege::Usage].into_iter().collect(),
        );

        let changes = diff(&current, &desired);
        assert_eq!(
            changes,
            vec![Change::Revoke {
                grantor: None,
                role: Grantee::Public,
                privileges: [Privilege::Execute].into_iter().collect(),
                object_type: ObjectType::Function,
                schema: Some("api".to_string()),
                name: Some("f()".to_string()),
            }]
        );
    }

    #[test]
    fn absence_of_a_privilege_that_is_not_held_plans_nothing() {
        let current = graph_with_public_grant("api", "f()", &[Privilege::Execute]);
        let mut desired = RoleGraph::default();
        desired.grant_absences.insert(
            public_function_key("api", "f()"),
            [Privilege::Usage].into_iter().collect(),
        );

        assert!(diff(&current, &desired).is_empty());
    }

    #[test]
    fn wildcard_absence_revokes_each_matching_object() {
        let mut current = RoleGraph::default();
        for name in ["f(integer)", "f(text)", "g()"] {
            current.grants.insert(
                public_function_key("api", name),
                GrantState {
                    privileges: [Privilege::Execute].into_iter().collect(),
                },
            );
        }

        let mut desired = RoleGraph::default();
        desired.grant_absences.insert(
            GrantKey {
                role: Grantee::Public,
                object_type: ObjectType::Function,
                schema: Some("api".to_string()),
                name: Some("*".to_string()),
            },
            [Privilege::Execute].into_iter().collect(),
        );

        let changes = diff(&current, &desired);
        assert_eq!(
            changes,
            ["f(integer)", "f(text)", "g()"]
                .into_iter()
                .map(|name| change_revoke(
                    &public_function_key("api", name),
                    &BTreeSet::from([Privilege::Execute]),
                    None
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn wildcard_absence_over_an_empty_scope_is_vacuously_converged() {
        let mut desired = RoleGraph::default();
        desired.grant_absences.insert(
            GrantKey {
                role: Grantee::Public,
                object_type: ObjectType::Function,
                schema: Some("api".to_string()),
                name: Some("*".to_string()),
            },
            [Privilege::Execute].into_iter().collect(),
        );

        assert!(diff(&RoleGraph::default(), &desired).is_empty());
    }

    #[test]
    fn unmentioned_public_grants_are_never_revoked() {
        // PUBLIC state is assertion-driven: without an absence rule naming it,
        // a live PUBLIC grant is unmanaged, not drift.
        let current = graph_with_public_grant("api", "f()", &[Privilege::Execute]);
        assert!(diff(&current, &RoleGraph::default()).is_empty());

        // Same for a PUBLIC key the manifest declares with other privileges.
        let mut desired = RoleGraph::default();
        desired.grants.insert(
            public_function_key("api", "f()"),
            GrantState {
                privileges: [Privilege::Usage].into_iter().collect(),
            },
        );
        let changes = diff(&current, &desired);
        assert!(
            changes
                .iter()
                .all(|change| !matches!(change, Change::Revoke { .. })),
            "unexpected revoke in {changes:?}"
        );
    }

    #[test]
    fn a_key_hit_by_convergence_and_absence_emits_one_merged_revoke() {
        let key = GrantKey {
            role: "reader".into(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("t".to_string()),
        };
        let mut current = RoleGraph::default();
        current.grants.insert(
            key.clone(),
            GrantState {
                privileges: [Privilege::Select, Privilege::Insert, Privilege::Delete]
                    .into_iter()
                    .collect(),
            },
        );

        let mut desired = RoleGraph::default();
        desired.grants.insert(
            key.clone(),
            GrantState {
                privileges: [Privilege::Select].into_iter().collect(),
            },
        );
        desired
            .grant_absences
            .insert(key, [Privilege::Delete].into_iter().collect());

        let changes = diff(&current, &desired);
        let revokes: Vec<&Change> = changes
            .iter()
            .filter(|change| matches!(change, Change::Revoke { .. }))
            .collect();
        assert_eq!(revokes.len(), 1, "expected one merged revoke: {revokes:?}");
        let Change::Revoke { privileges, .. } = revokes[0] else {
            unreachable!()
        };
        assert_eq!(
            *privileges,
            [Privilege::Insert, Privilege::Delete]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn default_privilege_absence_revokes_in_both_scopes() {
        let global_key = DefaultPrivKey {
            owner: "owner".to_string(),
            scope: DefaultPrivilegeScope::Global,
            on_type: ObjectType::Function,
            grantee: Grantee::Public,
        };
        let schema_key = DefaultPrivKey {
            owner: "owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "api".to_string(),
            },
            on_type: ObjectType::Function,
            grantee: Grantee::Public,
        };

        let mut current = RoleGraph::default();
        for key in [&global_key, &schema_key] {
            current.default_privileges.insert(
                key.clone(),
                DefaultPrivState {
                    privileges: [Privilege::Execute].into_iter().collect(),
                },
            );
        }

        let mut desired = RoleGraph::default();
        for key in [&global_key, &schema_key] {
            desired
                .default_privilege_absences
                .insert(key.clone(), [Privilege::Execute].into_iter().collect());
        }

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(changes.iter().all(|change| matches!(
            change,
            Change::RevokeDefaultPrivilege {
                grantee: Grantee::Public,
                ..
            }
        )));
    }

    #[test]
    fn global_public_absence_revokes_builtin_for_owner_created_in_same_plan() {
        let key = DefaultPrivKey {
            owner: "new_owner".to_string(),
            scope: DefaultPrivilegeScope::Global,
            on_type: ObjectType::Function,
            grantee: Grantee::Public,
        };
        let current = RoleGraph::default();
        let mut desired = RoleGraph::default();
        desired
            .roles
            .insert("new_owner".to_string(), RoleState::default());
        desired
            .default_privilege_absences
            .insert(key, BTreeSet::from([Privilege::Execute]));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(matches!(
            &changes[0],
            Change::CreateRole { name, .. } if name == "new_owner"
        ));
        assert!(matches!(
            &changes[1],
            Change::RevokeDefaultPrivilege {
                owner,
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Function,
                grantee: Grantee::Public,
                privileges,
            } if owner == "new_owner" && privileges == &BTreeSet::from([Privilege::Execute])
        ));
    }

    #[test]
    fn global_public_type_absence_revokes_builtin_for_owner_created_in_same_plan() {
        let key = DefaultPrivKey {
            owner: "new_owner".to_string(),
            scope: DefaultPrivilegeScope::Global,
            on_type: ObjectType::Type,
            grantee: Grantee::Public,
        };
        let current = RoleGraph::default();
        let mut desired = RoleGraph::default();
        desired
            .roles
            .insert("new_owner".to_string(), RoleState::default());
        desired
            .default_privilege_absences
            .insert(key, BTreeSet::from([Privilege::Usage]));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(matches!(
            &changes[0],
            Change::CreateRole { name, .. } if name == "new_owner"
        ));
        assert!(matches!(
            &changes[1],
            Change::RevokeDefaultPrivilege {
                owner,
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Type,
                grantee: Grantee::Public,
                privileges,
            } if owner == "new_owner" && privileges == &BTreeSet::from([Privilege::Usage])
        ));
    }

    #[test]
    fn schema_public_absence_does_not_invent_a_builtin_for_new_owner() {
        let key = DefaultPrivKey {
            owner: "new_owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "api".to_string(),
            },
            on_type: ObjectType::Function,
            grantee: Grantee::Public,
        };
        let current = RoleGraph::default();
        let mut desired = RoleGraph::default();
        desired
            .roles
            .insert("new_owner".to_string(), RoleState::default());
        desired
            .default_privilege_absences
            .insert(key, BTreeSet::from([Privilege::Execute]));

        let changes = diff(&current, &desired);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(matches!(&changes[0], Change::CreateRole { .. }));
    }

    #[test]
    fn additive_mode_ignores_absence_while_adopt_and_authoritative_apply_it() {
        let current = graph_with_public_grant("api", "f()", &[Privilege::Execute]);
        let mut desired = RoleGraph::default();
        desired.grant_absences.insert(
            public_function_key("api", "f()"),
            [Privilege::Execute].into_iter().collect(),
        );
        // A role creation in the same plan proves additive keeps the rest of it.
        desired
            .roles
            .insert("newcomer".to_string(), RoleState::default());

        let changes = diff(&current, &desired);

        let additive = filter_changes(changes.clone(), ReconciliationMode::Additive);
        assert!(
            !additive
                .iter()
                .any(|change| matches!(change, Change::Revoke { .. })),
            "additive must ignore absence: {additive:?}"
        );
        assert!(
            additive
                .iter()
                .any(|change| matches!(change, Change::CreateRole { .. })),
            "additive must keep the rest of the plan"
        );

        for mode in [ReconciliationMode::Adopt, ReconciliationMode::Authoritative] {
            let filtered = filter_changes(changes.clone(), mode);
            assert!(
                filtered
                    .iter()
                    .any(|change| matches!(change, Change::Revoke { .. })),
                "{mode:?} must apply absence"
            );
        }

        assert!(additive_ignores_absence_assertions(
            &desired,
            ReconciliationMode::Additive
        ));
        assert!(!additive_ignores_absence_assertions(
            &desired,
            ReconciliationMode::Adopt
        ));
        assert!(!additive_ignores_absence_assertions(
            &RoleGraph::default(),
            ReconciliationMode::Additive
        ));
    }

    #[test]
    fn additive_mode_ignores_exclusive_membership_but_warns() {
        // `exclusive: true` is a declarative absence assertion: its revokes
        // are stripped in additive mode like every RemoveMember, and the
        // warning predicate must surface that safety-relevant no-op.
        let mut desired = empty_graph();
        desired
            .exclusive_membership_roles
            .insert("pg_read_all_data".to_string());
        desired.memberships.insert(MembershipEdge {
            role: "pg_read_all_data".to_string(),
            member: "auditor".to_string(),
            inherit: true,
            admin: false,
        });

        let changes = vec![Change::RemoveMember {
            grantor: None,
            role: "pg_read_all_data".to_string(),
            member: "forgotten_contractor".to_string(),
        }];
        // The exclusive filter keeps the revoke...
        let kept = filter_external_role_changes(
            changes.clone(),
            &[],
            &[membership("pg_read_all_data", &["auditor"], true)],
        );
        assert_eq!(kept, changes);
        // ...but additive mode strips it before that filter ever runs.
        let additive = filter_changes(changes, ReconciliationMode::Additive);
        assert!(additive.is_empty());

        assert!(additive_ignores_absence_assertions(
            &desired,
            ReconciliationMode::Additive
        ));
        assert!(!additive_ignores_absence_assertions(
            &desired,
            ReconciliationMode::Authoritative
        ));
    }

    #[test]
    fn exclusive_membership_populates_graph_assertion_set() {
        use crate::manifest::{expand_manifest, parse_manifest};
        let manifest = parse_manifest(
            r#"
roles:
  - name: auditor
    login: true

memberships:
  - role: pg_read_all_data
    exclusive: true
    members:
      - name: auditor
"#,
        )
        .unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let desired = RoleGraph::from_expanded(&expanded, None).unwrap();
        assert!(
            desired
                .exclusive_membership_roles
                .contains("pg_read_all_data")
        );
    }
}
