//! Executor-authority preflight for planned changes.
//!
//! Several failure modes are caught before apply:
//!
//! `ALTER DEFAULT PRIVILEGES FOR ROLE owner` requires the executor to be a
//! member of the owner role (or a superuser). Without that, apply fails
//! mid-transaction with a permission error, so the check only moves the
//! failure earlier and names the owner.
//!
//! `REVOKE` can be worse than a loud failure: every grant is attributed to a
//! grantor, and a plain REVOKE removes only the entry of the *one* grantor
//! PostgreSQL selects for the executor. A REVOKE that matches no such entry
//! silently removes nothing — the next inspection still sees the privilege,
//! and the controller re-plans the same revoke forever.
//!
//! The selection rules, verified live against PostgreSQL 16:
//!
//! * **Object privileges**: the executor itself when it holds the privilege
//!   `WITH GRANT OPTION` (shadowing the owner even for owner members),
//!   otherwise the object's owner when the executor can act as the owner —
//!   which includes superusers, whose GRANT/REVOKE "is performed as though
//!   it were issued by the owner of the affected object" (upstream REVOKE
//!   notes). An entry a delegate granted onward therefore survives
//!   *everyone's* plain revoke except the delegate's own, superusers
//!   included, and `GRANTED BY` for object privileges must name the current
//!   user — only revoking the delegate's grant option with `CASCADE` clears
//!   it.
//! * **Role memberships** (PostgreSQL 16+, which records a grantor per
//!   edge): the executor itself under direct ADMIN OPTION; for superusers
//!   the bootstrap superuser, which is also how grants *by* any superuser
//!   are recorded. An edge granted by an ordinary role survives even a
//!   superuser's bare revoke, with only a WARNING; `REVOKE ... GRANTED BY`
//!   works for any role holding the grantor's privileges.
//!
//! Grantor-targeted changes (the normal case — inspection records every
//! entry's grantor, PUBLIC entries included) are checked exactly: per
//! grantor, can the executor become it. The remaining sweeps cover only
//! *plain* revokes — grantor-less snapshots and wildcard-collapsed keys —
//! where the conservative owner/`pg_has_role` tests apply and the operator's
//! post-apply non-convergence detection remains the backstop for the
//! shadowing case.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

use pgroles_core::diff::Change;
use pgroles_core::manifest::{ObjectType, is_predefined_role, predefined_role_min_version};
use pgroles_core::model::{GrantKey, Grantee, RoleGraph};

/// Maximum number of objects named by an [`AuthorityIssue::PublicRevoke`].
const REVOKE_EXAMPLE_LIMIT: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityIssue {
    /// The executor cannot act as the owner of a planned
    /// `ALTER DEFAULT PRIVILEGES` change.
    DefaultPrivilegeOwner { owner: String, executor: String },

    /// A planned `ALTER DEFAULT PRIVILEGES` names an owner that does not
    /// exist and that this plan does not create.
    MissingDefaultPrivilegeOwner { owner: String },

    /// A planned membership change grants or revokes a predefined (`pg_*`)
    /// role, and the executor lacks ADMIN OPTION on it. In PostgreSQL 16+
    /// this effectively requires a superuser executor or an explicit
    /// `GRANT <pg_role> TO executor WITH ADMIN OPTION`; `CREATEROLE` alone
    /// is not sufficient.
    PredefinedRoleGrant { role: String, executor: String },

    /// A manifest membership names a predefined (`pg_*`) role the connected
    /// server does not have. `min_version` carries the PostgreSQL major
    /// version that introduced the role when it is one we recognize.
    MissingPredefinedRole {
        role: String,
        server_major: u32,
        min_version: Option<u32>,
    },

    /// A planned `REVOKE ... FROM PUBLIC` covers objects whose owners the
    /// executor cannot act as, so the revoke would silently do nothing there.
    PublicRevoke {
        object_type: ObjectType,
        schema: Option<String>,
        executor: String,
        skipped_count: usize,
        /// Up to [`REVOKE_EXAMPLE_LIMIT`] affected objects as
        /// `(name, owner)`.
        examples: Vec<(String, String)>,
    },

    /// A planned `REVOKE ... FROM <role>` targets ACL entries the executor's
    /// plain REVOKE cannot remove: PostgreSQL revokes only the entry of the
    /// one grantor it selects for the executor, and a REVOKE matching no such
    /// entry succeeds silently — no error, no warning — so these entries
    /// would survive and the same drift would re-plan on every run.
    ///
    /// This is the ordinary-grantee sibling of [`AuthorityIssue::PublicRevoke`]
    /// and checks per ACL entry: an entry a delegate granted onward via
    /// `WITH GRANT OPTION` is unremovable even for an owner-acting executor —
    /// superusers included, whose revoke is performed as though issued by the
    /// owner. A residue remains for non-superuser executors: an entry whose
    /// grantor is reachable can still survive when PostgreSQL's grantor
    /// selection prefers another path (the executor's own grant option
    /// shadowing the owner's), which only the post-apply non-convergence
    /// detection catches.
    ForeignGrantorRevoke {
        object_type: ObjectType,
        schema: Option<String>,
        grantee: String,
        executor: String,
        skipped_count: usize,
        /// Up to [`REVOKE_EXAMPLE_LIMIT`] surviving entries as
        /// `(object name, grantor)`.
        examples: Vec<(String, String)>,
    },

    /// A planned membership `REVOKE <role> FROM <member>` targets an edge
    /// the executor's plain REVOKE cannot remove (PostgreSQL 16+).
    ///
    /// Since PostgreSQL 16 each membership edge records its grantor, and a
    /// bare `REVOKE` removes only the edge whose grantor the revoke is
    /// attributed to — the executor under direct ADMIN OPTION, or for a
    /// superuser the bootstrap superuser. Any other edge survives with just
    /// a WARNING ("role ... has not been granted membership ... by role
    /// ...") — an edge granted by an ordinary role survives even a
    /// superuser's bare revoke — so the same revocation re-plans on every
    /// run. `REVOKE ... GRANTED BY <grantor>` removes it, but requires the
    /// privileges of that grantor.
    ForeignGrantorMembershipRevoke {
        role: String,
        member: String,
        grantor: String,
        executor: String,
    },

    /// A planned object-privilege revoke targets an ACL entry attributed to
    /// `grantor`, and the executor cannot become that grantor. The revoke is
    /// rendered as `SET ROLE <grantor>; REVOKE ...;` (restoring the
    /// configured execution role afterwards) because a
    /// plain REVOKE removes only the entry of the grantor PostgreSQL selects
    /// for the executor (and `GRANTED BY` for object privileges must name the
    /// current user) — without SET ROLE feasibility the statement fails or
    /// the entry silently survives.
    RevokeGrantorUnavailable { grantor: String, executor: String },

    /// The plan itself removes the executor's membership path to a role it
    /// must still act as later in the same plan.
    ///
    /// Membership removals execute in one transaction with everything else.
    /// A `REVOKE ... GRANTED BY <grantor>` (membership revoke) and an
    /// `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` both require the
    /// privileges of the named role at the moment the statement runs — and a
    /// membership removal earlier in the plan can strip exactly that path,
    /// so a preflight against the *current* graph would pass while execution
    /// fails and rolls back. This issue flags such dependency-breaking plans
    /// phase by phase: membership revokes are checked against the graph with
    /// the plan's removals applied, default-privilege revokes against the
    /// graph with the plan's removals *and* inheriting additions applied —
    /// they execute after the addition batch, so an option change or a newly
    /// declared membership can legitimately restore the path first.
    GrantorAuthorityRemovedByPlan { grantor: String, executor: String },
}

impl std::fmt::Display for AuthorityIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityIssue::DefaultPrivilegeOwner { owner, executor } => write!(
                f,
                "UnsatisfiableDefaultPrivilegeChange: cannot ALTER DEFAULT PRIVILEGES \
                 FOR ROLE \"{owner}\" as executor \"{executor}\"; requires membership \
                 in the owner role or superuser"
            ),
            AuthorityIssue::MissingDefaultPrivilegeOwner { owner } => write!(
                f,
                "UnsatisfiableDefaultPrivilegeChange: default privileges name owner \"{owner}\", \
                 which does not exist and is not created by this plan"
            ),
            AuthorityIssue::PredefinedRoleGrant { role, executor } => write!(
                f,
                "UnsatisfiableMembershipChange: cannot GRANT/REVOKE predefined role \
                 \"{role}\" as executor \"{executor}\"; requires ADMIN OPTION on it — \
                 use a superuser executor or an explicit \
                 GRANT \"{role}\" TO \"{executor}\" WITH ADMIN OPTION (since \
                 PostgreSQL 16, CREATEROLE alone is not sufficient)"
            ),
            AuthorityIssue::MissingPredefinedRole {
                role,
                server_major,
                min_version,
            } => {
                write!(
                    f,
                    "MissingPredefinedRole: manifest declares membership in \"{role}\", \
                     which does not exist on this server (PostgreSQL {server_major})"
                )?;
                if let Some(min_version) = min_version {
                    write!(f, "; it was added in PostgreSQL {min_version}")?;
                }
                Ok(())
            }
            AuthorityIssue::PublicRevoke {
                object_type,
                schema,
                executor,
                skipped_count,
                examples,
            } => {
                let examples = examples
                    .iter()
                    .map(|(name, owner)| format!("\"{name}\" (owner \"{owner}\")"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(
                    f,
                    "UnsatisfiableRevoke: cannot revoke PUBLIC privileges on {object_type} \
                     objects{} as executor \"{executor}\"; {skipped_count} object(s) have \
                     owners the executor cannot act as, so the REVOKE would silently \
                     change nothing",
                    match schema {
                        Some(schema) => format!(" in schema \"{schema}\""),
                        None => String::new(),
                    },
                )?;
                if !examples.is_empty() {
                    write!(f, " (examples: {examples})")?;
                }
                Ok(())
            }
            AuthorityIssue::ForeignGrantorRevoke {
                object_type,
                schema,
                grantee,
                executor,
                skipped_count,
                examples,
            } => {
                let examples = examples
                    .iter()
                    .map(|(name, grantor)| format!("\"{name}\" (grantor \"{grantor}\")"))
                    .collect::<Vec<_>>()
                    .join("; ");
                write!(
                    f,
                    "UnsatisfiableRevoke: cannot revoke \"{grantee}\" privileges on \
                     {object_type} objects{} as executor \"{executor}\"; {skipped_count} ACL \
                     entr{} attributed to grantors this executor's REVOKE cannot remove \
                     (PostgreSQL revokes only grants made by the revoker; a superuser acts \
                     as the owner), so the REVOKE would succeed while silently leaving them \
                     in place — revoke the delegating grantor's grant option with CASCADE, \
                     or run the revoke as that grantor",
                    match schema {
                        Some(schema) => format!(" in schema \"{schema}\""),
                        None => String::new(),
                    },
                    if *skipped_count == 1 {
                        "y was"
                    } else {
                        "ies were"
                    },
                )?;
                if !examples.is_empty() {
                    write!(f, " (examples: {examples})")?;
                }
                Ok(())
            }
            AuthorityIssue::ForeignGrantorMembershipRevoke {
                role,
                member,
                grantor,
                executor,
            } => write!(
                f,
                "UnsatisfiableRevoke: cannot revoke membership of \"{member}\" in \
                 \"{role}\" as executor \"{executor}\"; the edge was granted by \
                 \"{grantor}\" and is removed with REVOKE ... GRANTED BY \
                 \"{grantor}\", which requires the privileges of that grantor — \
                 grant the executor membership in \"{grantor}\" or run the revoke \
                 as a role that has it"
            ),
            AuthorityIssue::RevokeGrantorUnavailable { grantor, executor } => write!(
                f,
                "UnsatisfiableRevoke: the plan revokes object privileges from ACL \
                 entries granted by \"{grantor}\", which requires running the REVOKE \
                 as that grantor (SET ROLE) — executor \"{executor}\" cannot become \
                 \"{grantor}\"; grant the executor membership in \"{grantor}\" (with \
                 the SET option) or run the revoke as a role that has it"
            ),
            AuthorityIssue::GrantorAuthorityRemovedByPlan { grantor, executor } => write!(
                f,
                "UnsatisfiableRevoke: this plan removes the membership path that \
                 lets executor \"{executor}\" act with the privileges of \
                 \"{grantor}\", and a later statement in the same plan must still \
                 act as \"{grantor}\" (REVOKE ... GRANTED BY or ALTER DEFAULT \
                 PRIVILEGES FOR ROLE) — split the membership removal into a \
                 separate, later apply"
            ),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ObjectAuthorityRow {
    schema_name: Option<String>,
    object_name: String,
    owner_name: String,
    can_act: bool,
}

/// Check executor authority for the planned changes.
///
/// `current` supplies the per-object PUBLIC state so the ownership check
/// covers exactly the objects an `ON ALL` revoke would have to touch, not
/// every object in the schema.
pub async fn preflight_authority_issues(
    pool: &PgPool,
    changes: &[Change],
    current: &RoleGraph,
) -> Result<Vec<AuthorityIssue>, sqlx::Error> {
    let mut issues = Vec::new();

    let (executor, executor_is_superuser, executor_has_createrole) = {
        let (user, is_superuser, has_createrole): (String, bool, bool) = sqlx::query_as(
            "SELECT r.rolname::text, r.rolsuper, r.rolcreaterole \
             FROM pg_roles r WHERE r.rolname = current_user",
        )
        .fetch_one(pool)
        .await?;
        (user, is_superuser, has_createrole)
    };
    let (server_version_num,): (i32,) =
        sqlx::query_as("SELECT current_setting('server_version_num')::int")
            .fetch_one(pool)
            .await?;
    let server_major = (server_version_num / 10_000) as u32;

    let created: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::CreateRole { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    // PostgreSQL 16+ can grant inherited authority immediately at CREATE ROLE.
    // SET alone is insufficient: default-privilege SQL does not SET ROLE.
    let inherits_created = if server_major >= 16
        && executor_has_createrole
        && !executor_is_superuser
        && !created.is_empty()
    {
        let setting: String = sqlx::query_scalar("SHOW createrole_self_grant")
            .fetch_one(pool)
            .await?;
        setting.split(',').any(|option| {
            option
                .trim()
                .trim_matches('"')
                .eq_ignore_ascii_case("inherit")
        })
    } else {
        false
    };
    let creation_edges: Vec<(String, String)> = if inherits_created {
        created
            .iter()
            .map(|role| (role.clone(), executor.clone()))
            .collect()
    } else {
        Vec::new()
    };

    // --- Predefined-role membership authority ---
    // Granting or revoking membership in a predefined (`pg_*`) role requires
    // ADMIN OPTION on it. `pg_has_role(..., 'MEMBER WITH ADMIN OPTION')`
    // reports true for superusers, so this is exactly the authority the
    // GRANT/REVOKE needs. A referenced predefined role the server does not
    // have at all is reported with the version that introduced it.
    let predefined_targets: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::AddMember { role, .. } | Change::RemoveMember { role, .. }
                if is_predefined_role(role) =>
            {
                Some(role.clone())
            }
            _ => None,
        })
        .collect();
    if !predefined_targets.is_empty() {
        let target_list: Vec<String> = predefined_targets.iter().cloned().collect();
        let rows: Vec<(String, bool)> = sqlx::query_as(
            r#"
            SELECT r.rolname::text, pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION')
            FROM pg_roles r
            WHERE r.rolname = ANY($1)
            "#,
        )
        .bind(&target_list)
        .fetch_all(pool)
        .await?;
        let known: BTreeSet<String> = rows.iter().map(|(role, _)| role.clone()).collect();
        // Before PostgreSQL 16, CREATEROLE alone allowed granting and
        // revoking any non-superuser role, predefined roles included — the
        // ADMIN OPTION requirement is the PG16 semantics change. Requiring it
        // unconditionally would hard-block executors that work fine on 14/15.
        let admin_required = server_major >= 16;
        for (role, can_admin) in rows {
            if !can_admin && (admin_required || !(executor_is_superuser || executor_has_createrole))
            {
                issues.push(AuthorityIssue::PredefinedRoleGrant {
                    role,
                    executor: executor.clone(),
                });
            }
        }
        for role in predefined_targets
            .iter()
            .filter(|role| !known.contains(role.as_str()))
        {
            issues.push(AuthorityIssue::MissingPredefinedRole {
                role: role.clone(),
                server_major,
                min_version: predefined_role_min_version(role),
            });
        }
    }

    // --- Revoke grantor feasibility ---
    // Grantor-targeted changes carry the exact edge or ACL entry inspection
    // saw, and their rendering acts as that grantor: a membership revoke
    // renders `REVOKE ... GRANTED BY <grantor>`, which requires the
    // privileges of the grantor; an object revoke renders
    // `SET ROLE <grantor>; REVOKE ...;`, which requires the executor to be
    // able to become the grantor (the SET option on PG16+, plain membership
    // before). Check both up front so an apply never runs a
    // statement PostgreSQL would reject — no attribution heuristics needed,
    // the grantor is named on the change.
    let membership_grantors: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::RemoveMember {
                grantor: Some(grantor),
                ..
            } => Some(grantor.clone()),
            _ => None,
        })
        .collect();
    let revoke_grantors: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::Revoke {
                grantor: Some(grantor),
                ..
            } => Some(grantor.clone()),
            _ => None,
        })
        .collect();
    if !membership_grantors.is_empty() || !revoke_grantors.is_empty() {
        let all: Vec<String> = membership_grantors
            .iter()
            .chain(revoke_grantors.iter())
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        // 'SET' is the PG16+ SET ROLE feasibility mode; before 16 plain
        // membership suffices for SET ROLE. 'USAGE' is "has the privileges
        // of", which is what GRANTED BY requires. Superusers pass both.
        let set_mode = if server_major >= 16 { "SET" } else { "MEMBER" };
        let rows: Vec<(String, bool, bool)> = sqlx::query_as(&format!(
            "SELECT r.rolname::text, \
                    pg_has_role(current_user, r.oid, 'USAGE'), \
                    pg_has_role(current_user, r.oid, '{set_mode}') \
             FROM pg_roles r WHERE r.rolname = ANY($1)"
        ))
        .bind(&all)
        .fetch_all(pool)
        .await?;
        let usage: BTreeSet<&str> = rows
            .iter()
            .filter(|(_, has_usage, _)| *has_usage)
            .map(|(name, _, _)| name.as_str())
            .collect();
        let settable: BTreeSet<&str> = rows
            .iter()
            .filter(|(_, _, can_set)| *can_set)
            .map(|(name, _, _)| name.as_str())
            .collect();
        for change in changes {
            match change {
                Change::RemoveMember {
                    role,
                    member,
                    grantor: Some(grantor),
                } if !usage.contains(grantor.as_str()) => {
                    issues.push(AuthorityIssue::ForeignGrantorMembershipRevoke {
                        role: role.clone(),
                        member: member.clone(),
                        grantor: grantor.clone(),
                        executor: executor.clone(),
                    });
                }
                Change::Revoke {
                    grantor: Some(grantor),
                    ..
                } if !settable.contains(grantor.as_str()) => {
                    issues.push(AuthorityIssue::RevokeGrantorUnavailable {
                        grantor: grantor.clone(),
                        executor: executor.clone(),
                    });
                }
                _ => {}
            }
        }
        // One report per unavailable grantor is enough for the object side.
        issues.dedup_by(|a, b| {
            matches!(
                (&a, &b),
                (
                    AuthorityIssue::RevokeGrantorUnavailable { grantor: ga, .. },
                    AuthorityIssue::RevokeGrantorUnavailable { grantor: gb, .. },
                ) if ga == gb
            )
        });
    }

    // --- Grantor authority removed by the plan itself ---
    // The feasibility checks above run against the *current* membership
    // graph, but membership changes execute inside the same transaction —
    // and object revokes are the only grantor-targeted changes ordered
    // before them. Authority is re-checked phase by phase, matching plan
    // order (removals, then additions, then default-privilege revokes):
    //
    //   - a `REVOKE ... GRANTED BY <grantor>` runs in the removal batch, so
    //     its grantor must stay reachable in the graph with the plan's
    //     removals applied (conservative: a removal order that would keep a
    //     path alive long enough is still flagged);
    //   - an `ALTER DEFAULT PRIVILEGES FOR ROLE <owner>` runs after the
    //     addition batch, so the plan's added inheriting edges count too —
    //     an option change (remove + re-add) or a newly declared membership
    //     can legitimately restore the executor's path before it runs.
    //
    // Requires the per-edge `inherit_option` PostgreSQL 16 records; before
    // 16 there are no grantor-targeted removals to protect, so the residual
    // pre-16 default-privilege exposure stays with the post-apply detection.
    let removed_edges: Vec<(String, String)> = changes
        .iter()
        .filter_map(|change| match change {
            Change::RemoveMember { role, member, .. } => Some((role.clone(), member.clone())),
            _ => None,
        })
        .collect();
    // Only inheriting additions extend USAGE.
    let added_edges: Vec<(String, String)> = changes
        .iter()
        .filter_map(|change| match change {
            Change::AddMember {
                role,
                member,
                inherit: true,
                ..
            } => Some((role.clone(), member.clone())),
            _ => None,
        })
        .collect();
    // GRANT ... INHERIT FALSE can overwrite an automatic creation grant,
    // even without a preceding RemoveMember (the role did not exist at
    // inspection). Apply these downgrades only after the addition phase.
    let defaults_removed_edges: Vec<(String, String)> = removed_edges
        .iter()
        .cloned()
        .chain(changes.iter().filter_map(|change| match change {
            Change::AddMember {
                role,
                member,
                inherit: false,
                ..
            } => Some((role.clone(), member.clone())),
            _ => None,
        }))
        .collect();
    // Owners of `SetDefaultPrivilege` changes, which execute before any
    // membership change: the owner check below judges their initial authority.
    // The later phase check avoids duplicating that check's failures.
    let set_owners: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::SetDefaultPrivilege { owner, .. } => Some(owner.clone()),
            _ => None,
        })
        .collect();
    let phase_checks_active = !executor_is_superuser && server_major >= 16;
    // When the plan changes memberships at all, the phase graph — not the
    // current graph — is authoritative for RevokeDefaultPrivilege owners, so
    // the current-state owner check below must not double-judge them.
    let revoke_owners_phase_checked =
        phase_checks_active && !(defaults_removed_edges.is_empty() && added_edges.is_empty());
    if phase_checks_active {
        let mut broken_by_plan: BTreeSet<String> = BTreeSet::new();
        let mut never_usable: BTreeSet<String> = BTreeSet::new();

        // Membership `GRANTED BY` revokes run in the removal batch, before
        // any addition, so only removals can affect them.
        if !removed_edges.is_empty() && !membership_grantors.is_empty() {
            let membership_phase_roles: Vec<String> = membership_grantors.iter().cloned().collect();
            for (grantor, usable_now) in roles_unreachable_in_graph(
                pool,
                &membership_phase_roles,
                &removed_edges,
                &[],
                &created,
                &creation_edges,
            )
            .await?
            {
                // A grantor the executor cannot use even now was already
                // flagged exactly (ForeignGrantorMembershipRevoke) above.
                if usable_now {
                    broken_by_plan.insert(grantor);
                }
            }
        }

        // Default-privilege revokes run after removals *and* additions: a
        // path the plan removes may be legitimately replaced, and a path the
        // executor lacks now may be legitimately acquired (e.g. its ADMIN
        // OPTION lets it grant the owner to a role it already inherits).
        if revoke_owners_phase_checked {
            let defaults_phase_roles: Vec<String> = changes
                .iter()
                .filter_map(|change| match change {
                    Change::RevokeDefaultPrivilege { owner, .. } => Some(owner.clone()),
                    _ => None,
                })
                .collect::<BTreeSet<String>>()
                .into_iter()
                .collect();
            for (owner, usable_now) in roles_unreachable_in_graph(
                pool,
                &defaults_phase_roles,
                &defaults_removed_edges,
                &added_edges,
                &created,
                &creation_edges,
            )
            .await?
            {
                if usable_now {
                    broken_by_plan.insert(owner);
                } else {
                    never_usable.insert(owner);
                }
            }
        }

        for grantor in broken_by_plan {
            issues.push(AuthorityIssue::GrantorAuthorityRemovedByPlan {
                grantor,
                executor: executor.clone(),
            });
        }
        for owner in never_usable {
            // Avoid duplicating a failing grant-phase check. A new owner
            // with inherited creation authority passes that check, but can
            // still lose authority before its later revoke.
            if set_owners.contains(&owner) && !(inherits_created && created.contains(&owner)) {
                continue;
            }
            issues.push(AuthorityIssue::DefaultPrivilegeOwner {
                owner,
                executor: executor.clone(),
            });
        }
    }

    // --- Default-privilege owner authority ---
    // `SetDefaultPrivilege` executes before any membership change, so the
    // current graph judges it. `RevokeDefaultPrivilege` executes after the
    // removal and addition batches — when the plan changes memberships (and
    // the phase checks above ran), those owners were already judged against
    // the phase graph and are skipped here; both kinds still get the
    // missing-owner check.
    let owners: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::SetDefaultPrivilege { owner, .. }
            | Change::RevokeDefaultPrivilege { owner, .. } => Some(owner.clone()),
            _ => None,
        })
        .collect();
    if !owners.is_empty() {
        let owner_list: Vec<String> = owners.iter().cloned().collect();
        let rows: Vec<(String, bool)> = sqlx::query_as(
            r#"
            SELECT r.rolname::text, pg_has_role(current_user, r.oid, 'USAGE')
            FROM pg_roles r
            WHERE r.rolname = ANY($1)
            "#,
        )
        .bind(&owner_list)
        .fetch_all(pool)
        .await?;
        let known: BTreeSet<String> = rows.iter().map(|(owner, _)| owner.clone()).collect();
        for (owner, can_act) in rows {
            if !can_act && (set_owners.contains(&owner) || !revoke_owners_phase_checked) {
                issues.push(AuthorityIssue::DefaultPrivilegeOwner {
                    owner,
                    executor: executor.clone(),
                });
            }
        }
        // Creation precedes default grants; later revokes use the phase graph
        // when memberships change, including CREATE ROLE's automatic edges.
        for owner in &owners {
            if known.contains(owner) {
                continue;
            }
            if created.contains(owner)
                && !executor_is_superuser
                && !inherits_created
                && (set_owners.contains(owner) || !revoke_owners_phase_checked)
            {
                issues.push(AuthorityIssue::DefaultPrivilegeOwner {
                    owner: owner.clone(),
                    executor: executor.clone(),
                });
            } else if !created.contains(owner) {
                issues.push(AuthorityIssue::MissingDefaultPrivilegeOwner {
                    owner: owner.clone(),
                });
            }
        }
    }

    // --- PUBLIC revoke ownership (grantor-less revokes) ---
    // Collect the objects each planned *plain* PUBLIC revoke touches, grouped
    // per (object_type, schema). `AllInSchema` means every object of that
    // type, which is what an `ON ALL` statement actually reaches. A
    // grantor-targeted PUBLIC revoke runs `SET ROLE <grantor>` and needs only
    // that — it was checked exactly above, so requiring owner authority here
    // as well would block a least-privilege executor whose targeted revoke
    // succeeds.
    #[derive(Default)]
    struct RevokeTargets {
        names: BTreeSet<String>,
        all_in_schema: bool,
    }

    let mut targets: BTreeMap<(ObjectType, Option<String>), RevokeTargets> = BTreeMap::new();
    for change in changes {
        let Change::Revoke {
            role: Grantee::Public,
            object_type,
            schema,
            name,
            grantor: None,
            ..
        } = change
        else {
            continue;
        };
        let entry = targets.entry((*object_type, schema.clone())).or_default();
        match name.as_deref() {
            Some("*") => {
                let range_start = GrantKey {
                    role: Grantee::Public,
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: None,
                };
                for (key, _) in current.grants.range(range_start..).take_while(|(key, _)| {
                    key.role == Grantee::Public
                        && key.object_type == *object_type
                        && key.schema == *schema
                }) {
                    match key.name.as_deref() {
                        // Wildcard normalization collapses per-object PUBLIC
                        // rows into one `"*"` key when the same scope also has
                        // a present wildcard. Narrowing to the remaining
                        // per-object names would then check nothing, so treat
                        // the collapsed key as covering the whole scope.
                        Some("*") => entry.all_in_schema = true,
                        Some(object_name) => {
                            entry.names.insert(object_name.to_string());
                        }
                        None => {}
                    }
                }
            }
            Some(object_name) => {
                entry.names.insert(object_name.to_string());
            }
            None => {}
        }
    }

    for ((object_type, schema), target) in targets {
        if target.names.is_empty() && !target.all_in_schema {
            continue;
        }
        let rows =
            fetch_object_authority(pool, object_type, schema.as_deref(), &target.names).await?;
        let mut blocked: Vec<(String, String)> = rows
            .into_iter()
            .filter(|row| {
                !row.can_act
                    && row.schema_name.as_deref() == schema.as_deref()
                    && (target.all_in_schema || target.names.contains(&row.object_name))
            })
            .map(|row| (row.object_name, row.owner_name))
            .collect();
        if blocked.is_empty() {
            continue;
        }
        blocked.sort();
        issues.push(AuthorityIssue::PublicRevoke {
            object_type,
            schema,
            executor: executor.clone(),
            skipped_count: blocked.len(),
            examples: blocked.into_iter().take(REVOKE_EXAMPLE_LIMIT).collect(),
        });
    }

    // --- Ordinary-grantee revoke grantor authority (grantor-less revokes) ---
    // A grantor-targeted revoke was checked exactly above; this sweep covers
    // only the revokes that carry no grantor — snapshots without a per-entry
    // breakdown and wildcard-collapsed keys — where a plain REVOKE runs and
    // removes only the entry of the grantor PostgreSQL selects for the
    // executor. Explode the live ACLs of the targeted objects and flag
    // entries for the revoked grantee and privileges the plain revoke cannot
    // reach.
    let mut grantee_targets: BTreeMap<(ObjectType, Option<String>, String), GranteeRevokeTargets> =
        BTreeMap::new();
    for change in changes {
        let Change::Revoke {
            role: Grantee::Role(grantee),
            object_type,
            schema,
            name,
            privileges,
            grantor: None,
        } = change
        else {
            continue;
        };
        let entry = grantee_targets
            .entry((*object_type, schema.clone(), grantee.clone()))
            .or_default();
        let revoked: BTreeSet<String> = privileges
            .iter()
            .map(|privilege| privilege.to_string())
            .collect();
        match name.as_deref() {
            Some("*") => {
                let range_start = GrantKey {
                    role: Grantee::Role(grantee.clone()),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: None,
                };
                for (key, _) in current.grants.range(range_start..).take_while(|(key, _)| {
                    key.role == Grantee::Role(grantee.clone())
                        && key.object_type == *object_type
                        && key.schema == *schema
                }) {
                    match key.name.as_deref() {
                        // Same wildcard normalization as the PUBLIC check: a
                        // collapsed `"*"` key covers the whole scope.
                        Some("*") => entry.all_in_schema.extend(revoked.iter().cloned()),
                        Some(object_name) => {
                            entry
                                .names
                                .entry(object_name.to_string())
                                .or_default()
                                .extend(revoked.iter().cloned());
                        }
                        None => {}
                    }
                }
            }
            Some(object_name) => {
                entry
                    .names
                    .entry(object_name.to_string())
                    .or_default()
                    .extend(revoked.iter().cloned());
            }
            None => {}
        }
    }

    for ((object_type, schema, grantee), target) in grantee_targets {
        if target.names.is_empty() && target.all_in_schema.is_empty() {
            continue;
        }
        // The query filters by the union of privileges for efficiency; the
        // object → privileges association is re-applied client-side so a
        // `SELECT` revoke on one table never flags a foreign-grantor `UPDATE`
        // entry on another.
        let privileges: Vec<String> = target
            .names
            .values()
            .flatten()
            .chain(target.all_in_schema.iter())
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        let names: BTreeSet<String> = target.names.keys().cloned().collect();
        let rows = fetch_revoke_grantor_authority(
            pool,
            object_type,
            schema.as_deref(),
            &names,
            &grantee,
            &privileges,
        )
        .await?;
        let mut surviving: BTreeSet<(String, String)> = rows
            .into_iter()
            .filter(|row| {
                !row.can_act
                    && row.schema_name.as_deref() == schema.as_deref()
                    && (target.all_in_schema.contains(&row.privilege_type)
                        || target
                            .names
                            .get(&row.object_name)
                            .is_some_and(|revoked| revoked.contains(&row.privilege_type)))
            })
            .map(|row| (row.object_name, row.grantor_name))
            .collect();
        if surviving.is_empty() {
            continue;
        }
        let skipped_count = surviving.len();
        let examples: Vec<(String, String)> = std::mem::take(&mut surviving)
            .into_iter()
            .take(REVOKE_EXAMPLE_LIMIT)
            .collect();
        issues.push(AuthorityIssue::ForeignGrantorRevoke {
            object_type,
            schema,
            grantee,
            executor: executor.clone(),
            skipped_count,
            examples,
        });
    }

    Ok(issues)
}

/// Objects one planned `(object_type, schema, grantee)` revoke group reaches.
///
/// The object → privileges association is preserved: a `SELECT` revoke on one
/// table and an `UPDATE` revoke on another in the same schema must not be
/// checked as their cross-product, or an untargeted foreign-grantor entry
/// would be reported and block apply. Privileges from a collapsed `"*"`
/// wildcard target apply to every object of the type in the schema and are
/// tracked separately.
#[derive(Default)]
struct GranteeRevokeTargets {
    /// Object name → privilege names being revoked on that object.
    names: BTreeMap<String, BTreeSet<String>>,
    /// Privilege names being revoked on every object of the type in the
    /// schema (from a collapsed `"*"` target). Empty when no wildcard applies.
    all_in_schema: BTreeSet<String>,
}

/// A live ACL entry for a revoked grantee: which object and privilege it
/// carries, who granted it, and whether the executor can act as that grantor.
#[derive(Debug, sqlx::FromRow)]
struct GrantorAuthorityRow {
    schema_name: Option<String>,
    object_name: String,
    grantor_name: String,
    privilege_type: String,
    can_act: bool,
}

/// Which of `roles` the executor cannot act as at a given plan phase:
/// inheritance-reachability from the executor over the live membership graph
/// with `removed` edges deleted and `added` inheriting edges inserted — the
/// phase equivalent of `pg_has_role(current_user, role, 'USAGE')`. Each
/// unreachable role is returned with whether the executor can use it *now*,
/// so callers can distinguish authority the plan breaks from authority the
/// executor never had. Planned roles and automatic creation grants are
/// included before membership removals and additions. Removals and inheritance
/// downgrades conservatively remove every grantor edge for the named pair.
/// Superusers are never passed here.
async fn roles_unreachable_in_graph(
    pool: &PgPool,
    roles: &[String],
    removed: &[(String, String)],
    added: &[(String, String)],
    created: &[String],
    creation_edges: &[(String, String)],
) -> Result<Vec<(String, bool)>, sqlx::Error> {
    if roles.is_empty() {
        return Ok(Vec::new());
    }
    let (removed_roles, removed_members): (Vec<String>, Vec<String>) =
        removed.iter().cloned().unzip();
    let (added_roles, added_members): (Vec<String>, Vec<String>) = added.iter().cloned().unzip();
    let (creation_roles, creation_members): (Vec<String>, Vec<String>) =
        creation_edges.iter().cloned().unzip();
    let rows: Vec<(String, bool)> = sqlx::query_as(
        r#"
        WITH RECURSIVE removed(rolname, memname) AS (
            SELECT * FROM unnest($2::text[], $3::text[])
        ),
        added(rolname, memname) AS (
            SELECT * FROM unnest($4::text[], $5::text[])
        ),
        known(rolname) AS (
            SELECT rolname::text FROM pg_roles
            UNION SELECT unnest($6::text[])
        ),
        initial_edges(rolname, memname) AS (
            SELECT g.rolname::text, mem.rolname::text
            FROM pg_auth_members m
            JOIN pg_roles g ON g.oid = m.roleid
            JOIN pg_roles mem ON mem.oid = m.member
            WHERE m.inherit_option
            UNION SELECT * FROM unnest($7::text[], $8::text[])
        ),
        edges(rolname, memname) AS (
            SELECT e.rolname, e.memname FROM initial_edges e
            WHERE NOT EXISTS (
                SELECT 1 FROM removed d
                WHERE d.rolname = e.rolname AND d.memname = e.memname
            )
            UNION
            SELECT a.rolname, a.memname FROM added a
            JOIN known g ON g.rolname = a.rolname
            JOIN known mem ON mem.rolname = a.memname
        ),
        reach(rolname) AS (
            SELECT current_user::text
            UNION
            SELECT e.rolname FROM edges e JOIN reach r ON e.memname = r.rolname
        )
        SELECT k.rolname,
               CASE WHEN r.oid IS NULL THEN false
                    ELSE pg_has_role(current_user, r.oid, 'USAGE') END
        FROM known k LEFT JOIN pg_roles r ON r.rolname = k.rolname
        WHERE k.rolname = ANY($1)
          AND k.rolname NOT IN (SELECT rolname FROM reach)
        "#,
    )
    .bind(roles)
    .bind(&removed_roles)
    .bind(&removed_members)
    .bind(&added_roles)
    .bind(&added_members)
    .bind(created)
    .bind(&creation_roles)
    .bind(&creation_members)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn fetch_object_authority(
    pool: &PgPool,
    object_type: ObjectType,
    schema: Option<&str>,
    names: &BTreeSet<String>,
) -> Result<Vec<ObjectAuthorityRow>, sqlx::Error> {
    let schemas: Vec<String> = schema.map(|s| vec![s.to_string()]).unwrap_or_default();
    let names: Vec<String> = names.iter().cloned().collect();
    match object_type {
        ObjectType::Table
        | ObjectType::View
        | ObjectType::MaterializedView
        | ObjectType::Sequence => {
            // Only the relkinds this object type actually names. Selecting
            // every relation would report objects the planned statement cannot
            // reach, and a wildcard target accepts them all.
            let relkinds: Vec<String> = match object_type {
                ObjectType::Table => vec!["r".to_string(), "p".to_string()],
                ObjectType::View => vec!["v".to_string()],
                ObjectType::MaterializedView => vec!["m".to_string()],
                _ => vec!["S".to_string()],
            };
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, c.relowner, 'USAGE') AS can_act
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_roles o ON o.oid = c.relowner
                WHERE n.nspname = ANY($1)
                  AND c.relkind::text = ANY($2)
                "#,
            )
            .bind(&schemas)
            .bind(&relkinds)
            .fetch_all(pool)
            .await
        }
        ObjectType::Function => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    (p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')')::text
                        AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, p.proowner, 'USAGE') AS can_act
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                JOIN pg_roles o ON o.oid = p.proowner
                WHERE n.nspname = ANY($1)
                "#,
            )
            .bind(&schemas)
            .fetch_all(pool)
            .await
        }
        ObjectType::Type => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    n.nspname::text AS schema_name,
                    t.typname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, t.typowner, 'USAGE') AS can_act
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                JOIN pg_roles o ON o.oid = t.typowner
                WHERE n.nspname = ANY($1)
                  -- Only user-facing types. Every table carries a composite
                  -- type, and every type carries an array type; neither is
                  -- something a revoke can name.
                  AND (
                    t.typrelid = 0
                    OR (SELECT c.relkind FROM pg_class c WHERE c.oid = t.typrelid) = 'c'
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM pg_type el
                    WHERE el.oid = t.typelem AND el.typarray = t.oid
                  )
                "#,
            )
            .bind(&schemas)
            .fetch_all(pool)
            .await
        }
        ObjectType::Schema => {
            // Schema targets carry the schema in `name`, so `names` holds the
            // schema names and `schemas` is empty. Match against `nspname`.
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    NULL::text AS schema_name,
                    n.nspname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, n.nspowner, 'USAGE') AS can_act
                FROM pg_namespace n
                JOIN pg_roles o ON o.oid = n.nspowner
                WHERE n.nspname = ANY($1)
                "#,
            )
            .bind(&names)
            .fetch_all(pool)
            .await
        }
        ObjectType::Database => {
            sqlx::query_as::<_, ObjectAuthorityRow>(
                r#"
                SELECT
                    NULL::text AS schema_name,
                    db.datname::text AS object_name,
                    o.rolname::text AS owner_name,
                    pg_has_role(current_user, db.datdba, 'USAGE') AS can_act
                FROM pg_database db
                JOIN pg_roles o ON o.oid = db.datdba
                WHERE db.datname = current_database()
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}

/// Fetch the live ACL entries a planned `REVOKE ... FROM <grantee>` group
/// would have to remove, with per-entry grantor actability.
///
/// One query per catalog family, each exploding the object's ACL column and
/// keeping entries for the named grantee and privilege types. `can_act` is
/// `pg_has_role(current_user, grantor, 'USAGE')` — the membership check
/// PostgreSQL's own grantor resolution walks — so a `false` row is an entry
/// the executor's REVOKE cannot remove under any grantor selection.
async fn fetch_revoke_grantor_authority(
    pool: &PgPool,
    object_type: ObjectType,
    schema: Option<&str>,
    names: &BTreeSet<String>,
    grantee: &str,
    privileges: &[String],
) -> Result<Vec<GrantorAuthorityRow>, sqlx::Error> {
    let schemas: Vec<String> = schema.map(|s| vec![s.to_string()]).unwrap_or_default();
    let names: Vec<String> = names.iter().cloned().collect();
    match object_type {
        ObjectType::Table
        | ObjectType::View
        | ObjectType::MaterializedView
        | ObjectType::Sequence => {
            let relkinds: Vec<String> = match object_type {
                ObjectType::Table => vec!["r".to_string(), "p".to_string()],
                ObjectType::View => vec!["v".to_string()],
                ObjectType::MaterializedView => vec!["m".to_string()],
                _ => vec!["S".to_string()],
            };
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    acl.privilege_type::text AS privilege_type,
                    CASE WHEN (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
                         -- A superuser's plain REVOKE is performed as though
                         -- issued by the object's owner, so only the
                         -- owner-attributed entry is removable.
                         THEN acl.grantor = c.relowner
                         ELSE pg_has_role(current_user, acl.grantor, 'USAGE')
                    END AS can_act
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND c.relkind::text = ANY($2)
                  AND ge.rolname = $3
                  AND acl.privilege_type = ANY($4)
                "#,
            )
            .bind(&schemas)
            .bind(&relkinds)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Function => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    (p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')')::text
                        AS object_name,
                    gr.rolname::text AS grantor_name,
                    acl.privilege_type::text AS privilege_type,
                    CASE WHEN (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
                         THEN acl.grantor = p.proowner
                         ELSE pg_has_role(current_user, acl.grantor, 'USAGE')
                    END AS can_act
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&schemas)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Type => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    n.nspname::text AS schema_name,
                    t.typname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    acl.privilege_type::text AS privilege_type,
                    CASE WHEN (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
                         THEN acl.grantor = t.typowner
                         ELSE pg_has_role(current_user, acl.grantor, 'USAGE')
                    END AS can_act
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                CROSS JOIN LATERAL aclexplode(t.typacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&schemas)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Schema => {
            // Schema targets carry the schema in `name`, so `names` holds the
            // schema names and the returned schema_name is NULL (matching how
            // the revoke change itself is keyed).
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    NULL::text AS schema_name,
                    n.nspname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    acl.privilege_type::text AS privilege_type,
                    CASE WHEN (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
                         THEN acl.grantor = n.nspowner
                         ELSE pg_has_role(current_user, acl.grantor, 'USAGE')
                    END AS can_act
                FROM pg_namespace n
                CROSS JOIN LATERAL aclexplode(n.nspacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE n.nspname = ANY($1)
                  AND ge.rolname = $2
                  AND acl.privilege_type = ANY($3)
                "#,
            )
            .bind(&names)
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
        ObjectType::Database => {
            sqlx::query_as::<_, GrantorAuthorityRow>(
                r#"
                SELECT DISTINCT
                    NULL::text AS schema_name,
                    db.datname::text AS object_name,
                    gr.rolname::text AS grantor_name,
                    acl.privilege_type::text AS privilege_type,
                    CASE WHEN (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
                         THEN acl.grantor = db.datdba
                         ELSE pg_has_role(current_user, acl.grantor, 'USAGE')
                    END AS can_act
                FROM pg_database db
                CROSS JOIN LATERAL aclexplode(db.datacl) AS acl
                JOIN pg_roles gr ON gr.oid = acl.grantor
                JOIN pg_roles ge ON ge.oid = acl.grantee
                WHERE db.datname = current_database()
                  AND ge.rolname = $1
                  AND acl.privilege_type = ANY($2)
                "#,
            )
            .bind(grantee)
            .bind(privileges)
            .fetch_all(pool)
            .await
        }
    }
}
