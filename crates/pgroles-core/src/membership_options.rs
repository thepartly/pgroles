//! Resolve option intents to catalog-proven grantor attribution before review.
use crate::{
    diff::Change,
    model::{MembershipOptions, RoleGraph},
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum MembershipExpectedState {
    Absent,
    Present { options: MembershipOptions },
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum MembershipSetEffect {
    Preserve,
    CreateFalse,
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct MembershipOptionBinding {
    pub executor: String,
    /// Explicit SET effect bound into the reviewed change digest.
    pub set_effect: MembershipSetEffect,
    pub expected: MembershipExpectedState,
    /// All independently attributed tuples for this pair at review time.
    pub expected_edges: BTreeMap<String, crate::model::MembershipOptions>,
}

/// Only include grantors whose direct ADMIN authority the actual executor
/// can use through inherited privileges. A SET-only path is insufficient.
#[derive(Debug, Clone)]
pub struct MembershipAuthority {
    pub executor: String,
    pub usable_grantors: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipOptionsError {
    #[error(
        "membership option planning requires complete per-grantor options for {member} in {role}"
    )]
    IncompleteFacts { role: String, member: String },
}

pub fn resolve_membership_options(
    changes: Vec<Change>,
    current: &RoleGraph,
    authority: &MembershipAuthority,
) -> Result<Vec<Change>, MembershipOptionsError> {
    changes
        .into_iter()
        .map(|change| {
            let Change::UpdateMemberOptions {
                role,
                member,
                mut grantor,
                inherit,
                admin,
                ..
            } = change
            else {
                return Ok(change);
            };
            // Complete tuples that also agree with the effective membership.
            let Some(options) = current
                .complete_membership_options(&role, &member)
                .filter(|os| {
                    current
                        .memberships
                        .iter()
                        .find(|e| e.role == role && e.member == member)
                        .is_some_and(|e| {
                            e.inherit == os.values().any(|o| o.inherit)
                                && e.admin == os.values().any(|o| o.admin)
                        })
                })
            else {
                return Err(MembershipOptionsError::IncompleteFacts { role, member });
            };
            if inherit == Some(true) || admin == Some(true) {
                let usable = authority.usable_grantors.get(&role);
                grantor = usable
                    .and_then(|gs| {
                        // Prefer an existing executor edge, then another usable
                        // existing edge. A new attribution never copies foreign SET.
                        if gs.contains(&authority.executor)
                            && options.contains_key(&authority.executor)
                        {
                            Some(authority.executor.clone())
                        } else if let Some(g) = gs.iter().find(|g| options.contains_key(*g)) {
                            Some(g.clone())
                        } else if gs.contains(&authority.executor) {
                            Some(authority.executor.clone())
                        } else {
                            gs.first().cloned()
                        }
                    })
                    // No usable ADMIN holder is missing executor authority,
                    // not a planning fault. Attribute the increase to the
                    // executor so the plan still renders for review; the
                    // authority preflight then blocks it before any SQL runs.
                    .unwrap_or_else(|| authority.executor.clone());
            } else if !options.contains_key(&grantor) {
                return Err(MembershipOptionsError::IncompleteFacts { role, member });
            }
            let expected =
                options
                    .get(&grantor)
                    .map_or(MembershipExpectedState::Absent, |options| {
                        MembershipExpectedState::Present {
                            options: options.clone(),
                        }
                    });
            Ok(Change::UpdateMemberOptions {
                role,
                member,
                grantor,
                inherit,
                admin,
                binding: Some(MembershipOptionBinding {
                    executor: authority.executor.clone(),
                    expected_edges: options.clone(),
                    set_effect: if matches!(expected, MembershipExpectedState::Absent) {
                        MembershipSetEffect::CreateFalse
                    } else {
                        MembershipSetEffect::Preserve
                    },
                    expected,
                }),
            })
        })
        .collect()
}

/// Remove ADMIN from the executor's own grant in a role this plan creates.
///
/// Since PostgreSQL 16, `CREATE ROLE` run by a non-superuser gives the creator
/// an ADMIN edge on the new role, granted by the bootstrap superuser. The
/// executor's own `GRANT ... WITH ADMIN TRUE` is attributed to the executor,
/// and PostgreSQL rejects it: "ADMIN option cannot be granted back to your own
/// grantor". The creation edge already supplies ADMIN, and inspection combines
/// a pair's edges, so the declared membership holds without it.
///
/// Callers apply this only for a non-superuser executor on PostgreSQL 16+.
pub fn omit_creator_admin_grants(changes: Vec<Change>, executor: &str) -> Vec<Change> {
    let created: BTreeSet<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::CreateRole { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    changes
        .into_iter()
        .map(|change| match change {
            Change::AddMember {
                role,
                member,
                inherit,
                admin: true,
            } if member == executor && created.contains(&role) => Change::AddMember {
                role,
                member,
                inherit,
                admin: false,
            },
            other => other,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RoleState;

    fn create(name: &str) -> Change {
        Change::CreateRole {
            name: name.into(),
            state: RoleState::default(),
        }
    }

    fn add(role: &str, member: &str, inherit: bool, admin: bool) -> Change {
        Change::AddMember {
            role: role.into(),
            member: member.into(),
            inherit,
            admin,
        }
    }

    #[test]
    fn executor_admin_in_a_created_role_comes_from_creation() {
        let changes = omit_creator_admin_grants(
            vec![
                create("owner"),
                add("owner", "executor", true, true),
                add("owner", "executor_group", false, true),
                add("existing", "executor", false, true),
            ],
            "executor",
        );
        assert_eq!(
            changes,
            vec![
                create("owner"),
                add("owner", "executor", true, false),
                // Other members and roles the plan does not create keep ADMIN.
                add("owner", "executor_group", false, true),
                add("existing", "executor", false, true),
            ]
        );
    }
}
