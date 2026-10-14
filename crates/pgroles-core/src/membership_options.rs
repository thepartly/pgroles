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
    #[error(
        "no proven usable direct-ADMIN grantor for increasing membership options of {member} in {role} as {executor}"
    )]
    NoUsableGrantor {
        role: String,
        member: String,
        executor: String,
    },
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
            let key = (role.clone(), member.clone());
            let grantors = current.membership_edge_grantors.get(&key);
            let options = current.membership_edge_options.get(&key);
            let complete = grantors.zip(options).is_some_and(|(gs, os)| {
                !gs.is_empty()
                    && gs.len() == os.len()
                    && gs.iter().all(|g| os.contains_key(g))
                    && current
                        .memberships
                        .iter()
                        .find(|e| e.role == role && e.member == member)
                        .is_some_and(|e| {
                            e.inherit == os.values().any(|o| o.inherit)
                                && e.admin == os.values().any(|o| o.admin)
                        })
            });
            if !complete {
                return Err(MembershipOptionsError::IncompleteFacts { role, member });
            }
            let options = options.expect("complete options");
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
                    .ok_or_else(|| MembershipOptionsError::NoUsableGrantor {
                        role: role.clone(),
                        member: member.clone(),
                        executor: authority.executor.clone(),
                    })?;
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
