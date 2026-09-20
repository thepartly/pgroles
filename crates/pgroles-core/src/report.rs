use serde::Serialize;
use thiserror::Error;

use crate::diff::Change;
use crate::manifest::{ObjectType, SchemaBindingFacet};
use crate::model::RoleAttribute;
use crate::model::{DefaultPrivKey, DefaultPrivilegeScope, GrantKey, Grantee};
use crate::ownership::{
    ManagedScope, MembershipKey, OwnershipIndex, SchemaFacetKey, describe_change, grant_schema_name,
};
use crate::visual::VisualManagedScope;

// v2: default-privilege changes and ownership keys carry a tagged `scope`
// instead of a bare `schema` string, to represent global (owner-wide) scope.
pub const BUNDLE_PLAN_SCHEMA_VERSION: &str = "pgroles.bundle_plan.v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanOutputMode {
    Full,
    Redacted,
}

#[derive(Debug, Clone)]
pub struct BundleReportContext<'a> {
    pub ownership: &'a OwnershipIndex,
    pub managed_scope: &'a ManagedScope,
}

#[derive(Debug, Error)]
pub enum BundlePlanError {
    #[error("missing managed owner for change: {change}")]
    MissingOwner { change: String },

    #[error("bundle change is missing required scope details: {change}")]
    InvalidChange { change: String },
}

#[derive(Debug, Error)]
pub enum BundlePlanRenderError {
    #[error(transparent)]
    Plan(#[from] BundlePlanError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct BundlePlanJson {
    pub schema_version: String,
    pub managed_scope: VisualManagedScope,
    pub changes: Vec<AnnotatedPlanChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedPlanChange {
    pub category: BundleChangeCategory,
    pub owner: BundleChangeOwner,
    pub change: Change,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleChangeOwner {
    pub document: String,
    pub managed_key: ManagedOwnershipKey,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleChangeCategory {
    Role,
    Schema,
    Grant,
    DefaultPrivilege,
    Membership,
    Retirement,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManagedOwnershipKey {
    Role {
        name: String,
    },
    SchemaFacet {
        schema: String,
        facet: SchemaBindingFacet,
    },
    Grant {
        role: Grantee,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },
    DefaultPrivilege {
        owner: String,
        scope: DefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: Grantee,
    },
    Membership {
        role: String,
        member: String,
    },
}

pub fn shape_plan_changes(changes: &[Change], mode: PlanOutputMode) -> Vec<Change> {
    match mode {
        PlanOutputMode::Full => changes.to_vec(),
        PlanOutputMode::Redacted => changes
            .iter()
            .map(|change| match change {
                Change::CreateRole { name, state } => {
                    let mut state = state.clone();
                    if state.comment.is_some() {
                        state.comment = Some("[REDACTED]".to_string());
                    }
                    for value in state.config.values_mut() {
                        *value = "[REDACTED]".to_string();
                    }
                    Change::CreateRole {
                        name: name.clone(),
                        state,
                    }
                }
                Change::AlterRole { name, attributes } => Change::AlterRole {
                    name: name.clone(),
                    attributes: attributes
                        .iter()
                        .map(|attribute| match attribute {
                            RoleAttribute::SetConfig(parameter, _) => RoleAttribute::SetConfig(
                                parameter.clone(),
                                "[REDACTED]".to_string(),
                            ),
                            other => other.clone(),
                        })
                        .collect(),
                },
                Change::SetComment { name, comment } => Change::SetComment {
                    name: name.clone(),
                    comment: comment.as_ref().map(|_| "[REDACTED]".to_string()),
                },
                Change::SetPassword { name, .. } => Change::SetPassword {
                    name: name.clone(),
                    password: "[REDACTED]".to_string(),
                },
                other => other.clone(),
            })
            .collect(),
    }
}

/// Redact credential material while preserving non-password statement values.
///
/// SQL output needs role configuration and comments to describe the actual
/// plan. Review formats use [`shape_plan_changes`] for broader sanitization.
pub fn redact_password_changes(changes: &[Change]) -> Vec<Change> {
    changes
        .iter()
        .map(|change| match change {
            Change::SetPassword { name, .. } => Change::SetPassword {
                name: name.clone(),
                password: "[REDACTED]".to_string(),
            },
            other => other.clone(),
        })
        .collect()
}

pub fn render_plan_json(
    changes: &[Change],
    mode: PlanOutputMode,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&shape_plan_changes(changes, mode))
}

pub fn build_bundle_plan(
    changes: &[Change],
    context: &BundleReportContext<'_>,
    mode: PlanOutputMode,
) -> Result<BundlePlanJson, BundlePlanError> {
    let shaped_changes = shape_plan_changes(changes, mode);
    let annotated_changes = shaped_changes
        .iter()
        .map(|change| {
            Ok(AnnotatedPlanChange {
                category: bundle_change_category(change),
                owner: lookup_bundle_change_owner(change, context.ownership)?,
                change: change.clone(),
            })
        })
        .collect::<Result<Vec<_>, BundlePlanError>>()?;

    Ok(BundlePlanJson {
        schema_version: BUNDLE_PLAN_SCHEMA_VERSION.to_string(),
        managed_scope: VisualManagedScope::from(context.managed_scope),
        changes: annotated_changes,
    })
}

pub fn render_bundle_plan_json(
    changes: &[Change],
    context: &BundleReportContext<'_>,
    mode: PlanOutputMode,
) -> Result<String, BundlePlanRenderError> {
    let plan = build_bundle_plan(changes, context, mode)?;
    Ok(serde_json::to_string_pretty(&plan)?)
}

fn lookup_bundle_change_owner(
    change: &Change,
    ownership: &OwnershipIndex,
) -> Result<BundleChangeOwner, BundlePlanError> {
    match change {
        Change::CreateRole { name, .. }
        | Change::AlterRole { name, .. }
        | Change::SetComment { name, .. }
        | Change::SetPassword { name, .. }
        | Change::DropRole { name } => ownership
            .roles
            .get(name)
            .cloned()
            .map(|document| BundleChangeOwner {
                document,
                managed_key: ManagedOwnershipKey::Role { name: name.clone() },
            })
            .ok_or_else(|| BundlePlanError::MissingOwner {
                change: describe_change(change),
            }),
        Change::TerminateSessions { role } | Change::DropOwned { role } => ownership
            .roles
            .get(role)
            .cloned()
            .map(|document| BundleChangeOwner {
                document,
                managed_key: ManagedOwnershipKey::Role { name: role.clone() },
            })
            .ok_or_else(|| BundlePlanError::MissingOwner {
                change: describe_change(change),
            }),
        Change::ReassignOwned { from_role, .. } => ownership
            .roles
            .get(from_role)
            .cloned()
            .map(|document| BundleChangeOwner {
                document,
                managed_key: ManagedOwnershipKey::Role {
                    name: from_role.clone(),
                },
            })
            .ok_or_else(|| BundlePlanError::MissingOwner {
                change: describe_change(change),
            }),
        Change::CreateSchema { name, .. } => {
            lookup_bundle_schema_owner_or_bindings(name, ownership, change)
        }
        Change::AlterSchemaOwner { name, .. }
        | Change::EnsureSchemaOwnerPrivileges { name, .. } => {
            lookup_bundle_schema_facet(name, SchemaBindingFacet::Owner, ownership, change)
        }
        Change::Grant {
            role,
            object_type,
            schema,
            name,
            ..
        }
        | Change::Revoke {
            role,
            object_type,
            schema,
            name,
            ..
        } => {
            let grant_key = GrantKey {
                role: role.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            };

            if let Some(document) = ownership.grants.get(&grant_key) {
                return Ok(BundleChangeOwner {
                    document: document.clone(),
                    managed_key: ManagedOwnershipKey::Grant {
                        role: grant_key.role.clone(),
                        object_type: grant_key.object_type,
                        schema: grant_key.schema.clone(),
                        name: grant_key.name.clone(),
                    },
                });
            }

            if *object_type == ObjectType::Database {
                return ownership
                    .roles
                    .get(role.as_str())
                    .cloned()
                    .map(|document| BundleChangeOwner {
                        document,
                        managed_key: ManagedOwnershipKey::Role {
                            name: role.as_str().to_string(),
                        },
                    })
                    .ok_or_else(|| BundlePlanError::MissingOwner {
                        change: describe_change(change),
                    });
            }

            let schema_name =
                grant_schema_name(&grant_key).ok_or_else(|| BundlePlanError::InvalidChange {
                    change: describe_change(change),
                })?;
            lookup_bundle_schema_facet(
                &schema_name,
                SchemaBindingFacet::Bindings,
                ownership,
                change,
            )
        }
        Change::SetDefaultPrivilege {
            owner,
            scope,
            on_type,
            grantee,
            ..
        }
        | Change::RevokeDefaultPrivilege {
            owner,
            scope,
            on_type,
            grantee,
            ..
        } => {
            let key = DefaultPrivKey {
                owner: owner.clone(),
                scope: scope.clone(),
                on_type: *on_type,
                grantee: grantee.clone(),
            };

            if let Some(document) = ownership.default_privileges.get(&key) {
                return Ok(BundleChangeOwner {
                    document: document.clone(),
                    managed_key: ManagedOwnershipKey::DefaultPrivilege {
                        owner: key.owner.clone(),
                        scope: key.scope.clone(),
                        on_type: key.on_type,
                        grantee: key.grantee.clone(),
                    },
                });
            }

            match scope {
                DefaultPrivilegeScope::Schema { schema } => lookup_bundle_schema_facet(
                    schema,
                    SchemaBindingFacet::Bindings,
                    ownership,
                    change,
                ),
                // Global defaults belong to whichever document owns the role.
                DefaultPrivilegeScope::Global => ownership
                    .roles
                    .get(owner)
                    .cloned()
                    .map(|document| BundleChangeOwner {
                        document,
                        managed_key: ManagedOwnershipKey::Role {
                            name: owner.clone(),
                        },
                    })
                    .ok_or_else(|| BundlePlanError::MissingOwner {
                        change: describe_change(change),
                    }),
            }
        }
        Change::AddMember { role, member, .. } | Change::RemoveMember { role, member, .. } => {
            let key = MembershipKey {
                role: role.clone(),
                member: member.clone(),
            };

            if let Some(document) = ownership.memberships.get(&key) {
                return Ok(BundleChangeOwner {
                    document: document.clone(),
                    managed_key: ManagedOwnershipKey::Membership {
                        role: role.clone(),
                        member: member.clone(),
                    },
                });
            }

            ownership
                .roles
                .get(role)
                .cloned()
                .map(|document| BundleChangeOwner {
                    document,
                    managed_key: ManagedOwnershipKey::Role { name: role.clone() },
                })
                .ok_or_else(|| BundlePlanError::MissingOwner {
                    change: describe_change(change),
                })
        }
    }
}

fn lookup_bundle_schema_owner_or_bindings(
    schema: &str,
    ownership: &OwnershipIndex,
    change: &Change,
) -> Result<BundleChangeOwner, BundlePlanError> {
    lookup_bundle_schema_facet(schema, SchemaBindingFacet::Owner, ownership, change).or_else(|_| {
        lookup_bundle_schema_facet(schema, SchemaBindingFacet::Bindings, ownership, change)
    })
}

fn lookup_bundle_schema_facet(
    schema: &str,
    facet: SchemaBindingFacet,
    ownership: &OwnershipIndex,
    change: &Change,
) -> Result<BundleChangeOwner, BundlePlanError> {
    let facet_key = SchemaFacetKey {
        schema: schema.to_string(),
        facet,
    };

    ownership
        .schema_facets
        .get(&facet_key)
        .cloned()
        .map(|document| BundleChangeOwner {
            document,
            managed_key: ManagedOwnershipKey::SchemaFacet {
                schema: schema.to_string(),
                facet,
            },
        })
        .ok_or_else(|| BundlePlanError::MissingOwner {
            change: describe_change(change),
        })
}

fn bundle_change_category(change: &Change) -> BundleChangeCategory {
    match change {
        Change::CreateRole { .. }
        | Change::AlterRole { .. }
        | Change::SetComment { .. }
        | Change::SetPassword { .. }
        | Change::DropRole { .. } => BundleChangeCategory::Role,
        Change::CreateSchema { .. }
        | Change::AlterSchemaOwner { .. }
        | Change::EnsureSchemaOwnerPrivileges { .. } => BundleChangeCategory::Schema,
        Change::Grant { .. } | Change::Revoke { .. } => BundleChangeCategory::Grant,
        Change::SetDefaultPrivilege { .. } | Change::RevokeDefaultPrivilege { .. } => {
            BundleChangeCategory::DefaultPrivilege
        }
        Change::AddMember { .. } | Change::RemoveMember { .. } => BundleChangeCategory::Membership,
        Change::ReassignOwned { .. }
        | Change::DropOwned { .. }
        | Change::TerminateSessions { .. } => BundleChangeCategory::Retirement,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::{self, PolicyDocument};
    use crate::diff::diff;
    use crate::model::RoleGraph;

    #[test]
    fn render_plan_json_redacts_passwords_in_redacted_mode() {
        let changes = vec![Change::SetPassword {
            name: "app".to_string(),
            password: "super-secret".to_string(),
        }];

        let redacted = shape_plan_changes(&changes, PlanOutputMode::Redacted);
        assert_eq!(
            redacted[0],
            Change::SetPassword {
                name: "app".to_string(),
                password: "[REDACTED]".to_string(),
            }
        );

        let json =
            render_plan_json(&changes, PlanOutputMode::Redacted).expect("json should render");
        assert!(json.contains("[REDACTED]"));
        assert!(!json.contains("super-secret"));
    }

    #[test]
    fn bundle_plan_json_contract_is_versioned_and_typed() {
        let bundle = composition::parse_policy_bundle(
            r#"
sources:
  - file: app.yaml
"#,
        )
        .expect("bundle should parse");
        let documents = vec![PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: composition::parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  roles: [app]
roles:
  - name: app
    login: false
"#,
            )
            .expect("fragment should parse"),
        }];
        let composed =
            composition::compose_bundle(&bundle, &documents).expect("bundle should compose");
        let changes = diff(&RoleGraph::default(), &composed.desired);

        let plan = build_bundle_plan(
            &changes,
            &composed.report_context(),
            PlanOutputMode::Redacted,
        )
        .expect("bundle plan should annotate");
        let json = serde_json::to_value(&plan).expect("bundle plan should serialize");

        // Pinned to the literal on purpose: comparing against the constant
        // the code writes would let a version bump through without anyone
        // documenting the migration.
        assert_eq!(json["schema_version"], "pgroles.bundle_plan.v2");
        assert_eq!(json["schema_version"], BUNDLE_PLAN_SCHEMA_VERSION);
        assert_eq!(json["managed_scope"]["roles"][0], "app");
        assert_eq!(json["changes"][0]["category"], "role");
        assert_eq!(json["changes"][0]["owner"]["document"], "app");
        assert_eq!(json["changes"][0]["owner"]["managed_key"]["kind"], "role");
        assert_eq!(json["changes"][0]["owner"]["managed_key"]["name"], "app");
    }

    #[test]
    fn bundle_plan_full_mode_preserves_password_values() {
        let bundle = composition::parse_policy_bundle(
            r#"
sources:
  - file: app.yaml
"#,
        )
        .expect("bundle should parse");
        let documents = vec![PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: composition::parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  roles: [app]
roles:
  - name: app
    login: true
"#,
            )
            .expect("fragment should parse"),
        }];
        let composed =
            composition::compose_bundle(&bundle, &documents).expect("bundle should compose");
        let changes = vec![Change::SetPassword {
            name: "app".to_string(),
            password: "super-secret".to_string(),
        }];

        let redacted = build_bundle_plan(
            &changes,
            &composed.report_context(),
            PlanOutputMode::Redacted,
        )
        .expect("redacted plan should build");
        let full = build_bundle_plan(&changes, &composed.report_context(), PlanOutputMode::Full)
            .expect("full plan should build");

        assert_eq!(
            redacted.changes[0].change,
            Change::SetPassword {
                name: "app".to_string(),
                password: "[REDACTED]".to_string(),
            }
        );
        assert_eq!(
            full.changes[0].change,
            Change::SetPassword {
                name: "app".to_string(),
                password: "super-secret".to_string(),
            }
        );
    }
}
