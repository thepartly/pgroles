//! Export a [`RoleGraph`] to a [`PolicyManifest`] for brownfield adoption.
//!
//! This is the reverse of `manifest::expand_manifest` → `RoleGraph::from_expanded`.
//! It produces a flat manifest (no profiles) that faithfully represents the
//! current database state. When applied back, it should produce zero diff.

use std::collections::BTreeMap;

use crate::manifest::{
    DefaultPrivilege, DefaultPrivilegeGrant, DefaultPrivilegeScopeSpec, DefaultPrivilegeScopeType,
    Ensure, Grant, MemberSpec, Membership, ObjectTarget, PolicyManifest, RoleDefinition,
    SchemaBinding,
};
use crate::model::{DefaultPrivilegeScope, RoleGraph};

/// Convert a [`RoleGraph`] into a flat [`PolicyManifest`].
///
/// The resulting manifest uses no profiles — all roles, grants, default
/// privileges, and memberships are emitted as top-level entries. This makes
/// the output straightforward and correct for round-tripping.
///
/// Absence assertions are intentionally not exported. `generate` builds
/// this from an inspected graph, where the maps are always empty, and inventing
/// `ensure: absent` from a privilege that merely happens to be missing would
/// assert policy the user never stated. A caller passing a *desired* graph
/// would lose those assertions — export the manifest it came from instead.
pub fn role_graph_to_manifest(graph: &RoleGraph) -> PolicyManifest {
    debug_assert!(
        graph.grant_absences.is_empty() && graph.default_privilege_absences.is_empty(),
        "role_graph_to_manifest cannot represent absence assertions; \
         export the source manifest rather than a desired graph"
    );

    // --- Roles ---
    let roles: Vec<RoleDefinition> = graph
        .roles
        .iter()
        .map(|(name, state)| {
            let defaults = crate::model::RoleState::default();
            RoleDefinition {
                name: name.clone(),
                external: false,
                preserve_undeclared_grants: false,
                login: if state.login != defaults.login {
                    Some(state.login)
                } else {
                    None
                },
                superuser: if state.superuser != defaults.superuser {
                    Some(state.superuser)
                } else {
                    None
                },
                createdb: if state.createdb != defaults.createdb {
                    Some(state.createdb)
                } else {
                    None
                },
                createrole: if state.createrole != defaults.createrole {
                    Some(state.createrole)
                } else {
                    None
                },
                inherit: if state.inherit != defaults.inherit {
                    Some(state.inherit)
                } else {
                    None
                },
                replication: if state.replication != defaults.replication {
                    Some(state.replication)
                } else {
                    None
                },
                bypassrls: if state.bypassrls != defaults.bypassrls {
                    Some(state.bypassrls)
                } else {
                    None
                },
                connection_limit: if state.connection_limit != defaults.connection_limit {
                    Some(state.connection_limit)
                } else {
                    None
                },
                comment: state.comment.clone(),
                password: None, // Passwords are never exported (cannot be read from DB)
                password_valid_until: state.password_valid_until.clone(),
                config: state
                    .config
                    .iter()
                    .map(|(parameter, value)| {
                        (
                            parameter.clone(),
                            crate::manifest::ConfigValue(value.clone()),
                        )
                    })
                    .collect(),
            }
        })
        .collect();

    // --- Grants ---
    // Owner-inherent entries are skipped: the grantee holds them as the
    // object's owner, not by anyone's declaration, so exporting them would
    // produce a manifest asserting privileges no one granted.
    let grants: Vec<Grant> = graph
        .grants
        .iter()
        .filter(|(key, _)| !graph.inherent_grants.contains(*key))
        .map(|(key, state)| Grant {
            role: key.role.as_str().to_string(),
            privileges: state.privileges.iter().copied().collect(),
            object: ObjectTarget {
                object_type: key.object_type,
                schema: key.schema.clone(),
                name: key.name.clone(),
            },
            ensure: Ensure::Present,
        })
        .collect();

    // --- Schemas ---
    let schemas: Vec<SchemaBinding> = graph
        .schemas
        .iter()
        .map(|(name, state)| SchemaBinding {
            name: name.clone(),
            profiles: Vec::new(),
            role_pattern: None,
            owner: state.owner.clone(),
        })
        .collect();

    // --- Default privileges ---
    // Group by (owner, scope) to produce compact default_privileges entries.
    let mut dp_groups: BTreeMap<(String, DefaultPrivilegeScope), Vec<DefaultPrivilegeGrant>> =
        BTreeMap::new();
    for (key, state) in &graph.default_privileges {
        dp_groups
            .entry((key.owner.clone(), key.scope.clone()))
            .or_default()
            .push(DefaultPrivilegeGrant {
                role: Some(key.grantee.as_str().to_string()),
                privileges: state.privileges.iter().copied().collect(),
                on_type: key.on_type,
                ensure: Ensure::Present,
            });
    }
    let default_privileges: Vec<DefaultPrivilege> = dp_groups
        .into_iter()
        .map(|((owner, scope), grant)| {
            // Schema scope keeps the `schema:` shorthand so exported YAML for
            // existing databases is unchanged; only global scope needs the
            // explicit `scope` field.
            let (schema, scope) = match scope {
                DefaultPrivilegeScope::Schema { schema } => (Some(schema), None),
                DefaultPrivilegeScope::Global => (
                    None,
                    Some(DefaultPrivilegeScopeSpec {
                        scope_type: DefaultPrivilegeScopeType::Global,
                        schema: None,
                    }),
                ),
            };
            DefaultPrivilege {
                owner: Some(owner),
                schema,
                scope,
                grant,
            }
        })
        .collect();

    // --- Memberships ---
    // Group by group role.
    let mut membership_map: BTreeMap<String, Vec<MemberSpec>> = BTreeMap::new();
    for edge in &graph.memberships {
        membership_map
            .entry(edge.role.clone())
            .or_default()
            .push(MemberSpec {
                name: edge.member.clone(),
                inherit: if edge.inherit { None } else { Some(false) },
                admin: if edge.admin { Some(true) } else { None },
            });
    }
    let memberships: Vec<Membership> = membership_map
        .into_iter()
        .map(|(role, members)| Membership {
            role,
            members,
            exclusive: false,
        })
        .collect();

    PolicyManifest {
        role_pattern: None,
        default_owner: None,
        auth_providers: Vec::new(),
        profiles: BTreeMap::new(),
        schemas,
        roles,
        grants,
        default_privileges,
        memberships,
        retirements: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::diff;
    use crate::manifest::{expand_manifest, parse_manifest};
    use crate::model::RoleGraph;

    /// Round-trip test: build a RoleGraph, export to manifest, re-import, diff should be empty.
    #[test]
    fn round_trip_export_import() {
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

roles:
  - name: analytics
    login: true
    comment: "Analytics role"

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
        inherit: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let original =
            RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();

        // Export and re-import
        let exported_manifest = role_graph_to_manifest(&original);
        let exported_expanded = expand_manifest(&exported_manifest).unwrap();
        let reimported = RoleGraph::from_expanded(
            &exported_expanded,
            exported_manifest.default_owner.as_deref(),
        )
        .unwrap();

        // Diff should be empty
        let changes = diff(&original, &reimported);
        assert!(
            changes.is_empty(),
            "round-trip produced unexpected changes: {changes:?}"
        );

        assert_eq!(exported_manifest.schemas.len(), 1);
        assert_eq!(exported_manifest.schemas[0].name, "inventory");
    }

    #[test]
    fn export_only_emits_non_default_attributes() {
        let yaml = r#"
roles:
  - name: basic-role
  - name: login-role
    login: true
    connection_limit: 5
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        let exported = role_graph_to_manifest(&graph);
        let basic = exported
            .roles
            .iter()
            .find(|r| r.name == "basic-role")
            .unwrap();
        assert!(basic.login.is_none());
        assert!(basic.superuser.is_none());
        assert!(basic.connection_limit.is_none());

        let login = exported
            .roles
            .iter()
            .find(|r| r.name == "login-role")
            .unwrap();
        assert_eq!(login.login, Some(true));
        assert_eq!(login.connection_limit, Some(5));
    }

    #[test]
    fn export_includes_managed_schemas() {
        let mut graph = RoleGraph::default();
        graph.schemas.insert(
            "cdc".to_string(),
            crate::model::SchemaState {
                owner: Some("cdc_owner".to_string()),
                owner_privileges: crate::model::default_schema_owner_privileges("cdc_owner"),
            },
        );

        let exported = role_graph_to_manifest(&graph);
        assert_eq!(exported.schemas.len(), 1);
        assert_eq!(exported.schemas[0].name, "cdc");
        assert_eq!(exported.schemas[0].owner.as_deref(), Some("cdc_owner"));
        assert!(exported.schemas[0].profiles.is_empty());
    }

    #[test]
    fn exported_yaml_omits_null_fields() {
        let yaml = r#"
roles:
  - name: basic-role
  - name: login-role
    login: true
    connection_limit: 5
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        let exported = role_graph_to_manifest(&graph);
        let serialized = serde_yaml::to_string(&exported).unwrap();

        assert!(
            !serialized.contains("null"),
            "serialized YAML should not contain null fields, got:\n{serialized}"
        );
        // Non-default attributes should still be present
        assert!(serialized.contains("login: true"), "got:\n{serialized}");
        assert!(
            serialized.contains("connection_limit: 5"),
            "got:\n{serialized}"
        );
    }

    #[test]
    fn exported_yaml_uses_object_for_grant_targets() {
        let yaml = r#"
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        let exported = role_graph_to_manifest(&graph);
        let serialized = serde_yaml::to_string(&exported).unwrap();

        assert!(serialized.contains("object:"), "got:\n{serialized}");
        assert!(
            !serialized.contains("\non:"),
            "exported YAML should not emit legacy on key, got:\n{serialized}"
        );
    }

    #[test]
    fn export_omits_password_and_preserves_password_valid_until() {
        let yaml = r#"
roles:
  - name: app-role
    login: true
    password_valid_until: "2026-12-31T00:00:00Z"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        let exported = role_graph_to_manifest(&graph);
        let role = exported
            .roles
            .iter()
            .find(|r| r.name == "app-role")
            .unwrap();

        assert!(
            role.password.is_none(),
            "passwords should never be exported"
        );
        assert_eq!(
            role.password_valid_until.as_deref(),
            Some("2026-12-31T00:00:00Z")
        );

        let serialized = serde_yaml::to_string(&exported).unwrap();
        assert!(
            !serialized.contains("password:"),
            "exported YAML must not contain password fields, got:\n{serialized}"
        );
        assert!(
            serialized.contains("password_valid_until: \"2026-12-31T00:00:00Z\"")
                || serialized.contains("password_valid_until: '2026-12-31T00:00:00Z'")
                || serialized.contains("password_valid_until: 2026-12-31T00:00:00Z"),
            "exported YAML should preserve password_valid_until, got:\n{serialized}"
        );
    }
}
