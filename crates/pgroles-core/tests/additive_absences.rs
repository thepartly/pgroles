use std::collections::BTreeSet;

use pgroles_core::diff::{Change, ReconciliationMode, plan_changes};
use pgroles_core::manifest::{ObjectType, Privilege, expand_manifest, parse_manifest};
use pgroles_core::model::{DefaultPrivilegeScope, Grantee, RoleGraph};

fn graph(yaml: &str) -> RoleGraph {
    let manifest = parse_manifest(yaml).unwrap();
    let expanded = expand_manifest(&manifest).unwrap();
    RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap()
}

fn plan(current: &RoleGraph, yaml: &str) -> Vec<Change> {
    let manifest = parse_manifest(yaml).unwrap();
    let expanded = expand_manifest(&manifest).unwrap();
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();
    plan_changes(
        current,
        &desired,
        &manifest,
        &expanded,
        ReconciliationMode::Additive,
    )
}

const CURRENT: &str = r#"
roles:
  - name: reader
  - name: owner
  - name: unrelated_owner
  - name: legacy
memberships:
  - role: reader
    members: [{name: legacy}]
grants:
  - role: reader
    privileges: [SELECT, INSERT]
    object: {type: table, schema: app, name: records}
  - role: reader
    privileges: [UPDATE]
    object: {type: table, schema: app, name: other}
default_privileges:
  - owner: owner
    schema: app
    grant:
      - role: reader
        privileges: [SELECT, INSERT]
        on_type: table
  - owner: unrelated_owner
    schema: app
    grant:
      - role: reader
        privileges: [SELECT]
        on_type: table
"#;

#[test]
fn explicit_absences_revoke_only_the_requested_edges_and_keep_positive_additions() {
    let current = graph(CURRENT);
    let yaml = r#"
roles:
  - name: reader
    external: true
  - name: owner
    external: true
  - name: newcomer
grants:
  - role: reader
    ensure: absent
    privileges: [SELECT]
    object: {type: table, schema: app, name: records}
  - role: reader
    privileges: [CONNECT]
    object: {type: database, name: product}
default_privileges:
  - owner: owner
    schema: app
    grant:
      - role: reader
        ensure: absent
        privileges: [SELECT]
        on_type: table
"#;
    let changes = plan(&current, yaml);
    assert!(changes.iter().any(|change| matches!(change,
        Change::CreateRole { name, .. } if name == "newcomer")));
    assert!(changes.iter().any(|change| matches!(
        change,
        Change::Grant {
            object_type: ObjectType::Database,
            ..
        }
    )));
    let revokes: Vec<_> = changes
        .iter()
        .filter(|change| {
            matches!(
                change,
                Change::Revoke { .. } | Change::RevokeDefaultPrivilege { .. }
            )
        })
        .collect();
    assert_eq!(revokes.len(), 2);
    assert!(
        matches!(revokes[0], Change::Revoke { role, name, privileges, .. }
        if role.as_str() == "reader" && name.as_deref() == Some("records")
        && privileges == &BTreeSet::from([Privilege::Select]))
    );
    assert!(
        matches!(revokes[1], Change::RevokeDefaultPrivilege { owner, scope, privileges, .. }
        if owner == "owner" && *scope == DefaultPrivilegeScope::Schema { schema: "app".into() }
        && privileges == &BTreeSet::from([Privilege::Select]))
    );
}

#[test]
fn without_absence_assertions_preserves_memberships_and_roles() {
    let current = graph(CURRENT);
    let yaml = r#"
roles:
  - name: reader
    external: true
  - name: owner
    external: true
memberships:
  - role: reader
    exclusive: true
    members: []
retirements:
  - role: legacy
    drop_owned: true
"#;
    assert!(plan(&current, yaml).is_empty());
}

#[test]
fn normalized_wildcards_do_not_broaden_named_absences_or_lose_the_grantor() {
    let mut current = graph(
        r#"
roles: [{name: reader}]
grants:
  - role: reader
    privileges: [SELECT, INSERT]
    object: {type: table, schema: app, name: '*'}
"#,
    );
    let key = current.grants.keys().next().unwrap().clone();
    current.grant_entry_grantors.insert(
        key,
        [(
            "owner".into(),
            BTreeSet::from([Privilege::Select, Privilege::Insert]),
        )]
        .into(),
    );
    let yaml = r#"
roles: [{name: reader, external: true}]
grants:
  - role: reader
    ensure: absent
    privileges: [SELECT]
    object: {type: table, schema: app, name: records}
"#;
    let changes = plan(&current, yaml);
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        matches!(&changes[0], Change::Revoke { name, grantor, privileges, .. }
        if name.as_deref() == Some("records") && grantor.as_deref() == Some("owner")
        && privileges == &BTreeSet::from([Privilege::Select]))
    );
}

#[test]
fn wildcard_absences_retain_unrequested_privileges_on_each_live_object() {
    let current = graph(CURRENT);
    let yaml = r#"
roles: [{name: reader, external: true}]
grants:
  - role: reader
    ensure: absent
    privileges: [SELECT]
    object: {type: table, schema: app, name: '*'}
"#;
    let changes = plan(&current, yaml);
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        matches!(&changes[0], Change::Revoke { name, privileges, .. }
        if name.as_deref() == Some("records") && privileges == &BTreeSet::from([Privilege::Select]))
    );
}

#[test]
fn global_public_defaults_for_new_roles_can_be_explicitly_removed() {
    let yaml = r#"
roles: [{name: owner}]
default_privileges:
  - owner: owner
    scope: {type: global}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
"#;
    let changes = plan(&RoleGraph::default(), yaml);
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(matches!(&changes[0], Change::CreateRole { name, .. } if name == "owner"));
    assert!(matches!(
        &changes[1],
        Change::RevokeDefaultPrivilege {
            scope: DefaultPrivilegeScope::Global,
            grantee: Grantee::Public,
            ..
        }
    ));
}

#[test]
fn routine_aliases_are_resolved_before_selecting_explicit_revokes() {
    let mut current = graph(
        r#"
grants:
  - role: PUBLIC
    privileges: [EXECUTE]
    object: {type: function, schema: app, name: 'lookup(smallint)'}
"#,
    );
    current.routine_aliases.insert(
        ("app".into(), "lookup(int2)".into()),
        "lookup(smallint)".into(),
    );
    let changes = plan(
        &current,
        r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: {type: function, schema: app, name: 'lookup(int2)'}
"#,
    );
    assert_eq!(changes.len(), 1);
    assert!(matches!(&changes[0], Change::Revoke { name, .. }
        if name.as_deref() == Some("lookup(smallint)")));
}

#[test]
fn deleting_a_converged_absence_does_not_restore_access() {
    let current = graph(
        "roles: [{name: reader}]\ngrants:\n  - role: reader\n    privileges: [INSERT]\n    object: {type: table, schema: app, name: records}\n",
    );
    assert!(plan(&current, "roles: [{name: reader, external: true}]").is_empty());
}

#[test]
fn bundle_absences_are_enforced_without_an_option() {
    use pgroles_core::composition::{
        PolicyDocument, compose_bundle, parse_policy_bundle, parse_policy_fragment,
    };
    let bundle = parse_policy_bundle("sources: [{file: platform.yaml}]").unwrap();
    let fragment = parse_policy_fragment(
        r#"
policy: {name: platform}
scope: {roles: [reader], schemas: [{name: app, facets: [bindings]}]}
roles: [{name: reader, external: true}]
grants:
  - role: reader
    ensure: absent
    privileges: [SELECT]
    object: {type: table, schema: app, name: records}
"#,
    )
    .unwrap();
    let composed = compose_bundle(
        &bundle,
        &[PolicyDocument {
            source: "platform.yaml".into(),
            fragment,
        }],
    )
    .unwrap();
    let yaml = serde_yaml::to_string(&composed.manifest).unwrap();
    let changes = plan(&graph(CURRENT), &yaml);
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert!(
        matches!(&changes[0], Change::Revoke { privileges, .. } if privileges == &BTreeSet::from([Privilege::Select]))
    );
}
