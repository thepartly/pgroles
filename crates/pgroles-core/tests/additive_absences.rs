use std::collections::BTreeSet;

use pgroles_core::diff::{Change, ReconciliationMode, plan_changes};
use pgroles_core::manifest::{ObjectType, Privilege, expand_manifest, parse_manifest};
use pgroles_core::model::{DefaultPrivilegeScope, Grantee, RoleGraph};

fn graph(yaml: &str) -> RoleGraph {
    let manifest = parse_manifest(yaml).unwrap();
    let expanded = expand_manifest(&manifest).unwrap();
    RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap()
}

fn plan(current: &RoleGraph, yaml: &str, enforce: bool) -> Vec<Change> {
    let mut manifest = parse_manifest(yaml).unwrap();
    manifest.additive_enforce_absences = enforce;
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
    let strict = plan(&current, yaml, false);
    assert!(strict.iter().all(|change| !matches!(
        change,
        Change::Revoke { .. } | Change::RevokeDefaultPrivilege { .. }
    )));

    let opted_in = plan(&current, yaml, true);
    assert_eq!(opted_in.len(), strict.len() + 2);
    assert!(opted_in.iter().any(|change| matches!(change,
        Change::CreateRole { name, .. } if name == "newcomer")));
    assert!(opted_in.iter().any(|change| matches!(
        change,
        Change::Grant {
            object_type: ObjectType::Database,
            ..
        }
    )));
    let revokes: Vec<_> = opted_in
        .iter()
        .filter(|change| {
            matches!(
                change,
                Change::Revoke { .. } | Change::RevokeDefaultPrivilege { .. }
            )
        })
        .collect();
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
fn opting_in_without_absence_assertions_keeps_strict_additive_behavior() {
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
    assert_eq!(plan(&current, yaml, true), plan(&current, yaml, false));
    assert!(plan(&current, yaml, true).is_empty());
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
    let changes = plan(&current, yaml, true);
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
    let changes = plan(&current, yaml, true);
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
    let changes = plan(&RoleGraph::default(), yaml, true);
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
        true,
    );
    assert_eq!(changes.len(), 1);
    assert!(matches!(&changes[0], Change::Revoke { name, .. }
        if name.as_deref() == Some("lookup(smallint)")));
}

#[test]
fn manifest_opt_in_is_explicit_and_false_keeps_existing_serialization() {
    let ordinary = parse_manifest("roles: []").unwrap();
    assert!(!ordinary.additive_enforce_absences);
    assert!(
        !serde_json::to_string(&ordinary)
            .unwrap()
            .contains("additive_enforce_absences")
    );
    let enabled = parse_manifest("additive_enforce_absences: true\nroles: []").unwrap();
    assert!(enabled.additive_enforce_absences);
    assert!(
        serde_json::to_string(&enabled)
            .unwrap()
            .contains("\"additive_enforce_absences\":true")
    );
}

#[test]
fn bundles_render_the_explicit_opt_in_into_the_composed_manifest() {
    use pgroles_core::composition::{
        PolicyDocument, compose_bundle, parse_policy_bundle, parse_policy_fragment,
    };
    let bundle =
        parse_policy_bundle("additive_enforce_absences: true\nsources:\n  - file: platform.yaml\n")
            .unwrap();
    let document = PolicyDocument {
        source: "platform.yaml".into(),
        fragment: parse_policy_fragment(
            "policy: {name: platform}\nscope: {roles: [reader]}\nroles: [{name: reader}]\n",
        )
        .unwrap(),
    };
    let composed = compose_bundle(&bundle, &[document]).unwrap();
    assert!(composed.manifest.additive_enforce_absences);
    assert!(
        serde_yaml::to_string(&composed.manifest)
            .unwrap()
            .contains("additive_enforce_absences: true")
    );
}
