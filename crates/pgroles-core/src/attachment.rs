//! Policies attached to a shared database, composed under delegated scope.
//!
//! A database owner delegates parts of one database to namespaces: which roles
//! a namespace may define and which schema facets it may manage. Policies from
//! those namespaces attach to the database; this module derives each policy's
//! scope from the delegation rather than from anything the policy says about
//! itself, rejects policies that reach outside it, and composes the rest.
//!
//! Conflicts resolve by precedence instead of failing the whole database:
//! policies are admitted oldest first, and a later policy that collides with an
//! earlier one is rejected on its own. One careless or hostile newcomer
//! therefore cannot stop policies that were already converging. A policy whose
//! new content is rejected, for any reason, keeps its last accepted content
//! composed, so a broken edit never frees its claims for a younger policy.
//!
//! A policy claims the roles it creates and retires, the schema facets it
//! uses, and the grants it asserts. A role it declares `external`, grants to,
//! or adds as a member is a reference: it claims nothing, and a role that no
//! accepted policy creates is composed as external so its grants converge.

use std::collections::{BTreeMap, BTreeSet};

use crate::composition::{
    BundleSource, ComposedPolicy, CompositionError, FragmentMetadata, FragmentScope, PolicyBundle,
    PolicyDocument, PolicyFragment, ScopedSchema, SharedPolicy, compose_bundle,
};
use crate::manifest::{ObjectType, SchemaBindingFacet};

/// One grant of authority from the database owner to a set of namespaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delegation {
    /// Unique among the database's delegations; status and routing refer to it.
    pub name: String,
    /// Namespaces this delegation applies to. `*` matches every namespace.
    pub namespaces: Vec<String>,
    /// Roles those namespaces may define or retire. An entry ending in `*`
    /// matches by prefix.
    pub roles: Vec<String>,
    /// Schema facets those namespaces may manage.
    pub schemas: Vec<DelegatedSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedSchema {
    pub name: String,
    pub facets: Vec<SchemaBindingFacet>,
}

/// A policy attached to the database, before its scope is known.
#[derive(Debug, Clone)]
pub struct AttachedPolicy {
    pub namespace: String,
    pub name: String,
    /// Orders precedence: earlier wins. RFC 3339 timestamps sort correctly as
    /// strings, which is what Kubernetes `creationTimestamp` provides.
    pub created_at: String,
    /// The policy content. Its `scope` is ignored and replaced by the scope
    /// the delegations grant.
    pub fragment: PolicyFragment,
    /// The content last accepted for this policy, when that differs from
    /// `fragment`. Served while the current content is rejected, so a broken
    /// edit neither drops what the policy already manages nor frees its claims
    /// for a later policy to take.
    pub last_accepted: Option<PolicyFragment>,
    /// Set when the caller has already found the current content invalid for a
    /// reason `fragment` cannot show, such as a field only the database owner
    /// may set. It is handled like any other rejected edit: the last accepted
    /// content is still served.
    pub invalid: Option<String>,
}

impl AttachedPolicy {
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    /// The current content was rejected; the last accepted content is still
    /// composed in its place.
    Retained {
        reason: RejectionReason,
        message: String,
    },
    Rejected {
        reason: RejectionReason,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// The namespace has no delegation on this database.
    NotDelegated,
    /// The policy reaches outside what its namespace was delegated.
    OutOfScope,
    /// An earlier policy already manages something this one claims.
    Conflicted,
    /// The policy does not validate on its own.
    Invalid,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectionReason::NotDelegated => "NotDelegated",
            RejectionReason::OutOfScope => "OutOfScope",
            RejectionReason::Conflicted => "Conflicted",
            RejectionReason::Invalid => "Invalid",
        }
    }
}

#[derive(Debug)]
pub struct AttachmentOutcome {
    /// Verdict per policy, in precedence order.
    pub verdicts: Vec<(String, Verdict)>,
    /// The composition of every accepted policy; `None` when none was.
    pub composed: Option<ComposedPolicy>,
    /// For each composed policy, the delegations whose scope admitted it.
    pub delegated_by: BTreeMap<String, Vec<String>>,
    /// Roles composed policies reference but none creates, declared external
    /// in the composition so their grants are inspected and converge.
    pub external_references: Vec<String>,
}

/// Label of the composed document that declares referenced roles external.
pub const REFERENCES_DOCUMENT: &str = "pgroles.io/references";

/// Compose every attached policy that its delegation permits, oldest first.
pub fn compose_attached(
    shared: &SharedPolicy,
    delegations: &[Delegation],
    policies: &[AttachedPolicy],
) -> AttachmentOutcome {
    let mut ordered: Vec<&AttachedPolicy> = policies.iter().collect();
    ordered.sort_by(|a, b| {
        (a.created_at.as_str(), a.namespace.as_str(), a.name.as_str()).cmp(&(
            b.created_at.as_str(),
            b.namespace.as_str(),
            b.name.as_str(),
        ))
    });

    let mut accepted: Vec<PolicyDocument> = Vec::new();
    let mut references: BTreeSet<String> = BTreeSet::new();
    let mut delegated_by = BTreeMap::new();
    let mut verdicts = Vec::with_capacity(ordered.len());

    for policy in ordered {
        let current = match &policy.invalid {
            Some(message) => Err((RejectionReason::Invalid, message.clone())),
            None => admit(shared, delegations, policy, &policy.fragment, &accepted)
                .map(|admitted| (admitted, &policy.fragment)),
        };
        let verdict = match current {
            Ok(((document, names), fragment)) => {
                accepted.push(document);
                references.extend(referenced_roles(fragment));
                delegated_by.insert(policy.key(), names);
                Verdict::Accepted
            }
            Err((reason, message)) => {
                let retained = policy.last_accepted.as_ref().and_then(|previous| {
                    admit(shared, delegations, policy, previous, &accepted)
                        .ok()
                        .map(|admitted| (admitted, previous))
                });
                match retained {
                    Some(((document, names), fragment)) => {
                        accepted.push(document);
                        references.extend(referenced_roles(fragment));
                        delegated_by.insert(policy.key(), names);
                        Verdict::Retained { reason, message }
                    }
                    None => Verdict::Rejected { reason, message },
                }
            }
        };
        verdicts.push((policy.key(), verdict));
    }

    let (composed, external_references) = if accepted.is_empty() {
        (None, Vec::new())
    } else {
        let base = compose(shared, &accepted)
            .expect("each accepted prefix composed, so the final set composes");
        let declared: BTreeSet<&str> = base
            .expanded
            .roles
            .iter()
            .map(|role| role.name.as_str())
            .chain(base.manifest.retirements.iter().map(|r| r.role.as_str()))
            .collect();
        let external: Vec<String> = references
            .iter()
            .filter(|role| role.as_str() != "PUBLIC" && !declared.contains(role.as_str()))
            .cloned()
            .collect();
        if external.is_empty() {
            (Some(base), external)
        } else {
            let mut documents = accepted.clone();
            documents.push(references_document(&external));
            // Every declared role was excluded above, so the extra document
            // claims nothing another one does. Should composition still fail,
            // the policies' own content is served and the references are
            // simply not inspected.
            match compose(shared, &documents) {
                Ok(with_references) => (Some(with_references), external),
                Err(_) => (Some(base), Vec::new()),
            }
        }
    };

    AttachmentOutcome {
        verdicts,
        composed,
        delegated_by,
        external_references,
    }
}

/// Every role `fragment` names without claiming it: roles it declares
/// external, grantees, members, schema and default-privilege owners, and
/// reassignment targets. Roles it also creates are filtered out by the caller.
fn referenced_roles(fragment: &PolicyFragment) -> BTreeSet<String> {
    fragment
        .roles
        .iter()
        .filter(|role| role.external)
        .map(|role| role.name.clone())
        .chain(fragment.grants.iter().map(|grant| grant.role.clone()))
        .chain(fragment.default_privileges.iter().flat_map(|dp| {
            dp.grant
                .iter()
                .filter_map(|grant| grant.role.clone())
                .chain(dp.owner.clone())
        }))
        .chain(
            fragment
                .memberships
                .iter()
                .flat_map(|membership| membership.members.iter().map(|member| member.name.clone())),
        )
        .chain(
            fragment
                .schemas
                .iter()
                .filter_map(|schema| schema.owner.clone()),
        )
        .chain(
            fragment
                .retirements
                .iter()
                .filter_map(|retirement| retirement.reassign_owned_to.clone()),
        )
        .collect()
}

/// A document that declares `roles` external and claims nothing else.
fn references_document(roles: &[String]) -> PolicyDocument {
    let definitions = roles
        .iter()
        .map(|role| {
            serde_json::from_value(serde_json::json!({ "name": role, "external": true }))
                .expect("a name and the external flag form a valid role definition")
        })
        .collect();
    PolicyDocument {
        source: REFERENCES_DOCUMENT.to_string(),
        fragment: PolicyFragment {
            policy: FragmentMetadata {
                name: Some(REFERENCES_DOCUMENT.to_string()),
            },
            scope: FragmentScope {
                roles: roles.to_vec(),
                schemas: Vec::new(),
            },
            roles: definitions,
            ..Default::default()
        },
    }
}

/// Admit one policy's content alongside the policies already accepted.
/// On success, returns the scoped document and the names of the delegations
/// that admitted it.
fn admit(
    shared: &SharedPolicy,
    delegations: &[Delegation],
    policy: &AttachedPolicy,
    fragment: &PolicyFragment,
    accepted: &[PolicyDocument],
) -> Result<(PolicyDocument, Vec<String>), (RejectionReason, String)> {
    let candidate = AttachedPolicy {
        fragment: fragment.clone(),
        last_accepted: None,
        invalid: None,
        ..policy.clone()
    };
    let DelegatedDocument {
        document,
        role_patterns,
        delegations: names,
    } = delegated_document(delegations, &candidate)?;

    // Validated alone first, so a policy that is broken on its own is
    // reported as invalid rather than as conflicting with its elders.
    let solo = compose(shared, std::slice::from_ref(&document))
        .map_err(|error| (RejectionReason::Invalid, error.to_string()))?;
    check_created_roles(&candidate, &document, &solo, &role_patterns)?;

    let mut with_elders = accepted.to_vec();
    with_elders.push(document.clone());
    compose(shared, &with_elders)
        .map_err(|error| (RejectionReason::Conflicted, error.to_string()))?;
    Ok((document, names))
}

fn compose(
    shared: &SharedPolicy,
    documents: &[PolicyDocument],
) -> Result<ComposedPolicy, CompositionError> {
    let bundle = PolicyBundle {
        shared: shared.clone(),
        sources: documents
            .iter()
            .map(|document| BundleSource {
                file: document.source.clone(),
            })
            .collect(),
    };
    compose_bundle(&bundle, documents)
}

/// Checks that need the policy expanded: what it creates, and what it may
/// decide for the roles it creates.
///
/// Roles generated from schema bindings count as created. Otherwise a role
/// pattern could mint names inside another team's delegation and claim them
/// before that team does.
fn check_created_roles(
    policy: &AttachedPolicy,
    document: &PolicyDocument,
    solo: &ComposedPolicy,
    role_patterns: &[String],
) -> Result<(), (RejectionReason, String)> {
    let out_of_scope = |message: String| Err((RejectionReason::OutOfScope, message));
    let created: BTreeSet<&str> = solo
        .expanded
        .roles
        .iter()
        .filter(|role| !role.external)
        .map(|role| role.name.as_str())
        .collect();
    for role in &created {
        if !role_matches(role_patterns, role) {
            return out_of_scope(format!(
                "role {role} is not delegated to namespace {}",
                policy.namespace
            ));
        }
    }

    // Memberships: only the role's owner decides who belongs to it.
    for membership in &document.fragment.memberships {
        if !created.contains(membership.role.as_str()) {
            return out_of_scope(format!(
                "membership in role {} needs that role to be created by this policy",
                membership.role
            ));
        }
    }

    // Database-level grants name no schema, so the grantee is what scopes
    // them: a policy may only grant or withhold database access for roles it
    // creates. PUBLIC is shared by everyone and stays with the database owner.
    for grant in &document.fragment.grants {
        if grant.object.object_type != ObjectType::Database {
            continue;
        }
        if grant.role == "PUBLIC" || !created.contains(grant.role.as_str()) {
            return out_of_scope(format!(
                "database privileges for {} need that role to be created by this policy",
                grant.role
            ));
        }
    }
    Ok(())
}

/// A policy as a bundle document, with the scope its delegations grant.
struct DelegatedDocument {
    document: PolicyDocument,
    /// Role patterns of every delegation that applies to the policy.
    role_patterns: Vec<String>,
    /// Names of those delegations.
    delegations: Vec<String>,
}

fn delegated_document(
    delegations: &[Delegation],
    policy: &AttachedPolicy,
) -> Result<DelegatedDocument, (RejectionReason, String)> {
    let granted: Vec<&Delegation> = delegations
        .iter()
        .filter(|delegation| {
            delegation
                .namespaces
                .iter()
                .any(|namespace| namespace == "*" || namespace == &policy.namespace)
        })
        .collect();
    if granted.is_empty() {
        return Err((
            RejectionReason::NotDelegated,
            format!(
                "namespace {} has no delegation on this database",
                policy.namespace
            ),
        ));
    }

    let fragment = &policy.fragment;
    let out_of_scope = |message: String| (RejectionReason::OutOfScope, message);

    // Roles: the policy owns exactly the roles it defines or retires, and
    // each must fall inside a delegated pattern. Retirements are checked here
    // because a retired role no longer appears once expanded.
    let mut owned_roles: BTreeSet<String> = BTreeSet::new();
    let defined = fragment
        .roles
        .iter()
        .filter(|role| !role.external)
        .map(|role| role.name.as_str())
        .chain(fragment.retirements.iter().map(|r| r.role.as_str()));
    for role in defined {
        if !granted
            .iter()
            .any(|delegation| role_matches(&delegation.roles, role))
        {
            return Err(out_of_scope(format!(
                "role {role} is not delegated to namespace {}",
                policy.namespace
            )));
        }
        owned_roles.insert(role.to_string());
    }

    // Schemas: claim only the facets the policy actually uses, so two
    // namespaces delegated the same schema do not collide over a facet only
    // one of them exercises.
    let mut scoped_schemas: Vec<ScopedSchema> = Vec::new();
    for schema in &fragment.schemas {
        let mut facets = Vec::new();
        if schema.owner.is_some() {
            facets.push(SchemaBindingFacet::Owner);
        }
        if !schema.profiles.is_empty() || schema.role_pattern.is_some() {
            facets.push(SchemaBindingFacet::Bindings);
        }
        for facet in &facets {
            if !granted
                .iter()
                .any(|delegation| schema_facet_delegated(delegation, &schema.name, *facet))
            {
                return Err(out_of_scope(format!(
                    "the {facet} facet of schema {} is not delegated to namespace {}",
                    schema.name, policy.namespace
                )));
            }
        }
        scoped_schemas.push(ScopedSchema {
            name: schema.name.clone(),
            facets,
        });
    }
    // Explicit grants and default privileges on a schema need its bindings
    // facet, even when the policy binds no profile there.
    let used_schemas = fragment
        .grants
        .iter()
        .filter_map(|grant| match grant.object.object_type {
            ObjectType::Database => None,
            ObjectType::Schema => grant.object.name.clone(),
            _ => grant.object.schema.clone(),
        })
        .chain(
            fragment
                .default_privileges
                .iter()
                .filter_map(|dp| dp.schema.clone()),
        );
    for schema in used_schemas {
        if !granted.iter().any(|delegation| {
            schema_facet_delegated(delegation, &schema, SchemaBindingFacet::Bindings)
        }) {
            return Err(out_of_scope(format!(
                "schema {schema} is not delegated to namespace {} for grants",
                policy.namespace
            )));
        }
        match scoped_schemas.iter_mut().find(|s| s.name == schema) {
            Some(scoped) if !scoped.facets.contains(&SchemaBindingFacet::Bindings) => {
                scoped.facets.push(SchemaBindingFacet::Bindings);
            }
            Some(_) => {}
            None => scoped_schemas.push(ScopedSchema {
                name: schema,
                facets: vec![SchemaBindingFacet::Bindings],
            }),
        }
    }

    // External declarations are references, not claims: two policies may both
    // grant to a role neither creates. They are composed as external once,
    // after admission (see `compose_attached`).
    let mut scoped = fragment.clone();
    scoped.roles.retain(|role| !role.external);
    scoped.policy = FragmentMetadata {
        name: Some(policy.key()),
    };
    scoped.scope = FragmentScope {
        roles: owned_roles.into_iter().collect(),
        schemas: scoped_schemas,
    };
    let role_patterns = granted
        .iter()
        .flat_map(|delegation| delegation.roles.iter().cloned())
        .collect();
    let names = granted
        .iter()
        .map(|delegation| delegation.name.clone())
        .collect();
    Ok(DelegatedDocument {
        document: PolicyDocument {
            source: policy.key(),
            fragment: scoped,
        },
        role_patterns,
        delegations: names,
    })
}

fn role_matches(patterns: &[String], role: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => role.starts_with(prefix),
            None => pattern == role,
        })
}

fn schema_facet_delegated(
    delegation: &Delegation,
    schema: &str,
    facet: SchemaBindingFacet,
) -> bool {
    delegation
        .schemas
        .iter()
        .any(|delegated| delegated.name == schema && delegated.facets.contains(&facet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::parse_policy_fragment;
    use crate::manifest::Profile;
    use std::collections::BTreeMap;

    fn attached(namespace: &str, name: &str, created_at: &str, yaml: &str) -> AttachedPolicy {
        AttachedPolicy {
            namespace: namespace.to_string(),
            name: name.to_string(),
            created_at: created_at.to_string(),
            fragment: parse_policy_fragment(yaml).expect("fragment parses"),
            last_accepted: None,
            invalid: None,
        }
    }

    fn shared() -> SharedPolicy {
        let profiles: BTreeMap<String, Profile> = serde_yaml::from_str(
            r#"
reader:
  grants:
    - privileges: [USAGE]
      object: { type: schema }
    - privileges: [SELECT]
      object: { type: table, name: "*" }
"#,
        )
        .unwrap();
        SharedPolicy {
            profiles,
            role_pattern: Some("{schema}_{profile}".to_string()),
            ..Default::default()
        }
    }

    fn delegations() -> Vec<Delegation> {
        vec![
            Delegation {
                name: "platform".into(),
                namespaces: vec!["platform".into()],
                roles: vec!["team_*".into(), "platform_*".into()],
                schemas: vec![],
            },
            Delegation {
                name: "billing".into(),
                namespaces: vec!["billing".into()],
                roles: vec!["billing_*".into()],
                schemas: vec![DelegatedSchema {
                    name: "billing".into(),
                    facets: vec![SchemaBindingFacet::Owner, SchemaBindingFacet::Bindings],
                }],
            },
        ]
    }

    const PLATFORM: &str = r#"
roles:
  - name: platform_admin
    createrole: true
  - name: team_payments
"#;

    const BILLING: &str = r#"
roles:
  - name: billing_migrator
  - name: billing_api
    login: true
schemas:
  - name: billing
    owner: billing_migrator
    profiles: [reader]
grants:
  - role: billing_api
    privileges: [CONNECT]
    object: { type: database, name: appdb }
  - role: team_payments
    privileges: [USAGE]
    object: { type: schema, name: billing }
"#;

    fn verdict<'a>(outcome: &'a AttachmentOutcome, key: &str) -> &'a Verdict {
        &outcome
            .verdicts
            .iter()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("no verdict for {key}"))
            .1
    }

    fn reason(outcome: &AttachmentOutcome, key: &str) -> RejectionReason {
        match verdict(outcome, key) {
            Verdict::Rejected { reason, .. } => *reason,
            other => panic!("{key} was not rejected: {other:?}"),
        }
    }

    #[test]
    fn teams_compose_within_their_delegations() {
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                attached("billing", "app", "2026-01-02T00:00:00Z", BILLING),
            ],
        );
        assert_eq!(verdict(&outcome, "platform/roles"), &Verdict::Accepted);
        assert_eq!(verdict(&outcome, "billing/app"), &Verdict::Accepted);
        let composed = outcome.composed.expect("composition");
        let roles: Vec<_> = composed
            .expanded
            .roles
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert!(roles.contains(&"platform_admin"));
        assert!(roles.contains(&"billing_reader"));
    }

    #[test]
    fn a_policy_may_not_add_itself_to_another_teams_role() {
        let rogue = r#"
roles:
  - name: billing_api
    login: true
memberships:
  - role: platform_admin
    members: [{ name: billing_api }]
"#;
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                attached("billing", "escalate", "2026-01-02T00:00:00Z", rogue),
            ],
        );
        assert_eq!(
            reason(&outcome, "billing/escalate"),
            RejectionReason::OutOfScope
        );
        assert_eq!(verdict(&outcome, "platform/roles"), &Verdict::Accepted);
    }

    #[test]
    fn database_grants_need_an_owned_grantee_and_never_public() {
        for grantee in ["team_payments", "PUBLIC"] {
            let yaml = format!(
                r#"
roles:
  - name: billing_api
grants:
  - role: {grantee}
    privileges: [CONNECT]
    object: {{ type: database, name: appdb }}
"#
            );
            let outcome = compose_attached(
                &shared(),
                &delegations(),
                &[attached("billing", "db", "2026-01-02T00:00:00Z", &yaml)],
            );
            assert_eq!(
                reason(&outcome, "billing/db"),
                RejectionReason::OutOfScope,
                "{grantee}"
            );
        }
    }

    #[test]
    fn undelegated_roles_schemas_and_namespaces_are_rejected() {
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached(
                    "billing",
                    "role",
                    "2026-01-02T00:00:00Z",
                    "roles:\n  - name: platform_ops\n",
                ),
                attached(
                    "billing",
                    "schema",
                    "2026-01-02T00:00:00Z",
                    "schemas:\n  - name: shipping\n    profiles: [reader]\n",
                ),
                attached(
                    "shipping",
                    "any",
                    "2026-01-02T00:00:00Z",
                    "roles:\n  - name: shipping_api\n",
                ),
            ],
        );
        assert_eq!(
            reason(&outcome, "billing/role"),
            RejectionReason::OutOfScope
        );
        assert_eq!(
            reason(&outcome, "billing/schema"),
            RejectionReason::OutOfScope
        );
        assert_eq!(
            reason(&outcome, "shipping/any"),
            RejectionReason::NotDelegated
        );
        assert!(outcome.composed.is_none());
    }

    #[test]
    fn the_older_policy_keeps_a_contested_role() {
        let duplicate = "roles:\n  - name: billing_api\n";
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                // Listed out of order: precedence follows creation time.
                attached("billing", "newer", "2026-01-03T00:00:00Z", duplicate),
                attached("billing", "app", "2026-01-02T00:00:00Z", BILLING),
            ],
        );
        assert_eq!(verdict(&outcome, "billing/app"), &Verdict::Accepted);
        assert_eq!(
            reason(&outcome, "billing/newer"),
            RejectionReason::Conflicted
        );
        assert_eq!(outcome.verdicts[0].0, "billing/app");
    }

    #[test]
    fn a_policy_invalid_on_its_own_is_not_reported_as_a_conflict() {
        let invalid =
            "roles:\n  - name: billing_x\nschemas:\n  - name: billing\n    profiles: [missing]\n";
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[attached(
                "billing",
                "broken",
                "2026-01-02T00:00:00Z",
                invalid,
            )],
        );
        assert_eq!(reason(&outcome, "billing/broken"), RejectionReason::Invalid);
    }

    #[test]
    fn a_role_pattern_may_not_mint_names_in_another_delegation() {
        let squat = r#"
role_pattern: "team_{profile}"
schemas:
  - name: billing
    profiles: [reader]
"#;
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[attached("billing", "squat", "2026-01-01T00:00:00Z", squat)],
        );
        assert_eq!(
            reason(&outcome, "billing/squat"),
            RejectionReason::OutOfScope
        );
    }

    #[test]
    fn a_policy_may_grant_membership_in_roles_its_bindings_generate() {
        let yaml = r#"
roles:
  - name: billing_migrator
schemas:
  - name: billing
    owner: billing_migrator
    profiles: [reader]
memberships:
  - role: billing_reader
    members: [{ name: team_payments }]
"#;
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                attached("billing", "app", "2026-01-02T00:00:00Z", yaml),
            ],
        );
        assert_eq!(verdict(&outcome, "billing/app"), &Verdict::Accepted);
    }

    #[test]
    fn a_rejected_edit_keeps_serving_the_last_accepted_content() {
        let squatter = "roles:\n  - name: billing_api\n    superuser: true\n";
        let broken = format!(
            "{BILLING}memberships:\n  - role: team_payments\n    members: [{{ name: billing_api }}]\n"
        );
        let mut billing = attached("billing", "app", "2026-01-02T00:00:00Z", &broken);
        billing.last_accepted = Some(parse_policy_fragment(BILLING).unwrap());
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                billing,
                attached("billing", "squatter", "2026-01-03T00:00:00Z", squatter),
            ],
        );
        assert!(matches!(
            verdict(&outcome, "billing/app"),
            Verdict::Retained {
                reason: RejectionReason::OutOfScope,
                ..
            }
        ));
        // The squatter does not inherit billing_api while billing's edit is broken.
        assert_eq!(
            reason(&outcome, "billing/squatter"),
            RejectionReason::Conflicted
        );
        let composed = outcome.composed.unwrap();
        assert!(
            composed
                .expanded
                .roles
                .iter()
                .any(|r| r.name == "billing_migrator")
        );
        assert!(
            composed
                .expanded
                .roles
                .iter()
                .all(|r| r.name != "billing_api" || r.superuser != Some(true))
        );
    }

    #[test]
    fn content_the_caller_rejects_is_retained_like_any_other_rejected_edit() {
        // A takeover through an edit the controller refuses before admission
        // (for example one that sets profiles) must not free the policy's
        // roles for a younger one.
        let squatter = "roles:\n  - name: billing_api\n    superuser: true\n";
        let mut billing = attached("billing", "app", "2026-01-02T00:00:00Z", BILLING);
        billing.last_accepted = Some(parse_policy_fragment(BILLING).unwrap());
        billing.invalid = Some("profiles are defined on the PostgresDatabase".into());
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                billing.clone(),
                attached("billing", "squatter", "2026-01-03T00:00:00Z", squatter),
            ],
        );
        assert!(matches!(
            verdict(&outcome, "billing/app"),
            Verdict::Retained {
                reason: RejectionReason::Invalid,
                ..
            }
        ));
        assert_eq!(
            reason(&outcome, "billing/squatter"),
            RejectionReason::Conflicted
        );

        // Without content to fall back to, the policy is rejected outright.
        billing.last_accepted = None;
        let outcome = compose_attached(&shared(), &delegations(), &[billing]);
        assert_eq!(reason(&outcome, "billing/app"), RejectionReason::Invalid);
    }

    #[test]
    fn external_declarations_are_references_that_claim_nothing() {
        // Two policies grant to a role neither creates; a third creates it.
        let reader = |schema: &str| {
            format!(
                "roles:\n  - name: app_runtime\n    external: true\n\
                 grants:\n  - role: app_runtime\n    privileges: [USAGE]\n\
                 \x20   object: {{ type: schema, name: {schema} }}\n"
            )
        };
        let mut delegations = delegations();
        delegations.push(Delegation {
            name: "shipping".into(),
            namespaces: vec!["shipping".into()],
            roles: vec!["shipping_*".into()],
            schemas: vec![DelegatedSchema {
                name: "shipping".into(),
                facets: vec![SchemaBindingFacet::Bindings],
            }],
        });
        let billing_reader = format!(
            "{}{}",
            reader("billing"),
            "schemas:\n  - name: billing\n    profiles: [reader]\n"
        );
        let policies = [
            attached("billing", "reader", "2026-01-02T00:00:00Z", &billing_reader),
            attached(
                "shipping",
                "reader",
                "2026-01-03T00:00:00Z",
                &reader("shipping"),
            ),
        ];
        let outcome = compose_attached(&shared(), &delegations, &policies);
        assert_eq!(verdict(&outcome, "billing/reader"), &Verdict::Accepted);
        assert_eq!(verdict(&outcome, "shipping/reader"), &Verdict::Accepted);
        assert_eq!(outcome.external_references, vec!["app_runtime".to_string()]);
        let composed = outcome.composed.unwrap();
        let runtime = composed
            .expanded
            .roles
            .iter()
            .find(|role| role.name == "app_runtime")
            .expect("a referenced role is declared so its grants are inspected");
        assert!(runtime.external);

        // Once a policy creates the role, that declaration stands alone: the
        // role is not also composed as external.
        let creator = attached(
            "platform",
            "roles",
            "2026-01-01T00:00:00Z",
            "roles:\n  - name: platform_runtime\n",
        );
        let referrer = attached(
            "billing",
            "reader",
            "2026-01-02T00:00:00Z",
            "roles:\n  - name: platform_runtime\n    external: true\n\
             grants:\n  - role: platform_runtime\n    privileges: [USAGE]\n\
             \x20   object: { type: schema, name: billing }\n",
        );
        let outcome = compose_attached(&shared(), &delegations, &[creator, referrer]);
        assert_eq!(verdict(&outcome, "billing/reader"), &Verdict::Accepted);
        assert!(outcome.external_references.is_empty());
        let composed = outcome.composed.unwrap();
        assert!(
            composed
                .expanded
                .roles
                .iter()
                .any(|role| role.name == "platform_runtime" && !role.external)
        );
    }

    #[test]
    fn the_outcome_names_the_delegations_that_admitted_each_policy() {
        let outcome = compose_attached(
            &shared(),
            &delegations(),
            &[
                attached("platform", "roles", "2026-01-01T00:00:00Z", PLATFORM),
                attached("billing", "app", "2026-01-02T00:00:00Z", BILLING),
            ],
        );
        assert_eq!(
            outcome.delegated_by["billing/app"],
            vec!["billing".to_string()]
        );
        assert_eq!(
            outcome.delegated_by["platform/roles"],
            vec!["platform".to_string()]
        );
    }
}
