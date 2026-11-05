//! `PostgresDatabase`: one shared database, the policies attached to it, and
//! the delegations that bound what each attached policy may manage.
//!
//! The database owner (usually a platform team) holds the connection and the
//! executor credential. Application teams write `PostgresPolicy` resources
//! with `databaseRef` instead of `connection`, so they never hold a credential
//! that could bypass the operator. This controller composes every attached
//! policy its delegations permit — oldest first, rejecting a later policy that
//! collides with an earlier one — into a single operator-owned
//! `PostgresPolicy`, which the ordinary policy reconciler then plans and
//! applies. One database therefore has one plan, one inspect/diff/apply cycle,
//! and one place where conflicts between teams are decided.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{CustomResource, KubeSchema, Resource, ResourceExt};
use pgroles_core::attachment::{
    AttachedPolicy, DelegatedSchema, Delegation, RejectionReason, Verdict, compose_attached,
};
use pgroles_core::composition::{PolicyFragment, SharedPolicy};
use pgroles_core::manifest::SchemaBindingFacet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::context::OperatorContext;
use crate::crd::{
    ApprovalMode, ConnectionSpec, CrdReconciliationMode, PolicyCondition, PolicyMode,
    PostgresPolicy, PostgresPolicySpec, PostgresPolicyStatus, ProfileSpec,
};

/// Label on the operator-owned policy that carries a database's composition.
pub const COMPOSED_FOR_LABEL: &str = "pgroles.io/composed-for";
const FIELD_MANAGER: &str = "pgroles-database-controller";
const CONDITION_ACCEPTED: &str = "Accepted";

/// Spec for a `PostgresDatabase` custom resource.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresDatabase",
    namespaced,
    status = "PostgresDatabaseStatus",
    shortname = "pgdb",
    category = "pgroles",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Accepted","type":"integer","jsonPath":".status.acceptedPolicies"}"#,
    printcolumn = r#"{"name":"Rejected","type":"integer","jsonPath":".status.rejectedPolicies"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct PostgresDatabaseSpec {
    /// How the operator reaches the database. Only the database owner holds
    /// this credential.
    pub connection: ConnectionSpec,

    /// Reconciliation interval for the composed policy.
    #[serde(default = "default_interval")]
    pub interval: String,

    /// `apply` executes the composed plan; `observe` only reports drift.
    #[serde(default)]
    pub mode: PolicyMode,

    /// Whether composed plans need a recorded approval before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalMode>,

    /// Convergence strategy for the composed policy.
    #[serde(default)]
    pub reconciliation_mode: CrdReconciliationMode,

    /// Profiles every attached policy may bind.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileSpec>,

    /// Default role naming pattern for schema bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_pattern: Option<String>,

    /// What each namespace may manage on this database. A policy from a
    /// namespace no delegation names is rejected.
    #[serde(default)]
    pub delegations: Vec<DelegationSpec>,

    /// The role the connection authenticates as. When set, the composed
    /// policy declares its inherited membership in every role that owns a
    /// schema or default privileges. Teams then need not know the executor,
    /// and convergence does not revoke the membership `createrole_self_grant`
    /// gave it, which the executor needs to grant on those roles' objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_role: Option<String>,
}

fn default_interval() -> String {
    "5m".to_string()
}

/// Authority the database owner grants to a set of namespaces.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DelegationSpec {
    /// Namespaces this delegation applies to; `*` matches every namespace.
    pub namespaces: Vec<String>,
    /// Roles those namespaces may define or retire. A trailing `*` matches by
    /// prefix.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Schema facets those namespaces may manage.
    #[serde(default)]
    pub schemas: Vec<DelegatedSchemaSpec>,
}

/// A schema and the facets of it a delegation covers.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DelegatedSchemaSpec {
    /// Schema name.
    pub name: String,
    /// `owner` (create the schema and set its owner) and/or `bindings`
    /// (profiles, grants and default privileges on it).
    pub facets: Vec<SchemaBindingFacet>,
}

/// Observed state of a `PostgresDatabase`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PostgresDatabaseStatus {
    /// Standard Kubernetes conditions; `Ready` mirrors the composed policy.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
    /// Every policy attached to this database, in precedence order.
    #[serde(default)]
    pub attached: Vec<AttachedPolicyStatus>,
    /// Attached policies whose content is composed.
    #[serde(default)]
    pub accepted_policies: i64,
    /// Attached policies with no content composed.
    #[serde(default)]
    pub rejected_policies: i64,
    /// The operator-owned `PostgresPolicy` carrying the composition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composed_policy: Option<String>,
}

/// The outcome for one attached policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AttachedPolicyStatus {
    /// Namespace of the attached `PostgresPolicy`.
    pub namespace: String,
    /// Name of the attached `PostgresPolicy`.
    pub name: String,
    /// Whether the policy's current generation is composed.
    pub accepted: bool,
    /// Why the current generation was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Details of the rejection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The generation whose content is composed: the current one when
    /// accepted, an earlier one while a newer edit is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_generation: Option<i64>,
    /// The content of `servingGeneration`, kept so a rejected edit can fall
    /// back to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_content: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("resource has no namespace")]
    NoNamespace,
}

/// Whether `policy` attaches to the database `namespace/name`.
pub fn attaches_to(policy: &PostgresPolicy, namespace: &str, name: &str) -> bool {
    let Some(reference) = &policy.spec.database_ref else {
        return false;
    };
    let policy_namespace = policy.namespace().unwrap_or_default();
    reference.name == name
        && reference.namespace.as_deref().unwrap_or(&policy_namespace) == namespace
}

pub async fn reconcile_database(
    database: Arc<PostgresDatabase>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, DatabaseError> {
    let namespace = database.namespace().ok_or(DatabaseError::NoNamespace)?;
    let name = database.name_any();
    let client = ctx.kube_client.clone();

    let all_policies: Api<PostgresPolicy> = match &ctx.watch_namespace {
        Some(watched) => Api::namespaced(client.clone(), watched),
        None => Api::all(client.clone()),
    };
    let attached: Vec<PostgresPolicy> = all_policies
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|policy| {
            policy.metadata.deletion_timestamp.is_none() && attaches_to(policy, &namespace, &name)
        })
        .collect();

    let shared = shared_policy(&database.spec)?;
    let delegations: Vec<Delegation> = database
        .spec
        .delegations
        .iter()
        .map(|delegation| Delegation {
            namespaces: delegation.namespaces.clone(),
            roles: delegation.roles.clone(),
            schemas: delegation
                .schemas
                .iter()
                .map(|schema| DelegatedSchema {
                    name: schema.name.clone(),
                    facets: schema.facets.clone(),
                })
                .collect(),
        })
        .collect();

    // Execution settings belong to the database owner. Content that only the
    // owner may set is refused up front rather than silently dropped.
    let previous: BTreeMap<String, AttachedPolicyStatus> = database
        .status
        .iter()
        .flat_map(|status| status.attached.iter())
        .map(|entry| (format!("{}/{}", entry.namespace, entry.name), entry.clone()))
        .collect();
    let mut current_content: BTreeMap<String, (Option<i64>, String)> = BTreeMap::new();
    let mut verdicts: BTreeMap<String, Verdict> = BTreeMap::new();
    let mut candidates = Vec::new();
    for policy in &attached {
        let key = format!(
            "{}/{}",
            policy.namespace().unwrap_or_default(),
            policy.name_any()
        );
        if !policy.spec.profiles.is_empty() {
            verdicts.insert(
                key,
                Verdict::Rejected {
                    reason: RejectionReason::Invalid,
                    message: "profiles are defined on the PostgresDatabase, not on an attached \
                              policy"
                        .to_string(),
                },
            );
            continue;
        }
        let fragment = fragment_of(&policy.spec);
        current_content.insert(
            key.clone(),
            (
                policy.metadata.generation,
                serde_json::to_string(&fragment)?,
            ),
        );
        let last_accepted = previous
            .get(&key)
            .filter(|entry| entry.serving_generation != policy.metadata.generation)
            .and_then(|entry| entry.serving_content.as_deref())
            .map(serde_json::from_str::<PolicyFragment>)
            .transpose()?;
        candidates.push(AttachedPolicy {
            last_accepted,
            namespace: policy.namespace().unwrap_or_default(),
            name: policy.name_any(),
            created_at: serde_json::to_value(&policy.metadata.creation_timestamp)?
                .as_str()
                .unwrap_or_default()
                .to_string(),
            fragment,
        });
    }

    let outcome = compose_attached(&shared, &delegations, &candidates);
    let mut order: Vec<String> = outcome
        .verdicts
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    for (key, verdict) in outcome.verdicts {
        verdicts.insert(key, verdict);
    }
    // Pre-rejected policies have no precedence position; list them last.
    for key in verdicts.keys() {
        if !order.contains(key) {
            order.push(key.clone());
        }
    }

    let composed_name = format!("{name}-composed");
    let policies_in_db_ns: Api<PostgresPolicy> = Api::namespaced(client.clone(), &namespace);
    if let Some(composed) = &outcome.composed {
        let mut manifest = composed.manifest.clone();
        if let Some(executor) = &database.spec.executor_role {
            declare_executor_memberships(&mut manifest, &composed.expanded, executor)?;
        }
        let body = composed_policy_body(&database, &composed_name, &manifest)?;
        policies_in_db_ns
            .patch(
                &composed_name,
                &PatchParams::apply(FIELD_MANAGER).force(),
                &Patch::Apply(&body),
            )
            .await?;
    }
    let composed_ready = policies_in_db_ns
        .get_opt(&composed_name)
        .await?
        .and_then(|policy| current_readiness(&policy));

    // Each attached policy learns its own verdict, and — once accepted — how
    // the shared plan it is part of is doing.
    for policy in &attached {
        let key = format!(
            "{}/{}",
            policy.namespace().unwrap_or_default(),
            policy.name_any()
        );
        let Some(verdict) = verdicts.get(&key) else {
            continue;
        };
        let mut status = policy.status.clone().unwrap_or_default();
        status.set_condition(accepted_condition(verdict, &namespace, &name));
        match (verdict, &composed_ready) {
            (Verdict::Accepted, Some(ready)) => {
                // This reconcile composed the policy's current content and the
                // composed policy has reconciled that composition, so the
                // outcome describes this generation of the attached policy.
                if ready.status == "True" {
                    status.observed_generation = policy.metadata.generation;
                }
                status.set_condition(ready.clone())
            }
            (Verdict::Accepted, None) => status.set_condition(condition(
                "Ready",
                false,
                "Composing",
                "waiting for the composed policy to reconcile",
            )),
            // The previous content still converges; report how it is doing
            // without claiming the current generation.
            (Verdict::Retained { .. }, Some(ready)) => status.set_condition(ready.clone()),
            (Verdict::Retained { .. }, None) => status.set_condition(condition(
                "Ready",
                false,
                "Composing",
                "waiting for the composed policy to reconcile",
            )),
            (Verdict::Rejected { reason, message }, _) => {
                status.set_condition(condition("Ready", false, reason.as_str(), message))
            }
        }
        patch_policy_status(&client, policy, &status).await?;
    }

    let attached_status: Vec<AttachedPolicyStatus> = order
        .iter()
        .filter_map(|key| {
            let verdict = verdicts.get(key)?;
            let (policy_namespace, policy_name) = key.split_once('/')?;
            let entry = |accepted, reason: Option<&RejectionReason>, message: Option<&String>| {
                AttachedPolicyStatus {
                    namespace: policy_namespace.to_string(),
                    name: policy_name.to_string(),
                    accepted,
                    reason: reason.map(|reason| reason.as_str().to_string()),
                    message: message.cloned(),
                    serving_generation: None,
                    serving_content: None,
                }
            };
            Some(match verdict {
                Verdict::Accepted => {
                    let (generation, content) = current_content.get(key).cloned()?;
                    AttachedPolicyStatus {
                        serving_generation: generation,
                        serving_content: Some(content),
                        ..entry(true, None, None)
                    }
                }
                Verdict::Retained { reason, message } => {
                    let kept = previous.get(key)?;
                    AttachedPolicyStatus {
                        serving_generation: kept.serving_generation,
                        serving_content: kept.serving_content.clone(),
                        ..entry(false, Some(reason), Some(message))
                    }
                }
                Verdict::Rejected { reason, message } => entry(false, Some(reason), Some(message)),
            })
        })
        .collect();
    let accepted = attached_status
        .iter()
        .filter(|a| a.serving_generation.is_some())
        .count() as i64;
    let mut status = database.status.clone().unwrap_or_default();
    status.rejected_policies = attached_status.len() as i64 - accepted;
    status.accepted_policies = accepted;
    status.attached = attached_status;
    status.composed_policy = outcome.composed.as_ref().map(|_| composed_name.clone());
    let mut wrapper = PostgresPolicyStatus {
        conditions: status.conditions.clone(),
        ..Default::default()
    };
    wrapper.set_condition(match &composed_ready {
        Some(ready) => ready.clone(),
        None if accepted == 0 => condition(
            "Ready",
            false,
            "NoAcceptedPolicies",
            "no attached policy is accepted",
        ),
        None => condition(
            "Ready",
            false,
            "Composing",
            "waiting for the composed policy to reconcile",
        ),
    });
    status.conditions = wrapper.conditions;

    let databases: Api<PostgresDatabase> = Api::namespaced(client, &namespace);
    if database
        .status
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        != Some(serde_json::to_value(&status)?)
    {
        databases
            .patch_status(
                &name,
                &PatchParams::default(),
                &Patch::Merge(json!({ "status": status })),
            )
            .await?;
    }

    // The composed policy's readiness is mirrored on a timer rather than by
    // watching its status, which every reconcile of it rewrites.
    Ok(Action::requeue(Duration::from_secs(15)))
}

pub fn database_error_policy(
    _database: Arc<PostgresDatabase>,
    error: &DatabaseError,
    _ctx: Arc<OperatorContext>,
) -> Action {
    tracing::warn!(%error, "postgres database reconcile failed");
    Action::requeue(Duration::from_secs(10))
}

/// The composed policy's `Ready` condition, but only once it describes the
/// current composition. Until the policy reconciler has attempted the latest
/// generation, the condition belongs to an older set of attached policies and
/// would report a newly attached policy ready before its content was applied.
fn current_readiness(policy: &PostgresPolicy) -> Option<PolicyCondition> {
    let generation = policy.metadata.generation?;
    let status = policy.status.as_ref()?;
    let ready = status
        .conditions
        .iter()
        .find(|condition| condition.condition_type == "Ready")?;
    let current = if ready.status == "True" {
        status.observed_generation == Some(generation)
    } else {
        status.last_attempted_generation == Some(generation)
    };
    current.then(|| ready.clone())
}

fn shared_policy(spec: &PostgresDatabaseSpec) -> Result<SharedPolicy, serde_json::Error> {
    // Profiles convert through the same path a policy's own profiles take.
    let carrier: PostgresPolicySpec = serde_json::from_value(json!({
        "profiles": spec.profiles,
        "role_pattern": spec.role_pattern,
    }))?;
    let manifest = carrier.to_policy_manifest();
    Ok(SharedPolicy {
        role_pattern: manifest.role_pattern,
        default_owner: None,
        auth_providers: Vec::new(),
        profiles: manifest.profiles,
    })
}

/// Declare the executor's inherited membership in every owner role the
/// composed policy relies on, unless an attached policy already declares it.
fn declare_executor_memberships(
    manifest: &mut pgroles_core::manifest::PolicyManifest,
    expanded: &pgroles_core::manifest::ExpandedManifest,
    executor: &str,
) -> Result<(), serde_json::Error> {
    let owners: std::collections::BTreeSet<&str> = expanded
        .schemas
        .iter()
        .filter_map(|schema| schema.owner.as_deref())
        .chain(
            expanded
                .default_privileges
                .iter()
                .filter_map(|dp| dp.owner.as_deref()),
        )
        .filter(|owner| *owner != executor)
        .collect();
    for owner in owners {
        let declared = manifest.memberships.iter().any(|membership| {
            membership.role == owner
                && membership
                    .members
                    .iter()
                    .any(|member| member.name == executor)
        });
        if !declared {
            manifest.memberships.push(serde_json::from_value(json!({
                "role": owner,
                "members": [{ "name": executor, "inherit": true }],
            }))?);
        }
    }
    Ok(())
}

fn fragment_of(spec: &PostgresPolicySpec) -> PolicyFragment {
    let manifest = spec.to_policy_manifest();
    PolicyFragment {
        role_pattern: manifest.role_pattern,
        schemas: manifest.schemas,
        roles: manifest.roles,
        grants: manifest.grants,
        default_privileges: manifest.default_privileges,
        memberships: manifest.memberships,
        retirements: manifest.retirements,
        ..Default::default()
    }
}

fn composed_policy_body(
    database: &PostgresDatabase,
    composed_name: &str,
    manifest: &pgroles_core::manifest::PolicyManifest,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut spec = serde_json::to_value(manifest)?;
    let object = spec
        .as_object_mut()
        .expect("a manifest serializes to an object");
    object.remove("auth_providers");
    object.insert(
        "connection".into(),
        serde_json::to_value(&database.spec.connection)?,
    );
    object.insert("interval".into(), json!(database.spec.interval));
    object.insert("mode".into(), serde_json::to_value(database.spec.mode)?);
    object.insert(
        "reconciliation_mode".into(),
        serde_json::to_value(database.spec.reconciliation_mode)?,
    );
    if let Some(approval) = &database.spec.approval {
        object.insert("approval".into(), serde_json::to_value(approval)?);
    }
    let owner = database
        .controller_owner_ref(&())
        .expect("a stored PostgresDatabase has a name and uid");
    Ok(json!({
        "apiVersion": "pgroles.io/v1alpha1",
        "kind": "PostgresPolicy",
        "metadata": {
            "name": composed_name,
            "labels": { COMPOSED_FOR_LABEL: database.name_any() },
            "ownerReferences": [owner],
        },
        "spec": spec,
    }))
}

fn accepted_condition(verdict: &Verdict, namespace: &str, name: &str) -> PolicyCondition {
    match verdict {
        Verdict::Accepted => condition(
            CONDITION_ACCEPTED,
            true,
            "Accepted",
            &format!("composed into PostgresDatabase {namespace}/{name}"),
        ),
        Verdict::Retained { reason, message } => condition(
            CONDITION_ACCEPTED,
            false,
            reason.as_str(),
            &format!("{message}; the last accepted generation is still applied"),
        ),
        Verdict::Rejected { reason, message } => {
            condition(CONDITION_ACCEPTED, false, reason.as_str(), message)
        }
    }
}

fn condition(kind: &str, ok: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: kind.to_string(),
        status: if ok { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(crate::crd::now_rfc3339()),
    }
}

async fn patch_policy_status(
    client: &kube::Client,
    policy: &PostgresPolicy,
    status: &PostgresPolicyStatus,
) -> Result<(), DatabaseError> {
    let unchanged = policy
        .status
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        == Some(serde_json::to_value(status)?);
    if unchanged {
        return Ok(());
    }
    let api: Api<PostgresPolicy> =
        Api::namespaced(client.clone(), &policy.namespace().unwrap_or_default());
    api.patch_status(
        &policy.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": status })),
    )
    .await?;
    Ok(())
}
