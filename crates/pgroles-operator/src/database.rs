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
    AttachedPolicy, DelegatedSchema, Delegation, Verdict, compose_attached,
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
    /// Unique among this database's delegations. Attached policies' status
    /// names the delegations that admitted them.
    #[schemars(length(min = 1, max = 63))]
    pub name: String,
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
    /// UID of the attached `PostgresPolicy`. Retained content belongs to this
    /// object: a policy deleted and re-created under the same name starts
    /// afresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The delegations whose scope admitted the composed content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<String>,
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
    #[error("invalid PostgresDatabase: {0}")]
    InvalidSpec(String),
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

/// Everything one reconcile decides, before anything is written.
#[derive(Debug)]
pub struct DatabasePlan {
    /// Verdict per attached policy, keyed `namespace/name`.
    pub verdicts: BTreeMap<String, Verdict>,
    /// The database's record of every attached policy, in precedence order,
    /// including the content each one is served from.
    pub attached: Vec<AttachedPolicyStatus>,
    /// The composed manifest, when any policy is accepted.
    pub composed: Option<pgroles_core::manifest::PolicyManifest>,
}

/// Decide verdicts, retained content and the composed manifest for the
/// policies attached to `database`. Pure, so the decision can be tested
/// without an API server.
pub fn plan_database(
    database: &PostgresDatabase,
    attached: &[PostgresPolicy],
) -> Result<DatabasePlan, DatabaseError> {
    let mut names = std::collections::BTreeSet::new();
    for delegation in &database.spec.delegations {
        if !names.insert(delegation.name.as_str()) {
            return Err(DatabaseError::InvalidSpec(format!(
                "delegation name {} is used more than once",
                delegation.name
            )));
        }
    }

    let shared = shared_policy(&database.spec)?;
    let delegations: Vec<Delegation> = database
        .spec
        .delegations
        .iter()
        .map(|delegation| Delegation {
            name: delegation.name.clone(),
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

    let previous: BTreeMap<String, AttachedPolicyStatus> = database
        .status
        .iter()
        .flat_map(|status| status.attached.iter())
        .map(|entry| (format!("{}/{}", entry.namespace, entry.name), entry.clone()))
        .collect();
    // The record kept for this object, never one left by a deleted policy
    // that had the same name.
    let kept = |policy: &PostgresPolicy, key: &str| {
        previous
            .get(key)
            .filter(|entry| entry.uid.is_some() && entry.uid == policy.metadata.uid)
    };

    let mut current_content: BTreeMap<String, (Option<i64>, String)> = BTreeMap::new();
    let mut uids: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut candidates = Vec::new();
    for policy in attached {
        let key = policy_key(policy);
        let fragment = fragment_of(&policy.spec);
        current_content.insert(
            key.clone(),
            (
                policy.metadata.generation,
                serde_json::to_string(&fragment)?,
            ),
        );
        uids.insert(key.clone(), policy.metadata.uid.clone());
        // Execution settings and profiles belong to the database owner. Such
        // content is refused rather than silently dropped, and refused like
        // any other rejected edit, so the last accepted content still holds
        // the policy's claims.
        let invalid = (!policy.spec.profiles.is_empty()).then(|| {
            "profiles are defined on the PostgresDatabase, not on an attached policy".to_string()
        });
        let last_accepted = kept(policy, &key)
            .filter(|entry| entry.serving_generation != policy.metadata.generation)
            .and_then(|entry| entry.serving_content.as_deref())
            .map(serde_json::from_str::<PolicyFragment>)
            .transpose()?;
        candidates.push(AttachedPolicy {
            last_accepted,
            invalid,
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
    let mut attached_status = Vec::with_capacity(outcome.verdicts.len());
    let mut verdicts = BTreeMap::new();
    for (key, verdict) in outcome.verdicts {
        let Some((policy_namespace, policy_name)) = key.split_once('/') else {
            continue;
        };
        let base = AttachedPolicyStatus {
            namespace: policy_namespace.to_string(),
            name: policy_name.to_string(),
            uid: uids.get(&key).cloned().flatten(),
            delegations: outcome.delegated_by.get(&key).cloned().unwrap_or_default(),
            accepted: false,
            reason: None,
            message: None,
            serving_generation: None,
            serving_content: None,
        };
        let entry = match &verdict {
            Verdict::Accepted => {
                let (generation, content) = current_content.get(&key).cloned().unzip();
                AttachedPolicyStatus {
                    accepted: true,
                    serving_generation: generation.flatten(),
                    serving_content: content,
                    ..base
                }
            }
            Verdict::Retained { reason, message } => {
                // Retention only ever uses this object's own record.
                let previous = previous
                    .get(&key)
                    .filter(|entry| entry.uid.is_some() && Some(&entry.uid) == uids.get(&key));
                AttachedPolicyStatus {
                    reason: Some(reason.as_str().to_string()),
                    message: Some(message.clone()),
                    serving_generation: previous.and_then(|entry| entry.serving_generation),
                    serving_content: previous.and_then(|entry| entry.serving_content.clone()),
                    ..base
                }
            }
            Verdict::Rejected { reason, message } => AttachedPolicyStatus {
                reason: Some(reason.as_str().to_string()),
                message: Some(message.clone()),
                delegations: Vec::new(),
                ..base
            },
        };
        attached_status.push(entry);
        verdicts.insert(key, verdict);
    }

    let composed = match outcome.composed {
        Some(composed) => {
            let mut manifest = composed.manifest.clone();
            if let Some(executor) = &database.spec.executor_role {
                declare_executor_memberships(&mut manifest, &composed.expanded, executor)?;
            }
            Some(manifest)
        }
        None => None,
    };
    Ok(DatabasePlan {
        verdicts,
        attached: attached_status,
        composed,
    })
}

fn policy_key(policy: &PostgresPolicy) -> String {
    format!(
        "{}/{}",
        policy.namespace().unwrap_or_default(),
        policy.name_any()
    )
}

pub async fn reconcile_database(
    database: Arc<PostgresDatabase>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, DatabaseError> {
    let namespace = database.namespace().ok_or(DatabaseError::NoNamespace)?;
    let name = database.name_any();
    let client = ctx.kube_client.clone();
    let databases: Api<PostgresDatabase> = Api::namespaced(client.clone(), &namespace);

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

    let plan = match plan_database(&database, &attached) {
        Ok(plan) => plan,
        Err(DatabaseError::InvalidSpec(message)) => {
            // Leave the composed policy as it is: an owner's typo must not
            // withdraw what every team already has.
            let mut status = database.status.clone().unwrap_or_default();
            status.conditions = with_ready(
                &status.conditions,
                condition("Ready", false, "InvalidSpec", &message),
            );
            write_database_status(&databases, &database, &status).await?;
            return Ok(Action::requeue(Duration::from_secs(60)));
        }
        Err(error) => return Err(error),
    };

    let composed_name = format!("{name}-composed");
    let accepted = plan
        .attached
        .iter()
        .filter(|entry| entry.serving_generation.is_some())
        .count() as i64;
    let mut status = database.status.clone().unwrap_or_default();
    status.rejected_policies = plan.attached.len() as i64 - accepted;
    status.accepted_policies = accepted;
    status.attached = plan.attached.clone();
    status.composed_policy = plan.composed.as_ref().map(|_| composed_name.clone());

    // Record what each policy is served from before composing it. If the
    // composed policy were patched first and this write then failed, the next
    // rejected edit would find no last accepted content, and a younger policy
    // could take the roles the edit was supposed to keep.
    write_database_status(&databases, &database, &status).await?;

    let policies_in_db_ns: Api<PostgresPolicy> = Api::namespaced(client.clone(), &namespace);
    if let Some(manifest) = &plan.composed {
        let body = composed_policy_body(&database, &composed_name, manifest)?;
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
        let Some(verdict) = plan.verdicts.get(&policy_key(policy)) else {
            continue;
        };
        let mut policy_status = policy.status.clone().unwrap_or_default();
        policy_status.set_condition(accepted_condition(verdict, &namespace, &name));
        match (verdict, &composed_ready) {
            (Verdict::Accepted, Some(ready)) => {
                // This reconcile composed the policy's current content and the
                // composed policy has reconciled that composition, so the
                // outcome describes this generation of the attached policy.
                if ready.status == "True" {
                    policy_status.observed_generation = policy.metadata.generation;
                }
                policy_status.set_condition(ready.clone())
            }
            (Verdict::Accepted | Verdict::Retained { .. }, None) => {
                policy_status.set_condition(condition(
                    "Ready",
                    false,
                    "Composing",
                    "waiting for the composed policy to reconcile",
                ))
            }
            // The previous content still converges; report how it is doing
            // without claiming the current generation.
            (Verdict::Retained { .. }, Some(ready)) => policy_status.set_condition(ready.clone()),
            (Verdict::Rejected { reason, message }, _) => {
                policy_status.set_condition(condition("Ready", false, reason.as_str(), message))
            }
        }
        patch_policy_status(&client, policy, &policy_status).await?;
    }

    status.conditions = with_ready(
        &status.conditions,
        match &composed_ready {
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
        },
    );
    write_database_status(&databases, &database, &status).await?;

    // The composed policy's readiness is mirrored on a timer rather than by
    // watching its status, which every reconcile of it rewrites.
    Ok(Action::requeue(Duration::from_secs(15)))
}

fn with_ready(conditions: &[PolicyCondition], ready: PolicyCondition) -> Vec<PolicyCondition> {
    let mut wrapper = PostgresPolicyStatus {
        conditions: conditions.to_vec(),
        ..Default::default()
    };
    wrapper.set_condition(ready);
    wrapper.conditions
}

async fn write_database_status(
    databases: &Api<PostgresDatabase>,
    database: &PostgresDatabase,
    status: &PostgresDatabaseStatus,
) -> Result<(), DatabaseError> {
    if database
        .status
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        == Some(serde_json::to_value(status)?)
    {
        return Ok(());
    }
    databases
        .patch_status(
            &database.name_any(),
            &PatchParams::default(),
            &Patch::Merge(json!({ "status": status })),
        )
        .await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn database(status: Option<PostgresDatabaseStatus>) -> PostgresDatabase {
        let mut database: PostgresDatabase = serde_json::from_value(json!({
            "apiVersion": "pgroles.io/v1alpha1",
            "kind": "PostgresDatabase",
            "metadata": {"name": "appdb", "namespace": "platform", "uid": "db-uid"},
            "spec": {
                "connection": {"secretRef": {"name": "appdb-owner"}},
                "delegations": [
                    {"name": "platform", "namespaces": ["platform"], "roles": ["team_*"]},
                    {
                        "name": "billing",
                        "namespaces": ["billing"],
                        "roles": ["billing_*"],
                        "schemas": [{"name": "billing", "facets": ["owner", "bindings"]}],
                    },
                ],
            },
        }))
        .expect("test database deserializes");
        database.status = status;
        database
    }

    fn policy(
        namespace: &str,
        name: &str,
        uid: &str,
        generation: i64,
        created: &str,
        spec: serde_json::Value,
    ) -> PostgresPolicy {
        let mut spec = spec;
        spec["databaseRef"] = json!({"name": "appdb", "namespace": "platform"});
        serde_json::from_value(json!({
            "apiVersion": "pgroles.io/v1alpha1",
            "kind": "PostgresPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "uid": uid,
                "generation": generation,
                "creationTimestamp": created,
            },
            "spec": spec,
        }))
        .expect("test policy deserializes")
    }

    fn billing_roles() -> serde_json::Value {
        json!({"roles": [{"name": "billing_api", "login": true}]})
    }

    fn squatter() -> PostgresPolicy {
        policy(
            "billing",
            "squatter",
            "squatter-uid",
            1,
            "2026-01-03T00:00:00Z",
            json!({"roles": [{"name": "billing_api", "superuser": true}]}),
        )
    }

    /// Plan once with billing at generation 1, and return the database as it
    /// would be after the status write.
    fn after_first_plan() -> PostgresDatabase {
        let billing = policy(
            "billing",
            "app",
            "billing-uid",
            1,
            "2026-01-02T00:00:00Z",
            billing_roles(),
        );
        let plan = plan_database(&database(None), &[billing]).unwrap();
        assert!(plan.attached[0].accepted);
        database(Some(PostgresDatabaseStatus {
            attached: plan.attached,
            ..Default::default()
        }))
    }

    fn verdict_of<'a>(plan: &'a DatabasePlan, key: &str) -> &'a Verdict {
        plan.verdicts
            .get(key)
            .unwrap_or_else(|| panic!("no verdict for {key}"))
    }

    #[test]
    fn an_edit_setting_profiles_keeps_the_last_accepted_content() {
        let database = after_first_plan();
        let mut edited = billing_roles();
        edited["profiles"] = json!({"reader": {"grants": []}});
        let billing = policy(
            "billing",
            "app",
            "billing-uid",
            2,
            "2026-01-02T00:00:00Z",
            edited,
        );
        let plan = plan_database(&database, &[billing, squatter()]).unwrap();
        assert!(matches!(
            verdict_of(&plan, "billing/app"),
            Verdict::Retained { .. }
        ));
        assert!(matches!(
            verdict_of(&plan, "billing/squatter"),
            Verdict::Rejected { .. }
        ));
        let manifest = plan.composed.unwrap();
        assert!(
            manifest
                .roles
                .iter()
                .all(|role| role.name != "billing_api" || role.superuser != Some(true))
        );
        let entry = &plan.attached[0];
        assert_eq!(entry.serving_generation, Some(1));
        assert_eq!(entry.delegations, vec!["billing".to_string()]);
    }

    #[test]
    fn a_recreated_policy_does_not_inherit_its_predecessors_content() {
        let database = after_first_plan();
        // Deleted and re-created under the same name with a broken edit: the
        // retained content belonged to the old object, so nothing holds
        // billing_api and the squatter, next in line, takes it.
        let mut broken = billing_roles();
        broken["memberships"] =
            json!([{"role": "team_payments", "members": [{"name": "billing_api"}]}]);
        let recreated = policy(
            "billing",
            "app",
            "new-uid",
            2,
            "2026-01-04T00:00:00Z",
            broken,
        );
        let plan = plan_database(&database, &[recreated, squatter()]).unwrap();
        assert!(matches!(
            verdict_of(&plan, "billing/app"),
            Verdict::Rejected { .. }
        ));
        assert_eq!(verdict_of(&plan, "billing/squatter"), &Verdict::Accepted);

        // The same broken edit on the original object keeps its content.
        let mut broken = billing_roles();
        broken["memberships"] =
            json!([{"role": "team_payments", "members": [{"name": "billing_api"}]}]);
        let edited = policy(
            "billing",
            "app",
            "billing-uid",
            2,
            "2026-01-02T00:00:00Z",
            broken,
        );
        let plan = plan_database(&database, &[edited, squatter()]).unwrap();
        assert!(matches!(
            verdict_of(&plan, "billing/app"),
            Verdict::Retained { .. }
        ));
    }

    #[test]
    fn duplicate_delegation_names_are_refused_before_anything_is_composed() {
        let mut database = database(None);
        database.spec.delegations[1].name = "platform".into();
        let billing = policy(
            "billing",
            "app",
            "billing-uid",
            1,
            "2026-01-02T00:00:00Z",
            billing_roles(),
        );
        assert!(matches!(
            plan_database(&database, &[billing]),
            Err(DatabaseError::InvalidSpec(_))
        ));
    }

    #[test]
    fn roles_attached_policies_only_reference_are_composed_as_external() {
        let reader = |namespace: &str, uid: &str, created: &str| {
            policy(
                namespace,
                "reader",
                uid,
                1,
                created,
                json!({
                    "roles": [{"name": "app_runtime", "external": true}],
                    "grants": [{
                        "role": "app_runtime",
                        "privileges": ["USAGE"],
                        "object": {"type": "schema", "name": "billing"},
                    }],
                }),
            )
        };
        let plan = plan_database(
            &database(None),
            &[reader("billing", "b-uid", "2026-01-02T00:00:00Z")],
        )
        .unwrap();
        assert_eq!(verdict_of(&plan, "billing/reader"), &Verdict::Accepted);
        let manifest = plan.composed.unwrap();
        assert!(
            manifest
                .roles
                .iter()
                .any(|role| role.name == "app_runtime" && role.external)
        );
    }
}
