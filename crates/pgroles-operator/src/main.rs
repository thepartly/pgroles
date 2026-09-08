//! pgroles-operator — Kubernetes controller for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use futures::{FutureExt, StreamExt, TryStreamExt, stream};
use k8s_openapi::api::core::v1::Secret;
use kube::runtime::controller::Config as ControllerConfig;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::reflector::{ObjectRef, Store};
use kube::runtime::{Controller, WatchStreamExt, predicates, reflector, watcher};
use kube::{Api, Client, Resource, ResourceExt};
use pgroles_operator::controller_health::{
    ControllerHealth, ControllerKind, WatchKind, shutdown_signal, supervise,
};
use tracing::{info, warn};
use tracing_subscriber::prelude::*;

use pgroles_operator::concurrency::ReconcileConcurrency;
use pgroles_operator::context::OperatorContext;
use pgroles_operator::crd::{
    EphemeralAccessPolicy, EphemeralAccessRequest, PostgresPolicy, PostgresPolicyCandidate,
    PostgresPolicyPlan, REQUESTED_RECONCILE_ANNOTATION,
};
use pgroles_operator::ephemeral::{
    access_policy_error_policy, access_request_error_policy, reconcile_access_policy,
    reconcile_access_request,
};
use pgroles_operator::observability::{
    OperatorObservability, init_log_provider_from_env, serve_health,
};
use pgroles_operator::plan::PlanRetention;
use pgroles_operator::reconciler::{error_policy, reconcile};
use pgroles_operator::request_index::RequestIndex;

/// Build a controller with the operator-wide concurrency bound already applied.
///
/// Keeping construction behind this helper makes the safe path the natural path:
/// callers cannot receive a controller that still has kube-rs's unbounded default.
fn configured_controller<K>(
    trigger: impl futures::Stream<Item = Result<K, watcher::Error>> + Send + 'static,
    reader: Store<K>,
    concurrency: ReconcileConcurrency,
) -> Controller<K>
where
    K: Clone + Resource + serde::de::DeserializeOwned + std::fmt::Debug + Send + Sync + 'static,
    K::DynamicType: Default + Eq + Hash + Clone,
{
    Controller::for_stream(trigger, reader)
        .with_config(ControllerConfig::default().concurrency(concurrency.get()))
}

/// Hash for plan decision changes — triggers parent policy reconciliation when
/// a reviewer records a decision, or the operator moves the plan's phase.
///
/// Decisions live in the status subresource, so this hashes the terminal
/// decision conditions rather than annotations.
fn plan_decision_hash(plan: &PostgresPolicyPlan) -> Option<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if let Some(status) = &plan.status {
        for condition in &status.conditions {
            if condition.condition_type == "Approved" || condition.condition_type == "Denied" {
                condition.condition_type.hash(&mut hasher);
                condition.status.hash(&mut hasher);
            }
        }
        format!("{}", status.phase).hash(&mut hasher);
    }
    Some(hasher.finish())
}

/// Hash identifying a candidate's *spec* state.
///
/// Deliberately not the resource version: the operator writes candidate status
/// on every reconcile, and waking the parent on our own status write would
/// spin. A candidate spec is immutable, so in practice this fires on creation
/// and deletion — which is exactly when the parent has new work.
fn candidate_trigger_hash(candidate: &PostgresPolicyCandidate) -> Option<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    candidate.meta().uid.hash(&mut hasher);
    candidate.meta().generation.hash(&mut hasher);
    candidate
        .meta()
        .deletion_timestamp
        .as_ref()
        .map(|timestamp| timestamp.0.to_string())
        .hash(&mut hasher);
    Some(hasher.finish())
}

fn policy_trigger_hash(policy: &PostgresPolicy) -> Option<u64> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    policy.meta().generation.hash(&mut hasher);
    policy
        .meta()
        .deletion_timestamp
        .as_ref()
        .map(|timestamp| timestamp.0.to_string())
        .hash(&mut hasher);
    policy.meta().finalizers.hash(&mut hasher);
    policy
        .meta()
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(REQUESTED_RECONCILE_ANNOTATION))
        .hash(&mut hasher);
    Some(hasher.finish())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured stdout logs and, when configured, export the same
    // events through OTLP. Lifecycle audit events therefore survive outside
    // the cluster without making Kubernetes objects the system of record.
    let logger_provider = init_log_provider_from_env()?;
    let otel_log_layer = logger_provider
        .as_ref()
        .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer().json().with_target(false))
        .with(otel_log_layer)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting pgroles-operator"
    );

    // Build kube client from in-cluster config or KUBECONFIG.
    let client = Client::try_default().await?;

    let observability = OperatorObservability::from_env()?.with_logger_provider(logger_provider);
    let http_addr = std::env::var("OPERATOR_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    let observability_server = observability.clone();
    tokio::spawn(async move {
        if let Err(error) = serve_health(http_addr, observability_server).await {
            tracing::error!(%error, %http_addr, "health server exited");
        }
    });

    let health = ControllerHealth::new(observability.clone());
    let signal = shutdown_signal()?;
    let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel::<()>();
    let shutdown = shutdown_rx.map(|_| ()).shared();

    let event_recorder = Recorder::new(
        client.clone(),
        Reporter {
            controller: "pgroles-operator".to_string(),
            instance: std::env::var("CONTROLLER_POD_NAME").ok(),
        },
    );

    let watch_namespace = std::env::var("WATCH_NAMESPACE")
        .ok()
        .filter(|namespace| !namespace.trim().is_empty());
    if let Some(namespace) = &watch_namespace {
        info!(%namespace, "scoping operator watches to one namespace");
    }
    let request_index = RequestIndex::default();

    // Resolved once here so a malformed value refuses startup with the exact
    // variable named, instead of surfacing later as retention quietly running
    // with bounds the environment did not ask for.
    let reconcile_concurrency = ReconcileConcurrency::from_env()?;
    if reconcile_concurrency.is_unbounded() {
        // Worth saying out loud: this is the configuration that lets every due
        // policy allocate its inspection at the same moment.
        info!("reconcile concurrency is unbounded");
    } else {
        info!(
            concurrency = reconcile_concurrency.get(),
            "reconcile concurrency bounded"
        );
    }
    let plan_retention = PlanRetention::from_env()?;
    if plan_retention != PlanRetention::default() {
        info!(
            ?plan_retention,
            "plan retention bounds set from environment"
        );
    }

    // Create the shared operator context.
    let ctx = Arc::new(
        OperatorContext::new_with_runtime_config(
            client.clone(),
            observability.clone(),
            event_recorder,
            request_index.clone(),
            watch_namespace.clone(),
        )
        .with_plan_retention(plan_retention),
    );

    // Watch all PostgresPolicy resources across all namespaces.
    let policies: Api<PostgresPolicy> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let (reader, writer) = reflector::store();
    let policy_stream = health
        .watch(
            WatchKind::Policies,
            watcher(policies.clone(), watcher::Config::default())
                .default_backoff()
                .reflect(writer),
        )
        .applied_objects()
        .predicate_filter(policy_trigger_hash, Default::default());
    let policy_store = reader.clone();
    let secrets: Api<Secret> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let secret_triggers = health
        .watch(
            WatchKind::Secrets,
            watcher(secrets, watcher::Config::default()).default_backoff(),
        )
        .touched_objects()
        .predicate_filter(predicates::resource_version, Default::default())
        .filter_map(|secret| async move { secret.ok() })
        .flat_map(move |secret| {
            let policy_store = policy_store.clone();
            let Some(secret_ns) = secret.namespace() else {
                return stream::iter(Vec::<ObjectRef<PostgresPolicy>>::new());
            };
            let secret_name = secret.name_any();
            let refs = policy_store
                .state()
                .into_iter()
                .filter(|policy| {
                    policy.namespace().as_deref() == Some(secret_ns.as_str())
                        && policy
                            .spec
                            .referenced_secret_names(&policy.name_any())
                            .contains(&secret_name)
                })
                .map(|policy| ObjectRef::from_obj(policy.as_ref()))
                .collect::<Vec<_>>();
            stream::iter(refs)
        });

    // Watch PostgresPolicyPlan resources for annotation changes (approval/rejection).
    // When a plan's annotations change, trigger reconciliation of the parent policy.
    let plan_policy_store = reader.clone();
    let plans: Api<PostgresPolicyPlan> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let plan_triggers = health
        .watch(
            WatchKind::Plans,
            watcher(plans, watcher::Config::default()).default_backoff(),
        )
        .touched_objects()
        .predicate_filter(plan_decision_hash, Default::default())
        .filter_map(|plan| async move { plan.ok() })
        .flat_map(move |plan| {
            let policy_store = plan_policy_store.clone();
            // Map the plan back to its parent by UID, never by name.
            //
            // This used to compare the plan's `pgroles.io/policy` label against
            // `metadata.name`, but that label is truncated at the 63-character label
            // limit while a policy name may be up to 253. For any longer name the
            // comparison never matched, so plan status changes silently stopped
            // waking the policy reconciler. The UID is exact at any name length.
            //
            // A candidate-origin plan is controller-owned by its *candidate*,
            // not the policy, so the owner UID maps to nothing — yet the
            // decision recorded on it is the parent's work: promotion runs in
            // the parent's reconcile. Those plans carry the policy's UID in
            // `spec.origin.policyUid`; without this fallback a candidate-plan
            // approval sat inert until the policy's periodic interval.
            let parent_policy_uid = plan
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|owner| owner.controller.unwrap_or(false))
                .map(|owner| owner.uid.clone())
                .filter(|uid| !uid.is_empty());
            let origin_policy_uid = plan
                .spec
                .origin
                .as_ref()
                .and_then(|origin| origin.policy_uid.clone())
                .filter(|uid| !uid.is_empty());

            let refs: Vec<ObjectRef<PostgresPolicy>> = policy_store
                .state()
                .into_iter()
                .filter(|policy| {
                    let uid = policy.metadata.uid.as_deref();
                    parent_policy_uid.as_deref().is_some_and(|p| Some(p) == uid)
                        || origin_policy_uid.as_deref().is_some_and(|o| Some(o) == uid)
                })
                .map(|policy| ObjectRef::from_obj(policy.as_ref()))
                .collect();
            stream::iter(refs)
        });

    // Watch PostgresPolicyCandidate resources and enqueue the *parent policy*.
    // Candidates have no reconciler of their own: they are planned inside the
    // parent's reconcile, under its lock and in its execution context, so the
    // parent is the only correct unit of work.
    let candidate_policy_store = reader.clone();
    let candidates: Api<PostgresPolicyCandidate> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let candidate_triggers = health
        .watch(
            WatchKind::Candidates,
            watcher(candidates, watcher::Config::default()).default_backoff(),
        )
        .touched_objects()
        .predicate_filter(candidate_trigger_hash, Default::default())
        .filter_map(|candidate| async move { candidate.ok() })
        .flat_map(move |candidate| {
            let policy_store = candidate_policy_store.clone();
            let Some(namespace) = candidate.namespace() else {
                return stream::iter(Vec::<ObjectRef<PostgresPolicy>>::new());
            };
            // Resolved by `spec.policyRef` rather than by owner reference: the
            // controller stamps the owner reference on first touch, so a brand
            // new candidate — the case that most needs to wake the parent —
            // does not have one yet.
            let policy_name = candidate.spec.policy_ref.name.clone();
            let refs = policy_store
                .state()
                .into_iter()
                .filter(|policy| {
                    policy.namespace().as_deref() == Some(namespace.as_str())
                        && policy.name_any() == policy_name
                })
                .map(|policy| ObjectRef::from_obj(policy.as_ref()))
                .collect::<Vec<_>>();
            stream::iter(refs)
        });

    info!("starting controllers");

    let policy_controller = configured_controller(policy_stream, reader, reconcile_concurrency)
        .reconcile_on(secret_triggers)
        .reconcile_on(plan_triggers)
        .reconcile_on(candidate_triggers)
        .graceful_shutdown_on(shutdown.clone())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx.clone())
        .for_each(|result| {
            observability.record_controller_progress(ControllerKind::Policy, result.is_ok());
            async move {
                match result {
                    Ok(action) => {
                        tracing::debug!(?action, "reconcile completed");
                    }
                    Err(error) => {
                        tracing::error!(%error, "reconcile failed");
                    }
                }
            }
        });

    let access_policies: Api<EphemeralAccessPolicy> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let (access_policy_reader, access_policy_writer) = reflector::store();
    let access_policy_stream = health
        .watch(
            WatchKind::AccessPolicies,
            watcher(access_policies, watcher::Config::default())
                .default_backoff()
                .reflect(access_policy_writer),
        )
        .applied_objects();
    let target_access_policy_store = access_policy_reader.clone();
    let target_policies: Api<PostgresPolicy> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let target_access_policy_triggers = health
        .watch(
            WatchKind::AccessPolicyTargets,
            watcher(target_policies, watcher::Config::default()).default_backoff(),
        )
        .touched_objects()
        .filter_map(|target| async move { target.ok() })
        .flat_map(move |target| {
            let namespace = target.namespace();
            let target_name = target.name_any();
            let refs = target_access_policy_store
                .state()
                .into_iter()
                .filter(|policy| {
                    policy.namespace() == namespace
                        && policy.spec.postgres_policy_ref.name == target_name
                })
                .map(|policy| ObjectRef::from_obj(policy.as_ref()))
                .collect::<Vec<_>>();
            stream::iter(refs)
        });

    let access_policy_controller = configured_controller(
        access_policy_stream,
        access_policy_reader,
        reconcile_concurrency,
    )
    .reconcile_on(target_access_policy_triggers)
    .graceful_shutdown_on(shutdown.clone())
    .shutdown_on_signal()
    .run(
        reconcile_access_policy,
        access_policy_error_policy,
        ctx.clone(),
    )
    .for_each(|result| {
        observability.record_controller_progress(ControllerKind::AccessPolicy, result.is_ok());
        async move {
            if let Err(error) = result {
                tracing::error!(%error, "ephemeral access policy reconcile failed");
            }
        }
    });

    let access_requests: Api<EphemeralAccessRequest> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let (access_request_reader, access_request_writer) = reflector::store();
    let request_index_writer = request_index.clone();
    let access_request_stream = health
        .watch(
            WatchKind::AccessRequests,
            watcher(access_requests, watcher::Config::default())
                .default_backoff()
                .inspect_ok(move |event| request_index_writer.observe(event))
                .reflect(access_request_writer),
        )
        .applied_objects();
    let access_policy_request_index = request_index.clone();
    let request_access_policies: Api<EphemeralAccessPolicy> = match &watch_namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let access_policy_request_triggers = health
        .watch(
            WatchKind::AccessRequestPolicies,
            watcher(request_access_policies, watcher::Config::default()).default_backoff(),
        )
        .touched_objects()
        .filter_map(|policy| async move { policy.ok() })
        .flat_map(move |policy| {
            let request_index = access_policy_request_index.clone();
            let namespace = policy.namespace().unwrap_or_default();
            let policy_name = policy.name_any();
            stream::once(async move {
                // A trigger is an optimization: the request controller also
                // requeues on its own. Dropping this fan-out when the index
                // is not yet synced delays a reconcile, so it is logged and
                // skipped rather than propagated.
                match request_index
                    .for_access_policy_name(&namespace, &policy_name)
                    .await
                {
                    Ok(requests) => requests
                        .into_iter()
                        .map(|request| ObjectRef::from_obj(request.as_ref()))
                        .collect::<Vec<_>>(),
                    Err(error) => {
                        warn!(
                            %error,
                            %namespace,
                            policy = %policy_name,
                            "skipping access-policy request triggers",
                        );
                        Vec::new()
                    }
                }
            })
            .flat_map(stream::iter)
        });

    let access_request_controller = configured_controller(
        access_request_stream,
        access_request_reader,
        reconcile_concurrency,
    )
    .reconcile_on(access_policy_request_triggers)
    .graceful_shutdown_on(shutdown.clone())
    .shutdown_on_signal()
    .run(reconcile_access_request, access_request_error_policy, ctx)
    .for_each(|result| {
        observability.record_controller_progress(ControllerKind::AccessRequest, result.is_ok());
        async move {
            if let Err(error) = result {
                tracing::error!(%error, "ephemeral access request reconcile failed");
            }
        }
    });

    let controllers = futures::stream::FuturesUnordered::new();
    controllers.push(policy_controller.boxed());
    controllers.push(access_policy_controller.boxed());
    controllers.push(access_request_controller.boxed());
    let unexpected_exit = supervise(health, controllers, signal, shutdown_tx).await;

    observability.mark_not_ready();
    info!("controller shut down");
    if let Err(error) = observability.shutdown() {
        eprintln!("failed to shut down observability: {error}");
    }
    anyhow::ensure!(
        !unexpected_exit,
        "required controller terminated unexpectedly"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::policy_trigger_hash;
    use pgroles_operator::crd::{
        ConnectionSpec, CrdReconciliationMode, PolicyMode, PostgresPolicy, PostgresPolicySpec,
        REQUESTED_RECONCILE_ANNOTATION, SecretReference,
    };
    use std::collections::BTreeMap;

    /// Raw controller construction belongs in `configured_controller`, where
    /// applying the operator-wide concurrency config is part of construction.
    /// This catches a future controller built directly with kube-rs's unbounded
    /// default instead of relying on counts that unrelated builder calls can
    /// accidentally balance.
    #[test]
    fn controllers_are_constructed_through_the_configured_helper() {
        let source = include_str!("main.rs");
        let body: String = source
            .split_once("mod tests {")
            .map(|(before, _)| before)
            .expect("this binary has a test module")
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(
            body.matches("Controller::").count(),
            1,
            "construct controllers through configured_controller; raw kube-rs controllers use \
             unbounded concurrency by default"
        );
        assert!(
            body.contains(
                ".with_config(ControllerConfig::default().concurrency(concurrency.get()))"
            ),
            "configured_controller must apply the resolved concurrency bound"
        );
    }

    fn test_policy() -> PostgresPolicy {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "db-credentials".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            allow_schema_owner_transfers: false,
            role_pattern: None,
            default_owner: None,
            profiles: Default::default(),
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
            retirements: Vec::new(),
            approval: None,
        };
        let mut policy = PostgresPolicy::new("example", spec);
        policy.metadata.namespace = Some("default".to_string());
        policy.metadata.generation = Some(1);
        policy
    }

    #[test]
    fn policy_trigger_hash_changes_when_generation_changes() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.generation = Some(2);

        assert_ne!(original, policy_trigger_hash(&changed));
    }

    #[test]
    fn policy_trigger_hash_changes_when_finalizers_change() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.finalizers = Some(vec!["pgroles.io/finalizer".to_string()]);

        assert_ne!(original, policy_trigger_hash(&changed));
    }

    #[test]
    fn policy_trigger_hash_changes_when_requested_reconcile_annotation_changes() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.annotations = Some(BTreeMap::from([(
            REQUESTED_RECONCILE_ANNOTATION.to_string(),
            "2026-05-15T00:00:00Z".to_string(),
        )]));

        assert_ne!(original, policy_trigger_hash(&changed));
    }

    #[test]
    fn policy_trigger_hash_ignores_unrelated_annotation_changes() {
        let policy = test_policy();
        let original = policy_trigger_hash(&policy);

        let mut changed = policy.clone();
        changed.metadata.annotations = Some(BTreeMap::from([(
            "argocd.argoproj.io/tracking-id".to_string(),
            "pgroles/default:pgroles.io/PostgresPolicy/example".to_string(),
        )]));

        assert_eq!(original, policy_trigger_hash(&changed));
    }
}
