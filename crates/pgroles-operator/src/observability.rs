//! Operator health endpoints and OTLP metrics export.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use crate::controller_health::{ControllerKind, WatchKind};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Router, serve};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider, UpDownCounter};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use tokio::net::TcpListener;

const SERVICE_NAME: &str = "pgroles-operator";

#[derive(Clone)]
pub struct OperatorObservability {
    ready: Arc<AtomicBool>,
    metrics: Option<Arc<Metrics>>,
    logger_provider: Option<SdkLoggerProvider>,
}

struct Metrics {
    provider: SdkMeterProvider,
    watch_synced: Arc<AtomicU8>,
    watch_events: Counter<u64>,
    controller_progress: Counter<u64>,
    reconcile_total: Counter<u64>,
    reconcile_duration_ms: Histogram<u64>,
    reconcile_inflight: UpDownCounter<i64>,
    inspect_duration_ms: Histogram<u64>,
    processing_duration_ms: Histogram<f64>,
    scheduling_lag_ms: Histogram<f64>,
    inspect_items_total: Counter<u64>,
    wildcard_grantability_queries_total: Counter<u64>,
    wildcard_unsatisfied_grants_total: Counter<u64>,
    plan_total: Counter<u64>,
    plan_changes_total: Counter<u64>,
    candidate_planning_duration_ms: Histogram<u64>,
    candidate_inspections: Histogram<u64>,
    lock_contention_total: Counter<u64>,
    policy_conflicts_total: Counter<u64>,
    invalid_spec_total: Counter<u64>,
    deprecated_approval_unset_total: Counter<u64>,
    deprecated_mode_plan_total: Counter<u64>,
    database_connection_failures_total: Counter<u64>,
    apply_total: Counter<u64>,
    apply_statements_total: Counter<u64>,
    ephemeral_transition_total: Counter<u64>,
    ephemeral_failure_total: Counter<u64>,
    ephemeral_retained_memberships_total: Counter<u64>,
    ephemeral_expiry_lag_ms: Histogram<u64>,
    ephemeral_role_retirement_blocked_total: Counter<u64>,
    ephemeral_cached_requests: Histogram<u64>,
    ephemeral_relevant_requests: Histogram<u64>,
    ephemeral_reconcile_duration_ms: Histogram<u64>,
    ephemeral_reconcile_inflight: UpDownCounter<i64>,
}

pub struct ReconcileGuard {
    metrics: Option<Arc<Metrics>>,
    started_at: Instant,
}

pub struct EphemeralReconcileGuard {
    metrics: Option<Arc<Metrics>>,
    started_at: Instant,
    kind: &'static str,
    request_count_bucket: &'static str,
}

impl OperatorObservability {
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            metrics: None,
            logger_provider: None,
        }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            ready: Arc::new(AtomicBool::new(false)),
            metrics: init_metrics_from_env()?,
            logger_provider: None,
        })
    }

    pub fn with_logger_provider(mut self, provider: Option<SdkLoggerProvider>) -> Self {
        self.logger_provider = provider;
        self
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Relaxed);
    }

    pub fn record_watch_sync(&self, watch: WatchKind, synced: bool) {
        if let Some(metrics) = &self.metrics {
            let bit = 1 << watch as u8;
            if synced {
                metrics.watch_synced.fetch_or(bit, Ordering::Relaxed);
            } else {
                metrics.watch_synced.fetch_and(!bit, Ordering::Relaxed);
            }
        }
    }

    pub fn record_watch_event(&self, watch: WatchKind, success: bool) {
        if let Some(metrics) = &self.metrics {
            metrics.watch_events.add(
                1,
                &[
                    KeyValue::new("watch", watch.label()),
                    KeyValue::new("result", if success { "event" } else { "error" }),
                ],
            );
        }
    }

    pub fn record_controller_progress(&self, controller: ControllerKind, success: bool) {
        if let Some(metrics) = &self.metrics {
            metrics.controller_progress.add(
                1,
                &[
                    KeyValue::new("controller", controller.label()),
                    KeyValue::new("result", if success { "success" } else { "error" }),
                ],
            );
        }
    }

    pub fn start_reconcile(&self) -> ReconcileGuard {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_inflight.add(1, &[]);
            ReconcileGuard {
                metrics: Some(metrics.clone()),
                started_at: Instant::now(),
            }
        } else {
            ReconcileGuard {
                metrics: None,
                started_at: Instant::now(),
            }
        }
    }

    pub fn record_database_connection_failure(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.database_connection_failures_total.add(1, &[]);
        }
    }

    pub fn record_policy_conflict(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.policy_conflicts_total.add(1, &[]);
        }
    }

    pub fn record_lock_contention(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.lock_contention_total.add(1, &[]);
        }
    }

    pub fn record_plan_result(&self, result: &str) {
        if let Some(metrics) = &self.metrics {
            metrics
                .plan_total
                .add(1, &[KeyValue::new("result", result.to_string())]);
        }
    }

    pub fn record_planned_changes(&self, changes: usize) {
        if changes == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics.plan_changes_total.add(changes as u64, &[]);
        }
    }

    pub fn record_invalid_spec(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.invalid_spec_total.add(1, &[]);
        }
    }

    /// Count a reconcile that relied on the deprecated `spec.approval`
    /// inference, so the remaining exposure is alertable fleet-wide rather than
    /// only visible per object.
    pub fn record_deprecated_approval_unset(&self, inferred: &str) {
        if let Some(metrics) = &self.metrics {
            metrics
                .deprecated_approval_unset_total
                .add(1, &[KeyValue::new("inferred", inferred.to_string())]);
        }
    }

    /// Count a reconcile of a policy spelled `mode: plan`, the deprecated
    /// alias of `observe`, for the same fleet-wide-exposure reason as
    /// [`Self::record_deprecated_approval_unset`].
    pub fn record_deprecated_mode_plan(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.deprecated_mode_plan_total.add(1, &[]);
        }
    }

    pub fn record_processing_phase(&self, phase: &'static str, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.processing_duration_ms.record(
                duration.as_secs_f64() * 1000.0,
                &[KeyValue::new("phase", phase)],
            );
        }
    }

    pub fn record_inspection(&self, stats: &pgroles_inspect::InspectionStats) {
        let Some(metrics) = &self.metrics else {
            return;
        };

        for (phase, duration) in &stats.phase_durations {
            metrics.inspect_duration_ms.record(
                duration.as_millis() as u64,
                &[KeyValue::new("phase", *phase)],
            );
        }

        for (kind, count) in [
            ("roles", stats.roles),
            ("memberships", stats.memberships),
            ("schemas", stats.schemas),
            ("grants", stats.grants),
            ("acl_rows", stats.acl_rows),
            ("grantor_keys", stats.grantor_keys),
            ("default_privileges", stats.default_privileges),
            (
                "wildcard_configured_grants",
                stats.wildcard.configured_grants,
            ),
            (
                "wildcard_configured_scopes",
                stats.wildcard.configured_scopes,
            ),
            (
                "wildcard_inventory_objects",
                stats.wildcard.inventory_objects,
            ),
            (
                "wildcard_unsatisfied_scopes",
                stats.wildcard.unsatisfied_scopes,
            ),
            (
                "wildcard_grantability_objects",
                stats.wildcard.grantability_objects,
            ),
        ] {
            if count > 0 {
                metrics
                    .inspect_items_total
                    .add(count as u64, &[KeyValue::new("kind", kind)]);
            }
        }

        if stats.wildcard.grantability_queries > 0 {
            metrics
                .wildcard_grantability_queries_total
                .add(stats.wildcard.grantability_queries as u64, &[]);
        }
        if stats.wildcard.unsatisfied_grants > 0 {
            metrics
                .wildcard_unsatisfied_grants_total
                .add(stats.wildcard.unsatisfied_grants as u64, &[]);
        }
    }

    /// How long planning one candidate took, end to end.
    ///
    /// Paired with [`Self::record_candidate_inspections`]: together they say
    /// whether candidate planning cost still scales with the number of open
    /// candidates, which is what issue #191 set out to bound.
    pub fn record_candidate_planning(&self, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics
                .candidate_planning_duration_ms
                .record(duration.as_millis() as u64, &[]);
        }
    }

    /// How many database inspections one reconcile's candidate pass performed,
    /// and how many candidates it covered.
    ///
    /// With the shared snapshot this is 1 for any number of candidates on the
    /// parent's own target; a value that tracks the candidate count means
    /// candidates are falling back to inspecting individually.
    pub fn record_candidate_inspections(&self, inspections: usize, candidates: usize) {
        if candidates == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics.candidate_inspections.record(
                inspections as u64,
                &[KeyValue::new(
                    "candidates",
                    request_count_bucket(candidates),
                )],
            );
        }
    }

    pub fn record_apply_result(&self, result: &str) {
        if let Some(metrics) = &self.metrics {
            metrics
                .apply_total
                .add(1, &[KeyValue::new("result", result.to_string())]);
        }
    }

    pub fn record_apply_statements(&self, statements: usize) {
        if statements == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics.apply_statements_total.add(statements as u64, &[]);
        }
    }

    pub fn record_ephemeral_transition(&self, phase: &str, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.ephemeral_transition_total.add(
                1,
                &[
                    KeyValue::new("phase", phase.to_string()),
                    KeyValue::new("reason", reason.to_string()),
                ],
            );
            if matches!(phase, "Failed" | "Denied" | "ApprovalExpired") {
                metrics
                    .ephemeral_failure_total
                    .add(1, &[KeyValue::new("reason", reason.to_string())]);
            }
        }
    }

    pub fn record_ephemeral_retained_memberships(&self, count: usize) {
        if count == 0 {
            return;
        }
        if let Some(metrics) = &self.metrics {
            metrics
                .ephemeral_retained_memberships_total
                .add(count as u64, &[]);
        }
    }

    pub fn record_ephemeral_expiry_lag(&self, lag: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics
                .ephemeral_expiry_lag_ms
                .record(lag.as_millis() as u64, &[]);
        }
    }

    pub fn record_ephemeral_role_retirement_blocked(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.ephemeral_role_retirement_blocked_total.add(1, &[]);
        }
    }

    pub fn record_ephemeral_relevant_requests(&self, lookup: &'static str, count: usize) {
        if let Some(metrics) = &self.metrics {
            metrics
                .ephemeral_relevant_requests
                .record(count as u64, &[KeyValue::new("lookup", lookup)]);
        }
    }

    pub fn start_ephemeral_reconcile(
        &self,
        kind: &'static str,
        cached_requests: usize,
    ) -> EphemeralReconcileGuard {
        if let Some(metrics) = &self.metrics {
            metrics
                .ephemeral_cached_requests
                .record(cached_requests as u64, &[]);
            metrics
                .ephemeral_reconcile_inflight
                .add(1, &[KeyValue::new("kind", kind)]);
        }
        EphemeralReconcileGuard {
            metrics: self.metrics.clone(),
            started_at: Instant::now(),
            kind,
            request_count_bucket: request_count_bucket(cached_requests),
        }
    }

    pub fn shutdown(&self) -> anyhow::Result<()> {
        if let Some(metrics) = &self.metrics {
            metrics.provider.shutdown()?;
        }
        if let Some(provider) = &self.logger_provider {
            provider.shutdown()?;
        }
        Ok(())
    }
}

impl ReconcileGuard {
    pub fn record_result(self, result: &str, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_total.add(
                1,
                &[
                    KeyValue::new("result", result.to_string()),
                    KeyValue::new("reason", reason.to_string()),
                ],
            );
            metrics
                .reconcile_duration_ms
                .record(self.started_at.elapsed().as_millis() as u64, &[]);
        }
    }
}

impl Drop for ReconcileGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.reconcile_inflight.add(-1, &[]);
        }
    }
}

impl Drop for EphemeralReconcileGuard {
    fn drop(&mut self) {
        if let Some(metrics) = &self.metrics {
            metrics.ephemeral_reconcile_duration_ms.record(
                self.started_at.elapsed().as_millis() as u64,
                &[
                    KeyValue::new("kind", self.kind),
                    KeyValue::new("request_count", self.request_count_bucket),
                ],
            );
            metrics
                .ephemeral_reconcile_inflight
                .add(-1, &[KeyValue::new("kind", self.kind)]);
        }
    }
}

fn request_count_bucket(count: usize) -> &'static str {
    match count {
        0 => "0",
        1..=10 => "1-10",
        11..=100 => "11-100",
        101..=1_000 => "101-1000",
        _ => "1001+",
    }
}

pub async fn serve_health(
    bind_addr: SocketAddr,
    observability: OperatorObservability,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    let app = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .with_state(observability.clone());

    let lag = async {
        let mut timer = tokio::time::interval(Duration::from_secs(1));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let scheduled = timer.tick().await;
            if let Some(metrics) = &observability.metrics {
                metrics
                    .scheduling_lag_ms
                    .record(scheduled.elapsed().as_secs_f64() * 1000.0, &[]);
            }
        }
    };
    tokio::select! {
        result = serve(listener, app).into_future() => { result?; }
        () = lag => {}
    }
    Ok(())
}

fn init_metrics_from_env() -> anyhow::Result<Option<Arc<Metrics>>> {
    if !otel_metrics_enabled() {
        return Ok(None);
    }

    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc)
        .build()?;

    let reader = PeriodicReader::builder(exporter).build();
    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(crate::telemetry_resource::operator_resource())
        .build();

    let meter = provider.meter(SERVICE_NAME);
    Ok(Some(Arc::new(Metrics::new(provider, meter))))
}

/// Build the OTLP log provider before the global tracing subscriber is
/// installed. The caller attaches an `OpenTelemetryTracingBridge` layer and
/// stores the provider in `OperatorObservability` for graceful shutdown.
pub fn init_log_provider_from_env() -> anyhow::Result<Option<SdkLoggerProvider>> {
    let logs_exporter = std::env::var("OTEL_LOGS_EXPORTER").ok();
    if matches!(logs_exporter.as_deref(), Some("none")) {
        return Ok(None);
    }
    let endpoint_configured = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT").is_some();
    if !endpoint_configured && !matches!(logs_exporter.as_deref(), Some("otlp")) {
        return Ok(None);
    }

    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc)
        .build()?;
    let provider = SdkLoggerProvider::builder()
        .with_resource(crate::telemetry_resource::operator_resource())
        .with_batch_exporter(exporter)
        .build();
    Ok(Some(provider))
}

fn otel_metrics_enabled() -> bool {
    let metrics_exporter = std::env::var("OTEL_METRICS_EXPORTER").ok();
    if matches!(metrics_exporter.as_deref(), Some("none")) {
        return false;
    }

    std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT").is_some()
        || std::env::var_os("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT").is_some()
}

impl Metrics {
    fn new(provider: SdkMeterProvider, meter: Meter) -> Self {
        let watch_synced = Arc::new(AtomicU8::new(0));
        let observed_sync = watch_synced.clone();
        meter
            .u64_observable_gauge("pgroles.watch.synced")
            .with_description("Whether a required watch has completed its latest initialization")
            .with_callback(move |observer| {
                let synced = observed_sync.load(Ordering::Relaxed);
                for watch in WatchKind::ALL {
                    observer.observe(
                        u64::from(synced & (1 << watch as u8) != 0),
                        &[KeyValue::new("watch", watch.label())],
                    );
                }
            })
            .build();
        Self {
            provider,
            watch_synced,
            watch_events: meter
                .u64_counter("pgroles.watch.events")
                .with_description("Watch events and errors; silence alone is not a failure")
                .build(),
            controller_progress: meter
                .u64_counter("pgroles.controller.progress")
                .with_description("Controller results including reconciler and watch errors")
                .build(),
            reconcile_total: meter
                .u64_counter("pgroles.reconcile.total")
                .with_description("Total reconciliations by result and reason")
                .build(),
            reconcile_duration_ms: meter
                .u64_histogram("pgroles.reconcile.duration")
                .with_unit("ms")
                .with_description("Reconciliation duration in milliseconds")
                .build(),
            reconcile_inflight: meter
                .i64_up_down_counter("pgroles.reconcile.inflight")
                .with_description("In-flight reconciliations")
                .build(),
            processing_duration_ms: meter
                .f64_histogram("pgroles.processing.duration")
                .with_unit("ms")
                .with_description("Synchronous policy processing by phase")
                .build(),
            scheduling_lag_ms: meter
                .f64_histogram("pgroles.runtime.scheduling_lag")
                .with_unit("ms")
                .with_description("Delay of a one-second runtime timer; not HTTP probe latency")
                .build(),
            inspect_duration_ms: meter
                .u64_histogram("pgroles.inspect.duration")
                .with_unit("ms")
                .with_description("Database inspection phase duration in milliseconds")
                .build(),
            inspect_items_total: meter
                .u64_counter("pgroles.inspect.items")
                .with_description("Database inspection objects observed by kind")
                .build(),
            wildcard_grantability_queries_total: meter
                .u64_counter("pgroles.wildcard.grantability_queries")
                .with_description("Wildcard grantability catalog queries")
                .build(),
            wildcard_unsatisfied_grants_total: meter
                .u64_counter("pgroles.wildcard.unsatisfied_grants")
                .with_description("Wildcard grants missing privileges before grantability checks")
                .build(),
            candidate_planning_duration_ms: meter
                .u64_histogram("pgroles.candidate.planning.duration")
                .with_unit("ms")
                .with_description("Duration of planning one candidate, in milliseconds")
                .build(),
            candidate_inspections: meter
                .u64_histogram("pgroles.candidate.inspections")
                .with_description(
                    "Database inspections performed by one reconcile's candidate pass, \
                     bucketed by how many candidates that pass covered",
                )
                .build(),
            plan_total: meter
                .u64_counter("pgroles.plan.total")
                .with_description("Successful observe-mode reconciliations by result")
                .build(),
            plan_changes_total: meter
                .u64_counter("pgroles.plan.changes")
                .with_description("Planned changes discovered during observe-mode reconciliations")
                .build(),
            lock_contention_total: meter
                .u64_counter("pgroles.lock_contention.total")
                .with_description("Reconciliations delayed by per-database lock contention")
                .build(),
            policy_conflicts_total: meter
                .u64_counter("pgroles.policy.conflicts")
                .with_description("Conflicting policies targeting the same database")
                .build(),
            invalid_spec_total: meter
                .u64_counter("pgroles.invalid_spec.total")
                .with_description("Invalid PostgresPolicy specifications")
                .build(),
            deprecated_approval_unset_total: meter
                .u64_counter("pgroles.deprecated.approval_unset")
                .with_description(
                    "Reconciles of a PostgresPolicy that omits spec.approval and relies on the \
                     deprecated inference from spec.mode",
                )
                .build(),
            deprecated_mode_plan_total: meter
                .u64_counter("pgroles.deprecated.mode_plan")
                .with_description(
                    "Reconciliations of policies using mode: plan, the deprecated spelling of \
                     observe",
                )
                .build(),
            database_connection_failures_total: meter
                .u64_counter("pgroles.database.connection_failures")
                .with_description("Database connection failures during reconciliation")
                .build(),
            apply_total: meter
                .u64_counter("pgroles.apply.total")
                .with_description("Apply transaction outcomes")
                .build(),
            apply_statements_total: meter
                .u64_counter("pgroles.apply.statements")
                .with_description("SQL statements executed during successful applies")
                .build(),
            ephemeral_transition_total: meter
                .u64_counter("pgroles.ephemeral_access.transitions")
                .with_description("Ephemeral access lifecycle transitions by phase and reason")
                .build(),
            ephemeral_failure_total: meter
                .u64_counter("pgroles.ephemeral_access.failures")
                .with_description("Terminal ephemeral access failures by reason")
                .build(),
            ephemeral_retained_memberships_total: meter
                .u64_counter("pgroles.ephemeral_access.retained_memberships")
                .with_description("Ephemeral memberships retained because they became durable")
                .build(),
            ephemeral_expiry_lag_ms: meter
                .u64_histogram("pgroles.ephemeral_access.expiry_lag")
                .with_unit("ms")
                .with_description("Delay between absolute expiry and revocation processing")
                .build(),
            ephemeral_role_retirement_blocked_total: meter
                .u64_counter("pgroles.ephemeral_access.role_retirement_blocked")
                .with_description("Role retirements blocked by active access requests")
                .build(),
            ephemeral_cached_requests: meter
                .u64_histogram("pgroles.ephemeral_access.cached_requests")
                .with_description("Request-cache size sampled at reconcile start")
                .build(),
            ephemeral_relevant_requests: meter
                .u64_histogram("pgroles.ephemeral_access.relevant_requests")
                .with_description("Requests returned by an indexed lookup")
                .build(),
            ephemeral_reconcile_duration_ms: meter
                .u64_histogram("pgroles.ephemeral_access.reconcile.duration")
                .with_unit("ms")
                .with_description("Ephemeral reconcile duration by kind and request-count bucket")
                .build(),
            ephemeral_reconcile_inflight: meter
                .i64_up_down_counter("pgroles.ephemeral_access.reconcile.inflight")
                .with_description("In-flight ephemeral reconciliations by resource kind")
                .build(),
        }
    }
}

async fn livez() -> &'static str {
    "ok"
}

async fn readyz(State(observability): State<OperatorObservability>) -> impl IntoResponse {
    if observability.is_ready() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use opentelemetry::metrics::MeterProvider;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

    use super::{
        Metrics, OperatorObservability, ReconcileGuard, SERVICE_NAME, livez, otel_metrics_enabled,
        readyz,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_observability() -> (
        OperatorObservability,
        SdkMeterProvider,
        InMemoryMetricExporter,
    ) {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let meter = provider.meter(SERVICE_NAME);
        let observability = OperatorObservability {
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics: Some(Arc::new(Metrics::new(provider.clone(), meter))),
            logger_provider: None,
        };

        (observability, provider, exporter)
    }

    fn metric_exists(metrics: &[ResourceMetrics], name: &str) -> bool {
        metrics.iter().any(|resource_metrics| {
            resource_metrics
                .scope_metrics()
                .flat_map(|scope_metrics| scope_metrics.metrics())
                .any(|metric| metric.name() == name)
        })
    }

    fn u64_sum_value(metrics: &[ResourceMetrics], name: &str) -> Option<u64> {
        let mut found = false;
        let total = metrics
            .iter()
            .flat_map(|resource_metrics| resource_metrics.scope_metrics())
            .flat_map(|scope_metrics| scope_metrics.metrics())
            .filter(|metric| metric.name() == name)
            .filter_map(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                    found = true;
                    Some(
                        sum.data_points()
                            .map(|data_point| data_point.value())
                            .sum::<u64>(),
                    )
                }
                _ => None,
            })
            .sum();

        found.then_some(total)
    }

    fn i64_sum_value(metrics: &[ResourceMetrics], name: &str) -> Option<i64> {
        metrics
            .iter()
            .flat_map(|resource_metrics| resource_metrics.scope_metrics())
            .flat_map(|scope_metrics| scope_metrics.metrics())
            .find(|metric| metric.name() == name)
            .and_then(|metric| match metric.data() {
                AggregatedMetrics::I64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .next()
                    .map(|data_point| data_point.value()),
                _ => None,
            })
    }

    #[test]
    fn controller_health_exports_bounded_watch_and_progress_series() {
        use crate::controller_health::{ControllerKind, WatchKind};
        let exporter = opentelemetry_sdk::metrics::InMemoryMetricExporterBuilder::new()
            .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
            .build();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let observability = OperatorObservability {
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            metrics: Some(Arc::new(Metrics::new(
                provider.clone(),
                provider.meter(SERVICE_NAME),
            ))),
            logger_provider: None,
        };
        for watch in WatchKind::ALL {
            observability.record_watch_sync(watch, false);
            observability.record_watch_sync(watch, true);
            observability.record_watch_event(watch, true);
            observability.record_watch_event(watch, false);
        }
        observability.record_controller_progress(ControllerKind::Policy, false);
        provider.force_flush().unwrap();
        let metrics = exporter.get_finished_metrics().unwrap();
        assert_eq!(u64_sum_value(&metrics, "pgroles.watch.events"), Some(16));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.controller.progress"),
            Some(1)
        );
        // No watch activity between delta collections: state must still export.
        for _ in 0..2 {
            exporter.reset();
            provider.force_flush().unwrap();
            let metrics = exporter.get_finished_metrics().unwrap();
            let gauges: Vec<_> = metrics
                .iter()
                .flat_map(|resource| resource.scope_metrics())
                .flat_map(|scope| scope.metrics())
                .filter(|metric| metric.name() == "pgroles.watch.synced")
                .flat_map(|metric| match metric.data() {
                    AggregatedMetrics::U64(MetricData::Gauge(gauge)) => gauge
                        .data_points()
                        .map(|point| point.value())
                        .collect::<Vec<_>>(),
                    _ => panic!("watch synced must be a gauge"),
                })
                .collect();
            assert_eq!(gauges, vec![1; 8]);
        }
    }

    #[test]
    fn otel_metrics_stay_disabled_without_endpoint() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
            std::env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
            std::env::remove_var("OTEL_METRICS_EXPORTER");
        }
        assert!(!otel_metrics_enabled());
    }

    #[test]
    fn otel_metrics_enable_with_explicit_endpoint() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317");
            std::env::remove_var("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
            std::env::remove_var("OTEL_METRICS_EXPORTER");
        }
        assert!(otel_metrics_enabled());
        unsafe {
            std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        }
    }

    #[tokio::test]
    async fn health_endpoints_reflect_readiness() {
        let (observability, _provider, _exporter) = test_observability();

        assert_eq!(livez().await, "ok");

        let not_ready = readyz(State(observability.clone())).await.into_response();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        observability.mark_ready();
        let ready = readyz(State(observability)).await.into_response();
        assert_eq!(ready.status(), StatusCode::OK);
    }

    #[test]
    fn metrics_are_recorded_and_flushed() {
        let (observability, provider, exporter) = test_observability();

        let guard: ReconcileGuard = observability.start_reconcile();
        observability.record_lock_contention();
        observability.record_policy_conflict();
        observability.record_invalid_spec();
        observability.record_database_connection_failure();
        observability.record_inspection(&pgroles_inspect::InspectionStats {
            acl_rows: 20,
            grantor_keys: 5,
            roles: 3,
            memberships: 2,
            schemas: 1,
            grants: 5,
            default_privileges: 1,
            phase_durations: [
                ("roles", Duration::from_millis(4)),
                ("object_privileges", Duration::from_millis(12)),
            ]
            .into_iter()
            .collect(),
            wildcard: pgroles_inspect::WildcardInspectionStats {
                configured_grants: 2,
                configured_scopes: 1,
                inventory_objects: 100,
                unsatisfied_grants: 1,
                unsatisfied_scopes: 1,
                grantability_queries: 1,
                grantability_objects: 3,
            },
        });
        observability.record_processing_phase("diff", Duration::from_millis(3));
        observability.record_plan_result("drift");
        observability.record_planned_changes(2);
        observability.record_candidate_planning(Duration::from_millis(37));
        // Non-zero: `record_candidate_inspections` returns early on zero
        // candidates, which would leave the instrument unexercised.
        observability.record_candidate_inspections(1, 12);
        observability.record_apply_result("success");
        observability.record_apply_statements(4);
        observability.record_ephemeral_transition("Active", "MembershipsGranted");
        observability.record_ephemeral_transition("Failed", "InvalidRequestState");
        observability.record_ephemeral_retained_memberships(2);
        observability.record_ephemeral_expiry_lag(Duration::from_millis(250));
        observability.record_ephemeral_role_retirement_blocked();
        observability.record_ephemeral_relevant_requests("effective_graph", 3);
        drop(observability.start_ephemeral_reconcile("access_request", 250));
        guard.record_result("conflict", "ConflictingPolicy");

        provider.force_flush().expect("flush should succeed");

        let metrics = exporter
            .get_finished_metrics()
            .expect("metrics should be exported");

        assert!(metric_exists(&metrics, "pgroles.reconcile.total"));
        assert!(metric_exists(&metrics, "pgroles.reconcile.duration"));
        assert!(metric_exists(&metrics, "pgroles.inspect.duration"));
        assert!(metric_exists(&metrics, "pgroles.processing.duration"));
        assert!(metric_exists(
            &metrics,
            "pgroles.candidate.planning.duration"
        ));
        // A histogram, not a counter — the interesting value is the
        // inspections-per-pass distribution, so there is no sum to assert on.
        assert!(metric_exists(&metrics, "pgroles.candidate.inspections"));
        assert_eq!(u64_sum_value(&metrics, "pgroles.inspect.items"), Some(144));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.ephemeral_access.transitions"),
            Some(2)
        );
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.ephemeral_access.failures"),
            Some(1)
        );
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.ephemeral_access.retained_memberships"),
            Some(2)
        );
        assert!(metric_exists(
            &metrics,
            "pgroles.ephemeral_access.expiry_lag"
        ));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.ephemeral_access.role_retirement_blocked"),
            Some(1)
        );
        assert!(metric_exists(
            &metrics,
            "pgroles.ephemeral_access.cached_requests"
        ));
        assert!(metric_exists(
            &metrics,
            "pgroles.ephemeral_access.relevant_requests"
        ));
        assert!(metric_exists(
            &metrics,
            "pgroles.ephemeral_access.reconcile.duration"
        ));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.wildcard.grantability_queries"),
            Some(1)
        );
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.wildcard.unsatisfied_grants"),
            Some(1)
        );
        assert_eq!(u64_sum_value(&metrics, "pgroles.plan.total"), Some(1));
        assert_eq!(u64_sum_value(&metrics, "pgroles.plan.changes"), Some(2));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.lock_contention.total"),
            Some(1)
        );
        assert_eq!(u64_sum_value(&metrics, "pgroles.policy.conflicts"), Some(1));
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.invalid_spec.total"),
            Some(1)
        );
        assert_eq!(
            u64_sum_value(&metrics, "pgroles.database.connection_failures"),
            Some(1)
        );
        assert_eq!(u64_sum_value(&metrics, "pgroles.apply.statements"), Some(4));
        assert_eq!(
            i64_sum_value(&metrics, "pgroles.reconcile.inflight"),
            Some(0)
        );
    }
}
