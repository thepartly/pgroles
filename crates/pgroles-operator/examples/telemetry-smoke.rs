//! Emit one metric and structured log through the production OTLP setup.
//! Set OTEL_EXPORTER_OTLP_ENDPOINT and optional standard resource env vars.
use pgroles_operator::observability::{OperatorObservability, init_log_provider_from_env};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let logger_provider = init_log_provider_from_env()?;
    let bridge = logger_provider
        .as_ref()
        .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new);
    tracing_subscriber::registry().with(bridge).try_init()?;
    let observability = OperatorObservability::from_env()?.with_logger_provider(logger_provider);
    observability
        .start_reconcile()
        .record_result("success", "TelemetrySmoke");
    tracing::info!(event = "pgroles.telemetry.smoke", "Telemetry smoke test");
    tokio::task::spawn_blocking(move || observability.shutdown()).await??;
    Ok(())
}
