//! Verify real OTLP payloads without a cluster or external collector.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use opentelemetry::logs::{LogRecord, Logger, LoggerProvider};
use opentelemetry_proto::tonic::{
    collector::logs::v1::{
        ExportLogsServiceRequest, ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    },
    collector::metrics::v1::{
        ExportMetricsServiceRequest, ExportMetricsServiceResponse,
        metrics_service_server::{MetricsService, MetricsServiceServer},
    },
    common::v1::any_value::Value,
    resource::v1::Resource,
};
use pgroles_operator::observability::{OperatorObservability, init_log_provider_from_env};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

#[derive(Clone, Default)]
struct Receiver {
    metrics: Arc<Mutex<Vec<ExportMetricsServiceRequest>>>,
    logs: Arc<Mutex<Vec<ExportLogsServiceRequest>>>,
}

#[tonic::async_trait]
impl MetricsService for Receiver {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        self.metrics.lock().unwrap().push(request.into_inner());
        Ok(Response::new(ExportMetricsServiceResponse::default()))
    }
}
#[tonic::async_trait]
impl LogsService for Receiver {
    async fn export(
        &self,
        request: Request<ExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        self.logs.lock().unwrap().push(request.into_inner());
        Ok(Response::new(ExportLogsServiceResponse::default()))
    }
}

// Invoked in isolated subprocesses so env configuration never races other tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_probe() {
    if std::env::var_os("PGROLES_EXPORT_PROBE").is_none() {
        return;
    }
    let provider = init_log_provider_from_env().unwrap();
    if let Some(provider) = &provider {
        let logger = provider.logger("pgroles-test");
        let mut record = logger.create_log_record();
        record.set_body("resource identity probe".into());
        logger.emit(record);
    }
    let observability = OperatorObservability::from_env()
        .unwrap()
        .with_logger_provider(provider);
    observability
        .start_reconcile()
        .record_result("success", "TelemetrySmoke");
    tokio::task::spawn_blocking(move || observability.shutdown())
        .await
        .unwrap()
        .unwrap();
}

fn attributes(resource: &Option<Resource>) -> BTreeMap<String, String> {
    resource
        .as_ref()
        .unwrap()
        .attributes
        .iter()
        .map(|kv| {
            let Some(Value::StringValue(value)) = kv.value.as_ref().unwrap().value.as_ref() else {
                panic!("expected string resource attribute")
            };
            (kv.key.clone(), value.clone())
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn providers_export_consistent_identity_and_respect_signal_opt_in() {
    let receiver = Receiver::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let services = receiver.clone();
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(MetricsServiceServer::new(services.clone()))
            .add_service(LogsServiceServer::new(services))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    for (mode, expected_metrics, expected_logs) in [
        ("both", true, true),
        ("metrics", true, false),
        ("logs", false, true),
        ("logs-disabled", true, false),
        ("metrics-disabled", false, true),
        ("disabled", false, false),
        ("unconfigured", false, false),
    ] {
        let endpoint = endpoint.clone();
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "provider_probe", "--nocapture"])
                .env("PGROLES_EXPORT_PROBE", "1");
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("OTEL_") { command.env_remove(key); }
            }
            command.env("OTEL_RESOURCE_ATTRIBUTES", "service.name=attribute-name,service.instance.id=pod-uid,k8s.namespace.name=operators")
                .env("OTEL_SERVICE_NAME", "configured-operator");
            match mode {
                "both" => { command.env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint); }
                "metrics" => { command.env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", endpoint); }
                "logs" => { command.env("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", endpoint); }
                "logs-disabled" => { command.env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint).env("OTEL_LOGS_EXPORTER", "none"); }
                "metrics-disabled" => { command.env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint).env("OTEL_METRICS_EXPORTER", "none"); }
                "disabled" => { command.env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint).env("OTEL_METRICS_EXPORTER", "none").env("OTEL_LOGS_EXPORTER", "none"); }
                _ => {}
            }
            command.output().unwrap()
        }).await.unwrap();
        assert!(
            output.status.success(),
            "mode {mode}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let metrics = std::mem::take(&mut *receiver.metrics.lock().unwrap());
        let logs = std::mem::take(&mut *receiver.logs.lock().unwrap());
        assert_eq!(!metrics.is_empty(), expected_metrics, "{mode}");
        assert_eq!(!logs.is_empty(), expected_logs, "{mode}");
        let sdk_resource = opentelemetry_sdk::Resource::builder_empty()
            .with_detector(Box::new(
                opentelemetry_sdk::resource::TelemetryResourceDetector,
            ))
            .build();
        let expected = BTreeMap::from([
            ("telemetry.sdk.name".into(), "opentelemetry".into()),
            ("telemetry.sdk.language".into(), "rust".into()),
            (
                "telemetry.sdk.version".into(),
                sdk_resource
                    .get(&opentelemetry::Key::from_static_str(
                        "telemetry.sdk.version",
                    ))
                    .unwrap()
                    .to_string(),
            ),
            ("service.name".into(), "configured-operator".into()),
            ("service.version".into(), env!("CARGO_PKG_VERSION").into()),
            ("service.instance.id".into(), "pod-uid".into()),
            ("k8s.namespace.name".into(), "operators".into()),
        ]);
        for batch in metrics {
            for resource_metrics in batch.resource_metrics {
                assert_eq!(attributes(&resource_metrics.resource), expected);
                assert!(
                    resource_metrics
                        .scope_metrics
                        .iter()
                        .flat_map(|scope| &scope.metrics)
                        .any(|metric| metric.name == "pgroles.reconcile.total")
                );
            }
        }
        for batch in logs {
            for resource_logs in batch.resource_logs {
                assert_eq!(attributes(&resource_logs.resource), expected);
                assert!(
                    resource_logs
                        .scope_logs
                        .iter()
                        .flat_map(|scope| &scope.log_records)
                        .any(
                            |record| record.body.as_ref().and_then(|body| body.value.as_ref())
                                == Some(&Value::StringValue("resource identity probe".into()))
                        )
                );
            }
        }
    }
    server.abort();
}
