//! Resource identity shared by every telemetry provider in this process.

use std::sync::OnceLock;

use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::resource::{EnvResourceDetector, TelemetryResourceDetector};

/// Capture configuration once so providers cannot acquire different identities.
/// Environment attributes override application defaults; OTEL_SERVICE_NAME takes
/// final precedence over service.name, matching the SDK's nonempty-name behavior.
pub(crate) fn operator_resource() -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            let mut builder = Resource::builder_empty()
                .with_detector(Box::new(TelemetryResourceDetector))
                .with_attributes([
                    KeyValue::new("service.name", "pgroles-operator"),
                    KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                    KeyValue::new(
                        "service.instance.id",
                        format!("{:032x}", rand::random::<u128>()),
                    ),
                ])
                .with_detector(Box::new(EnvResourceDetector::new()));
            if let Ok(name) = std::env::var("OTEL_SERVICE_NAME")
                && !name.is_empty()
            {
                builder = builder.with_attribute(KeyValue::new("service.name", name));
            }
            builder.build()
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::Key;
    use std::collections::BTreeMap;
    use std::process::Command;

    // Child processes avoid unsafe mutation of process-global environment while
    // the other operator tests run concurrently.
    #[test]
    fn resource_probe() {
        if std::env::var_os("PGROLES_RESOURCE_PROBE").is_none() {
            return;
        }
        let resource = operator_resource();
        assert_eq!(resource, operator_resource());
        assert!(
            resource
                .get(&Key::from_static_str("service.instance.id"))
                .is_some()
        );
        let attributes: BTreeMap<_, _> = resource
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        println!(
            "RESOURCE_JSON={}",
            serde_json::to_string(&attributes).unwrap()
        );
    }

    fn probe(attributes: Option<&str>, service_name: Option<&str>) -> BTreeMap<String, String> {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "telemetry_resource::tests::resource_probe",
                "--nocapture",
            ])
            .env("PGROLES_RESOURCE_PROBE", "1")
            .env_remove("OTEL_RESOURCE_ATTRIBUTES")
            .env_remove("OTEL_SERVICE_NAME");
        if let Some(attributes) = attributes {
            command.env("OTEL_RESOURCE_ATTRIBUTES", attributes);
        }
        if let Some(service_name) = service_name {
            command.env("OTEL_SERVICE_NAME", service_name);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let json = stdout
            .lines()
            .find_map(|line| line.strip_prefix("RESOURCE_JSON="))
            .unwrap();
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn defaults_are_stable_within_process_and_distinct_between_processes() {
        let first = probe(None, None);
        let second = probe(None, None);
        assert_eq!(first["telemetry.sdk.name"], "opentelemetry");
        assert_eq!(first["telemetry.sdk.language"], "rust");
        let sdk_resource = Resource::builder_empty()
            .with_detector(Box::new(TelemetryResourceDetector))
            .build();
        assert_eq!(
            first["telemetry.sdk.version"],
            sdk_resource
                .get(&Key::from_static_str("telemetry.sdk.version"))
                .unwrap()
                .to_string()
        );
        assert_eq!(first["service.name"], "pgroles-operator");
        assert_eq!(first["service.version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(first["service.instance.id"].len(), 32);
        assert_ne!(first["service.instance.id"], second["service.instance.id"]);
    }

    #[test]
    fn environment_attributes_override_defaults_and_add_deployment_identity() {
        let resource = probe(
            Some(
                "service.name=custom,service.version=release,service.instance.id=pod-uid,k8s.namespace.name=operators",
            ),
            None,
        );
        assert_eq!(resource["service.name"], "custom");
        assert_eq!(resource["service.version"], "release");
        assert_eq!(resource["service.instance.id"], "pod-uid");
        assert_eq!(resource["k8s.namespace.name"], "operators");
    }

    #[test]
    fn dedicated_service_name_has_final_precedence() {
        assert_eq!(
            probe(Some("service.name=attribute"), Some("dedicated"))["service.name"],
            "dedicated"
        );
        assert_eq!(
            probe(Some("service.name=attribute"), Some(""))["service.name"],
            "attribute"
        );
        assert_eq!(probe(None, Some(""))["service.name"], "pgroles-operator");
    }
}
