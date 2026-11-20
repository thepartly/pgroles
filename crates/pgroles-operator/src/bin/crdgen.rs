//! Generate CustomResourceDefinition files for pgroles CRDs.
//!
//! Usage: `cargo run --bin crdgen -- --output-dir charts/pgroles-operator/crds/`
//! Reference: `cargo run --bin crdgen -- --docs-dir docs/src/pages/docs/reference --schemas-dir docs/public/crd-reference`
//! Without --output-dir, prints all CRDs to stdout separated by `---`.

use std::path::PathBuf;

#[path = "crdgen/docs.rs"]
mod docs;

use kube::CustomResourceExt;
use pgroles_operator::crd::{
    EphemeralAccessPolicy, EphemeralAccessRequest, PostgresPolicy, PostgresPolicyPlan,
    postgres_policy_candidate_crd,
};
use pgroles_operator::database::PostgresDatabase;

struct CrdOutput {
    filename: &'static str,
    json: String,
}

fn generate() -> Vec<CrdOutput> {
    vec![
        CrdOutput {
            filename: "postgresdatabases.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&PostgresDatabase::crd())
                .expect("PostgresDatabase CRD should serialize"),
        },
        CrdOutput {
            filename: "postgrespolicies.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&PostgresPolicy::crd())
                .expect("PostgresPolicy CRD should serialize"),
        },
        CrdOutput {
            filename: "postgrespolicyplans.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&PostgresPolicyPlan::crd())
                .expect("PostgresPolicyPlan CRD should serialize"),
        },
        // Generated through `postgres_policy_candidate_crd()`, not
        // `PostgresPolicyCandidate::crd()`: the candidate's `spec.content`
        // must carry no OpenAPI defaults (ADR-001, Decision 2).
        CrdOutput {
            filename: "postgrespolicycandidates.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&postgres_policy_candidate_crd())
                .expect("PostgresPolicyCandidate CRD should serialize"),
        },
        CrdOutput {
            filename: "ephemeralaccesspolicies.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&EphemeralAccessPolicy::crd())
                .expect("EphemeralAccessPolicy CRD should serialize"),
        },
        CrdOutput {
            filename: "ephemeralaccessrequests.pgroles.io.yaml",
            json: serde_json::to_string_pretty(&EphemeralAccessRequest::crd())
                .expect("EphemeralAccessRequest CRD should serialize"),
        },
    ]
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Some(pos) = args.iter().position(|a| a == "--docs-dir") {
        let dir = PathBuf::from(args.get(pos + 1).expect("--docs-dir requires a path"));
        let schema_pos = args
            .iter()
            .position(|a| a == "--schemas-dir")
            .expect("--docs-dir also requires --schemas-dir");
        let schema_dir = PathBuf::from(
            args.get(schema_pos + 1)
                .expect("--schemas-dir requires a path"),
        );
        // Validate all schemas before writing any output.
        let pages: Vec<_> = generate()
            .iter()
            .flat_map(|crd| {
                docs::render(&serde_json::from_str(&crd.json).expect("generated CRD should parse"))
                    .unwrap_or_else(|error| {
                        panic!("{error}; add the description to the Rust schema source")
                    })
            })
            .collect();
        std::fs::create_dir_all(&dir).expect("failed to create docs directory");
        for (name, body) in pages {
            std::fs::write(dir.join(name), body).expect("failed to write CRD reference");
        }
        std::fs::create_dir_all(&schema_dir).expect("failed to create schema directory");
        for crd in generate() {
            for (name, body) in docs::schemas(&serde_json::from_str(&crd.json).unwrap()).unwrap() {
                std::fs::write(schema_dir.join(name), body)
                    .expect("failed to write schema download");
            }
        }
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--output-dir") {
        let dir = PathBuf::from(args.get(pos + 1).expect("--output-dir requires a path"));
        std::fs::create_dir_all(&dir).expect("failed to create output directory");
        for crd in generate() {
            let path = dir.join(crd.filename);
            std::fs::write(&path, format!("{}\n", crd.json))
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            eprintln!("wrote {}", path.display());
        }
    } else {
        let crds = generate();
        for (i, crd) in crds.iter().enumerate() {
            if i > 0 {
                println!("---");
            }
            println!("{}", crd.json);
        }
    }
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;
    use pgroles_operator::crd::{
        EphemeralAccessPolicy, EphemeralAccessRequest, PostgresPolicy, PostgresPolicyPlan,
        postgres_policy_candidate_crd,
    };

    #[test]
    fn policy_crd_serializes_to_json() {
        let crd = PostgresPolicy::crd();
        let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize");
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"PostgresPolicy\""));
    }

    #[test]
    fn plan_crd_serializes_to_json() {
        let crd = PostgresPolicyPlan::crd();
        let json = serde_json::to_string_pretty(&crd).expect("CRD should serialize");
        assert!(json.contains("\"apiVersion\""));
        assert!(json.contains("\"PostgresPolicyPlan\""));
        assert!(json.contains("\"pgplan\""));
    }

    #[test]
    fn candidate_crd_serializes_to_json() {
        let json = serde_json::to_string_pretty(&postgres_policy_candidate_crd())
            .expect("CRD should serialize");
        assert!(json.contains("\"PostgresPolicyCandidate\""));
        assert!(json.contains("\"pgcand\""));
        assert!(json.contains("self == oldSelf"));
    }

    #[test]
    fn ephemeral_crds_serialize_to_json() {
        let policy = serde_json::to_string_pretty(&EphemeralAccessPolicy::crd())
            .expect("policy CRD should serialize");
        assert!(policy.contains("\"apiVersion\""));
        assert!(policy.contains("\"EphemeralAccessPolicy\""));

        let request = serde_json::to_string_pretty(&EphemeralAccessRequest::crd())
            .expect("request CRD should serialize");
        assert!(request.contains("\"apiVersion\""));
        assert!(request.contains("\"EphemeralAccessRequest\""));
        assert!(request.contains("x-kubernetes-validations"));
    }
}
