//! Print the JSON Schema for recorded review artifacts.
//!
//! `scripts/generate-manifest-metadata.sh` writes this to
//! `docs/public/generated/review-artifact.schema.json`, and
//! `scripts/check-manifest-metadata.sh` fails CI when it drifts.
//!
//! The schema describes what an importer accepts (the deserialization
//! contract, draft 2020-12). It cannot express the checks
//! `pgroles_core::review_artifact::parse_review_artifact` also performs: the
//! size limit, the ordered change-index partition, reachability-delta
//! consistency, and the review fingerprint.

use pgroles_core::review_artifact::{REVIEW_ARTIFACT_SCHEMA_VERSION, ReviewArtifact};
use schemars::{generate::SchemaSettings, json_schema};

fn main() -> Result<(), serde_json::Error> {
    let mut schema = SchemaSettings::draft2020_12()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<ReviewArtifact>();
    if let Some(properties) = schema
        .get_mut("properties")
        .and_then(serde_json::Value::as_object_mut)
    {
        properties.insert(
            "schema_version".into(),
            json_schema!({ "const": REVIEW_ARTIFACT_SCHEMA_VERSION }).into(),
        );
    }
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
