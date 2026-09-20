use pgroles_core::{
    authoring::{CompileResponse, PolicyDiagnostic, PolicyRequest, ValidateResponse},
    manifest::PolicyManifest,
};
use schemars::{JsonSchema, Schema, generate::SchemaSettings, schema_for};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct ManifestMetadata {
    schema_version: &'static str,
    manifest_schema: schemars::Schema,
    contracts: BTreeMap<&'static str, schemars::Schema>,
}

fn serialization_schema<T: JsonSchema>() -> Schema {
    SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator()
        .into_root_schema_for::<T>()
}

fn main() -> Result<(), serde_json::Error> {
    let contracts = BTreeMap::from([
        ("PolicyRequest", schema_for!(PolicyRequest)),
        (
            "ValidateResponse",
            serialization_schema::<ValidateResponse>(),
        ),
        ("CompileResponse", serialization_schema::<CompileResponse>()),
        (
            "PolicyDiagnostic",
            serialization_schema::<PolicyDiagnostic>(),
        ),
    ]);
    let metadata = ManifestMetadata {
        schema_version: "pgroles.manifest-metadata.v1",
        manifest_schema: schema_for!(PolicyManifest),
        contracts,
    };
    println!("{}", serde_json::to_string_pretty(&metadata)?);
    Ok(())
}
