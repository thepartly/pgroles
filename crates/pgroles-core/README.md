# pgroles-core

Core manifest, diff, SQL rendering, and export primitives for `pgroles`.

This crate contains the pure data-model and planning logic behind the `pgroles`
CLI and operator. It does not connect to PostgreSQL itself.

The default `passwords` feature enables password operations. Consumers using
`default-features = false` cannot use the public `scram` module,
`diff::resolve_passwords`, or `diff::inject_password_changes` APIs. Parsing,
planning, SQL rendering, visualization, and illustrative plan fingerprints
remain available without password generation, entropy, or environment-based
password resolution.

## What It Includes

- YAML manifest parsing and expansion
- Snapshot-free validation and compilation with structured diagnostics
- Normalized role graph types
- Convergent diff planning
- Version-aware SQL rendering via `SqlContext`
- Export of live state back into a flat manifest

## What It Does Not Include

- Database introspection
- CLI argument parsing
- Kubernetes reconciliation

## Typical Use

```rust
use pgroles_core::{authoring::prepare_policy, diff, model::RoleGraph, sql};

let yaml = r#"
roles:
  - name: analytics
    login: true
"#;

let prepared = prepare_policy(yaml)?;
let current = RoleGraph::default();

let changes = diff::plan_changes(
    &current,
    &prepared.desired,
    &prepared.manifest,
    &prepared.expanded,
    diff::ReconciliationMode::Authoritative,
);
let sql = sql::render_all_with_context(
    &changes,
    &sql::SqlContext {
        pg_major_version: 16,
        ..Default::default()
    },
);
assert!(sql.contains("CREATE ROLE"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`authoring::prepare_policy` shares parsing, expansion, and graph construction
between the CLI and browser tools. `authoring::validate_policy` and
`authoring::compile_policy` accept a versioned `PolicyRequest` containing only
YAML and return diagnostics for invalid input. Compilation exposes expanded
policy data and a normalized desired graph through serializable DTOs. Neither
operation resolves password-source declarations or checks live database authority.

Manifest metadata and authoring TypeScript contracts are generated from Rust
schemas by `scripts/generate-manifest-metadata.sh`; CI checks them with
`scripts/check-manifest-metadata.sh`. The docs use this metadata for static field
highlighting and load WASM only for interactive authoring or plan analysis.

## Related Crates

- [`pgroles-inspect`](https://crates.io/crates/pgroles-inspect): build the current `RoleGraph` from a live database
- [`pgroles-cli`](https://crates.io/crates/pgroles-cli): end-user CLI built on this crate

Full project documentation: <https://github.com/thepartly/pgroles>
