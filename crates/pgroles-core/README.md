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
use pgroles_core::{diff, manifest, model::RoleGraph, sql};

let yaml = r#"
roles:
  - name: analytics
    login: true
"#;

let policy = manifest::parse_manifest(yaml)?;
let expanded = manifest::expand_manifest(&policy)?;
let desired = RoleGraph::from_expanded(&expanded, policy.default_owner.as_deref())?;
let current = RoleGraph::default();

let changes = diff::diff(&current, &desired);
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

## Related Crates

- [`pgroles-inspect`](https://crates.io/crates/pgroles-inspect): build the current `RoleGraph` from a live database
- [`pgroles-cli`](https://crates.io/crates/pgroles-cli): end-user CLI built on this crate

Full project documentation: <https://github.com/thepartly/pgroles>
