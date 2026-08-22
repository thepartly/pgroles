//! CLI integration tests for pgroles.
//!
//! These tests exercise the compiled binary via `assert_cmd`, verifying
//! exit codes, stdout, and stderr for all subcommands. Only the `validate`
//! subcommand can be tested without a live database — the others are
//! `#[ignore]`d for CI integration-test stage.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::{NamedTempFile, TempDir};

use std::io::Write;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a temp file with the given contents and return it.
/// The file stays alive as long as the returned `NamedTempFile` is in scope.
fn write_temp_manifest(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("failed to write temp manifest");
    file.flush().expect("failed to flush temp manifest");
    file
}

fn write_temp_bundle(bundle: &str, documents: &[(&str, &str)]) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("failed to create temp bundle dir");
    let bundle_path = dir.path().join("bundle.yaml");
    std::fs::write(&bundle_path, bundle).expect("failed to write bundle file");

    for (name, content) in documents {
        std::fs::write(dir.path().join(name), content).expect("failed to write policy document");
    }

    (dir, bundle_path)
}

fn pgroles_cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("pgroles")
}

// ---------------------------------------------------------------------------
// Manifest fixtures
// ---------------------------------------------------------------------------

const VALID_MINIMAL: &str = r#"
default_owner: app_owner

roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: pgroles_test }
"#;

const VALID_PROFILES: &str = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
  viewer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]

roles:
  - name: app-service
    login: true

grants:
  - role: app-service
    privileges: [CONNECT]
    object: { type: database, name: pgroles_test }

memberships:
  - role: inventory-editor
    members:
      - name: app-service
"#;

const INVALID_YAML: &str = r#"
this is: [not: valid yaml: [[
"#;

const UNDEFINED_PROFILE: &str = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: myschema
    profiles: [nonexistent]
"#;

const EMPTY_MANIFEST: &str = r#"
roles: []
"#;

// =========================================================================
// validate subcommand
// =========================================================================

#[test]
fn validate_valid_minimal_manifest() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("1 role(s) defined"))
        .stdout(predicate::str::contains("1 grant(s) defined"));
}

#[test]
fn validate_valid_profiles_manifest() {
    let manifest_file = write_temp_manifest(VALID_PROFILES);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("4 role(s) defined"));
}

#[test]
fn validate_empty_manifest() {
    let manifest_file = write_temp_manifest(EMPTY_MANIFEST);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"))
        .stdout(predicate::str::contains("0 role(s) defined"));
}

#[test]
fn validate_invalid_yaml() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn validate_undefined_profile() {
    let manifest_file = write_temp_manifest(UNDEFINED_PROFILE);

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nonexistent"));
}

#[test]
fn validate_duplicate_schema_name() {
    let manifest_file = write_temp_manifest(
        r#"
schemas:
  - name: inventory
    profiles: []
  - name: inventory
    owner: inventory_owner
    profiles: []
"#,
    );

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("duplicate schema name"))
        .stderr(predicate::str::contains("inventory"));
}

#[test]
fn validate_bundle_with_split_schema_ownership() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
        &[
            (
                "platform.yaml",
                r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#,
            ),
            (
                "app.yaml",
                r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
"#,
            ),
        ],
    );

    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "validate",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Policy bundle is valid"))
        .stdout(predicate::str::contains("2 source document(s) loaded"))
        .stdout(predicate::str::contains("2 role(s) defined"));
}

#[test]
fn validate_bundle_rejects_role_outside_scope() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
sources:
  - file: app.yaml
"#,
        &[(
            "app.yaml",
            r#"
roles:
  - name: app
    login: true
"#,
        )],
    );

    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "validate",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "defines role \"app\" outside its declared scope",
        ));
}

// =========================================================================
// render-bundle subcommand
// =========================================================================

const RENDER_BUNDLE_YAML: &str = r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE]
          object: { type: table, name: "*" }
sources:
  - file: platform.yaml
  - file: app.yaml
"#;

const RENDER_BUNDLE_PLATFORM: &str = r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#;

const RENDER_BUNDLE_APP: &str = r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
"#;

#[test]
fn render_bundle_emits_composed_manifest_with_header() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "# Rendered by `pgroles render-bundle`.",
        ))
        .stdout(predicate::str::contains(
            "# Do not edit by hand — regenerate from the source bundle.",
        ))
        .stdout(predicate::str::contains("#   - platform.yaml (platform)"))
        .stdout(predicate::str::contains("#   - app.yaml (app)"))
        // Composed manifest content
        .stdout(predicate::str::contains("app_owner"))
        .stdout(predicate::str::contains("inventory"))
        .stdout(predicate::str::contains("editor"));
}

#[test]
fn render_bundle_output_round_trips_through_validate() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    let rendered_file = NamedTempFile::new().expect("failed to create temp output file");

    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--output",
            rendered_file.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // The rendered manifest must validate as a regular flat manifest.
    pgroles_cmd()
        .args(["validate", "--file", rendered_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid."));
}

#[test]
fn render_bundle_no_header_omits_comment_block() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--no-header",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("# Rendered by").not());
}

#[test]
fn render_bundle_header_uses_only_basename_for_determinism() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    let stdout = pgroles_cmd()
        .args(["render-bundle", "--bundle", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(stdout).expect("stdout not utf-8");

    // The header MUST NOT contain the per-machine tempdir path; only the
    // bundle file's basename. Otherwise the committed render would diff
    // every time a developer runs the command from a different cwd.
    let tempdir_path = bundle_path
        .parent()
        .expect("bundle has parent")
        .display()
        .to_string();
    assert!(
        !rendered.contains(&tempdir_path),
        "rendered output leaked filesystem path {tempdir_path:?}: {rendered}"
    );
    assert!(rendered.contains("# Source bundle: bundle.yaml"));
}

#[test]
fn render_bundle_output_strips_defaults() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args(["render-bundle", "--bundle", bundle_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("auth_providers:").not())
        .stdout(predicate::str::contains("memberships: []").not())
        .stdout(predicate::str::contains("retirements: []").not())
        .stdout(predicate::str::contains("login: null").not())
        .stdout(predicate::str::contains("role_pattern:").not());
}

#[test]
fn render_bundle_check_succeeds_when_file_matches() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    let rendered_file = NamedTempFile::new().expect("failed to create temp output file");

    // First, render to a file.
    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--output",
            rendered_file.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Then verify --check confirms it matches.
    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--check",
            rendered_file.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn render_bundle_check_exits_two_on_drift() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    let stale_file = write_temp_manifest("# intentionally stale\nroles: []\n");

    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--check",
            stale_file.path().to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("rendered bundle differs from"));
}

#[test]
fn render_bundle_check_conflicts_with_output() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        RENDER_BUNDLE_YAML,
        &[
            ("platform.yaml", RENDER_BUNDLE_PLATFORM),
            ("app.yaml", RENDER_BUNDLE_APP),
        ],
    );
    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "render-bundle",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--output",
            "/tmp/never.yaml",
            "--check",
            "/tmp/also-never.yaml",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn render_bundle_fails_on_scope_conflict() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
sources:
  - file: app.yaml
"#,
        &[(
            "app.yaml",
            r#"
roles:
  - name: out_of_scope_role
    login: true
"#,
        )],
    );
    let _keep_dir = bundle_dir;

    // No scope declared, so the role is out of scope and validation should fail
    // *before* anything is emitted.
    pgroles_cmd()
        .args(["render-bundle", "--bundle", bundle_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("outside its declared scope"));
}

// =========================================================================
// graph subcommand
// =========================================================================

#[test]
fn graph_desired_tree_renders_managed_roles() {
    let manifest_file = write_temp_manifest(VALID_PROFILES);

    pgroles_cmd()
        .args([
            "graph",
            "desired",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--format",
            "tree",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("inventory-editor"))
        .stdout(predicate::str::contains("catalog-viewer"))
        .stdout(predicate::str::contains("app-service"));
}

#[test]
fn graph_desired_bundle_tree_renders_composed_roles() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
        &[
            (
                "platform.yaml",
                r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#,
            ),
            (
                "app.yaml",
                r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
"#,
            ),
        ],
    );
    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "graph",
            "desired",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
            "--format",
            "tree",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("inventory-editor"))
        .stdout(predicate::str::contains("app_owner"));
}

#[test]
fn graph_desired_bundle_json_includes_managed_scope_metadata() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
        &[
            (
                "platform.yaml",
                r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#,
            ),
            (
                "app.yaml",
                r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
"#,
            ),
        ],
    );
    let _keep_dir = bundle_dir;

    let output = pgroles_cmd()
        .args([
            "graph",
            "desired",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value =
        serde_json::from_slice(&output).expect("graph json should parse");
    assert_eq!(parsed["schema_version"], "pgroles.visual_graph.v1");
    assert_eq!(parsed["meta"]["managed_scope"]["roles"][0], "app_owner");
    assert_eq!(
        parsed["meta"]["managed_scope"]["schemas"][0]["name"],
        "inventory"
    );
    assert_eq!(parsed["meta"]["managed_scope"]["schemas"][0]["owner"], true);
}

#[test]
fn graph_desired_output_file_writes_requested_format() {
    let manifest_file = write_temp_manifest(VALID_PROFILES);
    let output_dir = tempfile::tempdir().expect("failed to create temp output dir");
    let output_path = output_dir.path().join("graph.json");

    pgroles_cmd()
        .args([
            "graph",
            "desired",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--format",
            "json",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let graph_json =
        std::fs::read_to_string(&output_path).expect("failed to read rendered graph output");
    assert!(graph_json.contains("\"inventory-editor\""));
    assert!(graph_json.contains("\"catalog-viewer\""));
}

#[test]
fn graph_current_managed_requires_file() {
    pgroles_cmd()
        .args([
            "graph",
            "current",
            "--database-url",
            "postgres://unused",
            "--scope",
            "managed",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--file or --bundle is required when --scope=managed",
        ));
}

#[test]
fn validate_nonexistent_file() {
    pgroles_cmd()
        .args([
            "validate",
            "--file",
            "/tmp/nonexistent-pgroles-test-xyz.yaml",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read manifest file"));
}

#[test]
fn validate_default_file_not_found() {
    // Running `pgroles validate` without --file should look for pgroles.yaml
    // in the current directory, which won't exist in a temp dir.
    pgroles_cmd()
        .current_dir(std::env::temp_dir())
        .args(["validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read manifest file"));
}

// =========================================================================
// --mode flag parsing
// =========================================================================

#[test]
fn diff_accepts_mode_authoritative() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    // Should parse without error (will fail on DB connect, not on arg parsing)
    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "authoritative",
        ])
        .assert()
        .failure()
        // Fails on DB connect, not on arg parsing — proving the flag was accepted
        .stderr(predicate::str::contains("database-url").not())
        .stderr(predicate::str::contains("invalid value").not());
}

#[test]
fn diff_accepts_mode_additive() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "additive",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").not());
}

#[test]
fn diff_accepts_mode_adopt() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "adopt",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").not());
}

#[test]
fn diff_rejects_invalid_mode() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "yolo",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn apply_accepts_mode_additive() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "apply",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "additive",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").not());
}

#[test]
fn apply_accepts_mode_adopt() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "apply",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--mode",
            "adopt",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid value").not());
}

#[test]
fn diff_help_shows_mode_flag() {
    pgroles_cmd()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--mode"))
        .stdout(predicate::str::contains("authoritative"))
        .stdout(predicate::str::contains("additive"))
        .stdout(predicate::str::contains("adopt"));
}

#[test]
fn apply_help_shows_mode_flag() {
    pgroles_cmd()
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--mode"))
        .stdout(predicate::str::contains("authoritative"))
        .stdout(predicate::str::contains("additive"))
        .stdout(predicate::str::contains("adopt"));
}

// =========================================================================
// Global CLI behaviour
// =========================================================================

#[test]
fn no_subcommand_shows_help() {
    // clap should show an error/help message when no subcommand is given.
    pgroles_cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn help_flag() {
    pgroles_cmd()
        .args(["--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pgroles"))
        .stdout(predicate::str::contains("validate"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("reconcile"));
}

#[test]
fn version_flag() {
    pgroles_cmd()
        .args(["--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pgroles"));
}

#[test]
fn validate_help() {
    pgroles_cmd()
        .args(["validate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Validate"))
        .stdout(predicate::str::contains("--file"));
}

#[test]
fn diff_help() {
    pgroles_cmd()
        .args(["diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--file"))
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--no-exit-code"));
}

#[test]
fn apply_help() {
    pgroles_cmd()
        .args(["apply", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--dry-run"));
}

#[test]
fn inspect_help() {
    pgroles_cmd()
        .args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"));
}

#[test]
fn reconcile_help() {
    pgroles_cmd()
        .args(["reconcile", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PostgresPolicy"))
        .stdout(predicate::str::contains("--namespace"))
        .stdout(predicate::str::contains("--wait"))
        .stdout(predicate::str::contains("--timeout"));
}

#[test]
fn reconcile_rejects_unsupported_kind_before_kube_client_setup() {
    pgroles_cmd()
        .args(["reconcile", "secret/db"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "unsupported reconcile resource kind",
        ));
}

#[test]
fn plan_alias_for_diff() {
    // `plan` should be an alias for `diff` — verify it shows the same help.
    pgroles_cmd()
        .args(["plan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--format"));
}

// =========================================================================
// generate subcommand — no DB
// =========================================================================

#[test]
fn generate_help() {
    pgroles_cmd()
        .args(["generate", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--database-url"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--suggest-profiles"))
        .stdout(predicate::str::contains("--suggest-min-schemas"));
}

#[test]
fn generate_suggest_min_schemas_requires_suggest_profiles() {
    // The flag is gated by clap's `requires`. Passing it alone must fail.
    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args([
            "generate",
            "--suggest-min-schemas",
            "1",
            "--database-url",
            "postgres://nowhere/",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("suggest"));
}

#[test]
fn generate_missing_database_url() {
    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["generate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

// =========================================================================
// diff/plan subcommand — requires DB (ignored by default)
// =========================================================================

#[test]
fn diff_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    // No DATABASE_URL env var and no --database-url flag → should fail
    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["diff", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

#[test]
fn apply_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["apply", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

#[test]
fn inspect_missing_database_url() {
    let manifest_file = write_temp_manifest(VALID_MINIMAL);

    pgroles_cmd()
        .env_remove("DATABASE_URL")
        .args(["inspect", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("database-url"));
}

// =========================================================================
// validate subcommand — password validation errors
// =========================================================================

#[test]
fn validate_rejects_password_on_nologin_role() {
    let manifest_file = write_temp_manifest(
        r#"
roles:
  - name: no_login_role
    password:
      from_env: SOME_VAR
"#,
    );

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no_login_role"))
        .stderr(predicate::str::contains("password").or(predicate::str::contains("login")));
}

#[test]
fn validate_rejects_invalid_password_valid_until() {
    let manifest_file = write_temp_manifest(
        r#"
roles:
  - name: expiring_role
    login: true
    password:
      from_env: SOME_VAR
    password_valid_until: "2025-13-01"
"#,
    );

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("expiring_role"))
        .stderr(
            predicate::str::contains("password_valid_until")
                .or(predicate::str::contains("ISO 8601")),
        );
}

#[test]
fn validate_accepts_role_with_password() {
    let manifest_file = write_temp_manifest(
        r#"
roles:
  - name: good_role
    login: true
    password:
      from_env: SOME_VAR
    password_valid_until: "2026-12-31T00:00:00Z"
"#,
    );

    pgroles_cmd()
        .args(["validate", "--file", manifest_file.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Manifest is valid"));
}

// =========================================================================
// diff/apply/inspect with invalid manifest (should fail before DB connect)
// =========================================================================

#[test]
fn diff_with_invalid_manifest() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn diff_with_invalid_manifest_accepts_no_exit_code_flag() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args([
            "diff",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
            "--no-exit-code",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn diff_with_invalid_bundle_fails_before_connecting() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
sources:
  - file: app.yaml
"#,
        &[(
            "app.yaml",
            r#"
roles:
  - name: app
    login: true
"#,
        )],
    );

    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "diff",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "defines role \"app\" outside its declared scope",
        ));
}

#[test]
fn apply_with_invalid_manifest() {
    let manifest_file = write_temp_manifest(INVALID_YAML);

    pgroles_cmd()
        .args([
            "apply",
            "--file",
            manifest_file.path().to_str().unwrap(),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("YAML parse error"));
}

#[test]
fn apply_with_invalid_bundle_fails_before_connecting() {
    let (bundle_dir, bundle_path) = write_temp_bundle(
        r#"
sources:
  - file: app.yaml
"#,
        &[(
            "app.yaml",
            r#"
roles:
  - name: app
    login: true
"#,
        )],
    );

    let _keep_dir = bundle_dir;

    pgroles_cmd()
        .args([
            "apply",
            "--bundle",
            bundle_path.to_str().expect("bundle path should be utf-8"),
            "--database-url",
            "postgres://localhost/test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "defines role \"app\" outside its declared scope",
        ));
}

// =========================================================================
// Integration tests requiring a live database — #[ignore]d
// =========================================================================

/// These tests require a running PostgreSQL instance.
/// Set DATABASE_URL before running:
///   DATABASE_URL=postgres://localhost/pgroles_test cargo test -- --ignored
mod live_db {
    use super::*;
    use sqlx::postgres::{PgConnectOptions, PgConnection};
    use sqlx::{Connection, Executor, PgPool, Row};
    use std::str::FromStr;
    use tokio::runtime::Runtime;

    fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
        Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(future)
    }

    fn database_url() -> String {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
    }

    fn database_url_for_role(role: &str, password: &str) -> String {
        let base = database_url();
        let scheme_end = base
            .find("://")
            .map(|index| index + 3)
            .expect("DATABASE_URL should include a scheme");
        let auth_end = base[scheme_end..]
            .find('@')
            .map(|index| scheme_end + index)
            .expect("DATABASE_URL should include credentials");

        format!(
            "{}{}:{}{}",
            &base[..scheme_end],
            role,
            password,
            &base[auth_end..]
        )
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        format!("{prefix}_{nanos}")
    }

    fn execute_sql(sql: &str) {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pool.execute(sql)
                .await
                .expect("failed to execute setup SQL");
        });
    }

    fn query_membership_flags(role: &str, member: &str) -> (bool, bool) {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                r#"
                SELECT m.admin_option, m.inherit_option
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                WHERE gr.rolname = $1 AND mr.rolname = $2
                "#,
            )
            .bind(role)
            .bind(member)
            .fetch_one(&pool)
            .await
            .expect("failed to query membership flags");
            (row.get("admin_option"), row.get("inherit_option"))
        })
    }

    fn query_has_function_privilege(role: &str, signature: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query("SELECT has_function_privilege($1, $2, 'EXECUTE') AS allowed")
                .bind(role)
                .bind(signature)
                .fetch_one(&pool)
                .await
                .expect("failed to query function privilege");
            row.get("allowed")
        })
    }

    fn query_has_relation_privilege(role: &str, relation: &str, privilege: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query("SELECT has_table_privilege($1, $2, $3) AS allowed")
                .bind(role)
                .bind(relation)
                .bind(privilege)
                .fetch_one(&pool)
                .await
                .expect("failed to query relation privilege");
            row.get("allowed")
        })
    }

    fn query_drop_role_safety(role: &str) -> pgroles_inspect::DropRoleSafetyReport {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pgroles_inspect::inspect_drop_role_safety(&pool, &[role.to_string()])
                .await
                .expect("failed to inspect role-drop safety")
        })
    }

    fn query_role_exists(role: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row =
                sqlx::query("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1) AS present")
                    .bind(role)
                    .fetch_one(&pool)
                    .await
                    .expect("failed to query role existence");
            row.get("present")
        })
    }

    fn query_role_login_and_inherit(role: &str) -> Option<(bool, bool)> {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row =
                sqlx::query("SELECT rolcanlogin, rolinherit FROM pg_roles WHERE rolname = $1")
                    .bind(role)
                    .fetch_optional(&pool)
                    .await
                    .expect("failed to query role attributes");
            row.map(|row| (row.get("rolcanlogin"), row.get("rolinherit")))
        })
    }

    fn query_schema_owner(schema: &str) -> Option<String> {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                "SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = $1",
            )
            .bind(schema)
            .fetch_optional(&pool)
            .await
            .expect("failed to query schema owner");
            row.map(|row| row.get("owner"))
        })
    }

    fn query_table_owner(schema: &str, table: &str) -> Option<String> {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                r#"
                SELECT pg_get_userbyid(c.relowner) AS owner
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = $1
                  AND c.relname = $2
                  AND c.relkind IN ('r', 'p')
                "#,
            )
            .bind(schema)
            .bind(table)
            .fetch_optional(&pool)
            .await
            .expect("failed to query table owner");
            row.map(|row| row.get("owner"))
        })
    }

    fn query_default_acl_owner(schema: &str, grantee: &str, object_type: &str) -> Option<String> {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                r#"
                SELECT owner_role.rolname AS owner
                FROM pg_default_acl da
                JOIN pg_roles owner_role ON owner_role.oid = da.defaclrole
                JOIN pg_namespace n ON n.oid = da.defaclnamespace
                CROSS JOIN LATERAL aclexplode(da.defaclacl) AS acl
                JOIN pg_roles grantee_role ON grantee_role.oid = acl.grantee
                WHERE n.nspname = $1
                  AND grantee_role.rolname = $2
                  AND da.defaclobjtype::text = $3
                LIMIT 1
                "#,
            )
            .bind(schema)
            .bind(grantee)
            .bind(object_type)
            .fetch_optional(&pool)
            .await
            .expect("failed to query default privilege owner");
            row.map(|row| row.get("owner"))
        })
    }

    fn query_has_database_privilege(role: &str, database: &str, privilege: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query("SELECT has_database_privilege($1, $2, $3) AS allowed")
                .bind(role)
                .bind(database)
                .bind(privilege)
                .fetch_one(&pool)
                .await
                .expect("failed to query database privilege");
            row.get("allowed")
        })
    }

    fn query_has_schema_privilege(role: &str, schema: &str, privilege: &str) -> bool {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query("SELECT has_schema_privilege($1, $2, $3) AS allowed")
                .bind(role)
                .bind(schema)
                .bind(privilege)
                .fetch_one(&pool)
                .await
                .expect("failed to query schema privilege");
            row.get("allowed")
        })
    }

    async fn open_role_connection(role: &str, password: &str) -> PgConnection {
        let options = PgConnectOptions::from_str(&database_url())
            .expect("failed to parse DATABASE_URL")
            .username(role)
            .password(password);
        PgConnection::connect_with(&options)
            .await
            .expect("failed to connect as retired role")
    }

    struct TestDbCleanup {
        sql: String,
    }

    impl TestDbCleanup {
        fn new(sql: String) -> Self {
            Self { sql }
        }
    }

    impl Drop for TestDbCleanup {
        fn drop(&mut self) {
            execute_sql(&self.sql);
        }
    }

    #[test]
    #[ignore]
    fn graph_current_all_renders_live_roles() {
        let live_role = unique_name("graph_all_role");
        let _cleanup = TestDbCleanup::new(format!(r#"DROP ROLE IF EXISTS "{live_role}";"#));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{live_role}";
            CREATE ROLE "{live_role}" LOGIN;
            "#
        ));

        pgroles_cmd()
            .args([
                "graph",
                "current",
                "--database-url",
                &database_url(),
                "--scope",
                "all",
                "--format",
                "tree",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains(live_role.as_str()));
    }

    #[test]
    #[ignore]
    fn graph_current_managed_scopes_to_manifest_roles() {
        let managed_role = unique_name("graph_managed_role");
        let extra_role = unique_name("graph_extra_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{managed_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{managed_role}";
            CREATE ROLE "{managed_role}" LOGIN;
            CREATE ROLE "{extra_role}" LOGIN;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {managed_role}
    login: true
"#
        ));

        pgroles_cmd()
            .args([
                "graph",
                "current",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--scope",
                "managed",
                "--format",
                "tree",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains(managed_role.as_str()))
            .stdout(predicate::str::contains(extra_role.as_str()).not());
    }

    #[test]
    #[ignore]
    fn diff_bundle_owner_only_scope_ignores_unmanaged_schema_grants() {
        let schema = unique_name("bundle_owner_schema");
        let owner_role = unique_name("bundle_owner");
        let extra_role = unique_name("bundle_extra");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            CREATE ROLE "{owner_role}" NOLOGIN;
            CREATE ROLE "{extra_role}" NOLOGIN;
            CREATE SCHEMA "{schema}" AUTHORIZATION "{owner_role}";
            GRANT USAGE ON SCHEMA "{schema}" TO "{extra_role}";
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: platform.yaml
"#,
            &[(
                "platform.yaml",
                &format!(
                    r#"
policy:
  name: platform
scope:
  roles: [{owner_role}]
  schemas:
    - name: {schema}
      facets: [owner]
roles:
  - name: {owner_role}
    login: false
schemas:
  - name: {schema}
    owner: {owner_role}
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--format",
                "sql",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"))
            .stdout(predicate::str::contains("REVOKE").not());
    }

    #[test]
    #[ignore]
    fn apply_bundle_owner_only_scope_ignores_unmanaged_schema_grants() {
        let schema = unique_name("bundle_apply_owner_schema");
        let owner_role = unique_name("bundle_apply_owner");
        let extra_role = unique_name("bundle_apply_extra");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{extra_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            CREATE ROLE "{owner_role}" NOLOGIN;
            CREATE ROLE "{extra_role}" NOLOGIN;
            CREATE SCHEMA "{schema}" AUTHORIZATION "{owner_role}";
            GRANT USAGE ON SCHEMA "{schema}" TO "{extra_role}";
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: platform.yaml
"#,
            &[(
                "platform.yaml",
                &format!(
                    r#"
policy:
  name: platform
scope:
  roles: [{owner_role}]
  schemas:
    - name: {schema}
      facets: [owner]
roles:
  - name: {owner_role}
    login: false
schemas:
  - name: {schema}
    owner: {owner_role}
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "apply",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        assert!(
            query_has_schema_privilege(&extra_role, &schema, "USAGE"),
            "owner-only bundle scope should not revoke unmanaged schema grants"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn apply_bundle_revokes_removed_database_grants_for_managed_role() {
        let managed_role = unique_name("bundle_db_role");
        let _cleanup = TestDbCleanup::new(format!(r#"DROP ROLE IF EXISTS "{managed_role}";"#));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{managed_role}";
            CREATE ROLE "{managed_role}" NOLOGIN;
            GRANT CREATE ON DATABASE pgroles_test TO "{managed_role}";
            "#
        ));

        assert!(
            query_has_database_privilege(&managed_role, "pgroles_test", "CREATE"),
            "test setup should grant database create privilege"
        );

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: app.yaml
"#,
            &[(
                "app.yaml",
                &format!(
                    r#"
policy:
  name: app
scope:
  roles: [{managed_role}]
roles:
  - name: {managed_role}
    login: false
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "apply",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("1 grant(s) to revoke"));

        assert!(
            !query_has_database_privilege(&managed_role, "pgroles_test", "CREATE"),
            "bundle apply should revoke removed database grants for managed roles"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn diff_rejects_database_grant_for_a_different_database() {
        let other_database = unique_name("other_database");
        let manifest = write_temp_manifest(&format!(
            r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [CONNECT]
    object: {{ type: database, name: {other_database} }}
"#
        ));

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--no-exit-code",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(&other_database))
            .stderr(predicate::str::contains("pgroles_test"))
            .stderr(predicate::str::contains(
                "reconciles database ACLs only for the connected database",
            ));
    }

    #[test]
    #[ignore]
    fn apply_bundle_with_split_schema_ownership_converges() {
        let schema = unique_name("bundle_split_schema");
        let owner_role = unique_name("bundle_split_owner");
        let generated_role = format!("{schema}-editor");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
        - privileges: [SELECT]
          object: { type: table, name: "*" }
      default_privileges:
        - privileges: [SELECT]
          on_type: table
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
            &[
                (
                    "platform.yaml",
                    &format!(
                        r#"
policy:
  name: platform
scope:
  roles: [{owner_role}]
  schemas:
    - name: {schema}
      facets: [owner]
roles:
  - name: {owner_role}
    login: false
schemas:
  - name: {schema}
    owner: {owner_role}
"#
                    ),
                ),
                (
                    "app.yaml",
                    &format!(
                        r#"
policy:
  name: app
scope:
  schemas:
    - name: {schema}
      facets: [bindings]
schemas:
  - name: {schema}
    profiles: [editor]
"#
                    ),
                ),
            ],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "apply",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Applied"))
            .stdout(predicate::str::contains("No changes needed").not());

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(owner_role.as_str()),
            "bundle apply should create the schema with the platform-owned owner"
        );
        assert!(
            query_role_exists(&generated_role),
            "bundle apply should create generated profile roles"
        );
        assert!(
            query_has_schema_privilege(&generated_role, &schema, "USAGE"),
            "bundle apply should grant schema usage from the binding profile"
        );
        assert_eq!(
            query_default_acl_owner(&schema, &generated_role, "r").as_deref(),
            Some(owner_role.as_str()),
            "bundle apply should bind default privileges to the declared schema owner"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn additive_mode_bundle_skips_owner_bound_default_privileges_when_transfer_is_skipped() {
        let schema = unique_name("bundle_additive_schema");
        let old_owner = unique_name("bundle_old_owner");
        let new_owner = unique_name("bundle_new_owner");
        let generated_role = format!("{schema}-editor");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            CREATE ROLE "{old_owner}";
            CREATE ROLE "{new_owner}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{old_owner}";
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
      default_privileges:
        - privileges: [SELECT]
          on_type: table
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
            &[
                (
                    "platform.yaml",
                    &format!(
                        r#"
policy:
  name: platform
scope:
  roles: [{new_owner}]
  schemas:
    - name: {schema}
      facets: [owner]
roles:
  - name: {new_owner}
schemas:
  - name: {schema}
    owner: {new_owner}
"#
                    ),
                ),
                (
                    "app.yaml",
                    &format!(
                        r#"
policy:
  name: app
scope:
  schemas:
    - name: {schema}
      facets: [bindings]
schemas:
  - name: {schema}
    profiles: [editor]
"#
                    ),
                ),
            ],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "apply",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Applied: 2 change(s)"))
            .stdout(predicate::str::contains("1 role(s) to create"))
            .stdout(predicate::str::contains("1 grant(s) to add"))
            .stdout(predicate::str::contains("No changes needed").not());

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(old_owner.as_str()),
            "additive bundle apply should not transfer schema ownership"
        );
        assert!(
            query_role_exists(&generated_role),
            "additive bundle apply should still create generated binding roles"
        );
        assert!(
            query_has_schema_privilege(&generated_role, &schema, "USAGE"),
            "additive bundle apply should still grant non-owner-bound schema privileges"
        );
        assert_eq!(
            query_default_acl_owner(&schema, &generated_role, "r"),
            None,
            "owner-bound default privileges should be skipped until ownership transfer is allowed"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn apply_creates_declared_schema_with_owner() {
        let schema = unique_name("owned_schema");
        let owner_role = unique_name("owned_schema_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner_role}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
default_owner: postgres

schemas:
  - name: {schema}
    owner: {owner_role}
    profiles: []

roles:
  - name: {owner_role}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(owner_role.as_str()),
            "schema should be created with the declared owner"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn additive_mode_does_not_transfer_schema_owner() {
        let schema = unique_name("schema_owner_additive");
        let old_owner = unique_name("old_owner");
        let new_owner = unique_name("new_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            CREATE ROLE "{old_owner}";
            CREATE ROLE "{new_owner}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{old_owner}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
schemas:
  - name: {schema}
    owner: {new_owner}
    profiles: []

roles:
  - name: {old_owner}
  - name: {new_owner}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(old_owner.as_str()),
            "additive mode should not transfer schema ownership"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn additive_mode_skips_owner_bound_default_privileges_when_transfer_is_skipped() {
        let schema = unique_name("schema_owner_additive_defaults");
        let old_owner = unique_name("old_owner");
        let new_owner = unique_name("new_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{schema}-editor";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{schema}-editor";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            CREATE ROLE "{old_owner}";
            CREATE ROLE "{new_owner}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{old_owner}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: {{ type: schema }}
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: {schema}
    owner: {new_owner}
    profiles: [editor]

roles:
  - name: {old_owner}
  - name: {new_owner}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Applied: 2 change(s)"))
            .stdout(predicate::str::contains("1 role(s) to create"))
            .stdout(predicate::str::contains("1 grant(s) to add"))
            .stdout(predicate::str::contains("No changes needed").not());

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(old_owner.as_str()),
            "additive mode should not transfer schema ownership"
        );
        assert_eq!(
            query_default_acl_owner(&schema, &format!("{schema}-editor"), "r"),
            None,
            "owner-bound default privileges should be skipped until ownership transfer is allowed"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn apply_converges_existing_schema_owner_and_uses_owner_for_default_privileges() {
        let schema = unique_name("schema_owner");
        let old_owner = unique_name("old_owner");
        let new_owner = unique_name("new_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{schema}-editor";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{schema}-editor";
            DROP ROLE IF EXISTS "{new_owner}";
            DROP ROLE IF EXISTS "{old_owner}";
            CREATE ROLE "{old_owner}";
            CREATE ROLE "{new_owner}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{old_owner}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: {{ type: schema }}
      - privileges: [SELECT]
        object: {{ type: table, name: "*" }}
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: {schema}
    owner: {new_owner}
    profiles: [editor]

roles:
  - name: {old_owner}
  - name: {new_owner}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(new_owner.as_str()),
            "schema owner should be converged"
        );
        assert_eq!(
            query_default_acl_owner(&schema, &format!("{schema}-editor"), "r").as_deref(),
            Some(new_owner.as_str()),
            "default privileges should be attached to the schema owner"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn apply_restores_owner_schema_privileges_after_revoke_all() {
        let schema = unique_name("schema_owner_acl");
        let owner = unique_name("schema_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner}";
            CREATE ROLE "{owner}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}";
            REVOKE ALL ON SCHEMA "{schema}" FROM "{owner}";
            "#
        ));

        assert!(
            !query_has_schema_privilege(&owner, &schema, "CREATE"),
            "test setup should remove CREATE from schema owner"
        );
        assert!(
            !query_has_schema_privilege(&owner, &schema, "USAGE"),
            "test setup should remove USAGE from schema owner"
        );

        let manifest_file = write_temp_manifest(&format!(
            r#"
schemas:
  - name: {schema}
    owner: {owner}
    profiles: []

roles:
  - name: {owner}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("1 grant(s) to add"));

        assert!(
            query_has_schema_privilege(&owner, &schema, "CREATE"),
            "apply should restore CREATE to the schema owner"
        );
        assert!(
            query_has_schema_privilege(&owner, &schema, "USAGE"),
            "apply should restore USAGE to the schema owner"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn apply_declared_schema_with_missing_owner_role_fails_clearly() {
        let schema = unique_name("missing_owner_schema");
        let missing_owner = unique_name("missing_owner_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{missing_owner}";
            "#
        ));

        execute_sql(&format!(r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE;"#));

        let manifest_file = write_temp_manifest(&format!(
            r#"
schemas:
  - name: {schema}
    owner: {missing_owner}
    profiles: []
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(missing_owner.as_str()));
    }

    #[test]
    #[ignore]
    fn generate_output_to_stdout_has_no_nulls() {
        let output = pgroles_cmd()
            .args(["generate", "--database-url", &database_url()])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let yaml = String::from_utf8(output).expect("output is not valid UTF-8");
        assert!(
            !yaml.contains("null"),
            "generated YAML should not contain null fields"
        );
        assert!(yaml.contains("roles:"), "expected roles section in output");
    }

    #[test]
    #[ignore]
    fn generate_includes_schema_owned_by_postgres_without_user_roles() {
        let schema = unique_name("generate_schema_only");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            CREATE SCHEMA "{schema}" AUTHORIZATION postgres;
            "#
        ));

        let output = pgroles_cmd()
            .args(["generate", "--database-url", &database_url()])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let yaml = String::from_utf8(output).expect("output is not valid UTF-8");
        assert!(
            yaml.contains("schemas:"),
            "expected schemas section in output"
        );
        assert!(
            yaml.contains(&format!("- name: {schema}")),
            "expected generated manifest to include schema {schema}: {yaml}"
        );
        assert!(
            yaml.contains("owner: postgres"),
            "expected generated manifest to include postgres schema owner: {yaml}"
        );
    }

    #[test]
    #[ignore]
    fn generate_with_suggest_profiles_extracts_clusters() {
        // Seed a small brownfield with three schemas that each have a
        // matching `*-reader` role. After --suggest-profiles, the manifest
        // should contain a single `reader` profile.
        let prefix = unique_name("sug").replace('-', "_");
        let s1 = format!("{prefix}_a");
        let s2 = format!("{prefix}_b");
        let s3 = format!("{prefix}_c");
        let r1 = format!("{s1}-reader");
        let r2 = format!("{s2}-reader");
        let r3 = format!("{s3}-reader");

        let cleanup_sql = format!(
            r#"
            DROP OWNED BY "{r1}" CASCADE;
            DROP OWNED BY "{r2}" CASCADE;
            DROP OWNED BY "{r3}" CASCADE;
            DROP ROLE IF EXISTS "{r1}";
            DROP ROLE IF EXISTS "{r2}";
            DROP ROLE IF EXISTS "{r3}";
            DROP SCHEMA IF EXISTS "{s1}" CASCADE;
            DROP SCHEMA IF EXISTS "{s2}" CASCADE;
            DROP SCHEMA IF EXISTS "{s3}" CASCADE;
            "#
        );
        let _cleanup = TestDbCleanup::new(cleanup_sql);

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{r1}";
            DROP ROLE IF EXISTS "{r2}";
            DROP ROLE IF EXISTS "{r3}";
            DROP SCHEMA IF EXISTS "{s1}" CASCADE;
            DROP SCHEMA IF EXISTS "{s2}" CASCADE;
            DROP SCHEMA IF EXISTS "{s3}" CASCADE;
            CREATE SCHEMA "{s1}" AUTHORIZATION postgres;
            CREATE SCHEMA "{s2}" AUTHORIZATION postgres;
            CREATE SCHEMA "{s3}" AUTHORIZATION postgres;
            CREATE TABLE "{s1}".t (id int);
            CREATE TABLE "{s2}".t (id int);
            CREATE TABLE "{s3}".t (id int);
            CREATE ROLE "{r1}" NOLOGIN;
            CREATE ROLE "{r2}" NOLOGIN;
            CREATE ROLE "{r3}" NOLOGIN;
            GRANT USAGE ON SCHEMA "{s1}" TO "{r1}";
            GRANT USAGE ON SCHEMA "{s2}" TO "{r2}";
            GRANT USAGE ON SCHEMA "{s3}" TO "{r3}";
            GRANT SELECT ON "{s1}".t TO "{r1}";
            GRANT SELECT ON "{s2}".t TO "{r2}";
            GRANT SELECT ON "{s3}".t TO "{r3}";
            "#
        ));

        // Without --suggest-profiles: flat manifest, no profiles section
        // (or an empty one).
        let flat_yaml = String::from_utf8(
            pgroles_cmd()
                .args(["generate", "--database-url", &database_url()])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .expect("flat output utf8");
        assert!(flat_yaml.contains(&format!("- name: {r1}")));
        assert!(flat_yaml.contains(&format!("- name: {r2}")));
        assert!(flat_yaml.contains(&format!("- name: {r3}")));
        // Either no profiles key or "profiles: {}".
        assert!(
            flat_yaml.contains("profiles: {}") || !flat_yaml.contains("\nprofiles:"),
            "flat manifest unexpectedly has profiles: {flat_yaml}"
        );

        // With --suggest-profiles: a single `reader` profile should appear,
        // and the three reader roles should be replaced by schema bindings.
        let suggested_yaml = String::from_utf8(
            pgroles_cmd()
                .args([
                    "generate",
                    "--database-url",
                    &database_url(),
                    "--suggest-profiles",
                ])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .expect("suggested output utf8");

        assert!(
            suggested_yaml.contains("reader:"),
            "expected `reader` profile section: {suggested_yaml}"
        );
        for s in [&s1, &s2, &s3] {
            // Each schema should now bind the reader profile.
            assert!(
                suggested_yaml.contains(&format!("- name: {s}\n  profiles:\n  - reader")),
                "schema {s} should bind reader profile in: {suggested_yaml}"
            );
        }
        // The original reader role names should not appear as flat roles
        // anymore (they're produced by expansion).
        assert!(
            !suggested_yaml.contains(&format!("- name: {r1}")),
            "{r1} should be replaced by profile expansion: {suggested_yaml}"
        );

        // Sanity: the suggested manifest must validate.
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), &suggested_yaml).unwrap();
        pgroles_cmd()
            .args(["validate", "--file", temp.path().to_str().unwrap()])
            .assert()
            .success();

        // We deliberately do NOT diff/apply the generated manifest here —
        // `pgroles generate` introspects every non-system role in the
        // cluster, so the manifest captures unrelated roles created by
        // parallel test cases. Round-trip semantic equivalence is covered
        // by the 1000-iteration property suite in `pgroles-core`.
    }

    #[test]
    #[ignore]
    fn generate_output_to_file() {
        let output_file = tempfile::NamedTempFile::new().expect("failed to create temp file");

        pgroles_cmd()
            .args([
                "generate",
                "--database-url",
                &database_url(),
                "--output",
                output_file.path().to_str().unwrap(),
            ])
            .assert()
            .success();

        let yaml = std::fs::read_to_string(output_file.path()).expect("failed to read output file");
        assert!(!yaml.is_empty(), "output file should not be empty");
        assert!(
            !yaml.contains("null"),
            "generated YAML written to file should not contain null fields"
        );
        assert!(yaml.contains("roles:"), "expected roles section in file");
    }

    #[test]
    #[ignore]
    fn diff_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--no-exit-code",
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn diff_summary_format() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
                "--no-exit-code",
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn apply_dry_run_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--dry-run",
            ])
            .assert()
            .success();
    }

    #[test]
    #[ignore]
    fn inspect_against_live_db() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "inspect",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Roles:"))
            .stdout(predicate::str::contains("Grants:"))
            .stdout(predicate::str::contains("PUBLIC grants"));
    }

    #[test]
    #[ignore]
    fn inspect_bundle_shows_managed_scope_summary() {
        let managed_role = unique_name("inspect_bundle_managed");
        let extra_role = unique_name("inspect_bundle_extra");
        let schema = unique_name("inspect_bundle_schema");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            CREATE ROLE "{managed_role}" NOLOGIN;
            CREATE ROLE "{extra_role}" NOLOGIN;
            CREATE SCHEMA "{schema}";
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: platform.yaml
"#,
            &[(
                "platform.yaml",
                &format!(
                    r#"
policy:
  name: platform
scope:
  roles: [{managed_role}]
  schemas:
    - name: {schema}
      facets: [owner]
roles:
  - name: {managed_role}
    login: false
schemas:
  - name: {schema}
    owner: {managed_role}
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "inspect",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("Managed scope:"))
            .stdout(predicate::str::contains("owner scope:"))
            .stdout(predicate::str::contains(managed_role.as_str()))
            .stdout(predicate::str::contains(extra_role.as_str()).not());
    }

    #[test]
    #[ignore]
    fn graph_current_managed_bundle_scopes_roles() {
        let managed_role = unique_name("graph_bundle_managed");
        let extra_role = unique_name("graph_bundle_extra");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            CREATE ROLE "{managed_role}" NOLOGIN;
            CREATE ROLE "{extra_role}" NOLOGIN;
            "#
        ));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: app.yaml
"#,
            &[(
                "app.yaml",
                &format!(
                    r#"
policy:
  name: app
scope:
  roles: [{managed_role}]
roles:
  - name: {managed_role}
    login: false
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        pgroles_cmd()
            .args([
                "graph",
                "current",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--scope",
                "managed",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains(managed_role.as_str()))
            .stdout(predicate::str::contains(extra_role.as_str()).not())
            .stdout(predicate::str::contains("\"managed_scope\""));
    }

    #[test]
    #[ignore]
    fn diff_bundle_format_json_includes_ownership_annotations() {
        let managed_role = unique_name("bundle_json_role");
        let _cleanup = TestDbCleanup::new(format!(r#"DROP ROLE IF EXISTS "{managed_role}";"#));

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{managed_role}";"#));

        let (bundle_dir, bundle_path) = write_temp_bundle(
            r#"
sources:
  - file: app.yaml
"#,
            &[(
                "app.yaml",
                &format!(
                    r#"
policy:
  name: app
scope:
  roles: [{managed_role}]
roles:
  - name: {managed_role}
    login: false
"#
                ),
            )],
        );
        let _keep_dir = bundle_dir;

        let output = pgroles_cmd()
            .args([
                "diff",
                "--bundle",
                bundle_path.to_str().expect("bundle path should be utf-8"),
                "--database-url",
                &database_url(),
                "--format",
                "json",
                "--no-exit-code",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let parsed: serde_json::Value =
            serde_json::from_slice(&output).expect("diff json should parse");
        assert_eq!(
            parsed["schema_version"],
            pgroles_core::report::BUNDLE_PLAN_SCHEMA_VERSION
        );
        assert_eq!(parsed["managed_scope"]["roles"][0], managed_role);
        assert_eq!(parsed["changes"][0]["owner"]["document"], "app");
        assert_eq!(parsed["changes"][0]["owner"]["managed_key"]["kind"], "role");
        assert_eq!(
            parsed["changes"][0]["owner"]["managed_key"]["name"],
            managed_role
        );
    }

    #[test]
    #[ignore]
    fn wildcard_table_grants_converge_after_apply() {
        let schema = unique_name("wildcard_schema");
        let role = unique_name("wildcard_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            CREATE TABLE "{schema}"."orders" (id integer);
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn wildcard_table_grants_converge_when_materialized_view_privileges_differ() {
        let schema = unique_name("wildcard_matview_schema");
        let role = unique_name("wildcard_matview_role");
        let matview = "sales_rollup";
        let table = "widgets";
        let table_signature = format!(r#""{schema}"."{table}""#);
        let matview_signature = format!(r#""{schema}"."{matview}""#);

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."{table}" (id integer);
            CREATE MATERIALIZED VIEW "{schema}"."{matview}" AS SELECT 1 AS id;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            query_has_relation_privilege(&role, &table_signature, "SELECT"),
            "table privilege should remain granted"
        );
        assert!(
            !query_has_relation_privilege(&role, &matview_signature, "SELECT"),
            "materialized view privilege should be revoked back out"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    /// Reproduces a production reconcile flap: a manifest
    /// with `function name: "*"` should converge in a single apply even when
    /// one of the functions in the schema has been DROPped+CREATEd between
    /// reconciles (resetting its proacl to NULL). Before the fix, the
    /// inspector's wildcard-collapse failed on the recreated function and
    /// `diff` emitted both a wildcard GRANT and per-name REVOKEs for every
    /// previously-granted function — apply order then stripped grants from
    /// the previously-known set, the next reconcile observed the inversion,
    /// and the controller flapped indefinitely.
    #[test]
    #[ignore]
    fn wildcard_function_grants_converge_after_function_recreate() {
        let schema = unique_name("wildfn_schema");
        let role = unique_name("wildfn_role");

        // Strip EXECUTE from PUBLIC so per-role explicit ACLs are the only
        // way for `role` to gain EXECUTE. Without this, PostgreSQL's default
        // GRANT EXECUTE ... TO PUBLIC obscures whether the wildcard convergence
        // actually re-issued the per-role grants, since `has_function_privilege`
        // would return true via the PUBLIC grant alone.
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE FUNCTION "{schema}".f1() RETURNS int LANGUAGE sql AS 'SELECT 1';
            CREATE FUNCTION "{schema}".f2() RETURNS int LANGUAGE sql AS 'SELECT 2';
            CREATE FUNCTION "{schema}".f3() RETURNS int LANGUAGE sql AS 'SELECT 3';
            REVOKE EXECUTE ON FUNCTION "{schema}".f1() FROM PUBLIC;
            REVOKE EXECUTE ON FUNCTION "{schema}".f2() FROM PUBLIC;
            REVOKE EXECUTE ON FUNCTION "{schema}".f3() FROM PUBLIC;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#
        ));

        // Initial apply materialises EXECUTE on every function in the schema.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        for sig in [
            format!(r#""{schema}"."f1"()"#),
            format!(r#""{schema}"."f2"()"#),
            format!(r#""{schema}"."f3"()"#),
        ] {
            assert!(
                query_has_function_privilege(&role, &sig),
                "{sig} should have EXECUTE after initial apply"
            );
        }

        // Simulate a service (e.g. cdc-relay) recreating one of the functions.
        // PostgreSQL resets proacl to NULL on DROP+CREATE, so f2 no longer has
        // the explicit grant — even though the manifest's wildcard still says
        // it should.
        execute_sql(&format!(
            r#"
            DROP FUNCTION "{schema}".f2();
            CREATE FUNCTION "{schema}".f2() RETURNS int LANGUAGE sql AS 'SELECT 22';
            REVOKE EXECUTE ON FUNCTION "{schema}".f2() FROM PUBLIC;
            "#
        ));

        assert!(
            !query_has_function_privilege(&role, &format!(r#""{schema}"."f2"()"#)),
            "recreated f2 should not yet have EXECUTE"
        );

        // A single apply must converge: every function should have EXECUTE
        // and a follow-up diff must produce no changes.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        for sig in [
            format!(r#""{schema}"."f1"()"#),
            format!(r#""{schema}"."f2"()"#),
            format!(r#""{schema}"."f3"()"#),
        ] {
            assert!(
                query_has_function_privilege(&role, &sig),
                "{sig} should have EXECUTE after convergent apply"
            );
        }

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn wildcard_function_grant_converges_with_procedures_in_schema() {
        let schema = unique_name("wildfn_proc_schema");
        let role = unique_name("wildfn_proc_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE FUNCTION "{schema}".do_thing() RETURNS int LANGUAGE sql AS 'SELECT 1';
            CREATE PROCEDURE "{schema}".run_something() LANGUAGE sql AS 'SELECT 1';
            REVOKE EXECUTE ON FUNCTION "{schema}".do_thing() FROM PUBLIC;
            REVOKE EXECUTE ON PROCEDURE "{schema}".run_something() FROM PUBLIC;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        let removed_manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                removed_manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                removed_manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn wildcard_function_grant_fails_before_partial_apply_when_object_not_grantable() {
        let schema = unique_name("wildfn_mixed_owner_schema");
        let executor = unique_name("wildfn_executor");
        let definer = unique_name("wildfn_definer");
        let role = unique_name("wildfn_editor");
        let password = "pgroles-test-password";
        let executor_url = database_url_for_role(&executor, password);

        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            DROP ROLE IF EXISTS "{definer}";
            DROP ROLE IF EXISTS "{executor}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            DROP ROLE IF EXISTS "{definer}";
            DROP ROLE IF EXISTS "{executor}";
            CREATE ROLE "{executor}" LOGIN PASSWORD '{password}';
            CREATE ROLE "{definer}" NOLOGIN;
            CREATE ROLE "{role}" NOLOGIN;
            CREATE SCHEMA "{schema}" AUTHORIZATION "{executor}";
            CREATE FUNCTION "{schema}".f1() RETURNS int LANGUAGE sql AS 'SELECT 1';
            ALTER FUNCTION "{schema}".f1() OWNER TO "{executor}";
            CREATE FUNCTION "{schema}".f2() RETURNS int LANGUAGE sql AS 'SELECT 2';
            ALTER FUNCTION "{schema}".f2() OWNER TO "{definer}";
            REVOKE EXECUTE ON FUNCTION "{schema}".f1() FROM PUBLIC;
            REVOKE EXECUTE ON FUNCTION "{schema}".f2() FROM PUBLIC;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &executor_url,
                "--format",
                "sql",
            ])
            .assert()
            .failure()
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains("UnsatisfiableWildcardGrant"))
            .stderr(predicate::str::contains("f2()"))
            .stderr(predicate::str::contains(&definer))
            .stderr(predicate::str::contains("GRANT EXECUTE ON ALL ROUTINES IN SCHEMA").not());

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &executor_url,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("UnsatisfiableWildcardGrant"));

        assert!(
            !query_has_function_privilege(&role, &format!(r#""{schema}"."f1"()"#)),
            "apply should fail before partially granting the grantable function"
        );
        assert!(
            !query_has_function_privilege(&role, &format!(r#""{schema}"."f2"()"#)),
            "non-grantable function should remain ungranted"
        );
    }

    #[test]
    #[ignore]
    fn specific_function_grants_apply_and_converge() {
        let schema = unique_name("function_schema");
        let role = unique_name("function_role");
        let function_name = "refresh_users";
        let signature = format!(r#""{schema}"."{function_name}"(integer, text)"#);

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE FUNCTION "{schema}"."{function_name}"(integer, text)
            RETURNS integer
            LANGUAGE SQL
            AS $$ SELECT $1; $$;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "{function_name}(integer, text)" }}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            query_has_function_privilege(&role, &signature),
            "role should have EXECUTE privilege on the function"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn membership_option_updates_apply_without_dropping_membership() {
        let group_role = unique_name("group_role");
        let member_role = unique_name("member_role");

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{member_role}";
            DROP ROLE IF EXISTS "{group_role}";
            "#
        ));

        let initial_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {group_role}
  - name: {member_role}

memberships:
  - role: {group_role}
    members:
      - name: {member_role}
        inherit: true
        admin: false
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                initial_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        let updated_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {group_role}
  - name: {member_role}

memberships:
  - role: {group_role}
    members:
      - name: {member_role}
        inherit: false
        admin: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                updated_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert_eq!(
            query_membership_flags(&group_role, &member_role),
            (true, false),
            "membership should remain present with updated admin/inherit flags"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                updated_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{member_role}";
            DROP ROLE IF EXISTS "{group_role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn drop_role_safety_reports_owned_objects() {
        let schema = unique_name("safety_schema");
        let role = unique_name("safety_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{role}";
            SET ROLE "{role}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            RESET ROLE;
            "#
        ));

        let report = query_drop_role_safety(&role);
        assert_eq!(report.issues.len(), 1, "expected one unsafe drop issue");
        let issue = &report.issues[0];
        assert_eq!(issue.role, role);
        assert!(
            issue.owned_object_count >= 2,
            "expected owned schema/table to be detected, got {:?}",
            issue
        );
        assert!(
            issue
                .owned_object_examples
                .iter()
                .any(|example| example.contains(&schema)),
            "expected at least one example mentioning the owned schema"
        );

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn retirement_manifest_requires_drop_owned_for_privilege_dependencies() {
        let schema = unique_name("acl_schema");
        let role = unique_name("acl_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            GRANT SELECT ON "{schema}"."widgets" TO "{role}";
            "#
        ));

        let report = query_drop_role_safety(&role);
        assert_eq!(report.issues.len(), 1, "expected one unsafe drop issue");
        let issue = &report.issues[0];
        assert_eq!(issue.role, role);
        assert!(
            issue.privilege_dependency_count >= 1,
            "expected privilege dependency to be detected, got {:?}",
            issue
        );

        let blocked_manifest = write_temp_manifest(&format!(
            r#"
retirements:
  - role: {role}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                blocked_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("privilege dependency"));

        let cleanup_manifest = write_temp_manifest(&format!(
            r#"
retirements:
  - role: {role}
    drop_owned: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                cleanup_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            !query_role_exists(&role),
            "role should be dropped after DROP OWNED cleanup"
        );

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            "#
        ));
    }

    #[test]
    #[ignore]
    fn retirement_manifest_reassigns_owned_objects_and_drops_role() {
        let schema = unique_name("retire_schema");
        let retired_role = unique_name("retired_role");
        let successor_role = unique_name("successor_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{retired_role}";
            DROP ROLE IF EXISTS "{successor_role}";
            CREATE ROLE "{successor_role}";
            CREATE ROLE "{retired_role}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{retired_role}";
            SET ROLE "{retired_role}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            RESET ROLE;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {successor_role}

retirements:
  - role: {retired_role}
    reassign_owned_to: {successor_role}
    drop_owned: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            !query_role_exists(&retired_role),
            "retired role should have been dropped"
        );
        assert_eq!(
            query_schema_owner(&schema).as_deref(),
            Some(successor_role.as_str()),
            "schema ownership should be reassigned"
        );
        assert_eq!(
            query_table_owner(&schema, "widgets").as_deref(),
            Some(successor_role.as_str()),
            "table ownership should be reassigned"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{successor_role}";
            "#
        ));
    }

    #[test]
    #[ignore]
    fn apply_with_password_does_not_leak_password_in_stderr() {
        let role = unique_name("pw_redact_role");
        let password = "s3cret_p@ssw0rd_DO_NOT_LEAK";

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{role}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
    password:
      from_env: TEST_PW_REDACT_VAR
"#
        ));

        // Apply with the password env var set and pgroles debug logging enabled.
        // Use a targeted log filter so sqlx query logs (which echo raw SQL
        // including passwords) are suppressed — we are testing *pgroles'* own
        // redaction, not sqlx's internal logging.
        let output = pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .env("TEST_PW_REDACT_VAR", password)
            .env(
                "RUST_LOG",
                "pgroles=debug,pgroles_core=debug,pgroles_inspect=debug,sqlx=warn",
            )
            .assert()
            .success()
            .get_output()
            .clone();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains(password),
            "stderr must NOT contain the actual password. Got:\n{stderr}"
        );
        assert!(
            stderr.contains("REDACTED"),
            "stderr should mention REDACTED when applying password changes. Got:\n{stderr}"
        );

        assert!(query_role_exists(&role), "role should exist after apply");

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));
    }

    #[test]
    #[ignore]
    fn diff_exit_code_ignores_password_only_drift() {
        let role = unique_name("pw_drift_role");

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{role}";
            "#
        ));

        // First apply to create the role without a password.
        let initial_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                initial_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        // Now diff with a password — should NOT trigger exit code 2
        // because password changes are not structural drift.
        let password_manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
    password:
      from_env: TEST_PW_DRIFT_VAR
"#
        ));

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                password_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--exit-code",
            ])
            .env("TEST_PW_DRIFT_VAR", "test_password_123")
            .assert()
            .success(); // exit code 0, not 2

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));
    }

    #[test]
    #[ignore]
    fn diff_format_json_redacts_password_changes() {
        let role = unique_name("pw_json_role");

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));

        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
    password:
      from_env: TEST_PW_JSON_VAR
"#
        ));

        let output = pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "json",
                "--no-exit-code",
            ])
            .env("TEST_PW_JSON_VAR", "json_secret_value")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8(output).expect("stdout is not valid UTF-8");
        assert!(stdout.contains("[REDACTED]"), "got:\n{stdout}");
        assert!(!stdout.contains("json_secret_value"), "got:\n{stdout}");
    }

    #[test]
    #[ignore]
    fn diff_format_sql_redacts_password_changes() {
        let role = unique_name("pw_sql_role");

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));

        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
    password:
      from_env: TEST_PW_SQL_VAR
"#
        ));

        let output = pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "sql",
                "--no-exit-code",
            ])
            .env("TEST_PW_SQL_VAR", "sql_secret_value")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8(output).expect("stdout is not valid UTF-8");
        assert!(stdout.contains("[REDACTED]"), "got:\n{stdout}");
        assert!(!stdout.contains("sql_secret_value"), "got:\n{stdout}");
        assert!(stdout.contains("ALTER ROLE"), "got:\n{stdout}");
    }

    #[test]
    #[ignore]
    fn apply_missing_password_env_var_fails() {
        let role = unique_name("pw_missing_env_role");

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));

        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}
    login: true
    password:
      from_env: TEST_PW_MISSING_ENV_VAR
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("failed to resolve role passwords"))
            .stderr(predicate::str::contains("TEST_PW_MISSING_ENV_VAR"));

        assert!(
            !query_role_exists(&role),
            "role should not be created when password env var is missing"
        );
    }

    #[test]
    #[ignore]
    fn generate_omits_password_fields_and_preserves_password_valid_until() {
        let role = unique_name("pw_generate_role");
        let password = "gen_secret_123!";
        let valid_until = "2027-01-01 00:00:00+00";

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}" LOGIN PASSWORD '{password}' VALID UNTIL '{valid_until}';
            "#
        ));

        let output = pgroles_cmd()
            .args(["generate", "--database-url", &database_url()])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let yaml = String::from_utf8(output).expect("output is not valid UTF-8");
        assert!(!yaml.contains("password:"), "got:\n{yaml}");
        assert!(!yaml.contains("from_env:"), "got:\n{yaml}");
        assert!(
            yaml.contains(&format!("name: {role}")),
            "generated YAML should include role, got:\n{yaml}"
        );
        assert!(
            yaml.contains("password_valid_until:"),
            "generated YAML should preserve password_valid_until, got:\n{yaml}"
        );

        execute_sql(&format!(r#"DROP ROLE IF EXISTS "{role}";"#));
    }

    #[test]
    #[ignore]
    fn retirement_manifest_can_terminate_active_sessions() {
        let role = unique_name("session_role");
        let password = "retireme123!";

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}" LOGIN PASSWORD '{password}';
            "#
        ));

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let role_for_thread = role.clone();

        let holder = std::thread::spawn(move || {
            with_runtime(async move {
                let connection = open_role_connection(&role_for_thread, password).await;
                ready_tx.send(()).expect("failed to signal ready");
                let _connection = connection;
                let _ = stop_rx.recv();
            });
        });

        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("timed out waiting for held session");

        let blocked_manifest = write_temp_manifest(&format!(
            r#"
retirements:
  - role: {role}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                blocked_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("active session"));

        let terminating_manifest = write_temp_manifest(&format!(
            r#"
retirements:
  - role: {role}
    terminate_sessions: true
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                terminating_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        let _ = stop_tx.send(());
        let _ = holder.join();

        assert!(
            !query_role_exists(&role),
            "role should be dropped after terminating sessions"
        );
    }

    // =================================================================
    // Reconciliation mode live-DB tests
    // =================================================================

    /// Additive mode: apply creates roles and grants but does NOT drop
    /// an extra role that exists in the database but not in the manifest.
    #[test]
    #[ignore]
    fn additive_mode_does_not_drop_extra_roles() {
        let schema = unique_name("add_schema");
        let managed_role = unique_name("add_managed");
        let extra_role = unique_name("add_extra");

        // Set up: create the extra role that is NOT in our manifest.
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            CREATE ROLE "{extra_role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {managed_role}

grants:
  - role: {managed_role}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        // Apply in additive mode
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success();

        // Managed role should be created
        assert!(
            query_role_exists(&managed_role),
            "managed role should be created in additive mode"
        );

        // Extra role should NOT have been dropped
        assert!(
            query_role_exists(&extra_role),
            "extra role should NOT be dropped in additive mode"
        );

        // Now diff in additive mode should show no changes
        // (the extra role isn't managed, and the managed role is in sync)
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
                "--mode",
                "additive",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        // Cleanup
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            "#
        ));
    }

    /// Additive mode: does not revoke grants that exist in the DB but
    /// not in the manifest.
    #[test]
    #[ignore]
    fn additive_mode_does_not_revoke_extra_grants() {
        let schema = unique_name("addgr_schema");
        let role = unique_name("addgr_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE ROLE "{role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            GRANT SELECT, INSERT ON "{schema}"."widgets" TO "{role}";
            "#
        ));

        // Manifest only declares SELECT, not INSERT.
        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        // Apply in additive mode — should NOT revoke INSERT
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success();

        // INSERT should still be granted
        assert!(
            query_has_relation_privilege(&role, &format!(r#""{schema}"."widgets""#), "INSERT"),
            "INSERT should NOT be revoked in additive mode"
        );

        // Cleanup
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    /// Additive mode: does not rewrite brownfield role attributes for a
    /// pre-existing role, which lets a limited CREATEROLE manager converge
    /// grants without needing ADMIN on every existing role.
    #[test]
    #[ignore]
    fn additive_mode_does_not_rewrite_preexisting_role_attributes() {
        let managed_role = unique_name("addattrs_role");
        let manager_role = unique_name("addattrs_manager");
        let manager_password = unique_name("pw");
        let manager_url = database_url_for_role(&manager_role, &manager_password);

        execute_sql(&format!(
            r#"
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{manager_role}";
            CREATE ROLE "{managed_role}" LOGIN NOINHERIT;
            CREATE ROLE "{manager_role}" LOGIN CREATEROLE PASSWORD '{manager_password}';
            "#
        ));
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{manager_role}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {managed_role}
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &manager_url,
                "--mode",
                "additive",
            ])
            .assert()
            .success();

        assert_eq!(
            query_role_login_and_inherit(&managed_role),
            Some((true, false)),
            "additive mode should leave existing role attributes unchanged"
        );

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &manager_url,
                "--mode",
                "additive",
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    /// Generated roles inherit profile-level inherit/login attributes.
    #[test]
    #[ignore]
    fn apply_profile_generated_role_preserves_inherit_attribute() {
        let schema = unique_name("profile_inherit_schema");
        let generated_role = format!("{schema}-editor");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            CREATE SCHEMA "{schema}";
            "#
        ));
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{generated_role}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
profiles:
  editor:
    login: false
    inherit: false
    grants:
      - privileges: [USAGE]
        object: {{ type: schema }}

schemas:
  - name: {schema}
    profiles: [editor]
"#
        ));

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert_eq!(
            query_role_login_and_inherit(&generated_role),
            Some((false, false)),
            "generated role should preserve profile login/inherit flags"
        );
    }

    /// Adopt mode: revokes extra grants within managed scope but does
    /// NOT drop roles that aren't in the manifest.
    #[test]
    #[ignore]
    fn adopt_mode_revokes_grants_but_does_not_drop_roles() {
        let schema = unique_name("adopt_schema");
        let managed_role = unique_name("adopt_managed");
        let extra_role = unique_name("adopt_extra");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            CREATE ROLE "{managed_role}";
            CREATE ROLE "{extra_role}";
            CREATE SCHEMA "{schema}";
            CREATE TABLE "{schema}"."widgets" (id integer);
            GRANT SELECT, INSERT ON "{schema}"."widgets" TO "{managed_role}";
            "#
        ));

        // Manifest only declares SELECT (not INSERT) for the managed role.
        // The extra role is not mentioned at all.
        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {managed_role}

grants:
  - role: {managed_role}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}
"#
        ));

        // Apply in adopt mode
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .assert()
            .success();

        // Extra role should NOT be dropped
        assert!(
            query_role_exists(&extra_role),
            "extra role should NOT be dropped in adopt mode"
        );

        // INSERT should be revoked (adopt mode revokes within managed scope)
        assert!(
            !query_has_relation_privilege(
                &managed_role,
                &format!(r#""{schema}"."widgets""#),
                "INSERT"
            ),
            "INSERT should be revoked in adopt mode"
        );

        // SELECT should remain
        assert!(
            query_has_relation_privilege(
                &managed_role,
                &format!(r#""{schema}"."widgets""#),
                "SELECT"
            ),
            "SELECT should remain in adopt mode"
        );

        // Diff in adopt mode should show no further changes
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
                "--mode",
                "adopt",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        // Cleanup
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            "#
        ));
    }

    /// A pre-existing role that owns relations and holds explicit grants must
    /// not have its inherent owner privileges revoked (issue #201). Once a
    /// grant materializes the table ACL, PostgreSQL records the owner's
    /// implicit privileges in it; inspection must not read that entry as
    /// granted state and plan revokes against it.
    #[test]
    #[ignore]
    fn adopt_mode_does_not_revoke_owner_inherent_privileges() {
        let schema = unique_name("owner_acl_schema");
        let owner = unique_name("owner_acl_role");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner}";
            CREATE ROLE "{owner}" NOLOGIN;
            CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}";
            CREATE TABLE "{schema}".widgets (id integer);
            ALTER TABLE "{schema}".widgets OWNER TO "{owner}";
            GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "{schema}"
                TO "{owner}";
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
default_owner: {owner}

roles:
  - name: {owner}
    nologin: true

profiles:
  writer:
    grants:
      - object: {{ type: schema }}
        privileges: [USAGE]
      - object: {{ type: table, name: "*" }}
        privileges: [SELECT, INSERT]

schemas:
  - name: {schema}
    profiles: [writer]
"#
        ));

        let diff_output = pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .output()
            .expect("failed to run diff");
        let diff_stdout = String::from_utf8_lossy(&diff_output.stdout);
        assert!(
            !diff_stdout.contains("REVOKE"),
            "adopt plan must not revoke anything from the table owner; got:\n{diff_stdout}"
        );

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .assert()
            .success();

        // The owner keeps DML on its own tables — including DELETE and
        // TRUNCATE/REFERENCES/TRIGGER, which nobody ever granted explicitly.
        for privilege in [
            "SELECT",
            "INSERT",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
        ] {
            assert!(
                query_has_relation_privilege(&owner, &format!("{schema}.widgets"), privilege),
                "owner should retain {privilege} on its own table"
            );
        }

        // Converged: no regrant churn on re-inspection.
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        // A manifest that explicitly declares SELECT for the owner on its own
        // table also converges: the inherent entry covers the declared grant,
        // so neither a GRANT nor a REVOKE is planned.
        let declaring_manifest = write_temp_manifest(&format!(
            r#"
default_owner: {owner}

roles:
  - name: {owner}
    nologin: true

profiles:
  writer:
    grants:
      - object: {{ type: schema }}
        privileges: [USAGE]
      - object: {{ type: table, name: "*" }}
        privileges: [SELECT, INSERT]

grants:
  - role: {owner}
    privileges: [SELECT]
    object: {{ type: table, schema: {schema}, name: "*" }}

schemas:
  - name: {schema}
    profiles: [writer]
"#
        ));
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                declaring_manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        // Cleanup
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{owner}";
            "#
        ));
    }

    /// Inspect without a manifest shows PUBLIC grants for the current database.
    /// A fresh database should have at least CONNECT and TEMPORARY granted to
    /// PUBLIC, and USAGE on the "public" schema.
    #[test]
    #[ignore]
    fn inspect_shows_public_grants() {
        pgroles_cmd()
            .args(["inspect", "--database-url", &database_url()])
            .assert()
            .success()
            .stdout(predicate::str::contains("PUBLIC grants"))
            .stdout(predicate::str::contains("Database:"))
            .stdout(predicate::str::contains("CONNECT"))
            .stdout(predicate::str::contains("TEMPORARY"))
            .stdout(predicate::str::contains("Schema \"public\""));
    }

    /// Inspect with a manifest also shows PUBLIC grants.
    #[test]
    #[ignore]
    fn inspect_with_manifest_shows_public_grants() {
        let manifest_file = write_temp_manifest(VALID_MINIMAL);

        pgroles_cmd()
            .args([
                "inspect",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("PUBLIC grants"))
            .stdout(predicate::str::contains("CONNECT"));
    }

    /// Authoritative mode (default): drops extra roles that aren't in the manifest.
    /// This confirms the default behavior is unchanged.
    #[test]
    #[ignore]
    fn authoritative_mode_drops_extra_roles() {
        let schema = unique_name("auth_schema");
        let managed_role = unique_name("auth_managed");
        let extra_role = unique_name("auth_extra");

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            DROP ROLE IF EXISTS "{extra_role}";
            CREATE ROLE "{extra_role}";
            CREATE SCHEMA "{schema}";
            "#
        ));

        // Manifest manages schema + one role. extra_role is a retirement candidate.
        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {managed_role}

retirements:
  - role: {extra_role}
"#
        ));

        // Apply in authoritative mode (explicitly)
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "authoritative",
            ])
            .assert()
            .success();

        // Extra role SHOULD be dropped in authoritative mode
        assert!(
            !query_role_exists(&extra_role),
            "extra role should be dropped in authoritative mode"
        );

        // Managed role should exist
        assert!(
            query_role_exists(&managed_role),
            "managed role should be created in authoritative mode"
        );

        // Cleanup
        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{managed_role}";
            "#
        ));
    }

    /// Regression for the wildcard EXECUTE flap on schemas containing functions
    /// whose `proname || '(' || identity_args || ')'` signature exceeds 63
    /// bytes.
    ///
    /// The inventory query UNION-ALLs `c.relname` / `t.typname` (PostgreSQL
    /// `name`, 63-byte cap) with the text-typed function signature. PostgreSQL
    /// resolves the result column to the common type — `name` — which silently
    /// truncates long function signatures. The per-type privilege query
    /// returns the full signature unaffected, so inventory's truncated key
    /// fails to match the grant key in `normalize_wildcard_grants` and the
    /// wildcard is treated as unsatisfied on every reconcile.
    ///
    /// This test creates a function with a long signature, applies a wildcard
    /// EXECUTE grant, and asserts a follow-up diff converges to zero changes.
    /// Before the inventory-column casts, the second diff would re-emit
    /// `GRANT EXECUTE ON ALL ROUTINES IN SCHEMA ... TO ...` forever.
    #[test]
    #[ignore]
    fn wildcard_function_grant_converges_with_signature_longer_than_63_bytes() {
        let schema = unique_name("wildfn_longsig");
        let role = unique_name("wildfn_longsig_role");
        // `proname || '(' || identity_args || ')'` is 74+ bytes; well past
        // PostgreSQL's 63-byte `name` cap.
        let function_body = format!(
            r#"CREATE FUNCTION "{schema}".compute_thing(parameter_with_a_deliberately_long_identifier integer) RETURNS int LANGUAGE sql AS 'SELECT $1'"#
        );

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            {function_body};
            REVOKE EXECUTE ON FUNCTION "{schema}".compute_thing(integer) FROM PUBLIC;
            "#
        ));

        let manifest_file = write_temp_manifest(&format!(
            r#"
roles:
  - name: {role}

grants:
  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#
        ));

        // Initial apply materialises the per-function grant.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        assert!(
            query_has_function_privilege(&role, &format!(r#""{schema}"."compute_thing"(integer)"#)),
            "function should have EXECUTE after initial apply"
        );

        // The bug: before the inventory-column casts, the wildcard satisfaction
        // check looks up the grant under a 63-byte-truncated function key that
        // doesn't match the full key in the grant map, so the diff re-emits
        // the wildcard GRANT on every reconcile. With the fix, the diff
        // converges to zero changes.
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest_file.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));
    }

    /// The `pg_default_acl` ACL text for an owner's global (namespace 0)
    /// defaults, or `None` when PostgreSQL has not materialized a row yet.
    fn query_global_default_acl(owner: &str, object_type: &str) -> Option<String> {
        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            let row = sqlx::query(
                r#"
                SELECT da.defaclacl::text AS acl
                FROM pg_default_acl da
                JOIN pg_roles owner_role ON owner_role.oid = da.defaclrole
                WHERE owner_role.rolname = $1
                  AND da.defaclnamespace = 0
                  AND da.defaclobjtype::text = $2
                "#,
            )
            .bind(owner)
            .bind(object_type)
            .fetch_optional(&pool)
            .await
            .expect("failed to query global default privileges");
            row.map(|row| row.get("acl"))
        })
    }

    /// Set up the proposal's SECURITY DEFINER scenario: an owner role, an
    /// allowed caller, an unrelated bystander, and one existing routine.
    struct PublicFixture {
        schema: String,
        owner: String,
        caller: String,
        bystander: String,
    }

    impl PublicFixture {
        fn new(prefix: &str) -> (Self, TestDbCleanup) {
            let fixture = PublicFixture {
                schema: unique_name(&format!("{prefix}_schema")),
                owner: unique_name(&format!("{prefix}_owner")),
                caller: unique_name(&format!("{prefix}_caller")),
                bystander: unique_name(&format!("{prefix}_bystander")),
            };
            // DROP OWNED must run first: a role owning global default
            // privileges is undroppable while pg_default_acl references it.
            let cleanup = TestDbCleanup::new(format!(
                r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE;
                   DO $$ BEGIN
                     IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') THEN
                       EXECUTE 'DROP OWNED BY "{owner}" CASCADE';
                     END IF;
                     IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{caller}') THEN
                       EXECUTE 'DROP OWNED BY "{caller}" CASCADE';
                     END IF;
                   END $$;
                   DROP ROLE IF EXISTS "{owner}";
                   DROP ROLE IF EXISTS "{caller}";
                   DROP ROLE IF EXISTS "{bystander}";"#,
                schema = fixture.schema,
                owner = fixture.owner,
                caller = fixture.caller,
                bystander = fixture.bystander,
            ));
            execute_sql(&format!(
                r#"CREATE ROLE "{owner}";
                   CREATE ROLE "{caller}";
                   CREATE ROLE "{bystander}";
                   CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}";
                   SET ROLE "{owner}";
                   CREATE FUNCTION "{schema}".secret(x integer) RETURNS integer
                       LANGUAGE sql SECURITY DEFINER AS 'SELECT x';
                   RESET ROLE;"#,
                schema = fixture.schema,
                owner = fixture.owner,
                caller = fixture.caller,
                bystander = fixture.bystander,
            ));
            (fixture, cleanup)
        }

        fn secret_signature(&self) -> String {
            format!("\"{}\".secret(integer)", self.schema)
        }

        /// A manifest asserting PUBLIC holds no EXECUTE on existing or future
        /// routines, while the caller keeps access.
        fn manifest(&self) -> String {
            self.manifest_with_extra("", "")
        }

        /// `extra_roles` and `extra_grants` are spliced into the matching
        /// sections so callers never append after `default_privileges`.
        fn manifest_with_extra(&self, extra_roles: &str, extra_grants: &str) -> String {
            format!(
                r#"
roles:
  - name: {owner}
  - name: {caller}
{extra_roles}grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
{extra_grants}
  - role: {caller}
    privileges: [USAGE]
    object: {{ type: schema, name: {schema} }}
  - role: {caller}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
default_privileges:
  - owner: {owner}
    scope: {{ type: global }}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
  - owner: {owner}
    schema: {schema}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
      - role: {caller}
        privileges: [EXECUTE]
        on_type: function
"#,
                owner = self.owner,
                caller = self.caller,
                schema = self.schema,
                extra_roles = extra_roles,
                extra_grants = extra_grants,
            )
        }
    }

    /// Apply until the plan is empty, returning the number of passes.
    ///
    /// pgroles needs a second pass whenever the first one materializes an
    /// object ACL: PostgreSQL writes the owner's implicit self-grant into the
    /// ACL at that moment, and authoritative mode then revokes it. That is
    /// pre-existing behavior for any grant on an owner-managed object, not
    /// something absence assertions introduce.
    fn apply_until_converged(manifest_path: &std::path::Path, max_passes: usize) -> usize {
        for pass in 1..=max_passes {
            pgroles_cmd()
                .args([
                    "apply",
                    "--file",
                    manifest_path.to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                ])
                .assert()
                .success();

            let output = pgroles_cmd()
                .args([
                    "diff",
                    "--file",
                    manifest_path.to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                    "--format",
                    "summary",
                    "--no-exit-code",
                ])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            if String::from_utf8_lossy(&output).contains("No changes needed") {
                return pass;
            }
        }
        panic!("plan did not converge within {max_passes} passes");
    }

    #[test]
    #[ignore]
    fn public_absence_revokes_implicit_execute_and_converges() {
        let (fixture, _cleanup) = PublicFixture::new("pubabs");
        let manifest = write_temp_manifest(&fixture.manifest());

        // PostgreSQL grants EXECUTE to PUBLIC implicitly, with no ACL row.
        assert!(query_has_function_privilege(
            &fixture.bystander,
            &fixture.secret_signature()
        ));

        let plan = String::from_utf8_lossy(
            &pgroles_cmd()
                .args([
                    "diff",
                    "--file",
                    manifest.path().to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                    "--format",
                    "sql",
                    "--no-exit-code",
                ])
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        assert!(
            plan.contains(&format!(
                r#"REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA "{}" FROM PUBLIC;"#,
                fixture.schema
            )),
            "plan should revoke PUBLIC EXECUTE on existing routines:\n{plan}"
        );

        apply_until_converged(manifest.path(), 3);

        assert!(
            !query_has_function_privilege(&fixture.bystander, &fixture.secret_signature()),
            "PUBLIC EXECUTE should be gone"
        );
        assert!(
            query_has_function_privilege(&fixture.caller, &fixture.secret_signature()),
            "the allowed caller should keep EXECUTE"
        );
    }

    #[test]
    #[ignore]
    fn global_default_revoke_renders_without_in_schema_and_protects_new_routines() {
        let (fixture, _cleanup) = PublicFixture::new("pubglobal");
        let manifest = write_temp_manifest(&fixture.manifest());

        let plan = String::from_utf8_lossy(
            &pgroles_cmd()
                .args([
                    "diff",
                    "--file",
                    manifest.path().to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                    "--format",
                    "sql",
                    "--no-exit-code",
                ])
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        let global_revoke = format!(
            r#"ALTER DEFAULT PRIVILEGES FOR ROLE "{}" REVOKE EXECUTE ON ROUTINES FROM PUBLIC;"#,
            fixture.owner
        );
        assert!(
            plan.contains(&global_revoke),
            "global default revoke must omit IN SCHEMA:\n{plan}"
        );

        apply_until_converged(manifest.path(), 3);

        // The built-in default is now an explicit row without PUBLIC.
        let acl = query_global_default_acl(&fixture.owner, "f")
            .expect("global default row should exist after the revoke");
        // A PUBLIC entry has an empty grantee, so it renders as `{=X/owner}`
        // or `,=X/owner`. The owner's own `owner=X/owner` entry must remain.
        assert!(
            !acl.contains("{=") && !acl.contains(",="),
            "no PUBLIC entry expected in global defaults, got {acl}"
        );
        assert!(
            acl.contains(&format!("{owner}=X/", owner = fixture.owner)),
            "the owner keeps its own default EXECUTE, got {acl}"
        );

        // Routines created afterwards inherit the corrected default.
        execute_sql(&format!(
            r#"SET ROLE "{owner}";
               CREATE FUNCTION "{schema}".later(y integer) RETURNS integer
                   LANGUAGE sql AS 'SELECT y';
               CREATE PROCEDURE "{schema}".later_proc() LANGUAGE sql AS 'SELECT 1';
               RESET ROLE;"#,
            owner = fixture.owner,
            schema = fixture.schema,
        ));

        for signature in [
            format!("\"{}\".later(integer)", fixture.schema),
            format!("\"{}\".later_proc()", fixture.schema),
        ] {
            assert!(
                !query_has_function_privilege(&fixture.bystander, &signature),
                "new routine {signature} must not be executable by PUBLIC"
            );
            assert!(
                query_has_function_privilege(&fixture.caller, &signature),
                "new routine {signature} should be executable by the allowed caller"
            );
        }

        // Creating routines must not reopen PUBLIC drift. (pgroles may still
        // plan a revoke of the owner's self-grant that PostgreSQL
        // materialized into each new ACL — pre-existing behavior for any
        // grant on an owner-managed object, unrelated to PUBLIC.)
        let plan_after = String::from_utf8_lossy(
            &pgroles_cmd()
                .args([
                    "diff",
                    "--file",
                    manifest.path().to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                    "--format",
                    "sql",
                    "--no-exit-code",
                ])
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        assert!(
            !plan_after.contains("FROM PUBLIC"),
            "new routines must not reopen PUBLIC drift:\n{plan_after}"
        );
    }

    #[test]
    #[ignore]
    fn global_public_builtin_absences_are_applied_when_the_owner_is_created() {
        let owner = unique_name("pubnew_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"DO $$ BEGIN
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') THEN
                   EXECUTE 'DROP OWNED BY "{owner}" CASCADE';
                 END IF;
               END $$;
               DROP ROLE IF EXISTS "{owner}";"#
        ));
        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {owner}
default_privileges:
  - owner: {owner}
    scope: {{ type: global }}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
      - role: PUBLIC
        ensure: absent
        privileges: [USAGE]
        on_type: type
"#
        ));

        let plan = String::from_utf8_lossy(
            &pgroles_cmd()
                .args([
                    "diff",
                    "--file",
                    manifest.path().to_str().unwrap(),
                    "--database-url",
                    &database_url(),
                    "--format",
                    "sql",
                    "--no-exit-code",
                ])
                .assert()
                .success()
                .get_output()
                .stdout,
        )
        .to_string();
        assert!(
            plan.contains(&format!(r#"CREATE ROLE "{owner}""#)),
            "{plan}"
        );
        assert!(
            plan.contains(&format!(
                r#"ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" REVOKE EXECUTE ON ROUTINES FROM PUBLIC;"#
            )),
            "the first plan must revoke the new role's built-in PUBLIC default:\n{plan}"
        );
        assert!(
            plan.contains(&format!(
                r#"ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" REVOKE USAGE ON TYPES FROM PUBLIC;"#
            )),
            "the first plan must revoke the new role's built-in PUBLIC type default:\n{plan}"
        );

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
            ])
            .assert()
            .success();

        let acl = query_global_default_acl(&owner, "f")
            .expect("the revoke should materialize a global default ACL row");
        assert!(
            !acl.contains("{=") && !acl.contains(",="),
            "PUBLIC must not remain in the new owner's defaults: {acl}"
        );
        let type_acl = query_global_default_acl(&owner, "T")
            .expect("the type revoke should materialize a global default ACL row");
        assert!(
            !type_acl.contains("{=") && !type_acl.contains(",="),
            "PUBLIC must not retain USAGE in the new owner's type defaults: {type_acl}"
        );
        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
                "--no-exit-code",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn drifted_public_grant_is_revoked_again() {
        let (fixture, _cleanup) = PublicFixture::new("pubdrift");
        let manifest = write_temp_manifest(&fixture.manifest());
        apply_until_converged(manifest.path(), 3);

        // Someone re-grants by hand, both on the object and as a schema default.
        execute_sql(&format!(
            r#"GRANT EXECUTE ON FUNCTION "{schema}".secret(integer) TO PUBLIC;
               ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA "{schema}"
                   GRANT EXECUTE ON FUNCTIONS TO PUBLIC;"#,
            schema = fixture.schema,
            owner = fixture.owner,
        ));
        assert!(query_has_function_privilege(
            &fixture.bystander,
            &fixture.secret_signature()
        ));

        apply_until_converged(manifest.path(), 3);

        assert!(
            !query_has_function_privilege(&fixture.bystander, &fixture.secret_signature()),
            "the re-granted PUBLIC EXECUTE should be revoked again"
        );
    }

    #[test]
    #[ignore]
    fn additive_mode_ignores_absence_while_adopt_applies_it() {
        let (fixture, _cleanup) = PublicFixture::new("pubmode");
        let manifest = write_temp_manifest(&fixture.manifest());

        // Additive never revokes, so the absence assertion is skipped rather
        // than failing the run.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "additive",
            ])
            .assert()
            .success()
            .stderr(predicate::str::contains(
                "additive reconciliation ignores every `ensure: absent` assertion",
            ));
        assert!(
            query_has_function_privilege(&fixture.bystander, &fixture.secret_signature()),
            "additive mode must not revoke PUBLIC EXECUTE"
        );

        // Adopt applies the same assertion.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--mode",
                "adopt",
            ])
            .assert()
            .success();
        assert!(
            !query_has_function_privilege(&fixture.bystander, &fixture.secret_signature()),
            "adopt mode must apply the absence assertion"
        );
    }

    #[test]
    #[ignore]
    fn overloaded_routines_converge_under_one_wildcard_absence() {
        let (fixture, _cleanup) = PublicFixture::new("puboverload");
        execute_sql(&format!(
            r#"SET ROLE "{owner}";
               CREATE FUNCTION "{schema}".secret(x text) RETURNS text
                   LANGUAGE sql SECURITY DEFINER AS 'SELECT x';
               CREATE PROCEDURE "{schema}".secret_proc() LANGUAGE sql AS 'SELECT 1';
               RESET ROLE;"#,
            owner = fixture.owner,
            schema = fixture.schema,
        ));

        let manifest = write_temp_manifest(&fixture.manifest());
        apply_until_converged(manifest.path(), 3);

        for signature in [
            format!("\"{}\".secret(integer)", fixture.schema),
            format!("\"{}\".secret(text)", fixture.schema),
            format!("\"{}\".secret_proc()", fixture.schema),
        ] {
            assert!(
                !query_has_function_privilege(&fixture.bystander, &signature),
                "{signature} should not be executable by PUBLIC"
            );
        }
    }

    #[test]
    #[ignore]
    fn unmanaged_public_grants_in_other_schemas_are_left_alone() {
        // Guards the #108 class of regression: declaring PUBLIC rules for one
        // schema must not turn every other PUBLIC ACL into drift, and a role
        // wildcard elsewhere must still converge.
        let (fixture, _cleanup) = PublicFixture::new("pubscope");
        let other_schema = unique_name("pubscope_other");
        let _other_cleanup = TestDbCleanup::new(format!(
            r#"DROP SCHEMA IF EXISTS "{other_schema}" CASCADE;"#
        ));
        execute_sql(&format!(
            r#"CREATE SCHEMA "{other_schema}" AUTHORIZATION "{owner}";
               SET ROLE "{owner}";
               CREATE FUNCTION "{other_schema}".extension_like() RETURNS integer
                   LANGUAGE sql AS 'SELECT 1';
               GRANT EXECUTE ON FUNCTION "{other_schema}".extension_like() TO PUBLIC;
               RESET ROLE;"#,
            other_schema = other_schema,
            owner = fixture.owner,
        ));

        let manifest = write_temp_manifest(&fixture.manifest_with_extra(
            "",
            &format!(
                r#"  - role: {caller}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {other_schema}, name: "*" }}
"#,
                caller = fixture.caller,
                other_schema = other_schema,
            ),
        ));

        apply_until_converged(manifest.path(), 3);

        assert!(
            query_has_function_privilege(
                &fixture.bystander,
                &format!("\"{other_schema}\".extension_like()")
            ),
            "PUBLIC EXECUTE outside the declared scope must survive"
        );
        assert!(
            query_has_function_privilege(
                &fixture.caller,
                &format!("\"{other_schema}\".extension_like()")
            ),
            "the role wildcard in the other schema should converge"
        );
    }

    #[test]
    #[ignore]
    fn a_role_named_public_is_not_the_public_pseudo_role() {
        let (fixture, _cleanup) = PublicFixture::new("publower");
        // PostgreSQL reserves the bare name `public`, so use the closest
        // legal spelling. It must survive while PUBLIC is revoked.
        let role = unique_name("public_role");
        let _role_cleanup = TestDbCleanup::new(format!(
            r#"DO $$ BEGIN
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                   EXECUTE 'DROP OWNED BY "{role}" CASCADE';
                 END IF;
               END $$;
               DROP ROLE IF EXISTS "{role}";"#
        ));
        execute_sql(&format!(r#"CREATE ROLE "{role}";"#));

        let manifest = write_temp_manifest(&fixture.manifest_with_extra(
            &format!("  - name: {role}\n"),
            &format!(
                r#"  - role: {role}
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#,
                role = role,
                schema = fixture.schema,
            ),
        ));

        apply_until_converged(manifest.path(), 3);

        // The quoted role keeps EXECUTE; the pseudo-role does not.
        assert!(
            query_has_function_privilege(&role, &fixture.secret_signature()),
            "a role whose name resembles the keyword should keep EXECUTE"
        );
        assert!(
            !query_has_function_privilege(&fixture.bystander, &fixture.secret_signature()),
            "PUBLIC should still be revoked"
        );
    }

    #[test]
    #[ignore]
    fn empty_schema_absence_is_vacuously_converged() {
        let schema = unique_name("pubempty_schema");
        let owner = unique_name("pubempty_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE; DROP ROLE IF EXISTS "{owner}";"#
        ));
        execute_sql(&format!(
            r#"CREATE ROLE "{owner}"; CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}";"#
        ));

        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {owner}
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
"#
        ));

        pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &database_url(),
                "--format",
                "summary",
                "--no-exit-code",
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains("No changes needed"));
    }

    #[test]
    #[ignore]
    fn preflight_warns_on_diff_and_blocks_only_on_apply() {
        let (fixture, _cleanup) = PublicFixture::new("pfgate");
        let reporter = unique_name("pfgate_reporter");
        let _reporter_cleanup = TestDbCleanup::new(format!(
            r#"DO $$ BEGIN
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{reporter}') THEN
                   EXECUTE 'DROP OWNED BY "{reporter}" CASCADE';
                 END IF;
               END $$;
               DROP ROLE IF EXISTS "{reporter}";"#
        ));
        execute_sql(&format!(
            r#"CREATE ROLE "{reporter}" LOGIN PASSWORD 'testpassword';
               GRANT USAGE ON SCHEMA "{schema}" TO "{reporter}";"#,
            reporter = reporter,
            schema = fixture.schema,
        ));

        // Only the absence rules: a positive wildcard grant would trip the
        // pre-existing UnsatisfiableWildcardGrant diagnostic first and mask
        // what this test is about.
        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {owner}
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: {{ type: function, schema: {schema}, name: "*" }}
default_privileges:
  - owner: {owner}
    scope: {{ type: global }}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
"#,
            owner = fixture.owner,
            schema = fixture.schema,
        ));
        let reporter_url = database_url_for_role(&reporter, "testpassword");

        // A CI drift check running as a read-only role must still get its
        // plan: diff executes no SQL, so authority problems are warnings.
        let diff_output = pgroles_cmd()
            .args([
                "diff",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &reporter_url,
                "--format",
                "summary",
                "--no-exit-code",
            ])
            .assert()
            .success()
            .get_output()
            .clone();
        assert!(
            String::from_utf8_lossy(&diff_output.stdout).contains("change(s)"),
            "diff should still produce a plan for a low-privilege role"
        );
        assert!(
            String::from_utf8_lossy(&diff_output.stderr)
                .contains("UnsatisfiableDefaultPrivilegeChange"),
            "diff should warn about executor authority"
        );

        // A dry run executes nothing either, so it also only warns.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &reporter_url,
                "--dry-run",
            ])
            .assert()
            .success();

        // The real apply is where authority actually matters.
        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &reporter_url,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "UnsatisfiableDefaultPrivilegeChange",
            ));

        // Nothing ran, so PUBLIC still holds EXECUTE.
        assert!(
            query_has_function_privilege(&reporter, &fixture.secret_signature()),
            "the blocked apply must not have changed anything"
        );
    }

    #[test]
    #[ignore]
    fn preflight_blocks_new_default_owner_for_a_non_superuser() {
        let executor = unique_name("pfnew_executor");
        let owner = unique_name("pfnew_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"DO $$ BEGIN
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') THEN
                   EXECUTE 'DROP OWNED BY "{owner}" CASCADE';
                 END IF;
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{executor}') THEN
                   EXECUTE 'DROP OWNED BY "{executor}" CASCADE';
                 END IF;
               END $$;
               DROP ROLE IF EXISTS "{owner}";
               DROP ROLE IF EXISTS "{executor}";"#
        ));
        execute_sql(&format!(
            r#"CREATE ROLE "{executor}" LOGIN CREATEROLE PASSWORD 'testpassword';"#
        ));
        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {owner}
default_privileges:
  - owner: {owner}
    scope: {{ type: global }}
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
"#
        ));
        let executor_url = database_url_for_role(&executor, "testpassword");

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &executor_url,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "UnsatisfiableDefaultPrivilegeChange",
            ));
        assert!(
            !query_role_exists(&owner),
            "preflight must reject before CREATE ROLE runs"
        );
    }

    #[test]
    #[ignore]
    fn preflight_blocks_positive_defaults_for_a_new_owner_and_non_superuser() {
        let executor = unique_name("pfnew_grant_executor");
        let owner = unique_name("pfnew_grant_owner");
        let _cleanup = TestDbCleanup::new(format!(
            r#"DO $$ BEGIN
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner}') THEN
                   EXECUTE 'DROP OWNED BY "{owner}" CASCADE';
                 END IF;
                 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{executor}') THEN
                   EXECUTE 'DROP OWNED BY "{executor}" CASCADE';
                 END IF;
               END $$;
               DROP ROLE IF EXISTS "{owner}";
               DROP ROLE IF EXISTS "{executor}";"#
        ));
        execute_sql(&format!(
            r#"CREATE ROLE "{executor}" LOGIN CREATEROLE PASSWORD 'testpassword';"#
        ));
        let manifest = write_temp_manifest(&format!(
            r#"
roles:
  - name: {owner}
  - name: {executor}
    external: true
default_privileges:
  - owner: {owner}
    scope: {{ type: global }}
    grant:
      - role: {executor}
        privileges: [SELECT]
        on_type: table
"#
        ));
        let executor_url = database_url_for_role(&executor, "testpassword");

        pgroles_cmd()
            .args([
                "apply",
                "--file",
                manifest.path().to_str().unwrap(),
                "--database-url",
                &executor_url,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "UnsatisfiableDefaultPrivilegeChange",
            ));
        assert!(
            !query_role_exists(&owner),
            "preflight must reject a positive default before CREATE ROLE runs"
        );
    }
}
