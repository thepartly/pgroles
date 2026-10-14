//! Live round-trip test for role configuration defaults.
//!
//! Exercises the full pipeline against a real PostgreSQL server:
//! manifest → expand → diff → SQL → execute → inspect → diff again.
//! This is the coverage that catches version- or quoting-dependent drift
//! in how `pg_roles.rolconfig` stores values (e.g. list-typed settings set
//! from a single literal come back double-quoted), which unit tests with
//! hand-written rolconfig fixtures cannot see.
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use sqlx::{Executor, PgPool};

use pgroles_core::diff::{Change, diff};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::render_statements;
use pgroles_inspect::{InspectConfig, inspect};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos()
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

async fn execute_all(pool: &PgPool, statements: &[String]) {
    for statement in statements {
        pool.execute(statement.as_str())
            .await
            .unwrap_or_else(|error| panic!("failed to execute `{statement}`: {error}"));
    }
}

struct RoleCleanup {
    roles: Vec<String>,
}

impl Drop for RoleCleanup {
    fn drop(&mut self) {
        let roles = self.roles.clone();
        with_runtime(async move {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect for cleanup");
            for role in roles {
                let _ = pool
                    .execute(format!(r#"DROP ROLE IF EXISTS "{role}";"#).as_str())
                    .await;
            }
        });
    }
}

/// Like `RoleCleanup`, but also drops schemas. Schemas are dropped FIRST:
/// `DROP ROLE` fails (via `pg_shdepend`) while the role still holds grants on
/// a surviving schema, whereas `DROP SCHEMA ... CASCADE` clears those
/// dependent ACL entries, letting the subsequent role drops succeed even if a
/// future test grants schema privileges to its roles.
struct RoleAndSchemaCleanup {
    roles: Vec<String>,
    schemas: Vec<String>,
}

impl Drop for RoleAndSchemaCleanup {
    fn drop(&mut self) {
        let roles = self.roles.clone();
        let schemas = self.schemas.clone();
        with_runtime(async move {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect for cleanup");
            for schema in schemas {
                let _ = pool
                    .execute(format!(r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE;"#).as_str())
                    .await;
            }
            for role in roles {
                let _ = pool
                    .execute(format!(r#"DROP ROLE IF EXISTS "{role}";"#).as_str())
                    .await;
            }
        });
    }
}

#[test]
#[ignore]
fn role_config_converges_and_detects_drift() {
    let suffix = unique_suffix();
    let blue = format!("cfg_blue_{suffix}");
    let green = format!("cfg_green_{suffix}");
    let combined = format!("cfg_combined_{suffix}");
    let _cleanup = RoleCleanup {
        roles: vec![blue.clone(), green.clone(), combined.clone()],
    };

    // The issue-132 blue/green pattern, plus a multi-element search_path with
    // an element PostgreSQL quotes on storage ("$user") — exercising the
    // element-wise GUC list handling end to end.
    let yaml = format!(
        r#"
roles:
  - name: {combined}
  - name: {blue}
    login: true
    config:
      role: {combined}
      search_path: '"$user", public'
  - name: {green}
    login: true
    config:
      role: {combined}

memberships:
  - role: {combined}
    members:
      - name: {blue}
      - name: {green}
"#
    );

    let manifest = parse_manifest(&yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);

    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");

        // Fresh state: plan creates everything, including config alters.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(!changes.is_empty(), "fresh plan should not be empty");
        let statements: Vec<String> = changes
            .iter()
            .flat_map(|change| render_statements(change).unwrap())
            .collect();
        assert!(
            statements
                .iter()
                .any(|s| s
                    == &format!(r#"ALTER ROLE "{blue}" SET "search_path" = '$user', 'public';"#)),
            "list GUCs must render one literal per element, got: {statements:?}"
        );
        execute_all(&pool, &statements).await;

        // The applied search_path must be a real two-element path, not one
        // schema literally named `$user, public`.
        let (stored,): (String,) = sqlx::query_as(
            "SELECT s FROM pg_roles r, unnest(r.rolconfig) AS s
             WHERE r.rolname = $1 AND s LIKE 'search_path=%'",
        )
        .bind(&blue)
        .fetch_one(&pool)
        .await
        .expect("failed to read stored search_path");
        assert_eq!(stored, r#"search_path="$user", public"#);

        // Converged: a re-inspect must produce an empty plan. This is the
        // no-flapping property — if rolconfig normalization ever disagrees
        // with what we applied, this assertion catches it.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(
            changes.is_empty(),
            "expected converged state, got: {changes:?}"
        );

        // Drift both ways: green loses its setting, blue gains a stray one.
        execute_all(
            &pool,
            &[
                format!(r#"ALTER ROLE "{green}" RESET "role";"#),
                format!(r#"ALTER ROLE "{blue}" SET "statement_timeout" = '10s';"#),
            ],
        )
        .await;

        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        let statements: Vec<String> = changes
            .iter()
            .flat_map(|change| render_statements(change).unwrap())
            .collect();
        assert!(
            statements
                .iter()
                .any(|s| s == &format!(r#"ALTER ROLE "{green}" SET "role" = '{combined}';"#)),
            "expected drift plan to restore green's role setting, got: {statements:?}"
        );
        assert!(
            statements
                .iter()
                .any(|s| s == &format!(r#"ALTER ROLE "{blue}" RESET "statement_timeout";"#)),
            "expected drift plan to reset blue's stray setting, got: {statements:?}"
        );

        // Applying the drift plan converges again.
        execute_all(&pool, &statements).await;
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(
            changes.is_empty(),
            "expected re-converged state, got: {changes:?}"
        );
    });
}

/// Live round-trip for profile-level `config`, exercising the `{schema}`
/// placeholder end to end: a profile bound to one schema generates a role
/// whose `search_path` is the schema's literal name. Also declares the
/// schema itself so the plan includes `CreateSchema`, proving that path
/// isn't specific to hand-written roles either.
#[test]
#[ignore]
fn profile_config_placeholder_round_trips() {
    let suffix = unique_suffix();
    let schema = format!("cfgprof_{suffix}");
    let role = format!("{schema}-editor");
    let _cleanup = RoleAndSchemaCleanup {
        roles: vec![role.clone()],
        schemas: vec![schema.clone()],
    };

    let yaml = format!(
        r#"
schemas:
  - name: {schema}
    profiles: [editor]

profiles:
  editor:
    login: true
    config:
      search_path: "{{schema}}"
      statement_timeout: "30s"
"#
    );

    let manifest = parse_manifest(&yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);

    // The `{schema}` placeholder must have been substituted with the literal
    // schema name before we ever hit the database.
    assert_eq!(
        desired.roles[&role]
            .config
            .get("search_path")
            .map(String::as_str),
        Some(schema.as_str())
    );

    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");

        // Fresh state: plan creates the schema, the role, and its config.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(!changes.is_empty(), "fresh plan should not be empty");
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, Change::CreateSchema { name, .. } if name == &schema)),
            "expected a CreateSchema change, got: {changes:?}"
        );
        let statements: Vec<String> = changes
            .iter()
            .flat_map(|change| render_statements(change).unwrap())
            .collect();
        assert!(
            statements
                .iter()
                .any(|s| s == &format!(r#"ALTER ROLE "{role}" SET "search_path" = '{schema}';"#)),
            "expected the substituted search_path to be applied, got: {statements:?}"
        );
        execute_all(&pool, &statements).await;

        // Converged: re-inspecting must produce an empty plan.
        let current = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&current, &desired);
        assert!(
            changes.is_empty(),
            "expected converged state, got: {changes:?}"
        );

        // Sanity: the role really carries the substituted value, not the
        // literal placeholder text.
        assert_eq!(
            current.roles[&role]
                .config
                .get("search_path")
                .map(String::as_str),
            Some(schema.as_str())
        );
    });
}
