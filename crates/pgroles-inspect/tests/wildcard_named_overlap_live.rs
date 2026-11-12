//! Live convergence for a named grant that repeats a wildcard grant.
//!
//! Inspection folds per-object privileges held on every object in a wildcard
//! scope into the `name: "*"` key. A desired graph that kept the named entry
//! beside the wildcard would see the named privilege as missing after every
//! apply, so each plan re-granted it and the manifest never reached a fixed
//! point.
//!
//! Requires DATABASE_URL (superuser); run with `cargo test -- --include-ignored`.

use sqlx::{Connection, Executor, PgPool};

use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::render_statements;
use pgroles_inspect::{InspectConfig, inspect};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

const ROLE: &str = "wno_r0";
const SCHEMA: &str = "wno_s0";

/// Drop-guard removing the test schema and role even on panic.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                reset(&pool).await;
            }
        });
    }
}

async fn reset(pool: &PgPool) {
    let _ = pool
        .execute(format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE").as_str())
        .await;
    let _ = pool.execute(format!("DROP OWNED BY {ROLE}").as_str()).await;
    let _ = pool
        .execute(format!("DROP ROLE IF EXISTS {ROLE}").as_str())
        .await;
}

/// `t` repeats the wildcard exactly; `u` repeats it and adds INSERT, which
/// must survive as a per-object grant. `v` is named nowhere.
const MANIFEST: &str = r#"
roles:
  - name: wno_r0

schemas:
  - name: wno_s0

grants:
  - role: wno_r0
    privileges: [SELECT]
    object: { type: table, schema: wno_s0, name: "*" }
  - role: wno_r0
    privileges: [SELECT]
    object: { type: table, schema: wno_s0, name: t }
  - role: wno_r0
    privileges: [SELECT, INSERT]
    object: { type: table, schema: wno_s0, name: u }
"#;

async fn plan(pool: &PgPool) -> Vec<Change> {
    let manifest = parse_manifest(MANIFEST).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("desired graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);
    let current = inspect(pool, &config).await.expect("inspection should run");
    filter_changes(diff(&current, &desired), ReconciliationMode::Authoritative)
}

/// Apply the way production does: every statement in one transaction.
async fn apply(pool: &PgPool, changes: &[Change]) {
    let mut conn = pool.acquire().await.expect("connection should acquire");
    let mut tx = conn.begin().await.expect("transaction should begin");
    for change in changes {
        for statement in render_statements(change).unwrap() {
            tx.execute(statement.as_str())
                .await
                .unwrap_or_else(|error| panic!("failed `{statement}`: {error}"));
        }
    }
    tx.commit().await.expect("transaction should commit");
}

async fn table_privileges(pool: &PgPool, table: &str) -> Vec<String> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT privilege_type::text
         FROM information_schema.role_table_grants
         WHERE grantee = $1 AND table_schema = $2 AND table_name = $3
         ORDER BY privilege_type",
    )
    .bind(ROLE)
    .bind(SCHEMA)
    .bind(table)
    .fetch_all(pool)
    .await
    .expect("privilege query should run");
    rows.into_iter().map(|(privilege,)| privilege).collect()
}

#[test]
#[ignore]
fn named_grant_repeating_a_wildcard_converges_in_one_apply() {
    let _cleanup = Cleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        reset(&pool).await;
        for statement in [
            format!("CREATE SCHEMA {SCHEMA}"),
            format!("CREATE TABLE {SCHEMA}.t (id int)"),
            format!("CREATE TABLE {SCHEMA}.u (id int)"),
            format!("CREATE TABLE {SCHEMA}.v (id int)"),
        ] {
            pool.execute(statement.as_str())
                .await
                .unwrap_or_else(|error| panic!("failed `{statement}`: {error}"));
        }

        let first = plan(&pool).await;
        assert!(!first.is_empty(), "the first plan should create and grant");
        apply(&pool, &first).await;

        let second = plan(&pool).await;
        assert!(
            second.is_empty(),
            "the plan after one apply should be empty, got {second:#?}"
        );

        assert_eq!(table_privileges(&pool, "t").await, ["SELECT"]);
        assert_eq!(table_privileges(&pool, "u").await, ["INSERT", "SELECT"]);
        assert_eq!(table_privileges(&pool, "v").await, ["SELECT"]);
    });
}
