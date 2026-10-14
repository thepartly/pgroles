//! Live convergence for delegated grants to PUBLIC.
//!
//! A grant-option holder can grant a privilege to PUBLIC; that entry lives in
//! the *delegate's* ACL slot, so an owner-attributed plain revoke leaves it in
//! place and a declared `ensure: absent` re-plans forever. PUBLIC ACL rows now
//! record their grantor like role rows do, so the diff emits a
//! grantor-targeted revoke (`SET ROLE <delegate>`) and the assertion converges
//! in one apply — for a non-superuser executor.
//!
//! Requires DATABASE_URL (superuser); run with `cargo test -- --include-ignored`.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgPool};
use std::str::FromStr;

use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::{Grantee, RoleGraph};
use pgroles_core::sql::render_statements;
use pgroles_inspect::{InspectConfig, inspect, preflight_authority_issues};

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

const ROLES: [&str; 3] = ["pdg_exec", "pdg_delegate", "pdg_owner"];

/// Drop-guard removing the test objects and roles even on panic.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP TABLE IF EXISTS pdg_t").await;
                for role in ROLES {
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

const MANIFEST: &str = r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [SELECT]
    object:
      type: table
      schema: public
      name: pdg_t
"#;

async fn plan(pool: &PgPool, manifest_yaml: &str) -> Vec<Change> {
    let manifest = parse_manifest(manifest_yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("desired graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);
    let current = inspect(pool, &config).await.expect("inspection should run");
    filter_changes(diff(&current, &desired), ReconciliationMode::Authoritative)
}

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

#[test]
#[ignore]
fn delegated_public_grant_converges_for_a_non_superuser_executor() {
    let _cleanup = Cleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let (version,): (i32,) =
            sqlx::query_as("SELECT current_setting('server_version_num')::int")
                .fetch_one(&pool)
                .await
                .expect("version probe should run");
        if version < 160_000 {
            // Object-ACL grantor targeting itself is not version-gated, but
            // this test's assertions were validated against the PG16+
            // matrix, which is also where CI runs.
            return;
        }
        let _ = pool.execute("DROP TABLE IF EXISTS pdg_t").await;
        for role in ROLES {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        // The reviewer's reproduction: the delegate grants SELECT to PUBLIC,
        // so the entry is attributed to the delegate — an owner-attributed
        // plain revoke leaves it in place.
        pool.execute(
            "CREATE ROLE pdg_owner; CREATE ROLE pdg_delegate; \
             CREATE ROLE pdg_exec LOGIN PASSWORD 'pdg_exec_pw'; \
             CREATE TABLE pdg_t(i int); ALTER TABLE pdg_t OWNER TO pdg_owner; \
             SET ROLE pdg_owner; \
             GRANT SELECT ON pdg_t TO pdg_delegate WITH GRANT OPTION; \
             RESET ROLE; \
             SET ROLE pdg_delegate; \
             GRANT SELECT ON pdg_t TO PUBLIC; \
             RESET ROLE; \
             GRANT pdg_owner TO pdg_exec; \
             GRANT pdg_delegate TO pdg_exec;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("pdg_exec")
            .password("pdg_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        let changes = plan(&exec_pool, MANIFEST).await;
        let public_revoke_grantors: Vec<&str> = changes
            .iter()
            .filter_map(|change| match change {
                Change::Revoke {
                    role: Grantee::Public,
                    grantor,
                    ..
                } => grantor.as_deref(),
                _ => None,
            })
            .collect();
        assert_eq!(
            public_revoke_grantors,
            ["pdg_delegate"],
            "the PUBLIC revoke must target the delegate's ACL entry: {changes:?}"
        );
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.is_empty(),
            "executor can become the delegate: {issues:?}"
        );

        apply(&exec_pool, &changes).await;

        let replan = plan(&exec_pool, MANIFEST).await;
        assert!(replan.is_empty(), "must converge in one apply: {replan:?}");
        // Every role reaches the table through memberships here, so probe the
        // ACL itself: the PUBLIC entry (grantee 0) must be gone.
        let (public_select,): (bool,) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM pg_class c \
             CROSS JOIN LATERAL aclexplode(c.relacl) a \
             WHERE c.relname = 'pdg_t' AND a.grantee = 0 \
               AND a.privilege_type = 'SELECT')",
        )
        .fetch_one(&pool)
        .await
        .expect("probe should run");
        assert!(!public_select, "the delegate's PUBLIC entry must be gone");
    });
}

const LP_ROLES: [&str; 3] = ["pdl_exec", "pdl_delegate", "pdl_owner"];

/// Drop-guard for the least-privilege variant.
struct LpCleanup;

impl Drop for LpCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP TABLE IF EXISTS pdl_t").await;
                for role in LP_ROLES {
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

const LP_MANIFEST: &str = r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [SELECT]
    object:
      type: table
      schema: public
      name: pdl_t
"#;

/// The least-privilege posture: the executor can become the delegate but has
/// no path to the object owner. The generated SQL is `SET ROLE pdl_delegate;
/// REVOKE ...;`, which needs exactly that — the PUBLIC owner-authority sweep
/// must not also demand owner membership for a grantor-targeted revoke.
#[test]
#[ignore]
fn delegated_public_grant_converges_without_owner_membership() {
    let _cleanup = LpCleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let (version,): (i32,) =
            sqlx::query_as("SELECT current_setting('server_version_num')::int")
                .fetch_one(&pool)
                .await
                .expect("version probe should run");
        if version < 160_000 {
            return;
        }
        let _ = pool.execute("DROP TABLE IF EXISTS pdl_t").await;
        for role in LP_ROLES {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        pool.execute(
            "CREATE ROLE pdl_owner; CREATE ROLE pdl_delegate; \
             CREATE ROLE pdl_exec LOGIN PASSWORD 'pdl_exec_pw'; \
             CREATE TABLE pdl_t(i int); ALTER TABLE pdl_t OWNER TO pdl_owner; \
             SET ROLE pdl_owner; \
             GRANT SELECT ON pdl_t TO pdl_delegate WITH GRANT OPTION; \
             RESET ROLE; \
             SET ROLE pdl_delegate; \
             GRANT SELECT ON pdl_t TO PUBLIC; \
             RESET ROLE; \
             GRANT pdl_delegate TO pdl_exec;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("pdl_exec")
            .password("pdl_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        let changes = plan(&exec_pool, LP_MANIFEST).await;
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::Revoke { role: Grantee::Public, grantor: Some(grantor), .. }
                    if grantor == "pdl_delegate"
            )),
            "the PUBLIC revoke must target the delegate's entry: {changes:?}"
        );
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.is_empty(),
            "becoming the delegate is the only requirement — owner authority \
             must not be demanded for a grantor-targeted PUBLIC revoke: {issues:?}"
        );

        apply(&exec_pool, &changes).await;

        let replan = plan(&exec_pool, LP_MANIFEST).await;
        assert!(replan.is_empty(), "must converge in one apply: {replan:?}");
    });
}
