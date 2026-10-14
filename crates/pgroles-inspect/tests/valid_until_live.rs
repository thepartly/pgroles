//! Live convergence coverage for `password_valid_until`.
//!
//! Desired state and inspection compare this field by string equality, so
//! the two must agree on one canonical rendering. Inspection reports UTC
//! second-precision `YYYY-MM-DDTHH:MM:SSZ`; the manifest accepts exactly that
//! form. `VALID UNTIL 'infinity'` — which pgroles itself sets when removing an
//! expiration — must inspect as "no expiration", not as an empty string that
//! no manifest value can ever equal (which re-planned the ALTER ROLE forever).
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use sqlx::{Executor, PgPool};

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

/// Drop-guard removing the test role even on panic.
struct RoleCleanup;

impl Drop for RoleCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP ROLE IF EXISTS vu_live_role").await;
            }
        });
    }
}

const MANIFEST_WITH_EXPIRY: &str = r#"
roles:
  - name: vu_live_role
    login: true
    password_valid_until: "2030-06-15T09:00:00Z"
"#;

const MANIFEST_WITHOUT_EXPIRY: &str = r#"
roles:
  - name: vu_live_role
    login: true
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
    for change in changes {
        for statement in render_statements(change).unwrap() {
            pool.execute(statement.as_str())
                .await
                .unwrap_or_else(|error| panic!("failed `{statement}`: {error}"));
        }
    }
}

#[test]
#[ignore]
fn valid_until_converges_and_infinity_inspects_as_none() {
    let _cleanup = RoleCleanup;
    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let _ = pool.execute("DROP ROLE IF EXISTS vu_live_role").await;

        // A canonical-form expiration converges in one apply.
        let changes = plan(&pool, MANIFEST_WITH_EXPIRY).await;
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::CreateRole { .. })),
            "fresh role should be created: {changes:?}"
        );
        apply(&pool, &changes).await;
        let replan = plan(&pool, MANIFEST_WITH_EXPIRY).await;
        assert!(
            replan.is_empty(),
            "canonical valid_until must be idempotent, still planning: {replan:?}"
        );

        // Removing the expiration renders `VALID UNTIL 'infinity'`; the next
        // inspection must see "no expiration", not an empty string.
        let changes = plan(&pool, MANIFEST_WITHOUT_EXPIRY).await;
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::AlterRole { .. })),
            "dropping the expiration should plan an ALTER ROLE: {changes:?}"
        );
        apply(&pool, &changes).await;
        let replan = plan(&pool, MANIFEST_WITHOUT_EXPIRY).await;
        assert!(
            replan.is_empty(),
            "VALID UNTIL 'infinity' must inspect as no expiration, still planning: {replan:?}"
        );

        // An explicit hand-set 'infinity' (brownfield) is equally invisible.
        pool.execute("ALTER ROLE vu_live_role VALID UNTIL 'infinity'")
            .await
            .expect("hand-set infinity should succeed");
        let replan = plan(&pool, MANIFEST_WITHOUT_EXPIRY).await;
        assert!(
            replan.is_empty(),
            "hand-set infinity must not diff against an expiry-free manifest: {replan:?}"
        );

        // '-infinity' means "already expired" — the opposite of "never
        // expires" — so it must stay visible to the diff: one ALTER ROLE
        // repairs it to the declared state, and the repair converges.
        pool.execute("ALTER ROLE vu_live_role VALID UNTIL '-infinity'")
            .await
            .expect("hand-set -infinity should succeed");
        let changes = plan(&pool, MANIFEST_WITHOUT_EXPIRY).await;
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::AlterRole { .. })),
            "-infinity must diff against an expiry-free manifest: {changes:?}"
        );
        apply(&pool, &changes).await;
        let replan = plan(&pool, MANIFEST_WITHOUT_EXPIRY).await;
        assert!(
            replan.is_empty(),
            "repairing -infinity must converge: {replan:?}"
        );
    });
}
