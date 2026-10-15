//! A non-superuser executor's own ADMIN edges survive adopt reconciliation.
//! Run only on disposable PostgreSQL 16+ databases.
use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::sql::{SqlContext, render_batch_with_context};
use pgroles_inspect::{
    InspectConfig, inspect, preflight_authority_issues, resolve_membership_options,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;

/// Both tests recreate the same cluster-wide `eap_*` roles.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const EXECUTOR: &str = "eap_exec";
const PASSWORD: &str = "eap-test-password";
const ROLES: &str = "\"eap-fresh-editor\", eap_seeded_owner, eap_app_core, eap_exec";

async fn reset(root: &PgPool, self_grant: &str) {
    root.execute(format!("DROP ROLE IF EXISTS {ROLES}").as_str())
        .await
        .unwrap();
    root.execute(
        format!(
            "CREATE ROLE {EXECUTOR} LOGIN CREATEROLE PASSWORD '{PASSWORD}';
             ALTER ROLE {EXECUTOR} SET createrole_self_grant = '{self_grant}';
             CREATE ROLE eap_app_core LOGIN;
             CREATE ROLE eap_seeded_owner;
             GRANT eap_seeded_owner TO {EXECUTOR} WITH ADMIN OPTION"
        )
        .as_str(),
    )
    .await
    .unwrap();
}

async fn executor_pool() -> PgPool {
    let options = PgConnectOptions::from_str(&std::env::var("DATABASE_URL").unwrap())
        .unwrap()
        .username(EXECUTOR)
        .password(PASSWORD);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap()
}

/// The CLI's adopt planning pipeline, short of the apply guards.
async fn plan(pool: &PgPool, yaml: &str) -> (Vec<Change>, Vec<String>) {
    let prepared = pgroles_core::authoring::prepare_policy(yaml).unwrap();
    let config = InspectConfig::from_expanded(&prepared.expanded, false);
    let current = inspect(pool, &config).await.unwrap();
    let changes = filter_changes(diff(&current, &prepared.desired), ReconciliationMode::Adopt);
    let changes = pgroles_core::diff::filter_external_role_changes(
        changes,
        &prepared.manifest.roles,
        &prepared.manifest.memberships,
    );
    let changes = resolve_membership_options(pool, changes, &current)
        .await
        .unwrap();
    let issues = preflight_authority_issues(pool, &changes, &current)
        .await
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect();
    (changes, issues)
}

async fn apply(pool: &PgPool, changes: &[Change], case: &str) {
    let statements = render_batch_with_context(changes, &SqlContext::default()).unwrap();
    let mut tx = pool.begin().await.unwrap();
    for statement in statements {
        tx.execute(statement.sql.as_str())
            .await
            .unwrap_or_else(|error| panic!("{case}: {}: {error}", statement.sql));
    }
    tx.commit().await.unwrap();
}

async fn executor_admin_edges(root: &PgPool) -> Vec<(String, String, bool)> {
    sqlx::query_as(
        "SELECT r.rolname::text, g.rolname::text, a.admin_option
         FROM pg_auth_members a
         JOIN pg_roles r ON r.oid = a.roleid
         JOIN pg_roles m ON m.oid = a.member
         JOIN pg_roles g ON g.oid = a.grantor
         WHERE m.rolname = $1 AND a.admin_option
         ORDER BY 1, 2",
    )
    .bind(EXECUTOR)
    .fetch_all(root)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn apply_then_diff_keeps_the_executors_own_admin_edges() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let root = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&root)
        .await
        .unwrap();
    if version < 160_000 {
        return;
    }
    let bootstrap: String = sqlx::query_scalar("SELECT rolname::text FROM pg_roles WHERE oid = 10")
        .fetch_one(&root)
        .await
        .unwrap();

    // The CREATE ROLE self-grant on eap-fresh-editor and an explicit
    // superuser ADMIN grant on eap_seeded_owner (the migration-bootstrap
    // shape), both attributed to the bootstrap superuser. The executor is
    // either undeclared, declared without ADMIN, or declared as live.
    for self_grant in ["", "set, inherit"] {
        for executor_member in [
            "",
            "{ name: eap_exec }",
            "{ name: eap_exec, admin: true, inherit: true }",
        ] {
            let case = format!("createrole_self_grant={self_grant:?} executor={executor_member:?}");
            reset(&root, self_grant).await;
            let policy = |executor_member: &str| {
                let executor_line = if executor_member.is_empty() {
                    String::new()
                } else {
                    format!("\n      - {executor_member}")
                };
                format!(
                    r#"
roles:
  - name: eap-fresh-editor
    login: false
  - name: eap_seeded_owner
    login: false
memberships:
  - role: eap-fresh-editor
    members:
      - {{ name: eap_app_core }}{executor_line}
  - role: eap_seeded_owner
    members:
      - {{ name: eap_app_core }}{executor_line}
"#
                )
            };
            let pool = executor_pool().await;

            // Create the role undeclared, then (as in prod) declare the
            // executor's membership in the now-existing roles.
            for (step, yaml) in [policy(""), policy(executor_member)].iter().enumerate() {
                let (changes, issues) = plan(&pool, yaml).await;
                assert!(issues.is_empty(), "{case}: first plan: {issues:?}");
                apply(&pool, &changes, &case).await;

                // A non-empty createrole_self_grant adds a second, non-ADMIN
                // edge granted by the executor itself. Undeclared, it is an
                // ordinary adopt-mode removal the executor can perform.
                let (changes, issues) = plan(&pool, yaml).await;
                assert!(issues.is_empty(), "{case}: second plan: {issues:?}");
                if step == 0 && !self_grant.is_empty() {
                    assert_eq!(
                        changes,
                        vec![Change::RemoveMember {
                            role: "eap-fresh-editor".into(),
                            member: EXECUTOR.into(),
                            grantor: Some(EXECUTOR.into()),
                        }],
                        "{case}"
                    );
                    apply(&pool, &changes, &case).await;
                    let (changes, issues) = plan(&pool, yaml).await;
                    assert!(issues.is_empty(), "{case}: third plan: {issues:?}");
                    assert!(changes.is_empty(), "{case}: third plan: {changes:?}");
                } else {
                    assert!(
                        changes.is_empty(),
                        "{case}: apply then diff must converge: {changes:?}"
                    );
                }
            }
            assert_eq!(
                executor_admin_edges(&root).await,
                vec![
                    ("eap-fresh-editor".to_string(), bootstrap.clone(), true),
                    ("eap_seeded_owner".to_string(), bootstrap.clone(), true),
                ],
                "{case}"
            );
            pool.close().await;
        }
    }
    root.execute(format!("DROP ROLE IF EXISTS {ROLES}").as_str())
        .await
        .unwrap();
    root.close().await;
}

/// Turning INHERIT off on a bootstrap-attributed edge needs that grantor's
/// privileges. With no earlier reductions in the plan, the diagnostic must
/// not blame them.
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn bootstrap_inherit_reduction_names_the_missing_grantor_privileges() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let root = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&root)
        .await
        .unwrap();
    if version < 160_000 {
        return;
    }
    reset(&root, "").await;
    root.execute("GRANT eap_seeded_owner TO eap_app_core WITH INHERIT TRUE")
        .await
        .unwrap();
    let pool = executor_pool().await;
    let (changes, issues) = plan(
        &pool,
        r#"
roles:
  - name: eap_seeded_owner
    login: false
memberships:
  - role: eap_seeded_owner
    members:
      - { name: eap_app_core, inherit: false }
"#,
    )
    .await;
    pool.close().await;
    root.execute(format!("DROP ROLE IF EXISTS {ROLES}").as_str())
        .await
        .unwrap();
    root.close().await;

    assert!(
        matches!(
            changes.as_slice(),
            [Change::UpdateMemberOptions {
                inherit: Some(false),
                admin: None,
                ..
            }]
        ),
        "{changes:?}"
    );
    assert!(!issues.is_empty());
    assert!(
        issues
            .iter()
            .all(|issue| !issue.contains("earlier membership reductions")),
        "{issues:#?}"
    );
    assert!(
        issues
            .iter()
            .any(|issue| issue.contains("GRANTED BY requires the grantor's privileges")),
        "{issues:#?}"
    );
}
