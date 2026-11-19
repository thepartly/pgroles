//! An executor's own ADMIN membership in a role it creates (issue #270).
use pgroles_core::diff::{ReconciliationMode, diff, filter_changes, filter_external_role_changes};
use pgroles_core::sql::{SqlContext, render_batch_with_context};
use pgroles_inspect::{
    InspectConfig, inspect, preflight_authority_issues, resolve_membership_options,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database and DATABASE_URL"]
async fn executor_admin_membership_in_a_created_role_converges() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    for inherit in [true, false] {
        let policy = pgroles_core::authoring::prepare_policy(&format!(
            r#"
roles:
  - name: ca_owner
    login: false
  - name: ca_executor
    external: true
    preserve_undeclared_grants: true
memberships:
  - role: ca_owner
    members: [{{ name: ca_executor, inherit: {inherit}, admin: true }}]
"#
        ))
        .unwrap();
        root.execute(
            "DROP ROLE IF EXISTS ca_owner, ca_executor;
            CREATE ROLE ca_executor LOGIN CREATEROLE PASSWORD 'ca-test-password'",
        )
        .await
        .unwrap();
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .username("ca_executor")
            .password("ca-test-password")
            .options([("createrole_self_grant", "")]);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        let config = InspectConfig::from_expanded(&policy.expanded, false);
        let plan = |current| {
            filter_external_role_changes(
                filter_changes(diff(current, &policy.desired), ReconciliationMode::Adopt),
                &policy.manifest.roles,
                &policy.manifest.memberships,
            )
        };

        let current = inspect(&pool, &config).await.unwrap();
        let changes = resolve_membership_options(&pool, plan(&current), &current)
            .await
            .unwrap();
        let issues = preflight_authority_issues(&pool, &changes, &current)
            .await
            .unwrap();
        assert!(issues.is_empty(), "inherit {inherit}: {issues:?}");
        let mut tx = pool.begin().await.unwrap();
        for statement in render_batch_with_context(&changes, &SqlContext::default()).unwrap() {
            tx.execute(statement.sql.as_str())
                .await
                .unwrap_or_else(|error| panic!("inherit {inherit}: {}: {error}", statement.sql));
        }
        tx.commit().await.unwrap();

        let current = inspect(&pool, &config).await.unwrap();
        let follow_up = plan(&current);
        assert!(
            follow_up.is_empty(),
            "inherit {inherit}: follow-up diff: {follow_up:?}"
        );
        let (admin, inherits): (bool, bool) = sqlx::query_as(
            "SELECT pg_has_role(current_user, 'ca_owner', 'USAGE WITH ADMIN OPTION'), \
             pg_has_role(current_user, 'ca_owner', 'USAGE')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(admin, "inherit {inherit}: executor lacks ADMIN");
        assert_eq!(inherits, inherit, "inherit {inherit}");
        pool.close().await;
    }
    root.execute("DROP ROLE ca_owner, ca_executor")
        .await
        .unwrap();
}

/// Tests that change the database ACL take turns: concurrent grants on one
/// `pg_database` row fail with "tuple concurrently updated".
static DATABASE_ACL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The executor created the owner in an earlier apply, before the policy
/// declared its membership (issue #272). Declaring the membership and a
/// schema for that owner must apply in one plan and then converge.
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL database and DATABASE_URL"]
async fn membership_declared_after_creation_lets_the_executor_create_schemas() {
    let _database_acl = DATABASE_ACL.lock().await;
    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&root)
        .await
        .unwrap();
    for (inherit, admin) in [(true, false), (false, false), (true, true)] {
        root.execute("DROP SCHEMA IF EXISTS cl_schema CASCADE")
            .await
            .unwrap();
        for role in ["cl_owner", "cl_executor"] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                    .bind(role)
                    .fetch_one(&root)
                    .await
                    .unwrap();
            if exists {
                root.execute(format!("DROP OWNED BY {role}").as_str())
                    .await
                    .unwrap();
            }
        }
        root.execute(
            "DROP ROLE IF EXISTS cl_owner, cl_executor;
            CREATE ROLE cl_executor LOGIN CREATEROLE PASSWORD 'cl-test-password'",
        )
        .await
        .unwrap();
        root.execute(format!("GRANT CREATE ON DATABASE {database} TO cl_executor").as_str())
            .await
            .unwrap();
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .username("cl_executor")
            .password("cl-test-password")
            .options([("createrole_self_grant", "")]);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        // The earlier apply: the role exists, the membership was never declared.
        pool.execute("CREATE ROLE cl_owner").await.unwrap();

        let policy = pgroles_core::authoring::prepare_policy(&format!(
            r#"
roles:
  - name: cl_owner
  - name: cl_executor
    external: true
    preserve_undeclared_grants: true
schemas:
  - name: cl_schema
    owner: cl_owner
memberships:
  - role: cl_owner
    members: [{{ name: cl_executor, inherit: {inherit}, admin: {admin} }}]
"#
        ))
        .unwrap();
        let config = InspectConfig::from_expanded(&policy.expanded, false);
        let plan = |current| {
            filter_external_role_changes(
                filter_changes(diff(current, &policy.desired), ReconciliationMode::Adopt),
                &policy.manifest.roles,
                &policy.manifest.memberships,
            )
        };
        let case = format!("inherit {inherit}, admin {admin}");

        let current = inspect(&pool, &config).await.unwrap();
        let changes = resolve_membership_options(&pool, plan(&current), &current)
            .await
            .unwrap();
        let issues = preflight_authority_issues(&pool, &changes, &current)
            .await
            .unwrap();
        assert!(issues.is_empty(), "{case}: {issues:?}");
        let mut tx = pool.begin().await.unwrap();
        for statement in render_batch_with_context(&changes, &SqlContext::default()).unwrap() {
            tx.execute(statement.sql.as_str())
                .await
                .unwrap_or_else(|error| panic!("{case}: {}: {error}", statement.sql));
        }
        tx.commit().await.unwrap();

        let current = inspect(&pool, &config).await.unwrap();
        let follow_up = plan(&current);
        assert!(
            follow_up.is_empty(),
            "{case}: follow-up diff: {follow_up:?}"
        );
        let (can_set, inherits, has_admin): (bool, bool, bool) = sqlx::query_as(
            "SELECT pg_has_role(current_user, 'cl_owner', 'SET'), \
             pg_has_role(current_user, 'cl_owner', 'USAGE'), \
             pg_has_role(current_user, 'cl_owner', 'USAGE WITH ADMIN OPTION')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(can_set, "{case}: executor lacks SET");
        assert_eq!(inherits, inherit, "{case}");
        assert!(has_admin, "{case}: executor lost ADMIN");
        pool.close().await;
    }
    root.execute(
        "DROP SCHEMA cl_schema CASCADE; DROP OWNED BY cl_owner; DROP OWNED BY cl_executor;
        DROP ROLE cl_owner, cl_executor",
    )
    .await
    .unwrap();
}
