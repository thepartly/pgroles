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
