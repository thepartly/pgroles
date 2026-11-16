//! Fresh owner access must not depend on managed-service automatic grants.
use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::sql::{SqlContext, quote_ident, render_batch_with_context};
use pgroles_inspect::{
    InspectConfig, inspect, preflight_authority_issues, resolve_membership_options,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn explicit_fresh_owner_membership_bootstraps_schema_without_self_grant() {
    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&root)
        .await
        .unwrap();
    let policy = pgroles_core::authoring::prepare_policy(
        r#"
roles:
  - name: sbo_owner
    login: false
  - name: sbo_executor
    external: true
    preserve_undeclared_grants: true
schemas:
  - name: sbo_schema
    owner: sbo_owner
memberships:
  - role: sbo_owner
    members: [{ name: sbo_executor }]
default_privileges:
  - owner: sbo_owner
    scope: { type: schema, schema: sbo_schema }
    grant:
      - role: sbo_executor
        on_type: table
        privileges: [SELECT]
"#,
    )
    .unwrap();
    root.execute(
        "DROP SCHEMA IF EXISTS sbo_schema CASCADE; DROP ROLE IF EXISTS sbo_owner, sbo_executor;
        CREATE ROLE sbo_executor LOGIN CREATEROLE PASSWORD 'sbo-test-password'",
    )
    .await
    .unwrap();
    root.execute(
        format!(
            "GRANT CREATE ON DATABASE {} TO sbo_executor",
            quote_ident(&database)
        )
        .as_str(),
    )
    .await
    .unwrap();
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .username("sbo_executor")
        .password("sbo-test-password")
        .options([("createrole_self_grant", "")]);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let config = InspectConfig::from_expanded(&policy.expanded, false);
    for round in 0..2 {
        let current = inspect(&pool, &config).await.unwrap();
        let changes = filter_changes(diff(&current, &policy.desired), ReconciliationMode::Adopt);
        let changes = pgroles_core::diff::filter_external_role_changes(
            changes,
            &policy.manifest.roles,
            &policy.manifest.memberships,
        );
        let changes = resolve_membership_options(&pool, changes, &current)
            .await
            .unwrap();
        let issues = preflight_authority_issues(&pool, &changes, &current)
            .await
            .unwrap();
        assert!(issues.is_empty(), "round {round}: {issues:?}");
        if round == 0 {
            assert!(
                changes
                    .iter()
                    .any(|change| matches!(change, Change::CreateSchema { .. }))
            );
        }
        let mut tx = pool.begin().await.unwrap();
        for statement in render_batch_with_context(&changes, &SqlContext::default()).unwrap() {
            tx.execute(statement.sql.as_str())
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", statement.sql));
        }
        tx.commit().await.unwrap();
    }
    let current = inspect(&pool, &config).await.unwrap();
    let changes = filter_changes(diff(&current, &policy.desired), ReconciliationMode::Adopt);
    let changes = pgroles_core::diff::filter_external_role_changes(
        changes,
        &policy.manifest.roles,
        &policy.manifest.memberships,
    );
    assert!(changes.is_empty(), "follow-up diff: {changes:?}");
    let can_set: bool = sqlx::query_scalar("SELECT pg_has_role(current_user, 'sbo_owner', 'SET')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(can_set);
    pool.close().await;
    root.execute("DROP SCHEMA sbo_schema CASCADE; DROP OWNED BY sbo_owner, sbo_executor; DROP ROLE sbo_owner, sbo_executor").await.unwrap();
}
