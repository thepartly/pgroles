//! Fresh owner access must not depend on automatic creator memberships.
use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::sql::{SqlContext, quote_ident, render_batch_with_context};
use pgroles_inspect::{
    InspectConfig, inspect, preflight_authority_issues, resolve_membership_options,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;

/// Tests in this file run in parallel. Granting and dropping database
/// privileges both rewrite the `pg_database` row, and concurrent rewrites fail
/// with "tuple concurrently updated".
static DATABASE_ACL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Plan and apply `policy` twice as the pool's role, requiring a clean
/// preflight each time and an empty diff afterwards. Returns the first plan.
async fn apply_until_converged(
    pool: &PgPool,
    policy: &pgroles_core::authoring::PreparedPolicy,
) -> Vec<Change> {
    let config = InspectConfig::from_expanded(&policy.expanded, false);
    let plan = |current: &pgroles_core::model::RoleGraph| {
        pgroles_core::diff::filter_external_role_changes(
            filter_changes(diff(current, &policy.desired), ReconciliationMode::Adopt),
            &policy.manifest.roles,
            &policy.manifest.memberships,
        )
    };
    let mut first_round = Vec::new();
    for round in 0..2 {
        let current = inspect(pool, &config).await.unwrap();
        let changes = resolve_membership_options(pool, plan(&current), &current)
            .await
            .unwrap();
        let issues = preflight_authority_issues(pool, &changes, &current)
            .await
            .unwrap();
        assert!(issues.is_empty(), "round {round}: {issues:?}");
        let mut tx = pool.begin().await.unwrap();
        for statement in render_batch_with_context(&changes, &SqlContext::default()).unwrap() {
            tx.execute(statement.sql.as_str())
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", statement.sql));
        }
        tx.commit().await.unwrap();
        if round == 0 {
            first_round = changes;
        }
    }
    let changes = plan(&inspect(pool, &config).await.unwrap());
    assert!(changes.is_empty(), "follow-up diff: {changes:?}");
    first_round
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn explicit_fresh_owner_membership_bootstraps_schema_without_self_grant() {
    let _database_acl = DATABASE_ACL.lock().await;
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
  - name: sbo_defaults_owner
    login: false
  - name: sbo_executor
    external: true
    preserve_undeclared_grants: true
schemas:
  - name: sbo_schema
    owner: sbo_owner
  - name: sbo_existing
    owner: sbo_owner
memberships:
  - role: sbo_owner
    members: [{ name: sbo_executor }]
  - role: sbo_defaults_owner
    members: [{ name: sbo_executor }]
default_privileges:
  - owner: sbo_defaults_owner
    scope: { type: global }
    grant:
      - role: sbo_executor
        on_type: table
        privileges: [SELECT]
  - owner: sbo_owner
    scope: { type: schema, schema: sbo_schema }
    grant:
      - role: sbo_executor
        on_type: table
        privileges: [SELECT]
"#,
    )
    .unwrap();
    root.execute("DROP SCHEMA IF EXISTS sbo_schema, sbo_existing CASCADE")
        .await
        .unwrap();
    for role in ["sbo_owner", "sbo_defaults_owner", "sbo_executor"] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(role)
                .fetch_one(&root)
                .await
                .unwrap();
        if exists {
            root.execute(format!("DROP OWNED BY {}", quote_ident(role)).as_str())
                .await
                .unwrap();
        }
    }
    root.execute(
        "DROP ROLE IF EXISTS sbo_owner, sbo_defaults_owner, sbo_executor;
        CREATE ROLE sbo_executor LOGIN CREATEROLE PASSWORD 'sbo-test-password'; CREATE SCHEMA sbo_existing AUTHORIZATION sbo_executor",
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
    let first_round = apply_until_converged(&pool, &policy).await;
    assert!(
        first_round
            .iter()
            .any(|change| matches!(change, Change::CreateSchema { .. }))
    );
    let can_set: bool = sqlx::query_scalar("SELECT pg_has_role(current_user, 'sbo_owner', 'SET')")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(can_set);
    pool.close().await;
    root.execute("DROP SCHEMA sbo_schema, sbo_existing CASCADE")
        .await
        .unwrap();
    for role in ["sbo_owner", "sbo_defaults_owner", "sbo_executor"] {
        root.execute(format!("DROP OWNED BY {}", quote_ident(role)).as_str())
            .await
            .unwrap();
    }
    root.execute("DROP ROLE sbo_owner, sbo_defaults_owner, sbo_executor")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn schema_owner_preflight_follows_set_edges_at_each_statement() {
    use pgroles_core::model::{RoleGraph, RoleState};
    use pgroles_inspect::AuthorityIssue;

    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    root.execute(
        "DROP ROLE IF EXISTS sbp_owner, sbp_bridge, sbp_executor;
        CREATE ROLE sbp_executor LOGIN CREATEROLE PASSWORD 'sbp-test-password';
        CREATE ROLE sbp_bridge;
        CREATE ROLE sbp_owner;
        GRANT sbp_owner TO sbp_bridge WITH INHERIT FALSE, SET TRUE;
        GRANT sbp_bridge TO sbp_executor WITH INHERIT FALSE, SET TRUE",
    )
    .await
    .unwrap();
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .username("sbp_executor")
        .password("sbp-test-password")
        .options([("createrole_self_grant", "")]);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let current = RoleGraph::default();
    for schema in [
        Change::CreateSchema {
            name: "sbp_schema".into(),
            owner: Some("sbp_owner".into()),
        },
        Change::AlterSchemaOwner {
            name: "sbp_schema".into(),
            owner: "sbp_owner".into(),
        },
    ] {
        let issues = preflight_authority_issues(&pool, std::slice::from_ref(&schema), &current)
            .await
            .unwrap();
        assert!(issues.is_empty(), "SET-only transitive path: {issues:?}");
        root.execute(
            "GRANT sbp_owner TO sbp_bridge WITH INHERIT TRUE, SET FALSE;
            GRANT sbp_bridge TO sbp_executor WITH INHERIT TRUE, SET TRUE",
        )
        .await
        .unwrap();
        let issues = preflight_authority_issues(&pool, std::slice::from_ref(&schema), &current)
            .await
            .unwrap();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, AuthorityIssue::SchemaOwnerSet { .. })),
            "INHERIT without SET: {issues:?}"
        );
        root.execute(
            "GRANT sbp_owner TO sbp_bridge WITH INHERIT FALSE, SET TRUE;
            GRANT sbp_bridge TO sbp_executor WITH INHERIT FALSE, SET TRUE",
        )
        .await
        .unwrap();
        let removal = Change::RemoveMember {
            role: "sbp_owner".into(),
            member: "sbp_bridge".into(),
            grantor: None,
        };
        let issues = preflight_authority_issues(&pool, &[removal, schema], &current)
            .await
            .unwrap();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, AuthorityIssue::SchemaOwnerSet { .. })),
            "removed SET path: {issues:?}"
        );
    }
    for inherit in [false, true] {
        let create = Change::CreateRole {
            name: "sbp_new_owner".into(),
            state: RoleState::default(),
        };
        let edge = Change::AddMember {
            role: "sbp_new_owner".into(),
            member: "sbp_executor".into(),
            inherit,
            admin: false,
        };
        let schema = Change::CreateSchema {
            name: "sbp_schema".into(),
            owner: Some("sbp_new_owner".into()),
        };
        let issues = preflight_authority_issues(
            &pool,
            &[create.clone(), edge.clone(), schema.clone()],
            &current,
        )
        .await
        .unwrap();
        assert!(issues.is_empty(), "early membership: {issues:?}");
        for changes in [
            vec![create.clone(), schema.clone(), edge],
            vec![create, schema],
        ] {
            let issues = preflight_authority_issues(&pool, &changes, &current)
                .await
                .unwrap();
            assert!(
                issues
                    .iter()
                    .any(|i| matches!(i, AuthorityIssue::SchemaOwnerSet { .. })),
                "late or missing membership: {issues:?}"
            );
        }
    }
    pool.close().await;
    root.execute("DROP ROLE sbp_owner, sbp_bridge, sbp_executor")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn preflight_agrees_with_postgres_for_self_grants_and_pg_prefixed_owners() {
    use pgroles_core::manifest::{ObjectType, Privilege};
    use pgroles_core::model::{DefaultPrivilegeScope, Grantee, RoleGraph, RoleState};
    use pgroles_inspect::AuthorityIssue;
    use std::collections::BTreeSet;

    let _database_acl = DATABASE_ACL.lock().await;
    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&root)
        .await
        .unwrap();
    let executor_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbs_executor')")
            .fetch_one(&root)
            .await
            .unwrap();
    if executor_exists {
        root.execute("DROP OWNED BY sbs_executor").await.unwrap();
    }
    // `pgsbs_owner` matches the inspection queries' `LIKE 'pg_%'` filter.
    // The executor can SET to `sbs_set_only` and inherits `sbs_inherited`.
    root.execute(
        "DROP SCHEMA IF EXISTS sbs_mine, sbs_of_set_only, sbs_of_inherited CASCADE;
        DROP ROLE IF EXISTS pgsbs_owner, sbs_set_only, sbs_inherited, sbs_executor;
        CREATE ROLE sbs_executor LOGIN CREATEROLE PASSWORD 'sbs-test-password';
        CREATE ROLE pgsbs_owner;
        CREATE ROLE sbs_set_only;
        CREATE ROLE sbs_inherited;
        GRANT pgsbs_owner, sbs_set_only TO sbs_executor WITH INHERIT FALSE, SET TRUE;
        GRANT sbs_inherited TO sbs_executor WITH INHERIT TRUE, SET FALSE;
        CREATE SCHEMA sbs_mine AUTHORIZATION sbs_executor;
        CREATE SCHEMA sbs_of_set_only AUTHORIZATION sbs_set_only;
        CREATE SCHEMA sbs_of_inherited AUTHORIZATION sbs_inherited",
    )
    .await
    .unwrap();
    root.execute(
        format!(
            "GRANT CREATE ON DATABASE {} TO sbs_executor",
            quote_ident(&database)
        )
        .as_str(),
    )
    .await
    .unwrap();
    let current = RoleGraph::default();
    let create = Change::CreateRole {
        name: "sbs_new_owner".into(),
        state: RoleState::default(),
    };
    let member = |inherit| Change::AddMember {
        role: "sbs_new_owner".into(),
        member: "sbs_executor".into(),
        inherit,
        admin: false,
    };
    let schema = |owner: &str| Change::CreateSchema {
        name: "sbs_schema".into(),
        owner: Some(owner.into()),
    };
    let defaults = Change::SetDefaultPrivilege {
        owner: "sbs_new_owner".into(),
        scope: DefaultPrivilegeScope::Global,
        on_type: ObjectType::Table,
        grantee: Grantee::Role("sbs_executor".into()),
        privileges: BTreeSet::from([Privilege::Select]),
    };
    let fresh = schema("sbs_new_owner");
    let transfer = |name: &str| Change::AlterSchemaOwner {
        name: name.into(),
        owner: "pgsbs_owner".into(),
    };
    for (label, self_grant, changes, blocked) in [
        (
            "existing SET path into a pg-prefixed owner",
            "",
            vec![schema("pgsbs_owner")],
            None,
        ),
        (
            "transfer of the executor's own schema",
            "",
            vec![transfer("sbs_mine")],
            None,
        ),
        (
            "transfer from an owner the executor inherits",
            "",
            vec![transfer("sbs_of_inherited")],
            None,
        ),
        (
            "transfer from an owner the executor can only SET to",
            "",
            vec![transfer("sbs_of_set_only")],
            Some("SchemaCurrentOwner"),
        ),
        (
            "automatic SET and INHERIT",
            "set,inherit",
            vec![create.clone(), fresh.clone(), defaults.clone()],
            None,
        ),
        (
            "inheriting membership",
            "set,inherit",
            vec![
                create.clone(),
                member(true),
                fresh.clone(),
                defaults.clone(),
            ],
            None,
        ),
        (
            "non-inheriting membership after the default grant",
            "set,inherit",
            vec![
                create.clone(),
                fresh.clone(),
                defaults.clone(),
                member(false),
            ],
            None,
        ),
        (
            "non-inheriting membership before the default grant",
            "set,inherit",
            vec![
                create.clone(),
                member(false),
                fresh.clone(),
                defaults.clone(),
            ],
            Some("DefaultPrivilegeOwner"),
        ),
    ] {
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .username("sbs_executor")
            .password("sbs-test-password")
            .options([("createrole_self_grant", self_grant)]);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        let issues = preflight_authority_issues(&pool, &changes, &current)
            .await
            .unwrap();
        let codes: Vec<&str> = issues.iter().map(AuthorityIssue::code).collect();
        assert_eq!(
            codes,
            blocked.into_iter().collect::<Vec<_>>(),
            "{label}: {issues:?}"
        );
        // The plan must fail in PostgreSQL exactly when preflight blocks it.
        let mut tx = pool.begin().await.unwrap();
        let mut failed = false;
        for statement in render_batch_with_context(&changes, &SqlContext::default()).unwrap() {
            if tx.execute(statement.sql.as_str()).await.is_err() {
                failed = true;
                break;
            }
        }
        tx.rollback().await.unwrap();
        assert_eq!(failed, blocked.is_some(), "{label}");
        pool.close().await;
    }
    root.execute(
        "DROP SCHEMA sbs_mine, sbs_of_set_only, sbs_of_inherited CASCADE;
        DROP OWNED BY sbs_executor;
        DROP ROLE pgsbs_owner, sbs_set_only, sbs_inherited, sbs_executor",
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
async fn new_membership_in_existing_owner_precedes_its_schema_and_defaults() {
    let _database_acl = DATABASE_ACL.lock().await;
    let url = std::env::var("DATABASE_URL").unwrap();
    let root = PgPool::connect(&url).await.unwrap();
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&root)
        .await
        .unwrap();
    root.execute("DROP SCHEMA IF EXISTS sbe_schema CASCADE")
        .await
        .unwrap();
    for role in ["sbe_owner", "sbe_executor"] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)")
                .bind(role)
                .fetch_one(&root)
                .await
                .unwrap();
        if exists {
            root.execute(format!("DROP OWNED BY {}", quote_ident(role)).as_str())
                .await
                .unwrap();
        }
    }
    // The owner already exists and the executor has no membership in it. The
    // executor can grant one through the ADMIN option its group holds.
    root.execute(
        "DROP ROLE IF EXISTS sbe_owner, sbe_admins, sbe_executor;
        CREATE ROLE sbe_executor LOGIN CREATEROLE PASSWORD 'sbe-test-password';
        CREATE ROLE sbe_admins;
        CREATE ROLE sbe_owner;
        GRANT sbe_owner TO sbe_admins WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
        GRANT sbe_admins TO sbe_executor",
    )
    .await
    .unwrap();
    root.execute(
        format!(
            "GRANT CREATE ON DATABASE {} TO sbe_executor",
            quote_ident(&database)
        )
        .as_str(),
    )
    .await
    .unwrap();
    let policy = pgroles_core::authoring::prepare_policy(
        r#"
roles:
  - name: sbe_owner
    login: false
  - name: sbe_admins
    external: true
  - name: sbe_executor
    external: true
    preserve_undeclared_grants: true
schemas:
  - name: sbe_schema
    owner: sbe_owner
memberships:
  - role: sbe_owner
    members:
      - { name: sbe_executor }
      - { name: sbe_admins, inherit: false, admin: true }
default_privileges:
  - owner: sbe_owner
    scope: { type: schema, schema: sbe_schema }
    grant:
      - role: sbe_executor
        on_type: table
        privileges: [SELECT]
"#,
    )
    .unwrap();
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .username("sbe_executor")
        .password("sbe-test-password")
        .options([("createrole_self_grant", "")]);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let first_round = apply_until_converged(&pool, &policy).await;
    let position = |wanted: fn(&Change) -> bool| first_round.iter().position(wanted).unwrap();
    let membership = position(|c| matches!(c, Change::AddMember { .. }));
    assert!(
        membership < position(|c| matches!(c, Change::CreateSchema { .. }))
            && membership < position(|c| matches!(c, Change::SetDefaultPrivilege { .. })),
        "{first_round:?}"
    );
    pool.close().await;
    root.execute("DROP SCHEMA sbe_schema CASCADE")
        .await
        .unwrap();
    for role in ["sbe_owner", "sbe_executor"] {
        root.execute(format!("DROP OWNED BY {}", quote_ident(role)).as_str())
            .await
            .unwrap();
    }
    root.execute("DROP ROLE sbe_owner, sbe_admins, sbe_executor")
        .await
        .unwrap();
}
