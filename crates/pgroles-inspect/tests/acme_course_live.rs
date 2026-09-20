use pgroles_core::diff::{Change, ReconciliationMode, plan_changes};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::render_all;
use pgroles_inspect::{InspectConfig, inspect};
use sqlx::{Executor, PgPool};

const POLICIES: [&str; 6] = [
    "chapter-1.yaml",
    "chapter-2.yaml",
    "chapter-3.yaml",
    "chapter-4.yaml",
    "chapter-5.yaml",
    "chapter-6.yaml",
];
const ROLES: [&str; 7] = [
    "alice",
    "bob",
    "reporting_app",
    "orders_reader",
    "deploy",
    "app_owner",
    "priya",
];

fn isolated(source: &str, prefix: &str) -> String {
    source
        .split_inclusive(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .map(|token| {
            let identifier = token.trim_end_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '_'
            });
            if ROLES.contains(&identifier) || ["app", "legacy"].contains(&identifier) {
                format!("{prefix}{token}")
            } else {
                token.to_owned()
            }
        })
        .collect()
}

async fn execute(pool: &PgPool, sql: &str) {
    let mut transaction = pool.begin().await.expect("begin transaction");
    transaction
        .execute(sql)
        .await
        .unwrap_or_else(|error| panic!("failed SQL: {sql}\n{error}"));
    transaction.commit().await.expect("commit SQL");
}

async fn plan(pool: &PgPool, yaml: &str) -> Vec<Change> {
    let manifest = parse_manifest(yaml).expect("parse cumulative policy");
    let expanded = expand_manifest(&manifest).expect("expand cumulative policy");
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref())
        .expect("build desired graph");
    let config = InspectConfig::from_expanded(&expanded, false).with_additional_roles(
        manifest
            .retirements
            .iter()
            .map(|retirement| retirement.role.clone()),
    );
    let current = inspect(pool, &config).await.expect("inspect chapter state");
    plan_changes(
        &current,
        &desired,
        &manifest,
        &expanded,
        ReconciliationMode::Authoritative,
    )
}

async fn assert_orders_access(pool: &PgPool, prefix: &str, role: &str, allowed: bool) {
    let mut transaction = pool.begin().await.expect("begin reader probe");
    transaction
        .execute(format!("SET LOCAL ROLE {prefix}{role}").as_str())
        .await
        .expect("select reader identity");
    let result =
        sqlx::query_scalar::<_, i32>(&format!("SELECT id FROM {prefix}app.orders ORDER BY id"))
            .fetch_all(&mut *transaction)
            .await;
    transaction
        .rollback()
        .await
        .expect("restore executor identity");
    if allowed {
        assert_eq!(
            result.expect("retained reader must query orders"),
            vec![1, 2],
            "{role}"
        );
    } else {
        let error = result.expect_err("offboarded reader must not query orders");
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some("42501")
        );
    }
}

struct Cleanup {
    database_url: String,
    prefix: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        tokio::runtime::Runtime::new()
            .expect("cleanup runtime")
            .block_on(async {
                if let Ok(pool) = PgPool::connect(&self.database_url).await {
                    for schema in ["app", "legacy"] {
                        let _ = pool
                            .execute(
                                format!("DROP SCHEMA IF EXISTS {}{schema} CASCADE", self.prefix)
                                    .as_str(),
                            )
                            .await;
                    }
                    for role in ROLES {
                        let _ = pool
                            .execute(format!("DROP OWNED BY {}{role}", self.prefix).as_str())
                            .await;
                    }
                    for role in ROLES {
                        let _ = pool
                            .execute(format!("DROP ROLE IF EXISTS {}{role}", self.prefix).as_str())
                            .await;
                    }
                }
            });
    }
}

#[test]
#[ignore = "requires DATABASE_URL for PostgreSQL"]
fn cumulative_chapter_policies_preserve_the_promised_access() {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let prefix = format!("acme_{suffix}_");
    let _cleanup = Cleanup {
        database_url: database_url.clone(),
        prefix: prefix.clone(),
    };
    tokio::runtime::Runtime::new()
        .expect("test runtime")
        .block_on(async {
            let pool = PgPool::connect(&database_url)
                .await
                .expect("connect database");
            execute(
                &pool,
                &isolated(
                    "CREATE ROLE priya LOGIN; CREATE SCHEMA app AUTHORIZATION priya;
            SET LOCAL ROLE priya; CREATE TABLE app.orders (id integer PRIMARY KEY);
            INSERT INTO app.orders VALUES (1), (2);",
                    &prefix,
                ),
            )
            .await;

            for (index, filename) in POLICIES.iter().enumerate() {
                let chapter = index + 1;
                let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../docs/public/examples/acme-policy")
                    .join(filename);
                let policy =
                    std::fs::read_to_string(path).expect("read downloadable chapter policy");
                if chapter == 5 {
                    execute(
                        &pool,
                        &isolated(
                            "SET LOCAL ROLE deploy; CREATE TABLE app.deploy_created (id integer);",
                            &prefix,
                        ),
                    )
                    .await;
                    for transfer_owner in [false, true] {
                        if transfer_owner {
                            execute(
                                &pool,
                                &isolated(
                                    "ALTER TABLE app.deploy_created OWNER TO app_owner;",
                                    &prefix,
                                ),
                            )
                            .await;
                        }
                        let allowed: bool =
                            sqlx::query_scalar("SELECT has_table_privilege($1, $2, 'SELECT')")
                                .bind(format!("{prefix}reporting_app"))
                                .bind(format!("{prefix}app.deploy_created"))
                                .fetch_one(&pool)
                                .await
                                .expect("wrong creator probe");
                        assert!(
                            !allowed,
                            "neither inherited authority nor later ownership applies the default"
                        );
                    }
                    execute(
                        &pool,
                        &isolated(
                            "SET LOCAL ROLE deploy; CREATE TABLE app.refunds (id integer);",
                            &prefix,
                        ),
                    )
                    .await;
                }
                if chapter == 6 {
                    execute(
                        &pool,
                        &isolated(
                            "CREATE SCHEMA legacy AUTHORIZATION priya;
                    SET LOCAL ROLE priya; CREATE TABLE legacy.customer_notes (id integer);",
                            &prefix,
                        ),
                    )
                    .await;
                }
                let yaml = isolated(&policy, &prefix);
                let changes = plan(&pool, &yaml).await;
                execute(&pool, &render_all(&changes)).await;
                assert_orders_access(&pool, &prefix, "alice", chapter < 3).await;
                if chapter >= 2 {
                    assert_orders_access(&pool, &prefix, "reporting_app", true).await;
                }
                if chapter >= 3 {
                    assert_orders_access(&pool, &prefix, "bob", true).await;
                }
                let remaining = plan(&pool, &yaml).await;
                assert!(
                    remaining.is_empty(),
                    "chapter {chapter} must converge: {remaining:?}"
                );

                if chapter == 4 {
                    execute(
                        &pool,
                        &isolated("ALTER TABLE app.orders OWNER TO app_owner;", &prefix),
                    )
                    .await;
                }
                if chapter == 5 {
                    execute(
                        &pool,
                        &isolated(
                            "SET LOCAL ROLE app_owner; CREATE TABLE app.shipments (id integer);",
                            &prefix,
                        ),
                    )
                    .await;
                    for table in ["refunds", "shipments"] {
                        let allowed: bool =
                            sqlx::query_scalar("SELECT has_table_privilege($1, $2, 'SELECT')")
                                .bind(format!("{prefix}reporting_app"))
                                .bind(format!("{prefix}app.{table}"))
                                .fetch_one(&pool)
                                .await
                                .expect("existing and future reader access");
                        assert!(allowed, "chapter 5 must cover {table}");
                    }
                }
                if chapter == 6 {
                    let retired: bool = sqlx::query_scalar(
                        "SELECT NOT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)",
                    )
                    .bind(format!("{prefix}priya"))
                    .fetch_one(&pool)
                    .await
                    .expect("retired role probe");
                    assert!(retired);
                    let owner: String = sqlx::query_scalar(
                        "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = $1::regclass",
                    )
                    .bind(format!("{prefix}legacy.customer_notes"))
                    .fetch_one(&pool)
                    .await
                    .expect("preserved legacy object");
                    assert_eq!(owner, format!("{prefix}app_owner"));
                }
            }
        });
}
