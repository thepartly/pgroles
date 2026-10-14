//! Live end-to-end convergence for grantor-targeted revokes, as a
//! NON-superuser executor — the production posture.
//!
//! PostgreSQL's plain REVOKE removes only the grant attributed to the
//! revoker, so before grantor targeting these scenarios re-planned the same
//! revokes forever: a delegate-granted object entry (unremovable even by
//! superusers), an owner-granted entry shadowed by the executor's own grant
//! option, and a membership edge granted by another admin. Inspection now
//! records each entry's grantor, the diff targets it, and rendering becomes
//! the grantor (`SET ROLE` for object privileges, `GRANTED BY` for
//! memberships) inside the plan's single transaction.
//!
//! Requires DATABASE_URL (superuser); run with `cargo test -- --include-ignored`.

use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, Executor, PgPool};
use std::str::FromStr;

use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
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

const ROLES: [&str; 6] = [
    "gtr_exec",
    "gtr_grantee",
    "gtr_alice",
    "gtr_delegate",
    "gtr_admin",
    "gtr_owner",
];

/// Drop-guard removing the test objects and roles even on panic.
struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP TABLE IF EXISTS gtr_t").await;
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

/// The manifest keeps gtr_grantee at INSERT on gtr_t and gtr_reader-style
/// membership empty, so authoritative reconciliation must revoke the live
/// SELECT entries (owner- and delegate-granted) and the live membership edge
/// (granted by gtr_admin).
const MANIFEST: &str = r#"
roles:
  - name: gtr_grantee
    login: true
  - name: gtr_alice
    login: true

grants:
  - role: gtr_grantee
    privileges: [INSERT]
    object:
      type: table
      schema: public
      name: gtr_t

# gtr_admin's own membership (granted by the superuser at setup) is declared
# so the plan under test contains exactly the three grantor-targeted revokes.
memberships:
  - role: gtr_grantee
    members:
      - name: gtr_admin
        admin: true
"#;

async fn plan(pool: &PgPool, manifest_yaml: &str) -> Vec<Change> {
    let manifest = parse_manifest(manifest_yaml).expect("manifest should parse");
    let expanded = expand_manifest(&manifest).expect("manifest should expand");
    let desired = RoleGraph::from_expanded(&expanded, None).expect("desired graph should build");
    let config = InspectConfig::from_expanded(&expanded, false);
    let current = inspect(pool, &config).await.expect("inspection should run");
    filter_changes(diff(&current, &desired), ReconciliationMode::Authoritative)
}

/// Apply the way production does: every statement in one transaction on one
/// connection, so SET ROLE / RESET ROLE bracket exactly their statements.
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
fn grantor_targeted_revokes_converge_for_a_non_superuser_executor() {
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
            // Grantor targeting needs per-edge grantors (memberships) and
            // pg_has_role(..., 'SET'); pre-16 keeps the plain-revoke paths.
            return;
        }
        let _ = pool.execute("DROP TABLE IF EXISTS gtr_t").await;
        for role in ROLES {
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        // The tangle no plain revoke can clean up:
        //   - owner-granted SELECT for gtr_grantee, shadowed for the executor
        //     by the executor's own grant option;
        //   - delegate-granted SELECT for gtr_grantee (unremovable even by a
        //     superuser's plain revoke);
        //   - a gtr_grantee membership edge for gtr_alice granted by
        //     gtr_admin (bare revoke would only WARN).
        // The executor is a plain login role whose only powers are
        // memberships in the grantors it must become.
        pool.execute(
            "CREATE ROLE gtr_owner; CREATE ROLE gtr_delegate; CREATE ROLE gtr_admin; \
             CREATE ROLE gtr_grantee LOGIN; CREATE ROLE gtr_alice LOGIN; \
             CREATE ROLE gtr_exec LOGIN PASSWORD 'gtr_exec_pw'; \
             CREATE TABLE gtr_t(i int); ALTER TABLE gtr_t OWNER TO gtr_owner; \
             GRANT gtr_grantee TO gtr_admin WITH ADMIN OPTION; \
             SET ROLE gtr_owner; \
             GRANT SELECT ON gtr_t TO gtr_grantee; \
             GRANT SELECT ON gtr_t TO gtr_exec WITH GRANT OPTION; \
             GRANT SELECT ON gtr_t TO gtr_delegate WITH GRANT OPTION; \
             RESET ROLE; \
             SET ROLE gtr_delegate; \
             GRANT SELECT ON gtr_t TO gtr_grantee; \
             RESET ROLE; \
             SET ROLE gtr_admin; \
             GRANT gtr_grantee TO gtr_alice; \
             RESET ROLE; \
             GRANT gtr_owner TO gtr_exec; \
             GRANT gtr_delegate TO gtr_exec; \
             GRANT gtr_admin TO gtr_exec;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("gtr_exec")
            .password("gtr_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        let changes = plan(&exec_pool, MANIFEST).await;
        // Two grantor-targeted SELECT revokes (owner entry + delegate entry),
        // one grantor-targeted membership revoke, plus the INSERT grant.
        let object_grantors: Vec<&str> = changes
            .iter()
            .filter_map(|change| match change {
                Change::Revoke { grantor, .. } => grantor.as_deref(),
                _ => None,
            })
            .collect();
        assert_eq!(
            object_grantors,
            ["gtr_delegate", "gtr_owner"],
            "revokes must target both entries' grantors: {changes:?}"
        );
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::RemoveMember { grantor: Some(grantor), .. } if grantor == "gtr_admin"
            )),
            "membership revoke must target its grantor: {changes:?}"
        );
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.is_empty(),
            "executor can become every grantor: {issues:?}"
        );

        apply(&exec_pool, &changes).await;

        // The previously-unremovable entries are gone and the plan is empty:
        // the drift that used to re-plan forever converged in one apply.
        let replan = plan(&exec_pool, MANIFEST).await;
        assert!(replan.is_empty(), "must converge in one apply: {replan:?}");
        let (has_select,): (bool,) =
            sqlx::query_as("SELECT has_table_privilege('gtr_grantee', 'gtr_t', 'SELECT')")
                .fetch_one(&pool)
                .await
                .expect("probe should run");
        assert!(!has_select, "both SELECT entries must be revoked");
        let (is_member,): (bool,) =
            sqlx::query_as("SELECT pg_has_role('gtr_alice', 'gtr_grantee', 'MEMBER')")
                .fetch_one(&pool)
                .await
                .expect("probe should run");
        assert!(!is_member, "the admin-granted membership edge must be gone");
    });
}

const SRE_ROLES: [&str; 4] = ["sre_admin", "sre_owner", "sre_grantee", "sre_exec"];

/// Drop-guard for the setRole-restore test's objects.
struct SreCleanup;

impl Drop for SreCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool.execute("DROP TABLE IF EXISTS sre_t").await;
                for role in SRE_ROLES {
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

/// The operator's `connection.params.setRole` runs `SET ROLE` on every pooled
/// connection after connect. A grantor-targeted revoke temporarily becomes
/// the grantor; closing with `RESET ROLE` would reset to the *login* role,
/// silently dropping the configured boundary for the rest of the plan and the
/// pooled connection. With `SqlContext::execution_role` detected from the
/// connection, the revoke restores the configured role instead.
#[test]
#[ignore]
fn grantor_revoke_restores_the_configured_execution_role() {
    let _cleanup = SreCleanup;
    with_runtime(async {
        let admin_pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect");
        let (version,): (i32,) =
            sqlx::query_as("SELECT current_setting('server_version_num')::int")
                .fetch_one(&admin_pool)
                .await
                .expect("version probe should run");
        if version < 160_000 {
            return;
        }
        let _ = admin_pool.execute("DROP TABLE IF EXISTS sre_t").await;
        for role in SRE_ROLES {
            let _ = admin_pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        // sre_exec is the login role; sre_admin is the configured setRole
        // target the connection is meant to run as. The owner-granted SELECT
        // entry forces a grantor-targeted revoke (SET ROLE sre_owner).
        admin_pool
            .execute(
                "CREATE ROLE sre_owner; CREATE ROLE sre_grantee; \
                 CREATE ROLE sre_admin; \
                 CREATE ROLE sre_exec LOGIN PASSWORD 'sre_exec_pw'; \
                 CREATE TABLE sre_t(i int); ALTER TABLE sre_t OWNER TO sre_owner; \
                 SET ROLE sre_owner; GRANT SELECT ON sre_t TO sre_grantee; RESET ROLE; \
                 GRANT sre_owner TO sre_admin; \
                 GRANT sre_admin TO sre_exec;",
            )
            .await
            .expect("setup should succeed");

        // Mirror the operator: SET ROLE after connect on every connection.
        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("sre_exec")
            .password("sre_exec_pw");
        let exec_pool = sqlx::postgres::PgPoolOptions::new()
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::Executor::execute(&mut *conn, "SET ROLE sre_admin").await?;
                    Ok(())
                })
            })
            .connect_with(exec_options)
            .await
            .expect("executor should connect");

        let execution_role = pgroles_inspect::detect_execution_role(&exec_pool)
            .await
            .expect("execution-role probe should run");
        assert_eq!(
            execution_role.as_deref(),
            Some("sre_admin"),
            "the configured SET ROLE must be detected"
        );
        let ctx = pgroles_core::sql::SqlContext::from_version_num(version)
            .with_execution_role(execution_role);

        let change = Change::Revoke {
            role: pgroles_core::model::Grantee::Role("sre_grantee".to_string()),
            privileges: std::collections::BTreeSet::from([
                pgroles_core::manifest::Privilege::Select,
            ]),
            object_type: pgroles_core::manifest::ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("sre_t".to_string()),
            grantor: Some("sre_owner".to_string()),
        };
        let mut conn = exec_pool
            .acquire()
            .await
            .expect("connection should acquire");
        let mut tx = conn.begin().await.expect("transaction should begin");
        for statement in pgroles_core::sql::render_statements_with_context(&change, &ctx).unwrap() {
            sqlx::Executor::execute(&mut *tx, statement.as_str())
                .await
                .unwrap_or_else(|error| panic!("failed `{statement}`: {error}"));
        }
        // The connection must still run as the configured role *inside* the
        // transaction — later plan statements rely on it.
        let (current_role,): (String,) = sqlx::query_as("SELECT current_user::text")
            .fetch_one(&mut *tx)
            .await
            .expect("role probe should run");
        assert_eq!(
            current_role, "sre_admin",
            "the configured execution role must be restored, not the login role"
        );
        tx.commit().await.expect("transaction should commit");

        let (has_select,): (bool,) =
            sqlx::query_as("SELECT has_table_privilege('sre_grantee', 'sre_t', 'SELECT')")
                .fetch_one(&admin_pool)
                .await
                .expect("probe should run");
        assert!(!has_select, "the owner-granted entry must be revoked");
    });
}

const DFP_ROLES: [&str; 5] = [
    "dfp_exec",
    "dfp_alice",
    "dfp_newmid",
    "dfp_middle",
    "dfp_owner",
];

/// Drop-guard for the plan-phase authority test.
struct DfpCleanup;

impl Drop for DfpCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                for role in DFP_ROLES {
                    let _ = pool
                        .execute(format!("ALTER DEFAULT PRIVILEGES FOR ROLE {role} REVOKE SELECT ON TABLES FROM dfp_alice").as_str())
                        .await;
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

/// The plan replaces the executor's inheritance path to a default-privilege
/// owner: it removes the old intermediary edge and adds a new one, then
/// revokes the owner's default privileges. Phase order makes this executable
/// (removals → additions → default-privilege revokes), and the preflight must
/// model the additions — a removal-only simulation would reject this plan.
/// The whole plan comes out of `diff()` from a manifest, not hand-built
/// changes, and applies end to end as the non-superuser executor.
const DFP_MANIFEST: &str = r#"
roles:
  - name: dfp_owner
  - name: dfp_middle
  - name: dfp_newmid
  - name: dfp_alice

memberships:
  # The executor's direct membership is admin-only (INHERIT FALSE): it can
  # administer dfp_owner but does not inherit its privileges.
  - role: dfp_owner
    members:
      - name: dfp_exec
        admin: true
        inherit: false
      - name: dfp_newmid
  - role: dfp_middle
    members:
      - name: dfp_exec
  - role: dfp_newmid
    members:
      - name: dfp_exec
        admin: true

default_privileges:
  - owner: dfp_owner
    scope: { type: global }
    grant:
      - role: dfp_alice
        ensure: absent
        privileges: [SELECT]
        on_type: table
"#;

#[test]
#[ignore]
fn additions_restore_grantor_authority_within_one_plan() {
    let _cleanup = DfpCleanup;
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
        for role in DFP_ROLES {
            let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        // Current state: the executor inherits dfp_owner only through
        // dfp_middle (an edge the executor granted itself, so its removal is
        // GRANTED BY the executor); dfp_newmid is inheritable by the executor
        // but not yet a member of dfp_owner. The manifest drops the middle
        // path and adds the newmid path in the same plan.
        pool.execute(
            "CREATE ROLE dfp_owner; CREATE ROLE dfp_middle; CREATE ROLE dfp_newmid; \
             CREATE ROLE dfp_alice; \
             CREATE ROLE dfp_exec LOGIN PASSWORD 'dfp_exec_pw'; \
             GRANT dfp_owner TO dfp_exec WITH ADMIN TRUE, INHERIT FALSE; \
             GRANT dfp_middle TO dfp_exec; \
             GRANT dfp_newmid TO dfp_exec WITH ADMIN OPTION; \
             ALTER DEFAULT PRIVILEGES FOR ROLE dfp_owner GRANT SELECT ON TABLES TO dfp_alice;",
        )
        .await
        .expect("setup should succeed");
        // Granted as the executor so the planned removal is attributed to it.
        pool.execute("SET ROLE dfp_exec; GRANT dfp_owner TO dfp_middle; RESET ROLE;")
            .await
            .expect("executor-granted edge should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("dfp_exec")
            .password("dfp_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        let changes = plan(&exec_pool, DFP_MANIFEST).await;
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::RemoveMember { role, member, .. }
                    if role == "dfp_owner" && member == "dfp_middle"
            )),
            "the old path must be removed: {changes:?}"
        );
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::AddMember { role, member, inherit: true, .. }
                    if role == "dfp_owner" && member == "dfp_newmid"
            )),
            "the new path must be added: {changes:?}"
        );
        assert!(
            changes.iter().any(
                |change| matches!(change, Change::RevokeDefaultPrivilege { owner, .. }
                    if owner == "dfp_owner")
            ),
            "the owner's default privilege must be revoked: {changes:?}"
        );

        // The removal strips the executor's only *current* inheritance path
        // to dfp_owner, but the addition in the same plan restores one before
        // the default-privilege revoke runs — the preflight must not flag it.
        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.is_empty(),
            "the added path executes before the defaults revoke: {issues:?}"
        );

        apply(&exec_pool, &changes).await;

        let replan = plan(&exec_pool, DFP_MANIFEST).await;
        assert!(replan.is_empty(), "must converge in one apply: {replan:?}");
    });
}

const PAD_ROLES: [&str; 4] = ["pad_exec", "pad_alice", "pad_newmid", "pad_owner"];

/// Drop-guard for the pure-addition authority test.
struct PadCleanup;

impl Drop for PadCleanup {
    fn drop(&mut self) {
        with_runtime(async {
            if let Ok(pool) = PgPool::connect(&database_url()).await {
                let _ = pool
                    .execute(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE pad_owner \
                         REVOKE SELECT ON TABLES FROM pad_alice",
                    )
                    .await;
                for role in PAD_ROLES {
                    let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
                    let _ = pool
                        .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                        .await;
                }
            }
        });
    }
}

/// Pure-addition authority: the executor holds the defaults owner with
/// `ADMIN TRUE, INHERIT FALSE` — it can grant the owner role but does not
/// inherit its privileges — and the plan contains no removals at all. The
/// plan's own `AddMember` (owner → a role the executor inherits) acquires the
/// USAGE the later default-privilege revoke needs, so the plan is executable;
/// a current-state owner check would reject it with `DefaultPrivilegeOwner`.
const PAD_MANIFEST: &str = r#"
roles:
  - name: pad_owner
  - name: pad_newmid
  - name: pad_alice

memberships:
  - role: pad_owner
    members:
      - name: pad_exec
        admin: true
        inherit: false
      - name: pad_newmid
  - role: pad_newmid
    members:
      - name: pad_exec

default_privileges:
  - owner: pad_owner
    scope: { type: global }
    grant:
      - role: pad_alice
        ensure: absent
        privileges: [SELECT]
        on_type: table
"#;

#[test]
#[ignore]
fn pure_addition_acquires_defaults_owner_authority() {
    let _cleanup = PadCleanup;
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
        for role in PAD_ROLES {
            let _ = pool.execute(format!("DROP OWNED BY {role}").as_str()).await;
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {role}").as_str())
                .await;
        }
        pool.execute(
            "CREATE ROLE pad_owner; CREATE ROLE pad_newmid; CREATE ROLE pad_alice; \
             CREATE ROLE pad_exec LOGIN PASSWORD 'pad_exec_pw'; \
             GRANT pad_owner TO pad_exec WITH ADMIN TRUE, INHERIT FALSE; \
             GRANT pad_newmid TO pad_exec; \
             ALTER DEFAULT PRIVILEGES FOR ROLE pad_owner GRANT SELECT ON TABLES TO pad_alice;",
        )
        .await
        .expect("setup should succeed");

        let exec_options = PgConnectOptions::from_str(&database_url())
            .expect("DATABASE_URL should parse")
            .username("pad_exec")
            .password("pad_exec_pw");
        let exec_pool = PgPool::connect_with(exec_options)
            .await
            .expect("executor should connect");

        // Sanity: the executor cannot use the owner's privileges *now*.
        let (usage_now,): (bool,) =
            sqlx::query_as("SELECT pg_has_role(current_user, 'pad_owner', 'USAGE')")
                .fetch_one(&exec_pool)
                .await
                .expect("probe should run");
        assert!(!usage_now, "the admin-only edge must not inherit");

        let changes = plan(&exec_pool, PAD_MANIFEST).await;
        assert!(
            !changes
                .iter()
                .any(|change| matches!(change, Change::RemoveMember { .. })),
            "the plan must be pure-addition: {changes:?}"
        );
        assert!(
            changes.iter().any(|change| matches!(
                change,
                Change::AddMember { role, member, inherit: true, .. }
                    if role == "pad_owner" && member == "pad_newmid"
            )),
            "the authority-acquiring addition must be planned: {changes:?}"
        );
        assert!(
            changes.iter().any(
                |change| matches!(change, Change::RevokeDefaultPrivilege { owner, .. }
                    if owner == "pad_owner")
            ),
            "the owner's default privilege must be revoked: {changes:?}"
        );

        let issues = preflight_authority_issues(&exec_pool, &changes, &RoleGraph::default())
            .await
            .expect("preflight should run");
        assert!(
            issues.is_empty(),
            "the plan's own addition acquires the owner's privileges before \
             the defaults revoke runs: {issues:?}"
        );

        apply(&exec_pool, &changes).await;

        let replan = plan(&exec_pool, PAD_MANIFEST).await;
        assert!(replan.is_empty(), "must converge in one apply: {replan:?}");
    });
}

/// Wildcard convergence must address both delegates on every concrete object,
/// preserving owner privileges and named exceptions.
#[test]
#[ignore]
fn wildcard_revokes_keep_concrete_grantors_and_converge() {
    with_runtime(async {
        let pool = PgPool::connect(&database_url()).await.unwrap();
        pool.execute("DROP SCHEMA IF EXISTS wgr CASCADE; \
          DROP ROLE IF EXISTS wgr_exec; DROP ROLE IF EXISTS wgr_reader; DROP ROLE IF EXISTS wgr_a; DROP ROLE IF EXISTS wgr_b; \
          CREATE ROLE wgr_exec LOGIN PASSWORD 'wgr_test_password'; CREATE ROLE wgr_reader; CREATE ROLE wgr_a; CREATE ROLE wgr_b; \
          CREATE SCHEMA wgr; GRANT USAGE ON SCHEMA wgr TO PUBLIC; \
          CREATE TABLE wgr.t(i int); CREATE TABLE wgr.u(i int); \
          GRANT SELECT ON ALL TABLES IN SCHEMA wgr TO wgr_a, wgr_b WITH GRANT OPTION; \
          GRANT INSERT ON ALL TABLES IN SCHEMA wgr TO wgr_reader; \
          SET ROLE wgr_a; GRANT SELECT ON ALL TABLES IN SCHEMA wgr TO wgr_reader, PUBLIC; RESET ROLE; \
          SET ROLE wgr_b; GRANT SELECT ON ALL TABLES IN SCHEMA wgr TO wgr_reader, PUBLIC; RESET ROLE;")
          .await.unwrap();
        let manifest = "roles:\n  - name: wgr_reader\ngrants:\n  - role: wgr_reader\n    privileges: [INSERT]\n    object: {type: table, schema: wgr, name: '*'}\n  - role: PUBLIC\n    ensure: absent\n    privileges: [SELECT]\n    object: {type: table, schema: wgr, name: '*'}\n";
        let changes = plan(&pool, manifest).await;
        let revokes: Vec<_> = changes
            .iter()
            .filter(|c| matches!(c, Change::Revoke { .. }))
            .collect();
        assert_eq!(
            revokes.len(),
            8,
            "two grantors x two objects x two grantees: {changes:?}"
        );
        assert!(revokes.iter().all(
            |c| matches!(c, Change::Revoke {name: Some(n), grantor: Some(_), ..} if n != "*")
        ));
        assert!(filter_changes(changes.clone(), ReconciliationMode::Additive).is_empty());
        assert!(
            preflight_authority_issues(&pool, &changes, &RoleGraph::default())
                .await
                .unwrap()
                .is_empty()
        );
        let exec = PgPool::connect_with(
            PgConnectOptions::from_str(&database_url())
                .unwrap()
                .username("wgr_exec")
                .password("wgr_test_password"),
        )
        .await
        .unwrap();
        let denied = preflight_authority_issues(&exec, &changes, &RoleGraph::default())
            .await
            .unwrap();
        assert!(
            !denied.is_empty(),
            "missing grantor authority must block apply"
        );
        pool.execute("GRANT wgr_a, wgr_b TO wgr_exec")
            .await
            .unwrap();
        assert!(
            preflight_authority_issues(&exec, &changes, &RoleGraph::default())
                .await
                .unwrap()
                .is_empty()
        );
        apply(&exec, &changes).await;
        assert!(plan(&pool, manifest).await.is_empty());
        // A wildcard spanning owned and delegated objects must preserve the
        // owner's ACL while removing the undeclared privilege on the other.
        pool.execute("ALTER TABLE wgr.t OWNER TO wgr_reader; SET ROLE wgr_a; GRANT SELECT ON wgr.u TO wgr_reader; RESET ROLE").await.unwrap();
        let mixed = plan(&pool, manifest).await;
        assert!(
            mixed
                .iter()
                .all(|c| matches!(c, Change::Revoke {name: Some(n), ..} if n == "u")),
            "{mixed:?}"
        );
        assert_eq!(mixed.len(), 1);
        apply(&pool, &mixed).await;
        assert!(plan(&pool, manifest).await.is_empty());
        let (owner_select,): (bool,) =
            sqlx::query_as("SELECT has_table_privilege('wgr_reader', 'wgr.t', 'SELECT')")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(owner_select);
        // A named exception next to a wildcard must remain granted and
        // produce an empty replan, even when all objects once held SELECT.
        pool.execute("SET ROLE wgr_a; GRANT SELECT ON wgr.u TO wgr_reader; RESET ROLE")
            .await
            .unwrap();
        let exception = format!(
            "{manifest}  - role: wgr_reader\n    privileges: [SELECT]\n    object: {{type: table, schema: wgr, name: u}}\n"
        );
        assert!(plan(&pool, &exception).await.is_empty());
        exec.close().await;
        pool.execute("DROP SCHEMA wgr CASCADE; DROP OWNED BY wgr_reader, wgr_a, wgr_b; DROP ROLE wgr_exec, wgr_reader, wgr_a, wgr_b").await.unwrap();
    });
}
