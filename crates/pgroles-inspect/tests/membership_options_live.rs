//! Synthetic PG16+ membership-option fixtures. Run only on disposable databases.
use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::model::{MembershipEdge, RoleGraph};
use pgroles_core::sql::{SqlContext, render_batch_with_context};
use pgroles_inspect::{
    AuthorityIssue, InspectConfig, inspect, preflight_authority_issues, resolve_membership_options,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{Executor, PgPool};
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};

/// Every test here recreates the same cluster-wide `mop_*` roles, and the
/// harness runs a binary's tests in parallel by default, so they serialize.
static ONE_AT_A_TIME: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

const ROLES: &[&str] = &[
    "mop_child",
    "mop_member",
    "mop_exec",
    "mop_alloydbadmin",
    "mop_g1",
    "mop_g2",
    "mop_role",
];
const PASSWORD: &str = "mop-test-password";
type Row = (String, bool, bool, bool);
fn runtime<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        runtime(async {
            if let Ok(url) = std::env::var("DATABASE_URL")
                && let Ok(pool) = PgPool::connect(&url).await
            {
                let _ = pool
                    .execute("DROP TABLE IF EXISTS public.mop_option_table")
                    .await;
                let _ = pool
                    .execute(format!("DROP ROLE IF EXISTS {}", ROLES.join(",")).as_str())
                    .await;
                pool.close().await;
            }
        });
    }
}
async fn reset(root: &PgPool) {
    root.execute("DROP TABLE IF EXISTS public.mop_option_table")
        .await
        .unwrap();
    root.execute(format!("DROP ROLE IF EXISTS {}", ROLES.join(",")).as_str())
        .await
        .unwrap();
    for role in ROLES {
        root.execute(format!("CREATE ROLE {role}").as_str())
            .await
            .unwrap();
    }
    root.execute(format!("ALTER ROLE mop_exec LOGIN PASSWORD '{PASSWORD}'").as_str())
        .await
        .unwrap();
    root.execute("CREATE TABLE public.mop_option_table(id integer); GRANT SELECT ON public.mop_option_table TO mop_role").await.unwrap();
}
async fn ordinary_executor() -> PgPool {
    let options = PgConnectOptions::from_str(&std::env::var("DATABASE_URL").unwrap())
        .unwrap()
        .username("mop_exec")
        .password(PASSWORD);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    let (user, superuser): (String, bool) = sqlx::query_as(
        "SELECT current_user::text, rolsuper FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(user, "mop_exec");
    assert!(!superuser);
    pool
}
async fn current(pool: &PgPool) -> RoleGraph {
    let prepared = pgroles_core::authoring::prepare_policy("{}").unwrap();
    let mut config = InspectConfig::from_expanded(&prepared.expanded, false);
    config.managed_roles = ROLES.iter().map(|s| s.to_string()).collect();
    inspect(pool, &config).await.unwrap()
}

fn desired(current: &RoleGraph, inherit: bool, admin: bool) -> RoleGraph {
    let mut desired = current.clone();
    desired
        .memberships
        .retain(|e| !(e.role == "mop_role" && e.member == "mop_member"));
    desired.memberships.insert(MembershipEdge {
        role: "mop_role".into(),
        member: "mop_member".into(),
        inherit,
        admin,
    });
    desired
}
async fn rows(root: &PgPool) -> Vec<Row> {
    sqlx::query_as("SELECT g.rolname::text,a.inherit_option,a.admin_option,a.set_option FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor WHERE r.rolname='mop_role' AND m.rolname='mop_member' ORDER BY g.rolname").fetch_all(root).await.unwrap()
}
async fn apply(pool: &PgPool, changes: &[Change]) -> Result<(), sqlx::Error> {
    let statements = render_batch_with_context(changes, &SqlContext::default()).unwrap();
    let mut tx = pool.begin().await?;
    for statement in statements {
        tx.execute(statement.sql.as_str()).await?;
    }
    tx.commit().await
}
async fn table_access(root: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT has_table_privilege('mop_member','public.mop_option_table','SELECT')",
    )
    .fetch_one(root)
    .await
    .unwrap()
}

#[test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
fn ordinary_executor_option_changes_preserve_attribution_and_fail_closed() {
    // Declared first so the cleanup guard drops before the lock is released.
    let _serial = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _cleanup = Cleanup;
    runtime(async {
        let root = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&root)
            .await
            .unwrap();
        assert!(version >= 160_000);
        // Provider sorts first, but its privileges are unavailable to the
        // ordinary login. An own edge may be absent or already carry SET.
        for foreign_set in [false, true] {
            for own_set in [None, Some(false), Some(true)] {
                for (inherit, admin) in [(true, false), (false, true), (true, true)] {
                    reset(&root).await;
                    root.execute("GRANT mop_role TO mop_alloydbadmin, mop_exec WITH ADMIN TRUE, INHERIT FALSE, SET FALSE").await.unwrap();
                    root.execute(format!("GRANT mop_role TO mop_member WITH INHERIT FALSE, ADMIN FALSE, SET {} GRANTED BY mop_alloydbadmin",if foreign_set {"TRUE"} else {"FALSE"}).as_str()).await.unwrap();
                    if let Some(set) = own_set {
                        root.execute(format!("GRANT mop_role TO mop_member WITH INHERIT FALSE, ADMIN FALSE, SET {} GRANTED BY mop_exec",if set {"TRUE"} else {"FALSE"}).as_str()).await.unwrap();
                    }
                    let executor = ordinary_executor().await;
                    let before = current(&executor).await;
                    let raw = diff(&before, &desired(&before, inherit, admin));
                    let changes = resolve_membership_options(&executor, raw, &before)
                        .await
                        .unwrap();
                    assert_eq!(changes.len(), 1);
                    assert!(
                        matches!(&changes[0],Change::UpdateMemberOptions { grantor,.. } if grantor=="mop_exec")
                    );
                    assert!(
                        preflight_authority_issues(&executor, &changes, &before)
                            .await
                            .unwrap()
                            .is_empty()
                    );
                    apply(&executor, &changes).await.unwrap();
                    assert_eq!(
                        rows(&root).await,
                        vec![
                            ("mop_alloydbadmin".into(), false, false, foreign_set),
                            ("mop_exec".into(), inherit, admin, own_set.unwrap_or(false)),
                        ]
                    );
                    assert_eq!(table_access(&root).await, inherit);
                    // Later removal of the foreign edge must not leave a new
                    // SET capability behind on the executor's attribution.
                    root.execute(
                        "REVOKE mop_role FROM mop_member GRANTED BY mop_alloydbadmin RESTRICT",
                    )
                    .await
                    .unwrap();
                    let set: bool =
                        sqlx::query_scalar("SELECT pg_has_role('mop_member','mop_role','SET')")
                            .fetch_one(&root)
                            .await
                            .unwrap();
                    assert_eq!(set, own_set.unwrap_or(false));
                    executor.close().await;
                }
            }
        }
        // Mixed increases/reductions remain independent in additive mode.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_alloydbadmin, mop_exec WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_role TO mop_member WITH ADMIN TRUE, INHERIT FALSE, SET TRUE GRANTED BY mop_alloydbadmin").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let raw = diff(&before, &desired(&before, true, false));
        let full = resolve_membership_options(&executor, raw.clone(), &before)
            .await
            .unwrap();
        assert!(preflight_authority_issues(&executor,&full,&before).await.unwrap().iter().any(|i|matches!(i,AuthorityIssue::MembershipOptionsBlocked {grantor,..} if grantor=="mop_alloydbadmin")));
        let additive = resolve_membership_options(
            &executor,
            filter_changes(raw, ReconciliationMode::Additive),
            &before,
        )
        .await
        .unwrap();
        assert!(
            preflight_authority_issues(&executor, &additive, &before)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &additive).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![
                ("mop_alloydbadmin".into(), false, true, true),
                ("mop_exec".into(), true, false, false)
            ]
        );
        executor.close().await;

        // INHERIT-only/ADMIN-only REVOKE keeps each grantor row and SET option.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1, mop_g2 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1,mop_g2 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_member WITH INHERIT TRUE, ADMIN TRUE, SET FALSE GRANTED BY mop_g1; GRANT mop_role TO mop_member WITH INHERIT TRUE, ADMIN TRUE, SET TRUE GRANTED BY mop_g2").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let changes = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, false, false)),
            &before,
        )
        .await
        .unwrap();
        assert_eq!(changes.len(), 2);
        assert!(
            preflight_authority_issues(&executor, &changes, &before)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &changes).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![
                ("mop_g1".into(), false, false, false),
                ("mop_g2".into(), false, false, true)
            ]
        );
        assert!(!table_access(&root).await);
        executor.close().await;

        // The last supporting ADMIN reduction must fail RESTRICT when onward
        // grants remain. Preflight blocks it; executing the SQL independently
        // confirms PostgreSQL also rejects it and rolls back unchanged rows.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_member WITH ADMIN TRUE, INHERIT TRUE, SET FALSE GRANTED BY mop_g1; GRANT mop_role TO mop_child WITH INHERIT TRUE, SET FALSE GRANTED BY mop_member").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let changes = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, true, false)),
            &before,
        )
        .await
        .unwrap();
        let issues = preflight_authority_issues(&executor, &changes, &before)
            .await
            .unwrap();
        assert!(issues.iter().any(|i|matches!(i,AuthorityIssue::MembershipOptionsBlocked {reason,..} if reason.contains("dependent"))));
        let error = apply(&executor, &changes).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some("2BP01")
        );
        assert_eq!(
            rows(&root).await,
            vec![("mop_g1".into(), true, true, false)]
        );
        // GRANT ADMIN FALSE bypasses the dependency-aware REVOKE path.
        // Deliberately demonstrate the old unsafe operation, then restore the
        // synthetic support before testing a legitimate alternate grant.
        executor
            .execute("GRANT mop_role TO mop_member WITH ADMIN FALSE GRANTED BY mop_g1")
            .await
            .unwrap();
        let child_remains: bool =
            sqlx::query_scalar("SELECT pg_has_role('mop_child','mop_role','MEMBER')")
                .fetch_one(&root)
                .await
                .unwrap();
        assert!(child_remains);
        assert_eq!(
            rows(&root).await,
            vec![("mop_g1".into(), true, false, false)]
        );
        root.execute("GRANT mop_role TO mop_member WITH ADMIN TRUE GRANTED BY mop_g1; GRANT mop_role TO mop_g2 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g2 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_member WITH INHERIT TRUE, ADMIN TRUE, SET TRUE GRANTED BY mop_g2").await.unwrap();
        let alternate = current(&executor).await;
        let one = resolve_membership_options(
            &executor,
            vec![Change::UpdateMemberOptions {
                role: "mop_role".into(),
                member: "mop_member".into(),
                grantor: "mop_g1".into(),
                inherit: None,
                admin: Some(false),
                binding: None,
            }],
            &alternate,
        )
        .await
        .unwrap();
        assert!(
            preflight_authority_issues(&executor, &one, &alternate)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &one).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![
                ("mop_g1".into(), true, false, false),
                ("mop_g2".into(), true, true, true)
            ]
        );
        let last = current(&executor).await;
        let last_reduction =
            resolve_membership_options(&executor, diff(&last, &desired(&last, true, false)), &last)
                .await
                .unwrap();
        assert!(preflight_authority_issues(&executor,&last_reduction,&last).await.unwrap().iter().any(|i|matches!(i,AuthorityIssue::MembershipOptionsBlocked {reason,..} if reason.contains("dependent"))));
        // Staging an explicitly intended child removal resolves the dependency.
        root.execute("REVOKE mop_role FROM mop_child GRANTED BY mop_member RESTRICT")
            .await
            .unwrap();
        assert!(
            preflight_authority_issues(&executor, &last_reduction, &last)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &last_reduction).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![
                ("mop_g1".into(), true, false, false),
                ("mop_g2".into(), true, false, true)
            ]
        );
        executor.close().await;

        // An orphaned grantor need not regain ADMIN to reduce an existing
        // option. Actual executor ADMIN plus grantor USAGE still are required.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1,mop_exec WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_member WITH ADMIN TRUE, INHERIT TRUE, SET FALSE GRANTED BY mop_g1; GRANT mop_role TO mop_g1 WITH ADMIN FALSE").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let changes = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, false, false)),
            &before,
        )
        .await
        .unwrap();
        assert!(
            preflight_authority_issues(&executor, &changes, &before)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &changes).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![("mop_g1".into(), false, false, false)]
        );
        executor.close().await;

        // Losing the inherited administrator before the later grant must not
        // pass preflight, even though that grantor is usable at inspection time.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_g2 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g2 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE GRANTED BY mop_g2; GRANT mop_role TO mop_member WITH INHERIT FALSE, SET FALSE GRANTED BY mop_g1").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let mut target = desired(&before, true, false);
        target
            .memberships
            .retain(|e| !(e.role == "mop_g1" && e.member == "mop_exec"));
        let unsafe_raw = diff(&before, &target);
        // With no grantor usable after the earlier removal, the increase is
        // still planned for review — and the preflight blocks it.
        let unsafe_plan = resolve_membership_options(&executor, unsafe_raw.clone(), &before)
            .await
            .unwrap();
        assert!(
            !preflight_authority_issues(&executor, &unsafe_plan, &before)
                .await
                .unwrap()
                .is_empty()
        );
        let mut changes = unsafe_raw
            .into_iter()
            .filter(|c| matches!(c, Change::RemoveMember { .. }))
            .collect::<Vec<_>>();
        let positive = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, true, false)),
            &before,
        )
        .await
        .unwrap();
        changes.extend(positive);
        assert!(
            !preflight_authority_issues(&executor, &changes, &before)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(apply(&executor, &changes).await.is_err());
        assert_eq!(
            rows(&root).await,
            vec![("mop_g1".into(), false, false, false)]
        );
        executor.close().await;

        // Removing one INHERIT supplier retains the independent parallel path
        // needed by the following option increase.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_g2 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g2 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE GRANTED BY mop_g2; GRANT mop_role TO mop_member WITH INHERIT FALSE, SET FALSE GRANTED BY mop_g1").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let mut intents = vec![Change::UpdateMemberOptions {
            role: "mop_g1".into(),
            member: "mop_exec".into(),
            grantor: "mop_g2".into(),
            inherit: Some(false),
            admin: None,
            binding: None,
        }];
        intents.extend(diff(&before, &desired(&before, true, false)));
        let changes = resolve_membership_options(&executor, intents, &before)
            .await
            .unwrap();
        assert!(
            preflight_authority_issues(&executor, &changes, &before)
                .await
                .unwrap()
                .is_empty()
        );
        apply(&executor, &changes).await.unwrap();
        assert_eq!(
            rows(&root).await,
            vec![("mop_g1".into(), true, false, false)]
        );
        let surviving_usage: bool =
            sqlx::query_scalar("SELECT pg_has_role('mop_exec','mop_g1','USAGE')")
                .fetch_one(&root)
                .await
                .unwrap();
        assert!(surviving_usage);
        executor.close().await;

        // A same-attribution tuple appearing between resolution and preflight
        // invalidates the bound absent branch. Fresh resolution preserves its
        // actual SET value and changes the approval effects.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_alloydbadmin,mop_exec WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_role TO mop_member WITH INHERIT FALSE, SET FALSE GRANTED BY mop_alloydbadmin").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let old = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, true, false)),
            &before,
        )
        .await
        .unwrap();
        assert!(
            preflight_authority_issues(&executor, &old, &before)
                .await
                .unwrap()
                .is_empty()
        );
        root.execute(
            "GRANT mop_role TO mop_member WITH INHERIT FALSE, SET TRUE GRANTED BY mop_exec",
        )
        .await
        .unwrap();
        assert!(preflight_authority_issues(&executor,&old,&before).await.unwrap().iter().any(|i|matches!(i,AuthorityIssue::MembershipOptionsBlocked {reason,..} if reason.contains("changed since"))));
        let fresh = current(&executor).await;
        let replacement = resolve_membership_options(
            &executor,
            diff(&fresh, &desired(&fresh, true, false)),
            &fresh,
        )
        .await
        .unwrap();
        assert_ne!(old, replacement);
        apply(&executor, &replacement).await.unwrap();
        assert!(rows(&root).await.iter().any(|r| r.0 == "mop_exec" && r.3));
        executor.close().await;
        // When the actual executor loses both of its own options, INHERIT
        // must be reduced before ADMIN so the second revoke remains possible.
        // The orphaned grantor cannot supply alternative ADMIN authority.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_exec WITH ADMIN TRUE, INHERIT TRUE, SET TRUE GRANTED BY mop_g1; GRANT mop_role TO mop_g1 WITH ADMIN FALSE").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let mut target = before.clone();
        target
            .memberships
            .retain(|edge| !(edge.role == "mop_role" && edge.member == "mop_exec"));
        target.memberships.insert(MembershipEdge {
            role: "mop_role".into(),
            member: "mop_exec".into(),
            inherit: false,
            admin: false,
        });
        let changes = resolve_membership_options(&executor, diff(&before, &target), &before)
            .await
            .unwrap();
        assert!(
            preflight_authority_issues(&executor, &changes, &before)
                .await
                .unwrap()
                .is_empty()
        );
        let mut wrong_order = executor.begin().await.unwrap();
        let mut rejected = None;
        for statement in render_batch_with_context(&changes, &SqlContext::default())
            .unwrap()
            .into_iter()
            .rev()
        {
            if let Err(error) = wrong_order.execute(statement.sql.as_str()).await {
                rejected = Some(error);
                break;
            }
        }
        wrong_order.rollback().await.unwrap();
        assert_eq!(
            rejected
                .unwrap()
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref(),
            Some("42501")
        );
        apply(&executor, &changes).await.unwrap();
        let flags: (bool,bool,bool) = sqlx::query_as("SELECT a.inherit_option,a.admin_option,a.set_option FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor WHERE r.rolname='mop_role' AND m.rolname='mop_exec' AND g.rolname='mop_g1'").fetch_one(&root).await.unwrap();
        assert_eq!(flags, (false, false, true));
        executor.close().await;

        // A new independent supplier must invalidate a reviewed reduction,
        // even though the selected grantor tuple itself did not change.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_g1,mop_g2 WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_g1 TO mop_exec WITH INHERIT TRUE, SET FALSE; GRANT mop_role TO mop_member WITH INHERIT TRUE, SET TRUE GRANTED BY mop_g1").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let old = resolve_membership_options(
            &executor,
            diff(&before, &desired(&before, false, false)),
            &before,
        )
        .await
        .unwrap();
        root.execute("GRANT mop_role TO mop_member WITH INHERIT TRUE, SET FALSE GRANTED BY mop_g2")
            .await
            .unwrap();
        assert!(preflight_authority_issues(&executor, &old, &before).await.unwrap().iter().any(|issue| matches!(issue, AuthorityIssue::MembershipOptionsBlocked { reason, .. } if reason.contains("changed since"))));
        assert_eq!(
            rows(&root).await,
            vec![
                ("mop_g1".into(), true, false, true),
                ("mop_g2".into(), true, false, false)
            ]
        );
        executor.close().await;
        root.close().await;
    });
}

#[test]
#[ignore = "requires a disposable PostgreSQL 16+ database and DATABASE_URL"]
fn an_increase_without_usable_admin_is_planned_and_blocked_by_preflight() {
    // Declared first so the cleanup guard drops before the lock is released.
    let _serial = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _cleanup = Cleanup;
    runtime(async {
        let root = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        // INC-168 without the executor's own ADMIN: only the provider can
        // attribute the edge, and the ordinary login cannot act as it.
        reset(&root).await;
        root.execute("GRANT mop_role TO mop_alloydbadmin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE; GRANT mop_role TO mop_member WITH INHERIT FALSE, SET TRUE GRANTED BY mop_alloydbadmin").await.unwrap();
        let executor = ordinary_executor().await;
        let before = current(&executor).await;
        let raw = diff(&before, &desired(&before, true, false));
        // Missing authority is not a planning fault: the change still renders
        // for review, attributed to the executor as a new SET FALSE edge.
        let changes = resolve_membership_options(&executor, raw, &before)
            .await
            .unwrap();
        assert!(
            matches!(&changes[..], [Change::UpdateMemberOptions { grantor, .. }] if grantor == "mop_exec")
        );
        assert!(render_batch_with_context(&changes, &SqlContext::default()).is_ok());
        // The authority preflight is what blocks it, before any SQL runs.
        let issues = preflight_authority_issues(&executor, &changes, &before)
            .await
            .unwrap();
        assert!(issues.iter().any(|issue| matches!(
            issue,
            AuthorityIssue::MembershipOptionsBlocked { grantor, .. } if grantor == "mop_exec"
        )));
        assert_eq!(
            rows(&root).await,
            vec![("mop_alloydbadmin".into(), false, false, true)]
        );
        executor.close().await;
    });
}
