//! Compare bootstrap preflight with actual SQL, rolling every case back.
use pgroles_core::diff::Change;
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{DefaultPrivilegeScope, Grantee, RoleGraph, RoleState};
use pgroles_core::sql::render_statements;
use pgroles_inspect::{AuthorityIssue, preflight_authority_issues};
use sqlx::{Executor, PgPool, postgres::PgPoolOptions};

/// Always roll back before asserting, including when preflight or SQL fails.
async fn check_plan(pool: &PgPool, changes: &[Change], expected: Vec<AuthorityIssue>, case: &str) {
    let issues = preflight_authority_issues(pool, changes, &RoleGraph::default()).await;
    let mut failure = None;
    'plan: for change in changes {
        for statement in render_statements(change) {
            if let Err(error) = pool.execute(statement.as_str()).await {
                failure = Some((statement, error));
                break 'plan;
            }
        }
    }
    pool.execute("ROLLBACK").await.unwrap();
    assert_eq!(issues.unwrap(), expected, "preflight: {case}");
    if expected.is_empty() {
        assert!(failure.is_none(), "SQL: {case}: {failure:?}");
    } else {
        let (statement, error) =
            failure.unwrap_or_else(|| panic!("SQL unexpectedly passed: {case}"));
        assert!(
            statement.starts_with("ALTER DEFAULT PRIVILEGES"),
            "{case}: {statement}: {error}"
        );
        let expected_code = if matches!(
            expected[0],
            AuthorityIssue::MissingDefaultPrivilegeOwner { .. }
        ) {
            "42704"
        } else {
            "42501"
        };
        assert_eq!(
            error
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref(),
            Some(expected_code),
            "{case}: {statement}: {error}"
        );
    }
}

fn owner_issue() -> Vec<AuthorityIssue> {
    vec![AuthorityIssue::DefaultPrivilegeOwner {
        owner: "csg_owner".into(),
        executor: "csg_executor".into(),
    }]
}

#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to a superuser"]
async fn default_owner_bootstrap_matches_postgres() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&pool)
        .await
        .unwrap();
    if version < 160_000 {
        return;
    }

    for setting in ["", "set", "inherit", "set, inherit", "\"inherit\""] {
        // Grant phase, revoke phase, authority removal, and restoration.
        for phase in [
            "grant",
            "revoke",
            "remove",
            "restore",
            "add",
            "both_remove",
            "both_restore",
            "noninherit",
            "both_noninherit",
            "grant_then_noninherit",
        ] {
            pool.execute(
                "BEGIN; CREATE ROLE csg_executor CREATEROLE NOINHERIT; SET LOCAL ROLE csg_executor",
            )
            .await
            .unwrap();
            sqlx::query("SELECT set_config('createrole_self_grant', $1, true)")
                .bind(setting)
                .execute(&pool)
                .await
                .unwrap();
            let mut changes = vec![Change::CreateRole {
                name: "csg_owner".into(),
                state: RoleState::default(),
            }];
            if phase.starts_with("both_") || phase == "grant_then_noninherit" {
                changes.push(Change::SetDefaultPrivilege {
                    owner: "csg_owner".into(),
                    scope: DefaultPrivilegeScope::Global,
                    on_type: ObjectType::Table,
                    grantee: Grantee::Public,
                    privileges: [Privilege::Select].into(),
                });
            }
            if matches!(phase, "remove" | "restore" | "both_remove" | "both_restore") {
                changes.push(Change::RemoveMember {
                    role: "csg_owner".into(),
                    member: "csg_executor".into(),
                    grantor: None,
                });
            }
            if matches!(phase, "restore" | "add" | "both_restore") {
                changes.push(Change::AddMember {
                    role: "csg_owner".into(),
                    member: "csg_executor".into(),
                    inherit: true,
                    admin: false,
                });
            }
            if matches!(
                phase,
                "noninherit" | "both_noninherit" | "grant_then_noninherit"
            ) {
                changes.push(Change::AddMember {
                    role: "csg_owner".into(),
                    member: "csg_executor".into(),
                    inherit: false,
                    admin: false,
                });
            }
            if phase != "grant_then_noninherit" {
                changes.push(if phase == "grant" {
                    Change::SetDefaultPrivilege {
                        owner: "csg_owner".into(),
                        scope: DefaultPrivilegeScope::Global,
                        on_type: ObjectType::Table,
                        grantee: Grantee::Public,
                        privileges: [Privilege::Select].into(),
                    }
                } else {
                    Change::RevokeDefaultPrivilege {
                        owner: "csg_owner".into(),
                        scope: DefaultPrivilegeScope::Global,
                        on_type: ObjectType::Function,
                        grantee: Grantee::Public,
                        privileges: [Privilege::Execute].into(),
                    }
                });
            }
            let expected = matches!(phase, "restore" | "add")
                || (setting.contains("inherit")
                    && !matches!(
                        phase,
                        "remove" | "both_remove" | "noninherit" | "both_noninherit"
                    ));
            check_plan(
                &pool,
                &changes,
                if expected { vec![] } else { owner_issue() },
                &format!("{setting:?} {phase}"),
            )
            .await;
        }
    }

    // The setting affects creation only: it cannot provide authority over an
    // existing owner, and it cannot make an undeclared missing owner exist.
    for owner_state in ["existing_usable", "existing_unusable", "missing", "created"] {
        for revoke in [false, true] {
            for scope in [
                DefaultPrivilegeScope::Global,
                DefaultPrivilegeScope::Schema {
                    schema: "csg_schema".into(),
                },
            ] {
                pool.execute("BEGIN; CREATE ROLE csg_executor CREATEROLE NOINHERIT; CREATE SCHEMA csg_schema AUTHORIZATION csg_executor").await.unwrap();
                if owner_state.starts_with("existing_") {
                    pool.execute("CREATE ROLE csg_owner").await.unwrap();
                }
                if owner_state == "existing_usable" {
                    pool.execute("GRANT csg_owner TO csg_executor WITH INHERIT TRUE")
                        .await
                        .unwrap();
                }
                pool.execute(
                    "SET LOCAL ROLE csg_executor; SET LOCAL createrole_self_grant = 'inherit'",
                )
                .await
                .unwrap();
                let mut changes = Vec::new();
                if owner_state == "created" {
                    changes.push(Change::CreateRole {
                        name: "csg_owner".into(),
                        state: RoleState::default(),
                    });
                }
                // Exercise the phase graph for revokes too, without affecting
                // authority over csg_owner.
                if revoke {
                    changes.push(Change::CreateRole {
                        name: "csg_other".into(),
                        state: RoleState::default(),
                    });
                    changes.push(Change::AddMember {
                        role: "csg_other".into(),
                        member: "csg_executor".into(),
                        inherit: true,
                        admin: false,
                    });
                }
                changes.push(if revoke {
                    Change::RevokeDefaultPrivilege {
                        owner: "csg_owner".into(),
                        scope: scope.clone(),
                        on_type: ObjectType::Function,
                        grantee: Grantee::Public,
                        privileges: [Privilege::Execute].into(),
                    }
                } else {
                    Change::SetDefaultPrivilege {
                        owner: "csg_owner".into(),
                        scope: scope.clone(),
                        on_type: ObjectType::Table,
                        grantee: Grantee::Public,
                        privileges: [Privilege::Select].into(),
                    }
                });
                let expected = match owner_state {
                    "existing_unusable" => owner_issue(),
                    "missing" => vec![AuthorityIssue::MissingDefaultPrivilegeOwner {
                        owner: "csg_owner".into(),
                    }],
                    _ => vec![],
                };
                check_plan(
                    &pool,
                    &changes,
                    expected,
                    &format!("{owner_state} revoke={revoke} scope={scope:?}"),
                )
                .await;
            }
        }
    }
    // A new bridge provides inherited access only if the preceding membership
    // GRANT is executable. CREATEROLE does not confer ADMIN on existing owners.
    for can_admin in [false, true] {
        pool.execute("BEGIN; CREATE ROLE csg_executor CREATEROLE NOINHERIT; CREATE ROLE csg_owner")
            .await
            .unwrap();
        if can_admin {
            pool.execute("GRANT csg_owner TO csg_executor WITH ADMIN TRUE, INHERIT FALSE")
                .await
                .unwrap();
        }
        pool.execute("SET LOCAL ROLE csg_executor; SET LOCAL createrole_self_grant = 'inherit'")
            .await
            .unwrap();
        let changes = vec![
            Change::CreateRole {
                name: "csg_bridge".into(),
                state: RoleState::default(),
            },
            Change::AddMember {
                role: "csg_owner".into(),
                member: "csg_bridge".into(),
                inherit: true,
                admin: false,
            },
            Change::RevokeDefaultPrivilege {
                owner: "csg_owner".into(),
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Function,
                grantee: Grantee::Public,
                privileges: [Privilege::Execute].into(),
            },
        ];
        let issues = preflight_authority_issues(&pool, &changes, &RoleGraph::default()).await;
        let mut failure = None;
        'plan: for change in &changes {
            for statement in render_statements(change) {
                if let Err(error) = pool.execute(statement.as_str()).await {
                    failure = Some((statement, error));
                    break 'plan;
                }
            }
        }
        pool.execute("ROLLBACK").await.unwrap();
        assert_eq!(
            issues.unwrap(),
            if can_admin { vec![] } else { owner_issue() }
        );
        if can_admin {
            assert!(failure.is_none(), "{failure:?}");
        } else {
            let (statement, error) = failure.expect("membership GRANT must fail");
            assert!(statement.starts_with("GRANT "), "{statement}: {error}");
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("42501")
            );
        }
    }

    // Superusers do not need self-grants, and a role always has authority over
    // its own defaults even when NOINHERIT and without CREATEROLE.
    for superuser in [false, true] {
        for revoke in [false, true] {
            pool.execute("BEGIN; SET LOCAL createrole_self_grant = ''")
                .await
                .unwrap();
            let mut changes = Vec::new();
            let owner = if superuser {
                changes.push(Change::CreateRole {
                    name: "csg_owner".into(),
                    state: RoleState::default(),
                });
                "csg_owner"
            } else {
                pool.execute(
                    "CREATE ROLE csg_executor NOINHERIT NOCREATEROLE; SET LOCAL ROLE csg_executor",
                )
                .await
                .unwrap();
                "csg_executor"
            };
            changes.push(if revoke {
                Change::RevokeDefaultPrivilege {
                    owner: owner.into(),
                    scope: DefaultPrivilegeScope::Global,
                    on_type: ObjectType::Function,
                    grantee: Grantee::Public,
                    privileges: [Privilege::Execute].into(),
                }
            } else {
                Change::SetDefaultPrivilege {
                    owner: owner.into(),
                    scope: DefaultPrivilegeScope::Global,
                    on_type: ObjectType::Table,
                    grantee: Grantee::Public,
                    privileges: [Privilege::Select].into(),
                }
            });
            check_plan(
                &pool,
                &changes,
                vec![],
                &format!("superuser={superuser} revoke={revoke}"),
            )
            .await;
        }
    }
    pool.close().await;
}

/// ADMIN reachable through plain membership is insufficient for rendered GRANT:
/// the executor must retain inherited access to a usable grantor at that phase.
#[tokio::test]
#[ignore = "requires DATABASE_URL pointing to a superuser"]
async fn planned_owner_grants_require_surviving_admin_authority() {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .unwrap();
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&pool)
        .await
        .unwrap();
    if version < 160_000 {
        return;
    }

    for (case, inherits_admin, remove_admin, downgrade_admin, independent_admin) in [
        ("noninherited admin", false, false, false, false),
        ("retained inherited admin", true, false, false, false),
        ("removed inherited admin", true, true, false, false),
        (
            "independent admin survives removal",
            true,
            true,
            false,
            true,
        ),
        ("downgraded inherited admin", true, false, true, false),
        (
            "independent admin survives downgrade",
            true,
            false,
            true,
            true,
        ),
    ] {
        pool.execute(
            "BEGIN;
             CREATE ROLE csg_gap_owner;
             CREATE ROLE csg_gap_executor CREATEROLE NOINHERIT;
             SET LOCAL ROLE csg_gap_executor;
             SET LOCAL createrole_self_grant = 'inherit';
             CREATE ROLE csg_gap_admin",
        )
        .await
        .unwrap();
        if !inherits_admin {
            pool.execute("GRANT csg_gap_admin TO csg_gap_executor WITH INHERIT FALSE")
                .await
                .unwrap();
        }
        pool.execute(
            "RESET ROLE;
             GRANT csg_gap_owner TO csg_gap_admin WITH ADMIN TRUE, INHERIT FALSE",
        )
        .await
        .unwrap();
        if independent_admin {
            pool.execute("GRANT csg_gap_owner TO csg_gap_executor WITH ADMIN TRUE, INHERIT FALSE")
                .await
                .unwrap();
        }
        pool.execute("SET LOCAL ROLE csg_gap_executor")
            .await
            .unwrap();
        // All setups pass the broad catalog predicate that previously
        // admitted infeasible grants. The owner's privileges are not inherited.
        let catalog_admin: bool = sqlx::query_scalar(
            "SELECT pg_has_role(current_user, 'csg_gap_owner', 'MEMBER WITH ADMIN OPTION')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut changes = vec![Change::CreateRole {
            name: "csg_gap_bridge".into(),
            state: RoleState::default(),
        }];
        if remove_admin {
            changes.push(Change::RemoveMember {
                role: "csg_gap_admin".into(),
                member: "csg_gap_executor".into(),
                grantor: Some("csg_gap_executor".into()),
            });
        }
        if downgrade_admin {
            changes.push(Change::AddMember {
                role: "csg_gap_admin".into(),
                member: "csg_gap_executor".into(),
                inherit: false,
                admin: false,
            });
        }
        if independent_admin {
            // admin:false omits ADMIN in the renderer; it must not erase the
            // existing independent ADMIN grant when preflight models this plan.
            changes.push(Change::AddMember {
                role: "csg_gap_owner".into(),
                member: "csg_gap_executor".into(),
                inherit: false,
                admin: false,
            });
        }
        changes.extend([
            Change::AddMember {
                role: "csg_gap_owner".into(),
                member: "csg_gap_bridge".into(),
                inherit: true,
                admin: false,
            },
            Change::RevokeDefaultPrivilege {
                owner: "csg_gap_owner".into(),
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Function,
                grantee: Grantee::Public,
                privileges: [Privilege::Execute].into(),
            },
        ]);
        let issues = preflight_authority_issues(&pool, &changes, &RoleGraph::default()).await;
        let mut failure = None;
        'plan: for change in &changes {
            for statement in render_statements(change) {
                if let Err(error) = pool.execute(statement.as_str()).await {
                    failure = Some((statement, error));
                    break 'plan;
                }
            }
        }
        pool.execute("ROLLBACK").await.unwrap();

        assert!(catalog_admin, "setup: {case}");
        let executable = independent_admin || (inherits_admin && !remove_admin && !downgrade_admin);
        assert_eq!(
            issues.unwrap(),
            if executable {
                vec![]
            } else {
                vec![AuthorityIssue::DefaultPrivilegeOwner {
                    owner: "csg_gap_owner".into(),
                    executor: "csg_gap_executor".into(),
                }]
            },
            "preflight: {case}"
        );
        if executable {
            assert!(failure.is_none(), "SQL: {case}: {failure:?}");
        } else {
            let (statement, error) = failure.expect("membership GRANT must fail");
            assert!(
                statement.starts_with("GRANT \"csg_gap_owner\""),
                "{case}: {statement}: {error}"
            );
            // PostgreSQL versions differ in whether they reject the missing
            // grantor as insufficient privilege or fail grantor selection.
            assert!(
                matches!(
                    error.as_database_error().and_then(|e| e.code()).as_deref(),
                    Some("42501" | "XX000")
                ),
                "{case}: {statement}: {error}"
            );
        }
    }
    pool.close().await;
}
