use pgroles_core::diff::{Change, ReconciliationMode, filter_changes};
use pgroles_core::model::{MembershipEdge, MembershipOptions, RoleGraph};
use pgroles_core::sql::{SqlContext, render, render_all_with_context};

#[test]
fn option_reductions_are_filtered_but_increases_remain_additive() {
    let update = |inherit, admin| Change::UpdateMemberOptions {
        role: "reader".into(),
        member: "app".into(),
        grantor: "administrator".into(),
        inherit,
        admin,
        binding: None,
    };
    let increase = update(Some(true), Some(true));
    let changes = vec![
        increase.clone(),
        update(Some(false), None),
        update(None, Some(false)),
        update(Some(false), Some(true)),
    ];
    assert_eq!(
        filter_changes(changes.clone(), ReconciliationMode::Additive),
        vec![increase, update(None, Some(true))]
    );
    assert_eq!(
        filter_changes(changes.clone(), ReconciliationMode::Adopt),
        changes
    );
}

#[test]
fn rendering_preserves_omitted_options_and_refuses_legacy_contexts() {
    let change = Change::UpdateMemberOptions {
        role: "group\"role".into(),
        member: "app".into(),
        grantor: "grant\"or".into(),
        inherit: None,
        admin: Some(false),
        binding: Some(pgroles_core::membership_options::MembershipOptionBinding {
            set_effect: pgroles_core::membership_options::MembershipSetEffect::Preserve,
            executor: "executor".into(),
            expected_edges: [(
                "grant\"or".into(),
                MembershipOptions {
                    inherit: true,
                    admin: true,
                    set: false,
                },
            )]
            .into(),
            expected: pgroles_core::membership_options::MembershipExpectedState::Present {
                options: MembershipOptions {
                    inherit: true,
                    admin: true,
                    set: false,
                },
            },
        }),
    };
    assert_eq!(
        render(&change).unwrap(),
        "REVOKE ADMIN OPTION FOR \"group\"\"role\" FROM \"app\" GRANTED BY \"grant\"\"or\" RESTRICT;"
    );
    let legacy = SqlContext {
        pg_major_version: 15,
        ..Default::default()
    };
    assert_eq!(
        render_all_with_context(&[change], &legacy).unwrap_err(),
        pgroles_core::sql::SqlRenderError::UnsupportedMembershipOptions
    );
}

#[test]
fn analysis_retains_set_permission_and_tracks_option_reductions() {
    use pgroles_core::explorer::{
        ExecutorFacts, PlanAnalysisOptions, ReachabilityStatus, analyze_changes_with_options,
    };
    let mut graph = RoleGraph::default();
    let key = ("owner".to_string(), "executor".to_string());
    graph.memberships.insert(MembershipEdge {
        role: key.0.clone(),
        member: key.1.clone(),
        inherit: true,
        admin: true,
    });
    graph
        .membership_edge_grantors
        .insert(key.clone(), ["administrator".into()].into());
    graph.membership_edge_options.insert(
        key.clone(),
        [(
            "administrator".into(),
            MembershipOptions {
                inherit: true,
                admin: true,
                set: false,
            },
        )]
        .into(),
    );
    let changes = vec![Change::UpdateMemberOptions {
        role: key.0.clone(),
        member: key.1.clone(),
        grantor: "administrator".into(),
        inherit: Some(false),
        admin: None,
        binding: None,
    }];
    let executor: ExecutorFacts =
        serde_json::from_value(serde_json::json!({"role":"executor"})).unwrap();
    let analysis = analyze_changes_with_options(
        graph,
        &changes,
        &executor,
        PlanAnalysisOptions {
            pg_major_version: 16,
            authority_graph_complete: true,
        },
    );
    let last = analysis.phases.last().unwrap();
    assert!(
        last.executor_reachability
            .iter()
            .any(|r| r.role == "owner" && r.status == ReachabilityStatus::Unreachable)
    );
    assert!(
        last.executor_usage
            .iter()
            .any(|r| r.role == "owner" && r.status == ReachabilityStatus::Unreachable)
    );
}

#[test]
fn partial_catalog_facts_never_replace_known_grantors() {
    let mut current = RoleGraph::default();
    let key = ("reader".to_string(), "app".to_string());
    current.memberships.insert(MembershipEdge {
        role: key.0.clone(),
        member: key.1.clone(),
        inherit: true,
        admin: true,
    });
    current
        .membership_edge_grantors
        .insert(key.clone(), ["a".into(), "b".into()].into());
    let mut desired = current.clone();
    desired.memberships.clear();
    desired.memberships.insert(MembershipEdge {
        role: key.0,
        member: key.1,
        inherit: false,
        admin: false,
    });
    let changes = pgroles_core::diff::diff(&current, &desired);
    assert_eq!(changes.len(), 2);
    assert!(changes.iter().all(|change| matches!(
        change,
        Change::UpdateMemberOptions {
            inherit: Some(false),
            admin: Some(false),
            ..
        }
    )));
    assert_eq!(
        pgroles_core::sql::render_all(&changes).unwrap_err(),
        pgroles_core::sql::SqlRenderError::UnresolvedMembershipOptions
    );
    assert!(matches!(
        pgroles_core::membership_options::resolve_membership_options(
            changes,
            &current,
            &authority("executor")
        ),
        Err(pgroles_core::membership_options::MembershipOptionsError::IncompleteFacts { .. })
    ));
}

#[test]
fn incomplete_grantor_options_and_missing_targets_keep_authority_unknown() {
    use pgroles_core::explorer::{ExecutorFacts, ReachabilityStatus, analyze_changes};
    let key = ("owner".to_string(), "executor".to_string());
    for (complete, target) in [(false, "a"), (false, "b"), (true, "missing")] {
        let mut graph = RoleGraph::default();
        graph.memberships.insert(MembershipEdge {
            role: key.0.clone(),
            member: key.1.clone(),
            inherit: true,
            admin: true,
        });
        graph
            .membership_edge_grantors
            .insert(key.clone(), ["a".into(), "b".into()].into());
        let mut options = std::collections::BTreeMap::from([(
            "a".into(),
            MembershipOptions {
                inherit: true,
                admin: true,
                set: false,
            },
        )]);
        if complete {
            options.insert(
                "b".into(),
                MembershipOptions {
                    inherit: false,
                    admin: false,
                    set: true,
                },
            );
        }
        graph.membership_edge_options.insert(key.clone(), options);
        let change = Change::UpdateMemberOptions {
            role: key.0.clone(),
            member: key.1.clone(),
            grantor: target.into(),
            inherit: Some(false),
            admin: Some(false),
            binding: None,
        };
        let executor: ExecutorFacts =
            serde_json::from_value(serde_json::json!({"role":"executor"})).unwrap();
        let result = analyze_changes(graph, &[change], &executor);
        let phase = result.phases.last().unwrap();
        assert!(
            phase
                .executor_usage
                .iter()
                .any(|r| r.role == "owner" && r.status == ReachabilityStatus::Unknown)
        );
        if !complete {
            assert!(
                phase
                    .executor_reachability
                    .iter()
                    .any(|r| r.role == "owner" && r.status == ReachabilityStatus::Unknown)
            );
        }
    }
}

fn graph_with_options(options: std::collections::BTreeMap<String, MembershipOptions>) -> RoleGraph {
    let mut graph = RoleGraph::default();
    let key = ("reader".to_string(), "app".to_string());
    graph.memberships.insert(MembershipEdge {
        role: key.0.clone(),
        member: key.1.clone(),
        inherit: options.values().any(|o| o.inherit),
        admin: options.values().any(|o| o.admin),
    });
    graph
        .membership_edge_grantors
        .insert(key.clone(), options.keys().cloned().collect());
    graph.membership_edge_options.insert(key, options);
    graph
}

fn increase() -> Change {
    Change::UpdateMemberOptions {
        role: "reader".into(),
        member: "app".into(),
        grantor: "alloydbadmin".into(),
        inherit: Some(true),
        admin: None,
        binding: None,
    }
}

fn authority(grantor: &str) -> pgroles_core::membership_options::MembershipAuthority {
    pgroles_core::membership_options::MembershipAuthority {
        executor: "pgroles_executor".into(),
        usable_grantors: [("reader".into(), [grantor.into()].into())].into(),
    }
}

#[test]
fn positive_options_choose_proven_own_attribution_and_do_not_copy_foreign_set() {
    use pgroles_core::membership_options::{MembershipExpectedState, resolve_membership_options};
    for foreign_set in [false, true] {
        for own_set in [None, Some(false), Some(true)] {
            let mut rows: std::collections::BTreeMap<_, _> = [(
                "alloydbadmin".into(),
                MembershipOptions {
                    inherit: false,
                    admin: false,
                    set: foreign_set,
                },
            )]
            .into();
            if let Some(set) = own_set {
                rows.insert(
                    "pgroles_executor".into(),
                    MembershipOptions {
                        inherit: false,
                        admin: false,
                        set,
                    },
                );
            }
            let graph = graph_with_options(rows);
            let changes = resolve_membership_options(
                vec![increase()],
                &graph,
                &authority("pgroles_executor"),
            )
            .unwrap();
            let Change::UpdateMemberOptions {
                grantor,
                inherit,
                admin,
                binding: Some(binding),
                ..
            } = &changes[0]
            else {
                panic!("resolved options")
            };
            assert_eq!(grantor, "pgroles_executor");
            assert_eq!((*inherit, *admin), (Some(true), None));
            assert_eq!(binding.executor, "pgroles_executor");
            let sql = render_all_with_context(&changes, &SqlContext::default()).unwrap();
            assert!(!sql.contains("REVOKE") && !sql.contains("ADMIN"));
            if own_set.is_none() {
                assert_eq!(binding.expected, MembershipExpectedState::Absent);
                assert!(sql.contains("SET FALSE"));
            } else {
                assert!(matches!(
                    binding.expected,
                    MembershipExpectedState::Present { .. }
                ));
                assert!(!sql.contains("SET "));
            }
            assert!(sql.contains("GRANTED BY \"pgroles_executor\""));
        }
    }
}

#[test]
fn inherited_administration_uses_the_concrete_holder_instead_of_claiming_own_admin() {
    use pgroles_core::membership_options::resolve_membership_options;
    let graph = graph_with_options(
        [(
            "alloydbadmin".into(),
            MembershipOptions {
                inherit: false,
                admin: false,
                set: true,
            },
        )]
        .into(),
    );
    let changes =
        resolve_membership_options(vec![increase()], &graph, &authority("administrator")).unwrap();
    let sql = render_all_with_context(&changes, &SqlContext::default()).unwrap();
    assert!(sql.contains("GRANTED BY \"administrator\""));
    assert!(sql.contains("SET FALSE"));
}

#[test]
fn incomplete_or_inconsistent_catalog_facts_and_unusable_grantors_fail_closed() {
    use pgroles_core::membership_options::{MembershipOptionsError, resolve_membership_options};
    let graph = graph_with_options(
        [(
            "alloydbadmin".into(),
            MembershipOptions {
                inherit: false,
                admin: false,
                set: false,
            },
        )]
        .into(),
    );
    let no_authority = pgroles_core::membership_options::MembershipAuthority {
        executor: "pgroles_executor".into(),
        usable_grantors: Default::default(),
    };
    assert!(matches!(
        resolve_membership_options(vec![increase()], &graph, &no_authority),
        Err(MembershipOptionsError::NoUsableGrantor { .. })
    ));
    let mut partial = graph.clone();
    partial
        .membership_edge_grantors
        .get_mut(&("reader".into(), "app".into()))
        .unwrap()
        .insert("another_grantor".into());
    assert!(matches!(
        resolve_membership_options(vec![increase()], &partial, &authority("pgroles_executor")),
        Err(MembershipOptionsError::IncompleteFacts { .. })
    ));
    let mut inconsistent = graph;
    inconsistent
        .membership_edge_options
        .get_mut(&("reader".into(), "app".into()))
        .unwrap()
        .get_mut("alloydbadmin")
        .unwrap()
        .inherit = true;
    assert!(matches!(
        resolve_membership_options(
            vec![increase()],
            &inconsistent,
            &authority("pgroles_executor")
        ),
        Err(MembershipOptionsError::IncompleteFacts { .. })
    ));
    assert_eq!(
        render(&increase()).unwrap_err(),
        pgroles_core::sql::SqlRenderError::UnresolvedMembershipOptions
    );
}

#[test]
fn mixed_effective_option_changes_keep_independent_increases_in_additive_mode() {
    use pgroles_core::membership_options::resolve_membership_options;
    let current = graph_with_options(
        [(
            "alloydbadmin".into(),
            MembershipOptions {
                inherit: false,
                admin: true,
                set: true,
            },
        )]
        .into(),
    );
    let mut desired = current.clone();
    desired.memberships.clear();
    desired.memberships.insert(MembershipEdge {
        role: "reader".into(),
        member: "app".into(),
        inherit: true,
        admin: false,
    });
    let full = pgroles_core::diff::diff(&current, &desired);
    assert_eq!(full.len(), 2);
    let additive = filter_changes(full, ReconciliationMode::Additive);
    assert_eq!(additive.len(), 1);
    let resolved =
        resolve_membership_options(additive, &current, &authority("pgroles_executor")).unwrap();
    let sql = render_all_with_context(&resolved, &SqlContext::default()).unwrap();
    assert!(sql.contains("INHERIT TRUE") && sql.contains("SET FALSE"));
    assert!(!sql.contains("REVOKE") && !sql.contains("ADMIN FALSE"));
}

#[test]
fn approval_digest_binds_executor_grantor_expected_tuple_and_set_options() {
    use pgroles_core::approval::{EffectDigestInputs, TargetIdentity, compute_change_digest};
    use pgroles_core::membership_options::{MembershipExpectedState, resolve_membership_options};
    let graph = graph_with_options(
        [(
            "alloydbadmin".into(),
            MembershipOptions {
                inherit: false,
                admin: false,
                set: false,
            },
        )]
        .into(),
    );
    let resolved =
        resolve_membership_options(vec![increase()], &graph, &authority("pgroles_executor"))
            .unwrap();
    let identity = TargetIdentity::default();
    let versions = Default::default();
    let inputs = EffectDigestInputs {
        reconciliation_mode: ReconciliationMode::Authoritative,
        target: "synthetic",
        target_identity: &identity,
        password_source_versions: &versions,
        owned_roles: &[],
        owned_schemas: &[],
    };
    let original = compute_change_digest(&resolved, &inputs).unwrap();
    for component in 0..6 {
        let mut changed = resolved.clone();
        let Change::UpdateMemberOptions {
            grantor,
            binding: Some(binding),
            ..
        } = &mut changed[0]
        else {
            panic!("resolved options")
        };
        match component {
            0 => binding.executor = "different_executor".into(),
            1 => *grantor = "different_administrator".into(),
            2 => {
                binding.expected = MembershipExpectedState::Present {
                    options: MembershipOptions {
                        inherit: false,
                        admin: false,
                        set: false,
                    },
                }
            }
            3 => {
                binding.expected = MembershipExpectedState::Present {
                    options: MembershipOptions {
                        inherit: false,
                        admin: false,
                        set: true,
                    },
                }
            }
            _ => {
                binding.set_effect = pgroles_core::membership_options::MembershipSetEffect::Preserve
            }
        }
        assert_ne!(compute_change_digest(&changed, &inputs).unwrap(), original);
    }
}

#[test]
fn configured_external_membership_reductions_survive_authoritative_and_adopt_pipeline() {
    let current = graph_with_options(
        [(
            "alloydbadmin".into(),
            MembershipOptions {
                inherit: true,
                admin: true,
                set: false,
            },
        )]
        .into(),
    );
    let prepared = pgroles_core::authoring::prepare_policy("roles:\n  - {name: reader, external: true}\n  - {name: app, external: true}\nmemberships:\n  - role: reader\n    members: [{name: app, inherit: false, admin: false}]\n").unwrap();
    for mode in [ReconciliationMode::Authoritative, ReconciliationMode::Adopt] {
        let changes = pgroles_core::diff::plan_changes(
            &current,
            &prepared.desired,
            &prepared.manifest,
            &prepared.expanded,
            mode,
        );
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            Change::UpdateMemberOptions {
                inherit: Some(false),
                admin: Some(false),
                ..
            }
        ));
    }
    assert!(
        pgroles_core::diff::plan_changes(
            &current,
            &prepared.desired,
            &prepared.manifest,
            &prepared.expanded,
            ReconciliationMode::Additive
        )
        .is_empty()
    );
}

#[test]
fn unattributed_pg16_replacements_and_inconsistent_set_effect_fail_closed() {
    let changes = vec![
        Change::RemoveMember {
            role: "r".into(),
            member: "m".into(),
            grantor: None,
        },
        Change::AddMember {
            role: "r".into(),
            member: "m".into(),
            inherit: true,
            admin: false,
        },
    ];
    assert!(matches!(
        pgroles_core::sql::render_all(&changes),
        Err(pgroles_core::sql::SqlRenderError::UnattributedMembershipReplacement)
    ));
    let context = pgroles_core::sql::SqlContext {
        pg_major_version: 15,
        ..Default::default()
    };
    assert!(pgroles_core::sql::render_all_with_context(&changes, &context).is_ok());
}
