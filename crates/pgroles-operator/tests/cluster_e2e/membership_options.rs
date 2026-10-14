//! Membership option changes through the operator on PostgreSQL 16+: an
//! increase is granted by a holder the executor can use, beside — not instead
//! of — an edge another grantor owns, and a reduction the executor cannot make
//! is reported before it merges, with the repair it needs.

use pgroles_operator::crd::{ExecutionGuard, PostgresPolicyCandidate};
use serde_json::{Value, json};

use crate::harness::scenario;

const POLICY: &str = "membership-options-policy";

fn content(member_inherit: bool, admin_member_admin: bool) -> Value {
    json!({
        "roles": [
            {"name": "cmo_group", "external": true},
            {"name": "cmo_member", "external": true},
            {"name": "cmo_admin_member", "external": true},
        ],
        "memberships": [{"role": "cmo_group", "members": [
            {"name": "cmo_member", "inherit": member_inherit},
            {"name": "cmo_admin_member", "admin": admin_member_admin},
        ]}],
    })
}

fn issues(candidate: &PostgresPolicyCandidate) -> Vec<(ExecutionGuard, String)> {
    candidate
        .status
        .as_ref()
        .and_then(|status| status.execution_preflight.as_ref())
        .map(|result| {
            result
                .issues
                .iter()
                .map(|issue| (issue.guard, issue.message.clone()))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn option_changes_keep_other_grantors_edges_and_preview_what_cannot_change() {
    scenario(|s| async move {
        s.owns_roles(&[
            "cmo_group",
            "cmo_member",
            "cmo_admin_member",
            "cmo_provider",
            "cmo_executor",
        ]);
        // cmo_provider stands in for a managed service's administrator: its
        // edges are not the executor's to rewrite.
        s.sql(
            "CREATE ROLE cmo_group; CREATE ROLE cmo_member; CREATE ROLE cmo_admin_member;
             CREATE ROLE cmo_provider;
             CREATE ROLE cmo_executor LOGIN PASSWORD 'cmo-test-password';
             GRANT cmo_group TO cmo_provider WITH ADMIN TRUE;
             GRANT cmo_group TO cmo_executor WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
             GRANT cmo_group TO cmo_member WITH INHERIT FALSE, SET FALSE GRANTED BY cmo_provider;
             GRANT cmo_group TO cmo_admin_member WITH ADMIN TRUE GRANTED BY cmo_provider;",
        )
        .await;
        s.database_secret(
            "membership-options-credentials",
            "cmo_executor",
            "cmo-test-password",
        )
        .await;
        let mut spec = content(true, true);
        spec["connection"] = json!({"secretRef": {"name": "membership-options-credentials"}});
        spec["interval"] = json!("1h");
        spec["mode"] = json!("apply");
        spec["approval"] = json!("auto");
        s.create_policy(POLICY, spec).await;

        // INHERIT is raised by the executor's own edge; the provider's edge
        // and its SET FALSE are left exactly as they were.
        s.wait_policy_ready(POLICY, "True", "Reconciled").await;
        let edges_query =
            "SELECT string_agg(g.rolname || ':' || m.inherit_option || ':' || m.set_option, ','
                    ORDER BY g.rolname)
             FROM pg_auth_members m
             JOIN pg_roles r ON r.oid = m.roleid
             JOIN pg_roles u ON u.oid = m.member
             JOIN pg_roles g ON g.oid = m.grantor
             WHERE r.rolname = 'cmo_group' AND u.rolname = 'cmo_member'";
        let expected = "cmo_executor:true:false,cmo_provider:false:false";
        assert_eq!(s.query_text(edges_query).await, expected);
        // Converged: a further reconcile succeeds and rewrites nothing.
        s.reconcile(POLICY).await;
        s.wait_policy_ready(POLICY, "True", "Reconciled").await;
        assert_eq!(s.query_text(edges_query).await, expected);

        // Dropping ADMIN from an edge the provider granted needs the
        // provider's privileges. The preview says so, and offers keeping the
        // live option instead.
        s.create_candidate(
            "membership-options-reduce",
            POLICY,
            content(true, false),
            None,
        )
        .await;
        let reduce = s
            .wait_candidate_ready("membership-options-reduce", "False", "ExecutionBlocked")
            .await;
        let found = issues(&reduce);
        assert!(
            found.iter().any(
                |(guard, message)| *guard == ExecutionGuard::ExecutorAuthority
                    && message.contains("cmo_provider")
                    && message.contains("declare")
            ),
            "{found:?}"
        );
        assert!(
            s.query_bool(
                "SELECT bool_or(admin_option) FROM pg_auth_members m
                 JOIN pg_roles u ON u.oid = m.member
                 WHERE m.roleid = 'cmo_group'::regrole AND u.rolname = 'cmo_admin_member'",
            )
            .await,
            "previewing changed nothing"
        );
        // Declaring the live option is the repair: nothing to change. (The
        // extra external role only keeps this proposal's content distinct
        // from the policy's own.)
        let mut keep = content(true, true);
        keep["roles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "cmo_provider", "external": true}));
        s.create_candidate("membership-options-keep", POLICY, keep, None)
            .await;
        s.wait_candidate_ready("membership-options-keep", "True", "NoEffects")
            .await;
    })
    .await;
}
