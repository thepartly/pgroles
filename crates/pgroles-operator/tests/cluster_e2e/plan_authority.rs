//! An auto-approval policy whose executor lacks the authority to apply its
//! plan: the plan waits for review instead of being approved and abandoned on
//! every reconcile, a reviewer's denial is final, and recovery applies the
//! plan that was waiting.

use pgroles_operator::crd::PlanPhase;
use serde_json::json;

use crate::harness::{Decision, current_plan, is_actionable, ready, scenario};

const POLICY: &str = "plan-authority-policy";

fn members(with_member: bool) -> serde_json::Value {
    let mut members = vec![json!({"name": "pln_grantor", "admin": true})];
    if with_member {
        members.push(json!({"name": "pln_member", "inherit": false}));
    }
    json!([{"role": "pln_group", "exclusive": true, "members": members}])
}

#[tokio::test]
async fn a_blocked_auto_plan_waits_for_authority_and_honours_a_denial() {
    scenario(|s| async move {
        s.owns_roles(&["pln_group", "pln_member", "pln_grantor", "pln_executor"]);
        // The member's edge is attributed to pln_grantor. An executor that
        // cannot act as pln_grantor cannot revoke it.
        s.sql(
            "CREATE ROLE pln_group; CREATE ROLE pln_member; CREATE ROLE pln_grantor;
             CREATE ROLE pln_executor LOGIN PASSWORD 'pln-test-password';
             GRANT pln_group TO pln_grantor WITH ADMIN TRUE;
             GRANT pln_group TO pln_member WITH INHERIT FALSE, SET FALSE GRANTED BY pln_grantor;",
        )
        .await;
        s.database_secret(
            "plan-authority-credentials",
            "pln_executor",
            "pln-test-password",
        )
        .await;
        s.create_policy(
            POLICY,
            json!({
                "connection": {"secretRef": {"name": "plan-authority-credentials"}},
                "interval": "1h",
                "mode": "apply",
                "approval": "auto",
                "roles": [
                    {"name": "pln_group", "external": true},
                    {"name": "pln_member", "external": true},
                    {"name": "pln_grantor", "external": true},
                ],
                "memberships": members(true),
            }),
        )
        .await;
        s.wait_policy_ready(POLICY, "True", "Reconciled").await;

        // Dropping the member asks for a revoke the executor cannot run.
        s.patch_policy_spec(POLICY, json!({"memberships": members(false)}))
            .await;
        let blocked = s
            .wait_policy_ready(POLICY, "False", "ExecutorAuthority")
            .await;
        let plan = current_plan(&blocked).expect("the blocked plan stays referenced");
        s.wait_plan_phase(&plan, PlanPhase::Pending).await;
        assert!(
            s.plan_sql(&plan)
                .await
                .contains(r#"REVOKE "pln_group" FROM "pln_member" GRANTED BY "pln_grantor";"#)
        );
        assert!(s.is_member("pln_member", "pln_group").await);

        // Every further reconcile reuses the waiting plan, and the failure
        // does not flap: the Ready condition keeps its transition time.
        let blocked_since = ready(blocked.status.as_ref().map(|s| s.conditions.as_slice()))
            .unwrap()
            .last_transition_time
            .clone();
        for _ in 0..3 {
            let after = s.reconcile(POLICY).await;
            assert_eq!(current_plan(&after).as_deref(), Some(plan.as_str()));
            let condition = ready(after.status.as_ref().map(|s| s.conditions.as_slice())).unwrap();
            assert_eq!(condition.reason.as_deref(), Some("ExecutorAuthority"));
            assert_eq!(condition.last_transition_time, blocked_since);
            assert_eq!(
                s.plan(&plan).await.status.unwrap().phase,
                PlanPhase::Pending
            );
        }
        assert_eq!(s.plans_of(POLICY).await.len(), 1);

        // A reviewer denies the waiting plan. That plan never executes, and a
        // fresh plan for the same effects replaces it.
        let denied = plan;
        s.decide(&denied, Decision::Deny).await;
        s.wait_plan_phase(&denied, PlanPhase::Rejected).await;
        s.reconcile(POLICY).await;
        let excluded = denied.clone();
        let replacement = s
            .wait_current_plan(POLICY, move |plan| plan != excluded)
            .await;
        s.wait_plan_phase(&replacement, PlanPhase::Pending).await;
        let undecided = s.plan(&replacement).await;

        // An Approved plan is what an earlier controller left behind, and it
        // is reused rather than reopened.
        s.decide(&replacement, Decision::Approve).await;
        s.set_plan_phase(&replacement, PlanPhase::Approved).await;
        // So were identical duplicates: one more for the same effects is
        // retired, and the approved plan stays the one the policy acts on.
        let duplicate = format!("{replacement}-duplicate");
        s.duplicate_plan(&undecided, &duplicate).await;
        let after = s.reconcile(POLICY).await;
        assert_eq!(current_plan(&after).as_deref(), Some(replacement.as_str()));
        let retired = s.wait_plan_phase(&duplicate, PlanPhase::Superseded).await;
        assert!(
            retired.status.unwrap().conditions.iter().any(|c| c
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("identical effects")),
            "the duplicate says why it was retired"
        );
        for _ in 0..2 {
            let after = s.reconcile(POLICY).await;
            assert_eq!(current_plan(&after).as_deref(), Some(replacement.as_str()));
            assert_eq!(
                s.plan(&replacement).await.status.unwrap().phase,
                PlanPhase::Approved
            );
        }
        let actionable: Vec<_> = s
            .plans_of(POLICY)
            .await
            .into_iter()
            .filter(is_actionable)
            .collect();
        assert_eq!(
            actionable.len(),
            1,
            "one actionable plan beside the rejected one"
        );
        assert!(s.is_member("pln_member", "pln_group").await);

        // Restoring the authority applies the waiting plan. The denied plan
        // stays denied.
        s.sql("GRANT pln_grantor TO pln_executor WITH INHERIT TRUE, SET FALSE;")
            .await;
        s.reconcile(POLICY).await;
        s.wait_policy_ready(POLICY, "True", "Reconciled").await;
        s.wait_plan_phase(&replacement, PlanPhase::Applied).await;
        assert_eq!(
            s.plan(&denied).await.status.unwrap().phase,
            PlanPhase::Rejected
        );
        assert!(!s.is_member("pln_member", "pln_group").await);
    })
    .await;
}
