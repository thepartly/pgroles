//! A reconcile that finds nothing left to change retires every live plan of
//! the policy's own, not only the one its reference names. A plan nothing
//! references is otherwise never collected, and the candidate gate counts it
//! as a decision still outstanding while the policy reports InSync.

use pgroles_operator::crd::PlanPhase;
use serde_json::json;

use crate::harness::scenario;

const POLICY: &str = "plan-cleanup-policy";

#[tokio::test]
async fn converging_retires_unreferenced_live_plans() {
    scenario(|s| async move {
        s.owns_roles(&["pcl_reader"]);
        s.create_policy(
            POLICY,
            json!({
                "connection": {"secretRef": {"name": "postgres-credentials"}},
                "interval": "1h",
                "mode": "observe",
                "roles": [{"name": "pcl_reader", "login": false}],
            }),
        )
        .await;

        // The missing role is drift, and the policy references a plan for it.
        let referenced = s.wait_current_plan(POLICY, |_| true).await;
        let original = s.wait_plan_phase(&referenced, PlanPhase::Pending).await;

        // The drift is resolved out of band, so the next reconcile finds
        // nothing to change. It is resolved first: a reconcile that still saw
        // drift could retire the copy below through plan reuse, and the check
        // would prove nothing about the converged path.
        s.sql("CREATE ROLE pcl_reader NOLOGIN;").await;

        // An Approved copy nothing references: what 0.13 left behind when it
        // approved auto-apply plans it could not execute.
        let stray = "plan-cleanup-stray";
        s.duplicate_plan(&original, stray).await;
        s.set_plan_phase(stray, PlanPhase::Approved).await;
        s.reconcile(POLICY).await;

        s.wait_plan_phase(&referenced, PlanPhase::Superseded).await;
        s.wait_plan_phase(stray, PlanPhase::Superseded).await;
        let live: Vec<String> = s
            .plans_of(POLICY)
            .await
            .into_iter()
            .filter(|plan| {
                plan.status.as_ref().is_some_and(|status| {
                    matches!(status.phase, PlanPhase::Pending | PlanPhase::Approved)
                })
            })
            .map(|plan| plan.metadata.name.unwrap_or_default())
            .collect();
        assert!(live.is_empty(), "live plans left behind: {live:?}");
    })
    .await;
}
