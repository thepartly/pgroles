//! Candidate previews and executor authority: a preview reports what the
//! parent's executor could not run, keeps the review either way, says what
//! state it was computed against, and is withdrawn — never left stale — when
//! the parent cannot be evaluated.

use kube::ResourceExt;
use kube::api::{Patch, PatchParams};
use pgroles_operator::crd::{
    CandidateExecutionPreflight, CandidatePhase, ExecutionEligibility, ExecutionGuard,
    ParentEvaluationState, PlanPhase, PostgresPolicyCandidate,
};
use serde_json::{Value, json};

use crate::harness::{Decision, Scenario, candidate_plan, current_plan, ready_message, scenario};

const POLICY: &str = "candidate-authority-policy";
const PREVIEW: &str = "candidate-authority-preview";
const EXECUTOR_SECRET: &str = "candidate-authority-credentials";

fn preflight(candidate: &PostgresPolicyCandidate) -> Option<&CandidateExecutionPreflight> {
    candidate.status.as_ref()?.execution_preflight.as_ref()
}

fn roles(names: &[&str]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|name| json!({"name": name, "external": true}))
            .collect(),
    )
}

/// The parent's content. `member_inherit` is the option it declares for
/// cau_member's edge; `None` drops the member, which needs a revoke the
/// executor may not be able to run.
fn content(member_inherit: Option<bool>) -> Value {
    let mut members = vec![json!({"name": "cau_grantor", "admin": true})];
    if let Some(inherit) = member_inherit {
        members.push(json!({"name": "cau_member", "inherit": inherit}));
    }
    json!({
        "roles": roles(&["cau_group", "cau_member", "cau_grantor"]),
        "memberships": [{"role": "cau_group", "exclusive": true, "members": members}],
    })
}

/// The result names the parent generation and state it was computed against.
async fn assert_evaluated_against(s: &Scenario, candidate: &str, state: ParentEvaluationState) {
    let generation = s.policies().get(POLICY).await.unwrap().metadata.generation;
    let current = s.candidate(candidate).await;
    let result = preflight(&current).expect("a current preflight result");
    assert_eq!(result.parent_state, state);
    assert_eq!(result.parent_generation, generation);
    assert!(!result.evaluated_at.is_empty());
}

/// Wait for a fresh, eligible preview of the unchanged review.
async fn assert_fresh(s: &Scenario, plan: &str, sql: &str) {
    s.reconcile(POLICY).await;
    s.wait_policy_ready(POLICY, "True", "Reconciled").await;
    let preview = s.wait_candidate_ready(PREVIEW, "True", "Planned").await;
    assert_eq!(
        preflight(&preview).unwrap().eligibility,
        ExecutionEligibility::NoKnownBlockers
    );
    assert_evaluated_against(s, PREVIEW, ParentEvaluationState::Converged).await;
    assert_review_unchanged(s, plan, sql).await;
}

async fn assert_review_unchanged(s: &Scenario, plan: &str, sql: &str) {
    assert_eq!(
        candidate_plan(&s.candidate(PREVIEW).await).as_deref(),
        Some(plan)
    );
    assert_eq!(s.plan_sql(plan).await, sql);
    assert!(s.is_member("cau_member", "cau_group").await);
}

/// A parent that cannot be evaluated withdraws the result through status
/// alone, keeping the review, and a further reconcile in that state writes
/// nothing to the candidate.
async fn assert_withdrawn_while(s: &Scenario, plan: &str, sql: &str) {
    s.reconcile(POLICY).await;
    let preview = s
        .wait_candidate_ready(PREVIEW, "False", "BlockedByActivePolicy")
        .await;
    assert!(preflight(&preview).is_none(), "the old result is withdrawn");
    assert_review_unchanged(s, plan, sql).await;
    let version = s.candidate(PREVIEW).await.resource_version();
    s.reconcile(POLICY).await;
    assert_eq!(s.candidate(PREVIEW).await.resource_version(), version);
}

#[tokio::test]
async fn candidate_previews_report_executor_authority_against_the_state_they_used() {
    scenario(|s| async move {
        s.owns_roles(&[
            "cau_group", "cau_member", "cau_grantor", "cau_executor", "cau_repair", "cat_group",
            "cat_member", "cat_grantor",
        ]);
        s.sql(
            "CREATE ROLE cau_group; CREATE ROLE cau_member; CREATE ROLE cau_grantor;
             CREATE ROLE cau_executor LOGIN PASSWORD 'cau-test-password';
             CREATE ROLE cau_repair;
             GRANT cau_group TO cau_grantor WITH ADMIN TRUE;
             GRANT cau_group TO cau_member WITH INHERIT FALSE, SET FALSE GRANTED BY cau_grantor;
             GRANT cau_repair TO cau_executor WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;",
        )
        .await;
        s.database_secret(EXECUTOR_SECRET, "cau_executor", "cau-test-password")
            .await;
        let mut spec = content(Some(false));
        spec["connection"] = json!({"secretRef": {"name": EXECUTOR_SECRET}});
        spec["interval"] = json!("1h");
        spec["mode"] = json!("apply");
        spec["approval"] = json!("auto");
        s.create_policy(POLICY, spec).await;
        s.wait_policy_ready(POLICY, "True", "Reconciled").await;

        // The executor cannot revoke an edge cau_grantor granted. The preview
        // says so, and keeps the SQL for review.
        s.create_candidate(PREVIEW, POLICY, content(None), None).await;
        let preview = s
            .wait_candidate_ready(PREVIEW, "False", "ExecutionBlocked")
            .await;
        let status = preview.status.as_ref().unwrap();
        assert_eq!(status.phase, CandidatePhase::Planned);
        let result = preflight(&preview).unwrap();
        assert_eq!(result.eligibility, ExecutionEligibility::Blocked);
        assert_eq!(result.issues[0].guard, ExecutionGuard::ExecutorAuthority);
        assert_eq!(result.issues[0].code, "ForeignGrantorMembershipRevoke");
        assert!(ready_message(&preview).contains("cau_grantor"));
        let plan = candidate_plan(&preview).expect("the review SQL is kept");
        let sql = s.plan_sql(&plan).await;
        assert!(sql.contains(r#"REVOKE "cau_group" FROM "cau_member" GRANTED BY "cau_grantor";"#));
        assert!(s.is_member("cau_member", "cau_group").await);

        // An override target keeps its own executor even at the same endpoint:
        // a privileged override is not judged by the ordinary parent's pool…
        s.create_candidate(
            "candidate-authority-privileged-override",
            POLICY,
            content(None),
            Some("postgres-credentials"),
        )
        .await;
        let privileged = s
            .wait_candidate_ready("candidate-authority-privileged-override", "True", "Planned")
            .await;
        assert_eq!(
            preflight(&privileged).unwrap().eligibility,
            ExecutionEligibility::NoKnownBlockers
        );
        s.delete_candidate("candidate-authority-privileged-override")
            .await;

        // …and a privileged parent does not lend its authority to an ordinary
        // override.
        s.sql(
            "CREATE ROLE cat_group; CREATE ROLE cat_member; CREATE ROLE cat_grantor;
             GRANT cat_group TO cat_grantor WITH ADMIN TRUE;
             GRANT cat_group TO cat_member WITH INHERIT FALSE, SET FALSE GRANTED BY cat_grantor;",
        )
        .await;
        let cat_content = |with_member: bool| {
            let mut members = vec![json!({"name": "cat_grantor", "admin": true})];
            if with_member {
                members.push(json!({"name": "cat_member", "inherit": false}));
            }
            json!({
                "roles": roles(&["cat_group", "cat_member", "cat_grantor"]),
                "memberships": [{"role": "cat_group", "exclusive": true, "members": members}],
            })
        };
        let mut root = cat_content(true);
        root["connection"] = json!({"secretRef": {"name": "postgres-credentials"}});
        root["interval"] = json!("1h");
        root["mode"] = json!("apply");
        root["approval"] = json!("auto");
        s.create_policy("candidate-authority-root-parent", root).await;
        s.wait_policy_ready("candidate-authority-root-parent", "True", "Reconciled")
            .await;
        s.create_candidate(
            "candidate-authority-ordinary-override",
            "candidate-authority-root-parent",
            cat_content(false),
            Some(EXECUTOR_SECRET),
        )
        .await;
        let ordinary = s
            .wait_candidate_ready("candidate-authority-ordinary-override", "False", "ExecutionBlocked")
            .await;
        let message = &preflight(&ordinary).unwrap().issues[0].message;
        assert!(message.contains("cau_executor") && message.contains("cat_grantor"), "{message}");
        s.delete_candidate("candidate-authority-ordinary-override").await;
        s.delete_policy("candidate-authority-root-parent").await;

        // Granting the authority makes the same review eligible, without
        // executing it.
        s.sql("GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;")
            .await;
        assert_fresh(&s, &plan, &sql).await;
        assert!(preflight(&s.candidate(PREVIEW).await).unwrap().issues.is_empty());

        // A suspended parent never enters planning, so the result is withdrawn.
        s.patch_policy_spec(POLICY, json!({"suspend": true})).await;
        assert_withdrawn_while(&s, &plan, &sql).await;
        s.patch_policy_spec(POLICY, json!({"suspend": false})).await;
        assert_fresh(&s, &plan, &sql).await;

        // So is one that cannot connect.
        s.patch_policy_spec(
            POLICY,
            json!({"connection": {"secretRef": {"name": "candidate-authority-missing"}}}),
        )
        .await;
        assert_withdrawn_while(&s, &plan, &sql).await;
        s.patch_policy_spec(
            POLICY,
            json!({"connection": {"secretRef": {"name": EXECUTOR_SECRET}}}),
        )
        .await;
        assert_fresh(&s, &plan, &sql).await;

        // Losing grantor authority blocks the parent's own option change.
        // None of its plan ran, so candidates are still planned, against the
        // unchanged database, and say so.
        s.sql(
            "REVOKE cau_grantor FROM cau_executor GRANTED BY postgres;
             GRANT cau_group TO cau_member WITH INHERIT TRUE GRANTED BY cau_grantor;",
        )
        .await;
        s.reconcile(POLICY).await;
        let blocked = s
            .wait_policy_ready(POLICY, "False", "ExecutorAuthority")
            .await;
        let parent_plan = current_plan(&blocked).unwrap();
        s.wait_plan_phase(&parent_plan, PlanPhase::Pending).await;
        let preview = s
            .wait_candidate_ready(PREVIEW, "False", "ExecutionBlocked")
            .await;
        assert_eq!(
            preflight(&preview).unwrap().eligibility,
            ExecutionEligibility::Blocked
        );
        assert_evaluated_against(&s, PREVIEW, ParentEvaluationState::ExecutionBlocked).await;
        assert_review_unchanged(&s, &plan, &sql).await;

        // A repair keeps the live INHERIT option rather than rewriting an
        // edge the executor cannot touch, and adds a grant it can make. It is
        // eligible while the policy it repairs is still degraded.
        let mut repair = content(Some(true));
        repair["roles"] = roles(&["cau_group", "cau_member", "cau_grantor", "cau_repair"]);
        repair["memberships"]
            .as_array_mut()
            .unwrap()
            .push(json!({"role": "cau_repair", "members": [{"name": "cau_member"}]}));
        s.create_candidate("candidate-authority-repair", POLICY, repair, None)
            .await;
        let repaired = s
            .wait_candidate_ready("candidate-authority-repair", "True", "Planned")
            .await;
        assert_eq!(
            preflight(&repaired).unwrap().eligibility,
            ExecutionEligibility::NoKnownBlockers
        );
        assert_evaluated_against(&s, "candidate-authority-repair", ParentEvaluationState::ExecutionBlocked)
            .await;
        assert!(ready_message(&repaired).contains("replaces the blocked content"));
        let repair_sql = s.plan_sql(&candidate_plan(&repaired).unwrap()).await;
        assert!(repair_sql.contains(r#"GRANT "cau_repair" TO "cau_member""#));
        assert!(!repair_sql.contains("REVOKE"));
        // Previewing executed nothing; the parent is still blocked.
        assert!(!s.is_member("cau_member", "cau_repair").await);
        assert_eq!(
            s.plan(&parent_plan).await.status.unwrap().phase,
            PlanPhase::Pending
        );
        s.delete_candidate("candidate-authority-repair").await;

        // Restoring the authority applies the parent's own waiting plan.
        s.sql("GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;")
            .await;
        assert_fresh(&s, &plan, &sql).await;
        s.wait_plan_phase(&parent_plan, PlanPhase::Applied).await;

        // A stale status snapshot cannot reopen a superseded or promoted
        // candidate: the operator's guarded write is rejected by the API
        // server, and its next reconcile leaves the terminal state alone.
        for terminal in [CandidatePhase::Superseded, CandidatePhase::Promoted] {
            let race = format!("candidate-authority-cas-{}", format!("{terminal:?}").to_lowercase());
            s.create_candidate(&race, POLICY, content(None), None).await;
            s.reconcile(POLICY).await;
            let planned = s.wait_candidate_ready(&race, "True", "Planned").await;
            let race_plan = candidate_plan(&planned).unwrap();
            s.decide(&race_plan, Decision::Approve).await;
            let before = s.candidate(&race).await;
            s.candidates()
                .patch_status(
                    &race,
                    &PatchParams::default(),
                    &Patch::Merge(json!({"status": {"phase": terminal, "executionPreflight": null}})),
                )
                .await
                .unwrap();
            let mut stale = serde_json::to_value(before.status.unwrap()).unwrap();
            stale["phase"] = json!(CandidatePhase::Planned);
            stale.as_object_mut().unwrap().remove("executionPreflight");
            let guarded: json_patch::Patch = serde_json::from_value(json!([
                {"op": "test", "path": "/metadata/uid", "value": before.metadata.uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": before.metadata.resource_version},
                {"op": "add", "path": "/status", "value": stale},
            ]))
            .unwrap();
            assert!(
                s.candidates()
                    .patch_status(&race, &PatchParams::default(), &Patch::<()>::Json(guarded))
                    .await
                    .is_err(),
                "a stale write must not restore a {terminal:?} candidate"
            );
            s.reconcile(POLICY).await;
            let after = s.candidate(&race).await;
            assert_eq!(after.status.unwrap().phase, terminal);
            let approved = s.plan(&race_plan).await.status.unwrap().conditions;
            assert!(approved.iter().any(|c| c.condition_type == "Approved" && c.status == "True"));
            s.delete_candidate(&race).await;
        }
    })
    .await;
}
