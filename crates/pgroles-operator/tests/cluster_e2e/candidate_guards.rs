//! Candidate previews and the policy guards apply runs besides executor
//! authority: the adopt-mode schema ownership refusal and role-drop safety.
//! A preview is evaluated with its parent's current execution settings, so it
//! reports what promoting it would meet.

use pgroles_operator::crd::{
    CandidateExecutionPreflight, ExecutionEligibility, ExecutionGuard, ParentEvaluationState,
    PlanPhase, PostgresPolicyCandidate,
};
use serde_json::{Value, json};

use crate::harness::{Decision, candidate_plan, ready_message, scenario};

fn preflight(candidate: &PostgresPolicyCandidate) -> Option<&CandidateExecutionPreflight> {
    candidate.status.as_ref()?.execution_preflight.as_ref()
}

fn guards(candidate: &PostgresPolicyCandidate) -> Vec<ExecutionGuard> {
    preflight(candidate)
        .map(|result| result.issues.iter().map(|issue| issue.guard).collect())
        .unwrap_or_default()
}

fn with_execution(mut content: Value, mode: &str) -> Value {
    content["connection"] = json!({"secretRef": {"name": "postgres-credentials"}});
    content["interval"] = json!("1h");
    content["mode"] = json!(mode);
    content["approval"] = json!("auto");
    content
}

const OWNERSHIP: &str = "candidate-ownership-policy";

/// Adopt-mode content declaring `owner` for cow_workspace, and optionally a
/// membership unrelated to the schema.
fn ownership(owner: &str, with_membership: bool) -> Value {
    let roles: Vec<Value> = ["cow_live_owner", "cow_new_owner", "cow_group", "cow_member"]
        .iter()
        .map(|name| json!({"name": name, "external": true}))
        .collect();
    let mut content = json!({
        "reconciliation_mode": "adopt",
        "roles": roles,
        "schemas": [{"name": "cow_workspace", "owner": owner}],
    });
    if with_membership {
        content["memberships"] =
            json!([{"role": "cow_group", "members": [{"name": "cow_member"}]}]);
    }
    content
}

#[tokio::test]
async fn previews_follow_the_parents_schema_ownership_guard() {
    scenario(|s| async move {
        s.owns_schemas(&["cow_workspace"]);
        s.owns_roles(&["cow_live_owner", "cow_new_owner", "cow_group", "cow_member"]);
        s.sql(
            "CREATE ROLE cow_live_owner; CREATE ROLE cow_new_owner; CREATE ROLE cow_group;
             CREATE ROLE cow_member; CREATE SCHEMA cow_workspace AUTHORIZATION cow_live_owner;",
        )
        .await;
        let schema_owner =
            "SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'cow_workspace'";
        // The superuser connection keeps executor authority out of the
        // picture: the ownership refusal is the only guard in play.
        s.create_policy(
            OWNERSHIP,
            with_execution(ownership("cow_live_owner", false), "apply"),
        )
        .await;
        s.wait_policy_ready(OWNERSHIP, "True", "Reconciled").await;

        // A proposal that transfers the schema and adds an unrelated
        // membership is blocked before it merges, against a parent that does
        // not allow transfers.
        let transfer = "candidate-ownership-transfer";
        s.create_candidate(transfer, OWNERSHIP, ownership("cow_new_owner", true), None)
            .await;
        let blocked = s
            .wait_candidate_ready(transfer, "False", "ExecutionBlocked")
            .await;
        assert_eq!(guards(&blocked), vec![ExecutionGuard::SchemaOwnerTransfer]);
        assert!(
            preflight(&blocked).unwrap().issues[0]
                .message
                .contains("cow_workspace")
        );
        assert_eq!(
            preflight(&blocked).unwrap().parent_state,
            ParentEvaluationState::Converged
        );
        let review = candidate_plan(&blocked).unwrap();
        assert!(
            s.plan_sql(&review)
                .await
                .contains(r#"ALTER SCHEMA "cow_workspace" OWNER TO "cow_new_owner""#)
        );

        // The allowance is a parent setting, outside the content and its
        // digest: changing it re-evaluates the same review in both
        // directions.
        s.patch_policy_spec(OWNERSHIP, json!({"allow_schema_owner_transfers": true}))
            .await;
        s.reconcile(OWNERSHIP).await;
        let allowed = s.wait_candidate_ready(transfer, "True", "Planned").await;
        assert_eq!(
            preflight(&allowed).unwrap().eligibility,
            ExecutionEligibility::NoKnownBlockers
        );
        assert_eq!(candidate_plan(&allowed).as_deref(), Some(review.as_str()));
        s.patch_policy_spec(OWNERSHIP, json!({"allow_schema_owner_transfers": false}))
            .await;
        s.reconcile(OWNERSHIP).await;
        s.wait_candidate_ready(transfer, "False", "ExecutionBlocked")
            .await;

        // An observe-mode parent executes nothing and refuses no transfer, so
        // its preview passes; switching to apply re-evaluates and blocks.
        s.patch_policy_spec(OWNERSHIP, json!({"mode": "observe"}))
            .await;
        s.reconcile(OWNERSHIP).await;
        let observed = s.wait_candidate_ready(transfer, "True", "Planned").await;
        assert!(guards(&observed).is_empty());
        s.patch_policy_spec(OWNERSHIP, json!({"mode": "apply"}))
            .await;
        s.reconcile(OWNERSHIP).await;
        let applying = s
            .wait_candidate_ready(transfer, "False", "ExecutionBlocked")
            .await;
        assert_eq!(
            preflight(&applying).unwrap().parent_generation,
            s.policies()
                .get(OWNERSHIP)
                .await
                .unwrap()
                .metadata
                .generation
        );

        // Approving the review does not bypass the guard: merging the
        // content stops the whole policy, the unrelated membership with it,
        // and nothing runs.
        s.decide(&review, Decision::Approve).await;
        s.patch_policy_spec(OWNERSHIP, ownership("cow_new_owner", true))
            .await;
        s.wait_policy_ready(OWNERSHIP, "False", "OwnerTransferBlocked")
            .await;
        assert_eq!(s.query_text(schema_owner).await, "cow_live_owner");
        assert!(!s.is_member("cow_member", "cow_group").await);
        assert_ne!(
            s.plan(&review).await.status.unwrap().phase,
            PlanPhase::Applied
        );
        s.delete_candidate(transfer).await;

        // A repair keeps the live owner and the membership. It is previewed
        // while the policy is blocked, against the unchanged database.
        let repair = "candidate-ownership-repair";
        s.create_candidate(repair, OWNERSHIP, ownership("cow_live_owner", true), None)
            .await;
        s.reconcile(OWNERSHIP).await;
        let repaired = s.wait_candidate_ready(repair, "True", "Planned").await;
        let result = preflight(&repaired).unwrap();
        assert_eq!(result.eligibility, ExecutionEligibility::NoKnownBlockers);
        assert_eq!(result.parent_state, ParentEvaluationState::ExecutionBlocked);
        assert!(ready_message(&repaired).contains("replaces the blocked content"));
        let repair_sql = s.plan_sql(&candidate_plan(&repaired).unwrap()).await;
        assert!(repair_sql.contains(r#"GRANT "cow_group" TO "cow_member""#));
        assert!(!repair_sql.contains("ALTER SCHEMA"));
        assert!(!s.is_member("cow_member", "cow_group").await);

        // Once the membership exists, the repair has nothing left to review,
        // and its earlier result about executing SQL is withdrawn.
        s.sql("GRANT cow_group TO cow_member;").await;
        s.reconcile(OWNERSHIP).await;
        let settled = s.wait_candidate_ready(repair, "True", "NoEffects").await;
        assert!(preflight(&settled).is_none());
        s.delete_candidate(repair).await;

        // Merging the repair converges, and the schema keeps its owner.
        s.patch_policy_spec(OWNERSHIP, ownership("cow_live_owner", true))
            .await;
        s.wait_policy_ready(OWNERSHIP, "True", "Reconciled").await;
        assert_eq!(s.query_text(schema_owner).await, "cow_live_owner");
    })
    .await;
}

const DROPS: &str = "candidate-drop-policy";

/// Content keeping cdr_keep and retiring cdr_retired, with or without the
/// cleanup its owned objects need.
fn retiring(with_cleanup: bool) -> Value {
    let mut retirement = json!({"role": "cdr_retired"});
    if with_cleanup {
        retirement["reassign_owned_to"] = json!("cdr_keep");
        retirement["drop_owned"] = json!(true);
    }
    json!({"roles": [{"name": "cdr_keep"}], "retirements": [retirement]})
}

#[tokio::test]
async fn previews_report_unsafe_role_drops_and_preview_the_repair() {
    scenario(|s| async move {
        s.owns_schemas(&["cdr_space"]);
        s.owns_roles(&["cdr_keep", "cdr_retired"]);
        s.sql(
            "CREATE ROLE cdr_keep; CREATE ROLE cdr_retired;
             CREATE SCHEMA cdr_space;
             CREATE TABLE cdr_space.records (id int);
             ALTER TABLE cdr_space.records OWNER TO cdr_retired;",
        )
        .await;
        s.create_policy(
            DROPS,
            with_execution(json!({"roles": [{"name": "cdr_keep"}]}), "apply"),
        )
        .await;
        s.wait_policy_ready(DROPS, "True", "Reconciled").await;
        let table_owner =
            "SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE oid = 'cdr_space.records'::regclass";

        // Retiring a role that still owns a table, with no cleanup, is a drop
        // apply refuses.
        let unsafe_drop = "candidate-drop-unsafe";
        s.create_candidate(unsafe_drop, DROPS, retiring(false), None).await;
        let blocked = s.wait_candidate_ready(unsafe_drop, "False", "ExecutionBlocked").await;
        assert_eq!(guards(&blocked), vec![ExecutionGuard::RoleDropSafety]);
        let issue = &preflight(&blocked).unwrap().issues[0];
        assert_eq!(issue.code, "UnsafeRoleDrop");
        assert!(issue.message.contains("cdr_retired"), "{}", issue.message);

        // Merging it blocks the policy before anything runs.
        s.patch_policy_spec(DROPS, retiring(false)).await;
        s.wait_policy_ready(DROPS, "False", "UnsafeRoleDrops").await;
        assert_eq!(s.query_text(table_owner).await, "cdr_retired");
        s.delete_candidate(unsafe_drop).await;

        // The retirement that reassigns and drops the owned objects is
        // eligible, previewed against the blocked policy.
        let repair = "candidate-drop-repair";
        s.create_candidate(repair, DROPS, retiring(true), None).await;
        s.reconcile(DROPS).await;
        let repaired = s.wait_candidate_ready(repair, "True", "Planned").await;
        let result = preflight(&repaired).unwrap();
        assert_eq!(result.eligibility, ExecutionEligibility::NoKnownBlockers);
        assert_eq!(result.parent_state, ParentEvaluationState::ExecutionBlocked);
        let repair_sql = s.plan_sql(&candidate_plan(&repaired).unwrap()).await;
        assert!(repair_sql.contains(r#"REASSIGN OWNED BY "cdr_retired" TO "cdr_keep""#));
        // Previewing ran none of that cleanup.
        assert_eq!(s.query_text(table_owner).await, "cdr_retired");
        s.delete_candidate(repair).await;

        s.patch_policy_spec(DROPS, retiring(true)).await;
        s.wait_policy_ready(DROPS, "True", "Reconciled").await;
        assert!(
            !s.query_bool("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdr_retired')")
                .await
        );
    })
    .await;
}
