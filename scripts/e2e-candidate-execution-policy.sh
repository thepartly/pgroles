#!/usr/bin/env bash
# Runs only against the disposable plan-lifecycle E2E fixture.
set -Eeuo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
if [ -n "${PGROLES_TEST_PG_CONTAINER:-}" ]; then
  pg_query() { docker exec "$PGROLES_TEST_PG_CONTAINER" psql -U postgres -d pgroles_test -tAc "$1"; }
fi
cleanup() {
  kubectl delete pgcand execution-policy-preview execution-policy-repair execution-policy-noop \
    execution-policy-drop execution-policy-cleanup execution-policy-manual --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete pgr execution-policy-parent execution-policy-manual-parent --ignore-not-found --wait=true >/dev/null 2>&1 || true
  pg_query 'DROP SCHEMA IF EXISTS evp_space CASCADE; DROP SCHEMA IF EXISTS evp_archive CASCADE;
    DROP ROLE IF EXISTS evp_owner_a; DROP ROLE IF EXISTS evp_owner_b;
    DROP ROLE IF EXISTS evp_reader; DROP ROLE IF EXISTS evp_retired;
    DROP ROLE IF EXISTS evp_manual_reader; DROP ROLE IF EXISTS evp_manual_anchor;' >/dev/null 2>&1 || true
}
trap cleanup EXIT
failure_details() {
  printf '::error::Execution-policy scenario failed at line %s\n' "$1" >&2
  kubectl get pgr execution-policy-parent execution-policy-manual-parent -o yaml >&2 || true
  kubectl get pgcand execution-policy-preview execution-policy-repair execution-policy-noop \
    execution-policy-drop execution-policy-cleanup execution-policy-manual -o yaml >&2 || true
}
trap 'failure_details "$LINENO"' ERR
# Require an answer for the current parent generation. Waiting only for Ready
# would accept the status from before a flag-only edit.
wait_for_policy_result() {
  local candidate="$1" eligibility="$2" state="$3" parent="${4:-execution-policy-parent}"
  for attempt in $(seq 1 30); do
    if kubectl get pgcand "$candidate" -o json | python3 -c '
import json, sys
c=json.load(sys.stdin); p=c.get("status",{}).get("executionPreflight",{})
sys.exit(0 if p.get("eligibility")==sys.argv[1] and p.get("parentState")==sys.argv[2]
    and p.get("parentGeneration")==int(sys.argv[3]) and p.get("evaluatedAt") else 1)
' "$eligibility" "$state" "$(kubectl get pgr "$parent" -o jsonpath='{.metadata.generation}')"; then return 0; fi
    sleep 2
  done
  kubectl get pgcand "$candidate" -o yaml
  return 1
}
assert_owner_unchanged() {
  test "$(pg_query "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='evp_space';")" = evp_owner_a
}
pg_query 'CREATE ROLE evp_owner_a; CREATE ROLE evp_owner_b;
  CREATE ROLE evp_retired; CREATE SCHEMA evp_space AUTHORIZATION evp_owner_a;
  CREATE SCHEMA evp_archive AUTHORIZATION evp_retired;'
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: execution-policy-parent}
spec:
  connection: {secretRef: {name: postgres-credentials}}
  interval: 2s
  mode: apply
  approval: auto
  reconciliation_mode: adopt
  roles:
    - {name: evp_owner_a, external: true}
    - {name: evp_owner_b, external: true}
  schemas: [{name: evp_space, owner: evp_owner_a}]
YAML
wait_for_ready_status_reason execution-policy-parent True Reconciled
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-preview}
spec:
  policyRef: {name: execution-policy-parent}
  content:
    reconciliation_mode: adopt
    roles:
      - {name: evp_owner_a, external: true}
      - {name: evp_owner_b, external: true}
    schemas: [{name: evp_space, owner: evp_owner_b}]
YAML
wait_for_candidate_condition execution-policy-preview Ready False ExecutionBlocked
wait_for_policy_result execution-policy-preview Blocked Converged
test "$(kubectl get pgcand execution-policy-preview -o jsonpath='{.status.executionPreflight.issues[0].code}')" = AdoptSchemaOwnerTransfer
test "$(kubectl get pgcand execution-policy-preview -o jsonpath='{.status.executionPreflight.issues[*].guard}')" = SchemaOwnerTransfer
test "$(kubectl get pgcand execution-policy-preview -o jsonpath='{.status.phase}')" = Planned
plan="$(wait_for_candidate_plan_ref execution-policy-preview)"
sql="$(get_plan_sql "$plan")"
[[ "$sql" == *'ALTER SCHEMA "evp_space" OWNER TO "evp_owner_b";'* ]]
assert_owner_unchanged
# Observe assesses the parent's current settings and executes nothing. A
# passing observe preview is not apply eligibility: changing mode must produce
# a fresh, blocked result when the transfer allowance remains false.
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"mode":"observe"}}'
wait_for_policy_result execution-policy-preview NoKnownBlockers Converged
wait_for_candidate_condition execution-policy-preview Ready True Planned
test "$(wait_for_candidate_plan_ref execution-policy-preview)" = "$plan"
assert_owner_unchanged
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"mode":"apply"}}'
wait_for_policy_result execution-policy-preview Blocked Converged
wait_for_candidate_condition execution-policy-preview Ready False ExecutionBlocked
test "$(wait_for_candidate_plan_ref execution-policy-preview)" = "$plan"
assert_owner_unchanged
# The allowance stays outside content and SQL/digest. Both enabling and
# withdrawing it must re-evaluate, even after the review has been approved.
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"allow_schema_owner_transfers":true}}'
wait_for_policy_result execution-policy-preview NoKnownBlockers Converged
wait_for_candidate_condition execution-policy-preview Ready True Planned
test "$(wait_for_candidate_plan_ref execution-policy-preview)" = "$plan"
test "$(get_plan_sql "$plan")" = "$sql"
approve_plan "$plan"
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"allow_schema_owner_transfers":false}}'
wait_for_policy_result execution-policy-preview Blocked Converged
wait_for_candidate_condition execution-policy-preview Ready False ExecutionBlocked
test "$(wait_for_candidate_plan_ref execution-policy-preview)" = "$plan"
test "$(get_plan_sql "$plan")" = "$sql"
assert_owner_unchanged
# Promotion of approved content must still stop at the freshly failed guard.
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"schemas":[{"name":"evp_space","owner":"evp_owner_b"}]}}'
wait_for_ready_status_reason execution-policy-parent False OwnerTransferBlocked
wait_for_policy_result execution-policy-preview Blocked ExecutionBlocked
assert_owner_unchanged
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-repair}
spec:
  policyRef: {name: execution-policy-parent}
  content:
    reconciliation_mode: adopt
    roles:
      - {name: evp_owner_a, external: true}
      - {name: evp_owner_b, external: true}
      - {name: evp_reader}
    schemas: [{name: evp_space, owner: evp_owner_a}]
---
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-noop}
spec:
  policyRef: {name: execution-policy-parent}
  content:
    reconciliation_mode: adopt
    roles:
      - {name: evp_owner_a, external: true}
      - {name: evp_owner_b, external: true}
    schemas: [{name: evp_space, owner: evp_owner_a}]
---
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-drop}
spec:
  policyRef: {name: execution-policy-parent}
  content:
    reconciliation_mode: authoritative
    retirements: [{role: evp_retired}]
---
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-cleanup}
spec:
  policyRef: {name: execution-policy-parent}
  content:
    reconciliation_mode: authoritative
    retirements: [{role: evp_retired, reassign_owned_to: postgres, drop_owned: true}]
YAML
wait_for_candidate_condition execution-policy-repair Ready True Planned
wait_for_policy_result execution-policy-repair NoKnownBlockers ExecutionBlocked
test "$(pg_query "SELECT count(*) FROM pg_roles WHERE rolname='evp_reader';")" = 0
# An earlier SQL assessment must disappear when the same immutable proposal
# becomes a no-op after a separate fixture change, then return on fresh drift.
pg_query 'CREATE ROLE evp_reader;'
wait_for_candidate_condition execution-policy-repair Ready True NoEffects
test "$(kubectl get pgcand execution-policy-repair -o jsonpath='{.status.executionPreflight}')" = ''
test "$(kubectl get pgcand execution-policy-repair -o jsonpath='{.status.planRef}')" = ''
pg_query 'DROP ROLE evp_reader;'
wait_for_candidate_condition execution-policy-repair Ready True Planned
wait_for_policy_result execution-policy-repair NoKnownBlockers ExecutionBlocked
wait_for_candidate_condition execution-policy-noop Ready True NoEffects
test "$(kubectl get pgcand execution-policy-noop -o jsonpath='{.status.executionPreflight}')" = ''
test "$(kubectl get pgcand execution-policy-noop -o jsonpath='{.status.planRef}')" = ''
wait_for_candidate_condition execution-policy-drop Ready False ExecutionBlocked
wait_for_policy_result execution-policy-drop Blocked ExecutionBlocked
test "$(kubectl get pgcand execution-policy-drop -o jsonpath='{.status.executionPreflight.issues[0].code}')" = UnsafeRoleDrop
drop_plan="$(wait_for_candidate_plan_ref execution-policy-drop)"
[[ "$(get_plan_sql "$drop_plan")" == *'DROP ROLE IF EXISTS "evp_retired";'* ]]
wait_for_candidate_condition execution-policy-cleanup Ready True Planned
wait_for_policy_result execution-policy-cleanup NoKnownBlockers ExecutionBlocked
test "$(pg_query "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='evp_archive';")" = evp_retired
wait_for_ready_status_reason execution-policy-parent False OwnerTransferBlocked
# Unavailable evaluation must clear both results, retaining the review.
kubectl patch pgr execution-policy-parent --type=merge -p='{"spec":{"suspend":true}}'
wait_for_candidate_condition execution-policy-repair Ready False BlockedByActivePolicy
test "$(kubectl get pgcand execution-policy-repair -o jsonpath='{.status.executionPreflight}')" = ''
test -n "$(wait_for_candidate_plan_ref execution-policy-repair)"

# Manual approval must adopt the reviewed candidate plan, rather than silently
# authorizing a separately generated ordinary policy plan. Use a disjoint
# fixture scope so prior blocked proposals cannot be mistaken for promotion.
pg_query 'CREATE ROLE evp_manual_anchor;'
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: execution-policy-manual-parent}
spec:
  connection: {secretRef: {name: postgres-credentials}}
  interval: 2s
  mode: apply
  approval: manual
  reconciliation_mode: adopt
  roles: [{name: evp_manual_anchor, external: true}]
YAML
wait_for_ready_status_reason execution-policy-manual-parent True Reconciled
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: execution-policy-manual}
spec:
  policyRef: {name: execution-policy-manual-parent}
  content:
    reconciliation_mode: adopt
    roles:
      - {name: evp_manual_anchor, external: true}
      - {name: evp_manual_reader}
YAML
wait_for_candidate_condition execution-policy-manual Ready True Planned
wait_for_policy_result execution-policy-manual NoKnownBlockers Converged execution-policy-manual-parent
manual_plan="$(wait_for_candidate_plan_ref execution-policy-manual)"
approve_plan "$manual_plan"
test "$(pg_query "SELECT count(*) FROM pg_roles WHERE rolname='evp_manual_reader';")" = 0
kubectl patch pgr execution-policy-manual-parent --type=merge -p='{"spec":{"roles":[{"name":"evp_manual_anchor","external":true},{"name":"evp_manual_reader"}]}}'
wait_for_plan_phase "$manual_plan" Applied
wait_for_candidate_phase execution-policy-manual Promoted
wait_for_ready_status_reason execution-policy-manual-parent True Reconciled
test "$(kubectl get pgr execution-policy-manual-parent -o jsonpath='{.status.current_plan_ref.name}')" = "$manual_plan"
test "$(kubectl get pgcand execution-policy-manual -o jsonpath='{.status.executionPreflight}')" = ''
test "$(pg_query "SELECT count(*) FROM pg_roles WHERE rolname='evp_manual_reader';")" = 1
