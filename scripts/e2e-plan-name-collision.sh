#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
policy=plan-name-collision
role=plan_name_collision_user
cleanup() {
  set_operator_env PGROLES_E2E_FREEZE_PLAN_NAME_FOR- || true
  kubectl delete pgr "$policy" --ignore-not-found --wait=true >/dev/null || true
  pg_query "DROP ROLE IF EXISTS $role" >/dev/null || true
}
trap cleanup EXIT
set_operator_env PGROLES_E2E_FREEZE_PLAN_NAME_FOR="$policy"
kubectl apply -f - <<YAML
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: $policy
spec:
  connection:
    secretRef:
      name: postgres-credentials
  interval: 5s
  mode: apply
  approval: manual
  roles:
    - name: $role
      login: true
YAML
wait_for_ready_status_reason "$policy" True Planned
first=$(wait_for_current_plan_ref "$policy")
case "$first" in *-20000101-000000-*) ;; *) echo '::error::test clock hook is missing'; exit 1;; esac
reject_plan "$first"
wait_for_plan_phase "$first" Rejected
wait_for_ready_status_reason "$policy" False PlanNameCollision
# A collision must not be reported as a successful replacement or repoint to
# the rejected object. The terminal decision remains intact.
reference=$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}')
test -z "$reference"
wait_for_plan_phase "$first" Rejected
assert_role_absent "$role"
set_operator_env PGROLES_E2E_FREEZE_PLAN_NAME_FOR-
wait_for_ready_status_reason "$policy" True Planned
fresh=$(wait_for_current_plan_ref "$policy")
test "$fresh" != "$first"
wait_for_plan_phase "$fresh" Pending
approve_plan "$fresh"
wait_for_plan_phase "$fresh" Applied
assert_role_exists "$role"
wait_for_plan_phase "$first" Rejected
