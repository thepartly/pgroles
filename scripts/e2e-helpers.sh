#!/usr/bin/env bash
# Shared helper functions for E2E test suites.
# Source this file at the start of each E2E test step:
#   source scripts/e2e-helpers.sh
set -euo pipefail

# -- Policy status helpers ----------------------------------------------------

wait_for_ready_true() {
  local policy="$1"
  local attempts="${2:-30}"
  local sleep_secs="${3:-3}"
  for i in $(seq 1 "$attempts"); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    if [ "$status" = "True" ]; then
      echo "$policy reached Ready=True"
      return 0
    fi
    echo "Waiting for $policy Ready=True... (attempt $i/$attempts)"
    sleep "$sleep_secs"
  done
  echo "::error::$policy did not reach Ready=True"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_ready_status_reason() {
  local policy="$1"
  local expected_status="$2"
  local expected_reason="$3"
  for i in $(seq 1 30); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
    reason="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}' 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ] && [ "$reason" = "$expected_reason" ]; then
      echo "$policy reached Ready=$expected_status with reason=$expected_reason"
      return 0
    fi
    echo "Waiting for $policy Ready=$expected_status/$expected_reason... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not reach Ready=$expected_status with reason=$expected_reason"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_ready_reason() {
  local policy="$1"
  local expected_reason="$2"
  wait_for_ready_status_reason "$policy" "False" "$expected_reason"
}

# Empty output means the condition is absent, so a failed read must be a
# non-zero exit rather than empty output — otherwise a deleted policy or an API
# outage looks exactly like "the condition is not set" and assertions pass.
policy_condition_status() {
  local policy="$1"
  local condition="$2"
  kubectl get pgr "$policy" \
    -o jsonpath="{.status.conditions[?(@.type==\"$condition\")].status}" 2>/dev/null
}

wait_for_condition_status() {
  local policy="$1"
  local condition="$2"
  local expected="$3"
  for i in $(seq 1 30); do
    if status="$(policy_condition_status "$policy" "$condition")"; then
      if [ "$status" = "$expected" ]; then
        echo "$policy reached $condition=$expected"
        return 0
      fi
      echo "Waiting for $policy $condition=$expected (currently '${status:-absent}', attempt $i/30)"
    else
      echo "Waiting for $policy $condition=$expected (read failed, attempt $i/30)"
    fi
    sleep 3
  done
  echo "::error::$policy did not reach $condition=$expected"
  kubectl get pgr "$policy" -o yaml || true
  return 1
}

assert_condition_absent() {
  local policy="$1"
  local condition="$2"
  if ! status="$(policy_condition_status "$policy" "$condition")"; then
    echo "::error::could not read $condition from $policy; absence is unproven"
    return 1
  fi
  if [ -n "$status" ]; then
    echo "::error::$policy unexpectedly reports $condition=$status"
    kubectl get pgr "$policy" -o yaml || true
    return 1
  fi
  echo "$policy has no $condition condition, as expected"
}

# Clearing a condition takes a reconcile, so an immediate assert would race.
wait_for_condition_absent() {
  local policy="$1"
  local condition="$2"
  for i in $(seq 1 30); do
    if status="$(policy_condition_status "$policy" "$condition")"; then
      if [ -z "$status" ]; then
        echo "$policy no longer reports $condition"
        return 0
      fi
      echo "Waiting for $policy to clear $condition (currently $status, attempt $i/30)"
    else
      echo "Waiting for $policy to clear $condition (read failed, attempt $i/30)"
    fi
    sleep 3
  done
  echo "::error::$policy did not clear $condition"
  kubectl get pgr "$policy" -o yaml || true
  return 1
}

wait_for_drift_status() {
  local policy="$1"
  local expected_status="$2"
  for i in $(seq 1 30); do
    status="$(kubectl get pgr "$policy" -o jsonpath='{.status.conditions[?(@.type=="Drifted")].status}' 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "$policy reached Drifted=$expected_status"
      return 0
    fi
    echo "Waiting for $policy Drifted=$expected_status... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not reach Drifted=$expected_status"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_last_error_contains() {
  local policy="$1"
  local expected_substring="$2"
  for i in $(seq 1 30); do
    last_error="$(kubectl get pgr "$policy" -o jsonpath='{.status.last_error}' 2>/dev/null || true)"
    normalized_last_error="$(printf '%s' "$last_error" | tr '\n' ' ' | tr -s ' ')"
    if printf '%s' "$normalized_last_error" | grep -Fq "$expected_substring"; then
      echo "$policy reported expected error substring: $expected_substring"
      return 0
    fi
    echo "Waiting for $policy lastError to contain '$expected_substring'... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy lastError did not contain $expected_substring"
  kubectl get pgr "$policy" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

wait_for_event_reason() {
  local policy="$1"
  local expected_reason="$2"
  local namespace="${3:-default}"
  for i in $(seq 1 30); do
    events="$(
      kubectl get events.events.k8s.io -n "$namespace" \
        -o jsonpath='{range .items[*]}{.regarding.name}{"\t"}{.reason}{"\n"}{end}' \
        2>/dev/null || true
    )"
    if printf '%s\n' "$events" | grep -Fxq "$policy	$expected_reason"; then
      echo "$policy emitted Event reason=$expected_reason"
      return 0
    fi
    echo "Waiting for $policy Event/$expected_reason... (attempt $i/30)"
    sleep 3
  done
  echo "::error::$policy did not emit Event reason=$expected_reason"
  kubectl get events.events.k8s.io -n "$namespace" || true
  kubectl describe pgr "$policy" || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=200 || true
  return 1
}

# -- PostgreSQL helpers -------------------------------------------------------

pg_query() {
  local db="${2:-postgres}"
  kubectl exec postgres-0 -- psql -U postgres -d "$db" -tAc "$1"
}

assert_role_exists() {
  pg_query "SELECT rolname FROM pg_roles WHERE rolname = '$1'" | grep -qx "$1"
}

assert_role_absent() {
  local result
  if ! result="$(pg_query "SELECT 1 FROM pg_roles WHERE rolname = '$1'")"; then
    echo "::error::pg_query failed while checking absence of role $1"
    return 1
  fi
  if echo "$result" | grep -qx "1"; then
    echo "::error::Role $1 unexpectedly exists"
    return 1
  fi
}

assert_schema_exists() {
  pg_query "SELECT nspname FROM pg_namespace WHERE nspname = '$1'" | grep -qx "$1"
}

assert_schema_owner() {
  local schema="$1"
  local expected_owner="$2"
  pg_query "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '$schema'" | grep -qx "$expected_owner"
}

get_password_hash() {
  pg_query "SELECT rolpassword FROM pg_authid WHERE rolname = '$1'"
}

assert_password_set() {
  local hash
  hash="$(get_password_hash "$1")"
  if [ -z "$hash" ] || [ "$hash" = "" ]; then
    echo "::error::Password hash is null/empty for role $1"
    return 1
  fi
  echo "Password hash present for $1: ${hash:0:20}..."
}

wait_for_password_hash_change() {
  local role="$1" previous_hash="$2"
  for i in $(seq 1 40); do
    local current
    current="$(get_password_hash "$role")"
    if [ -n "$current" ] && [ "$current" != "$previous_hash" ]; then
      echo "Password hash changed for $role"
      return 0
    fi
    echo "Waiting for $role password hash to change... (attempt $i/40)"
    sleep 5
  done
  echo "::error::Password hash for $role did not change"
  echo "Previous: $previous_hash"
  echo "Current:  $(get_password_hash "$role")"
  return 1
}

wait_for_password_hash_stable() {
  local role="$1" expected_hash="$2"
  for i in $(seq 1 6); do
    sleep 5
    local current
    current="$(get_password_hash "$role")"
    if [ -z "$current" ] || [ "$current" != "$expected_hash" ]; then
      echo "::error::Password hash for $role changed unexpectedly"
      echo "Expected: $expected_hash"
      echo "Current:  $current"
      return 1
    fi
    echo "Password hash still stable for $role (attempt $i/6)"
  done
}

# -- Secret helpers -----------------------------------------------------------

assert_secret_has_keys() {
  local name="$1"; shift
  for key in "$@"; do
    local value
    value="$(kubectl get secret "$name" -o "jsonpath={.data.$key}" 2>/dev/null || true)"
    if [ -z "$value" ]; then
      echo "::error::Secret $name is missing key $key"
      return 1
    fi
  done
  echo "Secret $name contains expected keys: $*"
}

assert_secret_absent() {
  local name="$1"
  local err
  if err="$(kubectl get secret "$name" -o name 2>&1 >/dev/null)"; then
    echo "::error::Secret $name exists but should not"
    return 1
  fi
  # Only NotFound proves absence; any other failure (API outage, RBAC, typo in
  # the resource kind) must not be mistaken for the Secret not existing.
  if ! printf '%s' "$err" | grep -q "NotFound"; then
    echo "::error::could not query Secret $name: $err"
    return 1
  fi
  echo "Secret $name is absent as expected"
}

# A generated Secret must stay absent for as long as its plan is unapproved,
# not merely be absent at one instant — the operator reconciles on an interval,
# so a single check could simply have run before the first reconcile.
assert_secret_absent_stable() {
  local name="$1"
  local err
  for i in $(seq 1 6); do
    sleep 5
    if err="$(kubectl get secret "$name" -o name 2>&1 >/dev/null)"; then
      echo "::error::Secret $name appeared while its plan was still unapproved"
      return 1
    fi
    # Only NotFound proves absence; any other failure must not be mistaken for
    # the Secret not existing.
    if ! printf '%s' "$err" | grep -q "NotFound"; then
      echo "::error::could not query Secret $name: $err"
      return 1
    fi
    echo "Secret $name still absent (attempt $i/6)"
  done
}

upsert_secret() {
  local name="$1"; shift
  local args=()
  for kv in "$@"; do
    args+=(--from-literal="$kv")
  done
  kubectl create secret generic "$name" "${args[@]}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

# -- Operator helpers ---------------------------------------------------------

assert_operator_logs_clean() {
  local forbidden="$1"
  local logs
  logs="$(kubectl -n pgroles-system logs deployment/pgroles-operator --tail=500 2>/dev/null || true)"
  if printf '%s' "$logs" | grep -qF "$forbidden"; then
    echo "::error::Operator logs contain forbidden string: $forbidden"
    return 1
  fi
  echo "Operator logs clean (no '$forbidden')"
}

# -- Plan helpers -------------------------------------------------------------

wait_for_plan_phase() {
  local plan="$1" expected_phase="$2"
  for i in $(seq 1 30); do
    phase="$(kubectl get pgplan "$plan" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" = "$expected_phase" ]; then
      echo "$plan reached phase=$expected_phase"
      return 0
    fi
    echo "Waiting for $plan phase=$expected_phase (current=$phase)... ($i/30)"
    sleep 3
  done
  echo "::error::$plan did not reach phase=$expected_phase within timeout"
  kubectl get pgplan "$plan" -o yaml || true
  return 1
}

# Record a terminal decision on a plan's status subresource.
#
# The decision and the deciding identity must land in one write: CEL rejects a
# decision condition without `decidedBy`. In a cluster running the Kyverno
# reference policy the `decidedBy` sent here is overwritten with the caller's
# authenticated identity; without that policy it stands as written, which is
# exactly the trust boundary documented in operator-plan-approval.md.
decide_plan() {
  local plan="$1" condition="$2" reason="$3"
  local now existing merged
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Replace any existing decision condition rather than appending one.
  #
  # A plan is created carrying `Approved=False`, so a blind append leaves two
  # `Approved` entries; the operator's own condition writer then flips the
  # first, producing two `Approved=True`. The CRD's terminality rule compares
  # the decision types that are true, so that reads as ['Approved','Approved']
  # against ['Approved'] and the operator's write is rejected — the plan can
  # never reach Applied. A plain merge patch avoids the duplicate but deletes
  # the operator's Computed condition, so read, filter, and write back.
  if ! existing="$(kubectl get pgplan "$plan" -o json)"; then
    echo "::error::could not read PostgresPolicyPlan $plan" >&2
    return 1
  fi

  merged="$(printf '%s' "$existing" | python3 -c "
import json, sys
status = json.load(sys.stdin).get('status', {})
conditions = [
    c for c in status.get('conditions', [])
    if c.get('type') not in ('Approved', 'Denied')
]
conditions.append({
    'type': '$condition', 'status': 'True', 'reason': '$reason',
    'message': 'recorded by e2e', 'lastTransitionTime': '$now',
})
print(json.dumps({'status': {
    'conditions': conditions,
    'decidedBy': {'username': '${DECIDE_BY:-e2e-reviewer}'},
}}))
")" || return 1

  # DECIDE_AS impersonates the writer (the read above stays cluster-admin so
  # a low-privilege identity can still be tested against a readable plan);
  # DECIDE_BY forges the claimed decider, for asserting that an admission
  # layer replaces it with the authenticated identity.
  if [ -n "${DECIDE_AS:-}" ]; then
    kubectl --as="$DECIDE_AS" patch pgplan "$plan" --subresource=status --type=merge -p "$merged"
  else
    kubectl patch pgplan "$plan" --subresource=status --type=merge -p "$merged"
  fi
}

approve_plan() {
  decide_plan "$1" Approved ApprovedByReviewer
}

reject_plan() {
  decide_plan "$1" Denied DeniedByReviewer
}

get_plan_sql() {
  local plan="$1"
  local inline
  # Empty output is reserved for a plan with no stored SQL, so every read here
  # must fail loudly instead of falling through to that branch.
  if ! inline="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlInline}' 2>/dev/null)"; then
    echo "::error::could not read PostgresPolicyPlan $plan" >&2
    return 1
  fi
  if [ -n "$inline" ]; then
    echo "$inline"
    return 0
  fi
  local cm_name cm_key compression escaped_key
  if ! cm_name="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlRef.name}' 2>/dev/null)"; then
    echo "::error::could not read sqlRef.name from PostgresPolicyPlan $plan" >&2
    return 1
  fi
  if ! cm_key="$(kubectl get pgplan "$plan" -o jsonpath='{.status.sqlRef.key}' 2>/dev/null)"; then
    echo "::error::could not read sqlRef.key from PostgresPolicyPlan $plan" >&2
    return 1
  fi
  if ! compression="$(kubectl get pgplan "$plan" \
    -o jsonpath='{.status.sqlRef.compression}' 2>/dev/null)"; then
    echo "::error::could not read sqlRef.compression from PostgresPolicyPlan $plan" >&2
    return 1
  fi
  # No sqlRef at all is a real outcome, not a failure: a plan too large to store
  # even compressed keeps a truncated preview in sqlInline instead.
  if [ -z "$cm_name" ] && [ -z "$cm_key" ]; then
    echo ""
    return 0
  fi
  # A half-populated sqlRef is neither of those, and silently reading it as
  # "absent" would hide a malformed plan.
  if [ -z "$cm_name" ] || [ -z "$cm_key" ]; then
    echo "::error::PostgresPolicyPlan $plan has an incomplete sqlRef (name='$cm_name' key='$cm_key')" >&2
    return 1
  fi
  # The key contains dots (plan.sql.gz), which jsonpath reads as nested fields
  # unless they are escaped inside bracket notation.
  escaped_key="${cm_key//./\\.}"
  if [ "$compression" = "gzip" ]; then
    # Compressed SQL is stored in binaryData, which kubectl returns base64-encoded.
    # pipefail is set in a subshell so a failing kubectl/base64/gunzip surfaces
    # here rather than downstream as SQL that merely lacks the expected text,
    # without disturbing the shell options of whatever sourced this file.
    (
      set -o pipefail
      kubectl get configmap "$cm_name" -o jsonpath="{.binaryData['${escaped_key}']}" |
        base64 -d | gunzip
    )
    return
  fi
  kubectl get configmap "$cm_name" -o jsonpath="{.data['${escaped_key}']}"
}

wait_for_current_plan_ref() {
  local policy="$1"
  for i in $(seq 1 30); do
    local plan_name
    plan_name="$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}' 2>/dev/null || true)"
    if [ -n "$plan_name" ]; then
      echo "$plan_name"
      return 0
    fi
    # Progress goes to stderr: every caller captures this function with $(...),
    # so anything on stdout would be taken for the plan name.
    echo "Waiting for $policy currentPlanRef... ($i/30)" >&2
    sleep 3
  done
  echo "::error::$policy did not get currentPlanRef within timeout" >&2
  return 1
}

# Print the names of plans controller-owned by this policy, one per line.
#
# The label narrows server-side, but it is truncated at 63 characters and
# candidate-owned plans carry it too, so the controller-owner UID is the
# exact filter — the same discipline the operator itself uses.
plans_owned_by_policy() {
  local policy="$1"
  local policy_uid
  policy_uid="$(kubectl get pgr "$policy" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  if [ -z "$policy_uid" ]; then
    return 0
  fi
  kubectl get pgplan -l "pgroles.io/policy=$policy" -o json 2>/dev/null |
    POLICY_UID="$policy_uid" python3 -c '
import json, os, sys
uid = os.environ["POLICY_UID"]
for item in json.load(sys.stdin).get("items", []):
    owners = item.get("metadata", {}).get("ownerReferences") or []
    if any(o.get("controller") and o.get("uid") == uid for o in owners):
        phase = (item.get("status") or {}).get("phase", "")
        print(item["metadata"]["name"], phase)
'
}

# Assert the policy is not sitting on a plan awaiting a decision, and stays
# that way. A password change planned from a stale source version shows up
# exactly here: a second Pending plan for work that already applied.
assert_no_pending_plan_stable() {
  local policy="$1"
  for i in $(seq 1 6); do
    sleep 5
    local pending
    pending="$(plans_owned_by_policy "$policy" | awk '$2 == "Pending" { print $1 }')"
    if [ -n "$pending" ]; then
      echo "::error::$policy has a pending plan it should not: $pending"
      return 1
    fi
    echo "No pending plan for $policy (attempt $i/6)"
  done
}

get_plan_count() {
  local policy="$1"
  plans_owned_by_policy "$policy" | wc -l | tr -d ' '
}

# -- Candidate helpers --------------------------------------------------------

wait_for_candidate_phase() {
  local candidate="$1" expected_phase="$2"
  local phase
  for i in $(seq 1 30); do
    phase="$(kubectl get pgcand "$candidate" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" = "$expected_phase" ]; then
      echo "$candidate reached phase=$expected_phase"
      return 0
    fi
    echo "Waiting for $candidate phase=$expected_phase (current=$phase)... ($i/30)"
    sleep 3
  done
  echo "::error::$candidate did not reach phase=$expected_phase within timeout"
  kubectl get pgcand "$candidate" -o yaml || true
  return 1
}

# Wait for a condition on a candidate to hold a given status and reason.
# Conditions are the source of truth; phase is only a printable summary.
wait_for_candidate_condition() {
  local candidate="$1" ctype="$2" expected_status="$3" expected_reason="$4"
  for i in $(seq 1 30); do
    local status reason
    status="$(kubectl get pgcand "$candidate" \
      -o jsonpath="{.status.conditions[?(@.type==\"$ctype\")].status}" 2>/dev/null || true)"
    reason="$(kubectl get pgcand "$candidate" \
      -o jsonpath="{.status.conditions[?(@.type==\"$ctype\")].reason}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ] && [ "$reason" = "$expected_reason" ]; then
      echo "$candidate has $ctype=$expected_status reason=$expected_reason"
      return 0
    fi
    echo "Waiting for $candidate $ctype=$expected_status/$expected_reason (current=$status/$reason)... ($i/30)"
    sleep 3
  done
  echo "::error::$candidate did not reach $ctype=$expected_status/$expected_reason within timeout"
  kubectl get pgcand "$candidate" -o yaml || true
  return 1
}

# The plan the operator published for a candidate. Progress goes to stderr:
# callers capture stdout as the plan name.
wait_for_candidate_plan_ref() {
  local candidate="$1"
  for i in $(seq 1 30); do
    local plan_name
    plan_name="$(kubectl get pgcand "$candidate" -o jsonpath='{.status.planRef.name}' 2>/dev/null || true)"
    if [ -n "$plan_name" ]; then
      echo "$plan_name"
      return 0
    fi
    echo "Waiting for $candidate planRef... ($i/30)" >&2
    sleep 3
  done
  echo "::error::$candidate did not get a planRef within timeout" >&2
  kubectl get pgcand "$candidate" -o yaml >&2 || true
  return 1
}

get_candidate_digest() {
  kubectl get pgcand "$1" -o jsonpath='{.status.contentDigest}'
}

get_policy_content_digest() {
  kubectl get pgr "$1" -o jsonpath='{.status.content_digest}'
}

# The policy's current plan, once it names a plan that is actually awaiting a
# decision. `wait_for_current_plan_ref` can return a reference to the plan that
# just applied, which a caller about to approve something must not mistake for
# the fresh one.
wait_for_pending_plan_ref() {
  local policy="$1"
  for i in $(seq 1 30); do
    local plan_name phase
    plan_name="$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}' 2>/dev/null || true)"
    if [ -n "$plan_name" ]; then
      phase="$(kubectl get pgplan "$plan_name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      if [ "$phase" = "Pending" ]; then
        echo "$plan_name"
        return 0
      fi
    fi
    echo "Waiting for $policy to hold a Pending plan... ($i/30)" >&2
    sleep 3
  done
  echo "::error::$policy did not hold a Pending plan within timeout" >&2
  kubectl get pgplan -l "pgroles.io/policy=$policy" -o wide >&2 || true
  return 1
}

# -- Operator health helpers --------------------------------------------------

# Change the operator's environment, then wait until only pods of the new
# template remain. `rollout status` returns once the new ReplicaSet is
# available, but pods of the previous template can still be terminating, and a
# terminating operator keeps reconciling until it exits. Without the wait, an
# old pod can act on the next policy a scenario creates.
set_operator_env() {
  local namespace=pgroles-system
  local replicas
  kubectl -n "$namespace" set env deployment/pgroles-operator "$@" >/dev/null
  kubectl -n "$namespace" rollout status deployment/pgroles-operator --timeout=120s
  replicas="$(kubectl -n "$namespace" get deployment/pgroles-operator -o jsonpath='{.spec.replicas}')"
  for _ in $(seq 1 60); do
    if [ "$(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=pgroles-operator -o json | jq '.items | length')" = "$replicas" ]; then
      return 0
    fi
    sleep 2
  done
  echo "::error::operator pods of a previous template were still running 120s after the rollout"
  kubectl -n "$namespace" get pods -l app.kubernetes.io/name=pgroles-operator -o wide || true
  return 1
}

active_operator_pod_json() {
  local namespace="${1:-pgroles-system}"
  kubectl -n "$namespace" get pods \
    -l app.kubernetes.io/name=pgroles-operator -o json \
    | jq -e '
        [.items[] | select(.metadata.deletionTimestamp == null)]
        | if length == 1 then .[0]
          else error("expected exactly one active operator pod, found \(length)")
          end
      '
}

# Working set of the active operator container, from kubelet accounting.
operator_memory_bytes() {
  local namespace="${1:-pgroles-system}"
  local excluded_pod_uid="${2:-}"
  local pod_json pod_uid node
  pod_json="$(active_operator_pod_json "$namespace")" || return 1
  pod_uid="$(jq -r '.metadata.uid' <<<"$pod_json")"
  if [ -n "$excluded_pod_uid" ] && [ "$pod_uid" = "$excluded_pod_uid" ]; then
    return 1
  fi
  node="$(jq -r '.spec.nodeName' <<<"$pod_json")"
  kubectl get --raw "/api/v1/nodes/${node}/proxy/stats/summary" \
    | jq -er --arg uid "$pod_uid" '
        .pods[]
        | select(.podRef.uid == $uid)
        | .containers[]
        | select(.name == "operator")
        | (.memory.workingSetBytes // .memory.usageBytes)
        | select(. > 0)
      '
}

# Fail if the operator crashed during a scenario, naming the reason.
#
# Memory is the resource an operator overruns silently: peak allocation scales
# with how much of a database a reconcile inspects and with how many reconciles
# run at once, neither of which any assertion about policy convergence can see.
# A run whose policies all reached Ready can still have had the operator
# OOM-killed and restarted underneath it, which in a real cluster is
# CrashLoopBackOff and a policy graph that stops converging. E2E deploys the
# operator at the same 128Mi limit the chart ships, so a regression that widens
# peak memory shows up here as a restart, and only if something looks.
#
# `OOMKilled` is called out separately from other exit reasons because it is
# the one that says the change was in memory rather than in logic.
assert_operator_healthy() {
  local namespace="${1:-pgroles-system}"
  local pod_json pod restarts reason

  if ! pod_json="$(active_operator_pod_json "$namespace" 2>/dev/null)"; then
    echo "::error::expected exactly one active operator pod in $namespace"
    kubectl -n "$namespace" get pods -o wide || true
    return 1
  fi
  pod="$(jq -r '.metadata.name' <<<"$pod_json")"
  restarts="$(jq -r '[.status.containerStatuses[]? | select(.name == "operator")][0].restartCount // 0' <<<"$pod_json")"
  reason="$(jq -r '[.status.containerStatuses[]? | select(.name == "operator")][0].lastState.terminated.reason // empty' <<<"$pod_json")"

  if [ "$reason" = "OOMKilled" ]; then
    echo "::error::operator pod $pod was OOM-killed ($restarts restart(s)); peak memory now exceeds the deployed limit"
  elif [ "${restarts:-0}" -gt 0 ]; then
    echo "::error::operator pod $pod restarted $restarts time(s), last termination reason: ${reason:-unknown}"
  else
    echo "operator pod $pod: 0 restarts"
    return 0
  fi

  kubectl -n "$namespace" get pods -o wide || true
  kubectl -n "$namespace" describe deployment/pgroles-operator || true
  kubectl -n "$namespace" logs deployment/pgroles-operator --previous --tail=200 || true
  return 1
}
