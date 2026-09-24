#!/usr/bin/env bash
set -euo pipefail

secure_mode="${1:-false}"
source scripts/e2e-helpers.sh
session_output=""

cleanup() {
  if [ -n "$session_output" ]; then
    rm -f "$session_output"
  fi
}
trap cleanup EXIT

wait_request_phase() {
  local request="$1" expected="$2" attempts="${3:-60}"
  for i in $(seq 1 "$attempts"); do
    phase="$(kubectl get pgear "$request" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" = "$expected" ]; then
      echo "$request reached phase $expected"
      return 0
    fi
    echo "Waiting for $request phase $expected (currently $phase, attempt $i/$attempts)"
    sleep 2
  done
  kubectl get pgear "$request" -o yaml || true
  kubectl -n pgroles-system logs deployment/pgroles-operator --tail=300 || true
  return 1
}

wait_access_policy_accepted() {
  local policy="$1"
  for i in $(seq 1 45); do
    accepted="$(kubectl get pgeap "$policy" -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null || true)"
    if [ "$accepted" = "True" ]; then
      return 0
    fi
    echo "Waiting for $policy Accepted=True (attempt $i/45)"
    sleep 2
  done
  kubectl get pgeap "$policy" -o yaml || true
  return 1
}

wait_access_policy_condition() {
  local policy="$1" condition="$2" expected="$3"
  for i in $(seq 1 45); do
    actual="$(kubectl get pgeap "$policy" -o "jsonpath={.status.conditions[?(@.type==\"${condition}\")].status}" 2>/dev/null || true)"
    if [ "$actual" = "$expected" ]; then
      return 0
    fi
    echo "Waiting for $policy $condition=$expected (currently $actual, attempt $i/45)"
    sleep 2
  done
  kubectl get pgeap "$policy" -o yaml || true
  return 1
}

wait_policy_generation() {
  local policy="$1"
  for i in $(seq 1 45); do
    generation="$(kubectl get pgr "$policy" -o jsonpath='{.metadata.generation}')"
    observed="$(kubectl get pgr "$policy" -o jsonpath='{.status.observed_generation}' 2>/dev/null || true)"
    if [ "$generation" = "$observed" ]; then
      return 0
    fi
    echo "Waiting for $policy generation $generation (observed $observed, attempt $i/45)"
    sleep 2
  done
  kubectl get pgr "$policy" -o yaml || true
  return 1
}

wait_pending_plan_for_current_generation() {
  local policy="$1" generation plan plan_generation phase
  generation="$(kubectl get pgr "$policy" -o jsonpath='{.metadata.generation}')"
  for i in $(seq 1 45); do
    plan="$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}' 2>/dev/null || true)"
    if [ -n "$plan" ]; then
      plan_generation="$(kubectl get pgplan "$plan" -o jsonpath='{.spec.policyGeneration}' 2>/dev/null || true)"
      phase="$(kubectl get pgplan "$plan" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      if [ "$plan_generation" = "$generation" ] && [ "$phase" = "Pending" ]; then
        echo "$plan"
        return 0
      fi
    fi
    echo "Waiting for $policy generation $generation pending plan (attempt $i/45)" >&2
    sleep 2
  done
  kubectl get pgr "$policy" -o yaml >&2 || true
  return 1
}

membership_count() {
  local role="$1" member="$2"
  pg_query "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE r.rolname='$role' AND u.rolname='$member'"
}

assert_membership() {
  local role="$1" member="$2" expected="$3"
  for i in $(seq 1 30); do
    actual="$(membership_count "$role" "$member")"
    if [ "$actual" = "$expected" ]; then
      return 0
    fi
    echo "Waiting for membership $member -> $role to equal $expected (currently $actual)"
    sleep 2
  done
  return 1
}

create_request() {
  local name="$1" policy="$2" duration="$3"
  create_request_for_subject "$name" "$policy" "$duration" ephemeral_e2e_subject
}

create_request_for_subject() {
  local name="$1" policy="$2" duration="$3" subject="$4"
  kubectl create -f - <<EOF
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ${name}
spec:
  accessPolicyRef:
    name: ${policy}
  subject:
    role: ${subject}
  requestedBy:
    username: e2e-client
    groups: [system:masters]
  requestedDuration: ${duration}
  justification: E2E validation
EOF
}

append_decision() {
  local request="$1" decision="$2" identity="$3" asserted_identity="${4:-$3}"
  local bundle_hash granted_duration patch
  bundle_hash="$(kubectl get pgear "$request" -o jsonpath='{.status.resolvedAccess.bundleHash}')"
  granted_duration="$(kubectl get pgear "$request" -o jsonpath='{.status.resolvedAccess.grantedDuration}')"
  if [ -z "$bundle_hash" ] || [ -z "$granted_duration" ]; then
    echo "::error::request $request has no resolved bundle to attest" >&2
    return 1
  fi
  patch="[{\"op\":\"add\",\"path\":\"/status/conditions/-\",\"value\":{\"type\":\"${decision}\",\"status\":\"True\",\"reason\":\"E2E${decision}\",\"bundleHash\":\"${bundle_hash}\",\"grantedDuration\":\"${granted_duration}\"}},{\"op\":\"add\",\"path\":\"/status/decidedBy\",\"value\":{\"username\":\"${asserted_identity}\",\"groups\":[]}}]"
  kubectl --as="$identity" patch pgear "$request" --subresource=status --type=json -p "$patch"
}

kubectl apply -f k8s/samples/ephemeral-access-e2e.yaml
wait_for_ready_true ephemeral-e2e
wait_access_policy_accepted ephemeral-e2e-automatic
wait_access_policy_accepted ephemeral-e2e-required
wait_access_policy_accepted ephemeral-e2e-session

if [ "$secure_mode" = "true" ]; then
  echo "ResourceQuota rejects request-object growth before controller reconciliation"
  quota_namespace="ephemeral-quota-e2e"
  kubectl create namespace "$quota_namespace"
  sed \
    -e "s/namespace: pgroles-system/namespace: ${quota_namespace}/" \
    -e 's/count\/ephemeralaccessrequests.pgroles.io: "500"/count\/ephemeralaccessrequests.pgroles.io: "2"/' \
    k8s/security/ephemeral-access-resource-quota.yaml | kubectl apply -f -
  for i in $(seq 1 30); do
    quota_hard="$(kubectl -n "$quota_namespace" get resourcequota pgroles-ephemeral-access \
      -o json | jq -r '.status.hard["count/ephemeralaccessrequests.pgroles.io"] // ""')"
    [ "$quota_hard" = "2" ] && break
    sleep 1
  done
  test "$quota_hard" = "2"
  for request_number in 1 2; do
    kubectl --as=system:serviceaccount:default:ephemeral-requester \
      -n "$quota_namespace" create -f - <<EOF
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: quota-request-${request_number}
spec:
  accessPolicyRef:
    name: quota-probe
  subject:
    role: quota_probe
  requestedBy:
    username: forged-requester
  requestedDuration: 10s
  justification: ResourceQuota E2E validation
EOF
  done
  if kubectl --as=system:serviceaccount:default:ephemeral-requester \
    -n "$quota_namespace" create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: quota-request-3
spec:
  accessPolicyRef:
    name: quota-probe
  subject:
    role: quota_probe
  requestedBy:
    username: forged-requester
  requestedDuration: 10s
  justification: This request must be rejected by ResourceQuota
EOF
  then
    echo "::error::request above the ResourceQuota unexpectedly succeeded"
    exit 1
  fi
  test "$(kubectl -n "$quota_namespace" get pgear --no-headers | wc -l | tr -d ' ')" = "2"
  # Namespace teardown must bypass per-request ownership checks once the
  # namespace itself is Terminating. These unresolved quota probes verify
  # admission availability, not revocation of an active database membership.
  kubectl delete namespace "$quota_namespace" --wait=true --timeout=90s

  echo "CRD schema rejects oversized user-controlled fields"
  oversized_justification="$(printf 'x%.0s' $(seq 1 2049))"
  if jq -n \
    --arg justification "$oversized_justification" \
    '{
      apiVersion: "pgroles.io/v1alpha1",
      kind: "EphemeralAccessRequest",
      metadata: {name: "ephemeral-oversized-justification"},
      spec: {
        accessPolicyRef: {name: "ephemeral-e2e-automatic"},
        subject: {role: "ephemeral_e2e_subject"},
        requestedBy: {username: "forged-requester"},
        requestedDuration: "10s",
        justification: $justification
      }
    }' | kubectl --as=system:serviceaccount:default:ephemeral-requester create -f -
  then
    echo "::error::request with an oversized justification unexpectedly succeeded"
    exit 1
  fi

  echo "Admission rejects client-owned request finalizers"
  if kubectl --as=system:serviceaccount:default:ephemeral-requester \
    create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ephemeral-client-finalizer
  finalizers:
    - example.com/quota-hostage
spec:
  accessPolicyRef:
    name: ephemeral-e2e-automatic
  subject:
    role: ephemeral_e2e_subject
  requestedBy:
    username: forged-requester
  requestedDuration: 10s
  justification: This request must be rejected by admission
EOF
  then
    echo "::error::request with a client-supplied finalizer unexpectedly succeeded"
    exit 1
  fi

  if kubectl --as=system:serviceaccount:default:ephemeral-untrusted-requester \
    create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ephemeral-use-denied
spec:
  accessPolicyRef:
    name: ephemeral-e2e-automatic
  subject:
    role: ephemeral_e2e_subject
  requestedBy:
    username: forged-requester
    groups: [forged-group]
  requestedDuration: 10s
  justification: This caller lacks the logical use verb
EOF
  then
    echo "::error::request creation without the logical use verb unexpectedly succeeded"
    exit 1
  fi
  kubectl --as=system:serviceaccount:default:ephemeral-requester create -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  name: ephemeral-use-allowed
spec:
  accessPolicyRef:
    name: ephemeral-e2e-automatic
  subject:
    role: ephemeral_e2e_subject
  requestedDuration: 10s
  justification: Logical use verb validation
EOF
  wait_request_phase ephemeral-use-allowed Active
  test "$(kubectl get pgear ephemeral-use-allowed -o jsonpath='{.spec.requestedBy.username}')" = \
    "system:serviceaccount:default:ephemeral-requester"
  test "$(kubectl get pgear ephemeral-use-allowed -o jsonpath='{.spec.requestedBy.groups}' | tr ' ' '\n' | grep -c '^forged-group$' || true)" = "0"
  if kubectl --as=system:serviceaccount:default:ephemeral-untrusted-requester \
    delete pgear ephemeral-use-allowed --wait=false; then
    echo "::error::requester deleted another identity's request"
    exit 1
  fi
  kubectl --as=system:serviceaccount:default:ephemeral-requester \
    delete pgear ephemeral-use-allowed --wait=true
fi

echo "Automatic activation, immutable status, scoped plan, and natural expiry"
create_request ephemeral-auto-expiry ephemeral-e2e-automatic 15s
wait_request_phase ephemeral-auto-expiry Active
wait_for_event_reason ephemeral-auto-expiry MembershipsGranted
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
assert_membership ephemeral_e2e_auditor ephemeral_e2e_subject 1

request_uid="$(kubectl get pgear ephemeral-auto-expiry -o jsonpath='{.metadata.uid}')"
plan_owner_uid="$(kubectl get pgplan -o json | jq -r --arg uid "$request_uid" '[.items[] | select(.spec.origin.uid == $uid and .spec.scope.operation == "Activate") | .metadata.ownerReferences[] | select(.controller == true) | .uid][0] // ""')"
test "$plan_owner_uid" = "$request_uid"

if kubectl patch pgear ephemeral-auto-expiry --subresource=status --type=merge \
  -p '{"status":{"resolvedAccess":{"bundleHash":"sha256:forged"}}}'; then
  echo "::error::resolvedAccess mutation unexpectedly succeeded"
  exit 1
fi

wait_request_phase ephemeral-auto-expiry Ended
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
assert_membership ephemeral_e2e_auditor ephemeral_e2e_subject 0

echo "Connection retargeting fails closed and cleanup resumes after restoration"
create_request ephemeral-retarget-guard ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-retarget-guard Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
original_database_url="$(kubectl get secret postgres-credentials -o jsonpath='{.data.DATABASE_URL}' | base64 --decode)"
retargeted_database_url='postgres://postgres:devpassword@postgres.default.svc.cluster.local:5432/loadtest'
kubectl patch secret postgres-credentials --type=merge \
  -p "$(jq -nc --arg url "$retargeted_database_url" '{stringData:{DATABASE_URL:$url}}')"
kubectl delete pgear ephemeral-retarget-guard --wait=false
sleep 6
kubectl get pgear ephemeral-retarget-guard >/dev/null
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl patch secret postgres-credentials --type=merge \
  -p "$(jq -nc --arg url "$original_database_url" '{stringData:{DATABASE_URL:$url}}')"
kubectl wait --for=delete pgear/ephemeral-retarget-guard --timeout=90s
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Applying recovery after absolute expiry revokes instead of re-granting"
create_request ephemeral-expired-recovery ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-expired-recovery Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
recovery_patch='{"status":{"phase":"Applying","expiresAt":"2000-01-01T00:00:00Z"}}'
if [ "$secure_mode" = "true" ]; then
  kubectl --as=system:serviceaccount:pgroles-system:pgroles-operator \
    patch pgear ephemeral-expired-recovery --subresource=status --type=merge -p "$recovery_patch"
else
  kubectl patch pgear ephemeral-expired-recovery --subresource=status --type=merge -p "$recovery_patch"
fi
wait_request_phase ephemeral-expired-recovery Ended
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "A stale Accepted condition cannot authorize an unvalidated policy generation"
pg_query "CREATE ROLE ephemeral_e2e_unmanaged_power NOLOGIN"
kubectl patch pgeap ephemeral-e2e-automatic --type=merge \
  -p '{"spec":{"memberships":[{"role":"ephemeral_e2e_unmanaged_power","inherit":false}]}}'
create_request ephemeral-stale-policy ephemeral-e2e-automatic 30s
for i in $(seq 1 30); do
  resolved_status="$(kubectl get pgear ephemeral-stale-policy -o jsonpath='{.status.conditions[?(@.type=="Resolved")].status}' 2>/dev/null || true)"
  [ "$resolved_status" = "False" ] && break
  sleep 2
done
test "$resolved_status" = "False"
assert_membership ephemeral_e2e_unmanaged_power ephemeral_e2e_subject 0
kubectl delete pgear ephemeral-stale-policy --wait=true
kubectl patch pgeap ephemeral-e2e-automatic --type=merge \
  -p '{"spec":{"memberships":[{"role":"ephemeral_e2e_editor","inherit":false},{"role":"ephemeral_e2e_auditor","inherit":false}]}}'
wait_access_policy_accepted ephemeral-e2e-automatic
pg_query "DROP ROLE ephemeral_e2e_unmanaged_power"

echo "Overlapping requests retain the edge until the final owner ends"
create_request ephemeral-overlap-a ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-overlap-a Active
create_request ephemeral-overlap-b ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-overlap-b Active
kubectl delete pgear ephemeral-overlap-a --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-overlap-b --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "A membership made durable during access is retained"
create_request ephemeral-durable-race ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-durable-race Active
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"memberships":[{"role":"ephemeral_e2e_editor","members":[{"name":"ephemeral_e2e_subject","inherit":false}]}]}}'
wait_policy_generation ephemeral-e2e
kubectl delete pgear ephemeral-durable-race --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"memberships":[]}}'
wait_policy_generation ephemeral-e2e
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "An active request blocks durable removal of a role it still needs"
create_request ephemeral-role-drop-block ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-role-drop-block Active
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_auditor","login":false},{"name":"ephemeral_e2e_session_user","login":true}]}}'
wait_for_ready_reason ephemeral-e2e InvalidSpec
wait_for_last_error_contains ephemeral-e2e "active ephemeral request"
test "$(kubectl get pgeap ephemeral-e2e-automatic -o jsonpath='{.status.conditions[?(@.type=="RoleRetirementBlocked")].status}')" = "True"
blocking_uid="$(kubectl get pgear ephemeral-role-drop-block -o jsonpath='{.metadata.uid}')"
kubectl get pgeap ephemeral-e2e-automatic -o jsonpath='{.status.conditions[?(@.type=="RoleRetirementBlocked")].message}' | grep -Fq "$blocking_uid"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_editor","login":false},{"name":"ephemeral_e2e_auditor","login":false},{"name":"ephemeral_e2e_session_user","login":true}]}}'
wait_for_ready_true ephemeral-e2e
for i in $(seq 1 30); do
  retirement_status="$(kubectl get pgeap ephemeral-e2e-automatic -o jsonpath='{.status.conditions[?(@.type=="RoleRetirementBlocked")].status}' 2>/dev/null || true)"
  [ "$retirement_status" = "False" ] && break
  sleep 2
done
test "$retirement_status" = "False"
kubectl delete pgear ephemeral-role-drop-block --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Suspend blocks pending activation but leaves active access unchanged"
create_request ephemeral-active-while-suspended ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-active-while-suspended Active
kubectl patch pgeap ephemeral-e2e-automatic --type=merge -p '{"spec":{"suspend":true}}'
sleep 5
test "$(kubectl get pgear ephemeral-active-while-suspended -o jsonpath='{.status.phase}')" = "Active"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-active-while-suspended --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-automatic --type=merge -p '{"spec":{"suspend":false}}'

create_request ephemeral-pending-suspended ephemeral-e2e-required 45s
wait_request_phase ephemeral-pending-suspended PendingApproval
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"suspend":true}}'
sleep 6
test "$(kubectl get pgear ephemeral-pending-suspended -o jsonpath='{.status.phase}')" = "PendingApproval"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"suspend":false}}'
kubectl delete pgear ephemeral-pending-suspended --wait=true

echo "Approval deadlines continue while suspended and never revive"
kubectl apply -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: ephemeral-e2e-short-approval
spec:
  postgresPolicyRef:
    name: ephemeral-e2e
  memberships:
    - role: ephemeral_e2e_editor
      inherit: false
  maximumDuration: 1m
  defaultDuration: 30s
  pendingRequestTTL: 8s
  justification:
    required: true
  approval:
    mode: Required
EOF
wait_access_policy_accepted ephemeral-e2e-short-approval
create_request ephemeral-approval-expiry ephemeral-e2e-short-approval 30s
wait_request_phase ephemeral-approval-expiry PendingApproval
kubectl patch pgeap ephemeral-e2e-short-approval --type=merge -p '{"spec":{"suspend":true}}'
wait_request_phase ephemeral-approval-expiry ApprovalExpired
kubectl patch pgeap ephemeral-e2e-short-approval --type=merge -p '{"spec":{"suspend":false}}'
sleep 4
test "$(kubectl get pgear ephemeral-approval-expiry -o jsonpath='{.status.phase}')" = "ApprovalExpired"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl delete pgear ephemeral-approval-expiry --wait=true

echo "Approval-mode and bundle changes cancel the immutable pending snapshot"
create_request ephemeral-mode-change ephemeral-e2e-required 45s
wait_request_phase ephemeral-mode-change PendingApproval
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"approval":{"mode":"Automatic"}}}'
wait_request_phase ephemeral-mode-change Cancelled
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-required --type=merge -p '{"spec":{"approval":{"mode":"Required"}}}'
wait_access_policy_accepted ephemeral-e2e-required
kubectl delete pgear ephemeral-mode-change --wait=true

create_request ephemeral-bundle-change ephemeral-e2e-required 45s
wait_request_phase ephemeral-bundle-change PendingApproval
kubectl patch pgeap ephemeral-e2e-required --type=merge \
  -p '{"spec":{"memberships":[{"role":"ephemeral_e2e_auditor","inherit":false}]}}'
wait_request_phase ephemeral-bundle-change Cancelled
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgeap ephemeral-e2e-required --type=merge \
  -p '{"spec":{"memberships":[{"role":"ephemeral_e2e_editor","inherit":false}]}}'
wait_access_policy_accepted ephemeral-e2e-required
kubectl delete pgear ephemeral-bundle-change --wait=true

echo "A status-only lifecycle forgery has no activation provenance"
create_request ephemeral-phase-forgery ephemeral-e2e-required 45s
wait_request_phase ephemeral-phase-forgery PendingApproval
if [ "$secure_mode" = "true" ]; then
  if kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-phase-forgery --subresource=status --type=merge \
    -p '{"status":{"phase":"Applying"}}'; then
    echo "::error::unauthorized lifecycle mutation unexpectedly passed Kyverno"
    exit 1
  fi
else
  kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-phase-forgery --subresource=status --type=merge \
    -p '{"status":{"phase":"Applying"}}'
  wait_request_phase ephemeral-phase-forgery Cancelled
fi
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl delete pgear ephemeral-phase-forgery --wait=true

echo "Required approval trust boundary"
create_request ephemeral-required ephemeral-e2e-required 45s
wait_request_phase ephemeral-required PendingApproval

if [ "$secure_mode" = "true" ]; then
  test "$(kubectl auth can-i approve ephemeralaccesspolicies.pgroles.io --as=system:serviceaccount:pgroles-system:pgroles-operator -n default)" = "no"
  test "$(kubectl auth can-i manage ephemeralaccesspolicies.pgroles.io --as=system:serviceaccount:pgroles-system:pgroles-operator -n default)" = "yes"
  test "$(kubectl auth can-i patch ephemeralaccessrequests.pgroles.io --as=system:serviceaccount:default:ephemeral-approver -n default)" = "no"
  if append_decision ephemeral-required Approved system:serviceaccount:default:ephemeral-status-writer; then
    echo "::error::unauthorized approval unexpectedly passed Kyverno"
    exit 1
  fi
  if kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-required --subresource=status --type=merge \
    -p '{"status":{"phase":"Applying"}}'; then
    echo "::error::unauthorized lifecycle mutation unexpectedly passed Kyverno"
    exit 1
  fi
  append_decision ephemeral-required Approved system:serviceaccount:default:ephemeral-approver forged-approver
else
  append_decision ephemeral-required Approved system:serviceaccount:default:ephemeral-status-writer
fi

if [ "$secure_mode" = "true" ]; then
  test "$(kubectl get pgear ephemeral-required -o jsonpath='{.status.decidedBy.username}')" = \
    "system:serviceaccount:default:ephemeral-approver"
  if kubectl --as=system:serviceaccount:default:ephemeral-approver \
    patch pgear ephemeral-required --subresource=status --type=merge \
    -p '{"status":{"decidedBy":{"username":"replacement-approver","groups":[]}}}'; then
    echo "::error::write-once decision identity mutation unexpectedly succeeded"
    exit 1
  fi
fi

wait_request_phase ephemeral-required Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
if [ "$secure_mode" = "true" ]; then
  if kubectl --as=system:serviceaccount:default:ephemeral-status-writer \
    patch pgear ephemeral-required --type=merge -p '{"metadata":{"finalizers":[]}}'; then
    echo "::error::unauthorized finalizer removal unexpectedly passed Kyverno"
    exit 1
  fi
fi
kubectl delete pgear ephemeral-required --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Denied requests terminate without database mutation"
create_request ephemeral-denied ephemeral-e2e-required 45s
wait_request_phase ephemeral-denied PendingApproval
if [ "$secure_mode" = "true" ]; then
  append_decision ephemeral-denied Denied system:serviceaccount:default:ephemeral-approver
else
  append_decision ephemeral-denied Denied system:serviceaccount:default:ephemeral-status-writer
fi
wait_request_phase ephemeral-denied Denied
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl delete pgear ephemeral-denied --wait=true

echo "Target suspension surfaces status and blocks new activation"
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"suspend":true}}'
wait_access_policy_condition ephemeral-e2e-automatic Suspended True
# The request has to outlive the suspend/unsuspend cycle below: its clock starts
# at creation, but nothing checks it for Active until after the policy has gone
# Ready again. At 30s it raced that wait and expired to Ended first. 2m is the
# ceiling here — ephemeral-e2e-automatic sets maximumDuration: 2m in
# k8s/samples/ephemeral-access-e2e.yaml, and exceeding it is rejected outright
# rather than clamped. Natural expiry has its own scenario; this request is
# deleted explicitly, so the wider window costs no wall-clock.
create_request ephemeral-target-suspended ephemeral-e2e-automatic 2m
for i in $(seq 1 30); do
  reason="$(kubectl get pgear ephemeral-target-suspended -o jsonpath='{.status.conditions[?(@.type=="Resolved")].reason}' 2>/dev/null || true)"
  [ "$reason" = "Suspended" ] && break
  sleep 2
done
test "$reason" = "Suspended"
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"suspend":false}}'
wait_for_ready_true ephemeral-e2e
wait_access_policy_condition ephemeral-e2e-automatic Suspended False
wait_request_phase ephemeral-target-suspended Active
test -z "$(kubectl get pgear ephemeral-target-suspended -o jsonpath='{.status.lastError}' 2>/dev/null || true)"
kubectl delete pgear ephemeral-target-suspended --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Scoped revocation remains effective in additive reconciliation"
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"reconciliation_mode":"additive"}}'
wait_for_ready_true ephemeral-e2e
create_request ephemeral-additive ephemeral-e2e-automatic 45s
wait_request_phase ephemeral-additive Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-additive --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"reconciliation_mode":"authoritative"}}'
wait_for_ready_true ephemeral-e2e

echo "An external subject declared in policy is not implicitly created"
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_editor","login":false},{"name":"ephemeral_e2e_auditor","login":false},{"name":"ephemeral_e2e_session_user","login":true},{"name":"ephemeral_e2e_missing_external","external":true}]}}'
wait_for_ready_true ephemeral-e2e
create_request_for_subject ephemeral-missing-subject ephemeral-e2e-automatic 30s ephemeral_e2e_missing_external
for i in $(seq 1 30); do
  request_error="$(kubectl get pgear ephemeral-missing-subject -o jsonpath='{.status.lastError}' 2>/dev/null || true)"
  printf '%s' "$request_error" | grep -Fq 'must already exist in PostgreSQL' && break
  sleep 2
done
printf '%s' "$request_error" | grep -Fq 'must already exist in PostgreSQL'
kubectl delete pgear ephemeral-missing-subject --wait=true
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_editor","login":false},{"name":"ephemeral_e2e_auditor","login":false},{"name":"ephemeral_e2e_session_user","login":true}]}}'
wait_for_ready_true ephemeral-e2e

echo "An already-elevated session retains SET ROLE, while fresh SET ROLE is denied"
pg_query "ALTER ROLE ephemeral_e2e_session_user PASSWORD 'ephemeral-session-password'"
create_request_for_subject ephemeral-session ephemeral-e2e-session 1m ephemeral_e2e_session_user
wait_request_phase ephemeral-session Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_session_user 1
session_output="$(mktemp)"
kubectl exec -i postgres-0 -- env PGPASSWORD=ephemeral-session-password \
  psql -X -v ON_ERROR_STOP=0 -h 127.0.0.1 -U ephemeral_e2e_session_user -d postgres \
  >"$session_output" 2>&1 <<'SQL' &
SET ROLE ephemeral_e2e_editor;
SELECT 'before=' || current_user;
SELECT pg_sleep(12);
SELECT 'during=' || current_user;
RESET ROLE;
SET ROLE ephemeral_e2e_editor;
SQL
session_pid=$!
for i in $(seq 1 30); do
  active_sleep="$(pg_query "SELECT count(*) FROM pg_stat_activity WHERE usename='ephemeral_e2e_session_user' AND query LIKE '%pg_sleep%'")"
  [ "$active_sleep" = "1" ] && break
  sleep 1
done
test "$active_sleep" = "1"
kubectl delete pgear ephemeral-session --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_session_user 0
wait "$session_pid" || true
grep -Fq 'before=ephemeral_e2e_editor' "$session_output"
grep -Fq 'during=ephemeral_e2e_editor' "$session_output"
grep -Fq 'permission denied to set role "ephemeral_e2e_editor"' "$session_output"
rm -f "$session_output"
session_output=""
if kubectl exec postgres-0 -- env PGPASSWORD=ephemeral-session-password \
  psql -X -v ON_ERROR_STOP=1 -h 127.0.0.1 -U ephemeral_e2e_session_user -d postgres \
  -c 'SET ROLE ephemeral_e2e_editor;'; then
  echo "::error::fresh SET ROLE unexpectedly succeeded after revocation"
  exit 1
fi

echo "Two operator replicas serialize scoped activation through the database lock"
kubectl -n pgroles-system scale deployment/pgroles-operator --replicas=2
kubectl -n pgroles-system rollout status deployment/pgroles-operator --timeout=90s
create_request ephemeral-multi-replica ephemeral-e2e-automatic 45s
wait_request_phase ephemeral-multi-replica Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgear ephemeral-multi-replica --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
kubectl -n pgroles-system scale deployment/pgroles-operator --replicas=1
kubectl -n pgroles-system rollout status deployment/pgroles-operator --timeout=90s

echo "Ephemeral churn does not replace or re-hash a pending durable plan"
kubectl patch pgr ephemeral-e2e --type=merge -p \
  '{"spec":{"approval":"manual","roles":[{"name":"ephemeral_e2e_subject","login":false},{"name":"ephemeral_e2e_editor","login":false},{"name":"ephemeral_e2e_auditor","login":false},{"name":"ephemeral_e2e_session_user","login":true},{"name":"ephemeral_e2e_plan_probe","login":false}]}}'
# Manual approval deliberately leaves observedGeneration at the last applied
# generation. The pending currentPlanRef is the readiness signal here.
durable_plan="$(wait_pending_plan_for_current_generation ephemeral-e2e)"
durable_hash="$(kubectl get pgplan "$durable_plan" -o jsonpath='{.status.sqlHash}')"
create_request ephemeral-plan-stability ephemeral-e2e-automatic 45s
wait_request_phase ephemeral-plan-stability Active
sleep 6
test "$(kubectl get pgr ephemeral-e2e -o jsonpath='{.status.current_plan_ref.name}')" = "$durable_plan"
test "$(kubectl get pgplan "$durable_plan" -o jsonpath='{.status.sqlHash}')" = "$durable_hash"
kubectl delete pgear ephemeral-plan-stability --wait=true
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0
approve_plan "$durable_plan"
wait_for_ready_true ephemeral-e2e
kubectl patch pgr ephemeral-e2e --type=merge -p '{"spec":{"approval":"auto"}}'
wait_for_ready_true ephemeral-e2e

echo "Access-policy deletion is a revoke-all kill switch"
create_request ephemeral-policy-delete ephemeral-e2e-automatic 1m
wait_request_phase ephemeral-policy-delete Active
kubectl delete pgeap ephemeral-e2e-automatic --wait=true
kubectl wait --for=delete pgear/ephemeral-policy-delete --timeout=90s
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Target-policy deletion waits for scoped revocation"
kubectl apply -f - <<'EOF'
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: ephemeral-e2e-target-delete
spec:
  postgresPolicyRef:
    name: ephemeral-e2e
  memberships:
    - role: ephemeral_e2e_editor
      inherit: false
  maximumDuration: 2m
  defaultDuration: 1m
  pendingRequestTTL: 1m
  justification:
    required: true
  approval:
    mode: Automatic
EOF
wait_access_policy_accepted ephemeral-e2e-target-delete
create_request ephemeral-target-delete ephemeral-e2e-target-delete 1m
wait_request_phase ephemeral-target-delete Active
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 1
kubectl delete pgr ephemeral-e2e --wait=true --timeout=120s
kubectl wait --for=delete pgeap/ephemeral-e2e-target-delete --timeout=90s
kubectl wait --for=delete pgear/ephemeral-target-delete --timeout=90s
assert_membership ephemeral_e2e_editor ephemeral_e2e_subject 0

echo "Structured lifecycle audit event reached the OTLP collector"
for i in $(seq 1 30); do
  # Read the complete stream without buffering it in the shell. Metrics and
  # ordinary reconciliation logs are deliberately noisy in this shared debug
  # collector, so a fixed tail can discard the lifecycle transition.
  if kubectl -n pgroles-system logs deployment/otel-collector 2>/dev/null |
    awk '
      /pgroles\.ephemeral_access\.lifecycle/ { lifecycle = 1 }
      /bundle_hash/ { bundle = 1 }
      /requester/ { requester = 1 }
      /decision_maker/ { decision_maker = 1 }
      /pgroles.ephemeral_access.transitions/ { metrics = 1 }
      END { exit !(lifecycle && bundle && requester && decision_maker && metrics) }
    '
  then
    exit 0
  fi
  echo "Waiting for structured access audit event (attempt $i/30)"
  sleep 2
done

kubectl -n pgroles-system logs deployment/pgroles-operator --tail=300 || true
kubectl -n pgroles-system logs deployment/otel-collector --tail=500 || true
# Rotated files here mean `kubectl logs` could no longer see earlier records.
node="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$node" ] && docker exec "$node" sh -c 'ls -la /var/log/pods/pgroles-system_otel-collector-*/*/' || true
exit 1
