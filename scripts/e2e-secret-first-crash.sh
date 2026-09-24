#!/usr/bin/env bash
# Requires the e2e-fault-injection operator feature. Never races a pod deletion.
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
policy=secret-first-crash
secret=secret-first-credential
role=secret_first_user
cleanup() {
  set_operator_env PGROLES_E2E_CRASH_AFTER_GENERATED_SECRET- || true
  kubectl delete pgr "$policy" --ignore-not-found --wait=true >/dev/null || true
  pg_query "DROP ROLE IF EXISTS $role" >/dev/null || true
}
trap cleanup EXIT
set_operator_env PGROLES_E2E_CRASH_AFTER_GENERATED_SECRET="default/$policy"
pod=$(kubectl -n pgroles-system get pods -l app.kubernetes.io/name=pgroles-operator -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name' | head -1)
test -n "$pod"
restart_before=$(kubectl -n pgroles-system get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
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
      password:
        generate:
          secretName: $secret
YAML
wait_for_ready_status_reason "$policy" True Planned
first=$(wait_for_current_plan_ref "$policy")
first_digest=$(kubectl get pgplan "$first" -o jsonpath='{.status.changeDigest}')
assert_secret_absent "$secret"
approve_plan "$first"
for i in $(seq 1 60); do
  restarts=$(kubectl -n pgroles-system get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
  if [ "$restarts" -gt "$restart_before" ]; then break; fi
  sleep 2
done
test "$restarts" -gt "$restart_before" || { echo '::error::fault injection did not restart the process'; exit 1; }
kubectl -n pgroles-system logs "$pod" --previous | grep -F 'E2E fault injection: generated Secret persisted; aborting before SQL'
assert_secret_has_keys "$secret" password verifier
# Compare the whole credential object through recovery without printing its data.
credential_before=$(kubectl get secret "$secret" -o json | jq -c '{uid:.metadata.uid,rv:.metadata.resourceVersion,data:.data}')
secret_version=$(kubectl get secret "$secret" -o jsonpath='{.metadata.resourceVersion}')
assert_role_absent "$role"
wait_for_plan_phase "$first" Superseded
kubectl get pgplan "$first" -o json | jq -e '.status.conditions | any(.reason == "PasswordSourceChanged")' >/dev/null
for i in $(seq 1 30); do
  fresh=$(kubectl get pgr "$policy" -o jsonpath='{.status.current_plan_ref.name}')
  if [ -n "$fresh" ] && [ "$fresh" != "$first" ]; then break; fi
  sleep 2
done
test -n "$fresh" && test "$fresh" != "$first"
wait_for_plan_phase "$fresh" Pending
fresh_digest=$(kubectl get pgplan "$fresh" -o jsonpath='{.status.changeDigest}')
test -n "$fresh_digest" && test "$fresh_digest" != "$first_digest"
assert_role_absent "$role"
approve_plan "$fresh"
wait_for_plan_phase "$fresh" Applied
assert_role_exists "$role"
assert_password_set "$role"
password=$(kubectl get secret "$secret" -o json | jq -r '.data.password | @base64d')
kubectl exec postgres-0 -- env PGPASSWORD="$password" psql -v ON_ERROR_STOP=1 -h postgres.default.svc.cluster.local -U "$role" -d postgres -Atc 'SELECT current_user' | grep -qx "$role"
unset password
wait_for_drift_status "$policy" False
assert_no_pending_plan_stable "$policy"
credential_after=$(kubectl get secret "$secret" -o json | jq -c '{uid:.metadata.uid,rv:.metadata.resourceVersion,data:.data}')
test "$credential_before" = "$credential_after" || { echo '::error::credential rotated during crash recovery'; exit 1; }
recorded=$(kubectl get pgr "$policy" -o json | jq -r --arg role "$role" '.status.applied_password_source_versions[$role]')
test "$recorded" = "$secret:password:$secret_version" || { echo '::error::applied source version does not match preserved Secret'; exit 1; }
restarts=$(kubectl -n pgroles-system get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')
test "$restarts" -eq "$((restart_before + 1))"
echo 'Secret-first recovery required one fresh approval and preserved the credential.'
