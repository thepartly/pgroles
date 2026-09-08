#!/usr/bin/env bash
# Requires the plan-lifecycle E2E cluster, operator and postgres-credentials.
# Uses actual candidate status/SQL, so bypassing the shared effect pipeline
# cannot be hidden by the pure planning tests.
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"

pg_query 'CREATE SCHEMA candidate_preserve; CREATE TABLE candidate_preserve.records(id integer);'
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: candidate-preserve-policy
spec:
  connection:
    secretRef:
      name: postgres-credentials
  interval: "5s"
  mode: apply
  approval: auto
  roles:
    - name: candidate_preserve_reader
      preserve_undeclared_grants: true
  grants:
    - role: candidate_preserve_reader
      privileges: [SELECT]
      object: {type: table, schema: candidate_preserve, name: records}
YAML
wait_for_ready_true candidate-preserve-policy
pg_query 'GRANT DELETE ON candidate_preserve.records TO candidate_preserve_reader;'

file_preservation_candidate() {
  local name="$1" preserve="$2" explicit="$3"
  python3 - "$name" "$preserve" "$explicit" <<'PY' | kubectl apply -f -
import json
import sys
name, preserve, explicit = sys.argv[1:]
content = {
    "roles": [{"name": "candidate_preserve_reader", "preserve_undeclared_grants": preserve == "true"}],
    "grants": [{"role": "candidate_preserve_reader", "privileges": ["SELECT"],
                "object": {"type": "table", "schema": "candidate_preserve", "name": "records"}}],
}
if explicit == "true":
    content["grants"].append({"role": "candidate_preserve_reader", "privileges": ["DELETE"],
                              "ensure": "absent", "object": content["grants"][0]["object"]})
print(json.dumps({"apiVersion": "pgroles.io/v1alpha1", "kind": "PostgresPolicyCandidate",
                  "metadata": {"name": name}, "spec": {
                      "policyRef": {"name": "candidate-preserve-policy"}, "content": content}}))
PY
}

file_preservation_candidate candidate-preserve-kept true false
wait_for_candidate_condition candidate-preserve-kept Ready True NoEffects
test -z "$(kubectl get pgcand candidate-preserve-kept -o jsonpath='{.status.planRef.name}')"

previous_digest=""
for name in candidate-preserve-off candidate-preserve-explicit; do
  if [ "$name" = candidate-preserve-off ]; then
    file_preservation_candidate "$name" false false
  else
    file_preservation_candidate "$name" true true
  fi
  wait_for_candidate_phase "$name" Planned
  plan="$(wait_for_candidate_plan_ref "$name")"
  test "$(kubectl get pgplan "$plan" -o jsonpath='{.status.changeSummary.grants_revoked}')" = 1
  sql="$(get_plan_sql "$plan")"
  [[ "$sql" == *'REVOKE DELETE ON TABLE "candidate_preserve"."records" FROM "candidate_preserve_reader";'* ]]
  [[ "$sql" != *'REVOKE SELECT'* ]]
  digest="$(kubectl get pgplan "$plan" -o jsonpath='{.status.changeDigest}')"
  test -n "$digest"
  if [ -n "$previous_digest" ]; then
    test "$digest" = "$previous_digest"
  fi
  previous_digest="$digest"
done

# Planning is read-only, and the live policy keeps the undeclared privilege.
test "$(pg_query "SELECT has_table_privilege('candidate_preserve_reader', 'candidate_preserve.records', 'DELETE');")" = t
kubectl delete pgcand candidate-preserve-kept candidate-preserve-off candidate-preserve-explicit
kubectl delete pgr candidate-preserve-policy --wait=true
pg_query 'DROP SCHEMA candidate_preserve CASCADE; DROP ROLE candidate_preserve_reader;'
echo 'Candidate preservation, explicit absence and read-only planning passed.'
