#!/usr/bin/env bash
# Runs only against the disposable plan-lifecycle E2E fixture.
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
if [ -n "${PGROLES_TEST_PG_CONTAINER:-}" ]; then
  pg_query() { docker exec "$PGROLES_TEST_PG_CONTAINER" psql -U postgres -d pgroles_test -tAc "$1"; }
fi
# Later scripts share this fixture, so a failed assertion must not leave
# policies reconciling or the roles behind.
cleanup() {
  kubectl delete pgcand candidate-authority-preview candidate-authority-repair \
    candidate-authority-privileged-override candidate-authority-ordinary-override \
    candidate-authority-cas-superseded candidate-authority-cas-promoted \
    --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete pgr candidate-authority-policy candidate-authority-root-parent \
    --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete secret candidate-authority-credentials --ignore-not-found >/dev/null 2>&1 || true
  for role in cau_member cau_executor cau_grantor cau_group cau_repair cat_member cat_grantor cat_group; do
    pg_query "DROP ROLE IF EXISTS $role;" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
review_sql() {
  local name="$1"
  for attempt in 1 2 3 4 5; do
    if value="$(get_plan_sql "$name")"; then printf '%s' "$value"; return 0; fi
    sleep 2
  done
  return 1
}
pg_query "CREATE ROLE cau_group; CREATE ROLE cau_member; CREATE ROLE cau_grantor;
  CREATE ROLE cau_executor LOGIN PASSWORD 'cau-test-password';
  CREATE ROLE cau_repair;
  GRANT cau_group TO cau_grantor WITH ADMIN TRUE;
  GRANT cau_group TO cau_member WITH INHERIT FALSE, SET FALSE GRANTED BY cau_grantor;
  GRANT cau_repair TO cau_executor WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;"
python3 - <<'PY_SECRET' | kubectl apply -f -
import base64, json, subprocess
from urllib.parse import urlsplit, urlunsplit
secret = json.loads(subprocess.check_output(["kubectl", "get", "secret", "postgres-credentials", "-o", "json"]))
url = urlsplit(base64.b64decode(secret["data"]["DATABASE_URL"]).decode())
value = urlunsplit((url.scheme, "cau_executor:cau-test-password@" + url.netloc.rsplit("@", 1)[-1], url.path, url.query, url.fragment))
print(json.dumps({"apiVersion":"v1", "kind":"Secret", "metadata":{"name":"candidate-authority-credentials"}, "stringData":{"DATABASE_URL":value}}))
PY_SECRET
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: candidate-authority-policy}
spec:
  connection: {secretRef: {name: candidate-authority-credentials}}
  interval: 2s
  mode: apply
  approval: auto
  roles:
    - {name: cau_group, external: true}
    - {name: cau_member, external: true}
    - {name: cau_grantor, external: true}
  memberships:
    - role: cau_group
      exclusive: true
      members:
        - {name: cau_grantor, admin: true}
        - {name: cau_member, inherit: false}
YAML
wait_for_ready_status_reason candidate-authority-policy True Reconciled
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: candidate-authority-preview}
spec:
  policyRef: {name: candidate-authority-policy}
  content:
    roles:
      - {name: cau_group, external: true}
      - {name: cau_member, external: true}
      - {name: cau_grantor, external: true}
    memberships:
      - role: cau_group
        exclusive: true
        members: [{name: cau_grantor, admin: true}]
YAML
wait_for_candidate_condition candidate-authority-preview Ready False ExecutorAuthority
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.phase}')" = Planned
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = Blocked
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.issues[0].code}')" = ForeignGrantorMembershipRevoke
plan="$(wait_for_candidate_plan_ref candidate-authority-preview)"
sql="$(review_sql "$plan")"
[[ "$sql" == *'REVOKE "cau_group" FROM "cau_member" GRANTED BY "cau_grantor";'* ]]
[[ "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}')" == *'cau_grantor'* ]]
test "$(pg_query "SELECT pg_has_role('cau_member','cau_group','MEMBER');")" = t
# Same endpoint, distinct executor: an ordinary parent must not downgrade
# an explicitly privileged override to the parent pool.
kubectl apply -f - <<'YAML_OVERRIDE'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: candidate-authority-privileged-override}
spec:
  policyRef: {name: candidate-authority-policy}
  target: {connectionRef: {secretName: postgres-credentials, key: DATABASE_URL}}
  content:
    roles:
      - {name: cau_group, external: true}
      - {name: cau_member, external: true}
      - {name: cau_grantor, external: true}
    memberships:
      - role: cau_group
        exclusive: true
        members: [{name: cau_grantor, admin: true}]
YAML_OVERRIDE
wait_for_candidate_condition candidate-authority-privileged-override Ready True Planned
test "$(kubectl get pgcand candidate-authority-privileged-override -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
kubectl delete pgcand candidate-authority-privileged-override --wait=true

# Converse: a privileged parent must not lend its authority to an ordinary
# override at the same host/port/database. Use separate role claims.
pg_query 'CREATE ROLE cat_group; CREATE ROLE cat_member; CREATE ROLE cat_grantor; GRANT cat_group TO cat_grantor WITH ADMIN TRUE; GRANT cat_group TO cat_member WITH INHERIT FALSE, SET FALSE GRANTED BY cat_grantor;'
kubectl apply -f - <<'YAML_CONVERSE'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: candidate-authority-root-parent}
spec:
  connection: {secretRef: {name: postgres-credentials}}
  interval: 2s
  mode: apply
  approval: auto
  roles:
    - {name: cat_group, external: true}
    - {name: cat_member, external: true}
    - {name: cat_grantor, external: true}
  memberships:
    - role: cat_group
      exclusive: true
      members: [{name: cat_grantor, admin: true}, {name: cat_member, inherit: false}]
---
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: candidate-authority-ordinary-override}
spec:
  policyRef: {name: candidate-authority-root-parent}
  target: {connectionRef: {secretName: candidate-authority-credentials, key: DATABASE_URL}}
  content:
    roles:
      - {name: cat_group, external: true}
      - {name: cat_member, external: true}
      - {name: cat_grantor, external: true}
    memberships:
      - role: cat_group
        exclusive: true
        members: [{name: cat_grantor, admin: true}]
YAML_CONVERSE
wait_for_ready_status_reason candidate-authority-root-parent True Reconciled
wait_for_candidate_condition candidate-authority-ordinary-override Ready False ExecutorAuthority
[[ "$(kubectl get pgcand candidate-authority-ordinary-override -o jsonpath='{.status.executorAuthority.issues[0].message}')" == *'cau_executor'* ]]
[[ "$(kubectl get pgcand candidate-authority-ordinary-override -o jsonpath='{.status.executorAuthority.issues[0].message}')" == *'cat_grantor'* ]]
kubectl delete pgcand candidate-authority-ordinary-override --wait=true
kubectl delete pgr candidate-authority-root-parent --wait=true
pg_query 'DROP ROLE cat_member; DROP ROLE cat_grantor; DROP ROLE cat_group;'

# Granting authority changes eligibility, without executing the candidate.
pg_query 'GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;'
wait_for_candidate_condition candidate-authority-preview Ready True Planned
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.issues[*].code}')" = ""
assert_review_unchanged() {
  test "$(wait_for_candidate_plan_ref candidate-authority-preview)" = "$plan"
  test "$(review_sql "$plan")" = "$sql"
  test "$(pg_query "SELECT pg_has_role('cau_member','cau_group','MEMBER');")" = t
}
assert_unavailable() {
  wait_for_candidate_condition candidate-authority-preview Ready False BlockedByActivePolicy
  test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority}')" = ""
  assert_review_unchanged
}
# The result names the parent generation and state it was computed against.
assert_evaluated_against() {
  local candidate="$1" state="$2"
  test "$(kubectl get pgcand "$candidate" -o jsonpath='{.status.executorAuthority.parentState}')" = "$state"
  test "$(kubectl get pgcand "$candidate" -o jsonpath='{.status.executorAuthority.parentGeneration}')" = \
    "$(kubectl get pgr candidate-authority-policy -o jsonpath='{.metadata.generation}')"
  test -n "$(kubectl get pgcand "$candidate" -o jsonpath='{.status.executorAuthority.evaluatedAt}')"
}
assert_fresh() {
  wait_for_ready_status_reason candidate-authority-policy True Reconciled
  wait_for_candidate_condition candidate-authority-preview Ready True Planned
  test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
  assert_evaluated_against candidate-authority-preview Converged
  assert_review_unchanged
}
assert_review_unchanged
# Suspension never enters planning under database locks.
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":true}}'
assert_unavailable
version="$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.metadata.resourceVersion}')"
kubectl annotate pgr candidate-authority-policy reconcile.pgroles.io/requestedAt="suspended-$(date +%s)" --overwrite
sleep 4
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.metadata.resourceVersion}')" = "$version"
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":false}}'
assert_fresh
# Parent connection failure also happens before candidate planning.
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"connection":{"secretRef":{"name":"candidate-authority-missing"}}}}'
assert_unavailable
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"connection":{"secretRef":{"name":"candidate-authority-credentials"}}}}'
assert_fresh
# Induce external drift without changing the parent content/base pin: the
# INC-168 shape. Losing grantor authority blocks the parent's option change.
# Nothing from its plan ran, so candidates are still planned against the
# unchanged database and say so. Recovery must apply the parent plan normally;
# deleting or canceling it would mask the lifecycle behavior this depends on.
pg_query 'REVOKE cau_grantor FROM cau_executor GRANTED BY postgres;'
pg_query 'GRANT cau_group TO cau_member WITH INHERIT TRUE GRANTED BY cau_grantor;'
wait_for_ready_status_reason candidate-authority-policy False ExecutorAuthority
parent_plan="$(wait_for_current_plan_ref candidate-authority-policy)"
wait_for_plan_phase "$parent_plan" Pending
wait_for_candidate_condition candidate-authority-preview Ready False ExecutorAuthority
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = Blocked
assert_evaluated_against candidate-authority-preview ExecutorAuthorityBlocked
assert_review_unchanged
# A repair keeps the live INHERIT option instead of rewriting a membership the
# executor cannot touch, and adds a grant it can make. Its own preview has no
# known blockers while the policy it repairs is still degraded.
kubectl apply -f - <<'YAML_REPAIR'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: candidate-authority-repair}
spec:
  policyRef: {name: candidate-authority-policy}
  content:
    roles:
      - {name: cau_group, external: true}
      - {name: cau_member, external: true}
      - {name: cau_grantor, external: true}
      - {name: cau_repair, external: true}
    memberships:
      - role: cau_group
        exclusive: true
        members:
          - {name: cau_grantor, admin: true}
          - {name: cau_member, inherit: true}
      - role: cau_repair
        members: [{name: cau_member}]
YAML_REPAIR
wait_for_candidate_condition candidate-authority-repair Ready True Planned
test "$(kubectl get pgcand candidate-authority-repair -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
assert_evaluated_against candidate-authority-repair ExecutorAuthorityBlocked
[[ "$(kubectl get pgcand candidate-authority-repair -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}')" == *'replaces the blocked content'* ]]
repair_sql="$(review_sql "$(wait_for_candidate_plan_ref candidate-authority-repair)")"
[[ "$repair_sql" == *'GRANT "cau_repair" TO "cau_member"'* ]]
[[ "$repair_sql" != *'REVOKE'* ]]
# Previewing executed nothing; the parent is still blocked on its own plan.
test "$(pg_query "SELECT pg_has_role('cau_member','cau_repair','MEMBER');")" = f
test "$(kubectl get pgplan "$parent_plan" -o jsonpath='{.status.phase}')" = Pending
kubectl delete pgcand candidate-authority-repair --wait=true
pg_query 'GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;'
assert_fresh
wait_for_plan_phase "$parent_plan" Applied
# Replay each stale-list interleaving against the real Kubernetes apiserver
# using a distinct disposable candidate; terminal objects are never reopened.
for phase in Superseded Promoted; do
  suffix="$(printf '%s' "$phase" | tr '[:upper:]' '[:lower:]')"
  race="candidate-authority-cas-$suffix"
  kubectl get pgcand candidate-authority-preview -o json | python3 -c 'import json,sys; c=json.load(sys.stdin); print(json.dumps({"apiVersion":c["apiVersion"],"kind":c["kind"],"metadata":{"name":sys.argv[1]},"spec":c["spec"]}))' "$race" | kubectl apply -f -
  wait_for_candidate_condition "$race" Ready True Planned
  race_plan="$(wait_for_candidate_plan_ref "$race")"
  approve_plan "$race_plan"
  kubectl get pgcand "$race" -o json > /tmp/candidate-authority-cas-before.json
  kubectl patch pgcand "$race" --subresource=status --type=merge -p="{\"status\":{\"phase\":\"$phase\",\"executorAuthority\":null}}"
  python3 - <<'PY_CAS' > /tmp/candidate-authority-cas-patch.json
import json
c=json.load(open('/tmp/candidate-authority-cas-before.json'))
s=c['status'].copy(); s.pop('executorAuthority',None)
s['phase']='Planned'
print(json.dumps([
 {'op':'test','path':'/metadata/uid','value':c['metadata']['uid']},
 {'op':'test','path':'/metadata/resourceVersion','value':c['metadata']['resourceVersion']},
 {'op':'add','path':'/status','value':s}]))
PY_CAS
  if kubectl patch pgcand "$race" --subresource=status --type=json --patch-file=/tmp/candidate-authority-cas-patch.json; then
    echo '::error::stale invalidation restored terminal candidate state'; exit 1
  fi
  kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":true}}'
  sleep 4
  test "$(kubectl get pgcand "$race" -o jsonpath='{.status.phase}')" = "$phase"
  test "$(kubectl get pgplan "$race_plan" -o jsonpath='{.status.conditions[?(@.type=="Approved")].status}')" = True
  kubectl delete pgcand "$race" --wait=true
  kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":false}}'
  assert_fresh
done
echo 'Candidate shared preflight, retained review SQL, parent failure freshness and recovery passed.'
