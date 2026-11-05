#!/usr/bin/env bash
# Drive the PostgresDatabase prototype through a multi-team scenario and
# assert outcomes in Kubernetes and in PostgreSQL.
set -uo pipefail
S=$(cd "$(dirname "$0")" && pwd)
export KUBECONFIG=/opt/k8s/state/kubeconfig
REPO=/home/user/pgroles
PSQL() { su postgres -c "psql -d appdb -v ON_ERROR_STOP=1 -qtAX -c \"$1\""; }
pass=0; fail=0
check() { # description, expected, actual
  if [ "$2" = "$3" ]; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1 (expected '$2', got '$3')"; fail=$((fail+1)); fi
}
wait_for() { # description, command, expected, timeout
  for _ in $(seq 1 "$4"); do [ "$(eval "$2" 2>/dev/null)" = "$3" ] && { echo "  ok    $1"; return 0; }; sleep 1; done
  echo "  TIMEOUT $1 (last: $(eval "$2" 2>/dev/null))"; return 1
}
verdict() { kubectl get pgr -n "$1" "$2" -o jsonpath='{.status.conditions[?(@.type=="Accepted")].reason}'; }
db_ready() { kubectl get pgdb -n platform appdb -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'; }
# Ready for the policy's current generation, not a stale one.
policy_live() { kubectl get pgr -n "$1" "$2" -o jsonpath='{.metadata.generation}={.status.observed_generation}/{.status.conditions[?(@.type=="Ready")].status}' | awk -F'[=/]' '{print ($1==$2 && $3=="True") ? "live" : "pending"}'; }

echo "== 1. Platform registers appdb; three teams attach bootstrap policies"
kubectl apply -f "$S/00-base.yaml" >/dev/null
kubectl apply -f "$S/05-database.yaml" >/dev/null; sleep 1
kubectl apply -f "$S/10-platform.yaml" >/dev/null; sleep 1
kubectl apply -f "$S/20-billing-bootstrap.yaml" >/dev/null; sleep 1
kubectl apply -f "$S/30-shipping-bootstrap.yaml" >/dev/null
for p in platform/team-roles billing/billing shipping/shipping; do
  wait_for "$p live" "policy_live ${p%/*} ${p#*/}" live 120
done
check "billing schema owned by billing_migrator" billing_migrator "$(PSQL "select nspowner::regrole from pg_namespace where nspname='billing'")"
check "alice_payments is in team_payments" t "$(PSQL "select pg_has_role('alice_payments','team_payments','MEMBER')")"

echo "== 2. Teams run their migrations, then attach full policies"
# Shipping's migration references billing.invoices, which only billing's full
# policy opens to shipping_migrator: a dependency between two teams' policies.
su postgres -c "psql -d appdb -qX -c 'SET ROLE billing_migrator' -f $REPO/examples/microservices/migrations/billing.sql" >/dev/null
kubectl apply -f "$S/20-billing.yaml" >/dev/null
wait_for "billing/billing live at its new generation" "policy_live billing billing" live 120
check "shipping_migrator may reference invoices (granted by billing)" t "$(PSQL "select has_table_privilege('shipping_migrator','billing.invoices','REFERENCES')")"
su postgres -c "psql -d appdb -qX -c 'SET ROLE shipping_migrator' -f $REPO/examples/microservices/migrations/shipping.sql" >/dev/null
kubectl apply -f "$S/30-shipping.yaml" >/dev/null
wait_for "shipping/shipping live at its new generation" "policy_live shipping shipping" live 120
check "billing_worker cannot insert invoices" f "$(PSQL "select has_table_privilege('billing_worker','billing.invoices','INSERT')")"
check "billing_api cannot read shipments" f "$(PSQL "select has_table_privilege('billing_api','shipping.shipments','SELECT')")"
check "shipping_reports can read shipments" t "$(PSQL "select has_table_privilege('shipping_reports','shipping.shipments','SELECT')")"
check "team_payments (platform-owned) can read invoices via billing's grant" t "$(PSQL "select has_table_privilege('team_payments','billing.invoices','SELECT')")"
check "team_payments CONNECT, granted by platform" t "$(PSQL "select has_database_privilege('team_payments','appdb','CONNECT')")"
check "attached policies accepted" "3" "$(kubectl get pgdb -n platform appdb -o jsonpath='{.status.acceptedPolicies}')"
check "billing policy mirrors composed readiness" True "$(kubectl get pgr -n billing billing -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"

echo "== 3. Rogue and careless policies attach"
kubectl apply -f "$S/40-rogue.yaml" >/dev/null
wait_for "rejections recorded" "kubectl get pgdb -n platform appdb -o jsonpath='{.status.rejectedPolicies}'" 4 60
check "billing/escalate rejected" OutOfScope "$(verdict billing escalate)"
check "analytics/reporting rejected" NotDelegated "$(verdict analytics reporting)"
check "shipping/open-up rejected" OutOfScope "$(verdict shipping open-up)"
check "billing/late-duplicate rejected" Conflicted "$(verdict billing late-duplicate)"
check "earlier billing policy still accepted" Accepted "$(verdict billing billing)"
sleep 20
check "database stays Ready despite rejected newcomers" True "$(db_ready)"
check "no escalation reached PostgreSQL" f "$(PSQL "select exists(select 1 from pg_roles where rolname='billing_escalator')")"
check "billing_api is not superuser" f "$(PSQL "select rolsuper from pg_roles where rolname='billing_api'")"
check "PUBLIC did not get CREATE" f "$(PSQL "select has_database_privilege('public','appdb','CREATE')")"

echo "== 4. Credentials"
check "database Secrets outside platform namespace" "" "$(kubectl get secret -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{end}' | tr ' ' '\n' | grep -v '^platform$' | grep -v '^$' | tr -d '\n')"
check "one operator-owned policy reconciles appdb" "appdb-composed" "$(kubectl get pgr -n platform -l pgroles.io/composed-for=appdb -o jsonpath='{.items[*].metadata.name}')"

echo "== 5. A rejected newcomer is fixed and accepted"
kubectl delete pgr -n shipping open-up >/dev/null
wait_for "rejections drop to 3" "kubectl get pgdb -n platform appdb -o jsonpath='{.status.rejectedPolicies}'" 3 60

echo "== 6. Billing pushes an out-of-scope edit while a squatter waits for billing_api"
kubectl patch pgr -n billing billing --type=json -p '[{"op":"add","path":"/spec/memberships","value":[{"role":"team_payments","members":[{"name":"billing_api"}]}]}]' >/dev/null
wait_for "billing edit rejected, previous generation retained" "kubectl get pgr -n billing billing -o jsonpath='{.status.conditions[?(@.type==\"Accepted\")].message}' | grep -c 'still applied'" 1 60
check "squatter still rejected" Conflicted "$(verdict billing late-duplicate)"
check "composed policy still declares billing_migrator" 1 "$(kubectl get pgr -n platform appdb-composed -o jsonpath='{.spec.roles[*].name}' | tr ' ' '\n' | grep -cx billing_migrator)"
sleep 20
check "database stays Ready" True "$(db_ready)"
check "billing_api still reads invoices" t "$(PSQL "select has_table_privilege('billing_api','billing.invoices','SELECT')")"
check "billing_api not superuser" f "$(PSQL "select rolsuper from pg_roles where rolname='billing_api'")"
check "out-of-scope membership not applied" f "$(PSQL "select pg_has_role('billing_api','team_payments','MEMBER')")"
kubectl patch pgr -n billing billing --type=json -p '[{"op":"remove","path":"/spec/memberships"}]' >/dev/null
wait_for "billing accepted again after the fix" "policy_live billing billing" live 90

echo "== 7. (observation) Shipping deletes its policy"
kubectl delete pgr -n shipping shipping >/dev/null
sleep 45
echo "  composed Ready: $(kubectl get pgr -n platform appdb-composed -o jsonpath='{.status.conditions[?(@.type=="Ready")].reason}: {.status.conditions[?(@.type=="Ready")].message}' | cut -c1-300)"
echo "  shipping roles left in PostgreSQL: $(PSQL "select string_agg(rolname, ',') from pg_roles where rolname like 'shipping_%'")"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
