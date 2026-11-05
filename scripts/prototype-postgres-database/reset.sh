#!/usr/bin/env bash
# Return the API server and appdb to an empty state between scenario runs.
export KUBECONFIG=/opt/k8s/state/kubeconfig
for r in $(kubectl get pgr -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}'); do
  kubectl patch pgr -n "${r%/*}" "${r#*/}" --type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null
  kubectl delete pgr -n "${r%/*}" "${r#*/}" --wait=false >/dev/null
done
kubectl delete pgdb,pgplan -A --all >/dev/null 2>&1
su postgres -c "psql -v ON_ERROR_STOP=1 -q" <<'SQL'
DROP DATABASE IF EXISTS appdb;
DO $$ DECLARE r text; BEGIN FOR r IN SELECT rolname FROM pg_roles WHERE rolname ~ '^(team_|alice_|bob_|billing_|shipping_|analytics_)' LOOP EXECUTE format('DROP ROLE %I', r); END LOOP; END $$;
CREATE DATABASE appdb OWNER pgroles_executor;
SQL
