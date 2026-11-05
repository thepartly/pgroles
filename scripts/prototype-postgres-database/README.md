# PostgresDatabase prototype harness

Throwaway harness for the `PostgresDatabase` prototype (see the ADR draft
issue). It runs a bare `etcd` + `kube-apiserver` (no kubelet), the operator on
the host, and a local PostgreSQL 16 as the shared database.

```shell
# once: etcd v3.5.15 and kube-apiserver v1.31.0 under /opt/k8s, PostgreSQL 16 running
./start-control-plane.sh
cargo run --bin crdgen -- --output-dir /tmp/crds && kubectl apply --server-side -f /tmp/crds
psql -U postgres -c "CREATE ROLE pgroles_executor LOGIN CREATEROLE PASSWORD 'executorpw'" \
     -c "ALTER ROLE pgroles_executor SET createrole_self_grant = 'set, inherit'"
KUBECONFIG=/opt/k8s/state/kubeconfig cargo run --bin pgroles-operator &
./reset.sh && ./scenario.sh
```

`generate.py` derives the team policies from `examples/microservices`.
`last-run.txt` is the output of the run the ADR cites.
