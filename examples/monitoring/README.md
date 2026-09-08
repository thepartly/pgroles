# Optional operator monitoring

The [monitoring guide](../../docs/src/pages/docs/operator-monitoring.md) explains
setup, alert semantics, resource identity, dashboard queries and limitations.
These files use only generic names and install no metrics backend.

- `kustomization.yaml`, `resources.yaml`: optional KSM and Collector workloads.
- `custom-resource-state.yaml`: policy inventory and status extraction.
- `collector.yaml`: OTLP metrics to a Prometheus-compatible scrape endpoint.
- `prometheus.yaml`: example scrape and rule-file configuration to merge.
- `rules.yaml`, `expected.yaml`: alert rules and independent desired inventory.
- `test-rules.py`, `test-extraction.py`: rule and real extraction regression tests.

From the repository root:

```sh
scripts/check-monitoring.sh
SQLX_OFFLINE=true cargo build -p pgroles-operator --example telemetry-smoke
scripts/check-monitoring-e2e.sh
```

The E2E script uses a disposable kind cluster and temporary kubeconfig. It needs
Docker, kind, kubectl and Python 3; it never connects to PostgreSQL. Set
`PGROLES_TELEMETRY_SMOKE_BIN` for a nondefault Cargo target directory.
