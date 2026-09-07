---
title: Monitoring the operator
description: Optional Collector and policy-state collection, tested alerts, and dashboard queries.
---

Monitor both operator activity and the policy state stored in Kubernetes. {% .lead %}

## Two independent sources

The operator pushes OTLP metrics to a Collector. Separately, kube-state-metrics
(KSM) watches `PostgresPolicy` resources and exposes their stored state even when
the operator is unavailable. A Prometheus-compatible backend scrapes both and
evaluates rules. No operator `/metrics` endpoint is required.

The optional [monitoring reference files](https://github.com/thepartly/pgroles/tree/main/examples/monitoring)
provide pinned KSM and Collector deployments, read-only RBAC, resource extraction,
scrape configuration, and tested alert rules. They are examples to adapt to your
backend; the chart does not install monitoring dependencies or a backend.

```bash
# Install the version-matched pgroles CRDs first.
kubectl apply -k examples/monitoring
```

This creates a separate `pgroles-monitoring` namespace. KSM receives only list/watch
access to CRDs and policies, without Secret access. For a namespaced installation,
use a Role for policy access in each watched namespace and configure KSM's
`--namespaces`; CRD discovery still requires cluster access. The Collector needs
no Kubernetes API credentials. Add resource limits, network policy, TLS and backend
authentication appropriate to your deployment. The reference receiver and scrape
ports are internal, unauthenticated cluster services.

Merge `prometheus.yaml` into your scraper configuration and load `rules.yaml` and
`expected.yaml` into the rule evaluator. Adjust the `cluster` label consistently
across both scrape jobs and inventory rules. An evaluator must retain that label
when querying multiple clusters. The reference pins name translation to
`UnderscoreEscapingWithoutSuffixes`; other backend conventions may add unit or
counter suffixes, so inspect exported names before reusing queries.

Configure the operator to export metrics only when container logs are already
collected:

```yaml
operator:
  env:
    - name: OTEL_EXPORTER_OTLP_METRICS_ENDPOINT
      value: http://pgroles-collector.pgroles-monitoring.svc:4317
    - name: OTEL_METRICS_EXPORTER
      value: otlp
    - name: OTEL_LOGS_EXPORTER
      value: none
```

The reference Collector accepts metrics only. To export logs through OTLP, add a
logs pipeline and backend exporter, then enable the operator's log endpoint.
Choose one log path to avoid ingesting both stdout and OTLP copies. Lifecycle
audit events require external retention, access controls and a searchable backend;
Kubernetes Events and pod logs alone are not a durable audit archive.

## Resource identity

Metrics and logs share one process resource. Defaults are `service.name` =
`pgroles-operator`, the binary's `service.version`, and a random per-process
`service.instance.id`. `OTEL_RESOURCE_ATTRIBUTES` overrides defaults, then a
nonempty `OTEL_SERVICE_NAME` overrides the service name. Configuration is captured
once when telemetry is enabled; restart the operator after changing it.

Use the chart's commented Downward API example to attach namespace, pod name and
pod UID. A pod UID can override the instance ID when identity should survive
container restarts within a pod. Cluster/environment labels require explicit
configuration or Collector enrichment. The reference Collector copies resource
attributes onto exported series so replicas remain distinguishable. Aggregate
counters with `sum(rate(...))`, applying `rate` before summing to handle independent
resets. Do not put database URLs, SQL, usernames or arbitrary policy contents in
resource attributes.

## Alert semantics

Policy alert identity is `(cluster, namespace, policy, uid)`. Failure reason is
available for investigation, but does not participate in the alert identity; a
reason change cannot reset a continuously unready policy's ten-minute hold.
A recreated name has a new UID and a new lifecycle.

| Situation | Reference behavior |
| --- | --- |
| Ready is false, unknown or absent | Not-ready alert after ten continuous minutes |
| Never reconciled, including absent status | Staleness starts at Kubernetes creation time, not Unix epoch zero |
| Successful reconciliation | Staleness starts at the last success timestamp |
| Suspended policy | Excluded from both policy alerts |
| `mode: observe` or deprecated `plan` | Excluded from both enforcement alerts; use separate advisory drift views |
| Manual approval | Included in not-ready alerts; excluded from staleness because waiting on approval does not necessarily refresh last-success time |
| Policy deleted | Inventory disappears and policy alerts clear; optional desired-policy inventory can report unexpected deletion |
| Long reconcile interval | Set a per-policy staleness grace before enabling alerts |

The default staleness grace is 1,800 seconds, followed by a five-minute hold.
Staleness alerts apply to automatic approval policies. For manual approval, use
a separate plan-age review policy: last-success time can remain old during normal
approval waiting and cannot establish that controller processing has stalled.
Override it with a positive decimal number of seconds, for example:

```yaml
metadata:
  annotations:
    monitoring.pgroles.io/stale-after-seconds: "7200"
spec:
  interval: 1h
```

Use plain seconds, such as `120`, without duration or unit suffixes. KSM accepts
Kubernetes quantities, so `2m` means `0.002` seconds here, not two minutes; `2h`
cannot be extracted and falls back to the default.

This annotation configures the monitoring example, not reconciliation. KSM exports
`spec.interval` as a label; it cannot convert arbitrary duration strings into
seconds. Choose grace longer than the configured interval plus expected processing
and retry time, and manage both settings together. Missing or zero overrides use
the default; invalid nonnumeric values should be rejected by your configuration
validation. Suspension excludes alerts immediately after KSM sees the spec; after
resumption an old last-success timestamp can trigger staleness before the next
success. Use a maintenance silence when that is intentional.

`pgroles_monitoring_expected{cluster="example"}=1` is maintained in the rule
configuration, independently of the operator. It enables missing-runtime and
KSM scrape alerts. Runtime scheduling samples exist even with no policies, so an
empty healthy installation does not require reconcile events. The reference
Collector expires inactive metrics after two minutes; allow this expiration,
scrape/evaluation delays and the five-minute hold before expecting a missing-data
alert. Stopping the backend or evaluator itself needs separate monitoring.

A successful KSM scrape is not proof that all desired policies were extracted.
Enable the commented `pgroles_policy_expected` records in `expected.yaml` for
policies whose presence is required. Manage these records with your desired
policy inventory, and remove them for intentional deletion. The associated alert
catches a missing policy series even when KSM serves HTTP 200. Without independent
inventory, a healthy empty namespace and a silently empty resource watch cannot be
distinguished from these metrics alone.

## Dashboard queries

These queries use the reference Collector's names. Histograms retain milliseconds;
counts are observations, and counters accumulate until process restart. Add cluster
and environment selectors for your installation. Keep instance labels for debugging,
then aggregate across replicas for fleet views.

| Panel | PromQL | Unit |
| --- | --- | --- |
| Watch synchronization | `min by (watch) (pgroles_watch_synced)` | 0 or 1; minimum highlights an unsynchronized replica |
| Controller results | `sum by (controller, result) (rate(pgroles_controller_progress[5m]))` | results/s; quiet controllers can be healthy |
| Reconcile outcomes | `sum by (result, reason) (rate(pgroles_reconcile_total[5m]))` | reconciles/s |
| Reconcile p95 | `histogram_quantile(0.95, sum by (le) (rate(pgroles_reconcile_duration_bucket[5m])))` | ms |
| Inspection p95 by phase | `histogram_quantile(0.95, sum by (le, phase) (rate(pgroles_inspect_duration_bucket[5m])))` | ms |
| Inspected object throughput | `sum by (kind) (rate(pgroles_inspect_items[5m]))` | objects/s, including repeated inspections |
| Synchronous processing p95 | `histogram_quantile(0.95, sum by (le, phase) (rate(pgroles_processing_duration_bucket[5m])))` | ms |
| Runtime scheduling p95 | `histogram_quantile(0.95, sum by (le) (rate(pgroles_runtime_scheduling_lag_bucket[5m])))` | ms |
| Ephemeral revocation p95 | `histogram_quantile(0.95, sum by (le) (rate(pgroles_ephemeral_access_expiry_lag_bucket[5m])))` | ms |
| Planned changes observed | `sum(increase(pgroles_plan_changes[1h]))` | changes counted across observe-mode reconciliations |
| Deprecated approval use | `sum by (inferred) (rate(pgroles_deprecated_approval_unset[5m]))` | reconciles/s, not distinct policies |
| Current failure detail | `pgroles_policy_condition{type="Ready"} == 0` | current state with reason |

A missing ephemeral histogram means no samples were observed; it is not proof of
zero revocation delay. Percentiles can hide rare outliers; also inspect counts,
upper buckets and individual lifecycle logs. Planned changes can be counted again
on successive observe reconciliations and are not unique pending changes.

## Validation

From the repository root, with Docker, Python 3, kind and kubectl available:

```bash
scripts/check-monitoring.sh
SQLX_OFFLINE=true cargo build -p pgroles-operator --example telemetry-smoke
scripts/check-monitoring-e2e.sh
```

The first runs pinned `promtool` checks, including failure-reason changes,
realistic Unix timestamps, missing status, zero success timestamps, recovery,
deletion, suspension, modes, manual approval, long intervals and independent
inventory. Its temporary rule copy shifts `time()` to a realistic epoch while
keeping samples short; production expressions remain unchanged.

The second creates and deletes a uniquely named kind cluster with its own temporary
kubeconfig. It installs the actual CRD, KSM configuration and Collector, verifies
extraction from real policy objects and status updates, and sends an OTLP histogram
through the Collector to assert metric names, values and resource labels. It does
not need a database or apply PostgreSQL changes. The test covers both an OTLP
protocol fixture and the production Rust SDK
via the prebuilt `telemetry-smoke` example, then verifies that both producers'
inactive samples disappear under the reference Collector's two-minute expiration.
Set `PGROLES_TELEMETRY_SMOKE_BIN` when using a different Cargo target directory.

Configuration references:
[KSM custom resource metrics](https://github.com/kubernetes/kube-state-metrics/blob/v2.15.0/docs/metrics/extend/customresourcestate-metrics.md),
[Collector Prometheus exporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.142.0/exporter/prometheusexporter/README.md).
