---
title: Running the operator
description: Reconciliation triggers, intervals, force reconcile, suspend, reconciliation mode, and deletion behaviour.
---

Day-to-day operation of a running policy. {% .lead %}

---

## Reconciliation

The operator reconciles on five paths:

- `PostgresPolicy` spec changes
- referenced Secret changes
- force-reconcile annotation changes
- `PostgresPolicyPlan` changes, matched back to the owning policy by controller-owner UID — this is what makes approving or rejecting a plan take effect immediately rather than at the next `interval`
- the normal periodic `interval`

Each reconcile inspects the current database state, computes a diff from the policy, and then either applies it or publishes a plan depending on `spec.mode`. Observe mode is non-mutating: it does not execute PostgreSQL DDL and it does not create generated password Secrets. Same-database policies are serialized, and status-only updates do not retrigger the controller.

Use this page for the external behavior and operating model. For the internal controller pipeline and locking model, see the [operator architecture](/docs/operator-architecture) page.

{% operator-reconciliation-diagram /%}

### Reconcile concurrency

Each operator controller runs one reconcile at a time by default. This bounds memory, CPU, and database connection demand when many watched resources become ready at once, particularly during operator startup and watch resynchronization. The limit applies separately to the policy, ephemeral access policy, and ephemeral access request controllers; it is not a single shared global limit. Operators provisioned with more CPU can raise it to process independent databases in parallel.

Set `RECONCILE_CONCURRENCY` on the operator to tune the per-controller limit:

```yaml
operator:
  env:
    - name: RECONCILE_CONCURRENCY
      value: "2"
```

Use a positive integer for bounded concurrency. `0` restores kube-rs's unbounded behavior and should be reserved for controlled troubleshooting. An invalid value prevents the operator from starting and names `RECONCILE_CONCURRENCY` in the error.

### Measuring expensive policies

Inspection metrics include raw `acl_rows`, final `grants`, and concrete
`grantor_keys` under `pgroles.inspect.items`. These are observed counts, not
unique-object totals across reconciles. `pgroles.inspect.duration` separates
`privilege_derive` and `privilege_normalize` from catalog reads.
`pgroles.processing.duration` reports diff and summary construction.
Debug logs report plan rendering time and SQL bytes without logging SQL.

`pgroles.runtime.scheduling_lag` measures delay of a one-second runtime timer.
It helps identify async-worker starvation; it is **not** HTTP health-probe
latency. Correlate it with container CPU throttling, working set, and restarts.

ACL derivation runs on one bounded blocking worker per process. Concurrent
callers share snapshots through `Arc`; increasing reconcile concurrency does
not increase the number of simultaneous derivations. It can still increase
memory held by reads and queued snapshots. Keep the serial default on small
CPU allocations and validate the complete workload before raising it.

## Interval

The `interval` field controls how often the operator re-reconciles, even when the resource hasn't changed. This catches drift from manual SQL changes. Supports durations like `30s`, `5m`, `1h`, or compound forms like `1h30m`. Defaults to `5m`.

## Force reconcile

Set `reconcile.pgroles.io/requestedAt` to a new RFC 3339 timestamp to request an immediate reconcile without changing `spec`:

```shell
kubectl annotate postgrespolicy my-policy \
  reconcile.pgroles.io/requestedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --overwrite
```

The same timestamp is idempotent. Re-setting it is a no-op, while setting a newer value bypasses the normal `interval` wait. The operator mirrors the value to two status fields, which scripts and runbooks use to know where the request stands:

| Field | Set when the requested reconcile |
| --- | --- |
| `status.lastAttemptedReconcileAt` | has run, whatever its outcome — including a suspension, conflict or refusal such as `ExecutorAuthority`. The conditions written with it are that run's result |
| `status.lastHandledReconcileAt` | reconciled or produced a plan |

A request that only met lock contention has not run yet and sets neither.

The CLI wraps the same annotation flow:

```shell
pgroles reconcile postgrespolicy/my-policy -n platform --wait
```

## Suspending

Set `suspend: true` to pause reconciliation without deleting the resource. The operator will skip the resource until `suspend` is set back to `false`.

## Reconciliation mode

The `reconciliation_mode` field controls how aggressively the operator converges the database, independent of `mode` (which controls whether changes are applied or only planned).

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  reconciliation_mode: additive  # only grant, never revoke
```

| Value | Behavior |
| --- | --- |
| `authoritative` (default) | Full convergence — anything not in the manifest is revoked or dropped |
| `additive` | Only grant, never revoke — safe for incremental adoption, and it leaves pre-existing role attributes/comments unchanged |
| `adopt` | Manage declared roles fully, but never drop undeclared roles |

This is the same behavior as the CLI `--mode` flag. See the [CLI reconciliation modes](/docs/cli#reconciliation-modes) section for detailed semantics.

Under `adopt`, an apply-mode policy **refuses** to transfer schema ownership (`ALTER SCHEMA ... OWNER TO ...`) on a schema whose live owner differs, surfacing an `OwnerTransferBlocked` condition — matching the CLI's `--allow-schema-owner-transfers` refusal. Set `spec.allow_schema_owner_transfers: true` to permit the transfers, use `additive` to skip them, or declare each schema's current owner. Observe-mode policies keep producing plans for review either way.

## Deletion behaviour

When a `PostgresPolicy` resource is deleted, the operator **does not** revoke grants or drop roles. The database is left as-is. This is intentional — resource deletion means "stop managing", not "undo everything".
