---
title: Operator architecture
description: Internal architecture of the pgroles Kubernetes operator.
---

How the pgroles operator watches Kubernetes resources, talks to PostgreSQL, and enforces safe reconciliation. {% .lead %}

---

## Overview

The operator is a Kubernetes controller around the same core model as the CLI:

1. read desired state from a `PostgresPolicy`
2. inspect live PostgreSQL state
3. compute a convergent diff
4. either apply changes in a single transaction or publish a non-mutating plan
5. write status back to Kubernetes

The important difference is that the operator has to do this continuously, safely, and in the presence of concurrent policy updates, secret changes, and transient infrastructure failures.

## Control-plane diagram

{% operator-architecture-diagram /%}

## Main components

### CRD and policy model

`PostgresPolicy` is the operator-facing API. Its spec mirrors the CLI manifest format, with Kubernetes-specific fields for:

- Secret-based connection lookup
- reconciliation interval
- execution mode (`apply` or `observe`) and approval mode (`auto` or `manual`)
- reconciliation mode (`authoritative`, `additive`, or `adopt`)
- suspend/pause behavior

The controller converts the CRD into the same manifest types used by the CLI, so both paths share expansion, diffing, and SQL rendering semantics.

### Watch sources

The operator currently reconciles from four event-driven trigger sources, plus the periodic interval:

- `PostgresPolicy` generation changes
- `PostgresPolicy` `reconcile.pgroles.io/requestedAt` annotation changes
- Secret `resourceVersion` changes for referenced database credentials
- `PostgresPolicyPlan` changes, mapped back to the owning policy by controller-owner UID — this is what makes an approval or rejection recorded on a plan's status take effect immediately rather than at the next interval

Generation and annotation filtering matter. The controller intentionally ignores status-only `PostgresPolicy` updates and unrelated annotation changes as reconcile triggers, otherwise successful status patches and GitOps tracking metadata can create hot loops that starve other policies targeting the same database.

By default these watches cover all namespaces. Setting `WATCH_NAMESPACE` (or
the Helm value `operator.watchNamespace`) scopes every policy, plan, Secret,
access-policy, and access-request watch to one namespace. The chart also reduces
the operator's RBAC to that namespace.

Ephemeral requests share one reflector with a watch-fed index keyed by access
policy name, resolved access-policy UID, and resolved target-policy UID. The
index is refreshed atomically after watcher relists. Controller-owned UID labels
are routing hints for server-side inspection; reconciliation always verifies the
immutable UIDs stored in `status.resolvedAccess`.

### Database connection handling

The operator resolves credentials from a Secret in the same namespace as the
policy — either a whole connection URL via `connection.secretRef`, or individual
`connection.params` fields, each of which may be a literal or its own Secret
reference. It caches `sqlx::PgPool` instances. In URL mode the cache identity is:

```text
namespace / secret name / secret key
```

In `connection.params` mode the key covers every connection field, and the
operator additionally fingerprints the `resourceVersion` of all referenced
Secrets.

When any referenced Secret changes, the controller refetches it and refreshes the cached pool on the next reconcile. This is what enables credential rotation and recovery without restarting the operator.

### Reconcile engine

Each reconcile follows this path:

```text
PostgresPolicy
  -> Secret fetch
  -> PolicyManifest conversion
  -> manifest expansion
  -> live database inspection
  -> diff engine
  -> SQL rendering
  -> apply transaction or plan-only status update
  -> status patch
```

The diff/apply behavior is shared with the CLI. The operator is not a separate implementation of role management logic; it is a controller wrapped around the same core engine.

## Safety model

### Ownership and conflict detection

Multiple policies may target one database, or several databases of one server, when neither can undo the other's work.

A policy claims the lifecycle of the roles it creates, the schemas it declares, and each grant it asserts present or absent. A role it only grants to is a reference. What it can undo follows what it inspects. `adopt` and `authoritative` revoke undeclared privileges of every role they declare, external ones included, in the schemas the policy names, on the database if it declares a database grant, and in the global default privileges of the owners it names. They remove undeclared members of the roles they create and of `exclusive` stanzas. `additive` revokes only what it names. Two policies conflict when their claims overlap, when one asserts present what the other asserts absent, or when one can revoke something the other asserts. The controller reports that as a conflict instead of letting the policies revoke each other's grants. See [policy conflicts](/docs/operator-troubleshooting#policy-conflicts) for the full list.

"The same database" is decided by the server, not by how a policy names it. After connecting, each policy reads `system_identifier`, `inet_server_addr()`, `inet_server_port()` and `current_database()` and records a digest of them in `status.resolved_database_target`, with a second digest that leaves out `current_database()` to identify the server. Policies compare against each other's recorded targets, so two policies reaching one database through different Secrets, or from different namespaces, are checked against each other. The lineage and the address are combined because each alone misleads: a snapshot restore shares its source's `system_identifier`, and unrelated servers in separate networks can share a private address.

Roles, their attributes and memberships live in catalogs that every database of a server shares, so policies on different databases of one server are compared too, on the rules about roles, memberships and retirement. Grants, schemas and default privileges belong to one database, and are compared only between policies on that database.

Two policies that use the same Secret and key in the same namespace are always compared, including before either has connected. A recorded target is ignored once the policy's spec names a different connection from the one it was resolved through. Reaching one server through two different interfaces, such as its private and public address, is not recognised as the same database; the advisory lock below still serializes those reconciles. Policies in `observe` mode and suspended policies are not compared from the other side, since they cannot execute.

Detection has two limits:

- **Policies that have not connected yet.** A policy is compared with a peer through a different Secret or namespace only once that peer has recorded its target. When two such policies start together, or both were reconciling before an upgrade, the first to reconcile can apply once before the second records its target. Both report `ConflictingPolicy` from their next reconcile. The operator does not hold a policy until every peer has resolved, because one peer that cannot connect would then hold every other policy indefinitely.
- **What the operator watches.** An operator only compares policies it can list. With `WATCH_NAMESPACE` set, each install sees its own namespace, so separate namespace-scoped installs that manage one database do not detect conflicts between each other. Run one cluster-scoped operator for a database shared across namespaces, or keep the installs' ownership claims disjoint.

### Per-database serialization

Reconciliation is serialized per database target in two layers:

1. in-process locking to prevent concurrent reconciles in one operator replica
2. PostgreSQL advisory locking to prevent concurrent reconciles across replicas. The key is computed on the server from `current_database()`, so every policy reaching the database contends on it, whichever Secret or namespace it connects through

This is the core safety boundary for production use. It ensures one database target has one active inspect/diff/apply cycle at a time.

### Retry and backoff

The controller uses different retry behavior depending on failure class:

- invalid specs and ownership conflicts: normal reconcile interval
- secret-missing and other non-transient configuration errors: normal reconcile interval
- transient infrastructure/database failures: exponential backoff with jitter
- lock contention: short dedicated retry path

That keeps the operator from hammering the Kubernetes API or the database during persistent misconfiguration.

## Status model

The operator writes status conditions and summaries back to the `PostgresPolicy`, including:

- `Ready`
- `Drifted`
- `Reconciling`
- `Degraded`
- `Conflict`
- `Paused`
- `ApprovalUnset` and `ApprovalIgnored`, which are advisory: they report a
  configuration that will not behave as it looks, not a failed reconcile

It also records:

- last attempted generation
- last successful reconcile time
- last handled force-reconcile annotation timestamp
- managed database identity
- owned roles and schemas
- last error
- transient failure count
- change summary
- last reconcile mode
- current plan reference

This is the main operator-facing debugging surface for SREs. The rendered SQL
lives on the referenced `PostgresPolicyPlan`.

## Observability

The operator exposes:

- `/livez`
- `/readyz`

Metrics are exported through OpenTelemetry OTLP. The intended deployment model is:

```text
pgroles-operator -> OpenTelemetry Collector -> metrics backend
```

The operator deliberately does not default to a built-in Prometheus scrape endpoint.

Ephemeral access uses the same database and advisory locks as durable
reconciliation. Request-owned scoped plans establish execution provenance, and
their active membership edges are composed into the single effective desired
graph before diffing. See [ephemeral access](/docs/ephemeral-access) for the
request, approval, expiry, and session contracts, and
[securing ephemeral access](/docs/ephemeral-access-security) for the deployment
trust and audit boundaries.

For object-local debugging, the controller also emits transition-based Kubernetes Events for notable status changes such as conflicts, suspend/resume, observe-mode drift detection, recovery, secret failures, database connectivity failures, and insufficient privileges. The intended split is:

- status: current state of the policy
- Events: notable transitions visible in `kubectl describe`
- OTLP metrics: fleet-level trends and alerting

## Relationship to the CLI

The CLI remains the simplest path for explicit, reviewed role changes. The operator is the continuous control plane version of the same model.

That split is intentional:

- the CLI is the easiest way to validate and review manifests
- the operator is the right place to enforce drift correction continuously inside Kubernetes

For the external user model, see the [operator guide](/docs/operator). For the shared workspace structure, see the general [architecture](/docs/architecture) page.
