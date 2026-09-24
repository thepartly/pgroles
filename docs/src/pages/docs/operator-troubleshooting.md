---
title: Operator troubleshooting index
description: Diagnose PostgresPolicy failures from Kubernetes status reasons, plans, Events, and operator logs.
---

Start with the policy, then follow its reason to the failing boundary. {% .lead %}

---

## First five commands

Set the policy name and namespace once:

```bash
NAMESPACE=default
POLICY=my-policy
```

Then collect the controller's view before changing anything:

```bash
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" -o wide
kubectl describe pgr "$POLICY" --namespace "$NAMESPACE"
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{range .status.conditions[*]}{.type}{"="}{.status}{" reason="}{.reason}{" -- "}{.message}{"\n"}{end}'
kubectl get pgplan --namespace "$NAMESPACE"
kubectl get events --namespace "$NAMESPACE" \
  --field-selector involvedObject.name="$POLICY" \
  --sort-by='.lastTimestamp'
```

`status.conditions[].reason` is the primary index below. `status.last_error`
usually preserves the underlying PostgreSQL, Kubernetes, or connection error:

```bash
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{.status.last_error}{"\n"}'
```

For controller-side detail, read the operator log:

```bash
kubectl logs --namespace pgroles-system \
  -l app.kubernetes.io/instance=pgroles-operator \
  --all-containers --tail=200
```

Adjust `pgroles-system` and the instance label if you used different Helm
release or namespace names.

## Reason index

| Reason or symptom | Meaning and next step |
| --- | --- |
| No status, or the policy kind is unknown | CRD, operator Deployment, RBAC, or admission problem. [Diagnose no status](#no-status-or-no-reconcile). |
| `SecretMissing`, `SecretFetchFailed` | A connection or role-password Secret cannot be read. [Check Secrets](#secret-errors). |
| `InvalidConnectionParams` | A structured field or URL is empty or invalid. [Check the connection](#connection-and-authentication). |
| `DatabaseConnectionFailed` | DNS, network, TLS, database, or PostgreSQL login failure. [Check the connection](#connection-and-authentication). |
| `GcpAuthFailed`, `SetRoleFailed` | Workload Identity token or post-login role switch failed. [Check authentication](#connection-and-authentication). |
| `InvalidSpec` | The object passed admission but is not a valid pgroles policy. [Check policy validation](#policy-validation). |
| `AbsenceAssertionsIgnored=True` | The policy uses `ensure: absent` with additive reconciliation, which never revokes. Switch to `adopt` or `authoritative` to enforce it. |
| `InvalidDatabaseTarget` | A database grant names a database other than the one the connection reaches. Set `object.name` to `current_database()`. [Check database objects](#missing-database-objects). |
| `InvalidRoutineTarget` | A function or procedure grant names a routine PostgreSQL cannot resolve. The message lists the input-type signatures to use. [Check database objects](#missing-database-objects). |
| `InsufficientPrivileges` | The executor can connect but cannot inspect or apply an operation. [Check executor privileges](#executor-privileges). |
| `MissingDatabaseObject` | An external object referenced by the policy is absent. [Check database objects](#missing-database-objects). |
| `UnsatisfiableWildcardGrant` | A wildcard matched objects the executor cannot grant on. [Check wildcard grants](#wildcard-grants). |
| `ConflictingPolicy` | Two policies claim overlapping state on the same database. [Resolve the conflict](#policy-conflicts). |
| `UnsafeRoleDrops` | A role drop is blocked by owned objects or other dependencies. [Plan a safe retirement](#unsafe-role-drops). |
| `Planned`, `Drifted=True`, plan `Pending` | A preview or manual approval gate is working. [Inspect the plan](#a-plan-does-not-execute). |
| `ApprovalIgnored`, `ApprovalUnset` | Approval configuration is ineffective or implicit. [Fix the execution gates](#a-plan-does-not-execute). |
| `ApplyFailed`, `DatabaseInspectionFailed` | A transient or uncategorized PostgreSQL operation failed. [Check transient failures](#transient-and-infrastructure-failures). |
| `KubernetesApiError`, `PlanSqlStorageFailed` | Kubernetes state or large-plan storage failed. [Check infrastructure](#transient-and-infrastructure-failures). |
| `LockContention` | Another reconcile owns the same database lock. [Check contention](#lock-contention). |
| `EphemeralAccessCleanupPending` | Deletion is waiting for attached ephemeral-access resources. [Check deletion](#deletion-is-stuck). |

## No status or no reconcile

If `kubectl` does not recognize `PostgresPolicy`, install or update the CRDs.
Helm installs CRDs on the first install but does not upgrade them on
`helm upgrade`:

```bash
kubectl get crd postgrespolicies.pgroles.io
kubectl get crd postgrespolicyplans.pgroles.io
helm status pgroles-operator --namespace pgroles-system
kubectl get pods --namespace pgroles-system \
  -l app.kubernetes.io/instance=pgroles-operator
```

If the object exists but has no status, inspect the operator pod and logs. Check
that its ServiceAccount can `get`, `list`, `watch`, and patch status for the
CRDs, and can read Secrets in the policy namespace. An admission error from
`kubectl apply` happens before the controller sees the object; read that error
directly rather than waiting for a status condition.

## Secret errors

`SecretMissing` means the named Secret or key is absent. Connection URL Secrets
default to the key `DATABASE_URL`; role password keys have their own defaults.
Confirm the reference, namespace, and available keys without printing secret
values:

```bash
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{.spec.connection}{"\n"}'
kubectl get secret --namespace "$NAMESPACE"
SECRET=quick-start-database
kubectl get secret "$SECRET" --namespace "$NAMESPACE" \
  -o go-template='{{range $key, $_ := .data}}{{$key}}{{"\n"}}{{end}}'
```

`SecretFetchFailed` means the Kubernetes read itself failed, or generated-role
password storage failed. Check the operator ServiceAccount permissions and the
specific API error in `last_error`. Updating a referenced Secret's
`resourceVersion` triggers reconnection automatically.

## Connection and authentication

For `InvalidConnectionParams`, inspect `last_error` for the exact field. Common
causes are an empty Secret value, invalid port, invalid `sslMode`, or malformed
URL. For `DatabaseConnectionFailed`, test four boundaries from inside the
cluster: DNS resolution, network reachability, TLS requirements, and the
PostgreSQL username/password/database combination. A host that works on your
laptop may not be reachable from the operator pod.

For `GcpAuthFailed`, verify the Kubernetes ServiceAccount annotation, Workload
Identity binding, Cloud SQL login permission, IAM database username, and token
endpoint response. For `SetRoleFailed`, the login succeeded but
`connection.params.setRole` did not: the authenticated identity must be a
member of the target PostgreSQL role.

See [database connections](/docs/operator-connections) for every connection
shape and the Cloud SQL IAM flow.

## Policy validation

`InvalidSpec` covers policy rules that are more contextual than the CRD schema:
manifest expansion, interval parsing, password rules, and other cross-field
constraints. The condition message names the invalid field or relationship.
Fix the source manifest and re-apply it; do not edit status.

If `kubectl apply` rejects the YAML, that is CRD admission rather than
`InvalidSpec`. Useful distinctions:

- unknown or misspelled fields are rejected by the structural schema
- unquoted role `config` values are rejected because those values are strings
- invalid combinations such as a password on a non-login role may be caught by
  CRD validation or by the reconcile-time validator

Use [the PostgresPolicy resource](/docs/operator-postgrespolicy) and the
[manifest reference](/docs/manifest-reference) to check field spelling and
semantics.

## Executor privileges

`InsufficientPrivileges` means the database credential is valid but cannot
perform the requested inspection or mutation. The PostgreSQL error in
`last_error` identifies the failed operation, such as `permission denied to
create role`.

Do not respond by granting broad privileges blindly. Map the failed statement
to the executor requirements: role management normally needs `CREATEROLE` and
sometimes `ADMIN OPTION`; object grants need ownership or `WITH GRANT OPTION`;
default privileges need membership in their owner role. The complete matrix and
bootstrap SQL are in [executor privileges](/docs/executor-privileges).

## Missing database objects

`InvalidDatabaseTarget` is narrower than a missing object: a `type: database`
grant explicitly names a database other than `current_database()`. Change the
grant target or the connection so those names agree; the operator will not
inspect one database and render ACL changes for another.

`InvalidRoutineTarget` means a function or procedure grant names a routine
that PostgreSQL cannot resolve: an `ensure: present` rule for a routine that
does not exist, a bare name shared by several overloads, or a named-argument
signature spelled differently from the catalog. The condition message lists
the input-type signatures of routines with that name in the schema. Name the
routine by one of them, such as `process(integer)`. See
[function signatures](/docs/grants#function-signatures).

Before issuing DDL, the operator checks external schema references. Schemas
declared in `spec.schemas` are excluded because the operator can create them;
schemas referenced only by grants or default privileges must already exist.

`MissingDatabaseObject` therefore usually means one of three things:

- the policy references a misspelled or not-yet-migrated schema
- the operator should own the schema, but it is not declared in `spec.schemas`
- the connection points at the wrong PostgreSQL database

The same reason can classify PostgreSQL undefined-object errors that pass the
preflight. Read `last_error`, then create or declare the object, remove the
reference, or correct the database connection.

## Wildcard grants

`UnsatisfiableWildcardGrant` is a safety stop. A wildcard matched at least one
table, sequence, or function where the executor lacks the ability to grant the
requested privilege. The operator does not create a partial plan for that
reconcile.

The condition message includes example objects and missing privileges. Give the
executor ownership or the required grant option, narrow the wildcard, or manage
those objects under a different ownership boundary. See
[grants and privileges](/docs/grants) for wildcard semantics.

## Policy conflicts

`ConflictingPolicy` means another `PostgresPolicy` targeting the same database
has overlapping ownership claims. The condition message names the other
namespace/policy and summarizes the overlap.

Keep one policy per database and credential boundary where possible. Otherwise
make their roles, schemas, grants, memberships, and other ownership claims
disjoint. Changing reconcile timing does not solve an ownership conflict.

## Unsafe role drops

`UnsafeRoleDrops` blocks a role removal when PostgreSQL dependencies make a
plain `DROP ROLE` unsafe. Decide explicitly where owned objects should go, then
use a retirement with `reassign_owned_to` and/or `drop_owned` as appropriate.
If active sessions are the issue, a retirement can terminate them when the
executor has the required privilege.

Review the generated SQL in observe mode before approving destructive retirement
steps. Do not remove the safety blocker merely to make the policy green.

## A plan does not execute

First inspect all three execution gates:

```bash
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='suspend={.spec.suspend}{" mode="}{.spec.mode}{" approval="}{.spec.approval}{"\n"}'
```

- `suspend: true` stops reconciliation entirely
- `mode: observe` computes plans but never executes mutating SQL
- `mode: apply` with `approval: manual` waits for a terminal `Approved`
  decision on the current plan's status
- `mode: apply` with `approval: auto` applies without a human gate

Follow the current plan and inspect its phase and conditions:

```bash
PLAN="$(kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{.status.current_plan_ref.name}')"
kubectl get pgplan "$PLAN" --namespace "$NAMESPACE" -o yaml
```

A decision recorded on an observe-mode policy's plan produces `ApprovalIgnored`; switch
the policy to `mode: apply` if you intend SQL to execute. `ApprovalUnset` means
the operator inferred an approval mode from `spec.mode`; set `approval`
explicitly because that inference is deprecated.

If policy or database state changed after review, the approved plan may become
`Superseded`. Review and approve the newly referenced plan. If a plan was
rejected, its replacement is created on the next reconcile rather than in the
same cycle. Reject a plan by writing a terminal `Denied` condition and
`decidedBy` to its status subresource; see [plan and
approval](/docs/operator-plan-approval#deciding-a-plan) for the exact command
and the full lifecycle.

A superseded plan names its cause in the `Superseded=True` condition message —
effects changed, effects cleared, replaced by a newer plan, the policy stopped
referencing it, another candidate's content was promoted and applied (reason
`SupersededByPromotion`), or the target moved (reason `TargetChanged`,
`TargetIdentityUnavailable`, or `TargetIdentityAppeared`).

## Transient and infrastructure failures

`ApplyFailed` and `DatabaseInspectionFailed` preserve the underlying SQL error
in `last_error` and use transient backoff. Check database availability,
failovers, statement cancellation, and network stability before changing the
policy.

`KubernetesApiError` points to API reachability, authorization, or an update
conflict. `PlanSqlStorageFailed` means the operator could not persist a large
SQL preview in its ConfigMap-backed storage. Check API errors, namespace quota,
ConfigMap permissions, and object-size limits. The operator never executes SQL
stored in the ConfigMap; it re-renders from current state before apply.

Use `transient_failure_count` to distinguish a repeating infrastructure problem
from a single retry:

```bash
kubectl get pgr "$POLICY" --namespace "$NAMESPACE" \
  -o jsonpath='{.status.transient_failure_count}{"\n"}'
```

## Lock contention

`LockContention` means another reconcile currently holds the in-process or
PostgreSQL advisory lock for the same database target. The operator retries
after a short jittered delay; an occasional occurrence needs no intervention.

If it persists, look for multiple policies or replicas targeting the same
database and for slow inspection/apply cycles. Do not disable the lock: it is
what prevents overlapping inspect/diff/apply transactions.

## Deletion is stuck

Deleting a policy means “stop managing,” not “undo database changes.” The
finalizer first waits for attached ephemeral-access policies to be removed.
`EphemeralAccessCleanupPending` reports that guarded wait.

Inspect attached `EphemeralAccessPolicy` and `EphemeralAccessRequest` resources,
allow their revocation/finalizers to complete, and then retry deletion. Do not
strip finalizers until you have verified that temporary PostgreSQL memberships
were revoked; forced Kubernetes deletion can otherwise leave access behind.

## Force a fresh reconcile

After fixing the cause, you can wait for `spec.interval`, edit the policy, or
request an immediate reconcile with a unique timestamp:

```bash
kubectl annotate pgr "$POLICY" --namespace "$NAMESPACE" \
  reconcile.pgroles.io/requestedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --overwrite
```

Then re-read conditions rather than relying only on Events. Several reasons,
including `InvalidDatabaseTarget`, `MissingDatabaseObject`, `InvalidConnectionParams`, and
`UnsatisfiableWildcardGrant`, do not emit dedicated Events.
