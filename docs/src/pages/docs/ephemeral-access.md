---
title: Ephemeral access
description: Request, approve, and revoke bounded PostgreSQL role memberships.
---

For field types, defaults, and admission constraints, see the [CRD API reference](/docs/operator-api-reference).

Ephemeral access grants an existing PostgreSQL identity one predefined bundle of
role memberships for a bounded duration, then takes it back.

Three resources are involved. A `PostgresPolicy` remains the durable source of
truth for who has standing access. An `EphemeralAccessPolicy` defines a bundle
of memberships that may be requested against that policy, and the ceilings on
how long a grant may last. Each `EphemeralAccessRequest` is one immutable record
of one access request: who asked, for which subject, for how long, who approved
or refused it, and how it ended. Not every request becomes a grant — it can be
denied, or expire before anyone decides.

Two mechanisms are involved, and it is worth keeping them apart. The request
controller performs the grant itself, executing scoped membership SQL under the
same per-database locks the durable policy uses — that is what makes the access
real. Separately, when a `PostgresPolicy` reconciles, active ephemeral
memberships are composed onto its desired role graph, so authoritative
reconciliation sees them as intended state instead of revoking them as drift.
The grant happens without the `PostgresPolicy` ever being edited; the overlay is
what stops the next reconcile from undoing it.

The feature does not issue credentials or implement cloud login — the subject
must already exist as a PostgreSQL role.

{% callout type="warning" title="Requests need a trust boundary before you enable them" %}
Under `approval.mode: Automatic`, anyone who can create a request can grant
themselves the bundle. Under `Required`, approval is a real boundary only with
admission enforcement or a trusted broker in front of it. Read
[securing ephemeral access](/docs/ephemeral-access-security) before allowing
requests in a cluster that matters.
{% /callout %}

## Define a requestable bundle

```yaml
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessPolicy
metadata:
  name: inventory-incident-editor
  namespace: pgroles-system
spec:
  postgresPolicyRef:
    name: production
  memberships:
    - role: inventory-editor
      inherit: false
    - role: audit-viewer
      inherit: false
  maximumDuration: 1h
  defaultDuration: 30m
  pendingRequestTTL: 15m
  justification:
    required: true
  approval:
    mode: Required
```

The target must be a same-namespace `PostgresPolicy` in `mode: apply`. Roles are
concrete names from its expanded graph. The subject already exists; pgroles does
not create a login identity for a request. Ephemeral memberships never include
`ADMIN OPTION`: the subject can use the granted role but cannot grant it to
another role. Durations are one or more integer/unit pairs using `s`, `m`, or
`h` (for example `45s` or `1h30m`); unitless values are rejected.

Setting `inherit: false` creates set-role-only access: the subject must
explicitly run `SET ROLE` rather than inheriting the granted role's privileges
immediately.

Per-membership `inherit` needs PostgreSQL 16 or later. On PostgreSQL 15 and
earlier the option cannot be encoded per grant, so a membership is accepted only
when its `inherit` already matches the subject role's global `INHERIT`; a
mismatch is rejected naming both values. Set-role-only access on those versions
therefore requires a globally `NOINHERIT` subject.

`pendingRequestTTL` defaults to `15m` when omitted: a request that is not
approved within that window becomes `ApprovalExpired` and cannot be revived.

### Cluster ceilings

Two operator environment variables cap what any access policy may ask for. They
are the only cluster-wide limit on ephemeral access, so set them before enabling
the feature — a namespace `ResourceQuota` bounds how many objects exist, not how
long access lasts.

| Variable | Default | Bounds |
| --- | --- | --- |
| `EPHEMERAL_ACCESS_MAXIMUM_DURATION` | `24h` | `spec.maximumDuration` |
| `EPHEMERAL_ACCESS_MAX_PENDING_TTL` | `1h` | `spec.pendingRequestTTL` |

An access policy exceeding either ceiling is rejected with `Accepted=False` and
reason `DurationExceedsClusterMaximum`, so it never becomes requestable. Set them
through `operator.env` in the Helm chart.

## Create a request

```yaml
apiVersion: pgroles.io/v1alpha1
kind: EphemeralAccessRequest
metadata:
  generateName: inventory-incident-editor-
  namespace: pgroles-system
spec:
  accessPolicyRef:
    name: inventory-incident-editor
  subject:
    role: alice@example.com
  requestedBy:
    username: alice@example.com
  requestedDuration: 30m
  justification: Investigating a failed background task
```

`requestedBy` is required so every request is self-describing, but the API
server does not verify it — a caller writing this YAML can put any name in it.
It becomes trustworthy only under the enforcement described in
[securing ephemeral access](/docs/ephemeral-access-security), which also covers
why holding `use` does not by itself constrain which `subject.role` a requester
may name.

The request spec is immutable. The operator resolves concrete memberships into
write-once `status.resolvedAccess`, including the target and access-policy UIDs,
a non-secret fingerprint of the resolved host, port, and database, a versioned
canonical bundle hash, and the granted duration. Credential rotation is allowed,
but changing the resolved host, port, or database blocks activation, durable
reconciliation, and revocation until the original target is restored.

## Approve a request

`approval.mode: Automatic` begins activation after the request resolves. It
removes the decision step, not the need to authenticate and authorize whoever
can create requests.

`approval.mode: Required` waits for one terminal `Approved=True` or
`Denied=True` condition. An approval must attest to the exact resolved bundle
hash and duration. The condition and `status.decidedBy` are recorded together:

```json
[
  {
    "op": "add",
    "path": "/status/conditions/-",
    "value": {
      "type": "Approved",
      "status": "True",
      "reason": "ApprovedByAccessReview",
      "bundleHash": "sha256:...",
      "grantedDuration": "1800s"
    }
  },
  {
    "op": "add",
    "path": "/status/decidedBy",
    "value": {
      "username": "approver@example.com",
      "groups": []
    }
  }
]
```

The CRD makes the decision and the identity terminal — neither can be rewritten
once set. Whether that identity is *authoritative* is a property of your
deployment, not of the CRD; see
[securing ephemeral access](/docs/ephemeral-access-security).

## Request phases

`status.phase` is the field to read when asking what a request is doing. These
are the values you can observe on a live object:

| Phase | Meaning |
| --- | --- |
| `Pending` | Created; the operator has not yet resolved the bundle |
| `PendingApproval` | Resolved, waiting for a decision under `approval.mode: Required` |
| `Applying` | Membership SQL is being executed — after approval, or straight from resolution under `approval.mode: Automatic` |
| `Active` | Membership granted; `status.expiresAt` holds the absolute deadline |
| `Revoking` | The expiry deadline passed; membership is being taken back |
| `Ended` | Reached its expiry *(terminal)* |
| `Cancelled` | The access policy changed or was suspended, or the request expired before activation began *(terminal)* |
| `Denied` | A decision maker refused it *(terminal)* |
| `ApprovalExpired` | No decision within `pendingRequestTTL` *(terminal)* |

Two further phases exist in the API but will not be seen in `status.phase`.
`Revoked` describes deletion, and is written to the audit stream and the request's
Events but deliberately not to an object whose finalizer is about to be removed —
so deletion never passes through `Revoking` either. `Failed` is defined and
classified as a warning, but no code path currently sets it.

That makes failure slightly awkward to watch for. A request whose bundle cannot
be resolved or validated records the reason in `status.lastError` and retries.
An activation or revocation error does neither: the phase is left alone,
`lastError` is not written, the error is logged, and the scoped
`PostgresPolicyPlan` for that request records the failure. So the signal is a
request that stops advancing — sitting in `Applying` or `Revoking` — rather than
any phase or field on the request itself.

`Ended` does not always mean the memberships were revoked. When a membership has
become part of the durable `PostgresPolicy` in the meantime it is kept and
recorded in `status.retainedMemberships`; memberships kept because another active
request still needs them are left in place without being recorded there.

Alongside the phase, `status` carries `approvalExpiresAt`, `activatedAt`,
`expiresAt`, `endedAt`, and `lastError`.

Requests emit their own Kubernetes Events, so `kubectl describe -n <namespace>
ephemeralaccessrequest <name>` shows one request's history directly.

## Expiry and deletion

Activation records the absolute expiry before changing PostgreSQL. Expiry and
request deletion can change only memberships in the approved bundle. A
membership remains while another active request still needs it or when it has
become part of the durable `PostgresPolicy` configuration.

Recovery never resets the absolute deadline. An `Applying` request found after
its deadline is cancelled if SQL never began, or immediately cleaned up if its
activation plan shows that execution may have started. It is never granted a
fresh duration after restart.

Suspending an access policy blocks new activation while active requests run to
their existing expiry. Deleting an access policy deletes and revokes its
requests before the policy finalizer completes. Do not force-remove an active
request's finalizer — that is the one that bypasses revocation, stranding the
membership in PostgreSQL with no request left to take it back.
Authoritative reconciliation of the durable policy can later remove the stray
edge; additive mode may leave it indefinitely.

Deleting a target `PostgresPolicy` first deletes attached access policies and
waits for their request finalizers, keeping the database connection available
until scoped revocation completes. Invalid unresolved requests expose
`Resolved=False`, a reason, and `status.lastError` with a slower retry rather
than remaining silent in `Pending`.

Role retirement is blocked before SQL planning when an active request still
uses the subject or granted role. The target policy error and affected access
policy `RoleRetirementBlocked` condition include the blocking request name and
UID.

## Existing sessions

Revoking membership prevents a fresh `SET ROLE`; it does not terminate a
session which already assumed the granted role. The current session remains
elevated until `RESET ROLE` or disconnect. Further `SET ROLE` attempts,
including from new sessions, are rejected after revocation.

Connection pools therefore need their own bounded-lifetime or eviction policy
when wall-clock session termination is required. pgroles does not implicitly
call `pg_terminate_backend`.

Natural terminal requests remain as Kubernetes operational records. Deletion
is currently the garbage-collection mechanism. Choose explicit retention and
cleanup automation, and follow the [security guide](/docs/ephemeral-access-security)
for durable audit and resource-exhaustion controls.
