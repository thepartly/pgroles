---
title: Plan and approval
description: Preview changes with observe mode and gate execution behind a reviewed, approved plan.
---

For field types, defaults, and admission constraints, see the [CRD API reference](/docs/operator-api-reference).

Seeing what the operator would do before it does it. {% .lead %}

---

Everything on this page describes shipped behaviour and works today, with one
exception: the items in the callout below, which are marked inline where
they appear.

{% callout type="note" title="Not built yet" %}
These are the only forward-looking items on this page:

- **`pgroles plan ...` and `pgroles candidate ...` CLI subcommands** — the CLI
  has no such commands. `pgroles plan` is an alias of `pgroles diff` and works
  against a database directly, not against a cluster. Use `kubectl` for
  everything on this page, and for candidates too.
- **Content by reference** — `spec.contentRef` on a candidate, for policies too
  large to embed. Inline content is the only supported form today.
- **An `approvedChangeDigest` token on the decision** — pinning the digest a
  reviewer saw into the decision write itself. Today the binding is the plan
  object: a decision applies to whatever digest that plan holds, and a
  supersede retires the plan rather than mutating it.
{% /callout %}

## Observe mode

Set `mode: observe` to let the operator inspect the database, compute the diff,
and publish the planned SQL without executing it.

```yaml
spec:
  connection:
    secretRef:
      name: postgres-credentials
  mode: observe
  approval: manual
  roles:
    - name: preview-user
      login: true
```

In `observe` mode:

- the operator connects to the database and computes the full diff normally
- no mutating PostgreSQL SQL is executed and no Kubernetes Secrets are created
- `status.change_summary` records the pending changes
- `status.current_plan_ref.name` points at the generated `PostgresPolicyPlan`,
  which holds the rendered SQL in `status.sqlInline` or, for larger plans, a
  gzipped ConfigMap referenced by `status.sqlRef`
- `Ready=True` with reason `Planned`; `Drifted=True` while changes are pending

Be clear about what `observe` mode is not: it is a mutable spec field, not a
security boundary. Anyone who can edit the policy can switch it to `apply`,
and the operator still holds whatever database credential it was given. For
deployments where the operator must never write, the guarantee is a
**read-only PostgreSQL credential** — `mode: observe` is what makes running under
one coherent (drift visibility without a stream of permission-denied errors).
For a reviewed apply, use `mode: apply` with `approval: manual`. Use `suspend`
to stop reconciling entirely.

The rendered SQL lives on the plan; follow `current_plan_ref` to it. Small
plans carry it inline:

```bash
POLICY=observed-policy
PLAN="$(kubectl get pgr "$POLICY" -o jsonpath='{.status.current_plan_ref.name}')"
kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlInline}'
```

Plans above the inline size limit leave `sqlInline` empty and set
`status.sqlRef` instead, naming a ConfigMap whose `plan.sql.gz` entry holds
the gzipped SQL — so the command above prints nothing for a large plan.
Fetching that takes a decode step:

```bash
CM="$(kubectl get pgplan "$PLAN" -o jsonpath='{.status.sqlRef.name}')"
kubectl get configmap "$CM" -o jsonpath="{.binaryData['plan\.sql\.gz']}" |
  base64 -d | gunzip
```

A plan whose compressed preview would still exceed the ConfigMap limit sets no
`sqlRef`, and `sqlInline` carries a truncated preview ending in a
`-- truncated: ... --` marker; `status.sqlTruncated` is `true` in that case.
The preview is a review artifact in every case: **pgroles never executes stored
SQL**.

## What executes: mode and approval together

`suspend`, `mode`, and `approval` are three separate gates, checked in that
order. Only the last one is about human review:

| `suspend` | `mode` | `approval` | Plan created? | Mutating SQL executed? |
|---|---|---|---|---|
| `true` | — | — | no | no — nothing reconciles at all |
| `false` | `observe` | *ignored* | yes | **never** |
| `false` | `apply` | `auto` | yes | immediately, plan auto-approved |
| `false` | `apply` | `manual` | yes | only once approved *and* still current |

`approval` has no effect in `observe` mode; a decision recorded on an
observe-mode plan is accepted and does nothing, and the policy reports an `ApprovalIgnored`
condition so this is distinguishable from a stalled operator.

Under `approval: auto` the operator approves its own plan, so an audit trail
never shows an unattributed approval. The `Approved` condition's reason is
`AutoApproved` either way; `status.decidedBy.username` reads
`system:pgroles-operator(auto-approval)` on its own, and the operator's
authenticated ServiceAccount once the admission policy below is installed and
stamping the identity. The mechanism and the identity are separate facts and
each field carries its own.

## Approval identity: the change digest

What a decision approves is the plan's **change digest**: a versioned hash of
the canonical, deterministically ordered typed effects — role lifecycle,
grants, memberships, ownership and default privileges, retirements — bound
together with the reconciliation mode and the [target
identity](#target-identity), physical and logical. The encoding in force is
recorded on the plan as `status.changeDigestEncoding`, currently
`pgroles.io/approval-effect/v3`; digests computed under different encodings are
never comparable, so a plan carrying an older tag is superseded rather than
matched. The managed role and schema sets are also bound directly, so removing
an item from management invalidates an approval even when that ownership change
produces no SQL effect.

The applied base is deliberately *not* a digest input. The plan records which
base it was computed against as provenance, and that record advances whenever
revalidation confirms the effects are unchanged. Hashing the base in would
make every unrelated policy edit invalidate every pending approval, which is
exactly the churn semantic identity exists to prevent. What the base record
does buy is the promotion check: execution requires the promoted content to
match the approved candidate *and* the base to be the one the plan last
revalidated against.

The digest deliberately excludes anything that legitimately differs between
planning and execution: cleartext passwords, SCRAM salts and verifiers, and
renderer-specific SQL text. A password change is identified semantically as
*(role, password source, source version)* — rotating the source Secret
produces exactly one new plan, and re-planning an unchanged source produces
the same digest every time. `status.sqlHash` still exists, but only as a
diagnostic for the preview text; it is never the approval gate.

Full SQL, redacted previews, and execution share the same batch renderer.
Consecutive object revokes attributed to the same grantor share one `SET ROLE`
block. A different grantor or an ordinary statement closes the block, restoring
`connection.params.setRole` when configured, or using `RESET ROLE` otherwise.
The renderer preserves change order; it does not gather non-adjacent operations
by role. Passwords remain redacted in previews and execution logs.

This formatting can change SQL hashes and statement counts without changing the
semantic approval digest. The candidate preservation fix is different: removing
an undeclared revoke changes the effects, so an old approval cannot authorize a
different recomputed plan.

Because identity is semantic, plans survive irrelevant change. A policy
generation bump, an unrelated base edit, or unrelated ephemeral-access
activity re-plans to an identical digest and the pending plan — including a
decision already recorded on it — is retained, with the revalidated
generation noted on its status.

## Plan status fields

The fields on `PostgresPolicyPlan.status` that a reviewer or a runbook reads:

| Field | Meaning |
| --- | --- |
| `phase` | `Pending`, `Approved`, `Applying`, `Applied`, `Failed`, `Superseded`, `Rejected` |
| `conditions` | `Computed`, `Applied`, and the terminal decision conditions `Approved` / `Denied` |
| `decidedBy` | Kubernetes identity (`username`, `uid`, `groups`) that decided the plan. Write-once, and truthful only under the admission layer below |
| `changeDigest` | **The approval identity.** Canonical semantic digest of the typed effects, bound to reconciliation mode and target identity |
| `changeDigestEncoding` | Version tag the digest was computed under — `pgroles.io/approval-effect/v3`. Digests from different encodings never compare equal |
| `targetPhysicalIdentity` | `pg_control_system().system_identifier` read at plan time — the storage lineage the approval is bound to. Absent on engines that do not expose it |
| `targetLogicalFingerprint` | Fingerprint of the resolved connection endpoint (host, port, database) the plan was computed against |
| `physicalIdentityAvailable` | Whether the physical identity was *readable* at plan time. Recorded explicitly so "could not be read" is distinguishable from "this plan predates the field" — the difference is what makes a later downgrade fail closed |
| `revalidatedGeneration` | The owning object's generation the plan was most recently confirmed current against — the policy's for an ordinary plan, the candidate's for a candidate-origin plan. Provenance, never approval identity |
| `revalidatedAt` | When that confirmation last happened |
| `sqlHash` | SHA-256 of the rendered SQL. A diagnostic for the preview only — never the approval gate |
| `sqlInline` / `sqlRef` / `sqlTruncated` | Where the redacted SQL preview lives, and whether it was truncated |
| `changeSummary` / `sqlStatements` | Counts. `sqlStatements` can far exceed `changeSummary.total` when wildcard grants expand |
| `computedAt` / `appliedAt` / `applyingSince` / `failedAt` | Lifecycle timestamps |
| `lastError` | Failure detail when `phase` is `Failed` |

`kubectl get pgplan` shows the phase, the `Approved` condition and the change
counts; `-o wide` adds the change digest, the SQL hash and the statement count:

```bash
kubectl get pgplan -o wide
```

## Deciding a plan

A decision is a **write to the plan's status subresource**: one terminal
condition — `Approved` or `Denied` — and `status.decidedBy`, recorded in the
same write. There are no approval annotations. The `pgroles.io/approved` and
`pgroles.io/rejected` annotations earlier releases used have been removed
outright: setting them now does nothing at all, which is deliberate — a retired
approval mechanism that still worked would be a silent bypass of everything
below.

Approve the plan you reviewed:

```bash
kubectl patch pgplan "$PLAN" --namespace "$NAMESPACE" \
  --subresource=status --type=merge -p '{
    "status": {
      "conditions": [{
        "type": "Approved", "status": "True",
        "reason": "ApprovedByReviewer",
        "message": "reviewed change summary",
        "lastTransitionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }],
      "decidedBy": {"username": "'"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"'"}
    }
  }'
```

Reject it by writing `Denied` in place of `Approved`:

```bash
kubectl patch pgplan "$PLAN" --namespace "$NAMESPACE" \
  --subresource=status --type=merge -p '{
    "status": {
      "conditions": [{
        "type": "Denied", "status": "True",
        "reason": "DeniedByReviewer",
        "message": "not approving this change",
        "lastTransitionTime": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }],
      "decidedBy": {"username": "'"$(kubectl auth whoami -o jsonpath='{.status.userInfo.username}')"'"}
    }
  }'
```

Two mechanics of these commands are worth knowing:

- **A merge patch replaces the whole `conditions` array.** That is harmless
  here — the operator rewrites its own conditions on the next reconcile — but
  it means you must not append a second `Approved` entry alongside the
  `Approved=False` a plan is created with. Two `Approved` entries make the
  terminality rule compare `['Approved','Approved']` against `['Approved']` and
  reject the operator's next write, wedging the plan. If you prefer to preserve
  the operator's other conditions, read the array, drop any `Approved`/`Denied`
  entry, append yours, and write the result back — that is what
  `scripts/e2e-helpers.sh` does.
- **`decidedBy` must land in the same write.** A decision condition without it
  is rejected at admission.

### After a decision

Approval does not execute a stored artifact. On the next reconcile — which the
status write triggers immediately, via the plan watch — the operator takes the
advisory lock, re-inspects, recomputes the effects, and compares the recomputed
change digest and target identity against what the plan bound. On a match it
executes; on any divergence it supersedes the plan before the first statement.
The plan moves `Approved` → `Applying` → `Applied`, and the policy reports
`Drifted=False`.

A rejection is terminal in the same way. The plan records `Denied=True` with
reason `DeniedByReviewer` and moves to phase `Rejected`; `Approved=True` and
`Denied=True` are mutually exclusive and neither can be changed once written.
("Rejected" is the phase; `Denied` is the condition — they always travel
together.) The policy's `status.current_plan_ref` is cleared, and the
replacement plan is created on the *next* reconcile rather than immediately,
which keeps a rejected plan from spinning in a reject-recreate loop. Iterating
means a new plan, not an edited decision.

A rejected or superseded plan leaves **no generated password Secret behind**.
For `password.generate` roles the operator synthesizes material in memory while
planning and creates the Kubernetes Secret only during post-approval execution
— see [Passwords and planning](#passwords-and-planning).

Terminal plans are not kept forever: per-phase bounds prune the oldest, with
`Applied` plans kept the longest. See [what plan retention
keeps](/docs/operator-candidates#what-plan-retention-keeps) for the bounds,
how to configure them, and the `pgroles.io/keep=true` exemption.

### Who may decide

The trust model has two layers, and both matter:

- **CEL validation rules** (shipped in the CRD) make decisions terminal and
  write-once: `Approved=True` and `Denied=True` are mutually exclusive, a
  recorded decision can never change, and `decidedBy` must be written in the
  same operation as the decision.
- **Actor identity requires the admission layer.** CEL cannot see the
  requesting user, so `decidedBy` is truthful only when the shipped Kyverno
  reference policy (or an equivalent mutating webhook) overwrites it from
  admission `userInfo`. That policy also requires the logical `approve` verb on
  the parent `PostgresPolicy`, so patch access to `postgrespolicyplans/status`
  is not by itself authority to approve a database change. Without that layer,
  `decidedBy` is whatever the client asserted and anyone who can patch plan
  status can approve, under any name.

Install it through the chart (`admissionPolicies.enabled=true`, Kyverno 1.18 or
later), or apply `k8s/security/plan-decision-kyverno.yaml` — the same policy,
carrying nothing install-specific. Bind the `pgroles-plan-approver` ClusterRole
to the humans or groups permitted to authorise changes.

### The exemption is part of the boundary

The operator writes plan status too — it opens plans with `Approved=False`,
records a rejection it observed, and auto-approves under `approval: auto` — so
the policy has to let those writes through without the `approve` verb. It
recognises them by asking a `SubjectAccessReview` whether the writer holds the
logical `manage` verb on the parent `PostgresPolicy`. That is the same shape
the ephemeral-access policy uses for controller-owned lifecycle writes.

Keying the exemption on an authorization rather than on a ServiceAccount name
is what makes it safe to ship one policy for every install:

- **it cannot go stale.** A name-based exemption is wrong the moment the
  operator runs under a different name or namespace, and wrong silently: the
  operator's writes are judged as reviewer decisions and plans stall behind an
  admission denial that appears nowhere in the plan's status.
- **a name is not a credential.** An exemption naming an account this cluster
  does not actually run the operator as is a standing bypass of the approve
  check for anyone able to create or impersonate it. A grant cannot be claimed
  by minting an account.
- **it composes.** Several operators, in different namespaces and under
  different names, are all exempt under the one policy.

The exemption is narrow on purpose: it covers the **approve check only**. The
`decidedBy` stamp has no exemption at all, so every newly terminal decision
records the identity the API server authenticated for that write, controllers
included. Holding `manage` lets you decide without a reviewer's permission; it
never lets you name someone else as the decider.

The corollary is that `manage` on `postgrespolicies` is a controller-level
permission. Grant it in the operator's role and nowhere else — the shipped
`pgroles-plan-approver` role deliberately does not carry it, because a reviewer
holding it would be exempt from the very check that role exists to be subject
to. A wildcard rule (`verbs: ["*"]` on `pgroles.io`) confers it too, so avoid
those on roles bound to people.

Approval RBAC is per-kind: granting a team create on policies grants nothing on
plan status. Execution settings (`approval`, managed scope) are
platform-controlled — protect them with an admission policy so a policy author
cannot weaken them in the same edit that introduces a change.

## Plans stay current while awaiting review

A pending plan is revalidated on every reconcile — there is no frozen-plan
window. When the policy, database, target, or overlays change while a plan
awaits a decision:

- **effects unchanged** (identical change digest): the plan is retained and
  `revalidatedGeneration` / `revalidatedAt` advance; the policy's change
  summary and `current_plan_ref` always describe the same plan.
- **effects changed**: the plan is superseded with an explicit condition and
  Event, and a fresh plan is created for review.
- **effects gone**: the plan is superseded and *no* replacement is created — a
  replacement would hold nothing and still demand a decision.

Approving a plan therefore approves what the plan currently shows. If a
supersede races your approval, the decision lands on a plan that is no longer
current and nothing executes — the fresh plan awaits its own decision.

A supersede sets the phase to `Superseded` and writes a `Superseded=True`
condition naming the cause, so the reason a plan you were reviewing disappeared
survives on the object. The phase is what voids the plan — a superseded plan is
never selected for execution. A decision already recorded on it is left exactly
as the reviewer left it, because plan decisions and `decidedBy` are terminal and
write-once; on a plan nobody decided the cause is also stamped on its
`Approved=False` condition:

| Cause | Condition reason | What happened |
| --- | --- | --- |
| Effects changed | `Superseded` | the policy would now produce different effects; a fresh plan is opened |
| Effects cleared | `Superseded` | the changes are no longer pending — applied out of band, or edited away. No replacement |
| Replaced by a newer plan | `Superseded` | a newer plan already holds the current effects |
| Policy stopped planning | `Superseded` | the policy no longer references this plan |
| Target moved | `TargetChanged` and friends (see [below](#target-identity)) | the plan would execute against a different database than the one reviewed |

## Target identity

`DatabaseIdentity` — the Secret name and key a policy points at — says which
*reference* was followed, not which database answered. Repointing that Secret
leaves plan, conflict and lock identity untouched, so the approval identity
binds the database itself, in both of the forms that mean something:

1. **Physical**: `pg_control_system().system_identifier`, recorded on the plan
   as `status.targetPhysicalIdentity`. It answers *same storage lineage?* — it
   survives failover to a streaming replica, and it catches a restore taken
   from a different cluster behind an unchanged endpoint.
2. **Logical**: the resolved connection fingerprint — host, port, database
   name — recorded as `status.targetLogicalFingerprint`. It answers *same
   endpoint?* — which is what catches a clone, a branch, or a replica, since
   those all inherit the parent's `system_identifier`.

Neither is sufficient alone, so both are bound and a change in either fails
closed. The logical half is fooled by connection poolers and DNS; the physical
half is a *lineage* identifier, not an instance one. Credentials are
deliberately excluded from both, so rotating a password or a token does not
invalidate an open approval.

These are not tiers with a fallback. On the research: no mainstream managed
PostgreSQL blocks `pg_control_system()` — it has been executable by `PUBLIC`
since PostgreSQL 9.6, and monitoring tooling such as Datadog's Postgres
integration and `pgmetrics` calls it unconditionally on RDS, Aurora and Cloud
SQL. What lacks it are engines that merely speak the PostgreSQL protocol —
CockroachDB, Spanner's PostgreSQL interface, Redshift, Aurora DSQL — plus
YugabyteDB, where the value carries no meaning. Those targets run on the
logical identity, which is an ordinary configuration rather than a degraded
one. Set `connection.requirePhysicalIdentity: true` where a real PostgreSQL is
expected: the policy then reports `TargetIdentityBlocked` and makes no
progress at all rather than proceeding on the logical answer alone.

Between approval and execution the operator re-reads both identities under the
same lock and compares them to what the plan bound. Anything other than a
match stops the plan before any SQL runs, with an explicit reason on the
condition and a Warning Event:

| Observed | Reason | Result |
| --- | --- | --- |
| Either identity reads differently | `TargetChanged` | plan superseded, fresh plan for review |
| An identity readable at approval is unreadable now | `TargetIdentityUnavailable` | plan superseded — a downgrade is never treated as a match |
| An identity unavailable at approval is readable now | `TargetIdentityAppeared` | plan superseded once; the approval was never bound to it |
| `requirePhysicalIdentity` set, physical identity missing | `PhysicalIdentityRequired` | `TargetIdentityBlocked`; no plan progresses |

A target change is not an error to work around — it flows through the ordinary
supersede-and-review path, and the fresh approval *is* the sanctioned
acknowledgement that the target moved.

Two routine operations move the physical identity legitimately, and both will
invalidate approvals open across them: a **major version upgrade**, because
`pg_upgrade` runs a fresh `initdb` and mints a new `system_identifier`, and a
**blue-green cutover**, where the new colour is a different cluster. This is
the design working: the plan was reviewed against the old database. Re-approve
the plan the operator opens afterwards.

## Passwords and planning

Planning is side-effect free in every mode. For `password.generate` roles the
operator synthesizes in-memory material while planning and creates the real
Kubernetes Secret only during post-approval execution — under `apply +
manual` there is no generated Secret in the cluster until a reviewer has
approved the plan that introduces it, and a plan that is rejected or
abandoned leaves none behind.

The Secret is written immediately *before* the SQL transaction, not after: a
crash between the two then leaves an unused Secret that the next reconcile
adopts, rather than a password committed to the database that exists nowhere
else. If an equivalent Secret already exists — another replica won the race,
or a previous attempt got that far — that Secret's password is the one the
database is set from.

## Execution

Approval never executes a stored artifact. Under the same database and
advisory lock, with no unlock window, the operator re-inspects, recomputes
the effects, and verifies the recomputed change digest against the approved
one. The statements executed are exactly the approved canonical effects
recomputed against the state observed under that lock; any divergence aborts
before the first statement and supersedes the plan.

To review proposed changes *without* editing the active policy at all, see
[Candidates and promotion](/docs/operator-candidates). A promoted candidate
executes through this exact path: the candidate's own reviewed plan becomes the
policy's plan for that transition, and the verification above is what runs.

{% callout type="warning" title="Set `spec.approval` explicitly" %}
`spec.approval` decides whether a human gates SQL execution. When omitted the
operator still infers it from `spec.mode` — `apply` implies `auto`, `observe`
implies `manual` — which leaves the gate invisible on the object. That
inference is deprecated: a policy relying on it reports an `ApprovalUnset`
condition, emits a warning Event, and counts toward
`pgroles.deprecated.approval_unset`. Write the value down explicitly.
{% /callout %}

## Generated-password crash recovery

A generated password Secret is written after approval and before SQL execution. If the operator crashes between those steps, it keeps the Secret and supersedes the old approval because the password source version changed. Review and approve the replacement plan; it reuses that credential. New plans record a diagnostic `passwordSourceDigest`, and superseded plans report `PasswordSourceChanged` when that fingerprint differs. Older plans without the fingerprint still fail closed through the approval digest, with a generic replacement reason.

The plan lifecycle CI suite tests this exact process-crash boundary with an `e2e-fault-injection` build. Ordinary and released images do not compile the crash hook.

## Replacement-plan name collisions

If creating a replacement reports `PlanNameCollision`, the operator retries
without overwriting the existing plan or its decision. Plan names include a
second-resolution timestamp and SQL hash, so different approval contexts can
occasionally produce the same name. An interrupted creation is resumed only
when its persisted spec matches and it has neither computed status nor a
reviewer decision. Normal retries move beyond the naming window; do not delete
an approved or rejected plan to make room for a replacement.
