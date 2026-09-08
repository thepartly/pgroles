---
title: Candidates and promotion
description: Preview proposed policy effects and promote reviewed content while the active policy keeps enforcing.
---

For field types, defaults, and admission constraints, see the [CRD API reference](/docs/operator-api-reference).

Review what a change would do to production before it becomes the desired state. {% .lead %}

---

## The review loop

1. Create a candidate from the **complete proposed content**, while the parent keeps enforcing.
2. Read its plan with `pgroles candidate status` and `pgroles candidate diff`.
3. Approve that plan using the authenticated status-decision workflow.
4. Merge exactly the reviewed content into the parent policy.
5. Verify the plan is Applied and the parent has converged. If the effects changed, review the replacement plan.

Approval alone never promotes or executes a candidate. The sections below give
commands for each step, followed by lifecycle and recovery details.


## What a candidate is

A `PostgresPolicyCandidate` is a one-shot, immutable proposal: policy content
that an author wants reviewed against a live database without touching the
`PostgresPolicy` that is enforcing it. The operator plans the candidate in the
active policy's own execution context — same credentials, same advisory lock,
same managed scope — and publishes a `PostgresPolicyPlan` of proposed effects
with the [preview limitations](#preview-limitations) below. The active policy keeps enforcing throughout review. (After
promotion the picture changes if the promotion does not match its approval —
see [Promotion](#promotion).)

A candidate is not a second policy. It carries no interval or mode, and no
connection unless it is explicitly previewing a different target; it can never
execute SQL in any state; and it is terminal once promoted, superseded, stale,
or its plan is rejected. Think of it the way you think of a
`CertificateSigningRequest`: a request for the controller to produce a
reviewable result, not a piece of desired state.

The kinds divide authority. Anyone granted create on candidates can propose;
only whoever can write `PostgresPolicy` (typically your GitOps controller) can
promote; only plan approvers can approve. None of those grants implies the
others.

## Preview limitations

Candidate planning applies the same `preserve_undeclared_grants` filter as the
normal reconciler before generating SQL, the change summary, and the approval
digest. The setting comes from the candidate's proposed roles. It preserves
undeclared object grants; explicit object absence assertions, default privileges,
and memberships retain their normal reconciliation semantics. If only preserved
grants differ, the candidate reports `Ready=True` with reason `NoEffects` and
creates no approval plan.

In v0.11.0, candidate planning omitted this filter and could preview revokes that
the parent would suppress after promotion. This is fixed in the next release.

Candidate planning still omits executor-authority preflight, plan advisory
warnings, and the adopt-mode schema-owner-transfer guard. `Ready=True` means a
preview is available; it does not prove the executor can apply it. Execution
settings such as `allow_schema_owner_transfers` remain on the parent, outside
candidate content.

Promotion recomputes effects and checks the approved digest before execution.
Different effects require a replacement plan; matching effects can still be
blocked by executor privileges or execution settings. Review those prerequisites
separately using [Executor privileges](/docs/executor-privileges), and verify
Applied and parent convergence after promotion.

## Who does what

The intended workflow, end to end:

1. An author (or CI, from a PR branch) files a candidate against the cluster.
2. The operator plans it and publishes the redacted effects.
3. A reviewer approves or rejects the **plan** — this is the single
   operator-checked approval.
4. The pull request merges, promoting the same content into
   `PostgresPolicy.spec`. The merge is *promotion*, not a second approval —
   CI confirms before merge that the PR's content is the content that was
   reviewed (see [Verifying before the
   merge](#verifying-before-the-merge)).
5. The operator executes only when the promoted content digest matches the
   approved candidate and the recomputed effects match the approved change
   digest, verified under the database lock.

Candidates are imperative, CI- or CLI-created objects. They are deliberately
not GitOps-managed: `generateName` does not work with Argo CD or Flux tracking,
and a proposal has no business being continuously re-applied.

## Creating a candidate

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata:
  generateName: orders-change-
spec:
  policyRef:
    name: orders
  content:
    reconciliation_mode: authoritative
    roles:
      - name: reporting-reader
        login: true
    grants: []
    default_privileges: []
    memberships: []
    retirements: []
```

`spec.content` is the exact policy-content schema from `PostgresPolicySpec` —
excluding execution settings: connection, interval, mode, suspend, approval,
and allow_schema_owner_transfers. Those settings come from the parent policy; the connection does too, unless
`spec.target` overrides it (see [Previewing a connection
migration](#previewing-a-connection-migration)). The whole spec is immutable
(`self == oldSelf`); to revise a proposal, create a successor:

```yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata:
  generateName: orders-change-
spec:
  policyRef:
    name: orders
  replaces: orders-change-x7k2p
  content:
    roles:
      - name: reporting-reader
        login: true
        connection_limit: 4
```

`spec.replaces` marks the named earlier draft superseded. Supersession is
always explicit — the operator never infers it from creator identity, because
CI typically files every team's candidates under one service account.

### With the CLI

`pgroles candidate create` files the same object from an ordinary pgroles
manifest: the file you already run `pgroles validate` and `pgroles diff`
against. The file you propose is the file the PR merges:

```shell
pgroles candidate create --policy orders -f policy.yaml
pgroles candidate create --policy orders -f policy.yaml --replaces orders-x7k2p
```

It accepts a bare manifest, a `PostgresPolicy` CR (whose `connection`,
`interval`, `mode`, `suspend` and `approval` are dropped, because a candidate
takes those from its parent), or a `PostgresPolicyCandidate` CR. A manifest key
with no candidate counterpart, such as `auth_providers`, is rejected rather
than filed. A structural CRD schema would prune the key server-side, and the
stored content would then mean something other than the file on disk.

The content is validated locally first, through the same path as `pgroles
validate`, so a candidate the API server would reject on [size
bounds](#limits) fails on your machine with the same field-level message
instead of after a round trip. The object is created with `generateName`, so
two people filing against one policy at the same moment never collide; the
assigned name is printed.

There is no base pin in the spec. The plan records which applied base it was
computed against; staleness is decided semantically from there (see
[Staleness](#staleness-and-revalidation)).

## What the operator does with it

A new candidate enqueues its parent policy. Inside one lock hold, the
operator:

1. reconciles the active policy first, so the candidate is planned against
   post-enforcement reality rather than drift
2. plans the candidate content against that state
3. publishes an operator-owned `PostgresPolicyPlan` bound to the candidate
   (name and UID), its content digest, the target identity, the managed
   scope, and the canonical change digest — and records the applied base it
   observed as provenance (see [Staleness](#staleness-and-revalidation))

Planning writes nothing: no PostgreSQL statements, no generated password
Secrets, no changes to the active policy. Filing a candidate may advance the
parent's scheduled convergence — the reconcile it triggers is the same one the
interval would have run — but no effect of the candidate itself executes.

If the active policy is failing or awaiting its own approval, the candidate
reports `Ready=False` with reason `BlockedByActivePolicy` and is re-planned
when the parent recovers.

```text
NAME                  POLICY   PHASE     CHANGES   PLAN                              AGE
orders-change-x7k2p   orders   Planned   3         orders-change-x7k2p-plan-9f21c4   14s
```

## Reviewing and deciding

The candidate's plan is reviewed and decided exactly like any other
`PostgresPolicyPlan` — same redacted SQL preview, same change summary, same
write-once decision recorded on the plan status with an admission-stamped
`decidedBy`. See [Plan and approval](/docs/operator-plan-approval) for the
decision mechanics and their trust model.

```bash
kubectl get pgcand orders-change-x7k2p -o wide          # phase, plan, digest
kubectl get pgplan orders-change-x7k2p-plan-9f21c4 -o yaml
```

### With the CLI

Three subcommands read the same information without hand-rolled jsonpath:

```shell
pgroles candidate list --policy orders
pgroles candidate status orders-change-x7k2p
pgroles candidate diff orders-change-x7k2p
```

`list` gives one row per candidate for that policy: phase, abbreviated content
digest, plan name, and the `Ready` / `Superseded` / `Promoted` conditions with
their reasons, as listed in the [conditions table](#conditions) below.

`status` expands one candidate: its phase and full digest, its conditions with
messages, and then its plan — the plan's phase, its decision and the identity
that made it, whether it is still current or has been superseded, the applied
base it is pinned to, and any promotion outcome. A candidate with no plan yet
reports that, with the reason, rather than printing a blank plan section.

`diff` prints the proposed plan's SQL on stdout. Approval alone executes nothing;
promotion requires a fresh matching digest and successful execution checks. It reads `status.sqlInline`, falling back to the gzipped
ConfigMap in `status.sqlRef` when the plan is too large to inline. A plan
whose SQL survives only as a truncated preview is an error, not a short diff,
because a partial listing could be read as the full set of statements the
approval would execute.

Each subcommand reports missing state as a specific error rather than output
that could be misread: a policy that does not exist is distinguished from a
policy with no candidates, a candidate with no plan from a plan with no SQL,
and `--replaces` naming a candidate of a different policy is refused.

### Deciding stays `kubectl`-shaped

There is deliberately no `pgroles candidate approve` or `reject`. A decision is
a write to the plan's status subresource, gated by admission so that `decidedBy`
records an authenticated identity rather than an assertion by whoever wrote the
status. A CLI verb in front of that write would obscure which identity
authenticated the decision, and recording that identity unambiguously is the
point of the approval mechanism. See [Deciding a
plan](/docs/operator-plan-approval#deciding-a-plan) for the exact patch, which
is identical for a candidate's plan and a policy's.

Rejection lands on the plan, not the candidate: the plan records
`Denied=True` (phase `Rejected`) and is terminal. The candidate is terminal
too — it has no other plan coming — and reports `Superseded=True` with reason
`PlanDenied`. To propose a revised version, file a successor candidate.

## Promotion

Approval does not change the `PostgresPolicy`. Promotion is the ordinary
GitOps write: the PR carrying the same content merges, the GitOps controller
updates `PostgresPolicy.spec`, and the operator recognises the update as the
approved candidate by digest.

Recognition is exact. The digest is computed over the same canonical form for
both kinds — `PostgresPolicy.spec`'s content fields project into the candidate
content type and are digested through the identical function — so promoting a
candidate's content verbatim yields a byte-identical digest, and anything else
yields a different one. The policy publishes what it recognised in
`status.content_digest`, beside the candidate's `status.contentDigest`.

### The gate

When the promoted content is a candidate whose plan is **approved**, that plan
becomes the policy's plan for this transition. Nothing about execution is
special-cased: the operator takes the reviewed plan — the one carrying the
human decision, the `decidedBy`, the approved change digest and the bound
target identity — and runs it through the ordinary approved-plan path, which
under the database lock re-inspects, recomputes the canonical effects, and
executes only if the recomputed digest equals the approved one.

The property this buys, stated plainly:

> The statements executed are exactly the approved canonical effects,
> recomputed under the lock.

The operator never mints an approval of its own to make a promotion execute.
Adopting the candidate's plan is what makes that possible: transferring an
approval onto a freshly created policy plan would mean writing a decision no
human made, with a `decidedBy` the operator invented.

On success the candidate becomes `Promoted=True` (terminal), its plan reaches
phase `Applied`, and any *other* candidate that was sitting on an approved plan
has that plan retired — phase `Superseded`, condition `Superseded=True` with
reason `SupersededByPromotion` — because its approval was made against a base
this promotion replaced. The decision record on that plan is left exactly as
the reviewer wrote it; retiring a plan never rewrites who decided what.

### Verifying before the merge

There is no `pgroles candidate verify`. The dependable pre-merge check is
equality of the content itself, which is what the digest measures:

```bash
# In CI, on the PR branch: the candidate you filed and the policy you are about
# to merge must carry identical content.
diff <(yq -P '.spec.content' candidate.yaml) \
     <(yq -P 'del(.spec.connection, .spec.interval, .spec.mode, .spec.suspend, .spec.approval) | .spec' policy.yaml)
```

Filing the candidate from the very same file the PR promotes makes this
structural rather than checked. After the merge, the cluster answers directly:

```bash
kubectl get pgcand orders-change-x7k2p -o jsonpath='{.status.contentDigest}'
kubectl get pgr    orders             -o jsonpath='{.status.content_digest}'
```

A CLI subcommand is deliberately absent rather than pending: a faithful digest
has to be computed over the operator's typed content model, and a second
implementation in the CLI would be a second definition of the thing the digest
exists to make unambiguous.

### Edge cases

Defined, not implied — each row is a unit test, and the first three are covered
end to end in the kind E2E:

| What happens | Result |
| --- | --- |
| Promoted content matches the approved candidate | Its plan is adopted and executes under the lock after fresh verification; candidate → `Promoted=True` |
| Promoted content matches a candidate whose plan is *not* approved | Nothing executes on it. The policy falls back to its ordinary manual-plan flow, and the candidate reports `Promoted=False, reason=PromotedWithoutApproval`. It becomes `Promoted=True` once that fresh plan is approved and applied — the content did reach the database, just on a different approval |
| Promoted content was edited after approval (digest mismatch) | Nothing executes. The policy falls back to the manual-plan flow, and the approved candidate reports `Promoted=False, reason=PromotionDigestMismatch` naming the enforcement gap below |
| Promoted content matches no candidate at all | The ordinary policy flow. Nothing is reported, because nothing unusual happened |
| Plan X approved, candidate Y merged | Y promotes and executes; X's plan is retired with `SupersededByPromotion` and X is replanned against the new base |

Two execution modes make the gate moot rather than absent:

- **`approval: auto`** — the policy approves and executes its own plan on every
  reconcile, so there is no approval to gate and the candidate's plan is not
  adopted. Promotion executes immediately, and the bookkeeping still happens:
  the candidate reaches `Promoted=True` once the content is applied.
- **`mode: observe`** — the policy never executes anything, so a promoted
  candidate cannot reach `Promoted`. It reports `Promoted=False,
  reason=PromotionNotExecuted` and stays open; it becomes `Promoted=True` if
  and when the policy is switched to `mode: apply` and the content applies.

Promotion is recognised by digest and not by a one-shot transition, so it
survives an interrupted reconcile: if the SQL executed and the operator
restarted before writing `Promoted=True`, the next reconcile recognises the
same promotion and records it, with nothing to replay because the effects are
already gone.

One honest cost to know: after a mismatched promotion under `apply` +
`manual`, nothing has executed and the database is unchanged — but the merged
spec is now the desired state and is not being converged, so drift against
*either* state goes unreconciled until a fresh plan is approved. That is the
same suspension `apply + manual` has always had; the condition and Event on the
candidate say so in those words. Continued enforcement of the *previous* state
through a failed promotion is what a future Revision model would add.

## Staleness and revalidation

Staleness is semantic, and the applied base is *provenance, not identity*. The
plan records which base it was computed against so you can see what it was
compared to, but that value is not hashed into the change digest — if it were,
every unrelated base edit would invalidate every open candidate. When anything
the plan depends on changes — the applied base, the live database, active
ephemeral overlays — the operator replans the candidate and compares canonical
change digests:

- **identical digest**: the plan and any decision on it are retained; the
  recorded base advances to the one just observed and the revalidation is
  noted. Unrelated base changes and unrelated ephemeral activity do not cost
  you a review round.
- **changed digest**: the plan is superseded with an explicit condition and
  Event, and the fresh plan awaits a fresh decision.

An ephemeral overlay that overlaps the candidate's effects supersedes the plan
with reason `OverlayOverlap`. One that does not leaves the digest identical
and the plan stands — candidates remain usable on policies with active
ephemeral traffic.

After a successful promotion, other candidates against the same policy are
replanned against the new base by the same rule.

## Previewing a connection migration

A candidate may target a different connection than its parent policy, to
inspect what convergence would do on a migration destination before the
active policy follows it:

```yaml
spec:
  policyRef:
    name: orders
  target:
    connectionRef:
      secretName: orders-new-postgres
      key: url
  content: ...
```

A target override changes the execution context, and the contract is
explicit about it:

- **Credentials and connection settings come from the override**, not the
  parent. The referenced Secret must carry credentials for the destination.
- **Locking follows the target.** The advisory lock key is derived
  server-side from the connected database itself (`current_database()`), so
  differently-named Secrets or aliases of the same database contend on the
  same lock. An override that merely aliases the parent's own database is
  detected and shares the parent's lock hold; a genuinely different database
  gets its own advisory and in-process locks — it cannot share the parent's
  lock state, and it does not
  block the parent's reconcile. The enforce-then-plan ordering still applies
  to the parent (it is reconciled first on its own target); the override is
  then inspected separately within the same reconcile.
- **The plan binds the override's target identity**, so it can never be
  promoted onto the current target by accident: the identity check fails
  before execution.

Because of that last point, a target-override plan is a *preview*, not a
migration step. Promoting a migration is a deliberate two-part sequence:
merge the connection change into `PostgresPolicy.spec` so the active policy
points at the destination, then approve a plan computed against the new
target. The override lets you see the destination's diff before committing to
step one; it never performs the cutover itself.

## Retention

Candidates carry an `ownerReference` to their parent policy, and each derived
plan is owned by its candidate, so deleting a candidate cascades to its plan
and that plan's SQL ConfigMap. Pruning therefore decides on the pair, never
the candidate alone. A terminal candidate that owns no `Applied` plan —
superseded proposals of every kind, and promotions whose execution ran on
another plan — is proposal churn, bounded at 10 per policy, oldest first by
creation. A terminal candidate that owns an `Applied` plan is the provenance
of an execution record: it is held to the `Applied` bounds in the table below
— same count, age floor, and ceiling, ordered by when its plan applied — so
filing more proposals can never delete the record of what ran through the
owner object.
`pgroles.io/keep=true` on the candidate **or on its plan** exempts the pair.
Plans also expire after a TTL — an approval is not an indefinite
authorisation.

### What plan retention keeps

Terminal plans are bounded per phase, not as one pool, because the phases are
not worth the same and the cheapest one is generated fastest. Every replan
supersedes its predecessor, so under a single bound `Superseded` records — of
plans that never ran — would evict the `Applied` ones that record what did.

| Phase | Retained | Notes |
| --- | --- | --- |
| `Applied` | 25, and never fewer than 30 days' worth | Hard ceiling of 200 |
| `Failed`, `Rejected` | 10, shared | Why something did not run, and who declined it |
| `Superseded` | 3 | Enough to see what a replan replaced |
| `Pending`, `Approved`, `Applying` | all | Still live; never evicted |

The oldest go first within each bucket. For `Applied`, both the eviction
order and the age floor measure from `status.appliedAt` — not from creation,
since a plan can wait on a reviewer for arbitrarily long before it executes.
A plan applied inside the floor is kept even once the count is exceeded, so
the audit trail spans a stated period instead of however long the policy's
churn rate happens to make it. The ceiling overrides the floor — the floor is
a promise about history, not a licence to keep everything — and a policy applying hard
enough to reach 200 within the floor period will start losing its oldest.

`pgroles.io/keep=true` exempts a plan from every one of these bounds.

### Configuring the bounds

Each bound is operator-level configuration, set by environment variable on the
operator Deployment (`operator.env` in the Helm chart) — the same mechanism as
the `EPHEMERAL_ACCESS_*` ceilings, and the same `s`/`m`/`h` duration syntax:

| Variable | Default | Sets |
| --- | --- | --- |
| `PLAN_RETENTION_APPLIED` | `25` | `Applied` count bound |
| `PLAN_RETENTION_APPLIED_MIN_AGE` | `720h` (30 days) | `Applied` age floor |
| `PLAN_RETENTION_APPLIED_CEILING` | `200` | `Applied` hard ceiling; must be at least `PLAN_RETENTION_APPLIED` |
| `PLAN_RETENTION_DECIDED` | `10` | `Failed` + `Rejected` shared bound |
| `PLAN_RETENTION_SUPERSEDED` | `3` | `Superseded` bound |

An invalid value refuses operator startup with the variable named, rather than
silently running with bounds the environment did not ask for.

There is deliberately no per-policy retention field on `PostgresPolicy`.
Retention caps object growth in the cluster — an operational concern, like the
open-candidate budget and TTL above — not per-policy intent; the per-object
need ("this specific record matters") is what `pgroles.io/keep=true` is for.

## Bounding open candidates

Retention prunes what is already finished. Two separate bounds apply to
proposals that are still open, because planning them is work the parent policy
does while holding its locks. An unbounded number of open candidates would
slow enforcement of the live policy in proportion to how many people are
proposing changes to it.

**A budget.** At most 32 open candidates per policy are planned in one pass.
The oldest are kept: the failure this guards against is a CI loop filing a
candidate per push, and evicting the newest protects proposals already under
review from being displaced by new filings. Nothing is deleted: a candidate
over the budget reports `Ready=False, reason=CandidateBudgetExceeded` and is
planned as soon as enough older proposals are decided or expire.

**A TTL.** An open candidate that nobody decides within 14 days of being filed
is marked `Superseded=True, reason=Expired`: at that point it is abandoned
rather than under review, and retention prunes it in the ordinary way. The TTL
runs from creation and nothing else. Consulting each candidate's plan for a
decision would put per-candidate reads back into the parent's critical
section, which is what these bounds exist to avoid. A proposal that genuinely
is still in flight after two weeks can be labelled `pgroles.io/keep=true`,
which exempts it from the TTL and from retention pruning. It does not exempt
it from the budget: a kept candidate past the budget reports
`CandidateBudgetExceeded` like any other, so the label cannot be used to
enlarge the bound it exists inside.

Planning the candidates that *are* in budget costs one database inspection per
reconcile, not one per candidate: their inspection scopes are unioned, the
database is read once, and each candidate's own scoped inspection is derived
from that read. A candidate with a `spec.target` override is a different
database and still inspects for itself.

## Conditions

`status.phase` is a printable summary; conditions are the source of truth.

| Condition | Meaning |
| --- | --- |
| `Ready=True, reason=Planned` | A current plan exists for this candidate |
| `Ready=True, reason=NoEffects` | The content is already the database's state, so there is nothing to review. Not terminal — the content may diverge again |
| `Ready=False, reason=BlockedByActivePolicy` | Parent is failing or awaiting its own approval; will re-plan |
| `Ready=False, reason=OverlayOverlap` | An ephemeral grant overlaps this candidate's effects; fresh review required |
| `Ready=False, reason=PlanningFailed` | The candidate could not be planned at all; the message carries the error |
| `Ready=False, reason=CandidateBudgetExceeded` | The policy is at its open-candidate budget and older proposals are ahead in the queue. Not terminal, and nothing is deleted — it plans once they are decided or expire |
| `Superseded=True, reason=Replaced` | A successor candidate named this one in `spec.replaces` |
| `Superseded=True, reason=EffectsChanged` | Replanning produced a different change digest; the fresh plan awaits its own decision |
| `Superseded=True, reason=PlanDenied` | The candidate's plan was rejected (terminal) |
| `Superseded=True, reason=Expired` | Nobody decided this candidate within the open-candidate TTL, so it is treated as abandoned (terminal). Label it `pgroles.io/keep=true` to exempt it |
| `Promoted=True, reason=Promoted` | This candidate's content was promoted and executed (terminal) |
| `Promoted=False, reason=PromotedWithoutApproval` | The content was promoted while this candidate's plan held no approval |
| `Promoted=False, reason=PromotionDigestMismatch` | The policy's content changed into something that is not this approved candidate |
| `Promoted=False, reason=PromotionNotExecuted` | The content was promoted into a policy in `mode: observe`, which never executes |
| `Promoted=False, reason=SupersededByPromotion` | Another candidate was promoted; this candidate carries this condition, while its retired plan records the same reason on its own `Superseded=True` condition |

Rejection is recorded on the plan (`Denied=True`, phase `Rejected`); the
candidate reflects it as `Superseded=True, reason=PlanDenied`. Both are
terminal.

`Promoted` is a separate condition from `Ready` deliberately. `Ready` belongs to
the planning lifecycle and is rewritten on every cycle — including with
`BlockedByActivePolicy` the moment a fallen-back promotion opens a plan of its
own, which is exactly when a reviewer needs to read why the promotion did not
execute.

## Limits

`spec.content` collections carry explicit size bounds — 1024 roles, 4096
grants, 63-character identifiers and the rest of the table in the [manifest
reference](/docs/manifest-reference#size-limits). They are required by the
whole-spec immutability rule's CEL cost budget, and they apply to
`PostgresPolicy` too. Content too large to embed has no supported form today;
`spec.contentRef` is planned for that case (see the callout at the top of this
page), with the same digest binding.

`spec.content` also emits no OpenAPI defaults, unlike `PostgresPolicy.spec`.
An API-server default is written into the stored object, so if a default value
ever changed, a stored candidate would keep the old value while the identical
source YAML would now mean the new one — and the stored object's content
digest would no longer match the digest CI computed from that YAML. Omitted
content fields are resolved by the operator instead, identically for policies
and candidates.
