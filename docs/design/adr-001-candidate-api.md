# ADR-001: PostgresPolicyCandidate API

- **Status:** Accepted
- **Date:** 2026-08-15
- **Deciders:** pgroles maintainers
- **Supersedes / superseded by:** —

## Context and constraints

pgroles plans to add a user-created, spec-immutable `PostgresPolicyCandidate`
kind: `spec.content` carries proposed policy content, the operator plans it in
the parent policy's execution context, and a reviewed plan gates GitOps
promotion into `PostgresPolicy.spec`. The end-state behaviour is specified in
`docs/src/pages/docs/operator-candidates.md`. This ADR settles only the API
mechanics that are expensive to change after the kind ships.

Constraints in force at decision time:

- pgroles is pre-1.0 with a small install base. Breaking changes
  are acceptable and preferred over compatibility scar tissue; optimise for the
  long-term API and DX.
- Immutability must hold against the object's own author — reviewers must never
  adjudicate "which version did I approve". Whole-spec CEL immutability
  (`self == oldSelf`) requires every list/map/string in the transitive schema
  to carry explicit bounds for the API server's static cost estimator.
- Promotion integrity rests on a content digest computed over canonical content
  bytes; anything that makes stored content diverge from the authored manifest
  (schema defaulting, type conversion) undermines it.

Relevant current state, verified:

- `PostgresPolicySpec` — `crates/pgroles-operator/src/crd.rs:51-130`. Content
  fields (`profiles`, `schemas`, `roles`, `grants`, `default_privileges`,
  `memberships`, `retirements`, `reconciliation_mode`, `default_owner`) are
  distinct from execution fields (`connection`, `interval`, `suspend`, `mode`,
  `approval`).
- The nested content types are **shared with the CLI** and live in
  `crates/pgroles-core/src/manifest.rs` (`SchemaBinding:278`, `Grant:473`,
  `ObjectTarget:482`, `DefaultPrivilege:497`, `Membership:521`,
  `MemberSpec:534`, `RoleRetirement:560`); `RoleSpec`/`ProfileSpec` are operator
  types (`crd.rs:594`, `crd.rs:545`).
- The generated `PostgresPolicy` CRD has **zero** `maxItems`, `maxLength` or
  `x-kubernetes-validations`: `charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml`.
- The ephemeral kinds are already fully bounded and already use whole-spec CEL
  immutability: `crd.rs:1294` (`Rule::new("self == oldSelf")`), with
  `#[schemars(length(...))]` bounds throughout (`crd.rs:1209-1366`), emitted as
  `maxLength`/`maxItems` in
  `charts/pgroles-operator/crds/ephemeralaccessrequests.pgroles.io.yaml`.

So bounded schemas are already the house style for every kind added after
`PostgresPolicy`; the policy content type is the outlier, not the norm.

## Decision 1 — Do not fork the content schema; bound the shared type

**Decision.** `PostgresPolicyCandidate.spec.content` reuses the exact shared
policy-content type. Domain-derived `maxLength`/`maxItems`/`maxProperties`
bounds are added to that shared type, and therefore apply to `PostgresPolicy`
too. Whole-spec `self == oldSelf` immutability is applied to
`PostgresPolicyCandidate.spec`, matching the ephemeral kinds' existing rule.

### Cost-budget math

Upstream limits (Kubernetes `apiextensions-apiserver` / `apiserver`):

| Limit | Value | When |
| --- | --- | --- |
| `StaticEstimatedCostLimit` | 10,000,000 | per CEL expression, checked at **CRD create/update** |
| `StaticEstimatedCRDCostLimit` | 100,000,000 | total across a CRD's `x-kubernetes-validations` |
| `PerCallLimit` | 1,000,000 | actual runtime cost of one CEL evaluation |
| `RuntimeCELCostBudget` | 10,000,000 | actual runtime cost per custom-resource request |

Sources: `k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation`
(static limits), `k8s.io/apiserver/pkg/apis/cel/config.go` (runtime limits),
the CRD validation-rules KEP
(<https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2876-crd-validation-expression-language>)
and <https://kubernetes.io/docs/reference/using-api/cel/>.

The static estimate for object equality is driven by the schema's declared
bounds: list cost ≈ `maxItems × element cost`; string equality ≈ `maxLength / 8`
cost units. Chosen bounds and their estimated contribution to the single
`self == oldSelf` expression:

| Collection | Bound | Rationale | Est. cost |
| --- | --- | --- | --- |
| identifiers (`role`, `schema`, `name`, owners, members) | `maxLength: 63` | PostgreSQL `NAMEDATALEN-1` = **63 bytes**; longer names are silently truncated by the server | — |
| object names / comments | 256 | qualified names and free text | — |
| `roles` | 1024 | with `config` ≤ 32 entries (key 63 / value 256) | ~1.4M |
| `grants` | 4096 | ≤ 16 privileges each | ~0.3M |
| `memberships` | 2048, `members` ≤ 512 | sized ≥ 20× the largest production policy (99 edges, 21 members) | ~10.5M |
| `default_privileges` | 512, `grant` ≤ 64 | editor+viewer over three object types is ~15 alone | ~1.0M |
| `profiles` | `maxProperties: 128` | grants ≤ 64, defaults ≤ 32, config ≤ 32 | ~0.4M |
| `schemas` | 1024 | 20× 37 observed | ~0.08M |
| `retirements` | 512 | | ~0.05M |

This envelope arithmetic now totals ≈ **14M**, nominally above the 10M static
figure — and the generated CRD is nevertheless accepted by a real API server,
because the upstream estimator does not price nested list equality the way
this per-row arithmetic does (see the pessimism caveats below; the reverse
error also exists). The table's job is to show which bound dominates — the
memberships product — not to predict the estimator; the live-apply gate below
is the authoritative check, and any future raise of the membership bounds is
the first place to expect it to fire.
Runtime cost is computed on the *actual* object, which is bounded by the 1.5MiB
etcd object cap regardless; a realistic 100KB candidate evaluates at ~10⁴ units
against `PerCallLimit` 10⁶. Transition rules skip CREATE, so the rule only runs
on UPDATE — which for an immutable, create-once kind means only on rejected
edits.

**These numbers are an estimate.** The upstream estimator is known to be
pessimistic in specific cases
(<https://github.com/kubernetes/kubernetes/issues/120973>,
<https://github.com/kubernetes/kubernetes/issues/126239>), so the estimate is
not a proof. It is, however, cheaply falsifiable: the API server rejects the
CRD outright at create time if the expression exceeds 10M. **Required gate:**
a CI test that applies the generated candidate CRD to a real API server (the
existing kind-based E2E cluster) and fails on `estimated cost` rejection. Ship
the bounds only behind that test.

### Why bounding the shared type is a benefit, not a tax

1. Unbounded collections in a CRD are a wart in their own right. Every object is
   already bounded by the ~1.5MiB etcd/3MiB request cap — the limit exists, it is
   just implicit and produces an opaque `etcdserver: request is too large`
   instead of a field-level error.
2. Bounds are derived from PostgreSQL, not from CEL: 63-byte identifiers are a
   server limit, not a policy choice. A 1024-role / 4096-grant policy is already
   an order of magnitude above any policy observed in practice.
3. Bounding the shared type unblocks future CEL on `PostgresPolicy` itself
   (cross-field validation, protected-field rules) which is impossible today.
4. Promotion stays a **pure content copy**: `candidate.spec.content` →
   `policy.spec` with no conversion, so the digest binding compares like with
   like. This is the strongest argument. A forked type reintroduces a conversion
   step precisely at the moment the digest must be trusted.

### Rejected alternative: fork the content type

The content types are shared with the CLI's manifest model
(`pgroles-core/src/manifest.rs`) — a fork is not one duplicated struct but a
duplicated subtree plus a conversion layer plus drift risk in the exact code
path whose correctness the digest depends on. Forking buys only the ability to
leave `PostgresPolicy` unbounded, which we do not want.

### Fallbacks, ranked (use only if the CI gate fails)

1. **Per-field immutability**: transition rules on the handful of scalar fields,
   plus content-digest enforcement — cost collapses, immutability guarantee
   weakens to "operator-enforced".
2. **Digest-in-status + admission**: stamp `status.contentDigest` on first
   reconcile and reject spec updates in Kyverno. Weighed and rejected as the
   *primary* mechanism because the chart ships the Kyverno policies
   **default-off**, so this makes immutability depend on an optional
   component — acceptable for `decidedBy` attribution (which CEL genuinely
   cannot do: CEL has no `request.userInfo`), not acceptable for the integrity
   of the reviewed artifact.

**Steady state.** One bounded content type, shared by CLI, policy and
candidate; whole-spec CEL immutability on the candidate; bounds documented as
part of the API contract.

**Migration path and operational risk.** Existing `PostgresPolicy` objects
above the new bounds are rejected on their next apply — a breaking change,
accepted pre-1.0, with bounds set far above observed usage. Bounds must land on
the shared type and in the CLI's validation in the same release as the
candidate kind, and the release notes must call out the new limits.

## Decision 2 — No OpenAPI defaults anywhere under `spec.content`

An earlier working assumption in the candidate design held that serde-level
defaults are invisible to admission. **Verified false**: with the current
schemars/kube-derive setup, `#[serde(default)]` **does** emit OpenAPI `default`
into the CRD — including function-path defaults:

- `interval` → `"default": "5m"` (from `#[serde(default = "default_interval")]`,
  `crd.rs:56`)
- `mode` → `"default": "apply"`, `suspend` → `"default": false`
- and inside content: `reconciliation_mode` → `"default": "authoritative"`,
  `SchemaBinding.role_pattern` → `"default": "{schema}-{profile}"`,
  `RoleRetirement.drop_owned` / `RoleSpec.external` → `"default": false`,
  `default_privileges` → `"default": []`

(all in `charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml`, e.g.
lines 447, 495, 646, 662, 728, 840, 857, 299.)

**Decision.** The candidate's content schema must emit **zero** `default` keys.
Deserialisation-side serde defaults are kept (the operator still needs them);
schemars default emission is suppressed on every content field, enforced by a
golden test asserting no `default` key occurs anywhere under
`spec.properties.content` in the generated CRD. `MemberSpec` already documents
this hazard from the ArgoCD side (`manifest.rs:527-533`) — the same reasoning,
a stronger requirement.

**Why.** Schema defaults are materialised at write time. If
`role_pattern`'s default ever changed, every persisted candidate would carry the
old value while a re-applied manifest defaults to the new one — `self ==
oldSelf` fails on a byte-identical source manifest, and worse, the *content
digest* of a stored candidate would no longer match the digest CI computed from
the same YAML. Optionality must be expressed by `nullable` + resolution in the
operator, never by API-server defaulting.

**Steady state.** Content semantics for omitted fields are defined once, in the
operator/core resolution layer, and are identical for `PostgresPolicy` and
candidates.

**Migration path.** Suppress default emission on content fields when the
candidate kind is introduced; extending the same treatment to `PostgresPolicy`
content fields (so promotion is byte-stable in both directions) is follow-up
work, not a blocker — a policy has no `self == oldSelf` rule today.

## Decision 3 — Ownership, retention, cascade

- Candidate carries an `ownerReference` to its parent `PostgresPolicy`
  (non-controller is unnecessary; controller ref is correct — deleting the
  policy garbage-collects its candidates).
- The derived `PostgresPolicyPlan` is owned by the **candidate**, not the
  policy, so plan pruning cascades from candidate deletion.
- Terminal candidates (`Promoted=True`, `Superseded=True` including
  `PlanDenied`) are eligible for the existing bounded plan-retention loop;
  `pgroles.io/keep=true` exempts an object. Plans keep their TTL — an approval
  is a bounded authorisation, not an indefinite one.
- Cross-namespace refs are not supported: `spec.policyRef` resolves in the
  candidate's own namespace (an owner reference cannot cross namespaces anyway).

**Consequence / operational risk.** Deleting a policy silently deletes open
candidates and their plans. Accepted: a candidate has no meaning without its
base.

## Decision 4 — RBAC and admission boundaries

| Actor | Verbs |
| --- | --- |
| authors / CI | `create`, `get`, `list` on `postgrespolicycandidates`; **no** verbs on `postgrespolicies` |
| approvers | `patch` on `postgrespolicyplans/status` decision fields only |
| GitOps controller | `create`/`update` on `postgrespolicies`; no decision verbs |
| operator | full on plans and candidate status; read on policies |

Separation of duties rests on three cooperating mechanisms: per-kind RBAC
(above), CEL write-once terminality on the decision, and admission-stamped
`decidedBy` (Kyverno). The Kyverno reference policies extend to candidates with
exactly two rules: deny `UPDATE` of `spec` (defence in depth behind the CEL
rule) and deny `create` of a candidate whose `spec.content` sets
platform-controlled execution settings. Because the chart ships the Kyverno
policies **default-off**, the docs must state plainly: without the admission
layer, `decidedBy` is advisory and the author/approver split rests on RBAC
alone.

## Decision 5 — Content-by-reference threshold

**Decision.** Inline content is the only supported form in the first release.
`spec.contentRef` (ConfigMap + `spec.contentDigest`) is specified but not
implemented, with the trigger stated as a rule rather than a byte count: inline
content is supported up to the schema bounds in Decision 1, which fit
comfortably under the 1.5MiB etcd cap (a fully-saturated 1024-role /
4096-grant policy serialises to roughly 1–2MB, so the bounds and the cap are
deliberately the same order). Implement `contentRef` when a real policy first
exceeds ~256KB of content — well before the cap, and the point where API-server
request overhead and `kubectl` ergonomics start to bite.

**Consequence.** Deferring is safe because the digest binding is identical
either way: the digest is over canonical content bytes, not over the object,
so adding `contentRef` later changes transport only.

## Decision 6 — Overlay-overlap boundary

**Decision.** An ephemeral overlay forces fresh review
(`Superseded`/`Ready=False, reason=OverlayOverlap`) iff the set of
**(role, object) pairs touched by active overlay effects** intersects the set of
(role, object) pairs touched by the candidate's diff effects, where:

- *role* is the resolved PostgreSQL role name after profile/pattern expansion
  (not the manifest-level declaration), and role membership edges are normalised
  to the pair `(member, role-as-object)`;
- *object* is the fully-qualified target of the effect, with wildcards expanded
  to the objects observed under the lock at plan time; a schema-level effect is
  the pair `(role, schema)` and intersects any object within that schema;
- *touched* means the effect appears in the plan's canonical effect list —
  grants, revokes, membership add/remove, ownership and default-privilege
  changes. Role-attribute-only changes (`LOGIN`, `CONNECTION LIMIT`, passwords)
  touch `(role, ∅)` and intersect only overlay effects on the same role.

Comparison is on this pair set, not on the change digest: overlays legitimately
change the digest, and the rule must be narrower than "digest changed" so that
policies with continuous ephemeral traffic stay reviewable — blanket
invalidation would make candidates unusable wherever review latency exceeds the
overlay-change interval.

**Consequence.** Wildcard expansion makes overlap dependent on observed database
state, so the same candidate can flip to `OverlayOverlap` when a new object
appears. Correct — that is a genuine change in reviewed effects.

## Decision 7 — Execution preflight and the parent gate

*Added after the kind shipped, before the first release that carries
`status.executionPreflight`.*

**Context.** A candidate's plan was reviewed, approved and promoted, and then
the parent's apply refused it: once because the executor lacked a grantor's
authority, once because adopt mode refused a schema ownership transfer the
production policy did not allow while staging did. Previews had checked only
executor authority, and when the parent itself was refused, previews were
withdrawn — so the repair of a blocked policy could not be previewed at all.

**Decision.**

1. A preview runs every guard the apply runs before it executes anything —
   executor authority, the adopt-mode schema ownership refusal, role-drop
   safety — with the **parent's** execution settings (`mode`,
   `allow_schema_owner_transfers`), which are outside the content and its
   digest and which promotion keeps. The guards are one function in
   `pgroles-inspect`, called by the operator's apply, its candidate previews,
   and the CLI's `apply` and `diff`; no surface decides for itself what a
   guard finds.
2. The result is one status object, `status.executionPreflight`:
   `eligibility` (`Blocked`/`NoKnownBlockers`), `issues` that each name their
   `guard`, `code` and `message`, and the `evaluatedAt`, `parentGeneration`
   and `parentState` it was computed against. Known blockers report
   `Ready=False, reason=ExecutionBlocked` and keep the review SQL.
3. A parent refused by any of those guards has executed nothing — every guard
   precedes the plan's single transaction — and still holds both locks.
   Candidates are planned against the unchanged database and report
   `parentState=ExecutionBlocked`; every other parent failure withdraws the
   result.
4. Execution settings stay on the parent. A gate must evaluate each
   environment's candidate: a preview against one parent is not evidence about
   another with different settings.

**Rejected alternatives.**

- *A status field per guard* (`executorAuthority`, `ownershipTransfer`, …).
  Every consumer would have to know every guard, and a new guard would be a
  new field that old gates silently ignore. One eligibility answer with typed
  issues lets a gate stay correct as guards are added.
- *Copying execution settings into candidate content.* It would make the
  setting reviewable per candidate, but promotion copies content into the
  policy, so a candidate could grant itself `allow_schema_owner_transfers`. The
  setting is an environment decision, not part of a proposal.
- *Keeping previews closed while the parent is blocked.* Safe, but it removes
  the review exactly when a repair needs one, pushing operators to bypass the
  gate.

**Consequences.** `status.executorAuthority` (unreleased) became
`status.executionPreflight`, and `parentState=ExecutorAuthorityBlocked` became
`ExecutionBlocked`. A guard added later appears as a new `guard` value inside
the same object. A preview passing under observe mode says nothing about apply
eligibility; switching mode changes the parent generation and re-evaluates.

## Related decisions recorded here, with recommendations

- **Rename `mode: plan` → `mode: observe`.** *Recommendation: do it, in the same
  breaking release as candidates.* One release absorbs one rename; "plan" then
  names exactly one artifact (`PostgresPolicyPlan`). No shim, no alias, pre-1.0.
  It is a change to `PostgresPolicySpec.mode` (`crd.rs:65`), touching docs,
  samples and E2E — cheap now, expensive after GA. *Status: executed in this
  change set — `mode: observe` is the shipped value across code, CRDs, docs and
  E2E.*
- **Bundle/fragment composition in-cluster?** *Recommendation: composition stays
  a CLI/CI concern that emits a single candidate or policy.* This removes two
  kinds from the target set, keeps the operator free of Git fetching, and keeps
  the content digest computed over one artifact. Recorded as a strong lean, not
  a decision — formal resolution belongs with the composition design.

## Follow-up work and open items

- Confirm the estimated CEL cost via the CI gate in Decision 1; if the gate
  fails, fallback 1 (per-field immutability + digest) applies and this ADR is
  amended.
- Decide whether `PostgresPolicy` content should also drop OpenAPI defaults
  (Decision 2 follow-up).
- Still open elsewhere in the candidate design: the promotion-token variant of
  approval (a digest recorded in `PostgresPolicy.spec`, moving the
  approver/promoter boundary to Git branch protection), and the canonical
  encoding details of the semantic change digest.
