# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Owner-inherent ACL entries are no longer revocable state.** PostgreSQL records the owner's implicit privileges (`arwdDxtm`) in a relation's ACL as soon as any grant materializes it. Inspection read that entry back as explicit granted state, so convergence planned `REVOKE`s against table owners for privileges nobody had granted — including `TRUNCATE`, `REFERENCES`, and `TRIGGER` — and applying such a plan broke the owner's DML and foreign-key key-share checks. Inspection now tags owner-grantee entries across relations, schemas, functions, types, and databases as *inherent*: the diff engine never revokes them (`ensure: absent` included), treats them as covering any declared grant on the same target so manifests that declare privileges on an owner's own objects still converge, and `pgroles generate` never exports them. (#201)

### Added

- **Plan-time warnings for silently-destructive policy shapes.** `diff`/`apply` warn when adopt mode transfers schema ownership away from the live owner (adopt filters role drops, not ownership convergence), and — in both the CLI and the operator — when `default_owner` names a role the policy never declares, since every un-owned schema binding silently resolves to it while the role's own privileges stay uninspected. (#201)

## [0.10.0-alpha.1] - 2026-08-21

### Added

- **`PostgresPolicyCandidate`: propose and review policy content without touching the live policy.** A candidate points at an existing `PostgresPolicy` and carries only proposed content — roles, grants, memberships. Everything about execution (interval, mode, approval and, unless `spec.target` overrides it for a preview, the connection) comes from the policy it points at. Once created, a candidate cannot be edited — the API server rejects the write — so the version reviewed is exactly the version approved. To revise a proposal, file a successor:

  ```yaml
  apiVersion: pgroles.io/v1alpha1
  kind: PostgresPolicyCandidate
  metadata:
    generateName: orders-change-
  spec:
    policyRef:
      name: orders
    replaces: orders-change-x7k2p   # marks the earlier draft superseded
    content:
      roles:
        - name: reporting_reader
          login: true
  ```
  (#182, #173)

- **Candidates are planned inside the parent policy's reconcile.** Each open candidate gets its own `PostgresPolicyPlan`, computed with the parent's credentials and locks against post-enforcement database state, and reviewed and decided exactly like any other plan. Candidate planning never writes: no SQL in any state, and no generated-password Secrets. While the parent is failing or has a plan of its own awaiting a decision, candidates wait with `Ready=False, reason=BlockedByActivePolicy`; an active ephemeral grant that touches a candidate's effects sends its plan back for fresh review with `OverlayOverlap`. (#182, #173)

- **Promotion: merging an approved candidate's content makes its reviewed plan the one that executes.** When a policy's content digest matches an approved open candidate, the operator adopts that candidate's plan — it never mints an approval of its own — and executes only if the effects recomputed under the lock still match the digest that was approved. Anything that is not a clean promotion is reported on the candidate rather than ignored: merged without approval (`PromotedWithoutApproval`, the ordinary manual flow takes over), content edited after approval (`PromotionDigestMismatch`, nothing executes and the message says the merged spec is not being enforced), or a parent in `mode: observe` (`PromotionNotExecuted`). The [candidate docs](https://thepartly.github.io/pgroles/docs/operator-candidates/) give the `kubectl` and CI recipes for the whole flow. (#182, #173)

- **`pgroles candidate` covers the review side of the candidate workflow, so proposing and reading a change no longer means hand-rolling jsonpath.** `create` files a candidate from the ordinary manifest your PR promotes — validated locally through the same path as `pgroles validate`, so a proposal the API server would reject on size bounds fails on your machine with the same field-level message, and created with `generateName` so two people filing against one policy never collide. `list` shows every candidate for a policy with its phase, digest, plan and condition reasons; `status` expands one of them down to its plan's decision, who made it, whether it is still current, and what promotion had to say; `diff` prints the SQL approving it would run, reading the gzipped ConfigMap when the plan is too large to inline. Each command fails with a specific reason rather than printing something misreadable — a plan that stores only a truncated preview is an error, not a short diff. Deciding a plan stays `kubectl`-shaped on purpose: it is a status write gated by admission so `decidedBy` records an authenticated identity, and a CLI verb would blur who authenticated it. (#189)

- **Approvals are bound to the database they were reviewed against, not just the Secret that reaches it.** Every plan records the server's physical identity (`pg_control_system().system_identifier`, the storage lineage) and a logical fingerprint of the resolved host, port and database, and both are part of the approval digest. If either changes between approval and execution — or the physical identifier was readable at approval and is not at execution — the plan is superseded instead of executed. Set `spec.connection.requirePhysicalIdentity: true` to stop reconciliation entirely (`TargetIdentityBlocked`) when the identifier cannot be read, e.g. on engines that only speak the PostgreSQL protocol. (#180, #173)

- **Owner-wide default privileges.** `default_privileges` entries accept `scope: {type: global}` beside the existing `schema:` shorthand, emitting `ALTER DEFAULT PRIVILEGES FOR ROLE ...` with no `IN SCHEMA` clause. PostgreSQL keeps default privileges in two layers, and only the global one applies to every schema an owner creates objects in — including schemas no policy manages. Inspection reads the global layer for exactly the `(owner, object type)` pairs a manifest declares, reporting the *effective* default so a database with no explicit `pg_default_acl` row still compares against what PostgreSQL will apply. Owner self-entries are excluded, because every `ALTER DEFAULT PRIVILEGES` materializes the owner's implicit self-grant into the stored row and reporting it would make authoritative mode revoke the owner's own default on the next reconcile. Global changes are counted on their own line in `diff` output, and in a bundle only the document owning the owner role may declare them. See [default privileges](https://thepartly.github.io/pgroles/docs/default-privileges/).

- **`ensure: absent` and a typed `PUBLIC` grantee.** PostgreSQL grants `EXECUTE` on every function to `PUBLIC` without writing an ACL entry, so no combination of positive grants could take it away — a `SECURITY DEFINER` routine stayed callable by every role. Grant entries and default-privilege entries now accept `ensure: absent`, which revokes a privilege where it is held, and `role: PUBLIC` addresses the pseudo-role (rendered unquoted, never as the identifier `"PUBLIC"`). Inspection reports PUBLIC's *effective* privileges, synthesizing `acldefault(...)` where the ACL is still NULL, so a fresh database plans the revoke it needs. Pair an object-level absence rule with a global default-privilege one to cover both today's objects and tomorrow's. **PUBLIC is reconciled only where a rule names it**, in every mode: a PUBLIC privilege no rule mentions is never revoked, and deleting a `present` PUBLIC rule does not revoke it — switch the rule to `ensure: absent`. `additive` ignores absence assertions with a warning, since it never revokes; `adopt` and `authoritative` apply them. A profile is an additive template, so a profile grant or default privilege that sets `ensure: absent` is rejected by name instead of expanding to its opposite. Preflight warns on `diff` and dry runs, and blocks a real apply, when the executor cannot act as a default-privilege owner or cannot revoke on objects it does not own — a PUBLIC revoke without that authority silently changes nothing and would otherwise re-plan forever. See [grants](https://thepartly.github.io/pgroles/docs/grants/) and [default privileges](https://thepartly.github.io/pgroles/docs/default-privileges/).

### Changed

- **Plan retention is bounded per phase, so replan churn no longer evicts the record of what ran.** Terminal plans were trimmed as one pool of 10 by creation time. `Superseded` is generated churn — every replan supersedes its predecessor — so on an active policy it filled the pool and deleted the `Applied` plans, which are the audit record of what actually executed against the database. The least informative state was evicting the most informative one. The bounds are now `Applied` 25 (never fewer than 30 days' worth, hard ceiling 200), `Failed` and `Rejected` 10 shared, `Superseded` 3; `Pending`, `Approved` and `Applying` are live and never evicted. The age floor makes the retained span a stated period rather than a function of how often a policy applies, and the ceiling stops that promise becoming unbounded growth. `pgroles.io/keep=true` still exempts a plan from every bound. Each bound is operator-level configuration — `PLAN_RETENTION_APPLIED`, `PLAN_RETENTION_APPLIED_MIN_AGE`, `PLAN_RETENTION_APPLIED_CEILING`, `PLAN_RETENTION_DECIDED`, `PLAN_RETENTION_SUPERSEDED` on the operator environment, replacing the `max_plans` parameter that nothing could ever set — and an invalid value refuses operator startup with the variable named. Deliberately not a `PostgresPolicy` field: retention caps object growth in the cluster, and the per-object need is what the `keep` label is for. The `Applied` bounds measure — and order — by `status.appliedAt`, not object creation, so a plan that waited on a reviewer is not already outside its floor the moment it executes. They also govern terminal-candidate pruning: deleting a candidate cascades to the plan it owns, so a promoted candidate owning an `Applied` plan is held to the `Applied` bounds instead of the flat terminal-candidate bound, and `pgroles.io/keep=true` on either the candidate or its plan exempts the pair. (#194)

- **Bundle plan JSON is now `pgroles.bundle_plan.v2`.** Default-privilege changes and their ownership keys carry a tagged `scope` (`{"type": "schema", "schema": "app"}` or `{"type": "global"}`) in place of the bare `schema` string, which could not express a global rule. **Migration:** read `scope.schema` where you read `schema`, and handle `scope.type == "global"` entries having no schema at all.

- **`diff --format json` carries the same tagged `scope` on default-privilege changes.** Unlike bundle output it has no `schema_version` field to bump, so nothing announces the change in the payload itself. **Migration:** the same one as above — read `scope.schema` where you read `schema`, and handle `scope.type == "global"` entries having no schema. This output is a bare array of changes and stays unversioned for now, so treat its shape as unstable and pin the pgroles version if you parse it.

- **Database grants now name the connected database explicitly.** `object.name` is required for `type: database`, and inspection rejects a name that differs from `current_database()` instead of planning SQL against an ACL it did not inspect. Operator policies report `InvalidDatabaseTarget` for a mismatch.

- **`spec.mode: plan` is renamed to `spec.mode: observe`, with a deprecation window.** "Plan" now names exactly one thing, the `PostgresPolicyPlan` resource; the `ApprovalIgnored` reason `PlanModeNeverExecutes` is now `ObserveModeNeverExecutes`. The old value keeps working: `mode: plan` stays an accepted schema value with identical behaviour, so a GitOps controller re-applying an existing manifest is unaffected by the upgrade. A policy using it reports a `ModeValueDeprecated` condition, warns in the operator log, and counts toward `pgroles.deprecated.mode_plan`.
  **Upgrade:** change `mode: plan` to `mode: observe` in your manifests at your convenience — a future release removes the `plan` value, and that removal will be the breaking change.

- **BREAKING: policy content now has explicit size limits.** Identifiers (role, schema, owner, member names) are capped at 63 characters *and* 63 bytes — the point past which PostgreSQL silently truncates — and every list and map has a bound: 1024 roles, 4096 grants, 2048 memberships, and so on (full table in the [manifest reference](https://thepartly.github.io/pgroles/docs/manifest-reference/)). The bounds apply to `PostgresPolicy`, to candidates, and to `pgroles validate` alike, and they are what makes candidate immutability enforceable by the API server.
  **Upgrade:** a policy exceeding a limit is rejected on its next apply with a field-level error. Each limit sits at least 20× above the corresponding count in the largest policy known to run in production; previously the same policy would eventually have hit an opaque `etcdserver: request is too large`. (#182, #173)

- **BREAKING: the approval digest encoding is now `pgroles.io/approval-effect/v3`.** v2 binds the target identity above, and v3 additionally carries a default-privilege rule's scope as a tagged `scope` value instead of a bare `schema` string, which could not express an owner-wide rule.
  **Upgrade:** on the first reconcile after upgrading, every open plan is superseded and replaced by an equivalent plan under v3, and recorded decisions do not carry over — open plans need one fresh approval. Nothing executes in the meantime. Deliberately, a `pg_upgrade` (fresh `system_identifier`) or a blue-green cutover also moves the identity and invalidates any approval open across it; re-approve the fresh plan afterwards. (#180)

- **URL-mode connections bind the endpoint they resolve to**, not only the Secret name and key — editing the URL inside a referenced Secret is no longer invisible to an open approval. Credentials stay excluded, so password and token rotation still do not invalidate approvals. (#180, #185)

- **Generated password Secrets are created when the approved plan executes, not when it is proposed.** A plan that is rejected or never approved no longer leaves a credential in the cluster. Existing Secrets are read and reused, and `approval: auto` behaves as before. Deleting a generated Secret still rotates the password on the next apply — the policy now warns first with a `GeneratedSecretMissing` Event instead of rotating silently. (#181, #174)

- **Planning every open candidate now costs one database inspection instead of one each.** Candidate plans are computed inside the parent policy's reconcile, holding the parent's advisory lock, so the cost of reviewing proposals used to be charged to enforcement of the live policy: ten open candidates meant ten full inspections before the policy itself could be reconciled. The operator now computes each candidate's inspection scope from its content, reads the database once over the union of those scopes, and derives each candidate's own scoped inspection from that read in memory. Deriving is not sharing the *policy's* answer — a candidate's scope, wildcard expansion and diagnostics are still entirely its own, and a scope the shared read does not cover is refused rather than answered narrowly. Candidates with a `spec.target` override are a different database and still inspect for themselves, as does every candidate if the shared read fails: a proposal must never break enforcement. `pgroles.candidate.inspections` and `pgroles.candidate.planning.duration` report whether the cost is actually flat in the candidate count. (#191)

- **Open candidates are bounded by a budget and a TTL, not just by retention.** Retention prunes candidates that are already finished; these bound work that has not happened yet, since planning an open candidate happens inside the parent's reconcile while it holds its locks. At most 32 open candidates per policy are planned in one pass — the oldest, so a CI loop filing a candidate per push cannot evict proposals already under review — and the rest report `Ready=False, reason=CandidateBudgetExceeded` until older ones are decided or expire. Nothing is deleted: an over-budget candidate is somebody's proposal, not garbage. Separately, an open candidate nobody decides within 14 days of filing becomes `Superseded=True, reason=Expired`, on the grounds that it is abandoned rather than under review, and retention then prunes it normally. `pgroles.io/keep=true` exempts a candidate from the TTL and from retention pruning, but not from the budget: a kept candidate past the budget reports `CandidateBudgetExceeded` like any other, so the label cannot be used to enlarge the bound. (#191)

- **`spec.schemas`, `spec.roles` and `spec.retirements` are now map-lists** (keyed by `name`, `name` and `role`), so server-side apply merges entries instead of replacing whole lists, and a manifest with duplicate keys is rejected at `kubectl apply` instead of failing later at reconcile time. `memberships`, `grants` and `default_privileges` stay plain arrays: their natural keys are composite or legitimately repeat. (#126)

### Fixed

- The Kyverno plan-decision policy no longer identifies the operator by ServiceAccount name. Both decision rules now exempt callers holding the logical `manage` verb on the parent `PostgresPolicy`, checked with a `SubjectAccessReview` — the same shape the ephemeral-access policy already used for controller-owned writes — and the operator's ClusterRole grants it. The hardcoded `system:serviceaccount:pgroles-system:pgroles-operator` was wrong in both directions and silently so: it stalls plans when it names an account the operator does not run as, and it is a standing bypass of the approve-verb check for anyone able to create or impersonate that account in a cluster that installs the operator elsewhere. One policy now covers any number of operators under any names and namespaces, nothing install-specific is templated into it, and `k8s/security/plan-decision-kyverno.yaml` applies unmodified. The exemption covers the approve check only — every newly terminal decision still records the identity the API server authenticated, controllers included, so under `approval: auto` `decidedBy` now names the operator's ServiceAccount while the condition's `AutoApproved` reason carries the mechanism. Grant `manage` on `postgrespolicies` to controllers only. (#187, #179)
- The plan approval documentation now describes the mechanism that exists — a decision written to the plan's status subresource together with `decidedBy` — with working `kubectl` commands for both approval and rejection. The CLI commands it used to invent are gone; what genuinely remains unbuilt is confined to one callout. (#184, #173)
- A superseded plan names why it was superseded — effects changed, effects vanished, replaced by a newer plan, or the target moved — instead of always claiming the database changed. A moved target reports the specific identity reason. (#184)
- `kubectl get pgplan -o wide` shows the change digest a decision actually binds (`Digest` column), not just the SQL preview hash. (#184)
- Superseding a plan no longer tries to rewrite the decision recorded on it — a write the plan CRD itself rejects, which left decided plans stuck actionable against a real API server. A plan is voided by its phase, with the cause on a `Superseded=True` condition, and the decision record stays exactly as the reviewer left it. (#185, #182)
- The operator's RBAC now covers the candidate `patch` (adoption) and `delete` (retention) it actually performs. (#182)
- A crash between retiring a plan and creating its replacement can no longer leave a policy with nothing actionable: the old plan is retired only after the replacement is visible, on every path. (#185)
- `status.current_plan_ref` is cleared before the plan it points at is retired, so an interrupted reconcile leaves a findable pending plan rather than a dangling reference. (#185)
- A `mode: observe` policy now retires its pending plan when drift disappears out of band, instead of reporting `InSync` while `current_plan_ref` points at a stale plan. (#185)
- A change set waiting out its failure-retry window is reported as `PlanFailedRetryBackoff` instead of "awaiting approval" beside a Failed plan with no decision to make. (#185)

## [0.9.0] - 2026-08-14

### Added

- **Bounded, request-driven PostgreSQL memberships in Kubernetes.** `EphemeralAccessPolicy` defines a requestable bundle; immutable `EphemeralAccessRequest` resources resolve, activate, expire, and revoke one grant without touching the durable `PostgresPolicy`. **`approval.mode: Required` is only a real approval boundary under admission enforcement** — approving and otherwise managing a request are the same write to `ephemeralaccessrequests/status`, so RBAC alone cannot separate them. Deploy the CI-tested Kyverno profile in `k8s/security/`, or front the API with a trusted broker, before relying on it: [securing ephemeral access](https://thepartly.github.io/pgroles/docs/ephemeral-access-security/) sets out the three trust postures. Requires PostgreSQL 16 or later. (#158)
- **A generated [Helm chart reference](charts/pgroles-operator/README.md) documenting every value.** Previously 14 of the 21 chart values were undocumented, including `serviceAccount.annotations` (required for GKE Workload Identity) and the `EPHEMERAL_ACCESS_MAXIMUM_DURATION` / `EPHEMERAL_ACCESS_MAX_PENDING_TTL` ceilings. Generated by helm-docs from `values.yaml`; CI fails if it drifts.
- **Approving a plan that can never execute is now reported.** A policy in `spec.mode: plan` never consults `spec.approval`, so annotating its plan is accepted and then does nothing — indistinguishable from a stalled operator. The policy now reports an `ApprovalIgnored` condition and a warning Event, pointing at `mode: apply` with `approval: manual`, which is the combination that gates an apply.
- **Namespace-scoped operator deployments.** The chart value `operator.watchNamespace` sets `WATCH_NAMESPACE`, which scopes every operator watch and conflict-detection list to one namespace, and switches the chart from `ClusterRole`/`ClusterRoleBinding` to a namespaced `Role`/`RoleBinding`. Unset, the operator remains cluster-scoped as before. (#162)

### Changed

- **Ephemeral-access reconciliation is now proportional to the requests relevant to one policy**, instead of listing and filtering every retained `EphemeralAccessRequest` in the namespace on each pass. The request controller's existing watch feeds a shared index keyed by access-policy name and by resolved access-policy and target-policy UID; effective-graph composition, access-policy triggers, and scoped cleanup read that index and the namespace-wide LIST calls are gone. Indexes and the controller-owned UID labels added alongside them are routing optimizations only — every authorization and ownership decision still verifies the immutable UIDs in `status.resolvedAccess`. New OTLP metrics report cache size, indexed lookup sizes, and ephemeral reconcile duration and concurrency by resource kind. (#162)

### Deprecated

- **Omitting `spec.approval` on a `PostgresPolicy`.** Behaviour is unchanged — the value is still inferred from `spec.mode` (`apply` → `auto`, `plan` → `manual`) — but the inference hides whether a human gates SQL execution behind an unrelated field, and `spec.mode` itself defaults to `apply`. Policies relying on it report an `ApprovalUnset` condition and increment `pgroles.deprecated.approval_unset`. **Migration:** write down the value you already get. A future release will reject the omission. (#73)

### Removed

- **`PostgresPolicy` status fields `planned_sql`, `planned_sql_truncated`, and `last_reconcile_time`.** Superseded by `PostgresPolicyPlan` in 0.5.0, but still written on every reconcile with pending changes. **Migration:** read plan SQL from the plan the policy points at — `kubectl get pgplan $(kubectl get pgr <policy> -o jsonpath='{.status.current_plan_ref.name}') -o jsonpath='{.status.sqlInline}'` — falling back to the gzipped ConfigMap in `status.sqlRef`, or a truncated `status.sqlInline` for plans too large for either. Replace `last_reconcile_time` with `status.last_successful_reconcile_time`. (#73)
- **`OperatorContext::new`**, in the `pgroles-operator` crate. It could not supply the shared request index the reconcilers now read, so a context built through it produced lookups that no watch ever fed. **Migration:** use `OperatorContext::new_with_runtime_config`, passing the `RequestIndex` fed by the request controller's watch and the optional watch namespace. (#162)

### Fixed

- **The operator no longer holds PostgreSQL connections open against every database it manages.** Connection pools are cached for the operator's lifetime and inherited sqlx's 10-minute idle timeout, which never elapsed against the 5-minute default requeue interval — each reconcile re-touched the pool first, and sqlx's FIFO idle queue spread those touches across every pooled connection. A pool that once peaked at N concurrent connections therefore occupied N backends indefinitely, per database, whether or not anything was reconciling. Pools now drain to zero between reconciles.

## [0.8.0] - 2026-08-02

### Fixed

- **Policy names longer than 63 characters no longer break plan creation, plan lookup, and cleanup.** Kubernetes caps label values at 63 bytes but allows resource names up to 253, and the operator conflated the two rules. Three defects followed. A sanitized label value truncated at the cap could land on a separator and be rejected outright, so the plan ConfigMap failed to write and the policy stopped reconciling (thanks @aarons-afk for the report and original fix, #146). `generate_plan_name` cut the policy-name prefix without trimming an exposed `.` or `-`, so the appended `-plan-…` began a new DNS label with a separator and the API server refused the plan. And `is_valid_secret_name` rejected `generatePassword.secretName` values beginning with a digit, which Kubernetes permits. All three rules now come from one module (`k8s_names`) that restates them once, with property tests over a hostile alphabet — including multi-byte UTF-8, which an earlier fix attempt silently truncated mid-character.
- **Plans and plan-SQL ConfigMaps are now matched to their policy by controller-owner UID rather than by a truncated label.** The `pgroles.io/policy` label carries at most 63 bytes of a name that may be 253, so two policies sharing a 63-byte prefix selected each other's plans and SQL ConfigMaps — cross-approving and cross-deleting them — and the plan→policy watch never matched for any longer name, so approvals and status transitions silently stopped waking the reconciler. The label remains as a server-side prefilter; identity is now the UID at every lookup, approval, and cleanup site, including the create-conflict path, which deletes a colliding non-owned ConfigMap instead of adopting it. **Upgrade note:** deleting a policy with `--cascade=orphan` strips the owner references this depends on, so orphaned plans are no longer re-adopted by a recreated policy of the same name and must be deleted by hand. See [limitations](https://thepartly.github.io/pgroles/docs/limitations/).
- **Schema owner transfers no longer strip the incoming owner's privileges when a stale explicit grant exists.** `ALTER SCHEMA ... OWNER TO z` merges z's pre-existing explicit ACL entry into the new owner entry, so a same-plan `REVOKE` against that stale grant removed the *new owner's* USAGE — leaving the owner unable to resolve its own schema until the next reconcile. The diff engine now suppresses schema revokes whose grantee is that schema's incoming owner in the same plan; the state converges in a single pass. Proven by the live property suite, which previously had to exclude this shape. (#140)

### Added

- **Profiles can now declare `config` defaults for the roles they generate, with `{schema}`/`{profile}` placeholder substitution in values.** The same role-level `ALTER ROLE ... SET` config introduced below is now available on `profiles[].config`, so a per-schema `search_path` default (`config: { search_path: "{schema}" }`) can be declared once and expanded across every `schema x profile` binding instead of repeated per generated role. Placeholders substitute only in values — keys stay literal PostgreSQL parameter names, and the `config.role` membership cross-check applies to generated roles the same as hand-written ones. `pgroles generate --suggest-profiles` never clusters a `config`-carrying role into a profile, keeping it flat instead, since collapsing config maps modulo placeholder substitution risks silently changing what gets applied.
- **Roles can now declare configuration parameter defaults via `config`, managed with `ALTER ROLE ... SET`.** Keys are PostgreSQL setting names (including dot-qualified custom settings like `app.tenant`); values are always strings — quote numbers and booleans (`statement_timeout: "30000"`, `jit: "off"`) — and the same rule is enforced by both the CLI parser and the CRD schema, so a manifest means the same thing in both paths. Settings are diffed against the cluster-wide entries in `pg_roles.rolconfig`: authoritative and adopt modes `RESET` settings present on a managed role but absent from the manifest, while additive mode leaves config on pre-existing roles unchanged (config on newly created roles is still applied). Declaring `config: { role: <group> }` on blue/green login roles makes PostgreSQL `SET ROLE` at connect time, so objects created under either credential are owned by the shared group role and survive password rotation; when the target role is declared in the same manifest, pgroles validates that a matching membership is declared too. `pgroles generate` exports existing role config defaults for brownfield adoption. Per-database settings (`ALTER ROLE ... IN DATABASE`) are not managed. See [examples/zero-downtime-password-rotation.yaml](examples/zero-downtime-password-rotation.yaml). (#132)
- **New [executor privileges](https://thepartly.github.io/pgroles/docs/executor-privileges/) and [limitations](https://thepartly.github.io/pgroles/docs/limitations/) docs pages.** The former documents the minimal `CREATEROLE`-based grant set pgroles needs (verified against a live PostgreSQL 16 server), including the greenfield-vs-brownfield `ADMIN OPTION` distinction and a copy-pasteable bootstrap SQL block. The latter is a single-page, matter-of-fact list of what pgroles does not manage — column-level grants, per-database role settings, server configuration, extensions, row-level security, unmodeled grant object types (domains, FDWs, languages, tablespaces, large objects, publications/subscriptions), password drift, and database creation/ownership.
- **`diff` and `apply` now detect and warn about column-level grants in schemas whose privileges pgroles manages.** pgroles has never managed `GRANT SELECT (col) ON table ...` (it only reads `pg_class`-level ACLs, not `pg_attribute.attacl`), so column-level grants were a silent audit hole in authoritative mode — the manifest looked like the whole truth even when it wasn't. Inspection now aggregates column-level ACL entries per `(schema, relation, grantee)`, including grants to `PUBLIC`, and prints a warning listing the affected columns and privileges via `InspectionDiagnostics`. This is detection only: the grants are still not diffed, revoked, or exported by `generate`, and — unlike an `UnsatisfiableWildcardGrant`, which blocks reconciliation because desired state can't be computed — the warning never blocks `diff`/`apply` or operator reconciliation.

### Changed

- **Documented PostgreSQL version support as 16, 17, and 18 — the versions CI actually tests.** PG 14–15 code paths (the legacy `WITH ADMIN OPTION` grant syntax fallback) remain in the codebase but are now described as best-effort and untested rather than "supported," across the installation, quick start, memberships, architecture docs, and `ROADMAP.md`.
- **Documented a transaction-mode pooler caveat for role configuration defaults.** `config` (including `config.role`) is applied by PostgreSQL at connection start, so behind a pooler like PgBouncer it attaches to pooled server connections rather than individual clients; pooler reset queries do not remove it since PostgreSQL reapplies `ALTER ROLE ... SET` config on every (re)connect. See [role configuration defaults](https://thepartly.github.io/pgroles/docs/manifest-reference/#role-configuration-defaults).

## [0.7.8] - 2026-06-04

### Added

- **Externally managed roles can now be marked `external: true`.** External roles may still be referenced in grants, schema ownership, default privileges, and as members of managed roles, but pgroles will not create, alter, drop, password-manage, or manage memberships granted from those roles. This avoids breaking Cloud SQL IAM users and groups whose `LOGIN` attribute and provider memberships are owned outside pgroles. (#123)
- **Operator reconciles can now be requested immediately with `pgroles reconcile` or the `reconcile.pgroles.io/requestedAt` annotation.** The CLI annotates a `PostgresPolicy` and can optionally wait until `status.lastHandledReconcileAt` records that the operator successfully handled the request. The operator also includes the annotation value in its watch predicate, so changing only the request timestamp triggers a reconcile without mutating the policy spec. (#118)
- **`pgroles render-bundle` composes a policy bundle into a single flat manifest.** Validates and composes the bundle (rejecting scope/ownership conflicts up front), then emits the resulting `PolicyManifest` as YAML with a provenance header recording the source bundle basename, the manifest schema version (`pgroles.manifest.v1`), and the fragments it composed. The output round-trips through `pgroles validate -f` / `diff -f` / `apply -f`, so a bundle can be composed in CI and the rendered manifest wrapped into a `PostgresPolicy` resource in a GitOps repo. Pre-rendering keeps cross-team and cross-environment fragment composition available to operator users without adding operator-side CRDs. The renderer is byte-deterministic across machines: the header records only the bundle file's basename (never an absolute or `pwd`-relative path), and the YAML body is post-processed to strip serde-emitted optional defaults (empty optional sequences, `null` scalars, and the default `role_pattern`) so the file doesn't churn under unrelated upgrades. Required fields like `Membership.members`, `Grant.privileges`, and `DefaultPrivilege.grant`, plus named empty profiles, are preserved even when empty so the rendered manifest always re-parses. `--check <path>` compares against an existing rendered file and exits with code 2 on drift, suitable as a CI gate that catches stale checked-in renders. The new [bundle composition guide](https://thepartly.github.io/pgroles/docs/bundle-composition/) documents when to use each of the three workflows (single manifest, CLI bundle for direct apply, rendered bundle for the operator). Use `--no-header` to omit the header and `--output <path>` to write to a file. (#92)

## [0.7.7] - 2026-05-18

### Added

- **The operator can now `SET ROLE` to a privileged parent role on every pooled connection.** Set `connection.params.setRole: <role>` on a `PostgresPolicy` and the operator's sqlx pool runs `SET ROLE "<role>"` once via `after_connect`, so the session's `current_user` becomes that role and its attributes (`CREATEROLE`, `CREATEDB`, …) apply to every subsequent statement. This unblocks the "operator authenticates as a low-privilege identity (e.g. Cloud SQL IAM user via Workload Identity) that has been granted membership in `cloudsqlsuperuser`" pattern, where PostgreSQL's role membership semantics otherwise refuse role-attribute inheritance. The role identifier is validated at admission time against `^[A-Za-z_][A-Za-z0-9_$-]*$` via the CRD's OpenAPI `pattern`, and `SET ROLE` failures surface as a distinct `SetRoleFailed` status reason instead of being conflated with database connection failures. (#119, #120)

## [0.7.6] - 2026-05-14

### Fixed

- **Wildcard `GRANT EXECUTE` no longer flaps on schemas that contain procedures.** PostgreSQL's `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ...` does not cover procedures, but the inspector includes procedures in routine inventory. Function wildcard grants now render as `ALL ROUTINES`, and specific function/procedure grant and revoke targets render as `ROUTINE`, so manifests using `object.type: function` remain backward-compatible while converging on schemas with extension-installed procedures. (#113, #114)

## [0.7.5] - 2026-05-14

### Added

- **The operator can now authenticate to Cloud SQL with native GKE Workload Identity.** Structured connection params accept `auth.type: gcp_workload_identity`, fetch short-lived Cloud SQL IAM login tokens from the GKE metadata server, optionally impersonate a target Google service account through IAMCredentials, and refresh cached pools before token expiry. Static `password` / `passwordSecret` fields are mutually exclusive with provider-backed auth, and `sslMode` defaults to `require` for this mode. (#114, #115)

### Changed

- **Operator and manifest documentation are easier to validate and navigate.** The docs now include a dedicated manifest reference, a tooling guide with schema-validation examples, and Cloud SQL examples that cover native Workload Identity auth as well as proxy-based connectivity. (#111, #115)

## [0.7.4] - 2026-05-12

### Fixed

- **Wildcard `GRANT EXECUTE` on schemas with long function signatures no longer flaps.** The inventory queries (`fetch_object_inventory` and `fetch_object_inventory_for_wildcards`) `UNION ALL` their per-type rows. All branches except the function one project `object_name` as a PostgreSQL `name`-typed column (`c.relname`, `t.typname`, `n.nspname`, `db.datname`, 63-byte cap), while the function branch projects the text-typed `proname || '(' || identity_args || ')'`. PostgreSQL resolves the UNION result column to the common type — `name` — and silently truncates the text function signatures to 63 bytes. The wildcard satisfaction check in `normalize_wildcard_grants` then iterates the truncated inventory keys against the full-signature grant keys, treats every wildcard on a schema containing a long-signatured function as unsatisfied, and re-emits `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA … TO …` on every reconcile. Cast each `name`-typed `object_name` column to `text` so the UNION result is uniformly text. This closes the residual flap referenced in #105 for non-trivial function inventories (overloaded helpers, custom-typed arguments, extension defaults). (#109)

## [0.7.3] - 2026-05-12

### Fixed

- **Privilege inspection no longer returns PUBLIC / NULL grantee ACL entries.** Extension-installed functions (e.g. `partman`, `pg_stat_statements`) typically carry a `GRANT EXECUTE … TO PUBLIC` entry; previous inspection runs surfaced those PUBLIC rows alongside managed grantees, causing wildcard `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA … TO {role}` to be re-emitted every reconcile because the inspector couldn't reconcile a PUBLIC row against the managed grantee set. Privilege queries now restrict results to the managed-grantee set in SQL, so the wildcard converges. (#108)

### Changed

- **Inspection catalog queries are constrained to the wildcard scope.** `n.nspname = ANY(...)` predicates are added to each leg of inventory and grantability catalog queries so PostgreSQL can apply namespace filtering before joining the unnest scope rows. ACL filtering moves from Rust to SQL via `unnest(aclexplode(...))` with a managed-grantee predicate, reducing inspector wall time on large databases without changing observable behaviour. (#108)

## [0.7.2] - 2026-05-08

### Added

- **Operator OTLP metrics now expose database inspection cost.** The operator records inspection phase durations, inspected object counts, wildcard inventory size, unsatisfied wildcard scope counts, and grantability query/object counts so large-schema deployments can spot catalog-query regressions.

### Changed

- Wildcard diagnostics now avoid grantability catalog scans when current ACLs already satisfy the wildcard, and scope grantability checks to the unsatisfied wildcard schema/object-type pairs.

### Fixed

- **Unsatisfiable wildcard grants now fail with a clear diagnostic instead of re-planning forever.** A wildcard such as `function name: "*"` remains strict desired state: every matching object must either already have the requested privilege or be grantable by the executor. When a matching object is missing the privilege and the executor lacks the corresponding `WITH GRANT OPTION`, CLI `diff`/`plan`/`apply` now stop with `UnsatisfiableWildcardGrant` instead of printing or applying repeated wildcard SQL. The operator reports `Ready=False` and `Degraded=True` with the same reason, leaves no new `PostgresPolicyPlan` or SQL ConfigMap for that reconcile, and retries at the normal policy interval. (#105, #106)

## [0.7.1] - 2026-05-08

### Fixed

- **Wildcard grants no longer flap when an inventory object loses its ACL between reconciles.** When a desired manifest had a wildcard grant (e.g. `function name: "*"`) and an object in scope was `DROP`ped+`CREATE`d externally — for example by a service running its own migrations — the inspector's wildcard-collapse failed and `diff` emitted both a wildcard `GRANT ... ON ALL ... IN SCHEMA` and a per-name `REVOKE` for every previously-granted object. Apply order re-granted everywhere then stripped the previously-known set, the next reconcile observed the inversion, and the controller flapped indefinitely. `diff` now treats a desired wildcard as shadowing per-name revocations of the same privileges within the same `(role, schema, type)` scope; covers both wildcard-only and wildcard-plus-specific-extras manifest shapes. (#104)
- **Status starvation removed for cache-invalidating connection failures.** `reconcile_apply` previously held the in-process per-database lock across the connection probe, so `PostgresPolicy` resources sharing one credentials Secret could serialize on the lock during a Secret rotation to a bad URL — each lock-holder paying the full `POOL_ACQUIRE_TIMEOUT_SECS`. Lock contention requeues silently without updating the policy status, so an unlucky sibling could spend tens of seconds bouncing on the lock before publishing its `Ready=False/DatabaseConnectionFailed` condition. The connection probe now runs *before* lock acquisition, so failures surfaced at pool creation time (first reconcile, or after a Secret-resourceVersion / params-fingerprint cache invalidation) update status independently of concurrent reconciles for the same database target. Connection failures encountered inside the locked DDL phase against an already-cached pool are unaffected. (#104)
- **TLA+ model for wildcard-grant convergence** (`correctness/races/Convergence.tla`). Verifies eventually-permanent convergence under fairness and a finite number of external `DROP+CREATE`s, and produces the partly-dev15-shaped lasso counterexample under v0.7.0 semantics. (#104)

## [0.7.0] - 2026-05-06

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor flat brownfield manifests into reusable profiles, with live database inventory checks before wildcard collapse so generated profiles do not broaden privileges. (#96)
- **`pgroles_core::suggest` public API** and `pgroles_inspect::fetch_object_inventory` for callers building their own brownfield profile-suggestion pipelines. (#96)

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.7.0-beta.2] - 2026-05-06

### Fixed

- **Large operator plan SQL previews no longer exceed Kubernetes ConfigMap limits.** Small redacted SQL previews remain inline, large previews are stored as gzip-compressed ConfigMap `binaryData`, and exceptionally large incompressible previews fall back to a truncated inline preview while apply continues to render executable SQL from the in-memory change set. (#98)
- **Status-less `PostgresPolicyPlan` resources and orphaned plan SQL ConfigMaps are cleaned up defensively.** The operator persists SQL artifacts before making plans visible, cleans stale status-less plans and orphaned SQL ConfigMaps before and after reconcile, and also collects stale policy-labeled SQL ConfigMaps left behind by older versions. (#99)
- **Plan storage correctness is modeled in TLA+.** The new model covers persistence failure, the invariant that plans are not visible before their SQL artifact is ready, at-most-one actionable plan safety, and eventual cleanup of stale status-less plans and orphan SQL artifacts. (#98, #99)

## [0.7.0-beta.1] - 2026-05-05

### Added

- **`pgroles generate --suggest-profiles`** — deterministically refactor a flat brownfield manifest into reusable profiles. The suggester clusters roles whose grants share an identical *schema-relative signature* across multiple schemas, picks a uniform role-name pattern (`{schema}-{profile}` / `{schema}_{profile}` / `{profile}-{schema}` / `{profile}_{schema}`) so role names are preserved verbatim, and verifies round-trip equivalence against the flat manifest before committing. Re-runs on databases where a suggested manifest has already been applied are idempotent (auto-generated profile-role comments are recognised and ignored). (#96)
- **Live-DB inventory required for safe wildcard collapse** — the suggester only collapses per-name grants into wildcards (`name: "*"`) when given a complete object inventory from `pgroles_inspect::fetch_object_inventory`. The CLI fetches this automatically. A grant-only view would treat ungranted objects as nonexistent and could broaden privileges; the suggester now refuses to collapse if the provided inventory is missing any object that already appears in input grants. (#96)
- **`pgroles_core::suggest` module** — new public API: `suggest_profiles`, `SuggestOptions`, `SuggestReport`, `SuggestedProfile`, `SkipReason` (with variants `MultiSchema`, `SchemaNotDeclared`, `OwnerMismatch`, `UniqueAttributes`, `UnrepresentableGrant`, `SoleSchema`, `NoUniformPattern`, `SchemaPatternConflict`, `RoundTripFailure`, `IncompleteFullInventory`), `Inventory`, `inventory_from_manifest_grants`, `expand_wildcard_grants`. (#96)
- **`pgroles_inspect::fetch_object_inventory`** re-exported at the crate root for callers building their own suggester pipelines. (#96)

### Changed

- **BREAKING: `PolicyManifest.profiles` is now `BTreeMap<String, Profile>`** (was `HashMap<String, Profile>`). YAML serialization is now deterministic — two `pgroles generate` runs against the same database produce byte-identical output. Library consumers that construct `PolicyManifest` directly will need to update their map type. The CLI and operator are unaffected. (#96)

## [0.6.0] - 2026-04-30

### Added

- **Schema management** — declared schemas (`schemas[].owner`) are now first-class state. pgroles creates missing schemas, converges `OWNER TO`, and filters implicit owner ACLs from inspection/export so plan and apply round-trip cleanly. Plan/apply summaries report schema creations and owner alterations. Generated SQL includes `CREATE SCHEMA` and `ALTER SCHEMA … OWNER TO`. (#90)
- **Profile-level `inherit`** — profiles can set `inherit` on generated roles (already existed for `login`); threaded through to the operator CRD as well. (#95)

### Fixed

- **Additive mode no longer rewrites brownfield role attributes or comments.** Previously a pre-existing role like `accounts_editor LOGIN NOINHERIT` could trigger `ALTER ROLE … NOLOGIN INHERIT` under additive mode, which contradicts incremental adoption semantics. Additive mode now leaves attributes and comments unchanged on pre-existing roles. (#95)
- **CLI execution sticks to a single backend.** When a hostname resolves to multiple PostgreSQL servers, one-shot commands could inspect one backend and execute mutations against another. Connection identity is now pinned for the lifetime of a CLI invocation, and SQL execution failures include the backend identity. (#95)

### Changed

- **Documentation** — README and docs updated with schema-management semantics, examples, operator guidance, additive-brownfield behavior, and generated-role attributes. (#90, #95)
- **Dependency bumps** — `next` 16.2.0 → 16.2.3 in `/docs` (#75); `rand` 0.9.2 → 0.9.3 (#82).

## [0.5.0] - 2026-04-15

### Added

- **PostgresPolicyPlan CRD** — reconciliation plans are now separate Kubernetes resources with their own lifecycle. Plans can be reviewed, approved, rejected, or auto-approved before execution. Includes manual approval via annotations, plan superseding on policy changes, and operator-restart safety. (#74)
- **Operator password management** — the operator can generate random passwords and store them in Kubernetes Secrets with ownerReferences, or sync passwords from existing Secrets. Passwords are sent to PostgreSQL as SCRAM-SHA-256 verifiers (cleartext never crosses the wire). Includes secret rotation detection via resourceVersion tracking. (#65)
- **Structured connection parameters** — `connection.params` supports individual fields for host, port, dbname, username, password, and sslMode. Each field accepts a literal value or a `*Secret` SecretKeySelector reference. Integrates natively with Zalando postgres-operator, CloudNativePG, and CrunchyData PGO without requiring an ExternalSecret intermediary. (#87)
- **Pre-flight schema validation** — the operator validates that every schema referenced by the policy exists in the target database before issuing DDL, surfacing a clear `MissingDatabaseObject` status condition instead of failing mid-transaction. (#80)
- **Plan visibility improvements** — plans include SQL preview annotations, change summary annotations, SQL statement count (post-wildcard expansion), and printer columns for the SQL ConfigMap name and hash (`kubectl get pgplan -o wide`).
- **Printer columns for PostgresPolicy** — `kubectl get pgr` now shows Ready, Mode, Drift, Changes, and Last Reconcile columns.
- **CLI accepts Kubernetes CR manifests** — `pgroles diff/apply/validate` can read `PostgresPolicy` YAML directly (extracts the `spec` from the CR wrapper). (#71)
- **Manifest optional for inspect** — `pgroles inspect` can connect to a database without a manifest file to show the current role state. (#69)
- **Staged adoption guide** — new documentation page covering brownfield adoption patterns and PUBLIC privilege caveats. (#70)

### Fixed

- **Wildcard grant convergence on empty schemas** — wildcard grants on sequences, functions, and other types now converge correctly when no objects of that type exist. Previously re-issued on every reconcile, causing unbounded plan creation. (#84)
- **Missing-object SQL errors classified as non-transient** — SQLSTATE codes 3F000, 42P01, 42883, 42704 are now classified as `Slow` retry with `MissingDatabaseObject` reason instead of exponential transient backoff. (#79)
- **Plan resource deduplication** — recently-failed plans with the same SQL hash are deduplicated within a 120-second window, preventing accumulation during fast retries. (#81)
- **MemberSpec defaults removed from CRD** — `inherit` and `admin` fields are now `Option<bool>` with defaults applied at resolution time, avoiding perpetual ArgoCD diffs when using ServerSideApply. (#83)
- **TLS support for PostgreSQL connections** — the operator and CLI now support TLS connections to PostgreSQL, required for Cloud SQL and other managed services. (#67)

### Changed

- **E2E tests split into 3 parallel suites** — operator scenarios, load tests, and plan lifecycle run concurrently in separate kind clusters, reducing CI wall clock from ~20 min to ~10 min. Shared setup extracted into a composite action. (#85)
- **SCRAM-SHA-256 verifiers** — passwords are always hashed client-side before being sent to PostgreSQL. The verifier is stored alongside the cleartext in generated Secrets. Verified against RFC 7677 known vectors.
- **GitHub Actions updated to Node 24 runtimes.** (#66)

## [0.4.1] - 2026-04-08

### Fixed

- Enable TLS for PostgreSQL connections. (#67)

## [0.4.0] - 2026-04-08

### Added

- Printer columns for `PostgresPolicy` CRD (Ready, Mode, Drift, Changes, Last Reconcile, Age). (#68)

## [0.3.0] - 2026-03-26

### Added

- `pgroles graph` command for role visualization in tree, JSON, dot, and mermaid formats. (#60)

## [0.2.0] - 2026-03-12

### Added

- **Reconciliation modes** (`--mode` flag for CLI, `reconciliation_mode` field for Kubernetes operator):
  - `authoritative` (default): full convergence — anything not in the manifest is revoked or dropped. This is the existing behavior, now explicitly named.
  - `additive`: only grant, never revoke — safe for incremental adoption on existing databases.
  - `adopt`: manage declared roles fully (including revoking excess grants), but never drop undeclared roles.
- `ReconciliationMode` enum and `filter_changes()` post-filter in `pgroles-core` for library consumers.
- **Operator plan mode** via `spec.mode: plan`, including planned SQL in status without mutating PostgreSQL.
- **Password-backed roles** with `password` sources and optional `password_valid_until` support for CLI and operator workflows.
- `pgroles generate --output` for direct brownfield manifest export to a file.
- Live-database integration tests covering all three reconciliation modes.
- Documentation for reconciliation modes in CLI reference, operator guide, and CI/CD guide.

### Changed

- Wildcard relation grants and revokes are now scoped by object subtype, so table wildcards do not accidentally touch views or materialized views.
- The docs site, README, and operator guidance now reflect the current production-focused controller model more accurately.

## [0.1.5] - 2026-03-06

Initial public release.
