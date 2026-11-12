# ADR-002: Share a database through a PostgresDatabase and attached policies

- **Status:** Proposed
- **Date:** 2026-11-12
- **Decision-makers:** pgroles maintainers
- **Consulted:** operators running shared databases, including one running
  independent policies with separate SQL identities (#261, #264)
- **Related:** #91 (composed policies in the operator), #262 (bundle scopes),
  #263 (conflict detection on the resolved database), #265 (conflict claims
  by revoke reach), #261 (explicit absences in additive mode), ADR-003
  (executor per delegation)
- **Supersedes / superseded by:** —

## Context and problem statement

How should several teams manage roles and grants on one PostgreSQL database
with pgroles, when no team should be able to exceed what it was given or undo
another team's work?

Today pgroles has two partial answers, and neither holds between teams that do
not fully trust each other.

**Several `PostgresPolicy` resources on one database (operator).**

- Each policy carries its own `connection`, so each team holds a credential
  for an executor with `CREATEROLE` and can bypass pgroles entirely, unless
  each executor is narrowly privileged.
- Until #265, policies were compared through claims that treated every role a
  policy mentions as owned, grantees and membership members included. Two
  teams adding the same person to their own team roles conflicted, and so did
  two policies granting complementary privileges to one shared role. The real
  hazard is narrower: a policy can undo another's grants only where its revoke
  reach covers them. #265 changes the rule to that.
- A conflict blocks both policies, so a new or careless policy can freeze one
  that was converging.
- Which policies count as "the same database" is inferred. #263 infers it from
  the server, but cannot see across separate operator installs, and leaves a
  window of one apply before two new policies see each other.

**Bundles (CLI).** Ownership is tracked per grant, membership and default
privilege, which is the right granularity. Scope, however, is declared by each
fragment about itself, and #262 shows that memberships, grantees and database
grants are not bounded by it at all.

The decision covers the operator. The same ownership rules are meant to serve
CLI bundles later (see More information).

## Decision drivers

- **D1 — Containment.** A team cannot create, grant or revoke beyond what the
  database owner gave it, including through memberships and database-level
  grants.
- **D2 — Isolation of failure.** One team's mistake, or one hostile policy,
  does not stop or undo another team's policy.
- **D3 — No pgroles state in the database.** pgroles keeps nothing beside the
  roles and grants it manages.
- **D4 — Reuse.** Locking, plans, approval, authority preflight and drift
  handling keep working as they do for a single policy.
- **D5 — Self-service.** Teams change their own access from their own
  namespace and repository, without a central render step.
- **D6 — Fewer powerful credentials.** As few parties as possible hold a
  `CREATEROLE` credential.
- **D7 — Long-term API over compatibility.** pgroles is pre-1.0, and ADR-001
  prefers a better API to compatibility scar tissue.
- **D8 — Defence in depth.** Where practical, a mistake in pgroles' own checks
  is bounded by PostgreSQL privileges, not only by pgroles.
- **D9 — Shared recipients.** A role may receive access from several policies.
  Owning a role's lifecycle is separate from granting to it.

## Considered options

1. **Attached policies under a `PostgresDatabase` owned by the database
   owner**, with scope delegated by that owner.
2. **Independent policies**, compared by the database the server reports
   (#263), with claims limited to what each policy manages (#265).
3. **Claims recorded in the database**, checked and updated under the
   advisory lock.
4. **Bundles rendered in CI into one policy**, with stricter fragment scopes
   (#262).
5. **Option 1 with a separate executor per delegation.**

## Decision outcome

Chosen option: **1, attached policies under a `PostgresDatabase`**, because it
is the only option that meets D1, D2, D3, D5 and D6 together, and it meets D4
by reusing the existing policy reconciler. It does not meet D8. Option 5 does,
at the cost of D4, and is deferred to ADR-003 with the fields it needs
reserved here. Option 2 stays supported for deployments that need D8 now.

| Driver | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| D1 Containment | Yes | Only with narrow executors | Partly | Yes, with #262 | Yes |
| D2 Isolation of failure | Yes | No | Yes | No | Yes |
| D3 No state in the database | Yes | Yes | **No** | Yes | Yes |
| D4 Reuse | Yes | Yes | Partly | Yes | No |
| D5 Self-service | Yes | Yes | Yes | No | Yes |
| D6 Fewer credentials | Yes | No | No | Yes | Partly |
| D8 Defence in depth | No | Yes, per team | No | No | Yes, except role names |
| D9 Shared recipients | Yes | Yes, with #265 | Yes | Yes | Yes |

We will:

1. **Add a `PostgresDatabase` kind, and let a `PostgresPolicy` attach to it
   with `databaseRef` instead of `connection`.** The database owner's resource
   holds the connection, execution settings (`mode`, `approval`, `interval`,
   `reconciliationMode`), shared `profiles` and `rolePattern`, and
   `delegations`. "The same database" becomes an object reference instead of
   an inference. Only the owner's namespace holds a database credential.

   Policies with `connection` remain a supported model, not a transitional
   one: they are the option for deployments that need PostgreSQL itself to
   enforce the boundary between teams.

   ```yaml
   apiVersion: pgroles.io/v1alpha1
   kind: PostgresPolicy
   metadata: {name: billing, namespace: billing}
   spec:
     databaseRef: {name: appdb, namespace: platform}
     roles:
       - name: billing_api
         login: true
   ```

2. **Derive each attached policy's scope from the owner's delegations, never
   from the policy, and separate what a policy claims from what it
   references.**

   ```yaml
   spec:
     delegations:
       - name: billing
         namespaces: [billing]
         roles: ["billing_*"]
         schemas: [{name: billing, facets: [owner, bindings]}]
   ```

   A policy **claims** the lifecycle of the roles it defines (roles without
   `external: true`, roles its schema bindings generate, and roles it
   retires), the schema facets it uses, and each grant, default privilege and
   membership it asserts, present or absent. A role it only grants to, or
   declares `external: true`, is a **reference** and claims nothing.

   - Every role a policy claims must match a delegated pattern, including
     roles generated by schema bindings. Otherwise a `role_pattern` such as
     `team_{profile}` mints names inside another team's delegation.
   - Schema `owner` and `bindings` facets, and grants or default privileges on
     a schema, need that facet delegated.
   - Membership in a role needs the role's lifecycle to be claimed by the same
     policy.
   - Database-level grants need the grantee's lifecycle to be claimed by the
     same policy. `PUBLIC` stays with the database owner.
   - A policy may grant on what it was delegated to any role. Billing can
     grant `SELECT` to the platform's `team_payments` and `REFERENCES` to
     `shipping_migrator`, and several policies may grant to one `app_runtime`.
   - Two policies collide when both claim one role's lifecycle or one schema
     facet, or when one asserts present what the other asserts absent.
     Granting to the same role is not a collision.
   - A referenced role that no accepted policy claims is composed as an
     external role, so its grants are inspected and converge. If it does not
     exist in the database, the referencing policy reports
     `DanglingReference`.

   Rationale: scope that a policy declares about itself is not a boundary
   (#262). Scope granted by the owner is, and the rules close the escalation
   paths #262 found. The rules live in `pgroles-core` so bundles can use them.
   Independent policies (#265) use the same claims, plus rules a single
   composed plan does not need: each independent policy has its own revoke
   reach, so a policy that can revoke collides with any policy asserting
   something where it inspects; and because roles and memberships are
   server-wide, policies on different databases of one server are compared on
   those.

3. **Resolve conflicts by precedence, and keep serving a policy's last
   accepted content when a newer edit is rejected.** Policies are admitted
   oldest first by `creationTimestamp`, then namespace and name. A policy that
   collides with an older one is rejected alone (`Accepted=False`, reason
   `Conflicted`). A rejected edit leaves the policy's previously accepted
   generation composed (`Retained`), the way a Deployment keeps its old
   ReplicaSet when a rollout fails.

   Retention holds on every rejection path, including checks that run before
   composition. Retained content is keyed by the policy's UID, so a policy
   deleted and re-created under the same name starts afresh, and it is
   recorded before the composed policy is patched, so a failed write cannot
   lose it.

   Precedence is by age, not by who claimed first. An older policy that newly
   claims a role a younger one serves takes it, and the younger one is
   rejected whole, with nothing retained. Deleting an older policy can let a
   policy it blocked outrank one accepted after it. Policies created in the
   same second of `creationTimestamp` are ordered by namespace and name.
   Delegations limit all three to policies delegated the same names.

   Rationale: blocking both policies fails D2. Precedence alone is not enough:
   in the prototype, a rejected squatter that redefined `billing_api` with
   `superuser: true` became the oldest claimant as soon as billing pushed an
   out-of-scope edit, and the composed plan contained
   `ALTER ROLE "billing_api" SUPERUSER`. Retaining the last accepted content
   keeps the owner's claims in place while its edit is broken. Model checking
   (see More information) found three paths where the prototype loses retained
   content, which the second paragraph closes, and the consequences of
   ordering by age, which the third states.

4. **Compose every accepted policy into one operator-owned `PostgresPolicy`
   per database**, named `<database>-composed` and labelled
   `pgroles.io/composed-for`, which the existing reconciler plans and applies.
   Every change in the composed plan records the attached policy and
   delegation it comes from.

   Rationale: D4. One database gets one inspect, diff and apply cycle, which
   also removes races between policies on it. Provenance answers "whose change
   is this?" during review, and is the input ADR-003 needs to route changes.
   Teaching the reconciler to compose directly would hide the generated
   object, but touches every path in a 6,500-line reconciler. It can follow
   later without an API change.

5. **Let the database owner name the executor role (`executorRole`).** The
   composed policy declares that role's inherited membership in every role
   that owns a schema or default privileges. Each attached policy's status
   names the role that executed its changes (`executedBy`).

   Rationale: in `authoritative` mode undeclared memberships are revoked, and
   no team should need to know the executor's name. Without this the
   prototype's executor lost the `INHERIT` membership `createrole_self_grant`
   gives it, and grants on objects those roles own failed authority preflight.

6. **Report status on every attached policy and on the database.** Each
   attached policy gets `Accepted` with a reason, and `Ready` mirrored from
   the composed policy, but only once the composed policy has reconciled the
   composition that includes that policy's current generation. `Ready` is per
   attached policy and may differ between policies of one database.
   `PostgresDatabase.status.attached` lists every attached policy in
   precedence order.

   Rationale: mirroring `Ready` directly reported a new policy ready before
   its content was applied. Per-policy readiness also keeps the door open for
   execution that is not all-or-nothing (ADR-003).

### Reserved for ADR-003

So that an executor per delegation can be added without breaking this API:

- `delegations[].name` is required and unique. Status, routing and approvals
  refer to it.
- `delegations[].executor` is reserved for an optional per-delegation executor.
- Change provenance (decision 4) and `executedBy` (decision 5) are recorded
  from the start.
- The routing principle any future execution model must keep: a change runs
  as the executor of the delegation whose policy asserted it, decided from the
  specs alone, never from which identity is able to run it.

### Trust model

A `PostgresDatabase` has one executor: the role its `connection`
authenticates as. Every statement of every attached policy runs as that role.

**What the executor can do.** It needs `CREATEROLE`, `CREATE` on the
database, `ADMIN OPTION` on the roles it manages, and inherited membership in
every role that owns a schema or default privileges in any delegation
(`executorRole` declares these). It can therefore create, alter and drop any
role it administers, and act as the owner of every delegated schema: grant,
revoke, and also read, change or drop the objects in them. Its authority is
the union of every team's.

**What the delegation checks protect against.** A policy that defines a role
outside its namespace's patterns, manages a schema facet it was not delegated,
adds a member to another team's role, grants database privileges to a role it
does not create, or writes `PUBLIC` is rejected before it reaches the composed
plan. A policy that collides with an older one is rejected alone, and a
rejected edit leaves the previously accepted content in place. Teams hold no
database credential, so they cannot bypass these checks by connecting
directly.

**What they do not protect against.** The checks run inside pgroles.
PostgreSQL enforces none of them, because the executor may do everything any
team may do. A bug in the delegation rules, in composition, or in statement
rendering can act across teams, up to the executor's full authority. So can
anyone who can change the `PostgresDatabase`, read its Secret, or control the
operator. Delegations limit what a team can ask for; they are not a
PostgreSQL privilege boundary between teams.

**Who must be trusted.** The database owner (the `PostgresDatabase`, its
namespace and its Secret), the operator's service account, and pgroles itself.

**Recommended setup.**

- Give the executor `CREATEROLE` and `CREATE` on this database only. Never
  `SUPERUSER`, and not `BYPASSRLS`, `REPLICATION` or `CREATEDB`.
- Use one executor per database, for nothing but pgroles.
- Let pgroles create the owner roles, so the executor's `ADMIN OPTION` covers
  exactly the roles pgroles manages, and set `executorRole` so the memberships
  it needs are declared rather than accumulated.
- Use `approval: manual` where a plan should be read before it runs. The plan
  shows which attached policy each change comes from.
- Restrict who can edit the `PostgresDatabase` and read Secrets in its
  namespace.

**If PostgreSQL must enforce the boundary between teams,** use independent
`PostgresPolicy` resources, each with its own narrowly privileged executor
(option 2, with #265's conflict rule), until ADR-003 offers an executor per
delegation.

### Consequences

- Good, because teams no longer hold executor credentials; only the database
  owner does.
- Good, because a team cannot add itself to another team's roles, open
  `PUBLIC`, or mint roles in another team's name space.
- Good, because a broken or hostile policy is rejected on its own, and an
  established policy keeps converging.
- Good, because a role can receive access from several teams without any of
  them owning it.
- Good, because there is one plan per database, so plan review, approval and
  drift are per database rather than spread across policies.
- Bad, because one composed plan couples teams: a plan the executor cannot
  run, or one awaiting approval, holds back every team on that database. That
  follows from one transaction, not one executor, which ADR-003 can change.
- Bad, because the database owner approves plans that contain other teams'
  changes, unless per-team approval is designed (open question 1).
- Bad, because the executor's authority is the union of every team's, and the
  delegation checks run only inside pgroles. A bug in those checks, in
  composition or in rendering is not bounded by PostgreSQL privileges. See
  Trust model.
- Bad, because users see a generated `PostgresPolicy` in listings.
- Neutral, because precedence by creation time makes delete-and-recreate lose
  priority, which is usually what an owner wants but can surprise.
- Neutral, because policies with `connection` remain, so the operator carries
  two models.
- Neutral, because the claims model changes bundle composition too: external
  declarations stop being owned.

### Confirmation

- Unit tests for the admission rules, precedence and retention in
  `crates/pgroles-core/src/attachment.rs`.
- Unit tests for the claims model, including a property test that two
  policies the model accepts never plan to undo each other. #265 carries the
  operator-side tests for independent policies.
- A scripted scenario in `scripts/prototype-postgres-database/` that drives
  three teams and four bad policies against a real API server and PostgreSQL,
  and checks the outcome in both (results below).
- TLA+ models in `docs/design/models/`: `AttachmentPrecedence.tla` checks
  precedence, retention and composition; `PolicyConflictDetection.tla` checks
  conflict detection between independent policies. The README there lists
  each property and its result.
- Before this ADR is accepted: port that scenario to the Rust cluster harness
  in `crates/pgroles-operator/tests/cluster_e2e/`, so CI runs it on every
  change, including the retention and readiness cases.

## Pros and cons of the options

### 1. Attached policies under a `PostgresDatabase`

- Good, because the owner grants scope, which satisfies D1 without trusting
  the policy's own declaration.
- Good, because precedence and retention keep failures local (D2).
- Good, because it reuses the reconciler through one generated policy (D4).
- Bad, because it adds a kind, a controller and a generated object.
- Bad, because a shared plan couples teams (see Consequences).
- Bad, because one executor holds every team's authority (D8).

### 2. Independent policies compared by resolved database (#263, #265)

- Good, because it needs no new kind and is already implemented.
- Good, because each team's executor can be narrowly privileged, so
  PostgreSQL bounds each policy (D8).
- Good, with #265, because policies that only share a grantee no longer
  conflict (D9).
- Bad, because every team still holds an executor credential (D6), and
  containment depends on how narrowly each executor is privileged (D1).
- Bad, because conflicts still block both policies (D2).
- Bad, because separate operator installs cannot see each other, and two new
  policies can each apply once before either sees the other.

### 3. Claims recorded in the database

- Good, because checking and recording claims under the advisory lock is
  atomic, and visible to every operator install and to the CLI.
- Bad, because it keeps pgroles state beside the roles, which fails D3.
- Bad, because claims can outlive their owner and need cleanup by hand when a
  cluster disappears.

### 4. Bundles rendered in CI into one policy

- Good, because it works today, and ownership is already per grant.
- Good, with #262, because containment can be enforced at composition time.
- Bad, because every change goes through one repository or render job, which
  fails D5.
- Bad, because a fragment that fails composition fails the whole render, so
  one team's mistake blocks the others (D2).

### 5. Option 1 with an executor per delegation

- Good, because PostgreSQL itself bounds each team's grants, default
  privileges and memberships, so a pgroles bug cannot exceed them (D8). This
  is the separation the deployment that prompted ADR-003 relies on.
- Good, because one team's failed step need not hold back the others.
- Bad, because one composed plan no longer runs in one transaction under one
  identity: changes are split into steps, and partial failure, retries and
  approval need designing.
- Bad, because PostgreSQL has no namespace for role names, so it cannot
  enforce the role-pattern part of a delegation whichever identity runs
  `CREATE ROLE`.
- Bad, because a revoke only removes grants made by a grantor the executor can
  act as, so moving an existing delegation onto its own executor needs a
  reviewed re-grant step.
- Neutral, because it extends option 1 rather than replacing it. Deferred to
  ADR-003; this record reserves what it needs.

## More information

### Prototype

Branch:
[`prototype/postgres-database`](https://github.com/thepartly/pgroles/tree/prototype/postgres-database),
based on #263. It implements decisions 1 to 6 as first drafted, and is
evidence for this record, not code to merge as is. It predates the claims
wording in decision 2 and the reserved fields.

It ran against a real `kube-apiserver` 1.31 and PostgreSQL 16, with a
non-superuser `CREATEROLE` executor. The teams are `examples/microservices`
(platform, billing, shipping), turned into attached policies. All 27 checks
pass:

| Scenario | Result |
| --- | --- |
| Three teams bootstrap, migrate, then attach full policies | One plan converges; cross-team grants work |
| Isolation between teams | `billing_api` cannot read shipping's tables |
| Membership into another team's role | `OutOfScope`; nothing reaches PostgreSQL |
| Namespace without a delegation | `NotDelegated` |
| `CREATE` on the database to `PUBLIC` | `OutOfScope` |
| Newer policy redefining `billing_api` as superuser | `Conflicted`; the database stays `Ready` |
| Out-of-scope edit while that squatter waits | Edit rejected, previous generation kept, squatter still `Conflicted` |
| Credentials | Only the owner's namespace holds a database Secret |

Moving the example to delegations needed one change: database `CONNECT` for
the platform's `team_*` roles moved from the billing and shipping policies to
the platform policy.

Findings that shaped this revision:

- **An attached policy that declares an external role is rejected as
  `Invalid`.** Bundle composition registers every expanded role as owned,
  external ones included. Decision 2 makes external declarations references.
- **Two attached policies cannot grant on objects in one schema.** An explicit
  grant claims the schema's exclusive `bindings` facet. Open question 10.
- **Grant ownership is per object, not per privilege.** Two policies granting
  different privileges on one object to one role collide. Open question 10.
- **A team leaving.** Deleting shipping's policy left its roles in place, and
  billing's grant to `shipping_migrator` never converged, because a role no
  policy declares is not inspected. Decision 2's implicit external roles and
  `DanglingReference` address the convergence half.
- **Owner self-grants.** A grant of `CREATE, USAGE` on a schema to the role
  that owns it is accepted by PostgreSQL but never appears in the ACL when a
  non-superuser runs it, so the plan never converges. This predates this
  design.

### Model checking

TLC checked both models exhaustively at small bounds (two or three policies,
two roles, bounded edits and re-creations; up to 5.7 million distinct states).

Attached policies (`AttachmentPrecedence.tla`):

- **Holds everywhere**, including the prototype as written: composed claims
  are pairwise disjoint, and composition does not depend on listing order.
- **Retention prevents takeover by a younger policy** only when it covers every
  rejection path. The prototype misses three: its `profiles` pre-check
  rejects a policy before retention applies (`AP_ProfilesBypass`); its status
  is keyed by namespace and name, so a re-created policy inherits its
  predecessor's retained content until generations collide (`AP_NameReuse`);
  and it patches the composed policy before recording retained content, so a
  failed status write loses it (`AP_StatusLoss`). Decision 3 now closes all
  three; the fixed variants hold.
- **Ordering by age** has the consequences decision 3 states: an older policy
  can take a younger one's role by editing (`AP_StrictTakeover`,
  `AP_ElderKnockout`), deleting an older policy can displace an unchanged
  younger one (`AP_StableDeletion`), and same-second creation orders by name
  (`AP_Ties`).

Independent policies (`PolicyConflictDetection.tla`, the operator on `main`):

- **Holds:** a conflicting pair that starts together never both applies; after
  an upgrade at most one applies again, and only until its peer records a
  target; pairs sharing a Secret never apply.
- **Limits, now documented in the operator architecture guide:** editing
  `spec.connection` reopens the window until the policy records again
  (`PCD_ConnEditClobber`); a Secret re-pointed at another database leaves a
  stale target that blocks peers while the policy cannot connect
  (`PCD_RetargetPhantom`); and progress for a non-conflicting policy relies on
  the lock being granted eventually, which the operator's jittered retries
  provide but TLC does not assume (`PCD_Starvation`).

### Open questions

1. **Approval.** Should teams approve the part of a composed plan their policy
   causes? ADR-003's per-step digests would give this a mechanism.
2. **Generated passwords.** The composed policy lives in the owner's
   namespace, so generated password Secrets land there. They belong in the
   attached policy's namespace.
3. **Leaving.** Should deleting an attached policy retire its roles, orphan
   them, or require an explicit `retirements` entry first?
4. **Consent for references.** Whether a referenced team must consent before
   others grant to its roles (as Gateway API's `ReferenceGrant` does).
5. **Delegation selectors.** Namespace names only, or label selectors?
6. **Retained content.** The prototype keeps it in `PostgresDatabase` status,
   which is bounded by object size, and must record it before patching the
   composed policy (decision 3).
7. **Candidates and ephemeral access.** How `PostgresPolicyCandidate` and
   `EphemeralAccessPolicy` refer to attached policies.
8. **CLI bundles.** A bundle root is close to a `PostgresDatabase`; bundles
   could adopt the same admission rules, first as an opt-in.
9. **Migration.** A `pgroles migrate` that generates a `PostgresDatabase` and
   attached policies from existing policies.
10. **Shared schemas and per-privilege ownership.** Whether several policies
    may grant on objects in one schema (a non-exclusive grants facet), and
    whether two policies may assert different privileges, or the same
    privilege, on one object for one role.
11. **Executor per delegation.** ADR-003: routing, steps, partial failure,
    approval of multi-step plans, and moving existing grants to a new grantor.
12. **Sticky claims.** Should an accepted claim survive an older policy
    claiming it later, and an older policy's deletion? Both need acceptance
    state recorded per claim, which retention already keeps per policy.

Questions 1, 3 and 4 are each large enough for their own record.

### Prior art

Kubernetes Gateway API replaced `Ingress` with the same moves:

| Gateway API | This decision |
| --- | --- |
| `Gateway`, owned by the platform team | `PostgresDatabase` |
| `HTTPRoute` with `parentRefs` | `PostgresPolicy` with `databaseRef` |
| `allowedRoutes` on a listener | `delegations` |
| Oldest route wins a conflict; the loser is `Accepted=False` | Same, plus retention of the last accepted generation |
| Status per parent | `Accepted` and `Ready` per attached policy, `status.attached` on the database |

### Steady state and migration

Steady state: a database shared between teams is a `PostgresDatabase` with
attached policies. A database with one owner keeps a `PostgresPolicy` with
`connection`, and so does a shared database whose teams need PostgreSQL to
enforce the boundary between them, until ADR-003 lands.

Migration: independent policies on one database keep working, compared by the
rule in decision 2's rationale. A team moves by replacing `connection` with
`databaseRef` once the database owner has created the `PostgresDatabase` and
its delegation; the moved policy's roles are then managed by the composed
policy. Open question 9 covers generating the `PostgresDatabase` from existing
policies.

### Process

This record stays Proposed while maintainers review it. Once accepted it may
be updated in place with corrected facts and measured results; a reversal of
the decision is a new record that supersedes it.
