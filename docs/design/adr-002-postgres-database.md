# ADR-002: Share a database through a PostgresDatabase and attached policies

- **Status:** Proposed
- **Date:** 2026-11-07
- **Decision-makers:** pgroles maintainers
- **Consulted:** operators running shared databases (see #261)
- **Related:** #91 (composed policies in the operator), #262 (bundle scopes),
  #263 (conflict detection on the resolved database), #261 (explicit
  absences in additive mode)
- **Supersedes / superseded by:** —

## Context and problem statement

How should several teams manage roles and grants on one PostgreSQL database
with pgroles, when no team should be able to exceed what it was given or undo
another team's work?

Today pgroles has two partial answers, and neither holds between teams that do
not fully trust each other.

**Several `PostgresPolicy` resources on one database (operator).**

- Each policy carries its own `connection`, so each team holds a credential
  for an executor with `CREATEROLE` and can bypass pgroles entirely.
- Policies are compared through `ownership_claims`, which treats every role a
  policy mentions as owned, including grantees and membership members. Two
  teams adding the same person to their own team roles conflict.
- A conflict blocks both policies, so a new or careless policy can freeze one
  that was converging.
- Which policies count as "the same database" is inferred. Before #263 the
  inference used namespace and Secret and missed most real overlaps. #263
  infers it from the server, but cannot see across separate operator installs,
  and leaves a window of one apply before two new policies see each other.

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

## Considered options

1. **Attached policies under a `PostgresDatabase` owned by the database
   owner**, with scope delegated by that owner.
2. **Independent policies**, compared by the database the server reports
   (#263), with finer ownership claims.
3. **Claims recorded in the database**, checked and updated under the
   advisory lock.
4. **Bundles rendered in CI into one policy**, with stricter fragment scopes
   (#262).
5. **Option 1 with a separate executor credential per delegation.**

## Decision outcome

Chosen option: **1, attached policies under a `PostgresDatabase`**, because it
is the only option that meets D1, D2, D3, D5 and D6 together, and it meets D4
by reusing the existing policy reconciler.

| Driver | 1 | 2 | 3 | 4 | 5 |
| --- | --- | --- | --- | --- | --- |
| D1 Containment | Yes | No | Partly | Yes, with #262 | Yes, enforced twice |
| D2 Isolation of failure | Yes | No | Yes | No | Yes |
| D3 No state in the database | Yes | Yes | **No** | Yes | Yes |
| D4 Reuse | Yes | Yes | Partly | Yes | No |
| D5 Self-service | Yes | Yes | Yes | No | Yes |
| D6 Fewer credentials | Yes | No | No | Yes | Partly |

We will:

1. **Add a `PostgresDatabase` kind, and let a `PostgresPolicy` attach to it
   with `databaseRef` instead of `connection`.** The database owner's resource
   holds the connection, execution settings (`mode`, `approval`, `interval`,
   `reconciliationMode`), shared `profiles` and `rolePattern`, and
   `delegations`. "The same database" becomes an object reference instead of
   an inference. Only the owner's namespace holds a database credential. A
   policy with `connection` keeps working as a single-owner policy.

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
   from the policy.**

   ```yaml
   spec:
     delegations:
       - namespaces: [billing]
         roles: ["billing_*"]
         schemas: [{name: billing, facets: [owner, bindings]}]
   ```

   - Every role a policy creates must match a delegated pattern, including
     roles generated by schema bindings. Otherwise a `role_pattern` such as
     `team_{profile}` mints names inside another team's delegation.
   - Schema `owner` and `bindings` facets, and grants or default privileges on
     a schema, need that facet delegated.
   - Membership in a role needs the role to be created by the same policy.
   - Database-level grants need the grantee to be created by the same policy.
     `PUBLIC` stays with the database owner.
   - A policy may grant on what it owns to any role. Billing can grant
     `SELECT` to the platform's `team_payments`, and `REFERENCES` to
     `shipping_migrator`.

   Rationale: scope that the policy declares about itself is not a boundary
   (#262). Scope granted by the owner is, and the rules close the escalation
   paths #262 found. The rules live in `pgroles-core` so bundles can use them.

3. **Resolve conflicts by precedence, and keep serving a policy's last
   accepted content when a newer edit is rejected.** Policies are admitted
   oldest first by `creationTimestamp`, then namespace and name. A policy that
   collides with an older one is rejected alone (`Accepted=False`, reason
   `Conflicted`). A rejected edit leaves the policy's previously accepted
   generation composed (`Retained`), the way a Deployment keeps its old
   ReplicaSet when a rollout fails.

   Rationale: blocking both policies fails D2. Precedence alone is not enough:
   in the prototype, a rejected squatter that redefined `billing_api` with
   `superuser: true` became the oldest claimant as soon as billing pushed an
   out-of-scope edit, and the composed plan contained
   `ALTER ROLE "billing_api" SUPERUSER`. Retaining the last accepted content
   keeps the owner's claims in place while its edit is broken.

4. **Compose every accepted policy into one operator-owned `PostgresPolicy`
   per database**, named `<database>-composed` and labelled
   `pgroles.io/composed-for`, which the existing reconciler plans and applies.

   Rationale: D4. One database gets one inspect, diff and apply cycle, which
   also removes races between policies on it. Teaching the reconciler to
   compose directly would hide the generated object, but touches every path in
   a 6,500-line reconciler. It can follow later without an API change.

5. **Let the database owner name the executor role (`executorRole`).** The
   composed policy declares that role's inherited membership in every role
   that owns a schema or default privileges.

   Rationale: in `authoritative` mode undeclared memberships are revoked, and
   no team should need to know the executor's name. Without this the
   prototype's executor lost the `INHERIT` membership `createrole_self_grant`
   gives it, and grants on objects those roles own failed authority preflight.

6. **Report status on every attached policy and on the database.** Each
   attached policy gets `Accepted` with a reason, and `Ready` mirrored from the
   composed policy, but only once the composed policy has reconciled the
   composition that includes that policy's current generation.
   `PostgresDatabase.status.attached` lists every attached policy in
   precedence order.

   Rationale: mirroring `Ready` directly reported a new policy ready before its
   content was applied.

### Consequences

- Good, because teams no longer hold executor credentials; only the database
  owner does.
- Good, because a team cannot add itself to another team's roles, open
  `PUBLIC`, or mint roles in another team's name space.
- Good, because a broken or hostile policy is rejected on its own, and an
  established policy keeps converging.
- Good, because there is one plan per database, so plan review, approval and
  drift are per database rather than spread across policies.
- Bad, because one composed plan couples teams: a plan the executor cannot
  run, or one awaiting approval, holds back every team on that database.
- Bad, because the database owner approves plans that contain other teams'
  changes, unless per-team approval is designed (open question 1).
- Bad, because the executor credential concentrates authority: a bug in
  pgroles' scope checks is no longer backstopped by PostgreSQL privileges, as
  it would be with per-team executors (option 5).
- Bad, because users see a generated `PostgresPolicy` in listings.
- Neutral, because precedence by creation time makes delete-and-recreate lose
  priority, which is usually what an owner wants but can surprise.
- Neutral, because policies with `connection` remain, so the operator carries
  two models until one is retired.

### Confirmation

- Unit tests for the admission rules, precedence and retention in
  `crates/pgroles-core/src/attachment.rs`.
- A scripted scenario in `scripts/prototype-postgres-database/` that drives
  three teams and four bad policies against a real API server and PostgreSQL,
  and checks the outcome in both (results below).
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

### 2. Independent policies compared by resolved database (#263)

- Good, because it needs no new kind and is already implemented.
- Bad, because every team still holds an executor credential, which fails D1
  and D6: pgroles' checks can be bypassed by connecting directly.
- Bad, because conflicts still block both policies (D2).
- Bad, because separate operator installs cannot see each other, and two new
  policies can each apply once before either sees the other.
- Neutral, because an admission webhook would not help: without connecting it
  cannot know which database a policy reaches.

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

### 5. Option 1 with an executor credential per delegation

- Good, because PostgreSQL itself enforces each team's boundary, so a pgroles
  bug cannot exceed it. This is the separation the #261 author relies on.
- Bad, because one composed plan can no longer run in one transaction under
  one identity, and statements must be routed to the identity that may run
  them.
- Bad, because cross-team grants need the granting team's identity, and
  ownership edges for each executor multiply.
- Neutral, because it extends option 1 rather than replacing it: a delegation
  could later carry its own connection.

## More information

### Prototype

Branch:
[`prototype/postgres-database`](https://github.com/thepartly/pgroles/tree/prototype/postgres-database),
based on #263. It implements decisions 1 to 6, and is evidence for this record,
not code to merge as is.

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

Two findings are not decided here:

- **A team leaving.** Deleting shipping's policy left its roles in place, and
  billing's grant to `shipping_migrator` never converged, because a role no
  policy declares is not inspected. Cross-team grantees probably need to be
  treated as external roles of the composition, with a reported dangling
  reference when no policy creates them.
- **Owner self-grants.** A grant of `CREATE, USAGE` on a schema to the role
  that owns it is accepted by PostgreSQL but never appears in the ACL when a
  non-superuser runs it, so the plan never converges. This predates this
  design.

### Open questions

1. **Approval.** Should teams approve the part of a composed plan their policy
   causes, and how would that bind to one plan digest?
2. **Generated passwords.** The composed policy lives in the owner's
   namespace, so generated password Secrets land there. They belong in the
   attached policy's namespace.
3. **Leaving.** Should deleting an attached policy retire its roles, orphan
   them, or require an explicit `retirements` entry first?
4. **Cross-team references.** Implicit external roles, dangling-reference
   status, and whether a referenced team must consent (as Gateway API's
   `ReferenceGrant` does).
5. **Delegation selectors.** Namespace names only, or label selectors?
6. **Retained content.** The prototype keeps it in `PostgresDatabase` status,
   which is bounded by object size.
7. **Candidates and ephemeral access.** How `PostgresPolicyCandidate` and
   `EphemeralAccessPolicy` refer to attached policies.
8. **CLI bundles.** A bundle root is close to a `PostgresDatabase`; bundles
   could adopt the same admission rules, first as an opt-in.
9. **Migration.** A `pgroles migrate` that generates a `PostgresDatabase` and
   attached policies from existing policies.

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

### Process

This record stays Proposed while maintainers review it. Once accepted it is
not edited; a later change of direction gets a new record that supersedes it.
