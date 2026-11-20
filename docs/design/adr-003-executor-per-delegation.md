# ADR-003: Run each delegation as its own PostgreSQL role

- **Status:** Proposed
- **Date:** 2026-11-12
- **Decision-makers:** pgroles maintainers
- **Consulted:** operators running shared databases (see the discussion on
  #264)
- **Related:** ADR-002 (PostgresDatabase and attached policies), #265
  (conflict claims by revoke reach)
- **Supersedes / superseded by:** — (extends ADR-002)

## Context and problem statement

ADR-002 gives each shared database one executor. Its trust model says so
plainly: the executor's authority is the union of every team's, the
delegation checks run only inside pgroles, and a bug in those checks is not
bounded by PostgreSQL.

Some deployments rely on that bound. An operator running platform and
application policies with separate SQL identities described why, in feedback
on ADR-002 (#264): with
narrowly privileged executors, PostgreSQL itself limits what each one can
change, which remains a boundary if pgroles' validation or statement routing
goes wrong. The credentials can still be held centrally by the database owner;
teams need not see them, and not every executor needs `CREATEROLE`. They
accept losing a single transaction across teams, and asked three questions any
design must answer: which identity runs each statement, what happens after a
partial failure, and how a retry is reviewed against fresh state. Falling back
to a more powerful identity when a team's executor lacks authority would
undermine the isolation.

How can a `PostgresDatabase` run each delegation's changes as that
delegation's own PostgreSQL role, without giving up ADR-002's composition,
precedence and status?

## Decision drivers

- **E1 — PostgreSQL bounds each team.** A change a team's policy causes can do
  no more in PostgreSQL than that team's executor is allowed to.
- **E2 — No fallback.** A change never runs under a more powerful identity
  because the intended one failed.
- **E3 — Visible routing.** Reviewers can see which identity runs each change
  before it runs.
- **E4 — Recoverable partial failure.** After a partial failure, the next
  reconcile converges from fresh state, without a replay or a stored cursor.
- **E5 — No pgroles state in the database** (ADR-002 D3).
- **E6 — Least privilege.** Not every executor needs `CREATEROLE`.
- **E7 — Reuse.** Keep the existing reconciler, plans, approval and preflight
  where possible (ADR-002 D4).

## Considered options

1. **Steps inside one composed plan.** One composed policy; the reconciler
   splits its plan into steps by identity and runs each on its own connection.
2. **One generated policy per executor.** The `PostgresDatabase` controller
   generates one ordinary `PostgresPolicy` per identity, each restricted to the
   changes its delegation owns.
3. **Route by capability.** Run each change as whichever configured identity
   PostgreSQL would allow to run it.
4. **Keep one executor.** ADR-002 as is; deployments that need E1 keep
   independent policies.

## Decision outcome

Chosen option: **2, one generated policy per executor**, routed by
provenance, because it meets E1 to E6 and reuses the reconciler (E7), so the
PostgreSQL boundary can be tested before any reconciler change. Option 1
remains the candidate if option 2's eventual ordering proves unworkable (see
Confirmation). Option 3 is rejected because it fails E1 and E2 by design.

We will:

1. **Route by provenance, never by capability.** A change runs as the executor
   of the delegation whose policy asserted it, decided from the composed
   policy and the `PostgresDatabase` spec alone. If that executor lacks
   authority, the change does not run, and no other identity is tried.

   Rationale: this is the only rule under which PostgreSQL is a second
   boundary. A statement that slipped past the delegation check arrives at the
   team's own executor, and PostgreSQL refuses it. Capability-based routing
   would find the powerful identity instead.

2. **Add an optional executor to each delegation**, in the field ADR-002
   reserves:

   ```yaml
   spec:
     connection: {secretRef: {name: appdb-owner}}   # the database owner's executor
     executorRole: pgroles_owner
     delegations:
       - name: billing
         namespaces: [billing]
         roles: ["billing_*"]
         schemas: [{name: billing, facets: [owner, bindings]}]
         executor:                                  # optional
           role: pgroles_billing                    # checked as current_user after connecting
           connection: {secretRef: {name: appdb-billing-executor}}
           manages: [grants, defaultPrivileges]     # default; may add memberships
   ```

   - Credentials live in the `PostgresDatabase`'s namespace. Teams never see
     them.
   - Each executor connection must resolve to the same server-reported
     database as the owner's connection, and its `current_user` must equal
     `executor.role`. Otherwise the delegation reports
     `ExecutorTargetMismatch` or `ExecutorRoleMismatch`, and none of its
     changes run.
   - A superuser executor is reported as a warning condition, because it
     voids the boundary.

3. **Keep role and schema lifecycle with the owner's connection by default.**
   `manages` lists the kinds of change the delegation's executor runs:
   `grants`, `defaultPrivileges`, `memberships`, and only by explicit choice
   `roles` and `schemas`. Kinds not listed run as the owner's connection by
   declaration, visibly in the spec and in the plan, which is different from
   fallback. Database-level grants always run as the owner's connection.

   Rationale: E6, and a PostgreSQL limit. Role names have no namespace, so an
   executor with `CREATEROLE` can create a role inside another team's pattern
   whatever pgroles does. For role lifecycle, the delegation check is the only
   guard either way, so keeping it with the owner costs nothing in isolation
   and removes `CREATEROLE` from every team executor.

4. **Attribute every change to exactly one identity:**

   | Change | Attributed to | Runs as |
   | --- | --- | --- |
   | Grant or revoke a policy asserts | That policy's delegation | Its executor if it manages `grants` |
   | Revoke of undeclared privileges on a delegated schema | Delegation holding the schema's facet | Same |
   | Cross-team grant, e.g. billing grants `REFERENCES` to `shipping_migrator` | The delegation that asserted it (billing) | Billing's executor |
   | Default privileges for an owner role in a schema | Delegation holding the schema | Its executor if it manages `defaultPrivileges` |
   | Membership in role R | R's lifecycle owner | Its executor if it manages `memberships` |
   | Role create, alter, drop, password, comment, retirement | The role's lifecycle owner | Owner's connection unless `manages: [roles]` |
   | Schema create and owner change | Delegation holding the `owner` facet | Owner's connection unless `manages: [schemas]` |
   | Database-level grants | The grantee's lifecycle owner | Owner's connection |
   | Executor bootstrap edges (item 5) | The database owner | Owner's connection |

   A change no delegation is attributed, or that two are, fails the
   composition before anything runs.

5. **Declare each executor's bootstrap edges.** ADR-002 decision 5 has the
   composed policy declare the owner executor's inherited membership in owner
   roles. Here, for each delegation with an executor, the owner's policy also
   declares that executor's inherited membership in the owner roles of the
   delegation's own schemas, and `ADMIN OPTION` on its roles if it manages
   `memberships`. These edges are the full statement of what a team executor
   can do: whatever the owner roles of its own schemas can do, and nothing
   else.

6. **Execute through one generated `PostgresPolicy` per identity.** The
   controller emits `<database>-composed` for the owner's connection and
   `<database>-composed-<delegation>` for each delegation with an executor.
   Each is an ordinary policy with its own connection, restricted to the
   changes attributed to its identity, using the managed-scope inspection and
   change-surface checks that bundles already have. The existing reconciler
   runs each one unchanged: its own inspect, plan, approval, transaction and
   status. A team policy whose roles do not exist yet fails and retries until
   the owner's policy has created them.

7. **Check authority per identity, without fallback.** Each generated policy
   runs the existing authority preflight on its own connection. If it reports
   issues, that policy's plan does not run; its status is `Ready=False`,
   reason `ExecutorAuthority` (as today), naming the delegation, the executor role,
   the changes, and what the database owner needs to grant (for example
   `GRANT billing_migrator TO pgroles_billing WITH INHERIT TRUE`). Other
   identities' plans still run.

8. **Recover by re-planning, and approve per identity.**
   - Each generated policy's plan commits or rolls back whole. Nothing is
     compensated: undoing a committed plan would be a second, unreviewed
     plan.
   - The next reconcile inspects again and plans again, so a retry holds only
     what is still needed. There is no stored cursor; the database is the
     record of what was applied (E5).
   - Each plan's digest binds its changes, its executor role and its resolved
     target, so changing which identity runs something needs a new approval.
     A recomputed plan identical to an approved one stays approved, as plans
     do today. Per-team approval of a team's own plan follows for free.
   - An attached policy is `Ready` when every generated policy carrying its
     changes is ready for the composition that includes its current
     generation. Its status names the executing role (`executedBy`).

### Consequences

- Good, because a bug in pgroles' delegation checks or routing cannot make a
  team executor exceed its PostgreSQL privileges.
- Good, because one team's failed or blocked plan does not hold back the
  others, which removes ADR-002's "a plan the executor cannot run holds back
  every team".
- Good, because each team's plan can be approved on its own.
- Good, because team executors need no `CREATEROLE`.
- Bad, because there is no transaction across teams: between plans, the
  database can hold one team's changes and not another's.
- Bad, because ordering is eventual. A team policy fails until the owner's
  policy has created its roles, so `Ready=False` appears during first
  convergence, and retirement has no guard ordering it after other teams'
  revokes.
- Bad, because each identity inspects separately, multiplying inspection
  load per database.
- Bad, because there are more Secrets, connection pools and provider
  credentials (IAM, Entra) to manage per database.
- Neutral, because role names stay guarded by pgroles alone, as with one
  executor.

### Confirmation

- Extend the ADR-002 scenario with three executor roles: grants converge
  under each team's identity; a policy whose team executor lacks a needed
  membership reports `ExecutorAuthority` and nothing runs as the owner
  for it; a forged change attributed to billing but touching shipping's schema
  is refused by PostgreSQL.
- A property test that plans attributed to different delegations commute: any
  order of their application reaches the same end state.
- Measure first convergence and retirement with eventual ordering. If the
  `Ready=False` flapping or unguarded retirement is unacceptable, move to
  option 1 with explicit establish, grant and retire phases.

## Pros and cons of the options

### 1. Steps inside one composed plan

- Good, because ordering is explicit: establish, then grants per delegation,
  then retirement only if every grant step succeeded.
- Good, because one plan artifact covers every team's changes for review.
- Bad, because execution, preflight, the approval encoding and plan status all
  change inside the reconciler (fails E7).
- Bad, because identity-relative inspection (wildcard grantability, the
  executor's own ADMIN edges) must be re-run per step.

### 2. One generated policy per executor

- Good, because the existing reconciler runs each identity unchanged (E7).
- Good, because identity-relative inspection is right by construction.
- Good, because per-team approval needs no new mechanism.
- Bad, because ordering is eventual and retirement is unguarded.
- Bad, because review is spread across several plans.

### 3. Route by capability

- Good, because changes rarely block.
- Bad, because a validation bug would find the most powerful identity, which
  defeats E1 and is exactly the fallback E2 forbids.

### 4. Keep one executor

- Good, because it adds nothing.
- Bad, because deployments that need E1 cannot use `PostgresDatabase` at all
  and stay on independent policies, with every team holding a credential.

## More information

### Unresolved

- **Grantor attribution.** A revoke only removes grants made by a grantor the
  executor can act as, and a mismatch succeeds silently in PostgreSQL. Grants
  made before a delegation gets its own executor were made under another
  identity, so the team executor's revokes for them are blocked. With no
  fallback, moving a delegation onto its own executor needs an explicit,
  reviewed re-grant step run by the database owner.
- **Mixed ownership inside a schema.** A team executor cannot grant on objects
  in its schema owned by a role it is not a member of. That surfaces as an
  unsatisfiable wildcard, which blocks reconciliation today.
- **Passwords.** Setting a password needs `CREATEROLE` and ADMIN on the role,
  so it follows role lifecycle and stays with the owner's connection by
  default.
- **Ephemeral access.** Which identity grants an ephemeral membership: by item
  4, the role's lifecycle owner.
- **Changing `manages`.** Moving a kind of change between identities reopens
  grantor attribution.

### Steady state and migration

Steady state: a delegation without `executor` runs as the database owner's
executor, exactly as in ADR-002, so nothing changes for databases that do not
opt in. A delegation with `executor` runs its grants, default privileges and
(if listed) memberships as its own role.

Migration: adding `executor` to an existing delegation moves its changes to a
new identity, which is a new approval (item 8). Grants made earlier by the
owner's executor stay attributed to that grantor; until a re-grant step exists
(see Unresolved), revokes of those grants report `ExecutorAuthority`
rather than running as the owner.

### Process

This record stays Proposed until a prototype of option 2 has run the
confirmation scenario. Once accepted it may be updated in place with corrected
facts and measured results; a reversal is a new record that supersedes it.
