# TLA+ models for pgroles

Two specifications, model-checked with TLC (`tla2tools.jar` from the `v1.8.0` release URL; it reports version 2026.11.06.222357, rev d8fb231), Java 21, 4 cores.

| Spec | Models | Branch |
| --- | --- | --- |
| `PolicyConflictDetection.tla` | Cross-connection conflict detection between `PostgresPolicy` objects (PR #263 + #265) | `conflict-claims-by-reach` |
| `AttachmentPrecedence.tla` | Precedence and retention for policies attached to a `PostgresDatabase` (draft ADR-002, Decision 3) | `prototype/postgres-database` |

Each `.tla` file opens with the mapping from variables and actions to code (file and function) and the list of abstractions.

## Running

Download TLC first (not committed):

```bash
curl -fsSLo tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
```

```bash
./run.sh PolicyConflictDetection PCD_Fresh        # one configuration, log in out/PCD_Fresh.log
./run.sh AttachmentPrecedence AP_NoRetention 1    # 1 worker: shortest counterexample
python3 trace.py out/AP_NoRetention.log           # counterexample, changed variables only
./run_all.sh                                      # every configuration, writes results.txt (about 25 minutes)
./gen_pcd_cfgs.sh; ./gen_ap_cfgs.sh               # regenerate the .cfg files
```

`run.sh` is `java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config X.cfg X.tla -workers auto`.
The first line of every `.cfg` says what it checks and the expected outcome.

## Model 1: PolicyConflictDetection

One reconcile is `Start` (snapshot spec, connect, resolve target) → `Record` (write `status.resolved_database_target`) → `List` (list all policies, compare) → `TryLockOk`/`TryLockFail` → `Commit` (apply). Steps of different policies interleave freely. The environment can edit claims (`EditContent`), edit `spec.connection` (`EditConn`), re-point a Secret at another database without changing its name (`Retarget`), and make a connection unreachable or reachable (`Flip`). Initial states cover every assignment of policies to connection identities and of identities to databases.

Base constants: 2 policies, 2 or 3 connection identities, 2 databases, 2 contents with `c1`/`c2` conflicting. `PCD_Fresh3` and `PCD_Upgrade3` use 3 policies.

### Properties

| Property | Meaning |
| --- | --- |
| `NeverBothApplied` | (a) Two policies in conflict on one database never both have their work applied. For static specs. |
| `NoClobber` | (a) No apply made from a current snapshot lands where a conflicting peer's applied work is live. Usable with edits. |
| `NoStaleClobber` | The same for an apply made from a snapshot the spec has since moved past. |
| `NoAbaClobber` | The same when a spec was edited and reverted during a reconcile. |
| `NoMutualClobber` | (b) Upgrade start state: at most one member of a conflicting pair applies again. |
| `LateApplyBound` | (b) Once a conflicting peer holds a trusted record for the database, a policy commits at most one more apply. |
| `SameIdentityNeverApplies` | (b) A conflicting pair using the same Secret and key never applies at all. |
| `TrustedRecordAccurate` | (c) A record that peers trust (`connection_identity` equals the spec's identity) names the database the spec points at. |
| `NoPhantomConflict` | (c) No policy reports a conflict with a peer that does not target its database. |
| `NonConflictingApplies` | (d) A policy that is eventually always reachable and in conflict with nobody is applied infinitely often, given `LockFair`. |
| `ConflictingPairBlocks` | (d) A pair that is eventually always reachable and in conflict ends with both reporting `ConflictingPolicy` permanently. |
| `SameIdentityPairBlocks` | (d) The same, for pairs sharing a connection identity. |

Fairness: weak fairness on every reconcile step, strong fairness on taking the lock, none on the environment. `LockFair` is the extra assumption that a policy which keeps trying the lock keeps getting it.

### Results

| Configuration | Setting | Outcome | Distinct states | Time |
| --- | --- | --- | --- | --- |
| `PCD_Fresh` | fresh, static specs, outages | all safety properties hold | 936,192 | 13 s |
| `PCD_Fresh3` | 3 policies, static, no outages | all hold | 2,044,224 | 37 s |
| `PCD_FreshLive` | fresh, static, outages | `NonConflictingApplies`, `ConflictingPairBlocks` hold | 66,784 | 12 s |
| `PCD_Upgrade` | upgrade start state, outages | `NoMutualClobber`, `LateApplyBound`, others hold | 731,136 | 11 s |
| `PCD_Upgrade3` | 3 policies, upgrade | all hold | 2,044,224 | 34 s |
| `PCD_UpgradeLive` | upgrade, outages | both liveness properties hold | 66,784 | 12 s |
| `PCD_UpgradeWindow` | upgrade | `NoClobber` **violated** (expected) | 1,033 | 1 s |
| `PCD_CrdPruned` | CRD not upgraded | `NeverBothApplied` **violated** (expected) | 3,249 | 1 s |
| `PCD_CrdPrunedLive` | CRD not upgraded | `ConflictingPairBlocks` **violated** (expected) | 5,248 | 2 s |
| `PCD_CrdPrunedRemaining` | CRD not upgraded, outages | `SameIdentityNeverApplies`, `NoPhantomConflict` hold | 854,400 | 11 s |
| `PCD_CrdPrunedRemainingLive` | CRD not upgraded, outages | `NonConflictingApplies`, `SameIdentityPairBlocks` hold | 47,232 | 10 s |
| `PCD_ConnEdit` | `spec.connection` edits | `TrustedRecordAccurate`, `NoPhantomConflict` hold | 822,384 | 16 s |
| `PCD_ConnEditLive` | `spec.connection` edits | `NonConflictingApplies` holds | 822,384 | 187 s |
| `PCD_ConnEditClobber` | `spec.connection` edits | `NoClobber` **violated** | 349,576 | 7 s |
| `PCD_Retarget` | Secret re-pointed | `TrustedRecordAccurate` **violated** | 2,061 | 1 s |
| `PCD_RetargetPhantom` | Secret re-pointed | `NoPhantomConflict` **violated** | 23,480 | 2 s |
| `PCD_RetargetLive` | Secret re-pointed, outages | `NonConflictingApplies` **violated** | 447,488 | 61 s |
| `PCD_RetargetClobber` | Secret re-pointed | `NoClobber` holds | 4,481,680 | 59 s |
| `PCD_ContentEdit` | claim edits | `NoClobber`, `TrustedRecordAccurate`, `NoPhantomConflict` hold | 5,709,296 | 64 s |
| `PCD_ContentEditStale` | claim edits | `NoStaleClobber` **violated** | 38,674 | 2 s |
| `PCD_ContentEditAba` | claim edits | `NoAbaClobber` **violated** | 56,731 | 3 s |
| `PCD_Starvation` | fresh, static | liveness without `LockFair` **violated** | 5,920 | 2 s |

The liveness configurations and `PCD_ConnEdit` use `VIEW RealState`, which drops ghost variables that never influence a step. `PCD_FreshLive`, `PCD_UpgradeLive`, `PCD_CrdPrunedRemainingLive`, `PCD_CrdPrunedLive` and `PCD_Starvation` were also run without the view and gave the same verdicts. `PCD_ConnEdit` and `PCD_ConnEditLive` did not finish without it.

### What the results say

**(a) Fresh policies: holds.** With static specs, two conflicting policies on one database never both apply. This confirms the code comment in `reconcile_apply_inner`: each policy writes its target before it lists, so at least one sees the other.

**(b) The one-apply window, exactly.**

- Same Secret and key: neither policy ever applies (`SameIdentityNeverApplies`). The comparison needs no recorded target.
- Different Secrets, one database: at most one of the pair applies (`NeverBothApplied`, `NoMutualClobber`). The one that applies is the one whose `List` ran before the other's `Record`.
- Upgrade (`PCD_UpgradeWindow`, 6 states): `Start(p1)`, `Record(p1)`, `List(p1)` sees no record for `p2`, `TryLockOk(p1)`, `Commit(p1)`. `p1` applies over `p2`'s existing work once more. `p2` never applies again.
- "Once" is exact only after the peer records: from then on the winner commits at most one more apply, the reconcile that had already listed (`LateApplyBound`). Before the peer records there is no bound. A peer that cannot connect never records, so the winner keeps applying, and the peer applies nothing. When the peer later connects, both end in `ConflictingPolicy` (`ConflictingPairBlocks`).
- Both members of a pair can each apply in these cases only: CRD not upgraded, `spec.connection` re-pointed (below), or a reconcile working from a superseded snapshot (below).

**(c) Stale targets.**

- The `connection_identity` guard does what its doc comment says for spec edits: with `spec.connection` edits allowed, a trusted record always names the right database and no phantom conflict is reported (`PCD_ConnEdit`).
- The guard also re-opens the window (`PCD_ConnEditClobber`, 12 states). `p1` applies on `d1` through `i1`. `p1`'s connection is edited to `i3`, which reaches the same database. `p1`'s record now fails the guard, so `p2` (same database, other Secret, conflicting) lists, sees no trusted peer, and applies over `p1`'s live work. Both report the conflict once `p1` reconciles again. If `p1` cannot connect through the new Secret, `p2` stays unblocked.
- The guard does not cover a Secret whose contents change (`PCD_RetargetPhantom`, 7 states). The identity is namespace/Secret/key, so the record stays trusted while it names the old database. `p1` and `p2` record `d1`; `p1`'s Secret is re-pointed to `d2`; `p2` lists and reports a conflict with `p1`, which no longer targets `d1`. `PCD_RetargetLive` shows the block lasts for as long as `p1` cannot reconnect: nothing clears `resolved_database_target` on a failed reconcile (`mark_reconcile_failure_status` does not touch it).
- A stale-but-trusted record does not let anyone clobber live work (`PCD_RetargetClobber` holds): the re-pointed policy re-records before it lists.

**(d) Liveness.** Both properties hold for fresh and upgraded policies, with outages. `NonConflictingApplies` needs `LockFair`: without it TLC finds a schedule where one policy reaches the try-lock only while a non-conflicting peer on the same database holds it (`PCD_Starvation`). The operator's jittered requeue makes that schedule unlikely, not impossible.

**CRD not upgraded.** The API server prunes the status field, so no peer ever has a record. Policies through different Secrets both apply forever (`PCD_CrdPruned`, 11 states) and never report the conflict. What remains is the pre-PR guarantee: same-Secret pairs are detected and never apply, nobody sees a phantom conflict, non-conflicting policies apply.

**Superseded snapshots.** A reconcile compares its own snapshot of its spec against the peers' live specs.

- `PCD_ContentEditStale` (12 states): `p1` lists with content `c1` before `p2` has recorded, then `p1` is edited to `c2`. `p2` lists, sees `p1` at `c2`, applies. `p1`'s reconcile then commits `c1` over `p2`'s live work.
- `PCD_ContentEditAba` (13 states): `p1` applies `c1`, is edited to `c2`, `p2` lists and passes, `p1` is edited back to `c1`, `p2` commits.

Both need an edit to land inside one reconcile, and both existed before this PR for same-Secret pairs.

## Model 2: AttachmentPrecedence

State: which policies exist, their creation stamp, generation and content; the `PostgresDatabase` status entry per policy (`serving` generation and content); the verdict; and what went into the composed policy. `Reconcile` sorts by (stamp, name), admits oldest first, retries a rejected policy with its last accepted content, and writes status. The environment creates, deletes and edits policies. Content is `ok` with a set of claimed roles, `oos` (out of scope or invalid), or `prof` (sets `spec.profiles`).

Base constants: 2 or 3 policies, 2 roles, `MaxGen` 1 to 3, `MaxClock` 1 to 4.

Switches: `Retention`, `ProfilesBypass` (the `profiles` pre-check in `database.rs`), `NameKeyedStatus` (status entry looked up by namespace/name, as in `database.rs`), `AllowStatusLoss` (status write fails after the composed policy was written), `AllowTies` (two creations in one second).

### Properties

| Property | Meaning |
| --- | --- |
| `SortedOrderUnique` | (b) Exactly one ordering of the listed policies is sorted, so the listing order cannot matter. |
| `Idempotent` | (b) Reconciling again with nothing changed gives the same verdicts and serving content. |
| `RawListingOrderIrrelevant` | (b) Control: admitting in listing order would give the same outcome. Expected to fail. |
| `ComposedDisjoint`, `ServingDisjoint` | (c) No two composed (or serving) contents claim the same role. |
| `ComposedInScope` | Nothing out of scope is composed. |
| `NoTakeoverByYounger` | (a) A role a policy had accepted, has not released, and has not lost to an older policy is never composed for a younger policy. |
| `YoungerTakeoverOnlyViaElder` | (a) A younger policy gets a standing policy's role only if the owner released it or an older policy now collides with what the owner was serving. |
| `StrictNoTakeover` | (a) A standing policy loses a role only by releasing it. |
| `NewIsYoungest` | (d) A newly created policy sorts after every existing one. |
| `Stable` | (d) An accepted, unedited policy stays accepted if the policies older than it are the same objects, unedited, and none was deleted. |
| `StableDespiteElderDeletion` | (d) The same without "none was deleted". |
| `RetainedStaysServed` | (e) A retained, untouched policy keeps being served. |
| `NoTakeoverAfterElderWithdraws` | (e) A role lost to an older policy is not later composed for a younger one while the original owner is still rejected. |

### Results

| Configuration | Setting | Outcome | Distinct states | Time |
| --- | --- | --- | --- | --- |
| `AP_Retention` | 3 policies, retention, status keyed by object | (b), (c), `NewIsYoungest`, `YoungerTakeoverOnlyViaElder`, `Stable` hold | 835,525 | 110 s |
| `AP_Retention2` | 2 policies, same | same properties hold | 945,465 | 51 s |
| `AP_Retention2NoRecreate` | 2 policies, each created once | `NoTakeoverByYounger` holds | 38,693 | 4 s |
| `AP_ProfilesRetained` | profiles rejection goes through retention | `NoTakeoverByYounger` and the rest hold | 60,979 | 6 s |
| `AP_Prototype` | prototype as written (profiles pre-check, name-keyed status), 3 policies | (b), (c), `NewIsYoungest`, `Stable` hold | 1,457,824 | 195 s |
| `AP_NoRetentionRest` | retention off, 3 policies | (b), (c), `Stable` hold | 646,426 | 80 s |
| `AP_StatusLossRest` | status loss, 2 policies | (b), (c), `Stable` hold | 124,740 | 11 s |
| `AP_TiesRest` | ties, 2 policies | everything but `NewIsYoungest` holds | 567,462 | 36 s |
| `AP_NoRetention` | **retention off** | `NoTakeoverByYounger` **violated** (expected) | 2,048 | 2 s |
| `AP_ProfilesBypass` | retention on, profiles pre-check | `NoTakeoverByYounger` **violated** | 2,921 | 1 s |
| `AP_StatusLoss` | retention on, status write fails | `NoTakeoverByYounger` **violated** | 3,927 | 2 s |
| `AP_NameReuse` | retention on, name-keyed status | `YoungerTakeoverOnlyViaElder` **violated** | 304,471 | 32 s |
| `AP_ElderKnockout` | retention on, 3 policies | `NoTakeoverByYounger` **violated** | 63,272 | 7 s |
| `AP_Retention2Recreate` | retention on, 2 policies, one re-created | `NoTakeoverByYounger` **violated** | 42,450 | 6 s |
| `AP_StrictTakeover` | retention on | `StrictNoTakeover` **violated** | 1,780 | 1 s |
| `AP_RetainedDropped` | retention on | `RetainedStaysServed` **violated** | 5,375 | 2 s |
| `AP_ElderWithdraws` | retention on, 3 policies | `NoTakeoverAfterElderWithdraws` **violated** | 1,109,173 | 157 s |
| `AP_StableDeletion` | retention on, 3 policies | `StableDespiteElderDeletion` **violated** | 15,199 | 5 s |
| `AP_Ties` | same-second creation | `NewIsYoungest` **violated** | 109 | 0 s |
| `AP_RawListing` | control | `RawListingOrderIrrelevant` **violated** (expected) | 20 | 0 s |

### What the results say

**(a) Retention off reproduces the prototype finding** (`AP_NoRetention`, 6 states). Policy 1 (older) and policy 2 both claim `r1`. Reconcile: 1 `Accepted`, 2 `Rejected`. Policy 1 is edited to out-of-scope content. Reconcile: 1 `Rejected`, 2 `Accepted` with `r1`. This is the `billing_api` squatter. With retention on and the status entry tied to the object, the same edit leaves policy 1 `Retained` and policy 2 rejected (`YoungerTakeoverOnlyViaElder` holds in `AP_Retention`, `AP_Retention2`).

**(a) Three ways the prototype still loses the role with retention on.**

1. `AP_ProfilesBypass` (6 states). The owner's bad edit adds `spec.profiles`. `reconcile_database` rejects that policy before `compose_attached` and writes its status entry without serving content, so retention never applies. The younger policy is accepted with the role in the same reconcile. Sending that rejection through retention closes it (`AP_ProfilesRetained`).
2. `AP_StatusLoss` (6 states). The reconcile that accepts the owner writes the composed policy, then fails before `patch_status` on the `PostgresDatabase`. The owner's next bad edit finds no last-accepted content and is `Rejected`; the younger policy takes the role.
3. `AP_NameReuse` (12 states). The status entry is keyed by namespace/name and compared by generation. A policy is deleted and re-created under the same name before the next reconcile, with out-of-scope content. It is `Retained` on its predecessor's content, which it never held. When its generation reaches the predecessor's serving generation, `serving_generation != generation` is false, last-accepted is dropped, and it is `Rejected`; a younger policy takes the role.

**(a), (e) Rejection is all-or-nothing and erases the retained content.**

- `AP_StrictTakeover` (6 states): an older policy edits itself to claim a role a younger policy serves. The younger policy is `Rejected`. Precedence is by policy age, not by who claimed the role first.
- `AP_ElderKnockout` (7 states): policy 2 serves `{r1, r2}`, policy 3 (youngest) wants `r2` and is rejected. Policy 1 (oldest) edits to claim `r1`. Policy 2 is rejected as a whole, without having changed, and policy 3 is accepted with `r2`.
- `AP_RetainedDropped` (8 states): policy 2 is `Retained` on `{r1}`. Policy 1 (older) edits to claim `r1`. Policy 2 becomes `Rejected` and its status entry is written without serving content.
- `AP_ElderWithdraws` (9 states): after that, the older policy moves its claim to another role. The owner is still rejected, and a younger policy is accepted with the role the owner lost.
- All of these need the older policy to be allowed the role, so they arise between policies of one namespace or under overlapping delegations.

**(b) Determinism: holds.** The sort key is total, reconcile is a function of (policies, stamps, generations, contents, status), and it is idempotent. The control shows the sort is what provides this.

**(c) Disjoint claims: holds** in every configuration, including the prototype as written, retention off, status loss and ties.

**(d) Stability.**

- With strictly increasing timestamps a new policy is always youngest, and `Stable` holds.
- `AP_Ties` (3 states): `creationTimestamp` has one-second resolution and ties break by namespace/name, so a policy created in the same second with a smaller name sorts first. `Create(2)`, `Create(1)`.
- `AP_StableDeletion` (7 states): policy 1 serves `{r1}`, policy 2 wants `{r1, r2}` and is rejected, policy 3 serves `{r2}`. Deleting policy 1 gets policy 2 accepted, and policy 3 is `Rejected`. Policy 3 did not change, so it has no last-accepted content to fall back on.

## Not modelled, or not checked

Model 1:

- Several operator replicas reconciling one policy at once. Records are idempotent, so this should add no behaviours; not checked.
- `WATCH_NAMESPACE`-scoped installs, suspend, observe mode, plan approval, policy deletion.
- A server that reports neither `system_identifier` nor an address (`from_server` returns `None`). It behaves like the CRD-not-upgraded case for that policy.
- By code reading only: `resolved_database_target` is `skip_serializing_if = "Option::is_none"` and `update_status` sends a JSON merge patch, so a `None` result cannot clear a previously stored target.
- Liveness is checked with 2 policies. The 3-policy runs are safety only and have no outages.

Model 2:

- Delegation changes. Scope is a fixed property of the content.
- Schema facets, grants and revoke reach. Roles stand for anything claimed exclusively.
- A reconcile that reads a stale cached `PostgresDatabase` status. `reconcile_database` takes `previous` from the reflector's copy; `AllowStatusLoss` covers only the lost write.
- The composed policy's own reconcile and the `Ready` mirroring.
- Clock skew between API servers.
- The largest 3-policy runs use `MaxGen = 2`, `MaxClock = 3`, so no policy is re-created while three exist. The 2-policy runs cover re-creation.
