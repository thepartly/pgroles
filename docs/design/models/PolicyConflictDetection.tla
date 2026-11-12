----------------------- MODULE PolicyConflictDetection -----------------------
(***************************************************************************)
(* Cross-connection policy conflict detection in the pgroles operator, as  *)
(* implemented on branch `conflict-claims-by-reach` (PR #263 + #265).      *)
(*                                                                         *)
(* Code this models (all under crates/pgroles-operator/src/):              *)
(*   reconciler.rs  reconcile_apply            -> error path (ConnFailed)   *)
(*   reconciler.rs  reconcile_apply_inner      -> Start/Record/List/        *)
(*                                                TryLock/Commit            *)
(*   reconciler.rs  resolve_database_target    -> snap[p].db                *)
(*   reconciler.rs  detect_policy_conflict(_in_list) -> List, SameTarget    *)
(*   reconciler.rs  update_status              -> Record (GET + merge PATCH)*)
(*   crd.rs         ResolvedDatabaseTarget     -> rec[p] = [key, conn]      *)
(*   crd.rs         targets_same_database      -> SameTarget                *)
(*   crd.rs         OwnershipClaims::conflicts -> Conf (abstract relation)  *)
(*   crd.rs         ConnectionSpec::identity_key / DatabaseIdentity         *)
(*                                             -> spec[p].id                *)
(*   advisory.rs    try_acquire                -> TryLock (per database)    *)
(*   context.rs     get_or_create_pool         -> Start (re-reads the       *)
(*                                                Secret every reconcile)   *)
(*                                                                         *)
(* One reconcile of policy p is the sequence                               *)
(*   Start  : snapshot the spec, connect, ask the server which database    *)
(*   Record : write status.resolved_database_target = {key, conn}          *)
(*   List   : list every PostgresPolicy (consistent API read) and compare  *)
(*   TryLock: in-process lock + pg advisory lock, keyed on the database    *)
(*   Commit : apply the plan in one transaction, release the lock          *)
(* Steps of different policies interleave arbitrarily.                     *)
(*                                                                         *)
(* Abstractions                                                            *)
(*  - A DatabaseIdentity (namespace/Secret/key) is a model value in        *)
(*    Identities. secretDb maps it to the database the Secret currently    *)
(*    points at. Two identities may map to one database (two Secrets, two  *)
(*    namespaces).                                                         *)
(*  - The server-reported key (digest of system_identifier, address, port, *)
(*    database) is the database itself.  The case where the server reports *)
(*    nothing (from_server returns None) behaves like CrdUpgraded = FALSE  *)
(*    for that policy and is not modelled separately.                      *)
(*  - Policy content is a model value; Conf is a constant symmetric        *)
(*    relation over contents.                                              *)
(*  - The reconcile works on a snapshot of the spec taken at Start (the    *)
(*    Arc<PostgresPolicy> handed to reconcile()), while peers are read     *)
(*    live at List.  Spec edits may land between any two steps.            *)
(*  - One reconcile per policy at a time (kube-rs controller guarantee     *)
(*    inside one replica).  Several operator replicas reconciling the same *)
(*    policy, WATCH_NAMESPACE-scoped installs, suspend, observe mode,      *)
(*    plan approval and policy deletion are NOT modelled.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Policies,          \* PostgresPolicy objects
    Identities,        \* DatabaseIdentity values (namespace/Secret/key)
    Databases,         \* physical databases, as the server reports them
    Contents,          \* abstract policy contents (their ownership claims)
    ConflictSets,      \* {{c1,c2},...}: unordered pairs of contents whose
                       \* claims overlap; {c} means c conflicts with a copy
                       \* of itself
    None,              \* model value
    CrdUpgraded,       \* FALSE: the API server prunes the new status field
    Legacy,            \* TRUE: every policy already applied under the old
                       \* operator (upgrade start state)
    AllowContentEdit,  \* spec edits that change claims
    AllowConnEdit,     \* spec edits that change spec.connection
    AllowRetarget,     \* a Secret's contents change to point elsewhere
                       \* (same identity, different database)
    AllowOutage        \* identities may become unreachable / reachable

VARIABLES
    spec,       \* [p -> [id, content]]   the PostgresPolicy spec in the API
    secretDb,   \* [identity -> database] what each connection reaches now
    up,         \* [identity -> BOOLEAN]  whether connecting succeeds
    rec,        \* [p -> None | [key, conn]] status.resolved_database_target
    cond,       \* [p -> "Unknown"|"Ready"|"Conflict"|"ConnFailed"]
    pc,         \* [p -> "idle"|"record"|"list"|"lock"|"applying"]
    snap,       \* [p -> None | [id, content, db, clean]] the reconcile's
                \*   snapshot of its own spec, plus the database it
                \*   connected to.  `clean` is a ghost: nothing the snapshot
                \*   was taken from has been changed since Start.
    \* ---- ghost variables, used only to state properties ----
    lastApply,  \* [p -> None | <<db, content>>] last committed apply
    intact,     \* [p -> BOOLEAN] p's last apply came from its current spec
                \* and nothing p's spec or Secret says has changed since:
                \* the database holds p's work and p still stands behind it
    abaClobber, \* like clobberers, but the victim's spec was edited away
                \* and back (same value, not intact) around the apply
    clobberers, \* policies that committed (from a current snapshot) while a
                \* conflicting peer's applied state was live on that database
    staleClobber, \* same, but committed from a superseded snapshot
    phantom,    \* a Conflict was reported against a peer that does not
                \* target the reporter's database
    late        \* [p -> 0..2] applies p committed while a conflicting peer
                \* held a trusted record for the same database (saturating)

vars == <<spec, secretDb, up, rec, cond, pc, snap,
          lastApply, intact, abaClobber, clobberers, staleClobber, phantom, late>>

\* The operator's and the environment's state without the ghosts (except
\* `phantom`).  The ghosts never influence a step, so configurations whose
\* properties mention only these variables use this as TLC's VIEW to keep
\* the state graph small.
RealState == <<spec, secretDb, up, rec, cond, pc, phantom,
               [p \in Policies |-> IF snap[p] = None THEN None
                                   ELSE <<snap[p].id, snap[p].content, snap[p].db>>]>>

-----------------------------------------------------------------------------
\* OwnershipClaims::conflicts is non-empty.
Conf(a, b) == {a, b} \in ConflictSets

\* Database p's spec currently points at (ground truth, not operator state).
DbOf(p) == secretDb[spec[p].id]

\* Ground truth: p and q point at one database with overlapping claims.
TruthConflict(p, q) == DbOf(p) = DbOf(q) /\ Conf(spec[p].content, spec[q].content)

\* q's recorded target is trusted by peers: crd.rs targets_same_database,
\* `theirs.connection_identity == peer_identity`.
Trusted(q) == rec[q] # None /\ rec[q].conn = spec[q].id

\* p's work is "live": applied, and p's spec and Secret are untouched since.
Live(p) == intact[p]

\* Weaker, by value: p's last apply equals what p's spec says now, although
\* the spec or Secret may have been changed and changed back in between.
LiveByValue(p) == lastApply[p] # None /\ lastApply[p] = <<DbOf(p), spec[p].content>>

TypeOK ==
    /\ spec \in [Policies -> [id : Identities, content : Contents]]
    /\ secretDb \in [Identities -> Databases]
    /\ up \in [Identities -> BOOLEAN]
    /\ rec \in [Policies -> {None} \cup [key : Databases, conn : Identities]]
    /\ cond \in [Policies -> {"Unknown", "Ready", "Conflict", "ConnFailed"}]
    /\ pc \in [Policies -> {"idle", "record", "list", "lock", "applying"}]
    /\ snap \in [Policies -> {None} \cup
                   [id : Identities, content : Contents, db : Databases,
                    clean : BOOLEAN]]
    /\ lastApply \in [Policies -> {None} \cup (Databases \X Contents)]
    /\ intact \in [Policies -> BOOLEAN]
    /\ abaClobber \in BOOLEAN
    /\ clobberers \subseteq Policies
    /\ staleClobber \in BOOLEAN
    /\ phantom \in BOOLEAN
    /\ late \in [Policies -> 0..2]

\* Every combination of specs and Secret targets is an initial state, so one
\* run covers same-Secret pairs, different-Secret pairs on one database, and
\* unrelated policies.  rec = None for everyone: a fresh policy and a policy
\* inherited from the old operator look the same to the protocol.  Legacy
\* only changes the ghost: the database already holds each policy's work.
Init ==
    /\ spec \in [Policies -> [id : Identities, content : Contents]]
    /\ secretDb \in [Identities -> Databases]
    /\ up \in IF AllowOutage THEN [Identities -> BOOLEAN]
                             ELSE {[i \in Identities |-> TRUE]}
    /\ rec = [p \in Policies |-> None]
    /\ cond = [p \in Policies |-> "Unknown"]
    /\ pc = [p \in Policies |-> "idle"]
    /\ snap = [p \in Policies |-> None]
    /\ lastApply = [p \in Policies |->
                      IF Legacy THEN <<secretDb[spec[p].id], spec[p].content>>
                                ELSE None]
    /\ intact = [p \in Policies |-> Legacy]
    /\ abaClobber = FALSE
    /\ clobberers = {}
    /\ staleClobber = FALSE
    /\ phantom = FALSE
    /\ late = [p \in Policies |-> 0]

-----------------------------------------------------------------------------
(* reconcile_apply_inner up to and including resolve_database_target.      *)
(* get_or_create_pool reads the Secret on every reconcile, so the database *)
(* reached is whatever the Secret points at now.  A failed connect returns *)
(* DatabaseConnect; reconcile_apply's error arm writes Ready=False and     *)
(* does not touch resolved_database_target (mark_reconcile_failure_status).*)
Start(p) ==
    /\ pc[p] = "idle"
    /\ IF up[spec[p].id]
         THEN /\ snap' = [snap EXCEPT ![p] = [id |-> spec[p].id,
                                              content |-> spec[p].content,
                                              db |-> secretDb[spec[p].id],
                                              clean |-> TRUE]]
              /\ pc' = [pc EXCEPT ![p] = "record"]
              /\ cond' = cond
         ELSE /\ cond' = [cond EXCEPT ![p] = "ConnFailed"]
              /\ UNCHANGED <<snap, pc>>
    /\ UNCHANGED <<spec, secretDb, up, rec, lastApply, intact, abaClobber,
                   clobberers, staleClobber, phantom, late>>

(* update_status writing managed_database_identity, resolved_database_     *)
(* target and owned roles "before peers are listed".  With a CRD that does *)
(* not declare the field the API server prunes it and nothing is stored.   *)
Record(p) ==
    /\ pc[p] = "record"
    /\ rec' = IF CrdUpgraded
                THEN [rec EXCEPT ![p] = [key |-> snap[p].db, conn |-> snap[p].id]]
                ELSE rec
    /\ pc' = [pc EXCEPT ![p] = "list"]
    /\ UNCHANGED <<spec, secretDb, up, cond, snap, lastApply, intact, abaClobber,
                   clobberers, staleClobber, phantom, late>>

(* targets_same_database(identity, resolved_target, other_identity,        *)
(* other_resolved).  `identity`/`resolved_target` are the reconcile's own  *)
(* locals (the snapshot), not what was stored; the peer side is read from  *)
(* the list: its current spec and its recorded status.                     *)
SameTarget(p, q) ==
    \/ spec[q].id = snap[p].id
    \/ /\ rec[q] # None
       /\ rec[q].key = snap[p].db
       /\ rec[q].conn = spec[q].id

Peers(p) == {q \in Policies \ {p} :
               SameTarget(p, q) /\ Conf(snap[p].content, spec[q].content)}

(* detect_policy_conflict + the ConflictingPolicy status write.  The list  *)
(* is one consistent read, so it is one atomic step.                       *)
List(p) ==
    /\ pc[p] = "list"
    /\ IF Peers(p) # {}
         THEN /\ cond' = [cond EXCEPT ![p] = "Conflict"]
              /\ pc' = [pc EXCEPT ![p] = "idle"]
              /\ snap' = [snap EXCEPT ![p] = None]
              \* Phantom: p's own view is current, yet it blames a peer whose
              \* spec does not point at p's database.
              /\ phantom' = (phantom \/
                    /\ snap[p].db = DbOf(p)
                    /\ \E q \in Peers(p) : DbOf(q) # snap[p].db)
         ELSE /\ pc' = [pc EXCEPT ![p] = "lock"]
              /\ UNCHANGED <<cond, phantom, snap>>
    /\ UNCHANGED <<spec, secretDb, up, rec, lastApply, intact, abaClobber,
                   clobberers, staleClobber, late>>

\* The advisory lock key is hashtextextended('pgroles-reconcile:' ||
\* current_database()) computed on the server, so every policy connected to
\* one database contends, whatever Secret it came through.
LockHeld(d) == \E q \in Policies : pc[q] = "applying" /\ snap[q].db = d

(* try_lock_database + advisory::try_acquire.  Failure is LockContention:  *)
(* the reconcile ends, status is left alone, the policy is requeued.       *)
TryLockOk(p) ==
    /\ pc[p] = "lock"
    /\ ~LockHeld(snap[p].db)
    /\ pc' = [pc EXCEPT ![p] = "applying"]
    /\ UNCHANGED <<spec, secretDb, up, rec, cond, snap, lastApply, intact,
                   abaClobber, clobberers, staleClobber, phantom, late>>

TryLockFail(p) ==
    /\ pc[p] = "lock"
    /\ LockHeld(snap[p].db)
    /\ pc' = [pc EXCEPT ![p] = "idle"]
    /\ snap' = [snap EXCEPT ![p] = None]
    /\ UNCHANGED <<spec, secretDb, up, rec, cond, lastApply, intact,
                   abaClobber, clobberers, staleClobber, phantom, late>>

(* apply_under_lock: inspect, diff, apply in one transaction, then release *)
(* the advisory lock.  The ghosts are updated here, at the commit point.   *)
Commit(p) ==
    /\ pc[p] = "applying"
    /\ LET d == snap[p].db
           c == snap[p].content
           Hits(q) == lastApply[q] # None /\ lastApply[q][1] = d
                        /\ Conf(lastApply[q][2], c)
           \* peers whose live work on d this apply can undo
           victims == {q \in Policies \ {p} : Live(q) /\ Hits(q)}
           victimsByValue == {q \in Policies \ {p} : LiveByValue(q) /\ Hits(q)}
           \* p's spec and Secret were not touched during this reconcile
           current == snap[p].clean
           \* weaker: the snapshot equals the spec now (possibly after an
           \* edit and a revert)
           currentByValue == /\ snap[p].id = spec[p].id
                             /\ c = spec[p].content
                             /\ d = DbOf(p)
           latePeers == {q \in Policies \ {p} :
                           Trusted(q) /\ rec[q].key = d /\ Conf(c, spec[q].content)}
       IN /\ lastApply' = [lastApply EXCEPT ![p] = <<d, c>>]
          /\ intact' = [intact EXCEPT ![p] = current]
          /\ clobberers' = IF victims # {} /\ current
                             THEN clobberers \cup {p} ELSE clobberers
          /\ abaClobber' = (abaClobber \/
                (victimsByValue # {} /\ currentByValue
                    /\ ~(victims # {} /\ current)))
          /\ staleClobber' = (staleClobber \/
                (victimsByValue # {} /\ ~currentByValue))
          /\ late' = [late EXCEPT ![p] =
                        IF latePeers # {} /\ @ < 2 THEN @ + 1 ELSE @]
    /\ cond' = [cond EXCEPT ![p] = "Ready"]
    /\ pc' = [pc EXCEPT ![p] = "idle"]
    /\ snap' = [snap EXCEPT ![p] = None]
    /\ UNCHANGED <<spec, secretDb, up, rec, phantom>>

-----------------------------------------------------------------------------
\* Environment.  Each change to what p targets or claims clears intact[p].

\* The reconciles of the policies in S no longer work from a current snapshot.
Dirty(S) == [q \in Policies |->
              IF q \in S /\ snap[q] # None THEN [snap[q] EXCEPT !.clean = FALSE]
                                          ELSE snap[q]]

EditContent(p) ==
    /\ AllowContentEdit
    /\ \E c \in Contents \ {spec[p].content} :
          spec' = [spec EXCEPT ![p].content = c]
    /\ intact' = [intact EXCEPT ![p] = FALSE]
    /\ snap' = Dirty({p})
    /\ UNCHANGED <<secretDb, up, rec, cond, pc, lastApply, abaClobber,
                   clobberers, staleClobber, phantom, late>>

\* spec.connection now names another Secret/namespace-key.  status is not
\* touched: the old resolved_database_target stays until p reconciles.
\* intact[p] survives when the new connection reaches the same database:
\* p's work is still there and p still claims it.
EditConn(p) ==
    /\ AllowConnEdit
    /\ \E i \in Identities \ {spec[p].id} :
          /\ spec' = [spec EXCEPT ![p].id = i]
          /\ intact' = [intact EXCEPT ![p] = @ /\ secretDb[i] = DbOf(p)]
    /\ snap' = Dirty({p})
    /\ UNCHANGED <<secretDb, up, rec, cond, pc, lastApply, abaClobber,
                   clobberers, staleClobber, phantom, late>>

\* The Secret behind an identity is rewritten to point at another database
\* (failover to a different server, a corrected URL, a restore).  The
\* identity (namespace/Secret/key) is unchanged.
Retarget(i) ==
    /\ AllowRetarget
    /\ \E d \in Databases \ {secretDb[i]} :
          secretDb' = [secretDb EXCEPT ![i] = d]
    /\ intact' = [p \in Policies |-> intact[p] /\ spec[p].id # i]
    /\ snap' = Dirty({p \in Policies : spec[p].id = i})
    /\ UNCHANGED <<spec, up, rec, cond, pc, lastApply, abaClobber,
                   clobberers, staleClobber, phantom, late>>

Flip(i) ==
    /\ AllowOutage
    /\ up' = [up EXCEPT ![i] = ~@]
    /\ UNCHANGED <<spec, secretDb, rec, cond, pc, snap, lastApply, intact,
                   abaClobber, clobberers, staleClobber, phantom, late>>

Reconcile(p) == \/ Start(p) \/ Record(p) \/ List(p)
                \/ TryLockOk(p) \/ TryLockFail(p) \/ Commit(p)

Next == \/ \E p \in Policies : Reconcile(p) \/ EditContent(p) \/ EditConn(p)
        \/ \E i \in Identities : Retarget(i) \/ Flip(i)

\* Every reconcile step eventually runs (the controller requeues forever).
\* Strong fairness on taking the lock: try-lock losers are requeued with
\* jitter, so a policy is not shut out forever by another one re-locking.
\* No fairness on the environment.
Fairness == \A p \in Policies :
    /\ WF_vars(Start(p)) /\ WF_vars(Record(p)) /\ WF_vars(List(p))
    /\ WF_vars(TryLockFail(p)) /\ SF_vars(TryLockOk(p)) /\ WF_vars(Commit(p))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* SAFETY

(* (a) Two conflicting policies on one database never both have their work *)
(* applied.  For static specs (no edits, no retargeting) and Legacy=FALSE. *)
NeverBothApplied ==
    \A p, q \in Policies :
        p # q /\ TruthConflict(p, q) => ~(Live(p) /\ Live(q))

(* (a'), usable with edits: no apply from a current snapshot ever lands on *)
(* a database where a conflicting peer's work is live.                     *)
NoClobber == clobberers = {}

(* (a''): the same for applies from a snapshot the spec has moved past.    *)
NoStaleClobber == ~staleClobber

(* (a'''): the same where a spec (the victim's or the applier's own) was   *)
(* changed and changed back while a reconcile was between Start and Commit.*)
NoAbaClobber == ~abaClobber

(* (b) Upgrade start state (Legacy=TRUE): both members of a conflicting    *)
(* pair applied under the old operator.  Under the new one at most one     *)
(* member of any conflicting pair applies again.                           *)
NoMutualClobber ==
    \A p, q \in clobberers : p # q => ~TruthConflict(p, q)

(* (b) "once": after a conflicting peer has a trusted record for this      *)
(* database, a policy commits at most one more apply (the reconcile that   *)
(* had already listed).  Static specs.                                     *)
LateApplyBound == \A p \in Policies : late[p] <= 1

(* (b) Same-Secret pairs are compared from the spec alone, so neither      *)
(* member ever applies - also with CrdUpgraded = FALSE.                    *)
SameIdentityNeverApplies ==
    \A p, q \in Policies :
        (p # q /\ spec[p].id = spec[q].id
               /\ Conf(spec[p].content, spec[q].content))
            => (clobberers \cap {p, q} = {} /\ (~Legacy => lastApply[p] = None))

(* (c) What the connection_identity guard buys: a record peers trust names *)
(* the database the policy's spec points at.  Holds while Secrets keep     *)
(* pointing where they did; spec.connection edits cannot break it.         *)
TrustedRecordAccurate ==
    \A q \in Policies : Trusted(q) => rec[q].key = DbOf(q)

(* (c) No policy is blocked by a peer that is not on its database.         *)
NoPhantomConflict == ~phantom

\* The advisory lock serializes applies on one database.
MutualExclusion ==
    \A p, q \in Policies :
        (p # q /\ pc[p] = "applying" /\ pc[q] = "applying")
            => snap[p].db # snap[q].db

-----------------------------------------------------------------------------
\* LIVENESS (under Fairness)

Reachable(p) == up[spec[p].id]
Isolated(p) == Reachable(p) /\ \A q \in Policies \ {p} : ~TruthConflict(p, q)

(* Fairness of the individual steps is not enough for liveness: the locks  *)
(* are try-locks, and a loser ends its reconcile and starts over, so a     *)
(* schedule exists in which p reaches the lock only while a peer holds it  *)
(* (TLC finds it: PCD_Starvation.cfg).  The operator relies on jittered    *)
(* requeues (LOCK_CONTENTION_BASE_SECS + jitter) to avoid that.  LockFair  *)
(* states the assumption: who keeps trying the lock keeps getting it.      *)
LockFair == \A p \in Policies :
               []<>(pc[p] = "lock") => []<>(pc[p] = "applying")

(* (d1) A policy that, from some point on, is reachable and conflicts with *)
(* nobody on its database is applied again and again.                      *)
NonConflictingAppliesNoLockAssumption ==
    \A p \in Policies : <>[]Isolated(p) => []<>(cond[p] = "Ready")
NonConflictingApplies == LockFair => NonConflictingAppliesNoLockAssumption

(* (d2) A pair that, from some point on, is reachable and in conflict ends *)
(* with both reporting ConflictingPolicy, permanently.  Meant for static   *)
(* specs: an environment that re-points a connection forever can keep      *)
(* re-opening the window.                                                  *)
ConflictingPairBlocks ==
    \A p, q \in Policies :
        (p # q) =>
           (<>[](TruthConflict(p, q) /\ Reachable(p) /\ Reachable(q))
              => <>[](cond[p] = "Conflict" /\ cond[q] = "Conflict"))

(* (d2) restricted to pairs sharing a connection identity: what is left    *)
(* when the CRD was not upgraded.                                          *)
SameIdentityPairBlocks ==
    \A p, q \in Policies :
        (p # q) =>
           (<>[](TruthConflict(p, q) /\ spec[p].id = spec[q].id
                   /\ Reachable(p))
              => <>[](cond[p] = "Conflict" /\ cond[q] = "Conflict"))
=============================================================================
