------------------------- MODULE AttachmentPrecedence -------------------------
(***************************************************************************)
(* Precedence and retention for policies attached to a PostgresDatabase,   *)
(* as drafted in ADR-002 (docs/design/adr-002-postgres-database.md,        *)
(* Decision 3) and prototyped on branch `prototype/postgres-database`.     *)
(*                                                                         *)
(* Code this models:                                                       *)
(*   crates/pgroles-core/src/attachment.rs                                 *)
(*     compose_attached    -> Outcome(SortedSeq, ...) : sort, then admit   *)
(*                            oldest first                                 *)
(*     admit               -> Admit(c, claimed)                            *)
(*     Verdict::{Accepted, Retained, Rejected} -> verdict[p]               *)
(*     AttachedPolicy.created_at / namespace / name -> stamp[p], p         *)
(*     AttachedPolicy.last_accepted -> LastAccepted(p, prev)               *)
(*   crates/pgroles-operator/src/database.rs                               *)
(*     reconcile_database  -> Reconcile(persist)                           *)
(*       `previous` (status.attached, keyed by namespace/name) -> serving  *)
(*       the `profiles` pre-check before compose_attached -> ProfilesBypass*)
(*       patch of <database>-composed            -> composed               *)
(*       patch_status of the PostgresDatabase    -> serving' (persist)     *)
(*                                                                         *)
(* Abstractions                                                            *)
(*  - A policy's content is one of                                         *)
(*      [kind "ok",  claims S]  in scope, owning the roles in S            *)
(*      [kind "oos", claims {}] rejected by the delegation check or        *)
(*                              invalid on its own (delegated_document,    *)
(*                              check_created_roles, solo compose)         *)
(*      [kind "prof", claims {}] sets spec.profiles, which only the        *)
(*                              database owner may set                     *)
(*    Scope is a property of the content: delegations do not change.       *)
(*  - "Composes with its elders" is "claims are disjoint from the claims   *)
(*    already accepted".  Schema facets, grants and revoke reach are not   *)
(*    modelled; roles stand for anything exclusively claimed.              *)
(*  - Policies are the numbers 1..NumPolicies; the number is the           *)
(*    namespace/name tie-break (smaller sorts first).                      *)
(*  - creationTimestamp is a counter.  With AllowTies two policies may get *)
(*    the same timestamp (it has one-second resolution).                   *)
(*  - Reconcile is one atomic step: list policies, compose, write the      *)
(*    composed policy, write status.  With AllowStatusLoss the last write  *)
(*    may fail after the composed policy was written.                      *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    NumPolicies,       \* attached policies are 1..NumPolicies
    Roles,             \* roles a policy may claim
    MaxGen,            \* bound on metadata.generation (edits per object)
    MaxClock,          \* bound on the creationTimestamp counter
    None,              \* model value
    Retention,         \* FALSE: precedence only, no last-accepted content
    ModelProfiles,     \* TRUE: contents include the `profiles` edit
    ProfilesBypass,    \* TRUE: as in database.rs, a policy with profiles is
                       \* rejected before compose_attached sees it
    AllowTies,         \* TRUE: creations may share a timestamp
    AllowStatusLoss,   \* TRUE: a reconcile may fail to persist status
    NameKeyedStatus    \* TRUE: as in database.rs, the retained content is
                       \* looked up by namespace/name, so a policy deleted
                       \* and re-created under the same name before the next
                       \* reconcile inherits its predecessor's entry.
                       \* FALSE: the entry is tied to the object (its UID).

Policies == 1..NumPolicies

Ok(S) == [kind |-> "ok", claims |-> S]
Oos   == [kind |-> "oos", claims |-> {}]
Prof  == [kind |-> "prof", claims |-> {}]
Contents == {Ok(S) : S \in SUBSET Roles} \cup {Oos}
               \cup (IF ModelProfiles THEN {Prof} ELSE {})

VARIABLES
    exists,    \* attached PostgresPolicy objects (not being deleted)
    stamp,     \* [p -> 0..MaxClock] metadata.creationTimestamp
    clock,     \* API server clock
    gen,       \* [p -> 0..MaxGen]   metadata.generation
    content,   \* [p -> Contents]    current spec
    serving,   \* [p -> None | [gen, content]] PostgresDatabase.status
               \*   .attached[p].serving_generation / serving_content
    verdict,   \* [p -> "None"|"Accepted"|"Retained"|"Rejected"]
    composed,  \* [p -> None | Contents] p's content inside <db>-composed,
               \*   i.e. what the reconciler applies to PostgreSQL
    \* ---- ghost variables ----
    fresh,     \* [p -> BOOLEAN] created since the last reconcile
    seenSet,   \* policies the last reconcile listed
    seenGen,   \* [p -> generation the last reconcile saw]
    entitled,  \* [p -> SUBSET Roles] roles p had accepted, has not released
               \*   by an accepted edit, and has not lost to an older
               \*   policy that now serves the same role; cleared on delete
    lost,      \* [p -> SUBSET Roles] roles dropped from entitled[p] because
               \*   an older policy served them, while p has not been
               \*   accepted again since
    createdNotYoungest, \* some Create sorted before an existing policy
    settled    \* nothing changed since the last persisted reconcile

vars == <<exists, stamp, clock, gen, content, serving, verdict, composed,
          fresh, seenSet, seenGen, entitled, lost, createdNotYoungest, settled>>

-----------------------------------------------------------------------------
\* compose_attached's sort key: (created_at, namespace, name).
Before(p, q) == stamp[p] < stamp[q] \/ (stamp[p] = stamp[q] /\ p < q)

\* All listings of the existing policies, in every order the API may return.
Listings == {s \in [1..Cardinality(exists) -> exists] :
               \A i, j \in DOMAIN s : i # j => s[i] # s[j]}

IsSorted(s) == \A i, j \in DOMAIN s : i < j => Before(s[i], s[j])

SortedSeq == CHOOSE s \in Listings : IsSorted(s)

\* attachment.rs admit(): in scope and valid alone, and composes with the
\* documents accepted so far.
Admit(c, claimed) == c.kind = "ok" /\ c.claims \cap claimed = {}

\* database.rs: last_accepted = previous[key] filtered by
\* `serving_generation != metadata.generation`, then serving_content.
LastAccepted(p, prev) ==
    IF Retention /\ prev[p] # None /\ prev[p].gen # gen[p]
        THEN prev[p].content ELSE None

\* One iteration of the loop in compose_attached, for policy p, given the
\* claims accepted so far.  Returns the verdict and what is served.
DecideOne(p, claimed, prev) ==
    IF ProfilesBypass /\ content[p].kind = "prof"
      THEN \* database.rs pre-rejects: never handed to compose_attached,
           \* status entry written with no serving content.
           [v |-> "Rejected", serve |-> None]
      ELSE LET la == LastAccepted(p, prev) IN
           IF Admit(content[p], claimed)
             THEN [v |-> "Accepted",
                   serve |-> [gen |-> gen[p], content |-> content[p]]]
           ELSE IF la # None /\ Admit(la, claimed)
             THEN [v |-> "Retained", serve |-> prev[p]]
           ELSE [v |-> "Rejected", serve |-> None]

\* Admit the policies of sequence s from position i on.
RECURSIVE Fold(_, _, _, _, _)
Fold(s, i, claimed, out, prev) ==
    IF i > Cardinality(DOMAIN s) THEN out
    ELSE LET p == s[i]
             d == DecideOne(p, claimed, prev)
             more == IF d.serve = None THEN {} ELSE d.serve.content.claims
         IN Fold(s, i + 1, claimed \cup more, [out EXCEPT ![p] = d], prev)

NoDecision == [v |-> "None", serve |-> None]

\* The outcome of admitting in the order of s: [p -> [v, serve]].
Outcome(s, prev) == Fold(s, 1, {}, [p \in Policies |-> NoDecision], prev)

\* compose_attached: sort first, so the listing order does not matter.
Compose(prev) == Outcome(SortedSeq, prev)

Claims(x) == IF x = None THEN {} ELSE x.claims

-----------------------------------------------------------------------------
TypeOK ==
    /\ exists \subseteq Policies
    /\ stamp \in [Policies -> 0..MaxClock]
    /\ clock \in 0..MaxClock
    /\ gen \in [Policies -> 0..MaxGen]
    /\ content \in [Policies -> Contents]
    /\ serving \in [Policies -> {None} \cup [gen : 1..MaxGen, content : Contents]]
    /\ verdict \in [Policies -> {"None", "Accepted", "Retained", "Rejected"}]
    /\ composed \in [Policies -> {None} \cup Contents]
    /\ fresh \in [Policies -> BOOLEAN]
    /\ seenSet \subseteq Policies
    /\ seenGen \in [Policies -> 0..MaxGen]
    /\ entitled \in [Policies -> SUBSET Roles]
    /\ lost \in [Policies -> SUBSET Roles]
    /\ createdNotYoungest \in BOOLEAN
    /\ settled \in BOOLEAN

Init ==
    /\ exists = {}
    /\ stamp = [p \in Policies |-> 0]
    /\ clock = 0
    /\ gen = [p \in Policies |-> 0]
    /\ content = [p \in Policies |-> Ok({})]
    /\ serving = [p \in Policies |-> None]
    /\ verdict = [p \in Policies |-> "None"]
    /\ composed = [p \in Policies |-> None]
    /\ fresh = [p \in Policies |-> FALSE]
    /\ seenSet = {}
    /\ seenGen = [p \in Policies |-> 0]
    /\ entitled = [p \in Policies |-> {}]
    /\ lost = [p \in Policies |-> {}]
    /\ createdNotYoungest = FALSE
    /\ settled = TRUE

\* kubectl create.  The API server stamps creationTimestamp; with AllowTies
\* the clock may not have advanced since the previous creation.  A new
\* object starts at generation 1, whatever generation its predecessor of
\* the same name had reached.
Create(p) ==
    /\ p \notin exists
    /\ \E t \in {clock + 1} \cup (IF AllowTies THEN {clock} ELSE {}),
          c \in Contents :
          /\ t <= MaxClock
          /\ clock' = t
          /\ stamp' = [stamp EXCEPT ![p] = t]
          /\ content' = [content EXCEPT ![p] = c]
          /\ createdNotYoungest' =
                (createdNotYoungest \/
                   \E q \in exists : t < stamp[q] \/ (t = stamp[q] /\ p < q))
    /\ exists' = exists \cup {p}
    /\ gen' = [gen EXCEPT ![p] = 1]
    /\ fresh' = [fresh EXCEPT ![p] = TRUE]
    /\ entitled' = [entitled EXCEPT ![p] = {}]
    /\ lost' = [lost EXCEPT ![p] = {}]
    /\ settled' = FALSE
    /\ serving' = IF NameKeyedStatus THEN serving
                                     ELSE [serving EXCEPT ![p] = None]
    /\ UNCHANGED <<verdict, composed, seenSet, seenGen>>

\* kubectl delete.  The status entry (keyed by namespace/name) stays in
\* PostgresDatabase.status until the next reconcile rewrites the list.
Delete(p) ==
    /\ p \in exists
    /\ exists' = exists \ {p}
    /\ gen' = [gen EXCEPT ![p] = 0]
    /\ content' = [content EXCEPT ![p] = Ok({})]
    /\ entitled' = [entitled EXCEPT ![p] = {}]
    /\ lost' = [lost EXCEPT ![p] = {}]
    /\ settled' = FALSE
    /\ UNCHANGED <<stamp, clock, serving, verdict, composed, fresh, seenSet,
                   seenGen, createdNotYoungest>>

\* Any spec edit: bumps metadata.generation, content changes arbitrarily.
Edit(p) ==
    /\ p \in exists
    /\ gen[p] < MaxGen
    /\ \E c \in Contents \ {content[p]} :
          content' = [content EXCEPT ![p] = c]
    /\ gen' = [gen EXCEPT ![p] = @ + 1]
    /\ settled' = FALSE
    /\ UNCHANGED <<exists, stamp, clock, serving, verdict, composed, fresh,
                   seenSet, seenGen, entitled, lost, createdNotYoungest>>

(* reconcile_database.  The composed policy is patched before the          *)
(* PostgresDatabase status; every await in between ends the reconcile on   *)
(* error (`?`), so persist = FALSE leaves status as it was although the    *)
(* composed policy - and hence PostgreSQL - already follows the new        *)
(* outcome.                                                                *)
Reconcile(persist) ==
    LET D == Compose(serving) IN
    /\ verdict' = [p \in Policies |-> IF p \in exists THEN D[p].v ELSE "None"]
    /\ composed' = [p \in Policies |->
                      IF p \in exists /\ D[p].serve # None
                        THEN D[p].serve.content ELSE None]
    /\ serving' = IF persist
                    THEN [p \in Policies |->
                            IF p \in exists THEN D[p].serve ELSE None]
                    ELSE serving
    /\ LET ElderClaims(p) ==
               UNION {IF D[e].serve = None THEN {} ELSE D[e].serve.content.claims :
                        e \in {x \in exists : Before(x, p)}}
       IN /\ entitled' = [p \in Policies |->
                            IF p \notin exists THEN {}
                            ELSE IF D[p].v = "Accepted" THEN content[p].claims
                            ELSE entitled[p] \ ElderClaims(p)]
          /\ lost' = [p \in Policies |->
                        IF p \notin exists \/ D[p].v = "Accepted" THEN {}
                        ELSE lost[p] \cup (entitled[p] \cap ElderClaims(p))]
    /\ fresh' = [p \in Policies |-> FALSE]
    /\ seenSet' = exists
    /\ seenGen' = gen
    /\ settled' = persist
    /\ UNCHANGED <<exists, stamp, clock, gen, content, createdNotYoungest>>

Next == \/ \E p \in Policies : Create(p) \/ Delete(p) \/ Edit(p)
        \/ Reconcile(TRUE)
        \/ (AllowStatusLoss /\ Reconcile(FALSE))

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* (b) DETERMINISM

(* The sort key is total on existing policies, so exactly one listing is   *)
(* sorted: whatever order the API returns, compose_attached admits in the  *)
(* same order.  Reconcile is then a function of (exists, stamp, gen,       *)
(* content, serving) by construction.                                      *)
SortedOrderUnique == Cardinality({s \in Listings : IsSorted(s)}) = 1

(* Expected to FAIL: without the sort the outcome would depend on the      *)
(* listing order.  Shows the sort is what makes composition deterministic. *)
RawListingOrderIrrelevant ==
    \A s, t \in Listings : Outcome(s, serving) = Outcome(t, serving)

(* Reconciling twice without any change in between gives the same answer.  *)
Idempotent ==
    settled => \A p \in exists :
                  LET D == Compose(serving) IN
                  D[p].serve = serving[p] /\ D[p].v = verdict[p]

-----------------------------------------------------------------------------
\* (c) DISJOINT CLAIMS

ComposedDisjoint ==
    \A p, q \in Policies :
        p # q => Claims(composed[p]) \cap Claims(composed[q]) = {}

ServingDisjoint ==
    \A p, q \in Policies :
        (p # q /\ serving[p] # None /\ serving[q] # None)
            => serving[p].content.claims \cap serving[q].content.claims = {}

\* Nothing out of scope is ever composed.
ComposedInScope == \A p \in Policies : composed[p] # None => composed[p].kind = "ok"

\* Without status loss, status describes exactly what was composed.
ServingMatchesComposed ==
    \A p \in Policies :
        ~fresh[p] =>
            composed[p] = IF serving[p] = None THEN None ELSE serving[p].content

-----------------------------------------------------------------------------
\* (a) NO TAKEOVER

(* State form.  A role a policy had accepted, never gave up through an     *)
(* accepted edit or by being deleted, and that no older policy has claimed *)
(* since, is not composed for a younger policy.                            *)
(* (composed[q] of a policy created since the last reconcile still         *)
(* describes the deleted object of that name, so fresh q are skipped.)     *)
NoTakeoverByYounger ==
    \A p, q \in exists :
        (Before(p, q) /\ ~fresh[q])
            => entitled[p] \cap Claims(composed[q]) = {}

(* (e) Expected to FAIL.  A role p lost to an older policy is not composed  *)
(* for a younger policy later (after the older one withdrew or was         *)
(* deleted) while p still exists and has not been accepted since.          *)
NoTakeoverAfterElderWithdraws ==
    \A p, q \in exists :
        (Before(p, q) /\ ~fresh[q]) => lost[p] \cap Claims(composed[q]) = {}

\* The roles q is composed with after this step that p was composed with
\* before it.
Taken(p, q) == Claims(composed[p]) \cap Claims(composed'[q])

\* p is the same object the previous reconcile composed, and still exists.
Standing(p) == p \in exists /\ ~fresh[p] /\ composed[p] # None

(* Strict form: a standing policy loses a role to another policy only by   *)
(* releasing it (its own current content is accepted without the role).    *)
(* Expected to FAIL: an older policy can claim it.                         *)
StrictNoTakeoverStep ==
    \A p, q \in Policies :
        (p # q /\ Standing(p) /\ Taken(p, q) # {}) => verdict'[p] = "Accepted"
StrictNoTakeover == [][StrictNoTakeoverStep]_vars

(* What retention is meant to give: a YOUNGER policy gets a standing       *)
(* policy's role only if the owner released it, or an OLDER policy's       *)
(* composed content now collides with what the owner was serving.          *)
YoungerTakeoverStep ==
    \A p, q \in Policies :
        (p # q /\ Standing(p) /\ Before(p, q) /\ Taken(p, q) # {})
          => \/ verdict'[p] = "Accepted"
             \/ \E e \in exists :
                   /\ Before(e, p)
                   /\ Claims(composed'[e]) \cap Claims(composed[p]) # {}
YoungerTakeoverOnlyViaElder == [][YoungerTakeoverStep]_vars

(* (e) Expected to FAIL.  A policy that is being served its last accepted  *)
(* content, and is not touched, keeps being served.  It fails when an      *)
(* older policy's edit collides with the retained content: the verdict     *)
(* becomes Rejected and database.rs writes the status entry without        *)
(* serving content, so there is nothing left to retain afterwards.         *)
RetainedStaysServedStep ==
    \A p \in Policies :
        (/\ Standing(p) /\ verdict[p] = "Retained" /\ gen[p] = seenGen[p]
         /\ verdict' # verdict)
          => composed'[p] # None
RetainedStaysServed == [][RetainedStaysServedStep]_vars

-----------------------------------------------------------------------------
\* (d) STABILITY

\* A policy created now sorts after every existing one.
NewIsYoungest == ~createdNotYoungest

\* p was accepted by the last reconcile and has not been edited since.
AcceptedUnchanged(p) ==
    /\ p \in exists /\ ~fresh[p]
    /\ verdict[p] = "Accepted" /\ gen[p] = seenGen[p]

\* e is the object the last reconcile saw, at the generation it saw.
Unchanged(e) == e \in exists /\ e \in seenSet /\ ~fresh[e] /\ gen[e] = seenGen[e]

(* Stability: an accepted, unedited policy stays accepted across the next  *)
(* reconcile if the policies older than it are exactly the ones the last   *)
(* reconcile saw, unedited.  (Younger policies may do anything.)           *)
StableStep ==
    \A p \in Policies :
        (/\ AcceptedUnchanged(p)
         /\ \A e \in exists : Before(e, p) => Unchanged(e)
         /\ \A e \in seenSet : (~fresh[e] /\ Before(e, p)) => Unchanged(e)
         /\ \A e \in seenSet : ~fresh[e]   \* nobody deleted and recreated
         /\ verdict' # verdict)   \* i.e. this step is a Reconcile
          => verdict'[p] = "Accepted"
Stable == [][StableStep]_vars

(* Expected to FAIL: the same without "no older policy was deleted".       *)
(* Deleting an older policy can unblock a rejected policy in between.      *)
StableDespiteElderDeletionStep ==
    \A p \in Policies :
        (/\ AcceptedUnchanged(p)
         /\ \A e \in exists : Before(e, p) => Unchanged(e)
         /\ verdict' # verdict)
          => verdict'[p] = "Accepted"
StableDespiteElderDeletion == [][StableDespiteElderDeletionStep]_vars
=============================================================================
