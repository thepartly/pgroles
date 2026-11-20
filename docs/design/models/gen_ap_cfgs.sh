#!/usr/bin/env bash
# Regenerates the AP_*.cfg files for AttachmentPrecedence.tla.
cd "$(dirname "$0")"
mk() { # name n maxgen maxclock retention modelprof bypass ties loss invariants properties comment
{
echo "\\* ${12}"
echo "SPECIFICATION Spec"
echo "CONSTANTS"
echo "    NumPolicies = $2"
echo "    Roles = {r1, r2}"
echo "    MaxGen = $3"
echo "    MaxClock = $4"
echo "    None = None"
echo "    Retention = $5"
echo "    ModelProfiles = $6"
echo "    ProfilesBypass = $7"
echo "    AllowTies = $8"
echo "    AllowStatusLoss = $9"
echo "    NameKeyedStatus = ${13:-FALSE}"
if [ -n "${10}" ]; then echo "INVARIANTS"; for i in ${10}; do echo "    $i"; done; fi
if [ -n "${11}" ]; then echo "PROPERTIES"; for i in ${11}; do echo "    $i"; done; fi
} > "$1.cfg"
}
CORE="TypeOK SortedOrderUnique Idempotent ComposedDisjoint ServingDisjoint ComposedInScope"
#  name                    n gen clk retention profiles bypass ties  loss
mk AP_Retention            3 2   3   TRUE      FALSE    FALSE  FALSE FALSE "$CORE ServingMatchesComposed NewIsYoungest" "YoungerTakeoverOnlyViaElder Stable" "ADR-002 Decision 3 as compose_attached implements it, 3 policies. Expected: all hold."
mk AP_Retention2           2 3   4   TRUE      FALSE    FALSE  FALSE FALSE "$CORE ServingMatchesComposed NewIsYoungest" "YoungerTakeoverOnlyViaElder Stable" "Two policies. Expected: all hold."
mk AP_Retention2NoRecreate 2 3   2   TRUE      FALSE    FALSE  FALSE FALSE "$CORE NoTakeoverByYounger" "" "Two policies, each created once (MaxClock = 2). Expected: NoTakeoverByYounger holds."
mk AP_Retention2Recreate   2 2   3   TRUE      FALSE    FALSE  FALSE FALSE "NoTakeoverByYounger" "" "Two policies, one re-created. Expected: NoTakeoverByYounger VIOLATED - Rejected wipes the retained content."
mk AP_NoRetention          2 2   2   FALSE     FALSE    FALSE  FALSE FALSE "NoTakeoverByYounger" "" "Retention disabled. Expected: NoTakeoverByYounger VIOLATED - the prototype's billing_api squatter."
mk AP_NoRetentionRest      3 2   3   FALSE     FALSE    FALSE  FALSE FALSE "$CORE ServingMatchesComposed NewIsYoungest" "Stable" "Retention disabled: everything except takeover. Expected: hold."
mk AP_ElderKnockout        3 2   3   TRUE      FALSE    FALSE  FALSE FALSE "NoTakeoverByYounger" "" "Retention on, 3 policies. Expected: NoTakeoverByYounger VIOLATED - an older policy displaces the owner and a younger one takes a role."
mk AP_StrictTakeover       2 2   2   TRUE      FALSE    FALSE  FALSE FALSE "" "StrictNoTakeover" "Retention on. Expected: StrictNoTakeover VIOLATED - an older policy takes a role by editing."
mk AP_ProfilesBypass       2 2   2   TRUE      TRUE     TRUE   FALSE FALSE "NoTakeoverByYounger" "" "Retention on, database.rs profiles pre-check. Expected: NoTakeoverByYounger VIOLATED."
mk AP_ProfilesRetained     2 3   2   TRUE      TRUE     FALSE  FALSE FALSE "$CORE NoTakeoverByYounger" "YoungerTakeoverOnlyViaElder Stable" "As AP_ProfilesBypass but the profiles rejection goes through retention. Expected: hold."
mk AP_StatusLoss           2 2   2   TRUE      FALSE    FALSE  FALSE TRUE  "NoTakeoverByYounger" "" "Retention on, status write may fail after the composed policy was written. Expected: NoTakeoverByYounger VIOLATED."
mk AP_StatusLossRest       2 2   3   TRUE      FALSE    FALSE  FALSE TRUE  "TypeOK SortedOrderUnique Idempotent ComposedDisjoint ServingDisjoint ComposedInScope" "Stable" "Status loss: what still holds."
mk AP_Ties                 2 1   1   TRUE      FALSE    FALSE  TRUE  FALSE "NewIsYoungest" "" "Same-second creations. Expected: NewIsYoungest VIOLATED."
mk AP_TiesRest             2 2   2   TRUE      FALSE    FALSE  TRUE  FALSE "$CORE ServingMatchesComposed" "YoungerTakeoverOnlyViaElder Stable" "Same-second creations: everything else. Expected: hold."
mk AP_StableDeletion       3 1   3   TRUE      FALSE    FALSE  FALSE FALSE "" "StableDespiteElderDeletion" "Expected: StableDespiteElderDeletion VIOLATED - deleting an older policy unblocks a rejected one in between."
mk AP_RawListing           2 1   2   TRUE      FALSE    FALSE  FALSE FALSE "RawListingOrderIrrelevant" "" "Expected: RawListingOrderIrrelevant VIOLATED - the sort is what makes composition deterministic."
mk AP_NameReuse            2 3   3   TRUE      FALSE    FALSE  FALSE FALSE "" "YoungerTakeoverOnlyViaElder" "Status keyed by namespace/name (as in database.rs). Expected: YoungerTakeoverOnlyViaElder VIOLATED - a re-created policy inherits its predecessor's retained content, then loses it when its generation catches up." TRUE
mk AP_Prototype            3 2   3   TRUE      TRUE     TRUE   FALSE FALSE "$CORE ServingMatchesComposed NewIsYoungest" "Stable" "The prototype as written (profiles pre-check, name-keyed status): the properties that do not depend on retention. Expected: hold." TRUE
mk AP_ElderWithdraws       3 3   3   TRUE      FALSE    FALSE  FALSE FALSE "NoTakeoverAfterElderWithdraws" "" "Retention on. Expected: NoTakeoverAfterElderWithdraws VIOLATED - Rejected wipes the retained content for good."
mk AP_RetainedDropped      2 2   2   TRUE      FALSE    FALSE  FALSE FALSE "" "RetainedStaysServed" "Retention on. Expected: RetainedStaysServed VIOLATED - an older policy's edit collides with the retained content."
