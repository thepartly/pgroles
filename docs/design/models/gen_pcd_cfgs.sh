#!/usr/bin/env bash
# Regenerates the PCD_*.cfg files for PolicyConflictDetection.tla.
cd "$(dirname "$0")"
mk() { # name ids crd legacy content conn retarget outage invariants properties comment
{
echo "\\* ${11}"
echo "SPECIFICATION Spec"
echo "CONSTANTS"
echo "    Policies = ${POL:-{p1, p2\}}"
echo "    Identities = $2"
echo "    Databases = {d1, d2}"
echo "    Contents = {c1, c2}"
echo "    ConflictSets = {{c1, c2}}"
echo "    None = None"
echo "    CrdUpgraded = $3"
echo "    Legacy = $4"
echo "    AllowContentEdit = $5"
echo "    AllowConnEdit = $6"
echo "    AllowRetarget = $7"
echo "    AllowOutage = $8"
echo "INVARIANTS"
for i in $9; do echo "    $i"; done
if [ -n "${10}" ]; then echo "PROPERTIES"; for i in ${10}; do echo "    $i"; done; fi
if [ -n "${10}" ] || [ -n "${12}" ]; then echo "VIEW RealState"; fi
} > "$1.cfg"
}
I2="{i1, i2}"; I3="{i1, i2, i3}"
BASE="TypeOK MutualExclusion"
#  name                   ids   crd   legacy content conn  retarget outage
mk PCD_Fresh              "$I3" TRUE  FALSE  FALSE   FALSE FALSE    TRUE  "$BASE NeverBothApplied NoClobber NoStaleClobber NoAbaClobber LateApplyBound SameIdentityNeverApplies TrustedRecordAccurate NoPhantomConflict" "" "Fresh policies, static specs, outages allowed. Safety (a),(b),(c). Expected: all hold."
mk PCD_FreshLive          "$I2" TRUE  FALSE  FALSE   FALSE FALSE    TRUE  "TypeOK" "NonConflictingApplies ConflictingPairBlocks" "Fresh policies, static specs, outages allowed. Liveness (d). Expected: hold."
mk PCD_Upgrade            "$I3" TRUE  TRUE   FALSE   FALSE FALSE    TRUE  "$BASE NoMutualClobber LateApplyBound SameIdentityNeverApplies TrustedRecordAccurate NoPhantomConflict" "" "Upgrade start state. Expected: all hold (at most one of a conflicting pair applies again)."
mk PCD_UpgradeWindow      "$I2" TRUE  TRUE   FALSE   FALSE FALSE    FALSE "NoClobber" "" "Upgrade start state. Expected: NoClobber VIOLATED - the one-apply window."
mk PCD_UpgradeLive        "$I2" TRUE  TRUE   FALSE   FALSE FALSE    TRUE  "TypeOK" "NonConflictingApplies ConflictingPairBlocks" "Upgrade start state, liveness. Expected: hold."
mk PCD_CrdPruned          "$I2" FALSE FALSE  FALSE   FALSE FALSE    FALSE "NeverBothApplied" "" "CRD not upgraded. Expected: NeverBothApplied VIOLATED."
mk PCD_CrdPrunedRemaining "$I3" FALSE FALSE  FALSE   FALSE FALSE    TRUE  "$BASE SameIdentityNeverApplies NoPhantomConflict" "" "CRD not upgraded: safety that still holds. Expected: hold."
mk PCD_CrdPrunedRemainingLive "$I2" FALSE FALSE FALSE FALSE FALSE   TRUE  "TypeOK" "NonConflictingApplies SameIdentityPairBlocks" "CRD not upgraded: liveness that still holds. Expected: hold."
mk PCD_CrdPrunedLive      "$I2" FALSE FALSE  FALSE   FALSE FALSE    FALSE "TypeOK" "ConflictingPairBlocks" "CRD not upgraded. Expected: ConflictingPairBlocks VIOLATED."
mk PCD_ConnEdit           "$I3" TRUE  FALSE  FALSE   TRUE  FALSE    FALSE "$BASE TrustedRecordAccurate NoPhantomConflict" "" "spec.connection edits. Expected: guard invariants hold." view
mk PCD_ConnEditClobber    "$I3" TRUE  FALSE  FALSE   TRUE  FALSE    FALSE "NoClobber" "" "spec.connection edits. Expected: NoClobber VIOLATED - re-pointing re-opens the window."
mk PCD_ConnEditLive       "$I3" TRUE  FALSE  FALSE   TRUE  FALSE    FALSE "TypeOK" "NonConflictingApplies" "spec.connection edits, liveness of isolated policies. Expected: holds."
mk PCD_Retarget           "$I2" TRUE  FALSE  FALSE   FALSE TRUE     TRUE  "TrustedRecordAccurate" "" "Secret re-pointed. Expected: TrustedRecordAccurate VIOLATED."
mk PCD_RetargetPhantom    "$I2" TRUE  FALSE  FALSE   FALSE TRUE     TRUE  "NoPhantomConflict" "" "Secret re-pointed. Expected: NoPhantomConflict VIOLATED."
mk PCD_RetargetClobber    "$I2" TRUE  FALSE  FALSE   FALSE TRUE     FALSE "$BASE NoClobber" "" "Secret re-pointed. Does a stale-but-trusted record let anyone clobber live work?"
mk PCD_RetargetLive       "$I2" TRUE  FALSE  FALSE   FALSE TRUE     TRUE  "TypeOK" "NonConflictingApplies" "Secret re-pointed, liveness. Expected: NonConflictingApplies VIOLATED (phantom conflict forever)."
mk PCD_ContentEdit        "$I2" TRUE  FALSE  TRUE    FALSE FALSE    FALSE "$BASE NoClobber TrustedRecordAccurate NoPhantomConflict" "" "Claim edits. Expected: hold."
mk PCD_ContentEditStale   "$I2" TRUE  FALSE  TRUE    FALSE FALSE    FALSE "NoStaleClobber" "" "Claim edits. Expected: NoStaleClobber VIOLATED - in-flight reconcile applies a superseded snapshot."
mk PCD_ContentEditAba     "$I2" TRUE  FALSE  TRUE    FALSE FALSE    FALSE "NoAbaClobber" "" "Claim edits. Expected: NoAbaClobber VIOLATED - edit and revert between a peer's List and Commit."
mk PCD_Starvation         "$I2" TRUE  FALSE  FALSE   FALSE FALSE    FALSE "TypeOK" "NonConflictingAppliesNoLockAssumption" "Liveness without the lock-fairness assumption. Expected: VIOLATED - try-lock starvation."
POL="{p1, p2, p3}" mk PCD_Fresh3 "$I3" TRUE FALSE FALSE FALSE FALSE FALSE "$BASE NeverBothApplied NoClobber NoStaleClobber NoAbaClobber LateApplyBound SameIdentityNeverApplies TrustedRecordAccurate NoPhantomConflict" "" "Three fresh policies, static specs, no outages. Expected: all hold."
POL="{p1, p2, p3}" mk PCD_Upgrade3 "$I3" TRUE TRUE FALSE FALSE FALSE FALSE "$BASE NoMutualClobber LateApplyBound SameIdentityNeverApplies TrustedRecordAccurate NoPhantomConflict" "" "Three policies, upgrade start state. Expected: all hold."
