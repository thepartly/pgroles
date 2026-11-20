#!/usr/bin/env bash
# Runs every configuration and writes results.txt (one line per configuration).
# Configurations whose expected outcome is a violation run with one worker so
# that TLC's breadth-first search reports a shortest counterexample.
cd "$(dirname "$0")"
: > results.txt
one() { # module cfg workers
  local t0=$(date +%s)
  ./run.sh "$1" "$2" "$3" > /dev/null
  local t1=$(date +%s)
  local log="out/$2.log"
  local verdict
  if grep -q "No error has been found" "$log"; then verdict="holds"
  else verdict="VIOLATED: $(grep -oE '(Invariant|Temporal property|Action property) [A-Za-z]+' "$log" | head -1)"; fi
  local states=$(grep -E "states generated, .* distinct states found" "$log" | grep -v Progress | tail -1 | sed -E 's/^([0-9]+) states generated, ([0-9]+) distinct.*/\2 distinct \/ \1 generated/')
  printf "%-28s %-58s %-40s %ss\n" "$2" "$verdict" "$states" "$((t1-t0))" | tee -a results.txt
}
M=PolicyConflictDetection
for c in PCD_Fresh PCD_FreshLive PCD_Upgrade PCD_UpgradeLive PCD_CrdPrunedRemaining \
         PCD_CrdPrunedRemainingLive PCD_ConnEdit PCD_ConnEditLive PCD_RetargetClobber PCD_ContentEdit \
         PCD_Fresh3 PCD_Upgrade3; do one $M $c auto; done
for c in PCD_UpgradeWindow PCD_CrdPruned PCD_CrdPrunedLive PCD_ConnEditClobber PCD_Retarget \
         PCD_RetargetPhantom PCD_RetargetLive PCD_ContentEditStale PCD_ContentEditAba PCD_Starvation; do one $M $c 1; done
M=AttachmentPrecedence
for c in AP_Retention AP_Retention2 AP_Retention2NoRecreate AP_ProfilesRetained AP_Prototype \
         AP_NoRetentionRest AP_StatusLossRest AP_TiesRest; do one $M $c auto; done
for c in AP_NoRetention AP_ElderKnockout AP_Retention2Recreate AP_StrictTakeover AP_ProfilesBypass \
         AP_StatusLoss AP_NameReuse AP_ElderWithdraws AP_RetainedDropped AP_Ties AP_StableDeletion \
         AP_RawListing; do one $M $c 1; done
