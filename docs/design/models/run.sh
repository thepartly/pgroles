#!/usr/bin/env bash
# Usage: ./run.sh <Module> <cfg-basename> [workers]
#   e.g. ./run.sh PolicyConflictDetection PCD_Fresh
#        ./run.sh AttachmentPrecedence AP_NoRetention 1   (1 worker => shortest counterexample)
# Writes out/<cfg>.log and prints the verdict lines.
cd "$(dirname "$0")"
mkdir -p out states
mod=$1; cfg=$2; workers=${3:-auto}
rm -rf "states/$cfg"
java -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC -config "$cfg.cfg" "$mod.tla" \
     -workers "$workers" -metadir "states/$cfg" -noGenerateSpecTE > "out/$cfg.log" 2>&1
grep -E "Error:|is violated|No error has been found|states generated|Finished in|Temporal properties were violated" "out/$cfg.log" | grep -v "^Progress"
rm -rf "states/$cfg"
