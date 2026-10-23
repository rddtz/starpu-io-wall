#!/bin/bash
# Run StarVZ (phase 1 + 2) on the FxT trace of an IOTRACE2 run.
# Usage: iotrace2_starvz.sh STARVZ_TOOLS RUN_DIR
#   STARVZ_TOOLS: output of `nix build github:schnorr/starvz` (has bin/starvz)
#
# Two fixes are applied to a copy of paje.sorted.trace.gz (the original is
# kept as paje.sorted.trace.orig.gz); phase 1 reuses paje.sorted.trace.gz
# when present, so the first StarVZ pass only produces it.
# 1. starpu_fxt_tool (StarPU 1.4.12) writes user events emitted by the main
#    thread as type user_user_event on container "p", but that type is
#    declared for user-thread containers, so pj_dump rejects the trace. They
#    are renamed to user_event (declared for "p").
# 2. StarPU 1.4 added a Priority field to the task states (PajeSetState 20),
#    but the StarVZ worker CSV header has no Priority column, so every later
#    column shifts (Iteration gets Y, always 0). The field is removed from
#    the event definition and from every event 20 line.
set -euo pipefail

STARVZ=$1/bin/starvz
RUN_DIR=$(cd "$2" && pwd)
FXT=$RUN_DIR/fxt
CONFIG=$(cd "$(dirname "$0")/../.." && pwd)/star-fletcher/config.yaml

cd "$FXT"
# phase 1 reuses paje.sorted.trace.gz only if data.rec and tasks.rec also
# exist (a successful run deletes them), otherwise it regenerates the trace
# from the FxT file; the .orig.gz is deterministic from prof_file_*
if [ ! -f paje.sorted.trace.orig.gz ] || [ ! -f data.rec ] || [ ! -f tasks.rec ]; then
    rm -f paje.sorted.trace.gz
    "$STARVZ" -c "$CONFIG" "$FXT" > "$RUN_DIR/starvz.pass1.log" 2>&1 || true
    [ -f paje.sorted.trace.gz ] || { echo "no paje.sorted.trace.gz"; exit 1; }
    mv paje.sorted.trace.gz paje.sorted.trace.orig.gz
fi
zcat paje.sorted.trace.orig.gz \
    | sed -E 's/^(9\t[0-9.]+\t)user_user_event(\tp\t)/\1user_event\2/' \
    | awk -F'\t' '
        /^%EventDef PajeSetState 20$/ { in20 = 1; print; next }
        in20 && /^%EndEventDef/        { in20 = 0 }
        in20 && $2 == "Priority"       { next }
        $1 == "20" {
            # field 12 is Priority (after SubmitOrder)
            out = $1
            for (i = 2; i <= NF; i++) if (i != 12) out = out "\t" $i
            print out
            next
        }
        { print }' \
    | gzip -c > paje.sorted.trace.gz
"$STARVZ" -c "$CONFIG" "$FXT" > "$RUN_DIR/starvz.log" 2>&1
ls "$FXT"/events.parquet "$FXT"/starvz.pdf
