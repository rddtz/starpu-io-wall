#!/bin/bash
# Run StarVZ (phase 1 + 2) on the FxT trace of an IOTRACE2 run.
# Usage: iotrace2_starvz.sh STARVZ_TOOLS RUN_DIR
#   STARVZ_TOOLS: output of `nix build github:schnorr/starvz` (has bin/starvz)
#
# Workaround: starpu_fxt_tool (StarPU 1.4.12) writes user events emitted by
# the main thread as type user_user_event on container "p", but that type is
# declared for user-thread containers, so pj_dump rejects the trace. The first
# StarVZ pass stops there; we rename those events to user_event (declared for
# "p") in paje.sorted.trace.gz, keep the original as .orig.gz, and run again
# (phase 1 reuses paje.sorted.trace.gz when present).
set -euo pipefail

STARVZ=$1/bin/starvz
RUN_DIR=$(cd "$2" && pwd)
FXT=$RUN_DIR/fxt
CONFIG=$(cd "$(dirname "$0")/../.." && pwd)/star-fletcher/config.yaml

cd "$FXT"
if [ ! -f paje.sorted.trace.orig.gz ]; then
    "$STARVZ" -c "$CONFIG" "$FXT" > "$RUN_DIR/starvz.pass1.log" 2>&1 || true
    [ -f paje.sorted.trace.gz ] || { echo "no paje.sorted.trace.gz"; exit 1; }
    mv paje.sorted.trace.gz paje.sorted.trace.orig.gz
    zcat paje.sorted.trace.orig.gz \
        | sed -E 's/^(9\t[0-9.]+\t)user_user_event(\tp\t)/\1user_event\2/' \
        | gzip -c > paje.sorted.trace.gz
fi
"$STARVZ" -c "$CONFIG" "$FXT" > "$RUN_DIR/starvz.log" 2>&1
ls "$FXT"/events.parquet "$FXT"/starvz.pdf
