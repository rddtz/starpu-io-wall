#!/bin/bash
# IOTRACE2: run StarFletcher (mmap I/O, FxT on) with iotrace on the same disk.
# Usage: iotrace2_run.sh SF_BIN
#   SF_BIN: star-fletcher binary built with `nix build .#star-fletcher-trace`
# Needs iotrace with setcap cap_bpf,cap_perfmon+ep (no sudo).
# Outputs:
#   $DATA/<run>/  io.csv, sf.log, fxt/, env.txt, rsf header (kept)
#   $RSF_DIR/<run>/ the .rsf@ data file (on the traced disk, not kept in data)
set -euo pipefail

SF_BIN=$1
TCC=$(cd "$(dirname "$0")/../.." && pwd)
IOTRACE=$TCC/iotrace/iotrace
DEV=${DEV:-259:0}
NCPU=${NCPU:-4}
TAIL_S=${TAIL_S:-60}   # keep tracing after exit to catch writeback
ARGS="TTI 56 56 56 8 12.5 12.5 12.5 0.0001 0.01 4 0.0001"

RUN=iotrace2-$(date +%Y%m%d-%H%M%S)
DATA=$TCC/data/local/iotrace2/$RUN
RSF_DIR=$HOME/sf-runs/$RUN
# trace outputs on tmpfs while tracing, so they do not hit the traced disk
SHM=/dev/shm/$RUN
mkdir -p "$DATA" "$RSF_DIR" "$SHM/fxt"

{
    echo "run=$RUN"; date -Is; uname -r; nproc
    echo "dev=$DEV ncpu=$NCPU tail_s=$TAIL_S"
    echo "args=$ARGS"
    echo "sf_bin=$SF_BIN"
    echo "tcc_commit=$(git -C "$TCC" rev-parse HEAD)"
    echo "sf_commit=$(git -C "$TCC/star-fletcher" rev-parse HEAD)"
    for f in dirty_ratio dirty_background_ratio dirty_expire_centisecs dirty_writeback_centisecs; do
        echo "vm.$f=$(cat /proc/sys/vm/$f)"
    done
    grep -E '^(MemTotal|MemAvailable|Dirty|Writeback):' /proc/meminfo
} > "$SHM/env.txt"

sync
"$IOTRACE" -d "$DEV" > "$SHM/io.csv" 2> "$SHM/io.err" &
IO_PID=$!
sleep 2

# StarPU creates starpu.log in the current directory
cd "$SHM"
OUTPUT_FOLDER=$RSF_DIR OUTPUT_FILE=$RUN \
STARPU_NCPU=$NCPU STARPU_NCUDA=0 \
STARPU_FXT_TRACE=1 STARPU_FXT_PREFIX=$SHM/fxt/ \
    "$SF_BIN" $ARGS > "$SHM/sf.log" 2>&1

stat -c 'inode=%i size=%s' "$RSF_DIR/out-$RUN.rsf@" >> "$SHM/env.txt"
sleep "$TAIL_S"
kill -INT "$IO_PID"
wait "$IO_PID" || true
grep -E '^(Dirty|Writeback):' /proc/meminfo | sed 's/^/end_/' >> "$SHM/env.txt"

# copy only after tracing stopped
cp -r "$SHM"/* "$DATA/"
cp "$RSF_DIR/out-$RUN.rsf" "$DATA/"
rm -r "$SHM"
echo "$DATA"
