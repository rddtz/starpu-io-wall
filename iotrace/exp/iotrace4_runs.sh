#!/bin/bash
# IOTRACE4: N runs of iotrace2_run.sh with a .rsf@ 2x the RAM, then StarVZ
# and the analysis of each run. Meant to run detached (nohup) on santiago.
# Usage: iotrace4_runs.sh SF_BIN STARVZ_TOOLS [N]
#   SF_BIN:       star-fletcher binary with FxT (~/sf-runs/result-trace/bin/...)
#   STARVZ_TOOLS: starvz-tools build (~/sf-runs/result-starvz)
#   N:            number of runs, default 3
# Needs passwordless sudo for drop_caches and iotrace with setcap.
# Prints the run directories, one per line, at the end.
set -euo pipefail

SF_BIN=$1
STARVZ=$2
N=${3:-3}
TCC=$(cd "$(dirname "$0")/../.." && pwd)
EXP=$TCC/iotrace/exp
export ARGS=${ARGS:-"TTI 312 312 312 8 12.5 12.5 12.5 0.0001 0.01 4 0.0001"}
export DEV=""   # all disks
RSCRIPT=$(nix-store -qR "$STARVZ" | grep 'R-[0-9.]*-wrapper$' | head -1)/bin/Rscript

runs=()
for i in $(seq 1 "$N"); do
    echo "== run $i/$N $(date -Is)"
    sync
    sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches'
    sleep 5
    grep -E '^(MemAvailable|Dirty):' /proc/meminfo
    run_dir=$("$EXP/iotrace2_run.sh" "$SF_BIN" | tail -1)
    echo "run_dir=$run_dir"
    runs+=("$run_dir")
done

# post-processing after all runs, so it does not disturb them
for run_dir in "${runs[@]}"; do
    echo "== analysis $run_dir $(date -Is)"
    "$EXP/iotrace2_starvz.sh" "$STARVZ" "$run_dir" > "$run_dir/starvz.log" 2>&1
    "$RSCRIPT" "$EXP/iotrace2_analyze.R" "$run_dir" \
        "$run_dir/analysis-$(date +%Y%m%d-%H%M%S)" "$TCC/star-fletcher/config.yaml" \
        > "$run_dir/analysis.log" 2>&1
done
echo "== done $(date -Is)"
printf '%s\n' "${runs[@]}"
