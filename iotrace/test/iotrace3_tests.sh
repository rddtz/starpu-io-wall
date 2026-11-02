#!/bin/bash
# IOTRACE3 validation runs (run as root, from any directory).
# Usage: iotrace3_tests.sh USER OUTDIR [MB]
#   USER    runs dd and mmap_write as this user, files in its home
#   OUTDIR  where the CSVs go; use a tmpfs (/dev/shm) so the trace output
#           does not hit the traced disk
#   MB      size of each test write, default 256
# Traces all disks (no -d). Writes dd.* and mm.* in OUTDIR.
set -euo pipefail

U=$1
OUT=$2
MB=${3:-256}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
H=$(getent passwd "$U" | cut -d: -f6)
mkdir -p "$OUT"

# 1. dd with O_DIRECT: the process submits its own bios.
rm -f "$H/ddtest"
sync
"$ROOT/iotrace" -t 20 > "$OUT/dd.csv" 2> "$OUT/dd.err" &
P=$!
sleep 2
sudo -u "$U" dd if=/dev/zero of="$H/ddtest" bs=1M count="$MB" oflag=direct \
	2> "$OUT/dd.out"
stat -c %i "$H/ddtest" > "$OUT/dd.inode"
wait $P

# 2. mmap_write on a new file (no O_TRUNC of an existing one, which makes
#    ext4 flush at close): pages dirtied by the process, written by the
#    flusher after exit. 60 s covers dirty_expire (30 s) + flusher (5 s).
rm -f "$H/mmtest"
sync
"$ROOT/iotrace" -t 60 > "$OUT/mm.csv" 2> "$OUT/mm.err" &
P=$!
sleep 2
sudo -u "$U" "$ROOT/test/mmap_write" "$H/mmtest" "$MB" > "$OUT/mm.out"
stat -c %i "$H/mmtest" > "$OUT/mm.inode"
wait $P

rm -f "$H/ddtest" "$H/mmtest"
echo "$MB" > "$OUT/mb"
