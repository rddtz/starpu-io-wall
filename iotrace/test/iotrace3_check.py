#!/usr/bin/env python3
"""Check the IOTRACE3 acceptance criteria on the output of iotrace3_tests.sh.

Usage: iotrace3_check.py OUTDIR

Prints one line per check with PASS/FAIL and the numbers behind it.
"""

import csv
import os
import sys
from collections import Counter

WRITE_SYSCALLS = {"write", "pwrite64", "writev", "pwritev", "pwritev2"}


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def read(path):
    with open(path) as f:
        return f.read()


def dropped(err_path):
    for line in read(err_path).splitlines():
        if line.startswith("iotrace: dropped events:"):
            return int(line.split(":")[-1])
    return None


def check(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    return ok


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = sys.argv[1]
    n = int(read(os.path.join(out, "mb"))) * 1024 * 1024
    ok = True

    for t in ("dd", "mm"):
        d = dropped(os.path.join(out, f"{t}.err"))
        ok &= check(f"{t}: dropped events", d == 0, f"{d}")

    # dd oflag=direct: bios and write syscalls of dd add up to N exactly.
    dd = load(os.path.join(out, "dd.csv"))
    bio = sum(int(r["bytes"]) for r in dd
              if r["event"] == "bio_queue" and r["op"] == "W" and r["comm"] == "dd")
    sysw = sum(int(r["bytes"]) for r in dd
               if r["event"] == "syscall" and r["op"] in WRITE_SYSCALLS
               and r["comm"] == "dd")
    ok &= check("dd: bio_queue W bytes by dd == N", bio == n, f"{bio} vs {n}")
    ok &= check("dd: write syscall bytes by dd == N", sysw == n, f"{sysw} vs {n}")

    # mmap_write: dirty pages of its inode by its pid; flusher bios after exit.
    mm = load(os.path.join(out, "mm.csv"))
    ino = read(os.path.join(out, "mm.inode")).strip()
    kv = dict(line.split("=", 1) for line in read(os.path.join(out, "mm.out")).split())
    exit_ns = int(kv["exit_ns"])

    dirty = [r for r in mm if r["event"] == "dirty" and r["inode"] == ino]
    by_comm = Counter(r["comm"] for r in dirty)
    dbytes = sum(int(r["bytes"]) for r in dirty if r["comm"] == "mmap_write")
    ok &= check("mm: dirty bytes of inode by mmap_write within 5% of N",
                abs(dbytes - n) <= 0.05 * n, f"{dbytes} vs {n}")
    ok &= check("mm: dirty events of inode only by mmap_write",
                set(by_comm) == {"mmap_write"}, f"{dict(by_comm)}")

    flusher = sum(int(r["bytes"]) for r in mm
                  if r["event"] == "bio_queue" and r["op"] == "W"
                  and r["comm"].startswith("kworker/u") and int(r["ts_ns"]) > exit_ns)
    ok &= check("mm: bio_queue W bytes by kworker/u* after exit within 5% of N",
                abs(flusher - n) <= 0.05 * n, f"{flusher} vs {n}")

    for t, rows in (("dd", dd), ("mm", mm)):
        sw = sum(int(r["bytes"]) for r in rows
                 if r["event"] == "bio_queue" and r["comm"].startswith("swapper"))
        ok &= check(f"{t}: bio_queue bytes by swapper/* == 0", sw == 0, f"{sw}")

    # Not criteria, context for the notes: W bytes by submitter.
    for t, rows in (("dd", dd), ("mm", mm)):
        sub = Counter()
        for r in rows:
            if r["event"] == "bio_queue" and r["op"] == "W":
                sub[r["comm"]] += int(r["bytes"])
        print(f"INFO  {t}: bio_queue W bytes by comm: {dict(sub.most_common())}")
        ev = Counter(r["event"] for r in rows)
        print(f"INFO  {t}: events: {dict(ev)}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
