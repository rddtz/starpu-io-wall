/* Event layout shared by the BPF program and the loader. */
#ifndef IOTRACE_H
#define IOTRACE_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define IOTRACE_COMM_LEN 16

enum iotrace_type {
	EV_RQ_ISSUE = 1,
	EV_RQ_COMPLETE = 2,
	EV_WB_INODE = 3,
	EV_DIRTY = 4,
	EV_WB_START = 5,
	EV_BIO_QUEUE = 6,
	EV_BDP = 7,
	EV_SYSCALL = 8,
};

/* x86_64 syscall numbers traced by EV_SYSCALL (arch/x86/entry/syscalls). */
#define IOTRACE_NR_WRITE           1
#define IOTRACE_NR_MUNMAP          11
#define IOTRACE_NR_PWRITE64        18
#define IOTRACE_NR_WRITEV          20
#define IOTRACE_NR_MSYNC           26
#define IOTRACE_NR_FSYNC           74
#define IOTRACE_NR_FDATASYNC       75
#define IOTRACE_NR_SYNC_FILE_RANGE 277
#define IOTRACE_NR_PWRITEV         296
#define IOTRACE_NR_PWRITEV2        328

/* munmap calls smaller than this are not reported (every process unmaps). */
#define IOTRACE_MUNMAP_MIN (1UL << 20)

struct iotrace_event {
	__u64 ts_ns;    /* bpf_ktime_get_ns(), CLOCK_MONOTONIC; syscall: at exit */
	__u64 sector;   /* rq, bio_queue: 512-byte sector; dirty: page index in the file;
			   bdp: background threshold bytes; syscall: requested
			   count (write, pwrite64), vlen (writev family), length
			   (munmap, msync, sync_file_range) */
	__u64 bytes;    /* rq, bio_queue: bytes; wb_inode: bytes submitted by this call;
			   dirty: page bytes; wb_start: requested bytes (0 = no limit);
			   bdp: global dirty bytes; syscall: return value if >= 0 */
	__u64 inode;    /* wb_inode, dirty; syscall: inode of the fd (0 if none) */
	__u64 aux1;     /* bdp: dirty threshold bytes; syscall: fd (munmap, msync: address) */
	__s64 aux2;     /* bdp: pause in jiffies (< 0: no sleep);
			   syscall: duration in ns (enter to exit) */
	__s64 ret;      /* syscall: raw return value (< 0 is -errno) */
	__u32 type;     /* enum iotrace_type */
	__u32 op;       /* rq, bio_queue: REQ_OP_*; wb_start: enum wb_reason;
			   syscall: syscall number */
	__u32 major;
	__u32 minor;
	__u32 pid;      /* rq_complete: submitter recorded at issue */
	__u32 tid;      /* thread id; 0 when not meaningful (rq_complete, wb_*) */
	char comm[IOTRACE_COMM_LEN];
};

#endif
