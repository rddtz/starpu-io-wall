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
};

struct iotrace_event {
	__u64 ts_ns;    /* bpf_ktime_get_ns(), CLOCK_MONOTONIC */
	__u64 sector;   /* 512-byte sector on the disk (rq events) */
	__u64 bytes;    /* rq: request bytes; wb: bytes submitted by this call */
	__u64 inode;    /* wb events only */
	__u32 type;     /* enum iotrace_type */
	__u32 op;       /* REQ_OP_* (rq events) */
	__u32 major;
	__u32 minor;
	__u32 pid;      /* rq_complete: submitter recorded at issue */
	char comm[IOTRACE_COMM_LEN];
};

#endif
