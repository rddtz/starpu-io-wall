// SPDX-License-Identifier: GPL-2.0
/*
 * Block-layer and writeback tracer. Fixed tracepoints only (tp_btf), so the
 * loader can be installed with setcap cap_bpf,cap_perfmon+ep.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "iotrace.h"

char LICENSE[] SEC("license") = "GPL";

#define REQ_OP_MASK 0xff
#define PAGE_SZ 4096
#define MINORBITS 20

/* Set by the loader before load; filter_dev == 0 means trace all disks. */
const volatile __u32 filter_dev = 0;
const volatile __u32 target_major = 0;
const volatile __u32 target_minor = 0;

/* Events lost because the ring buffer was full. */
__u64 dropped = 0;

struct who {
	__u32 pid;
	char comm[IOTRACE_COMM_LEN];
};

/* Submitter of each in-flight request; completion runs in irq context. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct who);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline bool dev_match(struct gendisk *disk, __u32 *maj, __u32 *min)
{
	if (!disk)
		return false;
	*maj = disk->major;
	*min = disk->first_minor;
	if (!filter_dev)
		return true;
	return *maj == target_major && *min == target_minor;
}

/* Same filter for a kernel dev_t (MAJOR in the top 12 bits). */
static __always_inline bool devt_match(dev_t devt, __u32 *maj, __u32 *min)
{
	*maj = devt >> MINORBITS;
	*min = devt & ((1U << MINORBITS) - 1);
	if (!filter_dev)
		return true;
	return *maj == target_major && *min == target_minor;
}

static __always_inline struct iotrace_event *reserve(void)
{
	struct iotrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		__sync_fetch_and_add(&dropped, 1);
	return e;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(rq_issue, struct request *rq)
{
	struct iotrace_event *e;
	struct who w = {};
	__u32 maj, min;
	__u64 key = (__u64)rq;

	if (!dev_match(rq->q->disk, &maj, &min))
		return 0;

	w.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(w.comm, sizeof(w.comm));
	bpf_map_update_elem(&inflight, &key, &w, BPF_ANY);

	e = reserve();
	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_RQ_ISSUE;
	e->op = rq->cmd_flags & REQ_OP_MASK;
	e->major = maj;
	e->minor = min;
	e->sector = rq->__sector;
	e->bytes = rq->__data_len;
	e->inode = 0;
	e->pid = w.pid;
	__builtin_memcpy(e->comm, w.comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(rq_complete, struct request *rq, blk_status_t error, unsigned int nr_bytes)
{
	struct iotrace_event *e;
	struct who *w;
	__u32 maj, min;
	__u64 key = (__u64)rq;

	if (!dev_match(rq->q->disk, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_RQ_COMPLETE;
	e->op = rq->cmd_flags & REQ_OP_MASK;
	e->major = maj;
	e->minor = min;
	e->sector = rq->__sector;
	e->bytes = nr_bytes;
	e->inode = 0;
	w = bpf_map_lookup_elem(&inflight, &key);
	if (w) {
		e->pid = w->pid;
		__builtin_memcpy(e->comm, w->comm, sizeof(e->comm));
	} else {
		e->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(e->comm, sizeof(e->comm));
	}
	bpf_ringbuf_submit(e, 0);

	/* A request can complete in parts; forget it only when fully done. */
	if (rq->__data_len <= nr_bytes)
		bpf_map_delete_elem(&inflight, &key);
	return 0;
}

SEC("tp_btf/writeback_single_inode")
int BPF_PROG(wb_inode, struct inode *inode, struct writeback_control *wbc,
	     unsigned long nr_to_write)
{
	struct iotrace_event *e;
	__u32 maj, min;
	long wrote;

	if (!dev_match(inode->i_sb->s_bdev->bd_disk, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	/* Same formula as the tracepoint's "wrote" field, in bytes. */
	wrote = nr_to_write - wbc->nr_to_write;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_WB_INODE;
	e->op = 0;
	e->major = maj;
	e->minor = min;
	e->sector = 0;
	e->bytes = wrote > 0 ? (__u64)wrote * PAGE_SZ : 0;
	e->inode = inode->i_ino;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * A page of a file goes from clean to dirty. Runs in the context of the task
 * that dirtied it (write() or a write fault on a shared mapping), so this is
 * where the process behind the later kworker writeback is known.
 * ext4 on 6.1 uses order-0 folios for regular files, so one page per event.
 */
SEC("tp_btf/writeback_dirty_folio")
int BPF_PROG(dirty_folio, struct folio *folio, struct address_space *mapping)
{
	struct iotrace_event *e;
	struct inode *inode;
	__u32 maj, min;

	if (!mapping)
		return 0;
	inode = mapping->host;
	if (!inode || !dev_match(inode->i_sb->s_bdev->bd_disk, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_DIRTY;
	e->op = 0;
	e->major = maj;
	e->minor = min;
	e->sector = folio->index;
	e->bytes = PAGE_SZ;
	e->inode = inode->i_ino;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Start of a writeback pass; work->reason says what triggered it. */
SEC("tp_btf/writeback_start")
int BPF_PROG(wb_start, struct bdi_writeback *wb, struct wb_writeback_work *work)
{
	struct iotrace_event *e;
	struct device *owner;
	__u32 maj, min;
	long nr;

	owner = wb->bdi->owner;
	if (!owner || !devt_match(owner->devt, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	nr = work->nr_pages;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_WB_START;
	e->op = work->reason;
	e->major = maj;
	e->minor = min;
	e->sector = 0;
	/* background and sync passes use LONG_MAX as "no limit" */
	e->bytes = (nr > 0 && nr < (1L << 40)) ? (__u64)nr * PAGE_SZ : 0;
	e->inode = 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
