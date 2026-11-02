// SPDX-License-Identifier: GPL-2.0
/*
 * Block-layer and writeback tracer. Fixed tracepoints only (tp_btf), so the
 * loader can be installed with setcap cap_bpf,cap_perfmon+ep.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
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

	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return e;
	}
	/* Fields not used by every event; the others set what they need. */
	e->aux1 = 0;
	e->aux2 = 0;
	e->ret = 0;
	e->tid = 0;
	return e;
}

static __always_inline __u32 cur_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid();
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
	e->tid = cur_tid();
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
	e->tid = cur_tid();
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

/*
 * A bio enters the block layer. Runs in the context of the task that
 * submitted it (flusher kworker/u*, jbd2, or the process for O_DIRECT and
 * sync writes), before any plug flush or kblockd dispatch, so this is the
 * submitter that block_rq_issue does not see.
 */
SEC("tp_btf/block_bio_queue")
int BPF_PROG(bio_queue, struct bio *bio)
{
	struct iotrace_event *e;
	__u32 maj, min;

	if (!bio->bi_bdev || !dev_match(bio->bi_bdev->bd_disk, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_BIO_QUEUE;
	e->op = bio->bi_opf & REQ_OP_MASK;
	e->major = maj;
	e->minor = min;
	e->sector = bio->bi_iter.bi_sector;
	e->bytes = bio->bi_iter.bi_size;
	e->inode = 0;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = cur_tid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * A task that dirties pages goes through the dirty throttling check. Fires
 * from balance_dirty_pages() in the context of the writer; pause > 0 means
 * the task was put to sleep for that many jiffies.
 */
SEC("tp_btf/balance_dirty_pages")
int BPF_PROG(bdp, struct bdi_writeback *wb, unsigned long thresh,
	     unsigned long bg_thresh, unsigned long dirty, unsigned long bdi_thresh,
	     unsigned long bdi_dirty, unsigned long dirty_ratelimit,
	     unsigned long task_ratelimit, unsigned long dirtied,
	     unsigned long period, long pause, unsigned long start_time)
{
	struct iotrace_event *e;
	struct device *owner;
	__u32 maj, min;

	owner = wb->bdi->owner;
	if (!owner || !devt_match(owner->devt, &maj, &min))
		return 0;

	e = reserve();
	if (!e)
		return 0;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = EV_BDP;
	e->op = 0;
	e->major = maj;
	e->minor = min;
	e->sector = (__u64)bg_thresh * PAGE_SZ;
	e->bytes = (__u64)dirty * PAGE_SZ;
	e->inode = 0;
	e->aux1 = (__u64)thresh * PAGE_SZ;
	e->aux2 = pause;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tid = cur_tid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Write/sync syscall seen at enter, completed at exit (key: thread id). */
struct pending {
	__u64 ts_ns;
	__u64 sector;
	__u64 aux1;
	__u64 inode;
	__u32 nr;
	__u32 major;
	__u32 minor;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct pending);
} pending SEC(".maps");

static __always_inline bool num_match(__u32 maj, __u32 min)
{
	if (!filter_dev)
		return true;
	return maj == target_major && min == target_minor;
}

/*
 * Inode and disk of fd in the current task. Only files on a block device
 * count (pipes, sockets and ttys have no s_bdev and are skipped).
 */
static __always_inline bool fd_file(int fd, struct pending *p)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct fdtable *fdt;
	struct file **arr;
	struct file *f = NULL;
	struct inode *ino;
	struct gendisk *disk;
	unsigned int max;

	if (fd < 0)
		return false;
	fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt)
		return false;
	max = BPF_CORE_READ(fdt, max_fds);
	if ((unsigned int)fd >= max)
		return false;
	arr = BPF_CORE_READ(fdt, fd);
	if (!arr || bpf_probe_read_kernel(&f, sizeof(f), &arr[fd]) || !f)
		return false;
	ino = BPF_CORE_READ(f, f_inode);
	if (!ino)
		return false;
	disk = BPF_CORE_READ(ino, i_sb, s_bdev, bd_disk);
	if (!disk)
		return false;
	p->major = BPF_CORE_READ(disk, major);
	p->minor = BPF_CORE_READ(disk, first_minor);
	if (!num_match(p->major, p->minor))
		return false;
	p->inode = BPF_CORE_READ(ino, i_ino);
	return true;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id)
{
	struct pending p = {};
	__u32 tid = cur_tid();

	switch (id) {
	case IOTRACE_NR_WRITE:
	case IOTRACE_NR_PWRITE64:
	case IOTRACE_NR_WRITEV:
	case IOTRACE_NR_PWRITEV:
	case IOTRACE_NR_PWRITEV2:
	case IOTRACE_NR_SYNC_FILE_RANGE:
		/* arg 3: count (write, pwrite64), vlen (writev family),
		   nbytes (sync_file_range: fd, offset, nbytes, flags) */
		p.sector = regs->dx;
		p.aux1 = regs->di;
		if (!fd_file((int)regs->di, &p))
			return 0;
		break;
	case IOTRACE_NR_FSYNC:
	case IOTRACE_NR_FDATASYNC:
		p.aux1 = regs->di;
		if (!fd_file((int)regs->di, &p))
			return 0;
		break;
	case IOTRACE_NR_MUNMAP:
		if (regs->si < IOTRACE_MUNMAP_MIN)
			return 0;
		/* fallthrough */
	case IOTRACE_NR_MSYNC:
		/* (addr, len, ...): no fd, so no inode and no device filter */
		p.sector = regs->si;
		p.aux1 = regs->di;
		break;
	default:
		return 0;
	}
	p.nr = id;
	p.ts_ns = bpf_ktime_get_ns();
	bpf_map_update_elem(&pending, &tid, &p, BPF_ANY);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit, struct pt_regs *regs, long ret)
{
	struct iotrace_event *e;
	struct pending *p;
	__u32 tid = cur_tid();
	__u64 now;

	p = bpf_map_lookup_elem(&pending, &tid);
	if (!p)
		return 0;
	if (p->nr != (__u32)regs->orig_ax) {
		bpf_map_delete_elem(&pending, &tid);
		return 0;
	}
	now = bpf_ktime_get_ns();

	e = reserve();
	if (e) {
		e->ts_ns = now;
		e->type = EV_SYSCALL;
		e->op = p->nr;
		e->major = p->major;
		e->minor = p->minor;
		e->sector = p->sector;
		e->bytes = ret > 0 ? (__u64)ret : 0;
		e->inode = p->inode;
		e->aux1 = p->aux1;
		e->aux2 = now - p->ts_ns;
		e->ret = ret;
		e->pid = bpf_get_current_pid_tgid() >> 32;
		e->tid = tid;
		bpf_get_current_comm(e->comm, sizeof(e->comm));
		bpf_ringbuf_submit(e, 0);
	}
	bpf_map_delete_elem(&pending, &tid);
	return 0;
}
