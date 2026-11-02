/*
 * iotrace: print block request, writeback and page-dirty events as CSV.
 *
 * Usage: iotrace [-d MAJ:MIN] [-t SECONDS]
 *   -d  whole-disk device to trace (e.g. 8:0 for sda); default: all disks
 *   -t  stop after SECONDS; default: until SIGINT/SIGTERM
 *
 * Output (stdout): ts_ns,event,dev,op,sector,bytes,pid,comm,inode,tid,aux1,aux2,ret
 * ts_ns is CLOCK_MONOTONIC. Diagnostics go to stderr.
 * Events:
 *   rq_issue, rq_complete  block request; op R/W/F/D, sector on the disk
 *   wb_inode               writeback of one inode; bytes submitted
 *   dirty                  page of inode dirtied by pid/comm; sector = page index
 *   wb_start               writeback pass; op = reason (background, periodic, ...)
 *   bio_queue              bio submitted by pid/tid/comm; op R/W/F/D, sector, bytes
 *   bdp                    balance_dirty_pages of the writer; bytes = global dirty,
 *                          sector = background threshold, aux1 = dirty threshold
 *                          (all bytes), aux2 = pause in jiffies (< 0: no sleep)
 *   syscall                op = write, pwrite64, writev, pwritev, pwritev2, fsync,
 *                          fdatasync, sync_file_range (fd on a disk only), msync,
 *                          munmap (>= 1 MiB only); ts at exit, aux1 = fd (or
 *                          address), sector = count/vlen/len, bytes = return if
 *                          > 0, ret = raw return, aux2 = duration ns, inode of fd
 * Syscall numbers are x86_64.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "iotrace.h"
#include "iotrace.skel.h"

#define MAX_SECONDS 86400

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static const char *type_name(__u32 type)
{
	switch (type) {
	case EV_RQ_ISSUE:    return "rq_issue";
	case EV_RQ_COMPLETE: return "rq_complete";
	case EV_WB_INODE:    return "wb_inode";
	case EV_DIRTY:       return "dirty";
	case EV_WB_START:    return "wb_start";
	case EV_BIO_QUEUE:   return "bio_queue";
	case EV_BDP:         return "bdp";
	case EV_SYSCALL:     return "syscall";
	default:             return "unknown";
	}
}

/* enum wb_reason, include/linux/backing-dev-defs.h */
static const char *wb_reason_name(__u32 reason)
{
	switch (reason) {
	case 0:  return "background";
	case 1:  return "vmscan";
	case 2:  return "sync";
	case 3:  return "periodic";
	case 4:  return "laptop_timer";
	case 5:  return "fs_free_space";
	case 6:  return "forker_thread";
	case 7:  return "foreign_flush";
	default: return "other";
	}
}

static const char *syscall_name(__u32 nr)
{
	switch (nr) {
	case IOTRACE_NR_WRITE:           return "write";
	case IOTRACE_NR_MUNMAP:          return "munmap";
	case IOTRACE_NR_PWRITE64:        return "pwrite64";
	case IOTRACE_NR_WRITEV:          return "writev";
	case IOTRACE_NR_MSYNC:           return "msync";
	case IOTRACE_NR_FSYNC:           return "fsync";
	case IOTRACE_NR_FDATASYNC:       return "fdatasync";
	case IOTRACE_NR_SYNC_FILE_RANGE: return "sync_file_range";
	case IOTRACE_NR_PWRITEV:         return "pwritev";
	case IOTRACE_NR_PWRITEV2:        return "pwritev2";
	default:                         return "other";
	}
}

static const char *op_name(const struct iotrace_event *e)
{
	if (e->type == EV_WB_INODE || e->type == EV_DIRTY || e->type == EV_BDP)
		return "";
	if (e->type == EV_SYSCALL)
		return syscall_name(e->op);
	if (e->type == EV_WB_START)
		return wb_reason_name(e->op);
	switch (e->op) {
	case 0:  return "R";
	case 1:  return "W";
	case 2:  return "F";
	case 3:  return "D";
	default: return "O";
	}
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct iotrace_event *e = data;
	char comm[IOTRACE_COMM_LEN + 1];

	(void)ctx;
	if (size < sizeof(*e))
		return 0;

	/* Keep the CSV well formed whatever the task name is. */
	memcpy(comm, e->comm, IOTRACE_COMM_LEN);
	comm[IOTRACE_COMM_LEN] = '\0';
	for (char *p = comm; *p; p++)
		if (*p == ',' || *p == '\n' || *p == '"')
			*p = '_';

	printf("%llu,%s,%u:%u,%s,%llu,%llu,%u,%s,%llu,%u,%llu,%lld,%lld\n",
	       (unsigned long long)e->ts_ns, type_name(e->type), e->major, e->minor,
	       op_name(e), (unsigned long long)e->sector,
	       (unsigned long long)e->bytes, e->pid, comm,
	       (unsigned long long)e->inode, e->tid,
	       (unsigned long long)e->aux1, (long long)e->aux2,
	       (long long)e->ret);
	return 0;
}

static int parse_uint(const char *s, unsigned long max, unsigned long *out)
{
	char *end;

	if (*s < '0' || *s > '9')
		return -1;
	errno = 0;
	*out = strtoul(s, &end, 10);
	if (errno || *end || *out > max)
		return -1;
	return 0;
}

/* Accept only an existing whole disk: /sys/dev/block/M:m without "partition". */
static int parse_dev(const char *arg, unsigned long *maj, unsigned long *min)
{
	char buf[64], path[128];
	char *colon;

	if (strlen(arg) >= sizeof(buf))
		return -1;
	strcpy(buf, arg);
	colon = strchr(buf, ':');
	if (!colon)
		return -1;
	*colon = '\0';
	if (parse_uint(buf, 4095, maj) || parse_uint(colon + 1, 1048575, min))
		return -1;

	snprintf(path, sizeof(path), "/sys/dev/block/%lu:%lu", *maj, *min);
	if (access(path, F_OK)) {
		fprintf(stderr, "iotrace: no block device %lu:%lu\n", *maj, *min);
		return -1;
	}
	snprintf(path, sizeof(path), "/sys/dev/block/%lu:%lu/partition", *maj, *min);
	if (!access(path, F_OK)) {
		fprintf(stderr, "iotrace: %lu:%lu is a partition, use the whole disk\n",
			*maj, *min);
		return -1;
	}
	return 0;
}

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void usage(void)
{
	fprintf(stderr, "usage: iotrace [-d MAJ:MIN] [-t SECONDS]\n");
}

int main(int argc, char **argv)
{
	unsigned long maj = 0, min = 0, seconds = 0;
	int have_dev = 0, opt, err;
	const char *dev_arg = "all disks";
	struct iotrace_bpf *skel;
	struct ring_buffer *rb = NULL;
	double deadline = 0;

	while ((opt = getopt(argc, argv, "d:t:")) != -1) {
		switch (opt) {
		case 'd':
			if (parse_dev(optarg, &maj, &min)) {
				usage();
				return 2;
			}
			have_dev = 1;
			dev_arg = optarg;
			break;
		case 't':
			if (parse_uint(optarg, MAX_SECONDS, &seconds) || seconds == 0) {
				usage();
				return 2;
			}
			break;
		default:
			usage();
			return 2;
		}
	}
	if (optind != argc) {
		usage();
		return 2;
	}

	libbpf_set_print(libbpf_print);

	skel = iotrace_bpf__open();
	if (!skel) {
		fprintf(stderr, "iotrace: open failed: %s\n", strerror(errno));
		return 1;
	}
	skel->rodata->filter_dev = have_dev;
	skel->rodata->target_major = maj;
	skel->rodata->target_minor = min;

	err = iotrace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "iotrace: load failed: %s\n", strerror(-err));
		goto out;
	}
	err = iotrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "iotrace: attach failed: %s\n", strerror(-err));
		goto out;
	}
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "iotrace: ring buffer failed: %s\n", strerror(errno));
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	if (seconds)
		deadline = now_s() + seconds;

	printf("ts_ns,event,dev,op,sector,bytes,pid,comm,inode,tid,aux1,aux2,ret\n");
	fprintf(stderr, "iotrace: tracing %s\n", dev_arg);

	while (!stop && (!deadline || now_s() < deadline)) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "iotrace: poll failed: %s\n", strerror(-err));
			goto out;
		}
	}
	/* Drain what is left after the stop condition. */
	ring_buffer__consume(rb);
	err = 0;
	fflush(stdout);
	fprintf(stderr, "iotrace: dropped events: %llu\n",
		(unsigned long long)skel->bss->dropped);

out:
	ring_buffer__free(rb);
	iotrace_bpf__destroy(skel);
	return err ? 1 : 0;
}
