/*
 * mmap_write: write N MB to a file through a shared mapping and exit without
 * msync/fsync, so the data reaches the disk only through kernel writeback.
 *
 * Usage: mmap_write FILE MB
 * Prints CLOCK_MONOTONIC (ns) at start and right before exit, to compare
 * with iotrace ts_ns.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MB (1024UL * 1024UL)
#define MAX_MB 65536UL

static unsigned long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	unsigned long mb;
	size_t size, i;
	char *map, *end;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "usage: mmap_write FILE MB\n");
		return 2;
	}
	mb = strtoul(argv[2], &end, 10);
	if (*end || mb == 0 || mb > MAX_MB) {
		fprintf(stderr, "mmap_write: MB must be 1..%lu\n", MAX_MB);
		return 2;
	}
	size = mb * MB;

	printf("start_ns=%llu\n", now_ns());

	fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (ftruncate(fd, size)) {
		perror("ftruncate");
		return 1;
	}
	map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	/* Non-zero pattern so every page is dirtied with real data. */
	for (i = 0; i < size; i += 4096)
		memset(map + i, (int)((i / 4096) % 255) + 1, 4096);

	munmap(map, size);
	close(fd);
	printf("exit_ns=%llu\n", now_ns());
	return 0;
}
