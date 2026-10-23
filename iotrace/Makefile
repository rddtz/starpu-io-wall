# Build iotrace (libbpf + CO-RE, BPF object embedded via skeleton).
BPFTOOL ?= /usr/sbin/bpftool
CLANG   ?= clang
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
ARCH    := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)

all: iotrace test/mmap_write

test: test/mmap_write

# Generated from the running kernel; not committed.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

iotrace.bpf.o: iotrace.bpf.c iotrace.h vmlinux.h
	$(CLANG) -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -c $< -o $@

iotrace.skel.h: iotrace.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp
	mv $@.tmp $@

iotrace: iotrace.c iotrace.h iotrace.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

test/mmap_write: test/mmap_write.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f iotrace iotrace.bpf.o iotrace.skel.h vmlinux.h test/mmap_write

.PHONY: all test clean
