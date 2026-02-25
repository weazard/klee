# Klee - Userspace bwrap translation layer
# Build system

CC       ?= gcc
CPPFLAGS  = -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I./src
CFLAGS    = -g -Wall -Wextra -Wpedantic -O2 -std=c11
LDFLAGS   =
LDLIBS    =

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

# Feature detection
HAVE_SECCOMP_UNOTIFY := $(shell echo '\#include <linux/seccomp.h>' | \
	$(CC) -xc -c - -o /dev/null 2>/dev/null && echo 1 || echo 0)
HAVE_PROCESS_VM := $(shell echo '\#include <sys/uio.h>\nint main(){process_vm_readv(0,0,0,0,0,0);}' | \
	$(CC) -xc - -o /dev/null 2>/dev/null && echo 1 || echo 0)

# Optional FUSE3
HAVE_FUSE3 := $(shell pkg-config --exists fuse3 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_FUSE3),1)
FUSE_CFLAGS := $(shell pkg-config --cflags fuse3)
FUSE_LDFLAGS := $(shell pkg-config --libs fuse3)
CPPFLAGS += -DHAVE_FUSE3=1
else
FUSE_CFLAGS :=
FUSE_LDFLAGS :=
endif

ifeq ($(HAVE_SECCOMP_UNOTIFY),1)
CPPFLAGS += -DHAVE_SECCOMP_UNOTIFY=1
endif
ifeq ($(HAVE_PROCESS_VM),1)
CPPFLAGS += -DHAVE_PROCESS_VM=1
endif

# Source files
UTIL_SRCS = src/util/log.c src/util/arena.c src/util/hash_table.c
FS_SRCS   = src/fs/radix_tree.c src/fs/mount_table.c src/fs/path_resolve.c \
            src/fs/fd_table.c src/fs/tmpfs.c src/fs/readonly.c src/fs/pivot.c \
            src/fs/overlay.c
NS_SRCS   = src/ns/pid_ns.c src/ns/user_ns.c src/ns/ipc_ns.c \
            src/ns/uts_ns.c src/ns/net_ns.c src/ns/proc_synth.c
INTERCEPT_SRCS = src/intercept/intercept.c src/intercept/seccomp_notif.c \
                 src/intercept/ptrace_backend.c src/intercept/filter.c
PROCESS_SRCS   = src/process/process.c src/process/event.c \
                 src/process/memory.c src/process/regs.c
SYSCALL_SRCS   = src/syscall/dispatch.c src/syscall/enter.c \
                 src/syscall/exit.c src/syscall/handlers.c
COMPAT_SRCS    = src/compat/seccomp_filter.c src/compat/io_uring_block.c \
                 src/compat/edge_cases.c src/compat/nested.c
STEAM_SRCS     = src/steam/steam_compat.c

# fuse_mountinfo and fuse_pidns are always compiled (no FUSE dependency)
# fuse_proc requires FUSE3
FUSE_SRCS = src/fuse/fuse_mountinfo.c src/fuse/fuse_pidns.c src/fuse/fuse_proc.c

CORE_SRCS = src/main.c src/cli.c src/config.c
ALL_SRCS  = $(CORE_SRCS) $(UTIL_SRCS) $(FS_SRCS) $(NS_SRCS) $(INTERCEPT_SRCS) \
            $(PROCESS_SRCS) $(SYSCALL_SRCS) $(COMPAT_SRCS) $(STEAM_SRCS) $(FUSE_SRCS)

ALL_OBJS  = $(ALL_SRCS:.c=.o)

# Test sources
TEST_SRCS = tests/test_cli.c tests/test_radix_tree.c tests/test_mount_table.c \
            tests/test_path_resolve.c tests/test_pid_ns.c tests/test_user_ns.c \
            tests/test_fd_table.c
TEST_BINS = $(TEST_SRCS:.c=)

# Build targets
.PHONY: all clean test install

all: klee klee-noroot

klee: $(ALL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(FUSE_LDFLAGS)

# Same binary but never fakes root — processes keep their real uid/gid.
src/main-noroot.o: src/main.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DKLEE_NO_FAKE_ROOT -c -o $@ $<

NOROOT_OBJS = src/main-noroot.o $(filter-out src/main.o,$(ALL_OBJS))

klee-noroot: $(NOROOT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(FUSE_LDFLAGS)

# FUSE objects need extra flags
src/fuse/%.o: src/fuse/%.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FUSE_CFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# Generate build config header
src/build_config.h: Makefile
	@echo "/* Auto-generated - do not edit */" > $@
	@echo "#ifndef KLEE_BUILD_CONFIG_H" >> $@
	@echo "#define KLEE_BUILD_CONFIG_H" >> $@
	@echo "#define HAVE_SECCOMP_UNOTIFY_VAL $(HAVE_SECCOMP_UNOTIFY)" >> $@
	@echo "#define HAVE_PROCESS_VM_VAL $(HAVE_PROCESS_VM)" >> $@
	@echo "#define HAVE_FUSE3_VAL $(HAVE_FUSE3)" >> $@
	@echo "#endif" >> $@

# Test targets
# Each test links against needed library objects
COMMON_TEST_OBJS = $(UTIL_SRCS:.c=.o)
FS_TEST_OBJS     = $(FS_SRCS:.c=.o)
NS_TEST_OBJS     = $(NS_SRCS:.c=.o)

tests/test_cli: tests/test_cli.c src/cli.o src/config.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_radix_tree: tests/test_radix_tree.c src/fs/radix_tree.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_mount_table: tests/test_mount_table.c src/fs/mount_table.o src/fs/radix_tree.o src/fs/tmpfs.o src/fs/pivot.o src/fs/overlay.o src/fuse/fuse_mountinfo.o src/config.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_path_resolve: tests/test_path_resolve.c src/fs/path_resolve.o src/fs/mount_table.o src/fs/radix_tree.o src/fs/tmpfs.o src/fs/pivot.o src/fs/fd_table.o src/fs/overlay.o src/fuse/fuse_mountinfo.o src/config.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_pid_ns: tests/test_pid_ns.c src/ns/pid_ns.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_user_ns: tests/test_user_ns.c src/ns/user_ns.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_fd_table: tests/test_fd_table.c src/fs/fd_table.o $(COMMON_TEST_OBJS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_BINS)
	@echo "=== Running unit tests ==="
	@failed=0; \
	for t in $(TEST_BINS); do \
		echo "--- $$t ---"; \
		./$$t || failed=$$((failed + 1)); \
	done; \
	echo "=== $$failed test(s) failed ==="; \
	exit $$failed

install: klee klee-noroot
	install -D -m 755 klee $(DESTDIR)$(BINDIR)/klee
	install -D -m 755 klee-noroot $(DESTDIR)$(BINDIR)/klee-noroot
	ln -sf klee $(DESTDIR)$(BINDIR)/bwrap
	for d in /usr/bin /bin; do \
		install -D -m 755 klee "$(DESTDIR)$$d/klee" && \
			ln -sf klee "$(DESTDIR)$$d/bwrap" || true; \
	done

clean:
	rm -f klee klee-noroot src/build_config.h src/main-noroot.o
	find src tests -name '*.o' -delete
	rm -f $(TEST_BINS)
