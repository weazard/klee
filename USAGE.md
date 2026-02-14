# Klee Usage Guide

Klee is a userspace bubblewrap (bwrap) translation layer. It provides
bwrap-compatible sandboxing without requiring kernel namespace support,
making it possible to run Steam, Flatpak, and pressure-vessel inside
Docker containers or other restricted environments that lack
`CAP_SYS_ADMIN` or unprivileged user namespaces.

Klee intercepts syscalls via `seccomp_unotify` (Linux 5.0+) or `ptrace`
(fallback) and simulates namespace isolation entirely in userspace.

## Building

### Requirements

- Linux >= 5.0 (for `seccomp_unotify`; ptrace fallback works on older kernels)
- GCC or Clang with C11 support
- GNU Make

### Optional Dependencies

- **libfuse3** -- enables FUSE-based `/proc` overlay for full mountinfo
  synthesis. Detected automatically via `pkg-config`.
- **slirp4netns** -- enables `--unshare-net` network isolation.

### Build Commands

```sh
make            # Build the klee binary
make test       # Build and run unit tests
make install    # Install to /usr/local/bin (override with PREFIX=)
make clean      # Remove build artifacts
```

Override the compiler or install prefix:

```sh
make CC=clang
make install PREFIX=/usr DESTDIR=/tmp/staging
```

### Feature Detection

The build system automatically detects available features:

| Feature              | Macro                  | Effect                                     |
|----------------------|------------------------|--------------------------------------------|
| seccomp_unotify      | `HAVE_SECCOMP_UNOTIFY` | Primary interception backend               |
| process_vm_readv     | `HAVE_PROCESS_VM`      | Fast tracee memory access                  |
| libfuse3             | `HAVE_FUSE3`           | FUSE /proc overlay                         |

## Quick Start

Klee is a drop-in replacement for `bwrap`. Use the same command-line
arguments:

```sh
# Basic sandbox with root bind mount
klee --bind / / -- /usr/bin/id

# Read-only root with writable /tmp
klee --ro-bind / / --tmpfs /tmp -- /bin/sh

# Full namespace isolation (like pressure-vessel)
klee --unshare-all --share-net \
     --ro-bind / / --tmpfs /tmp --proc /proc --dev /dev \
     --uid 0 --gid 0 --hostname sandbox \
     -- /usr/bin/id
```

## Command-Line Reference

```
klee [OPTIONS...] [--] COMMAND [ARGS...]
```

The `--` separator between options and the command is optional. Options
are processed left-to-right; mount operations are applied in the order
specified.

### Mount Options

| Option                       | Arguments      | Description                                         |
|------------------------------|----------------|-----------------------------------------------------|
| `--bind SRC DEST`            | 2              | Bind mount SRC to DEST (read-write)                 |
| `--bind-try SRC DEST`        | 2              | Bind mount, ignore if SRC doesn't exist             |
| `--ro-bind SRC DEST`         | 2              | Read-only bind mount                                |
| `--ro-bind-try SRC DEST`     | 2              | Read-only bind mount, ignore if SRC doesn't exist   |
| `--dev-bind SRC DEST`        | 2              | Bind mount with device access                       |
| `--dev-bind-try SRC DEST`    | 2              | Device bind mount, ignore if SRC doesn't exist      |
| `--tmpfs DEST`               | 1              | Mount a tmpfs at DEST                               |
| `--proc DEST`                | 1              | Mount procfs at DEST                                |
| `--dev DEST`                 | 1              | Mount devfs at DEST                                 |
| `--dir DEST`                 | 1              | Create an empty directory at DEST                   |
| `--symlink SRC DEST`         | 2              | Create symlink DEST pointing to SRC                 |
| `--file FD DEST`             | 2              | Copy contents of file descriptor FD to DEST         |
| `--bind-data FD DEST`        | 2              | Copy FD data to DEST and bind mount it              |
| `--ro-bind-data FD DEST`     | 2              | Copy FD data to DEST and read-only bind mount it    |
| `--bind-fd FD DEST`          | 2              | Bind mount from file descriptor FD to DEST          |
| `--ro-bind-fd FD DEST`       | 2              | Read-only bind mount from file descriptor FD        |
| `--mqueue DEST`              | 1              | Mount a POSIX message queue at DEST                 |
| `--ro-overlay DEST`          | 1              | Mount read-only overlay at DEST                     |
| `--remount-ro DEST`          | 1              | Remount an existing mount at DEST as read-only      |
| `--chmod OCTAL DEST`         | 2              | Set permissions on an existing mount                 |
| `--overlay-src PATH`         | 1              | Add an overlay source layer (stacks)                |
| `--overlay RW WORK DEST`     | 3              | Mount overlayfs with read-write layer               |
| `--tmp-overlay DEST`         | 1              | Mount overlayfs with tmpfs for writes               |

### Mount Modifiers

These affect the next mount operation only:

| Option             | Arguments | Description                                |
|--------------------|-----------|--------------------------------------------|
| `--perms OCTAL`    | 1         | Set permissions for next --dir/--file/etc.  |
| `--size BYTES`     | 1         | Set size limit for next --tmpfs             |

### Namespace Options

| Option              | Description                                            |
|---------------------|--------------------------------------------------------|
| `--unshare-user`    | Simulate a user namespace                              |
| `--unshare-pid`     | Simulate a PID namespace (processes see virtual PIDs)  |
| `--unshare-ipc`     | Simulate an IPC namespace (virtual IPC keys)           |
| `--unshare-uts`     | Simulate a UTS namespace (virtual hostname)            |
| `--unshare-net`     | Simulate a network namespace (via slirp4netns)         |
| `--unshare-cgroup`  | Simulate a cgroup namespace                            |
| `--unshare-all`     | Enable all of the above                                |
| `--share-net`       | Undo `--unshare-net` (keep host networking)            |

### Identity Options

| Option              | Arguments | Description                              |
|---------------------|-----------|------------------------------------------|
| `--uid UID`         | 1         | Set virtual UID inside sandbox           |
| `--gid GID`         | 1         | Set virtual GID inside sandbox           |
| `--hostname NAME`   | 1         | Set virtual hostname (requires --unshare-uts) |

### Process Options

| Option              | Arguments | Description                                    |
|---------------------|-----------|------------------------------------------------|
| `--chdir DIR`       | 1         | Change working directory inside sandbox        |
| `--setenv VAR VAL`  | 2         | Set environment variable                       |
| `--unsetenv VAR`    | 1         | Unset environment variable                     |
| `--clearenv`        | 0         | Clear all environment variables                |
| `--new-session`     | 0         | Create a new terminal session (setsid)         |
| `--die-with-parent` | 0         | Kill sandbox when parent process exits         |
| `--as-pid-1`        | 0         | Run command as PID 1 inside sandbox            |
| `--argv0 VALUE`     | 1         | Set argv[0] of the child command               |
| `--level-prefix`    | 0         | Add log level prefix to output                 |
| `--exec-label LABEL`| 1         | Set SELinux exec label                         |
| `--file-label LABEL`| 1         | Set SELinux file label                         |

### File Descriptor Options

| Option                | Arguments | Description                                 |
|-----------------------|-----------|---------------------------------------------|
| `--info-fd FD`        | 1         | Write `{ "child-pid": N }` JSON to FD      |
| `--json-status-fd FD` | 1         | Write JSON status updates to FD             |
| `--sync-fd FD`        | 1         | Close FD when sandbox setup is complete     |
| `--block-fd FD`       | 1         | Block startup until FD is closed            |
| `--seccomp FD`        | 1         | Apply child seccomp filter from FD          |
| `--add-seccomp-fd FD` | 1         | Add additional seccomp filter from FD       |
| `--lock-file PATH`    | 1         | Hold a lock on PATH while running           |
| `--args FD`           | 1         | Read NUL-separated arguments from FD        |

### Capability Options

| Option           | Arguments | Description           |
|------------------|-----------|-----------------------|
| `--cap-add CAP`  | 1         | Add named capability  |
| `--cap-drop CAP` | 1         | Drop named capability |

### Namespace FD Options

| Option                     | Arguments | Description                              |
|----------------------------|-----------|------------------------------------------|
| `--userns FD` / `--userns-fd FD`   | 1  | Join existing user namespace from FD     |
| `--userns2 FD` / `--userns2-fd FD` | 1  | Switch to user namespace after setup     |
| `--pidns FD` / `--pidns-fd FD`     | 1  | Join existing PID namespace from FD      |
| `--userns-block-fd FD`             | 1  | Block on FD before setting up user ns    |
| `--disable-userns`                 | 0  | Disable further user namespace creation  |
| `--assert-userns-disabled`         | 0  | Fail if user namespaces are not disabled |

## Environment Variables

| Variable    | Values                                       | Description              |
|-------------|----------------------------------------------|--------------------------|
| `KLEE_LOG`  | `error`, `warn`, `info`, `debug`, `trace`    | Set log verbosity level  |

Default log level is `warn`. Set `KLEE_LOG=debug` for detailed operation
tracing, or `KLEE_LOG=trace` for full syscall-level output.

```sh
KLEE_LOG=debug klee --bind / / -- /usr/bin/id
```

## How It Works

### Architecture Overview

```
 Parent (klee supervisor)              Child (sandboxed process)
 +---------------------------+         +-------------------------+
 |  Event Loop (epoll)       |         |  execvp(COMMAND)        |
 |    seccomp notif fd  <----+-- IPC --+--> seccomp filter       |
 |    signalfd(SIGCHLD)      |         |    (SECCOMP_RET_        |
 |                           |         |     USER_NOTIF)         |
 |  Syscall Dispatch Table   |         |                         |
 |    enter handlers         |         |  All syscalls with path |
 |    exit handlers          |         |  args are intercepted   |
 |                           |         +-------------------------+
 |  Virtual Mount Table      |
 |    (radix tree)           |
 |                           |
 |  PID Map (real <-> virt)  |
 |  UID/GID State            |
 |  FD Table                 |
 |  Virtual CWD              |
 +---------------------------+
```

### Interception Backends

**seccomp_unotify** (preferred, Linux 5.0+): The child installs a BPF
filter returning `SECCOMP_RET_USER_NOTIF` for intercepted syscalls. The
parent supervisor receives notifications via `ioctl()` on the
notification fd, performs path translation, and responds. Memory access
uses `/proc/pid/mem`.

**ptrace** (fallback): The child calls `PTRACE_TRACEME`. The parent uses
`waitpid()` with `PTRACE_O_TRACESYSGOOD` to intercept syscalls at entry
and exit. Path arguments are rewritten in tracee memory before the
syscall executes. Memory access uses `process_vm_readv`/`writev` (fast)
or `PTRACE_PEEKDATA`/`POKEDATA` (fallback).

### Filesystem Virtualization

Mount operations build a radix tree (compressed trie) mapping guest
paths to host paths. When a syscall references a path:

1. The guest path is read from tracee memory
2. It is canonicalized (resolving `.`, `..`, symlinks, relative paths)
3. The radix tree performs longest-prefix matching to find the mount
4. The guest path prefix is replaced with the host source path
5. The translated path is written back to tracee memory (ptrace) or
   used directly for the syscall (seccomp_unotify)

Read-only mounts are enforced by checking write-mode syscalls against
the mount table and returning `-EROFS`.

### Namespace Simulation

- **PID namespace**: Bidirectional hash map translates between real and
  virtual PIDs. `getpid()` returns the virtual PID; `kill()` translates
  virtual PIDs to real ones before forwarding.

- **User namespace**: Per-process UID/GID state tracks
  real/effective/saved/fs IDs. `setuid()` family updates internal state
  and voids the real syscall. `stat()` exit rewrites file ownership.

- **UTS namespace**: Virtual hostname stored in sandbox state. `uname()`
  exit overwrites the nodename field.

- **IPC namespace**: Virtual IPC keys are translated to real keys via a
  hash table.

- **Network namespace**: Launches `slirp4netns` for userspace networking
  when `--unshare-net` is specified.

### Steam Compatibility

Klee automatically exposes paths needed by the Steam overlay:

- `/dev/shm` (shared memory segments)
- `$XDG_RUNTIME_DIR/steam-overlay-*` (overlay IPC)
- `$XDG_RUNTIME_DIR/steam-ipc` (Steam IPC socket)
- `gameoverlayrenderer.so` paths (`/usr/lib`, `/usr/lib64`, `/usr/lib32`,
  `~/.steam/ubuntu12_32/`, `~/.steam/ubuntu12_64/`)

This allows the Steam overlay to function inside Klee-sandboxed
containers without manual path configuration.

## Examples

### Basic Sandbox

```sh
# Run a command with the host filesystem visible
klee --bind / / -- /usr/bin/whoami

# Read-only root with writable home
klee --ro-bind / / --bind /home /home -- /bin/bash
```

### Pressure-Vessel Compatible

This matches the typical command line used by Steam's pressure-vessel:

```sh
klee \
    --unshare-all --share-net \
    --uid 0 --gid 0 \
    --hostname steamdeck \
    --ro-bind / / \
    --tmpfs /tmp \
    --proc /proc \
    --dev /dev \
    --bind /home /home \
    --die-with-parent \
    --new-session \
    --info-fd 3 \
    -- /usr/bin/id
```

### Docker Integration

Use Klee as a bwrap replacement inside a Docker container that doesn't
support user namespaces:

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libfuse3-3
COPY klee /usr/bin/bwrap
# Steam/pressure-vessel will now use klee instead of bwrap
```

### Read-Only Enforcement

```sh
# This will fail with EROFS
klee --ro-bind / / -- /bin/touch /tmp/test

# Writable /tmp on top of read-only root
klee --ro-bind / / --tmpfs /tmp -- /bin/touch /tmp/test
```

### PID Namespace

```sh
# The shell sees itself as PID 1
klee --bind / / --unshare-pid -- /bin/bash -c 'echo $$'
# Output: 1
```

### UID Simulation

```sh
# Appear as root inside the sandbox
klee --bind / / --unshare-user --uid 0 --gid 0 -- /usr/bin/id
# Output: uid=0(root) gid=0(root) groups=0(root)
```

### Environment Control

```sh
klee --bind / / \
    --clearenv \
    --setenv PATH /usr/bin:/bin \
    --setenv HOME /root \
    -- /usr/bin/env
```

## Debugging

Enable verbose logging to diagnose issues:

```sh
# Show mount table and path translations
KLEE_LOG=debug klee --bind / / -- /usr/bin/ls /

# Full syscall-level tracing
KLEE_LOG=trace klee --bind / / -- /usr/bin/id
```

The debug output includes:

- Mount table contents after population
- Path translation decisions (guest path -> host path)
- Syscall enter/exit events with arguments
- PID and UID mapping operations
- Interception backend selection

## Testing

### Unit Tests

```sh
make test
```

Runs 7 test suites covering:

| Suite               | Tests | Coverage                              |
|---------------------|-------|---------------------------------------|
| test_cli            | 14    | CLI argument parsing                  |
| test_radix_tree     | 11    | Compressed trie operations            |
| test_mount_table    | 7     | Mount resolution and translation      |
| test_path_resolve   | 8     | Path canonicalization                 |
| test_pid_ns         | 7     | PID mapping                           |
| test_user_ns        | 8     | UID/GID state simulation              |
| test_fd_table       | 9     | File descriptor tracking              |

### Integration Tests

```sh
bash tests/test_integration.sh
bash tests/test_steam.sh
```

### Comparison Testing

Compare Klee output against real bwrap on a system with namespace
support:

```sh
diff <(bwrap --bind / / -- /usr/bin/id) \
     <(klee --bind / / -- /usr/bin/id)
```

## Limitations

- **Overlay mounts** (`--overlay`, `--tmp-overlay`, `--ro-overlay`) are
  not yet fully implemented (logged as warnings).
- **FUSE /proc overlay** provides basic passthrough; some synthetic
  files (e.g., `/proc/self/maps` path rewriting) are incomplete.
- **io_uring** is blocked (`-ENOSYS`) because it bypasses both seccomp
  and ptrace interception.
- **Nested bwrap/klee** invocations are detected but not fully layered.
- The ptrace backend has higher overhead than seccomp_unotify due to
  context switches per syscall.

## Project Structure

```
src/
  main.c                    Entry point and supervisor setup
  cli.c / cli.h             bwrap CLI argument parser
  config.c / config.h       Configuration structures

  intercept/                Syscall interception backends
    intercept.c               Backend-agnostic API
    seccomp_notif.c           seccomp_unotify backend
    ptrace_backend.c          ptrace fallback backend
    filter.c                  Raw BPF filter generation

  process/                  Process management
    process.c                 Per-process state and process table
    event.c                   Main epoll event loop
    memory.c                  Tracee memory read/write
    regs.c                    Register access abstraction

  fs/                       Filesystem virtualization
    radix_tree.c              Compressed trie for mount lookups
    mount_table.c             Virtual mount table
    path_resolve.c            Path canonicalization
    fd_table.c                FD-to-virtual-path tracking
    tmpfs.c                   tmpfs backing directories
    readonly.c                Read-only enforcement
    pivot.c                   pivot_root simulation

  ns/                       Namespace simulation
    pid_ns.c                  PID namespace (bidirectional map)
    user_ns.c                 UID/GID simulation
    ipc_ns.c                  IPC namespace (key translation)
    uts_ns.c                  UTS namespace (virtual hostname)
    net_ns.c                  Network namespace (slirp4netns)

  syscall/                  Syscall handling
    dispatch.c                Table-driven syscall dispatch
    enter.c                   Syscall-enter handlers (~45 syscalls)
    exit.c                    Syscall-exit handlers
    handlers.c                Handler registration
    sysnum.h                  x86_64 syscall number constants

  fuse/                     FUSE /proc overlay (optional)
    fuse_proc.c               Passthrough + selective synthesis
    fuse_mountinfo.c          /proc/self/mountinfo generation
    fuse_pidns.c              /proc PID filtering

  compat/                   Compatibility layer
    seccomp_filter.c          Child seccomp filter handling
    io_uring_block.c          io_uring blocking
    edge_cases.c              openat2, memfd, handle_at
    nested.c                  Nested bwrap detection

  steam/                    Steam-specific support
    steam_compat.c            Auto-expose overlay IPC paths

  util/                     Utilities
    log.c / log.h             Leveled logging
    arena.c / arena.h         Pool-based arena allocator
    hash_table.c              Open-addressing hash table
    list.h                    Intrusive linked list macros

tests/
  test_cli.c                CLI parsing tests
  test_radix_tree.c         Radix tree tests
  test_mount_table.c        Mount table tests
  test_path_resolve.c       Path resolution tests
  test_pid_ns.c             PID namespace tests
  test_user_ns.c            UID/GID simulation tests
  test_fd_table.c           FD tracking tests
  test_integration.sh       End-to-end tests
  test_steam.sh             Steam-specific tests
```
