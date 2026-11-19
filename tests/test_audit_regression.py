"""Integration regressions for syscall and process bookkeeping."""
import os
import fcntl
import json
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile


KLEE = str(Path(sys.argv[1]).resolve())


def run(*args, status=0, **kwargs):
    result = subprocess.run(
        [KLEE, "--bind", "/", "/", *map(str, args)],
        text=True, capture_output=True, timeout=12, **kwargs
    )
    assert result.returncode == status, (result.args, result.returncode, result.stderr)
    return result.stdout


def thread_lifecycle(tmp):
    cc = shutil.which("cc")
    if not cc:
        return
    helper = tmp / "thread-work"
    subprocess.run([cc, "-pthread", "-x", "c", "-o", helper, "-"], check=True,
                   text=True, input=r"""
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void *work(void *unused)
{
    (void)unused;
    struct stat st;
    for (int i = 0; i < 200; i++)
        if (stat("/", &st) < 0)
            _exit(3);
    return NULL;
}

static void *exec_command(void *unused)
{
    (void)unused;
    execl("/bin/sh", "sh", "-c", "echo worker-exec; exit 7", (char *)NULL);
    _exit(8);
}

static void *after_leader(void *unused)
{
    (void)unused;
    usleep(100000);
    puts("worker-finished");
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    pthread_t threads[8];
    if (!strcmp(argv[1], "exec")) {
        if (pthread_create(threads, NULL, exec_command, NULL))
            return 2;
        pthread_join(threads[0], NULL);
        return 2;
    }
    if (!strcmp(argv[1], "leader-exit")) {
        if (pthread_create(threads, NULL, after_leader, NULL))
            return 2;
        pthread_exit(NULL);
    }
    if (!strcmp(argv[1], "stop")) {
        pid_t child = fork();
        if (child == 0) {
            raise(SIGSTOP);
            _exit(9);
        }
        int status;
        if (child < 0 || waitpid(child, &status, WUNTRACED) != child ||
            !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP ||
            kill(child, SIGCONT) < 0 || waitpid(child, &status, 0) != child)
            return 2;
        return WIFEXITED(status) && WEXITSTATUS(status) == 9 ? 0 : 2;
    }

    for (int iteration = 0; iteration < 10; iteration++) {
        for (int i = 0; i < 8; i++)
            if (pthread_create(&threads[i], NULL, work, NULL))
                return 2;
        for (int i = 0; i < 8; i++)
            if (pthread_join(threads[i], NULL))
                return 2;
    }
    return 0;
}
""")
    run("--", helper, "threads")
    run("--", helper, "stop")
    assert run("--unshare-pid", "--", helper, "exec", status=7) == "worker-exec\n"
    assert run("--", helper, "leader-exit") == "worker-finished\n"


def paths_and_exec(tmp):
    host = tmp / "backing"
    host.mkdir()
    guest = tmp / "guest"
    (host / "name").write_text("original")
    assert run("--bind", host, guest, "--dir", guest,
               "--", "/bin/cat", guest / "name") == "original"
    assert run("--bind", host, guest, "--chdir", guest.name, "--", "/bin/pwd",
               cwd=tmp).strip() == str(guest)
    assert run("--dev", "/dev", "--bind", host, "/dev/shm",
               "--", "/bin/cat", "/dev/shm/name",
               env=dict(os.environ, SteamAppId="test")) == "original"
    run("--bind", host, guest, "--dir", guest / "new", "--",
        "/bin/sh", "-c", 'printf persisted > "$1/new/file"', "sh", guest)
    assert (host / "new/file").read_text() == "persisted"

    upper = tmp / "later"
    upper.mkdir()
    (upper / "name").write_text("later")
    assert run("--bind", host / "name", guest / "name", "--bind", upper, guest,
               "--", "/bin/cat", guest / "name") == "later"

    run("--bind", host, guest, "--symlink", "name", guest / "link", "--", sys.executable,
        "-c", """import os, sys
os.chdir(sys.argv[1])
assert os.readlink("link") == "name"
assert open("link").read() == "original"
os.rename("link", "new-link")
assert os.readlink("new-link") == "name"
assert open("name").read() == "original"
""", guest)

def cwd_and_exec_args(tmp):
    backing = tmp / "runtime"
    guest = tmp / "x"
    backing.mkdir()
    (backing / "inner").write_text(f"#!{sys.executable}\n"
                                  "import sys\n"
                                  "assert sys.argv[1:3] == ['inner-opt', './outer']\n"
                                  "assert len(sys.argv) == 323\n")
    (backing / "outer").write_text(f"#!{guest}/inner inner-opt\n")
    for name in ("inner", "outer"):
        (backing / name).chmod(0o700)

    fd = os.open(backing, os.O_RDONLY | os.O_DIRECTORY)
    try:
        run("--bind", backing, guest, "--", sys.executable, "-c", """
import ctypes, os, sys
os.fchdir(int(sys.argv[1]))
assert os.getcwd() == sys.argv[2]
libc = ctypes.CDLL(None, use_errno=True)
buf = ctypes.create_string_buffer(len(os.fsencode(sys.argv[2])) + 1)
assert libc.syscall(79, buf, len(buf)) == len(buf)  # x86_64 getcwd
assert os.fsdecode(buf.value) == sys.argv[2]
old_exe = os.readlink("/proc/self/exe")
try:
    os.execv("./nonexistent", ["ignored"])
except FileNotFoundError:
    pass
assert os.readlink("/proc/self/exe") == old_exe
os.execv("./outer", ["custom-argv0"] + ["arg"] * 320)
""", fd, guest, pass_fds=(fd,))
    finally:
        os.close(fd)

    fifo = tmp / "fifo"
    os.mkfifo(fifo, 0o700)
    run("--", fifo, status=127)


def syscall_arguments(tmp):
    backing = tmp / "io"
    backing.mkdir()
    (backing / "name").write_text("mounted")
    guest = tmp / "io-guest"
    run("--bind", backing, guest, "--unshare-user", "--uid", 2734, "--gid", 2734,
        "--", sys.executable, "-c", """
import ctypes, errno, os, socket, sys
guest = sys.argv[1]
fd = os.open(guest, os.O_RDONLY | os.O_DIRECTORY)
libc = ctypes.CDLL(None, use_errno=True)
for path, resolve in ((b"name", 8), (b"/name", 16)):
    how = (ctypes.c_uint64 * 3)(os.O_RDONLY, 0, resolve)
    result = libc.syscall(437, fd, path, ctypes.byref(how), ctypes.sizeof(how))
    if result < 0 and ctypes.get_errno() == errno.ENOSYS:
        break
    assert result >= 0, ctypes.get_errno()
    assert os.read(result, 20) == b"mounted"
    os.close(result)
os.close(fd)

assert os.getgroups() == [2734]
os.setgroups([2734, 2735])
assert os.getgroups() == [2734, 2735]

path = guest + "/s"
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
    receiver.bind(path)
    receiver.settimeout(2)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sender:
        sender.sendto(b"one", path)
        sender.sendmsg([b"two"], [], 0, path)
    assert receiver.recv(20) == b"one"
    assert receiver.recv(20) == b"two"
""", guest)

    fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert run("--args", fd, "--", "/bin/echo", "unexpected",
                   status=1, pass_fds=(fd,)) == ""
    finally:
        os.close(fd)


def monitoring(tmp):
    lock = tmp / "lock"
    lock.touch()
    read_fd, write_fd = os.pipe()
    info_read, info_write = os.pipe()
    with subprocess.Popen(
        [KLEE, "--block-fd", str(read_fd), "--info-fd", str(info_write),
         "--lock-file", str(lock), "--", "/bin/sleep", "30"],
        pass_fds=(read_fd, info_write), stderr=subprocess.PIPE,
    ) as job:
        os.close(read_fd)
        os.close(info_write)
        try:
            os.write(write_fd, b"x")
            assert select.select([info_read], [], [], 5)[0]
            os.set_blocking(info_read, False)
            data = os.read(info_read, 4096)
            assert json.loads(data)["child-pid"] > 0
            assert select.select([info_read], [], [], 2)[0]
            assert os.read(info_read, 1) == b""
            with lock.open("r+") as handle:
                try:
                    fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError("supervisor released the lock")
            job.send_signal(signal.SIGTERM)
            assert job.wait(timeout=5) == 128 + signal.SIGTERM
        finally:
            os.close(write_fd)
            os.close(info_read)
            if job.poll() is None:
                job.kill()
    with lock.open("r+") as handle:
        fcntl.lockf(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)


with tempfile.TemporaryDirectory(prefix="klee-audit-test.") as root:
    temp = Path(root)
    thread_lifecycle(temp)
    paths_and_exec(temp)
    cwd_and_exec_args(temp)
    syscall_arguments(temp)
    monitoring(temp)
