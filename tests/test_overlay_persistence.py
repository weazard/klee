import ctypes
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile


AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
libc = ctypes.CDLL(None, use_errno=True)


def renameat2(source, target, flags):
    result = libc.renameat2(AT_FDCWD, os.fsencode(source),
                            AT_FDCWD, os.fsencode(target), flags)
    if result < 0:
        raise OSError(ctypes.get_errno(), "renameat2")


def expect_error(expected, operation, *args):
    try:
        operation(*args)
    except OSError as error:
        assert error.errno == expected, error
    else:
        raise AssertionError(f"{operation.__name__} unexpectedly succeeded")


def mutate(view):
    os.chdir(view)
    expect_error(errno.EEXIST, renameat2, "upper-source", "existing", RENAME_NOREPLACE)
    expect_error(errno.EISDIR, os.rename, "file-source", "directory")
    assert Path("file-source").read_text() == "file-source"
    expect_error(errno.ENOTEMPTY, os.rmdir, "directory")

    os.unlink("delete-me")
    os.unlink("upper-shadow")
    os.unlink("directory/child")
    os.rmdir("directory")
    os.mkdir("directory")
    os.rename("move-me", "moved")
    renameat2("swap-a", "swap-b", RENAME_EXCHANGE)
    assert Path("swap-a").read_text() == "swap-b"
    assert Path("swap-b").read_text() == "swap-a"
    os.unlink("swap-a")
    os.link("link-source", "linked")
    Path("linked").write_text("changed")
    assert Path("link-source").read_text() == "changed"

    # A duplicated descriptor retains its overlay origin after a rename.
    original = os.open("descriptor-source", os.O_RDONLY)
    fd = os.dup(original)
    os.close(original)
    os.rename("descriptor-source", "descriptor-moved")
    source = os.fsencode(f"/proc/self/fd/{fd}")
    result = libc.linkat(AT_FDCWD, source, AT_FDCWD, b"descriptor-link", AT_SYMLINK_FOLLOW)
    os.close(fd)
    if result < 0:
        raise OSError(ctypes.get_errno(), "linkat")
    assert Path("descriptor-link").stat().st_ino == Path("descriptor-moved").stat().st_ino

    reader = os.open("pipe", os.O_RDONLY | os.O_NONBLOCK)
    writer = os.open("pipe", os.O_WRONLY | os.O_NONBLOCK)
    os.write(writer, b"ok")
    assert os.read(reader, 2) == b"ok"
    os.close(reader)
    os.close(writer)


def nested_bind(view, klee, alias, other_alias):
    script = Path(__file__).resolve()
    subprocess.run([
        klee, "--bind", f"{view}/sub", alias, "--ro-bind", f"{view}/sub", other_alias,
        "--", sys.executable, str(script), "child", alias, other_alias,
    ], check=True)
    assert not Path(alias).exists(), "nested mount leaked into the parent"
    assert (Path(view) / "sub" / "new").read_text() == "nested"


def nested_child(alias, other_alias):
    tree = Path(alias)
    assert sorted(path.name for path in tree.iterdir()) == ["low", "up"]
    assert (tree / "low").read_text() == "low"
    assert (tree / "up").read_text() == "up"
    expect_error(errno.EXDEV, os.rename, tree / "low", Path(other_alias) / "moved")
    expect_error(errno.EROFS, (Path(other_alias) / "read-only").write_text, "blocked")
    (tree / "new").write_text("nested")


def check_reopened(view):
    os.chdir(view)
    visible = set(os.listdir("."))
    for name in ("delete-me", "upper-shadow", "move-me", "swap-a", ".klee-overlay"):
        assert name not in visible, name
        assert not Path(name).exists(), name
    assert list(Path("directory").iterdir()) == []
    assert Path("moved").read_text() == "move-me"
    assert Path("swap-b").read_text() == "swap-a"
    assert Path("legacy").read_text() == "existing upper data"
    assert Path("link-source").stat().st_ino == Path("linked").stat().st_ino


def run(klee):
    klee = str(Path(klee).resolve())
    lower_storage = "/dev/shm" if os.access("/dev/shm", os.W_OK | os.X_OK) else None
    with tempfile.TemporaryDirectory(prefix="klee-lower-", dir=lower_storage) as lower_dir, \
         tempfile.TemporaryDirectory(prefix="klee-upper-") as root_dir:
        lower, root = Path(lower_dir), Path(root_dir)
        upper, work = root / "upper", root / "work"
        for directory in (upper, work, lower / "directory", lower / "sub", upper / "sub"):
            directory.mkdir()
        for name in ("file-source", "existing", "delete-me", "upper-shadow", "move-me",
                     "swap-a", "swap-b", "link-source"):
            (lower / name).write_text(name)
        (lower / "directory" / "child").write_text("child")
        (lower / "sub" / "low").write_text("low")
        (upper / "sub" / "up").write_text("up")
        (upper / "legacy").write_text("existing upper data")
        (upper / "upper-source").write_text("source")
        (upper / "upper-shadow").write_text("shadow")
        (upper / "descriptor-source").write_text("descriptor")
        os.mkfifo(lower / "pipe")
        view = str(root / "view")
        launcher = [
            klee, "--bind", "/", "/", "--overlay-src", str(lower),
            "--overlay", str(upper), str(work), view, "--",
            sys.executable, str(Path(__file__).resolve()),
        ]
        subprocess.run(launcher + ["mutate", view], check=True)
        assert (upper / "upper-source").read_text() == "source"
        assert not (upper / "file-source").exists()
        for name in ("delete-me", "upper-shadow", "move-me", "link-source"):
            assert (lower / name).read_text() == name
        (lower / "directory" / "added-later").write_text("hidden by the opaque directory")
        subprocess.run(launcher + ["reopened", view], check=True)
        subprocess.run(launcher + ["nested", view, klee, str(root / "alias"),
                                   str(root / "other-alias")], check=True)
        assert (upper / "sub" / "new").read_text() == "nested"


if __name__ == "__main__":
    checks = {"mutate": mutate, "reopened": check_reopened,
              "nested": nested_bind, "child": nested_child}
    if sys.argv[1] in checks:
        checks[sys.argv[1]](*sys.argv[2:])
    else:
        run(sys.argv[1])
