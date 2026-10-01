"""Shared nonblocking Windows/Linux workspace lock for portable and agent runs."""
from contextlib import contextmanager
from functools import wraps
import os
from pathlib import Path
import stat
import threading


class WorkspaceBusy(RuntimeError):
    pass


_guard = threading.RLock()
_held = {}


@contextmanager
def workspace_lock(workspace):
    """Retain the lock inode; kernel ownership is released even on process exit."""
    workspace = Path(workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    lock_path = workspace / ".canca-workspace.lock"
    owner = threading.get_ident()
    with _guard:
        entry = _held.get(str(workspace))
        if entry:
            if entry[0] != owner:
                raise WorkspaceBusy("workspace_busy")
            entry[2] += 1
        else:
            if lock_path.is_symlink():
                raise WorkspaceBusy("unsafe_lock_file")
            fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise WorkspaceBusy("unsafe_lock_file")
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                os.close(fd)
                raise WorkspaceBusy("workspace_busy") from exc
            except BaseException:
                os.close(fd)
                raise
            _held[str(workspace)] = [owner, fd, 1]
    try:
        yield
    finally:
        with _guard:
            entry = _held[str(workspace)]
            entry[2] -= 1
            if entry[2] == 0:
                fd = entry[1]
                try:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
                    del _held[str(workspace)]


def locked_workspace(function):
    @wraps(function)
    def wrapped(workspace, *args, **kwargs):
        with workspace_lock(workspace):
            return function(workspace, *args, **kwargs)
    return wrapped
