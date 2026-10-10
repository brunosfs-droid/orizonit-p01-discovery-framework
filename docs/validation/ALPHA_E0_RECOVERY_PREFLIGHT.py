#!/usr/bin/env python3
"""Offline, read-only integrity gate for E0 backup artifacts.

This is NOT a database restore, signature, role/grant audit, or RPO/RTO test.
The manifest contains digests/counts only, no paths, SQL, or secret contents.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

SCHEMA = "canca-alpha-e0-artifacts-v1"
MAX_ENTRIES = 200000
MAX_MANIFEST_BYTES = 16384
BLOCK = 1024 * 1024


class GateError(Exception):
    pass


def _regular(path):
    try:
        info = path.lstat()
    except OSError:
        raise GateError("input_unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise GateError("invalid_regular_file")
    return info



def _open_source(path):
    """Open evidence without following directory/file symlinks on POSIX.

    File descriptor traversal closes a classic lstat/open race. On platforms
    lacking O_NOFOLLOW and open(dir_fd=...), the existing lstat/fstat checks
    still apply, but this strong race fence is not available.
    """
    if not (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
            hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd):
        return path.open("rb")
    components = path.absolute().parts
    if any(component in (".", "..") for component in components[1:]):
        raise GateError("unsafe_source_path")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(components[0], dir_flags)
    try:
        for component in components[1:-1]:
            opened = os.open(component, dir_flags, dir_fd=directory)
            os.close(directory)
            directory = opened
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(components[-1], file_flags, dir_fd=directory)
        try:
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, stat.S_IMODE(info.st_mode))



def _file(path):
    before = _regular(path)
    h = hashlib.sha256()
    try:
        with _open_source(path) as reader:
            opened = os.fstat(reader.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size == 0:
                raise GateError("invalid_regular_file")
            if _identity(opened) != _identity(before):
                raise GateError("input_changed")
            for chunk in iter(lambda: reader.read(BLOCK), b""):
                h.update(chunk)
            finished = os.fstat(reader.fileno())
            if _identity(finished) != _identity(opened):
                raise GateError("input_changed")
    except OSError:
        raise GateError("input_unavailable") from None
    after = _regular(path)
    if _identity(before) != _identity(after):
        raise GateError("input_changed")
    return {"sha256": h.hexdigest(), "bytes": after.st_size}



def _secure_tree_supported():
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
            hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd)


def _open_source_directory(path):
    """Anchor a directory tree to kernel fds; never traverse a symlink."""
    parts = path.absolute().parts
    if any(part in (".", "..") for part in parts[1:]):
        raise GateError("unsafe_source_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(parts[0], flags)
    try:
        for part in parts[1:]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _tree_secure(root, root_stat):
    """Hash every entry using directory-relative, nofollow kernel handles.

    All observed paths/identities must agree across opening and traversal.
    Atomic tree snapshots still require an operator-controlled quiesce.
    """
    root_fd = _open_source_directory(root)
    try:
        if _identity(os.fstat(root_fd)) != _identity(root_stat):
            raise GateError("input_changed")
        entries = []
        files = 0
        dirs = 0
        bytes_total = 0
        dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)

        def walk(directory_fd, prefix, depth):
            nonlocal files, dirs, bytes_total
            if depth > 64:
                raise GateError("entry_limit")
            initial = os.fstat(directory_fd)
            if not stat.S_ISDIR(initial.st_mode):
                raise GateError("invalid_directory")
            for leaf in sorted(os.listdir(directory_fd)):
                name = prefix + leaf
                if len(entries) >= MAX_ENTRIES:
                    raise GateError("entry_limit")
                observed = os.stat(leaf, dir_fd=directory_fd,
                                   follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    fd = os.open(leaf, dir_flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(fd)
                        if _identity(observed) != _identity(opened):
                            raise GateError("input_changed")
                        entries.append((name, ["D", name,
                                               oct(stat.S_IMODE(opened.st_mode))]))
                        dirs += 1
                        walk(fd, name + "/", depth + 1)
                        if _identity(os.fstat(fd)) != _identity(opened):
                            raise GateError("input_changed")
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(observed.st_mode):
                    fd = os.open(leaf, file_flags, dir_fd=directory_fd)
                    try:
                        with os.fdopen(fd, "rb") as reader:
                            fd = -1  # Ownership transferred to context manager.
                            before = os.fstat(reader.fileno())
                            if (not stat.S_ISREG(before.st_mode) or
                                    before.st_size == 0):
                                raise GateError("invalid_regular_file")
                            if _identity(observed) != _identity(before):
                                raise GateError("input_changed")
                            digest = hashlib.sha256()
                            for chunk in iter(lambda: reader.read(BLOCK), b""):
                                digest.update(chunk)
                            if _identity(os.fstat(reader.fileno())) != _identity(before):
                                raise GateError("input_changed")
                    finally:
                        if fd >= 0:
                            os.close(fd)
                    entries.append((name, ["F", name, str(before.st_size),
                                           digest.hexdigest(),
                                           oct(stat.S_IMODE(before.st_mode))]))
                    files += 1
                    bytes_total += before.st_size
                else:
                    raise GateError("unsupported_tree_entry")
                after = os.stat(leaf, dir_fd=directory_fd,
                                follow_symlinks=False)
                if _identity(after) != _identity(observed):
                    raise GateError("input_changed")
            if _identity(os.fstat(directory_fd)) != _identity(initial):
                raise GateError("input_changed")

        walk(root_fd, "", 0)
        if _identity(os.fstat(root_fd)) != _identity(root_stat):
            raise GateError("input_changed")
        if _identity(root.lstat()) != _identity(root_stat):
            raise GateError("input_changed")
        if files == 0:
            raise GateError("empty_directory")
        digest = hashlib.sha256()
        digest.update(("ROOT\0" + oct(stat.S_IMODE(root_stat.st_mode)) +
                       "\n").encode())
        for _, line in sorted(entries, key=lambda item: item[0]):
            digest.update(("\0".join(line) + "\n").encode("utf-8"))
        return {"sha256": digest.hexdigest(), "files": files,
                "directories": dirs, "bytes": bytes_total}
    finally:
        os.close(root_fd)


def _directory(root):
    try:
        root_stat = root.lstat()
    except OSError:
        raise GateError("input_unavailable") from None
    if not stat.S_ISDIR(root_stat.st_mode):
        raise GateError("invalid_directory")
    if _secure_tree_supported():
        try:
            return _tree_secure(root, root_stat)
        except (OSError, UnicodeError, ValueError):
            raise GateError("input_unavailable") from None
    entries = 0
    files = 0
    directories = 0
    total = 0
    h = hashlib.sha256()
    h.update(("ROOT\0" + oct(stat.S_IMODE(root_stat.st_mode)) + "\n").encode())
    try:
        paths = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
        for path in paths:
            entries += 1
            if entries > MAX_ENTRIES:
                raise GateError("entry_limit")
            info = path.lstat()
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                directories += 1
                line = ["D", name, oct(stat.S_IMODE(info.st_mode))]
            elif stat.S_ISREG(info.st_mode):
                # A file disappearing while it is read must fail the entire gate.
                result = _file(path)
                files += 1
                total += result["bytes"]
                line = ["F", name, str(result["bytes"]), result["sha256"],
                        oct(stat.S_IMODE(info.st_mode))]
            else:
                # Symlinks, sockets, FIFOs and device nodes cannot enter the bundle.
                raise GateError("unsupported_tree_entry")
            h.update(("\0".join(line) + "\n").encode("utf-8"))
    except (OSError, UnicodeError):
        raise GateError("input_unavailable") from None
    if files == 0:
        raise GateError("empty_directory")
    return {"sha256": h.hexdigest(), "files": files,
            "directories": directories, "bytes": total}


def _inside(path, root):
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _artifacts(args):
    paths = [Path(args.database_dump), Path(args.roles_snapshot)]
    roots = [Path(args.store_root), Path(args.config_root)]
    resolved = [p.resolve() for p in paths + roots]
    if len(set(resolved)) != 4:
        raise GateError("overlapping_inputs")
    if _inside(roots[0], roots[1]) or _inside(roots[1], roots[0]):
        raise GateError("overlapping_inputs")
    if any(_inside(path, root) for path in paths for root in roots):
        raise GateError("overlapping_inputs")
    return {"database_dump": _file(paths[0]),
            "roles_snapshot": _file(paths[1]),
            "store": _directory(roots[0]),
            "configuration": _directory(roots[1])}


def _manifest_output(path, args):
    roots = [Path(args.store_root), Path(args.config_root)]
    paths = [Path(args.database_dump), Path(args.roles_snapshot)]
    if any(_inside(path, root) for root in roots) or any(
        path.resolve() == candidate.resolve() for candidate in paths
    ):
        raise GateError("unsafe_output")
    parent = path.parent
    try:
        mode = parent.stat().st_mode
    except OSError:
        raise GateError("unsafe_output") from None
    if not stat.S_ISDIR(mode) or (stat.S_IMODE(mode) & 0o077):
        raise GateError("unsafe_output")
    return path


def _manifest_read(path):
    size = _regular(path).st_size
    if size > MAX_MANIFEST_BYTES:
        raise GateError("manifest_invalid")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise GateError("manifest_invalid") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "verify"):
        action = sub.add_parser(name)
        action.add_argument("--database-dump", required=True)
        action.add_argument("--roles-snapshot", required=True)
        action.add_argument("--store-root", required=True)
        action.add_argument("--config-root", required=True)
        action.add_argument("--output" if name == "capture" else "--manifest",
                            required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            path = _manifest_output(Path(args.output), args)
            body = {"schema": SCHEMA, "artifacts": _artifacts(args)}
            serialized = (json.dumps(body, sort_keys=True, separators=(",", ":")) +
                          "\n").encode("utf-8")
            # O_EXCL and 0600: never replace a previous proof.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as writer:
                writer.write(serialized)
                writer.flush()
                os.fsync(writer.fileno())
            status = "CAPTURED"
        else:
            expected = _manifest_read(Path(args.manifest))
            actual = {"schema": SCHEMA, "artifacts": _artifacts(args)}
            if expected != actual:
                raise GateError("artifact_mismatch")
            status = "PASS"
        print(json.dumps({"gate": "ALPHA_E0_ARTIFACTS", "status": status,
                          "scope": "offline_artifact_integrity_only"},
                         sort_keys=True))
        return 0
    except (GateError, OSError) as error:
        # Never emit paths, file names, SQL or exception strings into CI logs.
        code = str(error) if isinstance(error, GateError) else "io_error"
        print(json.dumps({"gate": "ALPHA_E0_ARTIFACTS", "status": "FAIL",
                          "reason": code}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
