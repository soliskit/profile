"""Fixed trusted preparation/inspection, not package-selected code.

Only a new disposable Docker-managed volume at /work is supported in production.
The container launch/image and root ownership are independently reviewed by host.
"""

import hashlib
import os
import pathlib
import stat

MAX_FILES = 10000
MAX_BYTES = 32 * 1024 * 1024
OUTPUT_FILES = {"next-env.d.ts", "tsconfig.tsbuildinfo"}
OUTPUT_DIRS = {".next", "out", "test-results", "playwright-report"}


def inspect(root):
    """Complete no-follow walk while NO package process can run.

    Volume must be mounted only to this inspector; no concurrent writers. Caller
    verifies mount source/identity and container teardown. No internal .git yet.
    """
    root = pathlib.Path(root)
    st = root.lstat()
    if not stat.S_ISDIR(st.st_mode) or root.is_symlink():
        raise ValueError("ordinary root directory required")
    root_meta = {
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": stat.S_IMODE(st.st_mode),
        "xattrs": sorted(os.listxattr(root, follow_symlinks=False)),
    }
    entries = []
    total = 0

    def visit(directory):
        nonlocal total
        for path in sorted(directory.iterdir()):
            if len(entries) >= MAX_FILES:
                raise ValueError("inventory entry limit")
            item_stat = path.lstat()
            mode = item_stat.st_mode
            if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
                raise ValueError("symlink or special file denied")
            if item_stat.st_dev != st.st_dev:
                raise ValueError("nested mount denied")
            digest = None
            if stat.S_ISREG(mode):
                if item_stat.st_nlink != 1 or item_stat.st_size > MAX_BYTES - total:
                    raise ValueError("hardlink or byte limit")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as stream:
                    actual = os.fstat(stream.fileno())
                    if (actual.st_dev, actual.st_ino) != (
                        item_stat.st_dev,
                        item_stat.st_ino,
                    ):
                        raise ValueError("file changed during inspection")
                    data = stream.read(MAX_BYTES - total + 1)
                    if len(data) != item_stat.st_size:
                        raise ValueError("file size changed or limit exceeded")
                    digest = hashlib.sha256(data).hexdigest()
                    total += len(data)
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "kind": "file" if stat.S_ISREG(mode) else "directory",
                    "mode": stat.S_IMODE(mode),
                    "uid": item_stat.st_uid,
                    "gid": item_stat.st_gid,
                    "nlink": item_stat.st_nlink,
                    "xattrs": sorted(os.listxattr(path, follow_symlinks=False)),
                    "sha256": digest,
                }
            )
            if stat.S_ISDIR(mode):
                visit(path)

    visit(root)
    return root_meta, entries


def prepare(root, native_entries, blobs):
    """Input is host-derived validated native tree, never package archive/JSON.

    root must be the sole fixed managed volume, empty, root-owned. Fixed setup
    requires root plus CHOWN only, no package tool or shell. No extraction used.
    """
    root = pathlib.Path(root)
    root_st = root.lstat()
    if os.geteuid() != 0 or not stat.S_ISDIR(root_st.st_mode) or root_st.st_uid != 0:
        raise ValueError("trusted root setup required")
    if list(root.iterdir()) or os.listxattr(root, follow_symlinks=False):
        raise ValueError("new empty volume required")
    total = 0
    if len(native_entries) + len(OUTPUT_FILES) + len(OUTPUT_DIRS) > MAX_FILES:
        raise ValueError("entry bound")
    for name in sorted(
        native_entries, key=lambda n: (len(pathlib.PurePosixPath(n).parts), n)
    ):
        item = native_entries[name]
        path = pathlib.PurePosixPath(name)
        if (
            path.is_absolute()
            or str(path) != name
            or any(p in {"..", ".", ".git"} for p in path.parts)
        ):
            raise ValueError("invalid native path")
        if name in OUTPUT_FILES | OUTPUT_DIRS or any(
            name.startswith(d + "/") for d in OUTPUT_DIRS
        ):
            raise ValueError("output collision")
        destination = root / name
        if item["kind"] == "directory" and item["mode"] == 0o555:
            destination.mkdir(mode=0o700)
        elif item["kind"] == "file" and item["mode"] in {0o444, 0o555}:
            data = blobs[name]
            total += len(data)
            if total > MAX_BYTES or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("native blob bytes differ or exceed bound")
            fd = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            destination.chmod(item["mode"])
        else:
            raise ValueError("unsupported source entry")
    for name in sorted(OUTPUT_FILES):
        path = root / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        path.chmod(0o600)
        os.chown(path, 10001, 10001, follow_symlinks=False)
    for name in sorted(OUTPUT_DIRS):
        path = root / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        os.chown(path, 10001, 10001, follow_symlinks=False)
    for name in sorted(
        native_entries, key=lambda n: len(pathlib.PurePosixPath(n).parts), reverse=True
    ):
        if native_entries[name]["kind"] == "directory":
            (root / name).chmod(0o555)
    root.chmod(0o555)
