"""Strict native-tree preparation contract. No runtime or filesystem proof."""

import hashlib
import re
from pathlib import PurePosixPath

PACKAGE_UID = 10001
PACKAGE_GID = 10001
OUTPUT_FILES = frozenset({"next-env.d.ts", "tsconfig.tsbuildinfo"})
OUTPUT_DIRS = frozenset({".next", "out", "test-results", "playwright-report"})
EMPTY = hashlib.sha256(b"").hexdigest()
FIELDS = {"path", "kind", "mode", "uid", "gid", "nlink", "xattrs", "sha256"}


def path_name(value):
    if type(value) is not str or not value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or str(path) != value
        or any(p in {".", ".."} for p in path.parts)
        or value == "."
    ):
        raise ValueError("noncanonical path")
    return path


def native_inventory(root_oid, objects):
    """Root OID comes from independently reviewed native tree, not package data.

    Objects are complete raw Git (type, bytes) pairs. Rehash every object against
    its OID before parsing; never execute or extract data. Only regular source
    files/directories supported. Internal .git metadata needs a separate sealed
    index contract, it is not smuggled into the native source tree.
    """
    if type(objects) is not dict:
        raise ValueError("object map required")
    result = {}
    active = set()

    def visit(oid, prefix, wanted):
        if type(oid) is not str or not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise ValueError("invalid object ID")
        kind, data = objects[oid]
        if type(data) is not bytes or kind != wanted:
            raise ValueError("object type differs")
        if (
            hashlib.sha1(
                kind.encode() + b" " + str(len(data)).encode() + b"\0" + data
            ).hexdigest()
            != oid
        ):
            raise ValueError("native object hash differs")
        if oid in active:
            raise ValueError("recursive tree")
        if kind == "blob":
            return hashlib.sha256(data).hexdigest()
        active.add(oid)
        offset = 0
        while offset < len(data):
            stop = data.index(b"\0", offset)
            mode, raw_name = data[offset:stop].split(b" ", 1)
            name = raw_name.decode("utf-8", "strict")
            if "/" in name or name == ".git":
                raise ValueError("invalid native component")
            path = prefix + name
            path_name(path)
            if path in result or mode not in {b"40000", b"100644", b"100755"}:
                raise ValueError("duplicate or unsupported native entry")
            raw_oid = data[stop + 1 : stop + 21]
            if len(raw_oid) != 20:
                raise ValueError("truncated native entry")
            offset = stop + 21
            directory = mode == b"40000"
            result[path] = {
                "kind": "directory" if directory else "file",
                "mode": 0o555 if directory or mode == b"100755" else 0o444,
                "sha256": None,
            }
            digest = visit(
                raw_oid.hex(),
                path + "/" if directory else "",
                "tree" if directory else "blob",
            )
            if not directory:
                result[path]["sha256"] = digest
        active.remove(oid)
        return None

    visit(root_oid, "", "tree")
    return result


def validate_contract(root_oid, objects, observed_entries, root_metadata):
    if root_metadata != {"uid": 0, "gid": 0, "mode": 0o555, "xattrs": []} or any(
        type(root_metadata[k]) is not int for k in ("uid", "gid", "mode")
    ):
        raise ValueError("work root not sealed")
    expected = native_inventory(root_oid, objects)
    for name in expected:
        if name in OUTPUT_FILES | OUTPUT_DIRS or any(
            name.startswith(d + "/") for d in OUTPUT_DIRS
        ):
            raise ValueError("source/output conflict")
    observed = {}
    for item in observed_entries:
        if type(item) is not dict or set(item) != FIELDS:
            raise ValueError("complete exact metadata required")
        name = item["path"]
        path_name(name)
        if name in observed or item["kind"] not in {"file", "directory"}:
            raise ValueError("duplicate or special entry")
        if any(
            type(item[k]) is not int or item[k] < 0
            for k in ("mode", "uid", "gid", "nlink")
        ):
            raise ValueError("invalid numeric metadata")
        if type(item["xattrs"]) is not list or item["xattrs"]:
            raise ValueError("extended metadata denied")
        if item["kind"] == "file":
            if (
                item["nlink"] != 1
                or type(item["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            ):
                raise ValueError("invalid file hash or link count")
        elif item["sha256"] is not None or item["nlink"] < 1:
            raise ValueError("invalid directory metadata")
        observed[name] = item
    if set(observed) != set(expected) | OUTPUT_FILES | OUTPUT_DIRS:
        raise ValueError("incomplete or additional inventory")
    for name, item in observed.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) == ".":
                continue
            if (
                str(parent) not in observed
                or observed[str(parent)]["kind"] != "directory"
            ):
                raise ValueError("directory ancestry missing")
        output = name in OUTPUT_FILES | OUTPUT_DIRS
        wanted = (
            {"kind": "file", "mode": 0o600, "sha256": EMPTY}
            if name in OUTPUT_FILES
            else {"kind": "directory", "mode": 0o700, "sha256": None}
            if name in OUTPUT_DIRS
            else expected[name]
        )
        if any(item[k] != wanted[k] for k in ("kind", "mode", "sha256")):
            raise ValueError("source bytes or mode differ")
        uid = PACKAGE_UID if output else 0
        gid = PACKAGE_GID if output else 0
        if item["uid"] != uid or item["gid"] != gid:
            raise ValueError("ownership differs")
    return True
