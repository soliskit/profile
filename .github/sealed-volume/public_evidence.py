"""Bounded synthetic qualification evidence allowlist and recursive digest manifest."""

import hashlib
import json
import os
import pathlib
import re
import stat

MAX_TOTAL = 240 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_COUNT = 4096
VOLUME = r"credit-volume-[0-9a-f]{32}"
CONTAINER = r"credit-(prepare|inspect)-[0-9a-f]{32}"


def ordinary(path, limit=MAX_FILE):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("bounded ordinary evidence required")
    return path.read_bytes()


class Writer:
    def __init__(self, root):
        self.root = root
        if root.is_symlink() or not root.is_dir() or list(root.iterdir()):
            raise ValueError("new ordinary empty bundle required")
        self.total = 0
        self.files = {}

    def write(self, relative, raw):
        parts = pathlib.PurePosixPath(relative)
        if (
            parts.is_absolute()
            or str(parts) != relative
            or any(
                not re.fullmatch(r"[a-zA-Z0-9_.-]+", p) or p in {".", ".."}
                for p in parts.parts
            )
        ):
            raise ValueError("fixed relative output route required")
        if (
            len(raw) > MAX_FILE
            or len(self.files) >= MAX_COUNT
            or self.total + len(raw) > MAX_TOTAL
        ):
            raise ValueError("bundle count/file/aggregate bound")
        if relative in self.files:
            raise ValueError("duplicate bundle output")
        target = self.root / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(
            target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.total += len(raw)
        self.files[relative] = hashlib.sha256(raw).hexdigest()

    def record(self, name, record):
        self.write(name, json.dumps(record, sort_keys=True).encode())

    def finish(self):
        self.record("SHA256.json", dict(self.files))
        verify(self.root)


def verify(root):
    manifest = json.loads(ordinary(root / "SHA256.json"))
    if (
        type(manifest) is not dict
        or len(manifest) >= MAX_COUNT
        or "SHA256.json" in manifest
    ):
        raise ValueError("manifest schema/count differs")
    files = {}
    total = 0
    count = 0
    for path in root.rglob("*"):
        info = path.lstat()
        count += 1
        if count > MAX_COUNT * 2:
            raise ValueError("bundle entry count bound")
        if stat.S_ISDIR(info.st_mode):
            continue
        raw = ordinary(path)
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError("bundle aggregate bound")
        name = path.relative_to(root).as_posix()
        if name != "SHA256.json":
            files[name] = hashlib.sha256(raw).hexdigest()
    if files != manifest:
        raise ValueError("recursive exact file/digest set differs")
    return files


def journal_records(root):
    volumes, names, records = set(), set(), []
    for path in sorted(root.glob("owned-[0-9][0-9][0-9][0-9].json")):
        value = json.loads(ordinary(path, 65536))
        kind = value.get("kind")
        if kind in {"volume-create-armed", "container-create-armed"}:
            pattern = VOLUME if kind == "volume-create-armed" else CONTAINER
            if set(value) != {"kind", "name"} or not re.fullmatch(
                pattern, value["name"]
            ):
                raise ValueError("owned journal identity differs")
            (volumes if kind == "volume-create-armed" else names).add(value["name"])
        elif kind != "removal-armed" or set(value) != {"kind", "argv"}:
            raise ValueError("journal schema differs")
        records.append((path.name, value))
    if len(volumes) > 1 or len(names) > 2:
        raise ValueError("owned journal resource count differs")
    for _, value in records:
        if (
            value["kind"] == "removal-armed"
            and value["argv"] not in (["docker", "rm", "--force", n] for n in names)
            and value["argv"] not in (["docker", "volume", "rm", v] for v in volumes)
        ):
            raise ValueError("removal journal outside owned resources")
    return volumes, names, records


def validate_args(args, volumes, names, policy):
    if type(args) is not list or any(type(a) is not str or "\0" in a for a in args):
        raise ValueError("ordinary fixed argv required")
    fixed = [["docker", "image", "inspect", policy["image"]], policy["pull"]]
    for volume in volumes:
        fixed += [
            ["docker", "volume", "create", "--driver", "local", volume],
            ["docker", "volume", "inspect", volume],
            ["docker", "volume", "rm", volume],
            ["docker", "volume", "ls", "--quiet", "--filter", "name=^" + volume + "$"],
            ["docker", "ps", "--all", "--quiet", "--filter", "volume=" + volume],
        ]
    for name in names:
        fixed += [
            ["docker", "inspect", name],
            ["docker", "start", "--attach", "--interactive", name],
            ["docker", "rm", "--force", name],
            ["docker", "ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"],
        ]
        for volume in volumes:
            role = "prepare" if name.startswith("credit-prepare-") else "inspect"
            fixed.append(policy["create"](name, volume, role, policy[role]))
    if args in fixed:
        return "owned"
    if args == ["docker", "ps", "--all", "--quiet", "--no-trunc"]:
        return "digest-only"
    if (
        args[:2] == ["docker", "inspect"]
        and len(args) > 2
        and all(re.fullmatch(r"[0-9a-f]{64}", a) for a in args[2:])
    ):
        return "digest-only"
    raise ValueError("argv outside exact owned qualification scope")


def build(parent, output, source_pins, policy=None, initial=None):
    writer = Writer(output)
    for name, value in (initial or {}).items():
        if name not in {"summary.json", "image.json", "tools.json"}:
            raise ValueError("initial schema name differs")
        writer.record(name, value)
    selected = []
    for name in ("launch-closeout.json", "foreground.json", "reconciliation.json"):
        path = parent / name
        if path.exists():
            value = json.loads(ordinary(path))
            if name == "launch-closeout.json":
                value = {k: value.get(k) for k in ("status", "acquisition")}
            writer.record(name, value)
            selected.append(name)
    closeout = parent / "volume-private-evidence/closeout.json"
    if closeout.exists():
        value = json.loads(ordinary(closeout))
        writer.record(
            "volume-observation.json",
            {k: value.get(k) for k in ("status", "home_removed", "observation")},
        )
    all_volumes, all_names = set(), set()
    roots = []
    for namespace in (
        "pull-private-evidence",
        "volume-private-evidence",
        "reconcile-private-evidence",
    ):
        root = parent / namespace
        if not root.exists():
            continue
        if (
            root.is_symlink()
            or not root.is_dir()
            or sum(1 for _ in root.iterdir()) > MAX_COUNT
        ):
            raise ValueError("ordinary bounded evidence namespace required")
        volumes, names, records = journal_records(root)
        all_volumes.update(volumes)
        all_names.update(names)
        roots.append((namespace, root, records))
    for namespace, root, records in roots:
        for filename, value in records:
            writer.record(namespace + "/" + filename, value)
        for path in sorted(root.glob("[0-9][0-9][0-9][0-9]-invocation.json")):
            if policy is None:
                raise ValueError("authenticated exact argv policy required")
            record = json.loads(ordinary(path, 2 * 1024 * 1024))
            required = {
                "argv",
                "argv_sha256",
                "stdin_sha256",
                "stdin_bytes",
                "binary_sha256",
                "environment",
                "timeout_seconds",
            }
            if set(record) != required:
                raise ValueError("invocation schema differs")
            home = (
                "/nonexistent"
                if namespace == "reconcile-private-evidence"
                else str(
                    parent
                    / (
                        "pull-empty-home"
                        if namespace == "pull-private-evidence"
                        else "volume-empty-home"
                    )
                )
            )
            if record["environment"] != {
                "PATH": "/usr/bin:/bin",
                "HOME": home,
                "LANG": "C.UTF-8",
            }:
                raise ValueError("invocation environment differs")
            args = record["argv"]
            if (
                record["argv_sha256"]
                != hashlib.sha256(json.dumps(args).encode()).hexdigest()
                or not re.fullmatch(r"[0-9a-f]{64}", record["stdin_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", record["binary_sha256"])
                or type(record["stdin_bytes"]) is not int
                or not 0 <= record["stdin_bytes"] <= 32 * 1024 * 1024
                or type(record["timeout_seconds"]) is not int
                or not 1 <= record["timeout_seconds"] <= 180
            ):
                raise ValueError("invocation digest/bounds differ")
            scope = validate_args(args, all_volumes, all_names, policy)
            prefix = path.name[:4]
            suffixes = (
                ("result.json",)
                if scope == "digest-only"
                else ("invocation.json", "stdout.bin", "stderr.bin", "result.json")
            )
            for suffix in suffixes:
                item = root / (prefix + "-" + suffix)
                if item.exists():
                    writer.write(
                        namespace + "/" + item.name, ordinary(item, 2 * 1024 * 1024)
                    )
    # Explicit fixed provisioning streams, never arbitrary parent files.
    for number in (0, 1):
        for suffix in ("stdout.bin", "stderr.bin", "result.json"):
            name = "provision-" + str(number) + "-" + suffix
            path = parent / name
            if path.exists():
                writer.write(name, ordinary(path, 1024 * 1024))
    writer.record(
        "source-bindings.json",
        {
            "source_sha256": source_pins,
            "artifact_policy": "owned synthetic qualification evidence only; no arbitrary host data or local tracebacks",
        },
    )
    manifest = dict(writer.files)
    writer.finish()
    return manifest, selected
