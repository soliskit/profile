"""Trusted always-run READ-ONLY reconciliation after timeout/cancel/HOLD.

Never relaunch, pull, start, remove or repair. An absent observation never erases
an earlier armed operation or HOLD. Caller verifies this source and executor pins.
"""

import json
import re


def reconcile(journal_root, executor):
    volumes = set()
    containers = set()
    records = sorted(journal_root.glob("owned-*.json"))
    if len(records) > 128:
        raise ValueError("journal bound")
    for path in records:
        if path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError("journal route or size differs")
        record = json.loads(path.read_bytes())
        if record["kind"] == "volume-create-armed":
            if not re.fullmatch(r"credit-volume-[0-9a-f]{32}", record["name"]):
                raise ValueError("unbound volume name")
            volumes.add(record["name"])
        elif record["kind"] == "container-create-armed":
            if not re.fullmatch(
                r"credit-(prepare|inspect)-[0-9a-f]{32}", record["name"]
            ):
                raise ValueError("unbound container name")
            containers.add(record["name"])
        elif record["kind"] != "removal-armed":
            raise ValueError("unexpected journal type")
    outcomes = []
    for name in sorted(containers):
        try:
            result = executor(
                ["docker", "ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"]
            )
            outcomes.append(
                {"kind": "container", "name": name, "present": bool(result.strip())}
            )
        except Exception as error:
            outcomes.append(
                {"kind": "container", "name": name, "error_type": type(error).__name__}
            )
    for name in sorted(volumes):
        try:
            result = executor(
                ["docker", "volume", "ls", "--quiet", "--filter", "name=^" + name + "$"]
            )
            outcomes.append(
                {"kind": "volume", "name": name, "present": bool(result.strip())}
            )
        except Exception as error:
            outcomes.append(
                {"kind": "volume", "name": name, "error_type": type(error).__name__}
            )
    return {
        "status": "HOLD",
        "scope": "read-only reconciliation, original ambiguity retained",
        "resources": outcomes,
    }


def reconcile_namespaces(parent, executor):
    """Fixed host-private namespaces only; absence of journals is unknown."""
    import pathlib

    parent = pathlib.Path(parent)
    if not parent.is_absolute() or parent.resolve(strict=True) != parent:
        raise ValueError("canonical trusted parent required")
    outcomes = []
    for name in ("pull-private-evidence", "volume-private-evidence"):
        root = parent / name
        if not root.is_dir() or root.is_symlink() or root.resolve(strict=True) != root:
            outcomes.append({"namespace": name, "status": "observation-unavailable"})
        elif not list(root.glob("owned-*.json")):
            outcomes.append(
                {"namespace": name, "status": "no-owned-journal-not-proof-of-no-create"}
            )
        else:
            outcomes.append(
                {"namespace": name, "observation": reconcile(root, executor)}
            )
    return {"status": "HOLD", "namespaces": outcomes}
