"""Source-only wiring of trusted native data to fixed disposable volume stages.

No CLI or package-facing entrypoint. No runtime executor supplied here. The caller
must verify this module and all executable buffers against independent pins.
"""

import hashlib
import json
import pathlib
import subprocess


class WorkCleanupHold(RuntimeError):
    """Both original exceptions retain typed values and traceback objects."""

    def __init__(self, primary_error, cleanup_error):
        super().__init__("work and cleanup failed; HOLD")
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error
        self.primary_traceback = primary_error.__traceback__
        self.cleanup_traceback = cleanup_error.__traceback__


MAX_DATA = 32 * 1024 * 1024
MAX_OBJECTS = 10000
MAX_DEPTH = 64


def protected_native(repo):
    import stat

    repo = pathlib.Path(repo)
    if not repo.is_absolute() or repo.resolve(strict=True) != repo:
        raise ValueError("canonical protected native repo required")
    for path in (repo, *repo.parents):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("protected native owner/ancestor required")
    gitdir = repo / ".git"
    paths = [gitdir, *gitdir.rglob("*")]
    if len(paths) > 20000:
        raise ValueError("native file count bound")
    for path in paths:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError("native object aliases unsupported")
        info = path.stat()
        if (
            info.st_uid != 0
            or info.st_mode & 0o022
            or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
        ):
            raise ValueError("protected native entry required")
    config = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
    if (gitdir / "config").read_bytes() != config:
        raise ValueError("native exact config differs")
    if (gitdir / "objects/info/alternates").exists() or (
        gitdir / "info/grafts"
    ).exists():
        raise ValueError("native external object route unsupported")


def native_input(repo, root_oid, contract, budget=None):
    """Host Git plumbing only, no hooks/package binaries/config-selected commands."""
    if len(root_oid) != 40 or any(c not in "0123456789abcdef" for c in root_oid):
        raise ValueError("authenticated native tree OID required")

    protected_native(repo)

    def git(*args):
        return subprocess.run(
            [
                "/usr/bin/git",
                "--no-replace-objects",
                "-c",
                "safe.directory=" + str(repo),
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.pager=cat",
                "-c",
                "gc.auto=0",
                "-C",
                str(repo),
                *args,
            ],
            cwd="/",
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "HOME": "/nonexistent",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
            },
            check=True,
            capture_output=True,
            timeout=min(30, budget.remaining()) if budget is not None else 30,
        ).stdout

    # fsck is read-only. A malformed native store is HOLD, not repair authority.
    git("fsck", "--strict", "--no-reflogs", root_oid)
    ids = (
        git("rev-list", "--objects", "--no-object-names", root_oid)
        .decode()
        .splitlines()
    )
    if len(ids) > MAX_OBJECTS or git("cat-file", "-t", root_oid) != b"tree\n":
        raise ValueError("native object count/type limit")
    objects = {}
    total = 0
    for oid in ids:
        kind = git("cat-file", "-t", oid).decode().strip()
        size = int(git("cat-file", "-s", oid))
        if size < 0 or size > MAX_DATA - total:
            raise ValueError("native data bound")
        data = git("cat-file", kind, oid)
        if len(data) != size:
            raise ValueError("native size changed")
        total += size
        objects[oid] = (kind, data)
    paths = git("ls-tree", "-r", "-t", "--name-only", "-z", root_oid).split(b"\0")
    if len(paths) > MAX_OBJECTS + 1 or any(
        p.count(b"/") + 1 > MAX_DEPTH for p in paths if p
    ):
        raise ValueError("native path count/depth bound")
    entries = contract.native_inventory(root_oid, objects)
    if any(len(pathlib.PurePosixPath(n).parts) > MAX_DEPTH for n in entries):
        raise ValueError("native path depth bound")
    blobs = {}
    for name, item in entries.items():
        if item["kind"] == "file":
            data = git("show", root_oid + ":" + name)
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("native blob lookup differs")
            blobs[name] = data.hex()
    wire = json.dumps(
        {"entries": entries, "blobs": blobs}, separators=(",", ":")
    ).encode()
    if len(wire) > MAX_DATA:
        raise ValueError("encoded preparation input bound")
    return objects, wire


def fixed_code(stage_buffer, expected_stage_sha256):
    if hashlib.sha256(stage_buffer).hexdigest() != expected_stage_sha256:
        raise ValueError("stage source differs from independent review")
    source = stage_buffer.decode("utf-8", "strict")
    prefix = "import os,sys,json\nos.umask(0o077)\nassert sys.flags.isolated and sys.flags.no_site\n"
    prepare = (
        prefix
        + source
        + "\nvalue=json.load(sys.stdin)\nprepare('/work',value['entries'],{k:bytes.fromhex(v) for k,v in value['blobs'].items()})\n"
    )
    inspector = (
        prefix
        + source
        + "\nroot,entries=inspect('/work')\nprint(json.dumps({'root':root,'entries':entries,'mountinfo':pathlib.Path('/proc/self/mountinfo').read_text()}))\n"
    )
    return prepare, inspector


def qualify(
    executor,
    lifecycle_module,
    contract,
    repo,
    root_oid,
    stage_buffer,
    expected_stage_sha256,
    budget=None,
):
    """No package execution. Always cleanup, failures never converted into PASS.

    Executor must retain all actual argv/config/status/bounded raw output and
    serialize this exclusive owned volume against any other management action.
    Host mount aliases/concurrent clients remain an external controlplane premise.
    """
    objects, wire = native_input(
        repo, root_oid, contract, **({"budget": budget} if budget is not None else {})
    )
    prepare, inspector = fixed_code(stage_buffer, expected_stage_sha256)
    life = lifecycle_module.Lifecycle(executor)
    executor.bind_cleanup(life.volume, life.names)
    life.cleanup_command = executor.cleanup_command
    primary = None
    try:
        life.create_volume()
        life.stage("prepare", prepare, data=wire)
        output = life.stage("inspect", inspector)
        if len(output) > MAX_DATA:
            raise ValueError("inspector evidence bound")
        observed = json.loads(output)
        if set(observed) != {"root", "entries", "mountinfo"}:
            raise ValueError("inspector schema differs")
        lifecycle_module.mountinfo_only_work(observed["mountinfo"].encode())
        contract.validate_contract(
            root_oid, objects, observed["entries"], observed["root"]
        )
        return {
            "inspection": observed,
            "native_binding": {
                "root_tree": root_oid,
                "inventory": contract.native_inventory(root_oid, objects),
                "objects": {
                    oid: {
                        "kind": kind,
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                    for oid, (kind, raw) in objects.items()
                },
                "stage_sha256": expected_stage_sha256,
                "prepare_code_sha256": hashlib.sha256(prepare.encode()).hexdigest(),
                "inspect_code_sha256": hashlib.sha256(inspector.encode()).hexdigest(),
                "input_sha256": hashlib.sha256(wire).hexdigest(),
                "input_bytes": len(wire),
            },
        }
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if budget is not None:
                budget.cleanup()
            life.cleanup()
        except BaseException as cleanup_error:
            if primary is not None:
                raise WorkCleanupHold(primary, cleanup_error) from primary
            else:
                raise
