"""Source-only qualification launcher. No implicit execution on import.

Independent review authenticates this file. The runner supplies exact fixed routes.
No package, shell, inherited credential environment or general command RPC.
"""

import hashlib
import importlib.abc
import io
import json
import os
import pathlib
import tarfile
import time
import types
import urllib.request

CALLER_SHA = "ea55006633284940479663fabea80ca24a991a945583767d4f6d45c4a90179ac"
ARCHIVE_URL = (
    "https://download.docker.com/linux/static/stable/x86_64/docker-cli_29.10.0.tgz"
)
ARCHIVE_SHA = "94e8261e6e566c719973a81b22906d7b0a2655440b83fca0ea9c26215437541a"
BINARY_SHA = "df7684b939d373a90a6bc4e8b8a2a1f131831fa260aff1afc0a01a1fa3f44171"
IMAGE = "python@sha256:1faf2343e747208b2a36e5f2b5ff908ec3b2d0078a6a7bfe73b535698fe83909"


class Loader(importlib.abc.InspectLoader):
    def __init__(self, data, path):
        self.data, self.path = data, str(path)

    def get_source(self, fullname):
        return self.data.decode()

    def get_code(self, fullname):
        return compile(self.data, self.path, "exec")


class AcquisitionCleanupHold(RuntimeError):
    def __init__(self, primary_error, cleanup_error):
        super().__init__("acquisition and owned-file cleanup failed; HOLD")
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


def write_owned(destination, data):
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
    )
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException as error:
        try:
            pathlib.Path(destination).unlink()
        except BaseException as cleanup_error:
            raise AcquisitionCleanupHold(error, cleanup_error) from error
        raise


def acquire_cli(destination, budget=None):
    """Bounded official archive, no extraction or observed-derived trust pin."""
    started = time.monotonic()
    with urllib.request.urlopen(
        ARCHIVE_URL, timeout=min(30, budget.remaining()) if budget is not None else 30
    ) as response:
        if response.geturl() != ARCHIVE_URL:
            raise ValueError("unexpected acquisition redirect")
        blob = response.read(16 * 1024 * 1024 + 1)
    if time.monotonic() - started > 60:
        raise RuntimeError("acquisition deadline exceeded; HOLD")
    if len(blob) > 16 * 1024 * 1024 or hashlib.sha256(blob).hexdigest() != ARCHIVE_SHA:
        raise ValueError("official archive differs from independent pin")
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = archive.getmembers()
        selected = [m for m in members if m.name == "bin/docker"]
        if len(selected) != 1:
            raise ValueError("exact CLI member missing/duplicate")
        item = selected[0]
        if (
            not item.isfile()
            or item.linkname
            or item.size != 34627657
            or item.mode != 0o755
        ):
            raise ValueError("CLI member type/size/mode differs")
        stream = archive.extractfile(item)
        data = stream.read(34627658)
    if len(data) != 34627657 or hashlib.sha256(data).hexdigest() != BINARY_SHA:
        raise ValueError("CLI bytes differ")
    write_owned(destination, data)
    return {
        "archive_sha256": ARCHIVE_SHA,
        "binary_sha256": BINARY_SHA,
        "member": "bin/docker",
    }


def launch(source, repo, parent, budget):
    """Called in exact allowlist environment from FIRST child process start."""
    if dict(os.environ) != {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}:
        raise ValueError("exact initial environment required")
    source, repo, parent = map(pathlib.Path, (source, repo, parent))
    for path in (source, repo, parent):
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("canonical trusted routes required")
    raw = (source / "volume_invoke.py").read_bytes()
    if hashlib.sha256(raw).hexdigest() != CALLER_SHA:
        raise ValueError("caller differs from independent pin")
    caller = types.ModuleType("fixed_volume_caller")
    caller.__file__ = str(source / "volume_invoke.py")
    Loader(raw, caller.__file__).exec_module(caller)
    bootstrap_raw = (source / "volume_bootstrap.py").read_bytes()
    if hashlib.sha256(bootstrap_raw).hexdigest() != caller.BOOTSTRAP:
        raise ValueError("bootstrap differs")
    bootstrap = types.ModuleType("fixed_launch_bootstrap")
    bootstrap.__file__ = str(source / "volume_bootstrap.py")
    Loader(bootstrap_raw, bootstrap.__file__).exec_module(bootstrap)
    modules, _ = bootstrap.load(source, caller.PINS)
    return orchestrate(caller, modules, source, repo, parent, budget=budget)


def orchestrate(caller, modules, source, repo, parent, budget=None):
    binary = parent / "fixed-docker-cli"
    pull_home = parent / "pull-empty-home"
    binary_owned = False
    home_owned = False
    failure = None
    acquired = None
    evidence = None
    try:
        acquired = acquire_cli(
            binary, **({"budget": budget} if budget is not None else {})
        )
        binary_owned = True
        pull_home.mkdir(mode=0o700)
        home_owned = True
        executor = modules["bounded_executor"].Executor(
            binary,
            BINARY_SHA,
            parent / "pull-private-evidence",
            {"PATH": "/usr/bin:/bin", "HOME": str(pull_home), "LANG": "C.UTF-8"},
            **({"budget": budget} if budget is not None else {}),
        )
        executor.pull_fixed_image_once()
        if (executor.root / f"{executor.sequence - 1:04d}-stderr.bin").read_bytes():
            raise RuntimeError("unexpected fixed pull stderr retained; HOLD")
        evidence = caller.invoke(
            source,
            repo,
            parent,
            binary,
            BINARY_SHA,
            **({"budget": budget} if budget is not None else {}),
        )
    except BaseException as error:
        failure = error
    finally:
        for path, owned, directory in [
            (pull_home, home_owned, True),
            (binary, binary_owned, False),
        ]:
            if owned:
                try:
                    if budget is not None:
                        budget.cleanup()
                    if directory:
                        if list(path.iterdir()):
                            raise RuntimeError(
                                "unexpected pull HOME contents retained; HOLD"
                            )
                        path.rmdir()
                    else:
                        path.unlink()
                except BaseException as cleanup_error:
                    failure = (
                        modules["volume_driver"].WorkCleanupHold(failure, cleanup_error)
                        if failure is not None
                        else cleanup_error
                    )
    record = {
        "status": "PASS" if failure is None else "HOLD",
        "errors": None if failure is None else caller.error_record(failure),
        "acquisition": acquired,
        "caller_evidence": None if evidence is None else str(evidence),
    }
    try:
        fd = os.open(
            parent / "launch-closeout.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(json.dumps(record, sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException as save_error:
        if failure is not None:
            raise modules["volume_driver"].WorkCleanupHold(
                failure, save_error
            ) from failure
        raise
    if failure is not None:
        raise failure
    return evidence


def foreground_python(*args):
    """Disabled unsafe hard-timeout helper. Use reviewed entrypoint in foreground.

    It must have a cooperative normal deadline, bounded cleanup budget and separate
    always-run read-only reconciliation. This helper cannot kill past finally.
    """
    raise RuntimeError("hard outer-timeout launch route unsupported; HOLD")
