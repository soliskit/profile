"""FINAL CALLER PROPOSAL, no automatic entrypoint or workflow activation.

Invoke only after independent review authenticates this caller and supplied Docker
binary hash. Git repository/tree/source and evidence destination are fixed here.
"""

import hashlib
import importlib.abc
import json
import os
import pathlib
import traceback
import types

ROOT_TREE = "2aeba6cd12f8e546e91ded37b93fca5fbd5dc245"
PINS = {
    "source_contract.py": "5c8b0b330df7e3ddf6438981f089f3a67a678a685ebf0cf182cf53ddcb1f7ec5",
    "volume_stage.py": "924ad90eaf362eb355d481d4870155f0d3d4abad06131f9a6c86e430ad8552f2",
    "volume_lifecycle.py": "336cfe0fea52ceb94fda6d73dd1397113cbd0f840f6af9aebcdc778cafe013cd",
    "volume_driver.py": "7ef9851f90e594c160aa1dd3e8e131e18d58931edfd7e8ceb89084c7d3a9bf2b",
    "bounded_executor.py": "388ba2f4cb4113230ec1bb9532c2a777dd7bb57453d221db441c67dbdf8e4280",
}
BOOTSTRAP = "d751b9126ad7b9eae0bdc186200383534339e685db45a063bae63e45ce831446"


class Loader(importlib.abc.InspectLoader):
    def __init__(self, source, path):
        self.source = source
        self.path = str(path)

    def get_source(self, fullname):
        return self.source.decode()

    def get_code(self, fullname):
        return compile(self.source, self.path, "exec")


def error_record(error):
    record = {
        "type": type(error).__name__,
        "traceback": "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        ),
    }
    if hasattr(error, "primary_error") and hasattr(error, "cleanup_error"):
        record["primary"] = error_record(error.primary_error)
        record["cleanup"] = error_record(error.cleanup_error)
    return record


def run_accountable(
    modules, buffers, repo, parent, docker_binary, expected_docker_sha256, budget=None
):
    home = parent / "volume-empty-home"
    evidence = parent / "volume-private-evidence"
    executor = None
    home_created = False
    failure = None
    result = None
    try:
        home.mkdir(mode=0o700)
        home_created = True
        executor = modules["bounded_executor"].Executor(
            docker_binary,
            expected_docker_sha256,
            evidence,
            {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"},
            **({"budget": budget} if budget is not None else {}),
        )

        class ExpectedStderr:
            def __call__(self, args, **kwargs):
                value = executor(args, **kwargs)
                if (evidence / f"{executor.sequence - 1:04d}-stderr.bin").read_bytes():
                    raise RuntimeError("unexpected raw stderr retained; HOLD")
                return value

            def bind_cleanup(self, volume, names):
                executor.bind_cleanup(volume, names)

            def cleanup_command(self, args, **kwargs):
                value = executor.cleanup_command(args, **kwargs)
                if (evidence / f"{executor.sequence - 1:04d}-stderr.bin").read_bytes():
                    raise RuntimeError("unexpected cleanup stderr retained; HOLD")
                return value

        result = modules["volume_driver"].qualify(
            ExpectedStderr(),
            modules["volume_lifecycle"],
            modules["source_contract"],
            repo,
            ROOT_TREE,
            buffers["volume_stage.py"],
            PINS["volume_stage.py"],
            **({"budget": budget} if budget is not None else {}),
        )
    except BaseException as error:
        failure = error
    finally:
        if home_created:
            try:
                if budget is not None:
                    budget.cleanup()
                if list(home.iterdir()):
                    raise RuntimeError("unexpected HOME contents retained; HOLD")
                home.rmdir()
            except BaseException as home_error:
                failure = (
                    modules["volume_driver"].WorkCleanupHold(failure, home_error)
                    if failure is not None
                    else home_error
                )
    record = {
        "status": "HOLD" if failure is not None else "PASS",
        "errors": None if failure is None else error_record(failure),
        "observation": result,
        "home_removed": home_created and not home.exists(),
    }
    try:
        payload = json.dumps(record, sort_keys=True).encode()
        if executor is not None:
            executor.save(evidence / "closeout.json", payload)
        else:
            fd = os.open(
                parent / "volume-setup-HOLD.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
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


def invoke(source, repo, parent, docker_binary, expected_docker_sha256, budget=None):
    """Foreground, credentialfree trusted runner only. No package code.

    Exact argument routes and Docker hash are still pending external independent
    review. No deriving expected hash from actual binary inside this call.
    parent is fresh private runner temp, not checkout/package-selected output.
    """
    source, repo, parent = map(pathlib.Path, (source, repo, parent))
    for path in (source, repo, parent):
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("canonical trusted route required")
    if any(
        k.startswith(("GIT_", "GITHUB_", "ACTIONS_", "CREDIT_")) or k == "EMAIL"
        for k in os.environ
    ):
        raise ValueError("credential/routing environment not cleared before caller")
    # Actual workflow may have these variables. Launcher must supply only a fixed
    # allowlist, not strip credentials after this check and claim they never existed.
    bootstrap_path = source / "volume_bootstrap.py"
    raw = bootstrap_path.read_bytes()
    if bootstrap_path.is_symlink() or hashlib.sha256(raw).hexdigest() != BOOTSTRAP:
        raise ValueError("independently pinned bootstrap differs")
    module = types.ModuleType("fixed_volume_bootstrap")
    module.__file__ = str(bootstrap_path)
    Loader(raw, bootstrap_path).exec_module(module)
    modules, buffers = module.load(source, PINS)
    return run_accountable(
        modules,
        buffers,
        repo,
        parent,
        docker_binary,
        expected_docker_sha256,
        budget=budget,
    )
