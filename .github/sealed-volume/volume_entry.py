"""Source-only authenticated foreground entrypoint. Not yet workflow-wired."""

import hashlib
import importlib.abc
import pathlib
import types

BUDGET_SHA = "bcd9d0fe283e3e32a5d75764bbf7cbe1557d88f4c0d6f5e621f3033f82313d48"
LAUNCH_SHA = "65b08e94b8e33083b8b0be3519a56741fe12274275726163ca17a9b2d28e177f"


class Loader(importlib.abc.InspectLoader):
    def __init__(self, raw, path):
        self.raw, self.path = raw, str(path)

    def get_source(self, fullname):
        return self.raw.decode()

    def get_code(self, fullname):
        return compile(self.raw, self.path, "exec")


def verified(path, expected):
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError("canonical ordinary source required")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("independently pinned source differs")
    module = types.ModuleType("fixed_" + path.stem)
    module.__file__ = str(path)
    Loader(raw, path).exec_module(module)
    return module


class EntryCleanupHold(RuntimeError):
    def __init__(self, primary_error, cleanup_error):
        super().__init__("entry and signal restoration failed; HOLD")
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


def run_entry(budget, operation):
    primary = None
    try:
        budget.arm()
        return operation(budget)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            budget.close()
        except BaseException as cleanup_error:
            if primary is not None:
                raise EntryCleanupHold(primary, cleanup_error) from primary
            raise


def entry(source, repo, parent):
    source = pathlib.Path(source)
    budget_module = verified(source / "shared_budget.py", BUDGET_SHA)
    budget = budget_module.Budget()

    def operation(shared):
        launcher = verified(source / "volume_launch.py", LAUNCH_SHA)
        return launcher.launch(source, repo, parent, budget=shared)

    return run_entry(budget, operation)
