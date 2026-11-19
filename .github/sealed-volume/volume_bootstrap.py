"""Fixed same-buffer loader. Caller authenticates this loader and literal pins.

No manifest loaded from candidate files. No execute/qualify call on import.
"""

import hashlib
import importlib.abc
import sys
import types
from pathlib import Path

FILES = {
    "source_contract.py",
    "volume_stage.py",
    "volume_lifecycle.py",
    "volume_driver.py",
    "bounded_executor.py",
}


class BufferLoader(importlib.abc.InspectLoader):
    def __init__(self, source, path):
        self.source = source
        self.path = str(path)

    def get_source(self, fullname):
        return self.source.decode("utf-8", "strict")

    def get_code(self, fullname):
        return compile(self.source, self.path, "exec")


def load(root, expected):
    root = Path(root)
    if (
        not root.is_absolute()
        or root.resolve(strict=True) != root
        or set(expected) != FILES
    ):
        raise ValueError("canonical exact trusted packet required")
    buffers = {}
    for name in sorted(FILES):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("ordinary source file required")
        source = path.read_bytes()
        if (
            len(source) > 1024 * 1024
            or hashlib.sha256(source).hexdigest() != expected[name]
        ):
            raise ValueError("source differs from independent pin")
        buffers[name] = source
    modules = {}
    previous = {}
    try:
        for name in sorted(FILES):
            key = name.removesuffix(".py")
            previous[key] = sys.modules.get(key)
            module = types.ModuleType(key)
            module.__file__ = str(root / name)
            modules[key] = module
            sys.modules[key] = module
        for name in sorted(FILES):
            key = name.removesuffix(".py")
            BufferLoader(buffers[name], root / name).exec_module(modules[key])
    finally:
        for key, old in previous.items():
            if old is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = old
    return modules, buffers
