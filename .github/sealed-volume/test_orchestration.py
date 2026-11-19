"""No real CLI acquisition or engine calls. Full launcher failure ordering."""

import json
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

import volume_driver
import volume_invoke
import volume_launch as target
import volume_reconcile


class OrchestrationTests(unittest.TestCase):
    def test_full_mock_success_and_failures(self):
        for mode in ["success", "pull", "caller", "home", "caller-home"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                parent = pathlib.Path(directory)
                calls = []

                class Executor:
                    def __init__(self, binary, pin, root, env):
                        self.root, self.sequence = root, 1
                        root.mkdir()

                    def pull_fixed_image_once(self, mode=mode, calls=calls):
                        calls.append("pull")
                        (self.root / "0000-stderr.bin").write_bytes(b"")
                        if mode == "pull":
                            raise ValueError("pull HOLD")

                def invoke(*args, mode=mode, calls=calls, parent=parent):
                    calls.append("caller")
                    if "home" in mode:
                        (parent / "pull-empty-home" / "unknown").write_text("data")
                    if mode in {"caller", "caller-home"}:
                        raise ValueError("caller HOLD")
                    return parent / "mock-caller-evidence"

                def acquire(path):
                    path.write_bytes(b"fake")
                    return {"fixed": True}

                caller = types.SimpleNamespace(
                    invoke=invoke, error_record=volume_invoke.error_record
                )
                modules = {
                    "bounded_executor": types.SimpleNamespace(Executor=Executor),
                    "volume_driver": volume_driver,
                }
                error = None
                with patch.object(target, "acquire_cli", acquire):
                    try:
                        target.orchestrate(caller, modules, None, None, parent)
                    except BaseException as caught:
                        error = caught
                record = json.loads((parent / "launch-closeout.json").read_text())
                self.assertEqual(
                    record["status"], "PASS" if mode == "success" else "HOLD"
                )
                self.assertEqual(error is None, mode == "success")
                self.assertFalse((parent / "fixed-docker-cli").exists())
                if mode == "pull":
                    self.assertNotIn("caller", calls)
                if mode == "caller-home":
                    self.assertIn("primary", record["errors"])
                    self.assertIn("cleanup", record["errors"])

    def test_reconcile_only_reads_and_remains_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            name = "credit-volume-" + "a" * 32
            (root / "owned-0000.json").write_text(
                json.dumps({"kind": "volume-create-armed", "name": name})
            )
            calls = []

            def read(args):
                calls.append(args)
                return b""

            result = volume_reconcile.reconcile(root, read)
            self.assertEqual(result["status"], "HOLD")
            self.assertFalse(result["resources"][0]["present"])
            self.assertEqual(calls[0][1:3], ["volume", "ls"])


if __name__ == "__main__":
    unittest.main()
