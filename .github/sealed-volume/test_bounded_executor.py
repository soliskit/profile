"""Disposable subprocess fixtures, no Docker engine invocation."""

import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import bounded_executor as target


class ExecutorTests(unittest.TestCase):
    def fixture(self, directory, source):
        root = pathlib.Path(directory)
        binary = root / "fixed-cli"
        binary.write_text("#!/usr/bin/python3\n" + source)
        binary.chmod(0o700)
        return target.Executor(
            binary,
            hashlib.sha256(binary.read_bytes()).hexdigest(),
            root / "evidence",
            {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8"},
        )

    def test_streams_and_stdin_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(
                directory,
                "import sys\ndata=sys.stdin.buffer.read()\nsys.stdout.buffer.write(data)\nsys.stderr.buffer.write(b'raw-error')\n",
            )
            self.assertEqual(
                executor(["docker", "version"], data=b"fixed-input"), b"fixed-input"
            )
            self.assertEqual(
                (executor.root / "0000-stderr.bin").read_bytes(), b"raw-error"
            )
            self.assertTrue((executor.root / "0000-result.json").is_file())

    def test_oversize_and_nonzero_hold(self):
        for source in [
            "import sys\nsys.stdout.buffer.write(b'x'*2048)\n",
            "raise SystemExit(3)\n",
        ]:
            with (
                self.subTest(source=source),
                tempfile.TemporaryDirectory() as directory,
            ):
                executor = self.fixture(directory, source)
                with (
                    patch.object(target, "MAX_STREAM", 1024),
                    self.assertRaises(target.ExecutionHold),
                ):
                    executor(["docker", "version"])
                self.assertLessEqual(
                    (executor.root / "0000-stdout.bin").stat().st_size, 1024
                )

    def test_timeout_kills_and_waits(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "import time\ntime.sleep(20)\n")
            with self.assertRaises(target.ExecutionHold):
                executor(["docker", "version"], timeout=1)
            self.assertIn(
                b'"returncode": -9', (executor.root / "0000-result.json").read_bytes()
            )

    def test_cleanup_reserve_and_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            executor.bind_cleanup("owned-volume", ["owned-container"])
            executor.saved = target.MAX_ARTIFACT
            with self.assertRaises(target.ExecutionHold):
                executor(["docker", "version"])
            executor.cleanup_command(["docker", "rm", "--force", "owned-container"])
            with self.assertRaises(ValueError):
                executor.cleanup_command(
                    ["docker", "rm", "--force", "foreign-container"]
                )
            executor.cleanup_calls = 64
            with self.assertRaises(target.ExecutionHold):
                executor.cleanup_command(["docker", "rm", "--force", "owned-container"])

    def test_failed_final_wait_still_saves_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            real_wait = target.subprocess.Popen.wait

            def wait(child, timeout=None):
                if timeout == 10:
                    raise target.subprocess.TimeoutExpired("fixed", timeout)
                return real_wait(child, timeout=timeout)

            with (
                patch.object(target.subprocess.Popen, "wait", wait),
                self.assertRaises(target.ExecutionHold),
            ):
                executor(["docker", "version"])
            self.assertTrue((executor.root / "0000-stdout.bin").is_file())
            self.assertIn(
                b"TimeoutExpired", (executor.root / "0000-result.json").read_bytes()
            )

    def test_disk_failure_does_not_suppress_cleanup_command(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "ran"
            executor = self.fixture(
                directory,
                "from pathlib import Path\nPath("
                + repr(str(marker))
                + ").write_text('ran')\n",
            )
            executor.bind_cleanup("owned-volume", ["owned-container"])
            with (
                patch.object(executor, "save", side_effect=OSError("disk")),
                self.assertRaises(target.ExecutionHold),
            ):
                executor.cleanup_command(["docker", "rm", "--force", "owned-container"])
            self.assertTrue(marker.is_file())

    def test_fixed_pull_once_not_general_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            with self.assertRaises(ValueError):
                executor(list(target.FIXED_PULL))
            executor.pull_fixed_image_once()
            self.assertTrue((executor.root / "fixed-pull-attempt.json").exists())
            with self.assertRaises(target.ExecutionHold):
                executor.pull_fixed_image_once()

    def test_fixed_pull_failure_not_resent(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "raise SystemExit(2)\n")
            with self.assertRaises(target.ExecutionHold):
                executor.pull_fixed_image_once()
            with self.assertRaises(target.ExecutionHold):
                executor.pull_fixed_image_once()
            self.assertEqual(executor.sequence, 1)

    def test_whole_normal_deadline_preserves_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            executor.bind_cleanup("owned-volume", ["owned-container"])
            executor.normal_deadline = 0
            with self.assertRaises(target.ExecutionHold):
                executor(["docker", "version"])
            executor.cleanup_command(["docker", "rm", "--force", "owned-container"])
            executor.cleanup_deadline = 0
            with self.assertRaises(target.ExecutionHold):
                executor.cleanup_command(["docker", "rm", "--force", "owned-container"])

    def test_shared_cleanup_only_on_failure(self):
        class Budget:
            def __init__(self):
                self.cleaning = False

            def remaining(self):
                return 60

            def cleanup(self):
                self.cleaning = True

        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            executor.budget = Budget()
            executor(["docker", "version"])
            self.assertFalse(executor.budget.cleaning)
            executor.binary.write_text("#!/usr/bin/python3\nraise SystemExit(3)\n")
            executor.binary_sha256 = hashlib.sha256(
                executor.binary.read_bytes()
            ).hexdigest()
            with self.assertRaises(target.ExecutionHold):
                executor(["docker", "version"])
            self.assertTrue(executor.budget.cleaning)

    def test_invalid_operation_and_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = self.fixture(directory, "pass\n")
            with self.assertRaises(ValueError):
                executor(["docker", "run", "anything"])
            executor.binary.write_text("changed")
            with self.assertRaises(target.ExecutionHold):
                executor(["docker", "version"])


if __name__ == "__main__":
    unittest.main()
