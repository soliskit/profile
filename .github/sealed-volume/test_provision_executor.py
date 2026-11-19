"""Local fake CLI/process-group cases. No sudo, network, engine or CI."""

import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import provision_executor as target


class Budget:
    def __init__(self, seconds=2):
        self.end = time.monotonic() + seconds

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fixture deadline")
        return remaining

    def cleanup(self):
        self.end = time.monotonic() + 2


class ProvisionTests(unittest.TestCase):
    def test_spawn_failure_retained_with_raw_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            records = []
            with patch.object(
                target.subprocess, "Popen", side_effect=ValueError("spawn")
            ):
                with self.assertRaises(ValueError):
                    target.run(
                        ["fixed"],
                        pathlib.Path(name) / "p",
                        {},
                        Budget(),
                        lambda p, v: records.append(v),
                    )
            self.assertEqual(records[-1]["failure_type"], "ValueError")
            self.assertEqual(records[-1]["stdout_bytes"], 0)

    def test_primary_survives_save_failure(self):
        with tempfile.TemporaryDirectory() as name:
            calls = []

            def save(path, value):
                calls.append(path)
                if len(calls) > 1:
                    raise OSError("save")

            with patch.object(
                target.subprocess, "Popen", side_effect=ValueError("primary")
            ):
                with self.assertRaises(target.ProvisionHold) as caught:
                    target.run(["fixed"], pathlib.Path(name) / "p", {}, Budget(), save)
            self.assertIsInstance(caught.exception.primary_error, ValueError)
            self.assertIsInstance(caught.exception.cleanup_errors[-1], OSError)

    def run_fake(self, code, seconds=2):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            records = []
            error = None
            try:
                target.run(
                    [sys.executable, "-I", "-S", "-c", code],
                    root / "p",
                    {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                    Budget(seconds),
                    lambda p, v: records.append(v),
                )
            except BaseException as caught:
                error = caught
            streams = [
                (root / ("p-" + label + ".bin")).read_bytes()
                for label in ("stdout", "stderr")
            ]
            return error, records, streams

    def test_real_fake_cli_success(self):
        error, records, streams = self.run_fake("print('synthetic')")
        self.assertIsNone(error)
        self.assertEqual(streams[0], b"synthetic\n")
        self.assertEqual(records[-1]["returncode"], 0)

    def test_real_overflow_bounded(self):
        error, records, streams = self.run_fake(
            "import os\nwhile True: os.write(1,b'x'*65536)"
        )
        self.assertIsInstance(error, RuntimeError)
        self.assertLessEqual(len(streams[0]), target.MAX_STREAM)
        self.assertIsNotNone(records[-1]["failure_type"])

    def test_real_timeout(self):
        error, records, _streams = self.run_fake("import time;time.sleep(10)", 0.1)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(records[-1]["failure_type"], "TimeoutError")

    def test_real_leader_exit_descendant_is_hold_and_killed(self):
        code = "import os,time\npid=os.fork()\nif pid: os._exit(0)\nos.write(1,(str(os.getpid())+'\\n').encode())\ntime.sleep(10)"
        start = time.monotonic()
        error, records, streams = self.run_fake(code)
        self.assertIsInstance(error, RuntimeError)
        self.assertLess(time.monotonic() - start, 2)
        child = int(streams[0].strip())
        state = pathlib.Path("/proc") / str(child) / "stat"
        # A killed orphan can remain a zombie until the host's init reaps it.
        if state.exists():
            self.assertEqual(state.read_text().split()[2], "Z")
        self.assertIsNotNone(records[-1]["failure_type"])


if __name__ == "__main__":
    unittest.main()
