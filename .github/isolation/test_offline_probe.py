"""Local parser/config fixtures. These are not container isolation evidence."""

import copy
import io
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import offline_probe as target

SOURCE = b"fixed-host-generated-fixture"


def observation():
    return {
        "Config": {
            "User": "10001:10001",
            "Image": target.IMAGE,
            "Env": ["PATH=/usr/bin"],
            "Entrypoint": ["/usr/local/bin/node"],
            "Cmd": ["--eval", SOURCE.decode()],
        },
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "NetworkMode": "none",
            "PidMode": "",
            "IpcMode": "private",
            "Tmpfs": {"/tmp": "rw"},
            "Memory": 268435456,
            "PidsLimit": 64,
            "NanoCpus": 1000000000,
        },
        "Mounts": [],
    }


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as output:
        for name, kind, mode, blob in entries:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            entry.mode = mode
            entry.size = len(blob)
            if kind == tarfile.SYMTYPE:
                entry.linkname = "/host/token"
            output.addfile(entry, io.BytesIO(blob))
    return stream.getvalue()


class ParserTests(unittest.TestCase):
    def test_exact_regular_files(self):
        data = archive([("package.json", tarfile.REGTYPE, 0o644, b"{}")])
        self.assertEqual(
            target.validate_tar(data, {"package.json"}), {"package.json": b"{}"}
        )

    def test_bad_outputs(self):
        cases = [
            [("../package.json", tarfile.REGTYPE, 0o644, b"{}")],
            [("package.json", tarfile.SYMTYPE, 0o644, b"")],
            [("package.json", tarfile.FIFOTYPE, 0o644, b"")],
            [("package.json", tarfile.REGTYPE, 0o755, b"{}")],
            [(".git/config", tarfile.REGTYPE, 0o644, b"{}")],
            [
                ("package.json", tarfile.REGTYPE, 0o644, b"{}"),
                ("package.json", tarfile.REGTYPE, 0o644, b"{}"),
            ],
            [],
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                target.validate_tar(archive(case), {"package.json"})

    def test_exact_config(self):
        target.validate_observation(observation(), SOURCE)

    def test_bad_config(self):
        cases = [
            ("User", "0:0", "Config"),
            ("ReadonlyRootfs", False, "HostConfig"),
            ("Privileged", True, "HostConfig"),
            ("CapAdd", ["SYS_ADMIN"], "HostConfig"),
            ("CapDrop", [], "HostConfig"),
            ("SecurityOpt", [], "HostConfig"),
            ("NetworkMode", "host", "HostConfig"),
            ("PidMode", "host", "HostConfig"),
            ("IpcMode", "host", "HostConfig"),
            ("Binds", ["/host:/host"], "HostConfig"),
            ("GroupAdd", ["docker"], "HostConfig"),
            ("PidsLimit", 0, "HostConfig"),
            ("Image", "node:latest", "Config"),
            ("Entrypoint", ["/bin/sh", "-c"], "Config"),
            ("Cmd", ["--eval", "different"], "Config"),
            ("Cmd", ["--eval", SOURCE.decode(), "extra"], "Config"),
            ("Env", ["GITHUB_TOKEN=fixture-only"], "Config"),
        ]
        for key, value, section in cases:
            item = copy.deepcopy(observation())
            item[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                target.validate_observation(item, SOURCE)


class CommandEvidenceTests(unittest.TestCase):
    def test_command_failure_keeps_bounded_raw_data(self):
        result = subprocess.CompletedProcess(
            [], 125, b"out", b"x" * (target.MAX_OUTPUT + 1)
        )
        with patch.object(target.subprocess, "run", return_value=result):
            with self.assertRaises(target.CommandFailure) as raised:
                target.command(["docker", "create", "private-argv"])
        error = raised.exception
        self.assertEqual(error.operation, ["docker", "create"])
        self.assertEqual(error.returncode, 125)
        self.assertEqual(len(error.stderr), target.MAX_OUTPUT)
        self.assertTrue(error.truncated)
        self.assertNotIn("private-argv", str(error))


class CleanupTests(unittest.TestCase):
    def test_ambiguous_create_still_removes_exact_name(self):
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            if args[1] == "create":
                raise subprocess.TimeoutExpired(args, 1)
            if args[1] == "version":
                return subprocess.CompletedProcess(args, 0, b"{}", b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(target, "command", fake),
        ):
            evidence = pathlib.Path(directory) / "evidence"
            with self.assertRaises(subprocess.TimeoutExpired):
                target.run(evidence)
            creates = [c for c in calls if c[1] == "create"]
            self.assertEqual(len(creates), 1)
            name = creates[0][creates[0].index("--name") + 1]
            self.assertIn(["docker", "rm", "--force", name], calls)
            self.assertEqual(calls[-1][-1], "name=^/" + name + "$")
            self.assertEqual(
                creates[0][creates[0].index("--entrypoint") + 1],
                "/usr/local/bin/node",
            )
            self.assertEqual(creates[0][-2], "--eval")
            self.assertNotIn(["docker", "cp"], [call[:2] for call in calls])
            self.assertTrue((evidence / "command-failure.json").exists())
            self.assertTrue((evidence / "cleanup.json").exists())

    def test_cleanup_absence_and_failure_paths(self):
        cases = [
            (
                [
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 0, b"", b""),
                ],
                False,
            ),
            (
                [
                    subprocess.CompletedProcess([], 1, b"", b"missing"),
                    subprocess.CompletedProcess([], 0, b"", b""),
                ],
                False,
            ),
            (
                [
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 0, b"still-present", b""),
                ],
                True,
            ),
            (
                [
                    subprocess.TimeoutExpired("rm", 1),
                    subprocess.CompletedProcess([], 0, b"", b""),
                ],
                True,
            ),
            (
                [
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.TimeoutExpired("ps", 1),
                ],
                True,
            ),
        ]
        for responses, fails in cases:
            with (
                tempfile.TemporaryDirectory() as directory,
                patch.object(target, "command", side_effect=responses) as mocked,
            ):
                evidence = pathlib.Path(directory)
                if fails:
                    with self.assertRaises(RuntimeError):
                        target.reconcile_name("fixed-fixture-name", evidence)
                else:
                    self.assertTrue(
                        target.reconcile_name("fixed-fixture-name", evidence)
                    )
                self.assertEqual(mocked.call_count, 2)
                self.assertTrue((evidence / "cleanup.json").exists())


if __name__ == "__main__":
    unittest.main()
