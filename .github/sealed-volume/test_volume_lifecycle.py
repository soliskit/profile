"""Lifecycle planning/ambiguity tests, no actual Docker calls."""

import json
import subprocess
import unittest

import volume_lifecycle as target


class LifecycleTests(unittest.TestCase):
    def test_fixed_isolated_argv(self):
        volume = "credit-volume-" + "a" * 32
        for role, user in [("prepare", "0:0"), ("inspect", "10001:10001")]:
            args = target.create_args("fixture", volume, role, "fixed")
            self.assertEqual(args[args.index("--user") + 1], user)
            self.assertEqual(args[-4:], ["-I", "-S", "-c", "fixed"])
            self.assertEqual("--cap-add" in args, role == "prepare")
            self.assertEqual(
                ",readonly" in args[args.index("--mount") + 1], role == "inspect"
            )

    def test_ambiguous_volume_create_is_armed(self):
        calls = []

        def command(args, **kwargs):
            calls.append(args)
            if args[1:3] == ["image", "inspect"]:
                return json.dumps(
                    [{"Id": target.CONFIG_ID, "Architecture": "amd64", "Os": "linux"}]
                ).encode()
            if args[1:3] == ["volume", "create"]:
                raise subprocess.TimeoutExpired(args, 1)
            return b""

        life = target.Lifecycle(command)
        with self.assertRaises(subprocess.TimeoutExpired):
            life.create_volume()
        self.assertTrue(life.volume_armed)
        life.cleanup()
        self.assertIn(["docker", "volume", "rm", life.volume], calls)

    def test_concurrent_consumer_holds(self):
        life = target.Lifecycle(lambda args: b"othercontainer")
        with self.assertRaises(ValueError):
            life.no_consumers()

    def test_completed_state_requires_real_execution(self):
        state = {
            "Status": "exited",
            "Running": False,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "ExitCode": 0,
            "Error": "",
            "StartedAt": "2026-11-18T00:00:00Z",
            "FinishedAt": "2026-11-18T00:00:01Z",
        }
        target.completed_state(state)
        for key, value in [
            ("Status", "created"),
            ("Status", "dead"),
            ("StartedAt", "0001-01-01T00:00:00Z"),
            ("FinishedAt", "2026-11-17T00:00:00Z"),
            ("StartedAt", "invalid"),
            ("ExitCode", False),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                target.completed_state(dict(state, **{key: value}))

    def test_security_options_reject_false_or_malformed(self):
        for options in [
            ["no-new-privileges=false"],
            ["no-new-privileges=garbage"],
            ["no-new-privileges=true", "no-new-privileges=false"],
            [],
        ]:
            item = {
                "Name": "/fixture",
                "Config": {
                    "Image": target.IMAGE,
                    "User": "10001:10001",
                    "WorkingDir": "/",
                    "Entrypoint": ["/usr/local/bin/python3"],
                    "Cmd": ["-I", "-S", "-c", "fixed"],
                },
                "HostConfig": {
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "CapDrop": ["ALL"],
                    "CapAdd": [],
                    "NetworkMode": "none",
                    "PidMode": "",
                    "IpcMode": "private",
                    "SecurityOpt": options,
                },
            }
            with self.subTest(options=options), self.assertRaises(ValueError):
                target.config_check(item, "fixture", "owned", "inspect", "fixed")

    def test_cleanup_removal_failure_still_reads_absence(self):
        for failure in [subprocess.TimeoutExpired("fixed", 1), OSError("evidence")]:
            calls = []

            def command(args, calls=calls, failure=failure, **kwargs):
                calls.append(args)
                if args[1] == "rm" or args[1:3] == ["volume", "rm"]:
                    raise failure
                return b""

            life = target.Lifecycle(command)
            life.names.extend(["owned-first", "owned-second"])
            life.volume_armed = True
            life.mountpoint = "/fixed/owned"
            with (
                self.subTest(failure=type(failure).__name__),
                self.assertRaises(RuntimeError),
            ):
                life.cleanup()
            for name in life.names:
                self.assertIn(
                    [
                        "docker",
                        "ps",
                        "--all",
                        "--quiet",
                        "--filter",
                        "name=^/" + name + "$",
                    ],
                    calls,
                )
            self.assertEqual(sum(c[:3] == ["docker", "volume", "rm"] for c in calls), 1)
            self.assertEqual(sum(c[:3] == ["docker", "volume", "ls"] for c in calls), 2)
            before = len(
                [c for c in calls if c[1] == "rm" or c[1:3] == ["volume", "rm"]]
            )
            with self.assertRaises(RuntimeError):
                life.cleanup()
            self.assertEqual(
                len([c for c in calls if c[1] == "rm" or c[1:3] == ["volume", "rm"]]),
                before,
            )

    def test_mountinfo(self):
        target.mountinfo_only_work(b"100 99 1:1 / /work ro - ext4 /dev/fixed rw\n")
        for data in [
            b"",
            b"100 99 1:1 / /work rw - ext4 /dev/fixed rw\n",
            b"100 99 1:1 / /work ro - ext4 /dev/fixed rw\n101 100 2:1 / /work/sub ro - tmpfs tmpfs ro\n",
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                target.mountinfo_only_work(data)


if __name__ == "__main__":
    unittest.main()
