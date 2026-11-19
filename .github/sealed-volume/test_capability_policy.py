"""Actual retained inspect fixture and exact capability policy regressions."""

import ast
import copy
import hashlib
import json
import pathlib
import unittest

import volume_lifecycle as target
import yaml

FIXTURES = pathlib.Path(__file__).with_name("capability-fixtures")


def fixture():
    item = json.loads((FIXTURES / "inspect.bin").read_bytes())[0]
    command = json.loads((FIXTURES / "create.bin").read_bytes())["argv"]
    volume = json.loads((FIXTURES / "volume.bin").read_bytes())[0]
    return item, command, volume


class CapabilityTests(unittest.TestCase):
    def check(self, item, role="prepare"):
        original, command, volume = fixture()
        target.config_check(
            item,
            original["Name"][1:],
            volume["Name"],
            role,
            command[-1],
            volume["Mountpoint"],
        )

    def test_actual_fixture_provenance_and_both_singleton_spellings(self):
        pins = json.loads((FIXTURES / "SHA256.json").read_text())
        for name, digest in pins.items():
            self.assertEqual(
                hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest(), digest
            )
        item, command, _ = fixture()
        self.assertEqual(command[command.index("--cap-add") + 1], "CHOWN")
        self.assertEqual(item["HostConfig"]["CapAdd"], ["CAP_CHOWN"])
        for value in (["CHOWN"], ["CAP_CHOWN"]):
            with self.subTest(value=value):
                changed = copy.deepcopy(item)
                changed["HostConfig"]["CapAdd"] = value
                self.check(changed)

    def test_prepare_rejects_extra_duplicate_alias_and_malformed_capabilities(self):
        item, _, _ = fixture()
        cases = [
            None,
            [],
            "CHOWN",
            {"CHOWN": True},
            [1],
            [None],
            [["CHOWN"]],
            ["CHOWN", "CHOWN"],
            ["CAP_CHOWN", "CAP_CHOWN"],
            ["CHOWN", "CAP_CHOWN"],
            ["CAP_CHOWN", "CHOWN"],
            ["CHOWN", "SYS_ADMIN"],
            ["CAP_CHOWN", "CAP_SYS_ADMIN"],
            ["SYS_ADMIN"],
            ["ALL"],
            ["CAP_ALL"],
            ["chown"],
            ["cap_chown"],
            [" CHOWN"],
            ["CHOWN "],
            ["CAP_CAP_CHOWN"],
            ["CAP_"],
            [""],
        ]
        for value in cases:
            changed = copy.deepcopy(item)
            changed["HostConfig"]["CapAdd"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(changed)

    def test_inspector_remains_no_capabilities(self):
        item, _, _ = fixture()
        item["Config"]["User"] = "10001:10001"
        item["Mounts"][0]["RW"] = False
        for value in (None, []):
            item["HostConfig"]["CapAdd"] = value
            self.check(item, "inspect")
        for value in (["CHOWN"], ["CAP_CHOWN"], ["ALL"], {}, "", False):
            item["HostConfig"]["CapAdd"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(item, "inspect")

    def test_drop_all_and_other_security_fields_remain_enforced(self):
        item, _, _ = fixture()
        mutations = [
            ("HostConfig", "CapDrop", None),
            ("HostConfig", "CapDrop", []),
            ("HostConfig", "CapDrop", ["CHOWN"]),
            ("HostConfig", "CapDrop", ["ALL", "CHOWN"]),
            ("HostConfig", "Privileged", True),
            ("HostConfig", "ReadonlyRootfs", False),
            ("HostConfig", "NetworkMode", "host"),
            ("HostConfig", "PidMode", "host"),
            ("HostConfig", "IpcMode", "host"),
            ("HostConfig", "SecurityOpt", ["no-new-privileges=false"]),
            ("HostConfig", "Devices", [{"PathOnHost": "/dev/fixture"}]),
            ("HostConfig", "Binds", ["/fixture:/work"]),
            ("HostConfig", "VolumesFrom", ["other"]),
            ("HostConfig", "GroupAdd", ["0"]),
            ("HostConfig", "Memory", 0),
            ("HostConfig", "PidsLimit", 0),
            ("HostConfig", "NanoCpus", 0),
            ("HostConfig", "Tmpfs", {}),
            ("Config", "User", "10001:10001"),
            ("Config", "Image", "untrusted"),
            ("Config", "WorkingDir", "/work"),
            ("Config", "Entrypoint", ["/bin/sh"]),
            ("Config", "Cmd", ["not-fixed"]),
            ("Config", "Env", ["UNTRUSTED=1"]),
        ]
        for section, key, value in mutations:
            changed = copy.deepcopy(item)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                self.check(changed)
        for key, value in [
            ("Type", "bind"),
            ("Name", "other"),
            ("Destination", "/other"),
            ("RW", False),
            ("Source", "/other"),
            ("Driver", "other"),
        ]:
            changed = copy.deepcopy(item)
            changed["Mounts"][0][key] = value
            with self.subTest(mount=key), self.assertRaises(ValueError):
                self.check(changed)

    def test_rejected_config_never_starts_and_cleanup_is_attempted(self):
        item, command, volume = fixture()
        item["HostConfig"]["CapAdd"] = ["CAP_CHOWN", "CAP_SYS_ADMIN"]
        calls = []

        def execute(args, **kwargs):
            calls.append(args)
            if args[1] == "inspect":
                return json.dumps([item]).encode()
            return b""

        life = target.Lifecycle(execute)
        life.volume = volume["Name"]
        life.mountpoint = volume["Mountpoint"]
        life.volume_armed = True
        # The fixture name must match the newly generated stage name.
        import unittest.mock

        fixed_uuid = item["Name"].rsplit("-", 1)[1]
        with unittest.mock.patch.object(
            target.uuid, "uuid4", return_value=type("U", (), {"hex": fixed_uuid})()
        ):
            with self.assertRaisesRegex(ValueError, "capability"):
                life.stage("prepare", command[-1])
        life.cleanup()
        self.assertFalse(any(args[1] == "start" for args in calls))
        self.assertTrue(any(args[1:3] == ["rm", "--force"] for args in calls))
        self.assertIn(["docker", "volume", "rm", volume["Name"]], calls)

    def test_full_source_pin_graph_and_wrapper_route_pins_match(self):
        root = pathlib.Path(__file__).parent
        for name in (
            "volume_invoke.py",
            "volume_launch.py",
            "volume_entry.py",
            "route_cli.py",
        ):
            tree = ast.parse((root / name).read_bytes())
            values = {}
            for node in tree.body:
                if (
                    isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                ):
                    try:
                        values[node.targets[0].id] = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        pass
            pins = values.get("PINS", values.get("SOURCE_PINS", {}))
            pins = dict(pins)
            for constant, target_name in [
                ("CALLER_SHA", "volume_invoke.py"),
                ("LAUNCH_SHA", "volume_launch.py"),
                ("ENTRY_SHA", "volume_entry.py"),
            ]:
                if constant in values:
                    pins[target_name] = values[constant]
            for target_name, expected in pins.items():
                self.assertEqual(
                    hashlib.sha256((root / target_name).read_bytes()).hexdigest(),
                    expected,
                )
        workflow = yaml.safe_load(
            (root.parent / "workflows/sealed-volume-qualification.yml").read_text()
        )
        steps = workflow["jobs"]["qualify"]["steps"]
        for step in steps:
            if step.get("id") == "bootstrap":
                tree = ast.parse(
                    step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
                )
                pins = ast.literal_eval(
                    next(
                        node.value
                        for node in tree.body
                        if isinstance(node, ast.Assign)
                        and any(
                            isinstance(t, ast.Name) and t.id == "pins"
                            for t in node.targets
                        )
                    )
                )
                for name, expected in pins.items():
                    self.assertEqual(
                        hashlib.sha256((root / name).read_bytes()).hexdigest(), expected
                    )
            if step.get("id") in {"foreground", "reconcile", "bundle"}:
                self.assertIn(
                    hashlib.sha256((root / "route_cli.py").read_bytes()).hexdigest(),
                    step["run"],
                )


if __name__ == "__main__":
    unittest.main()
