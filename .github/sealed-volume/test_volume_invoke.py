"""Mocked caller accountability, no real engine."""

import json
import pathlib
import tempfile
import types
import unittest

import volume_driver
import volume_invoke as target


class CallerTests(unittest.TestCase):
    def run_case(self, work=None, home=False, constructor=False, preexisting=False):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            if preexisting:
                (parent / "volume-empty-home").mkdir()

            class Executor:
                def __init__(self, binary, pin, evidence, env):
                    if constructor:
                        raise ValueError("constructor")
                    evidence.mkdir()

                def save(self, path, data):
                    path.write_bytes(data)

            def qualify(*args):
                if home:
                    (parent / "volume-empty-home" / "unexpected").write_text("data")
                if work:
                    raise work
                return {"fixed": True}

            modules = {
                "bounded_executor": types.SimpleNamespace(Executor=Executor),
                "volume_driver": types.SimpleNamespace(
                    qualify=qualify, WorkCleanupHold=volume_driver.WorkCleanupHold
                ),
                "volume_lifecycle": None,
                "source_contract": None,
            }
            caught = None
            try:
                target.run_accountable(
                    modules, {"volume_stage.py": b""}, None, parent, None, None
                )
            except BaseException as error:
                caught = error
            closeout = parent / "volume-private-evidence" / "closeout.json"
            if not closeout.exists():
                closeout = parent / "volume-setup-HOLD.json"
            record = json.loads(closeout.read_text())
            self.assertEqual(record["status"], "PASS" if caught is None else "HOLD")
            self.assertFalse(
                (
                    parent / "volume-private-evidence" / "prepared-observation.json"
                ).exists()
            )
            return caught, record

    def test_success(self):
        error, record = self.run_case()
        self.assertIsNone(error)
        self.assertTrue(record["home_removed"])

    def test_work_only(self):
        error, record = self.run_case(ValueError("work"))
        self.assertIsInstance(error, ValueError)
        self.assertEqual(record["errors"]["type"], "ValueError")

    def test_nested_work_and_cleanup(self):
        work = volume_driver.WorkCleanupHold(
            ValueError("work"), RuntimeError("resource")
        )
        error, record = self.run_case(work, home=True)
        self.assertIsInstance(error, volume_driver.WorkCleanupHold)
        self.assertEqual(record["errors"]["primary"]["primary"]["type"], "ValueError")
        self.assertEqual(record["errors"]["primary"]["cleanup"]["type"], "RuntimeError")
        self.assertEqual(record["errors"]["cleanup"]["type"], "RuntimeError")

    def test_home_only(self):
        error, record = self.run_case(home=True)
        self.assertIsInstance(error, RuntimeError)
        self.assertFalse(record["home_removed"])

    def test_constructor_and_existing_home(self):
        for constructor, preexisting in [(True, False), (False, True)]:
            with self.subTest(constructor=constructor):
                error, record = self.run_case(
                    constructor=constructor, preexisting=preexisting
                )
                self.assertIsNotNone(error)
                self.assertEqual(record["status"], "HOLD")


if __name__ == "__main__":
    unittest.main()
