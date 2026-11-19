"""Host-only native derivation and fixed interpreter wiring cases."""

import hashlib
import pathlib
import unittest
from unittest.mock import patch

import source_contract
import volume_driver as target


class DriverTests(unittest.TestCase):
    def test_fixed_code_and_hash_drift(self):
        source = pathlib.Path(__file__).with_name("volume_stage.py").read_bytes()
        digest = hashlib.sha256(source).hexdigest()
        prep, inspect = target.fixed_code(source, digest)
        self.assertTrue(prep.startswith("import os,sys,json\nos.umask(0o077)"))
        self.assertIn("/proc/self/mountinfo", inspect)
        compile(prep, "fixed-prepare", "exec")
        compile(inspect, "fixed-inspect", "exec")
        with self.assertRaises(ValueError):
            target.fixed_code(source + b"# drift", digest)

    def test_primary_error_survives_cleanup_failure(self):
        class Life:
            def __init__(self, executor):
                self.volume = "owned"
                self.names = []

            def create_volume(self):
                raise ValueError("primary fixture HOLD")

            def cleanup(self):
                raise RuntimeError("cleanup HOLD")

        class Executor:
            def bind_cleanup(self, volume, names):
                pass

            def cleanup_command(self):
                pass

        class Module:
            Lifecycle = Life

        with (
            patch.object(target, "native_input", return_value=({}, b"{}")),
            patch.object(target, "fixed_code", return_value=("prep", "inspect")),
        ):
            with self.assertRaises(target.WorkCleanupHold) as raised:
                target.qualify(Executor(), Module, None, None, "", b"", "")
        self.assertIsInstance(raised.exception.primary_error, ValueError)
        self.assertIsInstance(raised.exception.cleanup_error, RuntimeError)
        self.assertEqual(str(raised.exception.primary_error), "primary fixture HOLD")
        self.assertIs(raised.exception.__cause__, raised.exception.primary_error)
        self.assertIsNotNone(raised.exception.primary_traceback)
        self.assertIsNotNone(raised.exception.cleanup_traceback)

    def test_single_failure_paths(self):
        for work_fails in [True, False]:

            class Life:
                def __init__(self, executor):
                    self.volume = "owned"
                    self.names = []

                def create_volume(self, work_fails=work_fails):
                    if work_fails:
                        raise ValueError("work only")

                def stage(self, role, code, data=None):
                    return b'{"root":{},"entries":[],"mountinfo":""}'

                def cleanup(self, work_fails=work_fails):
                    if not work_fails:
                        raise RuntimeError("cleanup only")

            class Executor:
                def bind_cleanup(self, volume, names):
                    pass

                def cleanup_command(self):
                    pass

            class Module:
                Lifecycle = Life

                @staticmethod
                def mountinfo_only_work(data):
                    pass

            class Contract:
                @staticmethod
                def validate_contract(*args):
                    pass

                @staticmethod
                def native_inventory(*args):
                    return {}

            with (
                patch.object(target, "native_input", return_value=({}, b"{}")),
                patch.object(target, "fixed_code", return_value=("prep", "inspect")),
            ):
                with (
                    self.subTest(work_fails=work_fails),
                    self.assertRaises(
                        ValueError if work_fails else RuntimeError
                    ) as raised,
                ):
                    target.qualify(Executor(), Module, Contract, None, "", b"", "")
                self.assertNotIsInstance(raised.exception, target.WorkCleanupHold)

    def test_actual_native_tree_rejects_unprotected_local_fixture(self):
        repo = pathlib.Path("/tmp/prevention-inert-profile/candidate")
        if not repo.is_dir():
            self.skipTest("actual prepared profile evidence not present")
        with self.assertRaisesRegex(ValueError, "protected native"):
            target.native_input(
                repo, "2aeba6cd12f8e546e91ded37b93fca5fbd5dc245", source_contract
            )


if __name__ == "__main__":
    unittest.main()
