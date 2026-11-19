"""Acquisition ownership failure tests, never download/install/execute Docker."""

import pathlib
import tempfile
import unittest
from unittest.mock import patch

import volume_launch as target


class LaunchTests(unittest.TestCase):
    def test_owned_write_and_preexisting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "binary"
            target.write_owned(path, b"fixed")
            with self.assertRaises(FileExistsError):
                target.write_owned(path, b"other")
            self.assertEqual(path.read_bytes(), b"fixed")

    def test_fsync_failure_removes_only_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "binary"
            with (
                patch.object(target.os, "fsync", side_effect=OSError("fsync")),
                self.assertRaises(OSError),
            ):
                target.write_owned(path, b"fixed")
            self.assertFalse(path.exists())

    def test_primary_and_unlink_failure_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "binary"
            with (
                patch.object(target.os, "fsync", side_effect=OSError("fsync")),
                patch.object(
                    pathlib.Path, "unlink", side_effect=PermissionError("unlink")
                ),
            ):
                with self.assertRaises(target.AcquisitionCleanupHold) as raised:
                    target.write_owned(path, b"fixed")
            self.assertIsInstance(raised.exception.primary_error, OSError)
            self.assertIsInstance(raised.exception.cleanup_error, PermissionError)
            self.assertIs(raised.exception.__cause__, raised.exception.primary_error)
            self.assertTrue(path.exists())
            path.unlink()


if __name__ == "__main__":
    unittest.main()
