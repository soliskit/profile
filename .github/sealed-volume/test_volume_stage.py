"""Local inspector tests. No root preparation or container proof."""

import hashlib
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import volume_stage as target


class InspectorTests(unittest.TestCase):
    def test_real_files_and_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "src").mkdir()
            (root / "src" / "a.py").write_bytes(b"fixed bytes")
            metadata, entries = target.inspect(root)
            self.assertEqual(metadata["uid"], os.getuid())
            self.assertEqual([x["path"] for x in entries], ["src", "src/a.py"])
            self.assertEqual(
                entries[1]["sha256"], hashlib.sha256(b"fixed bytes").hexdigest()
            )
            self.assertEqual(entries[1]["nlink"], 1)
            self.assertIn("xattrs", entries[1])

    def test_symlink_and_hardlink_reject(self):
        for kind in ["symlink", "hardlink"]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                (root / "source").write_bytes(b"x")
                if kind == "symlink":
                    (root / "alias").symlink_to(root / "source")
                else:
                    os.link(root / "source", root / "alias")
                with self.assertRaises(ValueError):
                    target.inspect(root)

    def test_root_symlink_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "real").mkdir()
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaises(ValueError):
                target.inspect(root / "alias")

    def test_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "a").write_bytes(b"12")
            with patch.object(target, "MAX_BYTES", 1), self.assertRaises(ValueError):
                target.inspect(root)
            with patch.object(target, "MAX_FILES", 0), self.assertRaises(ValueError):
                target.inspect(root)

    def test_root_preparation_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(target.os, "geteuid", return_value=10001),
                self.assertRaises(ValueError),
            ):
                target.prepare(pathlib.Path(directory), {}, {})


if __name__ == "__main__":
    unittest.main()
