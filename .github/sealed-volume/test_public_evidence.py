"""Synthetic allowlist and recursive manifest unit cases, no external effects."""

import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import public_evidence as target


class EvidenceTests(unittest.TestCase):
    def test_excludes_unrelated_private_and_traceback(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            output = root / "public"
            output.mkdir()
            (root / "user-secret").write_text("secret")
            (root / "launch-closeout.json").write_text(
                json.dumps(
                    {
                        "status": "HOLD",
                        "errors": {"traceback": "private"},
                        "acquisition": None,
                    }
                )
            )
            manifest, selected = target.build(
                root, output, {"volume_stage.py": "a" * 64}
            )
            self.assertEqual(
                set(manifest), {"launch-closeout.json", "source-bindings.json"}
            )
            self.assertEqual(selected, ["launch-closeout.json"])
            self.assertNotIn("private", (output / "launch-closeout.json").read_text())
            self.assertFalse((output / "user-secret").exists())
            self.assertEqual(target.verify(output), manifest)

    def test_recursive_manifest_and_unlisted_file(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            writer = target.Writer(root)
            writer.write("owned/0000-stdout.bin", b"synthetic")
            writer.finish()
            self.assertEqual(set(target.verify(root)), {"owned/0000-stdout.bin"})
            (root / "extra").write_text("unexpected")
            with self.assertRaises(ValueError):
                target.verify(root)

    def test_every_write_accounts_aggregate(self):
        with tempfile.TemporaryDirectory() as name:
            writer = target.Writer(pathlib.Path(name))
            with patch.object(target, "MAX_TOTAL", 4):
                writer.record("a.json", 1)
                with self.assertRaises(ValueError):
                    writer.record("b.json", 12345)

    def test_links_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            first = root / "first"
            first.write_text("x")
            os.link(first, root / "hard")
            with self.assertRaises(ValueError):
                target.ordinary(first)
            (root / "soft").symlink_to(first)
            with self.assertRaises(ValueError):
                target.ordinary(root / "soft")

    def test_rejects_symlink_raw_namespace(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            out = root / "public"
            out.mkdir()
            (root / "pull-private-evidence").symlink_to(out, target_is_directory=True)
            with self.assertRaises(ValueError):
                target.build(root, out, {})

    def test_rejects_nonowned_argv(self):
        policy = {"image": "fixed", "pull": ["docker", "pull", "fixed"], "create": None}
        with self.assertRaises(ValueError):
            target.validate_args(
                ["docker", "inspect", "unrelated"], set(), set(), policy
            )
        with self.assertRaises(ValueError):
            target.validate_args(
                ["docker", "run", "credential-dump"], set(), set(), policy
            )


if __name__ == "__main__":
    unittest.main()
