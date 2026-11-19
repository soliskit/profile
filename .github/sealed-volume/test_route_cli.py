"""Deployment route and public bundle unit cases. No network or daemon."""

import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import route_cli as target


class RouteTests(unittest.TestCase):
    def test_unresolved_pin_fails_before_read(self):
        with self.assertRaisesRegex(ValueError, "unresolved"):
            target.verified_file(pathlib.Path("/nonexistent"), None)

    def test_argv_cannot_select_other_routes(self):
        for argv in ([], ["remove"], ["qualify", "/tmp/untrusted"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                target.main(argv)

    def test_source_same_buffer_not_reread(self):
        with tempfile.TemporaryDirectory() as name:
            path = pathlib.Path(name) / "source.py"
            path.write_text("value = 2")
            module = target.load_buffer(b"value = 1", path)
            self.assertEqual(module.value, 1)

    def test_fixed_failure_no_exception_or_external_detail(self):
        self.assertEqual(
            target.fixed_failure(),
            {"status": "HOLD", "classification": "route_failure"},
        )

    def test_metadata_missing_job_links_fails(self):
        with self.assertRaises(ValueError):
            target.image_metadata(b"[]")
        with self.assertRaises(ValueError):
            target.image_metadata(
                json.dumps(
                    [{"group": "Runner Image", "detail": "Image: ubuntu-latest"}]
                ).encode()
            )

    def test_public_bundle_excludes_raw_context_and_requires_foreground(self):
        import public_evidence

        with tempfile.TemporaryDirectory() as name:
            parent = pathlib.Path(name) / "evidence"
            parent.mkdir()
            (parent / "unrelated-secret.txt").write_text("never upload this")
            (parent / "qualify-failure.json").write_text("private local traceback")
            (parent / "launch-closeout.json").write_text(
                '{"status":"PASS","unrelated":"private"}'
            )
            self.assertEqual(target.public_summary(parent)["status"], "HOLD")
            (parent / "foreground.json").write_text('{"status":"PASS"}')
            self.assertEqual(target.public_summary(parent)["status"], "HOLD")
            resources = [
                {"kind": kind, "present": False}
                for kind in ("container", "container", "volume")
            ]
            records = {
                "namespaces": [
                    {
                        "namespace": "pull-private-evidence",
                        "status": "no-owned-journal-not-proof-of-no-create",
                    },
                    {
                        "namespace": "volume-private-evidence",
                        "observation": {"resources": resources},
                    },
                ]
            }
            (parent / "reconciliation.json").write_text(json.dumps(records))
            self.assertEqual(target.public_summary(parent)["status"], "PASS")
            resources[0]["present"] = True
            (parent / "reconciliation.json").write_text(json.dumps(records))
            self.assertEqual(target.public_summary(parent)["status"], "HOLD")
            import volume_driver
            import volume_lifecycle

            stage = pathlib.Path(__file__).with_name("volume_stage.py").read_bytes()
            modules = {
                "public_evidence.py": public_evidence,
                "volume_driver.py": volume_driver,
                "volume_lifecycle.py": volume_lifecycle,
            }
            with (
                patch.object(target, "verified_file", return_value=stage),
                patch.object(
                    target,
                    "load_buffer",
                    side_effect=lambda raw, path: modules[path.name],
                ),
            ):
                target.publish_bundle(parent)
            output = parent / "public-evidence"
            expected = {
                "summary.json",
                "SHA256.json",
                "source-bindings.json",
                "launch-closeout.json",
                "foreground.json",
                "reconciliation.json",
            }
            self.assertEqual({p.name for p in output.iterdir()}, expected)
            summary = (output / "summary.json").read_bytes()
            self.assertNotIn(b"private", summary)
            self.assertEqual(json.loads(summary)["status"], "HOLD")
            self.assertEqual(
                json.loads((output / "SHA256.json").read_bytes())["summary.json"],
                hashlib.sha256(summary).hexdigest(),
            )

    def test_owner_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            # /tmp is world writable, regardless of leaf ownership/mode.
            with self.assertRaises(ValueError):
                target.protected(pathlib.Path(name))


if __name__ == "__main__":
    unittest.main()
