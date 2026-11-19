"""Verify failure retention against the real workflow in this candidate checkout."""

import ast
import json
import pathlib
import tempfile
import unittest

import public_evidence
import yaml


class RetentionTests(unittest.TestCase):
    def test_early_failure_safe_upload_eligible_final_incomplete(self):
        workflow_path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "workflows"
            / "sealed-volume-qualification.yml"
        )
        workflow = yaml.safe_load(workflow_path.read_text())
        steps = workflow["jobs"]["qualify"]["steps"]
        verify = next(step["run"] for step in steps if step.get("id") == "verify")
        final = steps[-1]["run"]

        def bind(raw, root):
            code = raw.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and node.value
                    == "/opt/credit-qualification/evidence/public-evidence"
                ):
                    node.value = str(root)
            return compile(tree, "local-retention-fixture", "exec")

        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            writer = public_evidence.Writer(root)
            writer.record("summary.json", {"status": "HOLD", "scope": "early failure"})
            writer.record("source-bindings.json", {"source_sha256": {}})
            writer.write("provision-0-stderr.bin", b"inert synthetic failure bytes\n")
            writer.finish()
            exec(bind(verify, root), {})
            with self.assertRaises(SystemExit) as caught:
                exec(bind(final, root), {})
            self.assertEqual(caught.exception.code, 1)
            self.assertEqual(
                json.loads((root / "summary.json").read_bytes())["status"], "HOLD"
            )


if __name__ == "__main__":
    unittest.main()
