"""Exercise the exact workflow guard, creation contract and bounded diagnostics."""

import ast
import contextlib
import io
import pathlib
import types
import unittest
from typing import ClassVar
from unittest.mock import patch

import yaml


class FixedPath:
    """Inert system-path observations. Never touches host filesystem."""

    state: ClassVar[dict] = {}

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

    @property
    def parents(self):
        return [FixedPath(str(p)) for p in pathlib.PurePosixPath(self.value).parents]

    def stat(self):
        uid, mode, _canonical, missing = self.state.get(
            self.value, (0, 0o755, True, False)
        )
        if missing:
            raise FileNotFoundError("private detail must not print")
        return types.SimpleNamespace(st_uid=uid, st_mode=mode)

    def resolve(self, strict):
        canonical = self.state.get(self.value, (0, 0o755, True, False))[2]
        return self if canonical else FixedPath("/untrusted-private-target")

    def __eq__(self, other):
        return isinstance(other, FixedPath) and self.value == other.value


class WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = (
            pathlib.Path(__file__).resolve().parents[1]
            / "workflows/sealed-volume-qualification.yml"
        )
        cls.workflow = yaml.safe_load(path.read_text())
        cls.steps = cls.workflow["jobs"]["qualify"]["steps"]
        cls.codes = {
            s["id"]: s["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
            for s in cls.steps
            if s.get("id") in {"bootstrap", "foreground", "reconcile", "bundle"}
        }

    def guard(self, stage):
        tree = ast.parse(self.codes[stage])
        function = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "protected_source"
        )
        namespace = {}
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "actual-workflow-guard",
                "exec",
            ),
            namespace,
        )
        return namespace["protected_source"]

    def test_identical_guard_bootstrap_and_all_wrappers(self):
        functions = [
            ast.dump(
                next(n for n in ast.parse(code).body if isinstance(n, ast.FunctionDef))
            )
            for code in self.codes.values()
        ]
        self.assertEqual(len(set(functions)), 1)

    def test_every_predicate_on_every_ancestor_fail_closed_with_surviving_marker(self):
        leaf = "/credit-qualification/source/route_cli.py"
        paths = [leaf, "/credit-qualification/source", "/credit-qualification", "/"]
        for stage in self.codes:
            for name in paths:
                for state, reason in [
                    ((1, 0o755, True, False), "owner"),
                    ((0, 0o777, True, False), "write-bits"),
                    ((0, 0o755, False, False), "canonical"),
                    ((0, 0o755, True, True), "observe"),
                ]:
                    with (
                        self.subTest(stage=stage, path=name, reason=reason),
                        patch.object(FixedPath, "state", {name: state}),
                    ):
                        output = io.StringIO()
                        advanced = False
                        with (
                            contextlib.redirect_stdout(output),
                            self.assertRaises(ValueError),
                        ):
                            self.guard(stage)(FixedPath(leaf))
                            advanced = True
                        self.assertFalse(advanced)
                        self.assertIn("reason=" + reason, output.getvalue())
                        self.assertIn("guard-before item=", output.getvalue())
                        self.assertNotIn("private", output.getvalue())
                        self.assertNotIn("untrusted", output.getvalue())

    def test_success_uses_actual_wrapper_prefix_before_source_read(self):
        for stage in ("foreground", "reconcile", "bundle"):
            tree = ast.parse(self.codes[stage])
            prefix = []
            for node in tree.body:
                if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "raw" for t in node.targets
                ):
                    break
                if not isinstance(node, ast.Import):
                    prefix.append(node)
            output = io.StringIO()
            namespace = {"pathlib": types.SimpleNamespace(Path=FixedPath)}
            with (
                patch.object(FixedPath, "state", {}),
                contextlib.redirect_stdout(output),
            ):
                exec(
                    compile(
                        ast.Module(body=prefix, type_ignores=[]),
                        "actual-wrapper-prefix",
                        "exec",
                    ),
                    namespace,
                )
            self.assertEqual(output.getvalue().count("reason=pass"), 4)
            self.assertIn("route-before-" + stage, output.getvalue())

    def test_exclusive_bootstrap_no_existing_parent_mutation_and_path_consistency(self):
        tree = ast.parse(self.codes["bootstrap"])
        mkdir = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "mkdir"
        ]
        self.assertEqual(len(mkdir), 3)
        self.assertTrue(
            all(
                not any(k.arg in {"exist_ok", "parents"} for k in n.keywords)
                for n in mkdir
            )
        )
        text = self.codes["bootstrap"]
        self.assertLess(
            text.index('protected_source(pathlib.Path("/"))'), text.index("root.mkdir")
        )
        self.assertLess(
            text.index('protected_source(root/"source")'),
            text.index("for name,expected"),
        )
        self.assertNotIn("chmod", text)
        self.assertEqual(text.count("os.chown("), 1)
        self.assertIn('os.chown(root/"evidence",', text)
        self.assertNotIn("/opt/", str(self.workflow))
        upload = next(s for s in self.steps if s.get("id") == "upload")
        self.assertEqual(
            upload["with"]["path"], "/credit-qualification/evidence/public-evidence/"
        )
        self.assertEqual(upload["with"]["retention-days"], 7)
        self.assertEqual(self.workflow["jobs"]["qualify"]["runs-on"], "ubuntu-24.04")


if __name__ == "__main__":
    unittest.main()
