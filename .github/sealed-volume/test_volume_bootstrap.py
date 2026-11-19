"""Same-buffer pin tests only, no engine execution."""

import hashlib
import pathlib
import tempfile
import unittest

import volume_bootstrap as target


class BootstrapTests(unittest.TestCase):
    def test_exact_buffers_and_drift(self):
        root = pathlib.Path(__file__).parent
        expected = {
            n: hashlib.sha256((root / n).read_bytes()).hexdigest() for n in target.FILES
        }
        modules, buffers = target.load(root, expected)
        self.assertEqual(set(buffers), target.FILES)
        self.assertEqual(modules["volume_lifecycle"].IMAGE.split("@")[0], "python")
        expected["volume_stage.py"] = "f" * 64
        with self.assertRaises(ValueError):
            target.load(root, expected)

    def test_missing_set(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                target.load(pathlib.Path(directory), {})


if __name__ == "__main__":
    unittest.main()
