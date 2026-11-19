"""Strict source contract cases, no runtime proof."""

import copy
import hashlib
import unittest

import source_contract as target


def object_add(objects, kind, data):
    oid = hashlib.sha1(
        kind.encode() + b" " + str(len(data)).encode() + b"\0" + data
    ).hexdigest()
    objects[oid] = (kind, data)
    return oid


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.objects = {}
        blob = object_add(self.objects, "blob", b"trusted")
        sub = object_add(
            self.objects, "tree", b"100644 code.py\0" + bytes.fromhex(blob)
        )
        self.root = object_add(
            self.objects, "tree", b"40000 src\0" + bytes.fromhex(sub)
        )
        self.observed = []
        for name, item in target.native_inventory(self.root, self.objects).items():
            self.observed.append(
                dict(item, path=name, uid=0, gid=0, nlink=1, xattrs=[])
            )
        for name in sorted(target.OUTPUT_FILES | target.OUTPUT_DIRS):
            file = name in target.OUTPUT_FILES
            self.observed.append(
                {
                    "path": name,
                    "kind": "file" if file else "directory",
                    "mode": 0o600 if file else 0o700,
                    "uid": 10001,
                    "gid": 10001,
                    "nlink": 1,
                    "xattrs": [],
                    "sha256": target.EMPTY if file else None,
                }
            )
        self.metadata = {"uid": 0, "gid": 0, "mode": 0o555, "xattrs": []}

    def validate(self):
        return target.validate_contract(
            self.root, self.objects, self.observed, self.metadata
        )

    def test_native_tree_positive(self):
        self.assertTrue(self.validate())

    def test_missing_or_malformed_metadata(self):
        for field in target.FIELDS:
            original = copy.deepcopy(self.observed)
            del self.observed[1][field]
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                self.validate()
            self.observed = original
        for field, value in [
            ("xattrs", None),
            ("mode", True),
            ("uid", "0"),
            ("sha256", None),
            ("nlink", 2),
            ("mode", 0o644),
            ("kind", "symlink"),
            ("sha256", "f" * 64),
            ("xattrs", ["system.posix_acl_access"]),
        ]:
            original = copy.deepcopy(self.observed)
            self.observed[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate()
            self.observed = original

    def test_missing_parent_duplicate_extra(self):
        original = copy.deepcopy(self.observed)
        self.observed = self.observed[1:]
        with self.assertRaises(ValueError):
            self.validate()
        self.observed = [*original, copy.deepcopy(original[0])]
        with self.assertRaises(ValueError):
            self.validate()

    def test_tampered_native_objects_and_anchor(self):
        original = copy.deepcopy(self.objects)
        self.objects[self.root] = ("tree", b"different")
        with self.assertRaises(ValueError):
            self.validate()
        self.objects = original
        self.root = "f" * 40
        with self.assertRaises(KeyError):
            self.validate()

    def test_output_collision(self):
        b = object_add(self.objects, "blob", b"")
        self.root = object_add(
            self.objects, "tree", b"100644 next-env.d.ts\0" + bytes.fromhex(b)
        )
        with self.assertRaises(ValueError):
            self.validate()

    def test_paths_root_and_output(self):
        for name in ["..", "/a", "a//b", "a/../b", "a/./b", "a\x00b"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                target.path_name(name)
        self.metadata["mode"] = 0o755
        with self.assertRaises(ValueError):
            self.validate()
        self.metadata["mode"] = 0o555
        self.observed[-1]["uid"] = 0
        with self.assertRaises(ValueError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
