"""Entry finalizer negatives, no actual launcher or signal mutation."""

import unittest

import volume_entry as target


class EntryTests(unittest.TestCase):
    def test_signal_restore_preserves_primary(self):
        class Budget:
            def arm(self):
                pass

            def close(self):
                raise RuntimeError("restore")

        def operation(budget):
            raise ValueError("primary")

        with self.assertRaises(target.EntryCleanupHold) as raised:
            target.run_entry(Budget(), operation)
        self.assertIsInstance(raised.exception.primary_error, ValueError)
        self.assertIsInstance(raised.exception.cleanup_error, RuntimeError)
        self.assertIs(raised.exception.__cause__, raised.exception.primary_error)

    def test_success_and_restore_only_failure(self):
        class Budget:
            def arm(self):
                pass

            def close(self):
                pass

        self.assertEqual(target.run_entry(Budget(), lambda b: "fixed"), "fixed")

        class Bad(Budget):
            def close(self):
                raise RuntimeError("restore only")

        with self.assertRaises(RuntimeError):
            target.run_entry(Bad(), lambda b: "fixed")


if __name__ == "__main__":
    unittest.main()
