"""Deadline integration tests, no network or daemon."""

import time
import unittest

import shared_budget as target


class BudgetTests(unittest.TestCase):
    def test_absolute_deadlines_not_reset(self):
        budget = target.Budget(normal_seconds=3, cleanup_seconds=2)
        normal = budget.normal_end
        try:
            budget.arm()
            self.assertEqual(normal, budget.normal_end)
            budget.cleanup()
            cleanup = budget.cleanup_end
            budget.cleanup()
            self.assertEqual(cleanup, budget.cleanup_end)
            self.assertEqual(normal, budget.normal_end)
        finally:
            budget.close()

    def test_alarm_interrupts_blocking_wait(self):
        budget = target.Budget(normal_seconds=0.05, cleanup_seconds=1)
        start = time.monotonic()
        try:
            budget.arm()
            with self.assertRaises(target.DeadlineHold):
                time.sleep(2)
            self.assertLess(time.monotonic() - start, 0.5)
            budget.cleanup()
            self.assertGreater(budget.remaining(), 0)
        finally:
            budget.close()

    def test_expired_cleanup_not_reset(self):
        budget = target.Budget(cleanup_seconds=0.01)
        try:
            budget.cleanup()
            with self.assertRaises(target.DeadlineHold):
                time.sleep(0.1)
            with self.assertRaises(target.DeadlineHold):
                budget.cleanup()
        finally:
            budget.close()


if __name__ == "__main__":
    unittest.main()
