"""Entry real alarm-ownership negatives; no network/daemon."""

import signal
import threading
import unittest
from unittest.mock import patch

import shared_budget
import volume_entry as target


class OwnershipTests(unittest.TestCase):
    def test_preexisting_timer_unchanged_after_entry_rejection(self):
        previous = signal.getsignal(signal.SIGALRM)
        signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            with self.assertRaises(ValueError):
                target.run_entry(shared_budget.Budget(), lambda b: None)
            remaining, interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(remaining, 9)
            self.assertEqual(interval, 0)
            self.assertIs(signal.getsignal(signal.SIGALRM), previous)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    def test_wrong_thread_does_not_touch_timer(self):
        failures = []

        def worker():
            try:
                target.run_entry(shared_budget.Budget(), lambda b: None)
            except BaseException as error:
                failures.append(error)

        previous = signal.getsignal(signal.SIGALRM)
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], ValueError)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)

    def test_partial_arm_restores_owned_handler_only(self):
        previous = signal.getsignal(signal.SIGALRM)
        budget = shared_budget.Budget()
        with patch.object(
            shared_budget.signal, "setitimer", side_effect=OSError("arm failure")
        ) as setter:
            with self.assertRaises(OSError):
                target.run_entry(budget, lambda b: None)
            self.assertEqual(setter.call_count, 1)
        self.assertFalse(budget.handler_owned)
        self.assertFalse(budget.timer_owned)
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)


if __name__ == "__main__":
    unittest.main()
