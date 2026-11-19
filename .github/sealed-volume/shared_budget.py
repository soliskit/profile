"""Single main-thread absolute normal/cleanup alarm budget, source proposal."""

import signal
import threading
import time


class DeadlineHold(RuntimeError):
    pass


class Budget:
    def __init__(self, normal_seconds=480, cleanup_seconds=240):
        self.normal_end = time.monotonic() + normal_seconds
        self.cleanup_seconds = cleanup_seconds
        self.cleanup_end = None
        self.cleaning = False
        self.previous = None
        self.handler_owned = False
        self.timer_owned = False

    def remaining(self):
        end = self.cleanup_end if self.cleaning else self.normal_end
        value = end - time.monotonic()
        if value <= 0:
            raise DeadlineHold("shared phase deadline exhausted; HOLD")
        return value

    def _alarm(self, signum, frame):
        raise DeadlineHold("shared absolute deadline expired; HOLD")

    def arm(self):
        if threading.current_thread() is not threading.main_thread():
            raise ValueError("main thread required")
        remaining = self.remaining()
        if not self.handler_owned:
            if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
                raise ValueError("preexisting alarm unsupported")
            previous = signal.signal(signal.SIGALRM, self._alarm)
            self.previous = previous
            self.handler_owned = True
        try:
            signal.setitimer(signal.ITIMER_REAL, remaining)
            self.timer_owned = True
        except BaseException:
            if not self.timer_owned:
                # Never disable an unowned timer after a rejected/failed arm.
                signal.signal(signal.SIGALRM, self.previous)
                self.handler_owned = False
                self.previous = None
            raise

    def cleanup(self):
        if self.cleanup_end is None:
            self.cleanup_end = time.monotonic() + self.cleanup_seconds
        self.cleaning = True
        self.arm()

    def close(self):
        if not self.handler_owned and not self.timer_owned:
            return
        if threading.current_thread() is not threading.main_thread():
            raise ValueError("owned alarm must close on main thread")
        if self.timer_owned:
            signal.setitimer(signal.ITIMER_REAL, 0)
            self.timer_owned = False
        if self.handler_owned:
            signal.signal(signal.SIGALRM, self.previous)
            self.handler_owned = False
            self.previous = None
