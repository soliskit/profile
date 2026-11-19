"""Bounded fixed host provisioning. No shell, disk streaming or daemon retry."""

import hashlib
import os
import pathlib
import selectors
import signal
import subprocess
import time

MAX_STREAM = 1024 * 1024


class ProvisionHold(RuntimeError):
    def __init__(self, primary_error, cleanup_errors):
        super().__init__("provision or finalization unresolved; HOLD")
        self.primary_error = primary_error
        self.cleanup_errors = cleanup_errors


def write_raw(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def run(args, prefix, env, budget, save):
    save(
        pathlib.Path(str(prefix) + "-invocation.json"),
        {"argv": args, "scope": "fixed public native fetch, shared normal deadline"},
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    child = None
    failure = None
    cleanup_errors = []
    started = time.monotonic()
    try:
        child = subprocess.Popen(
            args,
            cwd="/",
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with selectors.DefaultSelector() as selector:
            for label, stream in (("stdout", child.stdout), ("stderr", child.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map():
                remaining = budget.remaining()
                if child.poll() is not None:
                    # A reaped leader cannot authorize live descendants.
                    try:
                        os.killpg(child.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        raise RuntimeError(
                            "provision leader exited with descendants; HOLD"
                        )
                for key, _ in selector.select(min(0.05, remaining)):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    destination = buffers[key.data]
                    room = MAX_STREAM - len(destination)
                    destination.extend(raw[:room])
                    if len(raw) > room:
                        raise RuntimeError("provision stream overflow; HOLD")
            child.wait(timeout=min(10, budget.remaining()))
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise RuntimeError("provision completed leader left descendants; HOLD")
            if child.returncode != 0:
                raise RuntimeError("provision nonzero; HOLD")
    except BaseException as error:
        failure = error
    finally:
        if failure is not None:
            try:
                budget.cleanup()
            except BaseException as error:
                cleanup_errors.append(error)
        if child is not None:
            # Always target the original process group, even after leader exit.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as error:
                cleanup_errors.append(error)
            try:
                child.wait(timeout=min(10, budget.remaining()))
            except BaseException as error:
                cleanup_errors.append(error)
            for stream in (child.stdout, child.stderr):
                try:
                    stream.close()
                except BaseException as error:
                    cleanup_errors.append(error)
    record = {
        "failure_type": None if failure is None else type(failure).__name__,
        "returncode": None if child is None else child.returncode,
        "elapsed_seconds": time.monotonic() - started,
    }
    for label, raw in buffers.items():
        record[label + "_bytes"] = len(raw)
        record[label + "_sha256"] = hashlib.sha256(raw).hexdigest()
        try:
            write_raw(pathlib.Path(str(prefix) + "-" + label + ".bin"), raw)
        except BaseException as error:
            cleanup_errors.append(error)
    record["cleanup_error_types"] = [type(e).__name__ for e in cleanup_errors]
    try:
        save(pathlib.Path(str(prefix) + "-result.json"), record)
    except BaseException as error:
        cleanup_errors.append(error)
    if cleanup_errors:
        raise ProvisionHold(failure, cleanup_errors) from failure
    if failure is not None:
        raise failure
    return record
