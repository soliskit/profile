"""Bounded trusted foreground Docker executor, no shell or output replay.

Invocation/root/source authority remains caller-owned and independently reviewed.
Only fixed docker executable, allowlisted operations and private new evidence root.
"""

import hashlib
import json
import os
import pathlib
import selectors
import signal
import subprocess
import time

MAX_STREAM = 1024 * 1024
MAX_INPUT = 32 * 1024 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024
OPERATIONS = {
    ("version",),
    ("create",),
    ("inspect",),
    ("start",),
    ("rm",),
    ("ps",),
    ("image", "inspect"),
    ("volume", "create"),
    ("volume", "inspect"),
    ("volume", "ls"),
    ("volume", "rm"),
}


FIXED_PULL = [
    "docker",
    "pull",
    "--platform",
    "linux/amd64",
    "python@sha256:1faf2343e747208b2a36e5f2b5ff908ec3b2d0078a6a7bfe73b535698fe83909",
]


class ExecutionHold(RuntimeError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Executor:
    def __init__(self, binary, binary_sha256, evidence, environment, budget=None):
        self.binary = pathlib.Path(binary)
        self.binary_sha256 = binary_sha256
        self.root = pathlib.Path(evidence)
        if not self.binary.is_absolute() or self.binary.is_symlink():
            raise ValueError("canonical ordinary executable required")
        if sha(self.binary.read_bytes()) != binary_sha256:
            raise ValueError("executable differs from independent pin")
        if (
            set(environment) != {"PATH", "HOME", "LANG"}
            or environment["LANG"] != "C.UTF-8"
        ):
            raise ValueError("exact trusted environment required")
        self.env = dict(environment)
        if not self.root.is_absolute() or self.root.resolve() != self.root:
            raise ValueError("canonical new evidence route required")
        self.root.mkdir(mode=0o700)
        self.sequence = 0
        self.pull_attempted = False
        self.in_fixed_pull = False
        self.saved = 0
        self.cleanup_saved = 0
        self.cleanup_calls = 0
        self.cleanup_resources = None
        self.in_cleanup = False
        self.budget = budget
        self.normal_deadline = time.monotonic() + 360
        self.cleanup_deadline = None
        self.journal_sequence = 0

    def journal(self, record):
        path = self.root / f"owned-{self.journal_sequence:04d}.json"
        self.journal_sequence += 1
        try:
            self.save(path, json.dumps(record, sort_keys=True).encode())
        except (OSError, ExecutionHold):
            if not self.in_cleanup:
                raise

    def bind_cleanup(self, volume, names):
        if self.cleanup_resources is not None:
            raise ValueError("cleanup capability already bound")
        self.cleanup_resources = (volume, names)

    def cleanup_command(self, args, **kwargs):
        if self.cleanup_resources is None or self.cleanup_calls >= 64:
            raise ExecutionHold("cleanup capability unavailable/exhausted; HOLD")
        volume, names = self.cleanup_resources
        exact = [
            ["docker", "ps", "--all", "--quiet", "--filter", "volume=" + volume],
            ["docker", "ps", "--all", "--quiet", "--no-trunc"],
            ["docker", "volume", "inspect", volume],
            ["docker", "volume", "rm", volume],
            ["docker", "volume", "ls", "--quiet", "--filter", "name=^" + volume + "$"],
        ]
        exact.extend(["docker", "rm", "--force", n] for n in names)
        exact.extend(
            ["docker", "ps", "--all", "--quiet", "--filter", "name=^/" + n + "$"]
            for n in names
        )
        readonly = (
            args[:2] == ["docker", "inspect"]
            and len(args) > 2
            and all(
                len(x) == 64 and all(c in "0123456789abcdef" for c in x)
                for x in args[2:]
            )
        )
        if args not in exact and not readonly:
            raise ValueError("cleanup capability scope differs")
        self.cleanup_calls += 1
        self.in_cleanup = True
        try:
            return self(args, **kwargs)
        finally:
            self.in_cleanup = False

    def save(self, path, data):
        used = self.cleanup_saved if self.in_cleanup else self.saved
        limit = 160 * 1024 * 1024 if self.in_cleanup else MAX_ARTIFACT
        if len(data) > limit - used:
            raise ExecutionHold("artifact budget exhausted; HOLD")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if self.in_cleanup:
            self.cleanup_saved += len(data)
        else:
            self.saved += len(data)

    def pull_fixed_image_once(self):
        if self.pull_attempted:
            raise ExecutionHold("fixed image pull already attempted; reconcile only")
        self.pull_attempted = True
        self.save(
            self.root / "fixed-pull-attempt.json",
            json.dumps(
                {"argv": FIXED_PULL, "status": "attempt-armed-no-retry"}
            ).encode(),
        )
        self.in_fixed_pull = True
        try:
            return self(list(FIXED_PULL), timeout=180)
        finally:
            self.in_fixed_pull = False

    def __call__(self, args, data=None, timeout=60, allowed=(0,)):
        if type(args) is not list or len(args) < 2 or args[0] != "docker":
            raise ValueError("fixed Docker argv required")
        if any(type(x) is not str or "\0" in x for x in args):
            raise ValueError("ordinary argv strings required")
        fixed_pull = self.in_fixed_pull and args == FIXED_PULL and not self.in_cleanup
        if not fixed_pull and not any(
            tuple(args[1 : 1 + len(op)]) == op for op in OPERATIONS
        ):
            raise ValueError("operation not approved")
        if type(timeout) is not int or timeout < 1 or timeout > 180:
            raise ValueError("bounded integer timeout required")
        if data is None:
            data = b""
        if type(data) is not bytes or len(data) > MAX_INPUT:
            raise ValueError("bounded stdin required")
        if sha(self.binary.read_bytes()) != self.binary_sha256:
            raise ExecutionHold("Docker binary drift; HOLD")
        deadline = self.normal_deadline
        if self.in_cleanup:
            if self.cleanup_deadline is None:
                self.cleanup_deadline = time.monotonic() + 240
            deadline = self.cleanup_deadline
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            raise ExecutionHold("whole-phase deadline exceeded; HOLD")
        if self.budget is not None:
            if self.in_cleanup:
                self.budget.cleanup()
            remaining_time = self.budget.remaining()
        effective_timeout = min(timeout, remaining_time)
        # Reserve enough artifact budget BEFORE spawn, including failure evidence.
        argv_bytes = json.dumps(args).encode()
        if len(argv_bytes) > MAX_STREAM or (
            not self.in_cleanup
            and self.saved + 2 * MAX_STREAM + len(argv_bytes) + 65536 > MAX_ARTIFACT
        ):
            raise ExecutionHold("insufficient evidence reserve; HOLD")
        number = self.sequence
        self.sequence += 1
        prefix = self.root / f"{number:04d}"
        evidence_errors = []

        def evidence_save(path, value):
            try:
                self.save(path, value)
            except (OSError, ExecutionHold) as caught:
                evidence_errors.append(type(caught).__name__)
                if not self.in_cleanup:
                    raise

        evidence_save(
            str(prefix) + "-invocation.json",
            json.dumps(
                {
                    "argv": args,
                    "argv_sha256": sha(argv_bytes),
                    "stdin_sha256": sha(data),
                    "stdin_bytes": len(data),
                    "binary_sha256": self.binary_sha256,
                    "environment": self.env,
                    "timeout_seconds": timeout,
                },
                sort_keys=True,
            ).encode(),
        )
        if args[1:3] == ["volume", "create"]:
            self.journal({"kind": "volume-create-armed", "name": args[-1]})
        elif args[1] == "create":
            self.journal(
                {
                    "kind": "container-create-armed",
                    "name": args[args.index("--name") + 1],
                }
            )
        elif args[1] == "rm" or args[1:3] == ["volume", "rm"]:
            self.journal({"kind": "removal-armed", "argv": args})
        output, error = bytearray(), bytearray()
        start = time.monotonic()
        failure = None
        child = None
        try:
            child = subprocess.Popen(
                [str(self.binary), *args[1:]],
                cwd="/",
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            with selectors.DefaultSelector() as selector:
                for stream, label in [
                    (child.stdout, "stdout"),
                    (child.stderr, "stderr"),
                ]:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, label)
                os.set_blocking(child.stdin.fileno(), False)
                if data:
                    selector.register(child.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    child.stdin.close()
                offset = 0
                while selector.get_map():
                    if time.monotonic() - start > effective_timeout:
                        raise ExecutionHold("foreground command timeout; HOLD")
                    for key, _ in selector.select(0.05):
                        stream, label = key.fileobj, key.data
                        if label == "stdin":
                            try:
                                sent = os.write(
                                    stream.fileno(), data[offset : offset + 65536]
                                )
                            except BrokenPipeError:
                                sent = 0
                                offset = len(data)
                            offset += sent
                            if offset >= len(data):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            blob = os.read(stream.fileno(), 65536)
                            if not blob:
                                selector.unregister(stream)
                                stream.close()
                            else:
                                destination = output if label == "stdout" else error
                                remaining = MAX_STREAM - len(destination)
                                destination.extend(blob[:remaining])
                                if len(blob) > remaining:
                                    raise ExecutionHold(
                                        "raw stream bound exceeded; HOLD"
                                    )
                child.wait(
                    timeout=max(0.001, effective_timeout - (time.monotonic() - start))
                )
                if child.returncode not in allowed:
                    raise ExecutionHold("foreground command nonzero; HOLD")
        except BaseException as caught:
            failure = type(caught).__name__
            raise
        finally:
            process_errors = []
            if failure is not None and self.budget is not None:
                try:
                    self.budget.cleanup()
                except BaseException as caught:
                    process_errors.append(type(caught).__name__)
            if child is not None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as caught:
                    process_errors.append(type(caught).__name__)
                try:
                    child.wait(timeout=10)
                except BaseException as caught:
                    process_errors.append(type(caught).__name__)
                for stream in (child.stdin, child.stdout, child.stderr):
                    try:
                        if stream and not stream.closed:
                            stream.close()
                    except OSError as caught:
                        process_errors.append(type(caught).__name__)
            artifacts = [
                (str(prefix) + "-stdout.bin", bytes(output)),
                (str(prefix) + "-stderr.bin", bytes(error)),
                (
                    str(prefix) + "-result.json",
                    json.dumps(
                        {
                            "failure_type": failure,
                            "returncode": None if child is None else child.returncode,
                            "unresolved_process_errors": process_errors,
                            "evidence_errors": evidence_errors,
                            "stdout_sha256": sha(output),
                            "stderr_sha256": sha(error),
                            "elapsed_seconds": time.monotonic() - start,
                            "scope": "local CLI only; daemon ambiguity remains HOLD",
                        },
                        sort_keys=True,
                    ).encode(),
                ),
            ]
            for path, value in artifacts:
                try:
                    self.save(path, value)
                except (OSError, ExecutionHold) as caught:
                    evidence_errors.append(type(caught).__name__)
            if failure is None and (process_errors or evidence_errors):
                raise ExecutionHold("process or evidence finalization unresolved; HOLD")
        return bytes(output)
