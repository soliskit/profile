#!/usr/bin/env python3
"""Inert, offline runner-boundary qualification. Never starts updater or publishes.

No token, Git upload, repo mutation, package update, daemon API or host mounts.
Requires reviewed Docker Engine on the intended disposable Linux runner.
"""

import argparse
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import time
import uuid

IMAGE = "node@sha256:51d24d08800f352afae68628d883e63db3f2c4dd807b7ddb6f805dc6b9ef8c0e"
MAX_OUTPUT = 1024 * 1024


class CommandFailure(RuntimeError):
    """Bounded evidence kept as data, never interpolated into workflow output."""

    def __init__(self, args, result):
        super().__init__("runner command failed; HOLD; no automatic retry")
        self.operation = args[:2]
        self.returncode = result.returncode
        self.stdout = result.stdout[:MAX_OUTPUT]
        self.stderr = result.stderr[:MAX_OUTPUT]
        self.truncated = (
            len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT
        )


def command(args, *, data=None, timeout=60, allowed=(0,)):
    env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
    result = subprocess.run(
        args,
        input=data,
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if result.returncode not in allowed:
        raise CommandFailure(args, result)
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise RuntimeError("runner evidence exceeds bound; HOLD")
    return result


def validate_observation(item, source):
    """Inspect real engine state before execution, not a package-written receipt."""
    config = item["Config"]
    host = item["HostConfig"]
    if config["User"] != "10001:10001" or not host["ReadonlyRootfs"]:
        raise ValueError("wrong identity or writable root")
    if host["Privileged"] or host.get("Devices") or host.get("CapAdd"):
        raise ValueError("privileged/device/capability exposure")
    if set(host.get("CapDrop") or ()) != {"ALL"}:
        raise ValueError("capabilities not fully dropped")
    if not any(x.startswith("no-new-privileges") for x in host.get("SecurityOpt", [])):
        raise ValueError("missing no-new-privileges")
    if any("unconfined" in x for x in host.get("SecurityOpt", [])):
        raise ValueError("security profile disabled")
    if (
        host["NetworkMode"] != "none"
        or host.get("PidMode")
        or host.get("IpcMode") != "private"
    ):
        raise ValueError("shared or networked namespace")
    if item.get("Mounts"):
        raise ValueError("unexpected host or volume mount")
    if set(host.get("Tmpfs", {})) != {"/tmp"}:
        raise ValueError("unexpected writable tmpfs")
    if host.get("Binds") or host.get("VolumesFrom") or host.get("GroupAdd"):
        raise ValueError("host filesystem/group exposure")
    if host.get("Memory") != 268435456 or host.get("PidsLimit") != 64:
        raise ValueError("resource limits differ")
    if host.get("NanoCpus") != 1000000000:
        raise ValueError("CPU limit differs")
    env = dict(x.split("=", 1) for x in config.get("Env", []))
    if any(k.startswith(("GITHUB_", "ACTIONS_", "RUNNER_", "CREDIT_")) for k in env):
        raise ValueError("runner credential or command environment exposed")
    if config["Image"] != IMAGE:
        raise ValueError("image pin differs")
    if config.get("Entrypoint") != ["/usr/local/bin/node"]:
        raise ValueError("unexpected entrypoint")
    if config.get("Cmd") != ["--eval", source.decode("utf-8")]:
        raise ValueError("fixed host-generated source differs")


def validate_tar(data, expected_names):
    """Bounded regular-file parser. No extraction and no package Git authority."""
    if len(data) > MAX_OUTPUT:
        raise ValueError("oversized output")
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name
            if name not in expected_names or name in result:
                raise ValueError("unexpected or duplicate output path")
            if not member.isfile() or member.linkname or member.mode & 0o111:
                raise ValueError("link/special/executable output")
            if member.size < 0 or member.size > MAX_OUTPUT:
                raise ValueError("oversized member")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError("missing output bytes")
            blob = handle.read(MAX_OUTPUT + 1)
            if len(blob) != member.size:
                raise ValueError("incomplete output")
            result[name] = blob
    if set(result) != set(expected_names):
        raise ValueError("missing output")
    return result


def probe_source(host_marker, host_pid):
    """All interpolated values are internally generated fixture identifiers."""
    return (
        (
            """const fs = require('fs');
const net = require('net');
const checks = {};
function denied(name, action) {
  try { action(); checks[name] = false; }
  catch (error) { checks[name] = true; }
}
checks.uid = process.getuid() === 10001;
checks.node = process.version === 'v26.13.0';
denied('host-marker', () => fs.readFileSync(__MARKER__));
denied('daemon-socket', () => fs.statSync('/var/run/docker.sock'));
denied('host-root', () => fs.statSync('/host'));
denied('readonly-binary', () => fs.writeFileSync('/usr/local/bin/node', 'changed'));
denied('readonly-root', () => fs.writeFileSync('/escape', 'changed'));
denied('host-pid', () => process.kill(__HOST_PID__, 0));
const status = fs.readFileSync('/proc/self/status', 'utf8');
checks.caps = /^CapEff:\\s+0+$/m.test(status);
checks.nnp = /^NoNewPrivs:\\s+1$/m.test(status);
checks.seccomp = /^Seccomp:\\s+2$/m.test(status);
checks.noTokenEnv = !Object.keys(process.env).some(k => /^(GITHUB_|ACTIONS_|RUNNER_|CREDIT_)/.test(k));
const targets = ['172.17.0.1', '169.254.169.254', '127.0.0.1', '::1'];
async function deniedConnect(host) {
  return await new Promise(resolve => {
    const socket = net.createConnection({host, port: 80});
    socket.setTimeout(1000);
    socket.once('connect', () => {socket.destroy(); resolve(false);});
    socket.once('error', () => {socket.destroy(); resolve(true);});
    socket.once('timeout', () => {socket.destroy(); resolve(true);});
  });
}
(async () => {
  for (const host of targets) checks['network-' + host] = await deniedConnect(host);
  console.log('::set-env name=CREDIT_FORGED_PASS::true');
  console.log(JSON.stringify({checks}));
  process.exit(Object.values(checks).every(Boolean) ? 0 : 1);
})();
"""
        )
        .replace("__MARKER__", json.dumps(str(host_marker)))
        .replace("__HOST_PID__", str(host_pid))
        .encode()
    )


def reconcile_name(name, evidence):
    """One removal attempt and independent absence read, including ambiguous create.

    An absence read is an observation, not proof a timed-out daemon request cannot
    finish later. The original create error always remains HOLD, never success.
    """
    removal_failure = None
    try:
        command(["docker", "rm", "--force", name], timeout=30, allowed=(0, 1))
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        removal_failure = type(error).__name__
    try:
        remaining = command(
            ["docker", "ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"]
        )
        absent = not remaining.stdout.strip()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        (evidence / "cleanup.json").write_text(
            json.dumps(
                {
                    "removal_failure": removal_failure,
                    "absence_observed": False,
                    "inspection_failure": type(error).__name__,
                    "status": "HOLD",
                },
                indent=2,
            )
            + "\n"
        )
        raise RuntimeError("container absence unverified; HOLD") from error
    (evidence / "cleanup.json").write_text(
        json.dumps(
            {
                "removal_failure": removal_failure,
                "absence_observed": absent,
                "status": "absence-observed"
                if absent and not removal_failure
                else "HOLD",
            },
            indent=2,
        )
        + "\n"
    )
    if not absent or removal_failure:
        raise RuntimeError("container removal/absence unverified; HOLD")
    return True


def run(evidence):
    evidence.mkdir(mode=0o700)
    name = "credit-isolation-" + uuid.uuid4().hex
    cleanup_armed = False
    absence_observed = False
    failure = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="credit-host-only-") as private:
        marker = pathlib.Path(private) / "fixture-marker"
        marker.write_bytes(os.urandom(32))
        marker.chmod(0o600)
        source = probe_source(marker, os.getpid())
        try:
            engine = command(["docker", "version", "--format", "{{json .}}"])
            (evidence / "engine.json").write_bytes(engine.stdout)
            command(["docker", "pull", "--platform", "linux/amd64", IMAGE], timeout=180)
            args = [
                "docker",
                "create",
                "--name",
                name,
                "--platform",
                "linux/amd64",
                "--user",
                "10001:10001",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges=true",
                "--network",
                "none",
                "--ipc",
                "private",
                "--pids-limit",
                "64",
                "--memory",
                "256m",
                "--cpus",
                "1",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                "--entrypoint",
                "/usr/local/bin/node",
                IMAGE,
                "--eval",
                source.decode("utf-8"),
            ]
            cleanup_armed = True
            command(args)
            inspected = command(["docker", "inspect", name])
            (evidence / "configured-container.json").write_bytes(inspected.stdout)
            item = json.loads(inspected.stdout)[0]
            validate_observation(item, source)
            result = command(
                ["docker", "start", "--attach", name], timeout=30, allowed=(0, 1)
            )
            # Deliberately never replay package stdout into the runner log.
            (evidence / "untrusted-stdout.bin").write_bytes(result.stdout)
            (evidence / "untrusted-stderr.bin").write_bytes(result.stderr)
            state = json.loads(command(["docker", "inspect", name]).stdout)[0]["State"]
            (evidence / "completed-state.json").write_text(json.dumps(state, indent=2))
            if state["Running"] or state["ExitCode"] != 0 or state.get("OOMKilled"):
                raise ValueError("offline boundary fixture did not pass")
            last_line = result.stdout.splitlines()[-1]
            checks = json.loads(last_line)["checks"]
            if len(checks) != 16 or not all(v is True for v in checks.values()):
                raise ValueError("missing or failing boundary assertions")
            (evidence / "probe-sha256.txt").write_text(
                hashlib.sha256(source).hexdigest() + "\n"
            )
        except BaseException as error:
            failure = type(error).__name__
            if isinstance(error, (CommandFailure, subprocess.TimeoutExpired)):
                (evidence / "command-failure-stdout.bin").write_bytes(
                    (error.stdout or b"")[:MAX_OUTPUT]
                )
                (evidence / "command-failure-stderr.bin").write_bytes(
                    (error.stderr or b"")[:MAX_OUTPUT]
                )
                (evidence / "command-failure.json").write_text(
                    json.dumps(
                        {
                            "failure_type": failure,
                            "operation": error.operation
                            if isinstance(error, CommandFailure)
                            else error.cmd[:2],
                            "returncode": getattr(error, "returncode", None),
                            "truncated": getattr(error, "truncated", False),
                            "output_limit_bytes": MAX_OUTPUT,
                        },
                        indent=2,
                    )
                    + "\n"
                )
            raise
        finally:
            if cleanup_armed:
                absence_observed = reconcile_name(name, evidence)
            (evidence / "closeout.json").write_text(
                json.dumps(
                    {
                        "failure_type": failure,
                        "cleanup_armed": cleanup_armed,
                        "absence_observed": absence_observed,
                        "elapsed_seconds": time.monotonic() - started,
                        "image": IMAGE,
                        "scope": "offline boundary fixture only; no hook/gate/updater proof",
                    },
                    indent=2,
                )
                + "\n"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    options = parser.parse_args()
    run(options.evidence)
    print(
        "Offline isolation fixture complete. Evidence retained; no updater activated."
    )
