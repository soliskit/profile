"""Source-only fixed volume lifecycle. Not wired to a workflow or publisher.

Caller must pass a trusted bounded Docker executor and fixed reviewed Python
source buffers, derived native data and authenticated image/tool pins. No shell.
"""

import datetime
import json
import pathlib
import re
import uuid

IMAGE = "python@sha256:1faf2343e747208b2a36e5f2b5ff908ec3b2d0078a6a7bfe73b535698fe83909"


CONFIG_ID = "sha256:cbf5dca8bec69a91156f1c7f6a2ebb250816049b2dbee82184ac1f9bd55631ba"


def mountinfo_only_work(data):
    rows = data.decode("utf-8", "strict").splitlines()
    work = []
    for row in rows:
        left, right = row.split(" - ", 1)
        parts = left.split()
        mount = parts[4]
        if "\\" in mount:
            raise ValueError("escaped mountpoint unsupported")
        if mount == "/work":
            work.append((parts, right.split()))
        elif mount.startswith("/work/"):
            raise ValueError("nested mount")
    if len(work) != 1 or "ro" not in work[0][0][5].split(","):
        raise ValueError("single read-only work mount required")


def config_check(item, name, volume, role, expected_code, expected_source=None):
    config, host = item["Config"], item["HostConfig"]
    uid = "0:0" if role == "prepare" else "10001:10001"
    if config["Image"] != IMAGE or config["User"] != uid:
        raise ValueError("image or user differs")
    if config["WorkingDir"] != "/" or config["Entrypoint"] != [
        "/usr/local/bin/python3"
    ]:
        raise ValueError("interpreter or working directory differs")
    if config["Cmd"] != ["-I", "-S", "-c", expected_code]:
        raise ValueError("fixed isolated interpreter code differs")
    if item["Name"] != "/" + name or not host["ReadonlyRootfs"] or host["Privileged"]:
        raise ValueError("name or root policy differs")
    added = host["CapAdd"]
    allowed_add = (
        type(added) is list
        and len(added) == 1
        and type(added[0]) is str
        and added[0] in ("CHOWN", "CAP_CHOWN")
        if role == "prepare"
        else added is None or (type(added) is list and len(added) == 0)
    )
    if set(host["CapDrop"] or []) != {"ALL"} or not allowed_add:
        raise ValueError("capability policy differs")
    if (
        host["NetworkMode"] != "none"
        or host.get("PidMode")
        or host["IpcMode"] != "private"
    ):
        raise ValueError("namespace policy differs")
    security = host["SecurityOpt"]
    if (
        not isinstance(security, list)
        or len(security) != 1
        or security[0] not in {"no-new-privileges", "no-new-privileges=true"}
    ):
        raise ValueError("exact enabled no-new-privileges required")
    if any(host.get(k) for k in ["Devices", "Binds", "VolumesFrom", "GroupAdd"]):
        raise ValueError("host authority exposed")
    if (
        host["Memory"] != 268435456
        or host["PidsLimit"] != 64
        or host["NanoCpus"] != 1000000000
    ):
        raise ValueError("resource limits differ")
    if set(host.get("Tmpfs", {})) != {"/tmp"}:
        raise ValueError("unexpected writable temporary mount")
    mounts = item["Mounts"]
    if len(mounts) != 1:
        raise ValueError("unexpected mounts")
    m = mounts[0]
    if (m["Type"], m["Name"], m["Destination"], m["RW"]) != (
        "volume",
        volume,
        "/work",
        role == "prepare",
    ):
        raise ValueError("owned volume identity/access differs")
    if (
        expected_source is None
        or m["Source"] != expected_source
        or m["Driver"] != "local"
    ):
        raise ValueError("volume source/driver differs")
    env = dict(x.split("=", 1) for x in config["Env"])
    if any(k not in {"PATH", "LANG", "PYTHON_VERSION", "PYTHON_SHA256"} for k in env):
        raise ValueError("unexpected environment")


def create_args(name, volume, role, code):
    if role not in {"prepare", "inspect"} or not re.fullmatch(
        r"credit-volume-[0-9a-f]{32}", volume
    ):
        raise ValueError("fixed role/owned volume required")
    args = [
        "docker",
        "create",
        "--name",
        name,
        "--platform",
        "linux/amd64",
        "--user",
        "0:0" if role == "prepare" else "10001:10001",
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
        "--interactive",
        "--workdir",
        "/",
        "--entrypoint",
        "/usr/local/bin/python3",
        "--mount",
        "type=volume,src="
        + volume
        + ",dst=/work,volume-nocopy"
        + (",readonly" if role == "inspect" else ""),
    ]
    if role == "prepare":
        args += ["--cap-add", "CHOWN"]
    return [*args, IMAGE, "-I", "-S", "-c", code]


def completed_state(state):
    if state["Status"] != "exited" or any(
        state[k] for k in ("Running", "Paused", "Restarting", "OOMKilled", "Dead")
    ):
        raise ValueError("stage did not exit cleanly")
    if type(state["ExitCode"]) is not int or state["ExitCode"] != 0 or state["Error"]:
        raise ValueError("stage exit failure")
    times = []
    for key in ("StartedAt", "FinishedAt"):
        value = state[key]
        if not isinstance(value, str) or value.startswith("0001-"):
            raise ValueError("missing execution timestamp")
        stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.year < 2020:
            raise ValueError("invalid execution timestamp")
        times.append(stamp)
    if times[1] < times[0]:
        raise ValueError("execution timestamps reversed")


class Lifecycle:
    """No retries. Ambiguous creation arms cleanup before call, always HOLD.

    executor API: command(argv, data=None, timeout=..., allowed=(0,)) returns
    bounded raw stdout; nonzero/timeouts raise. No action occurs at construction.
    Volume cleanup is never forced. Concurrent consumers fail closed. Executor
    must serialize all operations for this owned volume and retain raw evidence.
    """

    def __init__(self, executor):
        self.command = executor
        self.volume = "credit-volume-" + uuid.uuid4().hex
        self.names = []
        self.volume_armed = False
        self.volume_removal_attempted = False
        self.mountpoint = None
        self.removal_attempted = set()
        self.cleanup_command = executor
        self.cleanup_failed = False

    def no_consumers(self):
        out = self.command(
            ["docker", "ps", "--all", "--quiet", "--filter", "volume=" + self.volume]
        )
        if out.strip():
            raise ValueError("concurrent volume consumer")
        ids = (
            self.command(["docker", "ps", "--all", "--quiet", "--no-trunc"])
            .decode()
            .splitlines()
        )
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in ids):
            raise ValueError("unexpected container identity")
        if ids:
            items = json.loads(self.command(["docker", "inspect", *ids]))
            for item in items:
                for mount in item["Mounts"]:
                    if mount.get("Name") == self.volume:
                        raise ValueError("volume alias consumer")
                    if self.mountpoint and mount.get("Source"):
                        source = pathlib.PurePosixPath(mount["Source"])
                        target = pathlib.PurePosixPath(self.mountpoint)
                        if (
                            source == target
                            or source in target.parents
                            or target in source.parents
                        ):
                            raise ValueError("source-path alias consumer")

    def create_volume(self):
        image = json.loads(self.command(["docker", "image", "inspect", IMAGE]))[0]
        if (
            image["Id"] != CONFIG_ID
            or image["Architecture"] != "amd64"
            or image["Os"] != "linux"
        ):
            raise ValueError("actual image configuration identity/platform differs")
        self.volume_armed = True
        self.command(["docker", "volume", "create", "--driver", "local", self.volume])
        v = json.loads(self.command(["docker", "volume", "inspect", self.volume]))[0]
        if (
            v["Name"] != self.volume
            or v["Driver"] != "local"
            or v.get("Options")
            or v["Scope"] != "local"
        ):
            raise ValueError("unexpected volume driver/options")
        point = pathlib.PurePosixPath(v["Mountpoint"])
        if (
            not point.is_absolute()
            or ".." in point.parts
            or str(point) != v["Mountpoint"]
        ):
            raise ValueError("volume source path invalid")
        self.mountpoint = str(point)
        self.no_consumers()

    def stage(self, role, code, data=None):
        self.no_consumers()
        name = "credit-" + role + "-" + uuid.uuid4().hex
        self.names.append(name)
        self.command(create_args(name, self.volume, role, code))
        item = json.loads(self.command(["docker", "inspect", name]))[0]
        config_check(item, name, self.volume, role, code, self.mountpoint)
        output = self.command(
            ["docker", "start", "--attach", "--interactive", name],
            data=data,
            timeout=60,
        )
        state = json.loads(self.command(["docker", "inspect", name]))[0]["State"]
        completed_state(state)
        self.remove_container(name)
        self.no_consumers()
        return output

    def remove_container(self, name):
        errors = []
        if name not in self.removal_attempted:
            self.removal_attempted.add(name)
            try:
                self.command(
                    ["docker", "rm", "--force", name], timeout=30, allowed=(0, 1)
                )
            except Exception as error:
                errors.append(type(error).__name__)
        try:
            if self.command(
                ["docker", "ps", "--all", "--quiet", "--filter", "name=^/" + name + "$"]
            ).strip():
                raise ValueError("container still present")
        except Exception as error:
            errors.append(type(error).__name__)
        if errors:
            raise RuntimeError("container removal or absence unresolved; HOLD")

    def cleanup(self):
        self.command = self.cleanup_command
        failures = []
        for name in reversed(self.names):
            try:
                self.remove_container(name)
            except Exception as error:
                failures.append(type(error).__name__)
        if self.volume_armed:
            safe_remove = False
            try:
                current = self.command(
                    [
                        "docker",
                        "volume",
                        "ls",
                        "--quiet",
                        "--filter",
                        "name=^" + self.volume + "$",
                    ]
                )
                if current.strip() and self.mountpoint is None:
                    record = json.loads(
                        self.command(["docker", "volume", "inspect", self.volume])
                    )[0]
                    if (
                        record["Name"] != self.volume
                        or record["Driver"] != "local"
                        or record.get("Options")
                        or record["Scope"] != "local"
                    ):
                        raise ValueError("ambiguous volume metadata differs")
                    point = pathlib.PurePosixPath(record["Mountpoint"])
                    if (
                        not point.is_absolute()
                        or ".." in point.parts
                        or str(point) != record["Mountpoint"]
                    ):
                        raise ValueError("ambiguous volume source differs")
                    self.mountpoint = str(point)
                self.no_consumers()
                safe_remove = True
            except Exception as error:
                failures.append(type(error).__name__)
            if safe_remove and not self.volume_removal_attempted:
                self.volume_removal_attempted = True
                try:
                    self.command(
                        ["docker", "volume", "rm", self.volume],
                        timeout=30,
                        allowed=(0, 1),
                    )
                except Exception as error:
                    failures.append(type(error).__name__)
            try:
                if self.command(
                    [
                        "docker",
                        "volume",
                        "ls",
                        "--quiet",
                        "--filter",
                        "name=^" + self.volume + "$",
                    ]
                ).strip():
                    raise ValueError("volume still present")
            except Exception as error:
                failures.append(type(error).__name__)
        if failures:
            self.cleanup_failed = True
        if self.cleanup_failed:
            raise RuntimeError("cleanup incomplete or earlier ambiguous; HOLD")
