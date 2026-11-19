"""Read-only host inventory proposal. Not container or workload qualification.

Only main() reads the host. Tests inject inert bytes and fixture command results.
No package installation, sudo, Docker mutation, network client or cleanup API.
"""
import hashlib
import json
import os
import pathlib
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

TOTAL_SECONDS = 90
COMMAND_SECONDS = 5
COMMAND_BYTES = 65536
TOTAL_BYTES = 262144
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+:/=~-]{0,127}")
CONTROLLERS = {"cpu", "cpuset", "io", "memory", "pids", "hugetlb", "rdma", "misc", "dmem"}
COMMANDS = {
    "docker_client": ("/usr/bin/docker", "version", "--format", "{{json .Client.Version}}"),
    "docker_server": ("/usr/bin/docker", "version", "--format", "{{json .Server.Version}}"),
    "docker_fields": ("/usr/bin/docker", "info", "--format", '{{json .SecurityOptions}}|{{json .CgroupVersion}}|{{json .CgroupDriver}}|{{json .Driver}}'),
    "containerd": ("/usr/bin/containerd", "--version"),
    "runc": ("/usr/bin/runc", "--version"),
    "packages": ("/usr/bin/dpkg-query", "-W", "-f=${binary:Package}=${Version}\\n", "docker-ce", "docker-ce-cli", "containerd.io", "uidmap", "apparmor"),
}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent", "DOCKER_HOST": "unix:///var/run/docker.sock", "DOCKER_CONFIG": "/nonexistent"}


class BoundExceeded(RuntimeError):
    pass


class Budget:
    def __init__(self):
        self.start = time.monotonic()
        self.bytes = 0
        self.active = None

    def check(self):
        if time.monotonic() - self.start >= TOTAL_SECONDS:
            raise BoundExceeded("total-time")

    def consume(self, count):
        self.check()
        self.bytes += count
        if self.bytes > TOTAL_BYTES:
            raise BoundExceeded("total-bytes")

    def stop_active(self):
        if self.active is not None:
            try:
                os.killpg(self.active.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                self.active.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise BoundExceeded("child-reap")
            self.active = None


def bounded_command(label, budget):
    """Closed argv, new child group, bounded pipe drain, no raw stderr output."""
    budget.check()
    process = subprocess.Popen(COMMANDS[label], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, start_new_session=True, close_fds=True)
    budget.active = process
    data = bytearray()
    start = time.monotonic()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            budget.check()
            if time.monotonic() - start >= COMMAND_SECONDS:
                raise BoundExceeded("command-time")
            for key, _ in selector.select(timeout=0.05):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    break
                budget.consume(len(chunk))
                data.extend(chunk)
                if len(data) > COMMAND_BYTES:
                    raise BoundExceeded("command-bytes")
        code = process.wait(timeout=max(0.01, COMMAND_SECONDS - (time.monotonic() - start)))
        # Stop any process left in the owned child process group even if the
        # expected command exits while another group member closes the pipe.
        budget.stop_active()
        return code, bytes(data)
    except subprocess.TimeoutExpired as error:
        raise BoundExceeded("command-time") from error
    finally:
        selector.close()
        process.stdout.close()
        budget.stop_active()


def token(value):
    if type(value) is not str or not SAFE.fullmatch(value):
        raise ValueError("closed scalar grammar")
    return value


def numeric(raw):
    text = raw.decode("ascii").strip()
    if not re.fullmatch(r"[0-9]{1,12}", text):
        raise ValueError("numeric scalar")
    return int(text)


def controllers(raw):
    words = raw.decode("ascii").split()
    if len(words) > len(CONTROLLERS) or len(words) != len(set(words)) or set(words) - CONTROLLERS:
        raise ValueError("closed controller list")
    return sorted(words)


def subordinate_ranges(raw, username, uid):
    result = []
    for line in raw.decode("ascii").splitlines():
        fields = line.split(":")
        if len(fields) != 3:
            raise ValueError("subordinate record")
        if fields[0] in {username, str(uid)}:
            start, count = numeric(fields[1].encode()), numeric(fields[2].encode())
            if not count or start + count > 4294967296:
                raise ValueError("subordinate extent")
            result.append({"start": start, "count": count})
    if len(result) > 5:
        raise ValueError("bounded subordinate extents")
    return result


def parse_command(label, raw):
    text = raw.decode("ascii", "strict").strip()
    if label in {"docker_client", "docker_server"}:
        return token(json.loads(text))
    if label == "docker_fields":
        fields = text.split("|")
        if len(fields) != 4:
            raise ValueError("fixed Docker fields")
        security, cgroup, driver, storage = [json.loads(v) for v in fields]
        # Never print free-form security profile strings or paths. Only known
        # boolean flags survive; unexpected options stop this field.
        if type(security) is not list or len(security) > 8 or any(type(v) is not str for v in security):
            raise ValueError("security option shape")
        allowed = {"name=seccomp,profile=builtin", "name=seccomp,profile=default", "name=apparmor", "name=cgroupns", "name=rootless", "name=userns", "name=selinux"}
        if set(security) - allowed:
            raise ValueError("unrecognized Docker security option")
        return {"seccomp_listed": any(v.startswith("name=seccomp,") for v in security), "apparmor_listed": "name=apparmor" in security, "rootless_listed": "name=rootless" in security, "userns_listed": "name=userns" in security, "cgroup_version": token(cgroup), "cgroup_driver": token(driver), "storage_driver": token(storage)}
    if label == "packages":
        found = {}
        for line in text.splitlines():
            name, sep, value = line.partition("=")
            if not sep or name not in {"docker-ce", "docker-ce-cli", "containerd.io", "uidmap", "apparmor"} or name in found:
                raise ValueError("exact package list")
            found[name] = token(value)
        return found
    # Output only the fixed version group, never revision/path/runtime prose.
    patterns = {"containerd": r"containerd(?: github\.com/containerd/containerd)?\s+(v?[0-9][A-Za-z0-9_.+:-]*)", "runc": r"runc version\s+([0-9][A-Za-z0-9_.+:-]*)"}
    match = re.match(patterns[label], text)
    if not match:
        raise ValueError("known version format")
    return token(match[1])


def read_fixed(path, budget):
    budget.check()
    with open(path, "rb") as stream:
        raw = stream.read(COMMAND_BYTES + 1)
    budget.consume(len(raw))
    if len(raw) > COMMAND_BYTES:
        raise BoundExceeded("file-bytes")
    return raw


def file_metadata(path):
    info = pathlib.Path(path).stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("regular system binary")
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode))}


def main():
    budget = Budget()
    results, unavailable = {}, []

    def collect(label, operation):
        try:
            budget.check()
            results[label] = operation()
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            unavailable.append(label)

    def alarm(_signum, _frame):
        raise BoundExceeded("total-time")

    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(TOTAL_SECONDS)
    state = "INVENTORY_COLLECTED_NOT_QUALIFICATION"
    try:
        for key in ("ImageOS", "ImageVersion"):
            collect(key, lambda key=key: token(os.environ.get(key, "")))
        collect("architecture", lambda: token(os.uname().machine))
        collect("kernel", lambda: token(os.uname().release))
        def os_release():
            pairs = {}
            for line in read_fixed("/etc/os-release", budget).decode("ascii").splitlines():
                key, sep, value = line.partition("=")
                if sep and key in {"ID", "VERSION_ID"}:
                    if key in pairs:
                        raise ValueError("duplicate OS field")
                    pairs[key] = token(value.strip('"'))
            if set(pairs) != {"ID", "VERSION_ID"}:
                raise ValueError("OS identity absent")
            return pairs
        collect("os", os_release)
        for label in COMMANDS:
            def query(label=label):
                code, raw = bounded_command(label, budget)
                if code:
                    raise ValueError("command unavailable")
                return parse_command(label, raw)
            collect(label, query)
        for label, path in {"unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone", "max_user_namespaces": "/proc/sys/user/max_user_namespaces", "apparmor_restrict_unprivileged_userns": "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"}.items():
            collect(label, lambda path=path: numeric(read_fixed(path, budget)))
        def apparmor():
            value = read_fixed("/sys/module/apparmor/parameters/enabled", budget).strip()
            if value not in {b"Y", b"N"}:
                raise ValueError("AppArmor boolean")
            return value == b"Y"
        collect("apparmor_enabled", apparmor)
        collect("cgroup_root_controllers", lambda: controllers(read_fixed("/sys/fs/cgroup/cgroup.controllers", budget)))
        uid = os.getuid()
        for label, path in {"user_cgroup_controllers": f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers", "user_cgroup_subtree_control": f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/cgroup.subtree_control"}.items():
            collect(label, lambda path=path: controllers(read_fixed(path, budget)))
        for name in ("newuidmap", "newgidmap"):
            collect(name + "_metadata", lambda name=name: file_metadata("/usr/bin/" + name))
        username = pwd.getpwuid(uid).pw_name
        for name in ("subuid", "subgid"):
            collect(name + "_extents", lambda name=name: subordinate_ranges(read_fixed("/etc/" + name, budget), username, uid))
        def daemon_hash():
            path = shutil.which("dockerd", path="/usr/bin:/bin:/usr/sbin:/sbin")
            if path is None:
                raise ValueError("daemon binary unavailable")
            info = pathlib.Path(path).stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 128 * 1024 * 1024:
                raise ValueError("bounded daemon binary")
            h = hashlib.sha256()
            total = 0
            with open(path, "rb") as stream:
                while chunk := stream.read(65536):
                    budget.check()
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise BoundExceeded("daemon-binary-bytes")
                    h.update(chunk)
            return h.hexdigest()
        collect("daemon_sha256", daemon_hash)
        collect("temp_free_bytes", lambda: shutil.disk_usage("/tmp").free)
    except BoundExceeded:
        state = "INVENTORY_BOUND_HOLD"
    finally:
        signal.alarm(0)
        try:
            budget.stop_active()
            child_cleanup = "OWNED_COMMAND_GROUP_STOP_ATTEMPTED"
        except BoundExceeded:
            child_cleanup = "UNKNOWN"
            state = "INVENTORY_BOUND_HOLD"
    # This tool creates no result files, containers, daemons or volumes.
    print(json.dumps({"status": state, "facts": results, "unavailable": sorted(unavailable), "runtime_qualification": "NOT_PERFORMED", "child_cleanup": child_cleanup, "remapped_worker_created": False, "image_created": False}, sort_keys=True))
    return 0 if state == "INVENTORY_COLLECTED_NOT_QUALIFICATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
