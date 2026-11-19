"""Source-only hosted-runner route. Trusts host OS/daemon, not immutable attestation."""

import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import traceback
import types

PROVISION_SHA = "37b64bd3ea709cce08f11ae4e8443cc8eb4c65d2cb55fda81c016362263bcc6a"
PUBLIC_SHA = "ea5a63d67557554b95bed6e95dca6a50e39867ccb2d825f4ae313f8391f477a0"
SOURCE_PINS = {
    "shared_budget.py": "bcd9d0fe283e3e32a5d75764bbf7cbe1557d88f4c0d6f5e621f3033f82313d48",
    "volume_entry.py": "30e2368e50c4960ca51fe0160977bf6f7e396aaed1e005ed63f7540967087189",
    "volume_launch.py": "1760493efe1f4c94a8a991324ff44e38e845f38a1b8d8e2e5d1c4894b8544efb",
    "volume_invoke.py": "c394bc5b2fa94c8eab89f92fe5c96b853b1743657bd557ed749307e64f56a4e7",
    "volume_bootstrap.py": "d751b9126ad7b9eae0bdc186200383534339e685db45a063bae63e45ce831446",
    "bounded_executor.py": "388ba2f4cb4113230ec1bb9532c2a777dd7bb57453d221db441c67dbdf8e4280",
    "volume_driver.py": "7ef9851f90e594c160aa1dd3e8e131e18d58931edfd7e8ceb89084c7d3a9bf2b",
    "volume_lifecycle.py": "259c84edcd8f6d3ff3375d500604dc1920b9721a9ce038db04b3db61f10028f7",
    "source_contract.py": "5c8b0b330df7e3ddf6438981f089f3a67a678a685ebf0cf182cf53ddcb1f7ec5",
    "volume_stage.py": "924ad90eaf362eb355d481d4870155f0d3d4abad06131f9a6c86e430ad8552f2",
    "volume_reconcile.py": "1409db49e85132f8ad31332c22e96cba4d430ec6f53147660929b6aaa5a6adef",
    "public_evidence.py": "ea5a63d67557554b95bed6e95dca6a50e39867ccb2d825f4ae313f8391f477a0",
    "provision_executor.py": "37b64bd3ea709cce08f11ae4e8443cc8eb4c65d2cb55fda81c016362263bcc6a",
}

ROOT = pathlib.Path("/opt/credit-qualification")
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
GIT_ENV = {
    **ENV,
    "HOME": "/nonexistent",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
}
ENTRY_SHA = "30e2368e50c4960ca51fe0160977bf6f7e396aaed1e005ed63f7540967087189"
RECONCILE_SHA = "1409db49e85132f8ad31332c22e96cba4d430ec6f53147660929b6aaa5a6adef"
EXECUTOR_SHA = "388ba2f4cb4113230ec1bb9532c2a777dd7bb57453d221db441c67dbdf8e4280"
CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"


def protected(path):
    """Every resolved ancestor is root owned and not group/world writable."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("canonical protected route required")
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("protected root owner/ancestor required")
    return path


def verified_file(path, digest, executable=False):
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("deployment pin unresolved; HOLD")
    protected(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (executable and not info.st_mode & 0o111):
        raise ValueError("ordinary executable/source required")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("independently pinned source differs")
    return raw


def load_buffer(raw, path):
    module = types.ModuleType("fixed_route_" + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def save(path, record):
    payload = json.dumps(record, sort_keys=True).encode()
    if len(payload) > 65536:
        raise ValueError("route record bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def image_metadata(raw):
    if len(raw) > 65536:
        raise ValueError("image metadata bound")
    records = json.loads(raw)
    selected = [r for r in records if r.get("group") == "Runner Image"]
    if len(selected) != 1:
        raise ValueError("runner image metadata missing")
    fields = dict(line.split(": ", 1) for line in selected[0]["detail"].splitlines())
    if fields.get("Image") != "ubuntu-24.04" or not re.fullmatch(
        r"[0-9]{8}\.[0-9]+\.[0-9]+", fields.get("Version", "")
    ):
        raise ValueError("runner baseline differs")
    if not re.fullmatch(
        r"https://github.com/actions/runner-images/blob/ubuntu24/[0-9]{8}\.[0-9]+/images/ubuntu/Ubuntu2404-Readme.md",
        fields.get("Included Software", ""),
    ):
        raise ValueError("exact included software link missing")
    if not re.fullmatch(
        r"https://github.com/actions/runner-images/releases/tag/ubuntu24%2[Ff][0-9]{8}\.[0-9]+",
        fields.get("Image Release", ""),
    ):
        raise ValueError("exact image release link missing")
    return {
        key: fields[key]
        for key in ("Image", "Version", "Included Software", "Image Release")
    }


def validate_host():
    if dict(os.environ) != ENV or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("exact isolated process environment required")
    python = pathlib.Path("/usr/bin/python3").resolve(strict=True)
    if pathlib.Path(sys.executable).resolve() != python or sys.version_info[:2] != (
        3,
        12,
    ):
        raise ValueError("system interpreter baseline differs")
    tools = {}
    for label, path in (
        ("python", python),
        ("git", pathlib.Path("/usr/bin/git")),
        ("docker", pathlib.Path("/usr/bin/docker")),
    ):
        protected(path)
        if not stat.S_ISREG(path.stat().st_mode) or not path.stat().st_mode & 0o111:
            raise ValueError("system executable required")
        tools[label] = {
            "path": str(path),
            "observed_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    git = subprocess.run(
        ["/usr/bin/git", "--version"],
        env=GIT_ENV,
        cwd="/",
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout.decode()
    if not re.fullmatch(r"git version 2\.[0-9]+\.[0-9]+\n", git):
        raise ValueError("Git baseline version differs")
    tools["git"]["version"] = git.strip()
    tools["python"]["version"] = ".".join(map(str, sys.version_info[:3]))
    metadata = pathlib.Path("/imagegeneration/imagedata.json")
    protected(metadata)
    return {
        "trust": "GitHub hosted ubuntu-24.04 OS and daemon baseline; hashes are observations, not immutable attestation",
        "image": image_metadata(metadata.read_bytes()),
        "tools": tools,
        "official_versions_comparison": "REQUIRED before runtime qualification, using this job's Included Software and Image Release",
    }


def provision_native(parent, budget):
    source = ROOT / "source"
    module = load_buffer(
        verified_file(source / "provision_executor.py", PROVISION_SHA),
        source / "provision_executor.py",
    )
    commands = [
        [
            "/usr/bin/git",
            "init",
            "--template=",
            "--initial-branch=qualification",
            str(ROOT / "native"),
        ],
        [
            "/usr/bin/git",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-C",
            str(ROOT / "native"),
            "fetch",
            "--no-tags",
            "--depth=1",
            "https://github.com/soliskit/profile.git",
            "06bb4c1ac45ed85c46b75f08d0629464cf37c707",
        ],
    ]
    for number, command in enumerate(commands):
        args = [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/env",
            "-i",
            *[k + "=" + v for k, v in GIT_ENV.items()],
            *command,
        ]
        module.run(args, parent / ("provision-" + str(number)), ENV, budget, save)


def native_route(repo):
    protected(repo)
    gitdir = repo / ".git"
    protected(gitdir)
    if (gitdir / "config").read_bytes() != CONFIG:
        raise ValueError("fixed native repository config differs")
    paths = list(gitdir.rglob("*"))
    if len(paths) > 20000:
        raise ValueError("native repository file count bound")
    for path in paths:
        protected(path)
        if not (path.is_file() or path.is_dir()):
            raise ValueError("native repository ordinary objects required")
    if (gitdir / "objects/info/alternates").exists() or (
        gitdir / "info/grafts"
    ).exists():
        raise ValueError("external native object routes unsupported")


def reconcile(source, parent, entry, budget):
    module = load_buffer(
        verified_file(source / "volume_reconcile.py", RECONCILE_SHA),
        source / "volume_reconcile.py",
    )
    executor_module = load_buffer(
        verified_file(source / "bounded_executor.py", EXECUTOR_SHA),
        source / "bounded_executor.py",
    )
    binary = protected(pathlib.Path("/usr/bin/docker"))
    observed_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    executor = executor_module.Executor(
        binary,
        observed_sha,
        parent / "reconcile-private-evidence",
        {**ENV, "HOME": "/nonexistent"},
        budget=budget,
    )

    def readonly(args):
        if not (
            (
                len(args) == 6
                and args[:5] == ["docker", "ps", "--all", "--quiet", "--filter"]
                and re.fullmatch(
                    r"name=\^/credit-(prepare|inspect)-[0-9a-f]{32}\$", args[5]
                )
            )
            or (
                len(args) == 6
                and args[:5] == ["docker", "volume", "ls", "--quiet", "--filter"]
                and re.fullmatch(r"name=\^credit-volume-[0-9a-f]{32}\$", args[5])
            )
        ):
            raise ValueError("read-only reconciliation scope differs")
        return executor(args, timeout=10)

    record = module.reconcile_namespaces(parent, readonly)
    save(parent / "reconciliation.json", record)
    return record


def reconciliation_clean(parent):
    path = parent / "reconciliation.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        return False
    value = json.loads(path.read_bytes())
    namespaces = value.get("namespaces", [])
    if len(namespaces) != 2 or [x.get("namespace") for x in namespaces] != [
        "pull-private-evidence",
        "volume-private-evidence",
    ]:
        return False
    if namespaces[0].get("status") != "no-owned-journal-not-proof-of-no-create":
        return False
    resources = namespaces[1].get("observation", {}).get("resources", [])
    return (
        len(resources) == 3
        and sorted(x.get("kind") for x in resources)
        == ["container", "container", "volume"]
        and all(x.get("present") is False and "error_type" not in x for x in resources)
    )


def public_summary(parent):
    """Fixed synthetic facts only, never raw streams/argv/env/paths/tracebacks."""
    closeout = parent / "launch-closeout.json"
    foreground = parent / "foreground.json"
    launch_pass = (
        closeout.is_file() and json.loads(closeout.read_bytes()).get("status") == "PASS"
    )
    foreground_pass = (
        foreground.is_file()
        and json.loads(foreground.read_bytes()).get("status") == "PASS"
    )
    reconciled = reconciliation_clean(parent)
    return {
        "status": "PASS" if launch_pass and foreground_pass and reconciled else "HOLD",
        "launch_closeout_pass": launch_pass,
        "foreground_pass": foreground_pass,
        "owned_resources_observed_absent": reconciled,
        "scope": "fixed native tree preparation and inspection only; original updater not executed; prevention not installed",
        "runtime_review": "required; exact job image report/version comparison and full runtime qualification not implied",
        "signal_death_cleanup_guaranteed": False,
    }


def publish_bundle(parent):
    output = parent / "public-evidence"
    output.mkdir(mode=0o700)
    initial = {"summary.json": public_summary(parent)}
    baseline = parent / "host-baseline.json"
    if baseline.is_file():
        value = json.loads(baseline.read_bytes())
        image = value["image"]
        raw = json.dumps(
            [
                {
                    "group": "Runner Image",
                    "detail": "\n".join(k + ": " + str(v) for k, v in image.items()),
                }
            ]
        ).encode()
        initial["image.json"] = image_metadata(raw)
        tools = value["tools"]
        allowed = {
            "git": "/usr/bin/git",
            "docker": "/usr/bin/docker",
            "python": "/usr/bin/python3.12",
        }
        if set(tools) != set(allowed):
            raise ValueError("tool observation schema differs")
        selected = {}
        for label, expected in allowed.items():
            item = tools[label]
            if item.get("path") != expected or not re.fullmatch(
                r"[0-9a-f]{64}", item.get("observed_sha256", "")
            ):
                raise ValueError("fixed tool observation differs")
            selected[label] = {
                "path": expected,
                "observed_sha256": item["observed_sha256"],
            }
            if label != "docker":
                version = item.get("version", "")
                pattern = (
                    r"git version 2\.[0-9]+\.[0-9]+"
                    if label == "git"
                    else r"3\.12\.[0-9]+"
                )
                if not re.fullmatch(pattern, version):
                    raise ValueError("tool version differs")
                selected[label]["version"] = version
        initial["tools.json"] = {
            "scope": "trusted host baseline observations, not immutable attestation",
            "tools": selected,
        }
    source = ROOT / "source"
    builder = load_buffer(
        verified_file(source / "public_evidence.py", PUBLIC_SHA),
        source / "public_evidence.py",
    )
    life = load_buffer(
        verified_file(
            source / "volume_lifecycle.py", SOURCE_PINS["volume_lifecycle.py"]
        ),
        source / "volume_lifecycle.py",
    )
    driver = load_buffer(
        verified_file(source / "volume_driver.py", SOURCE_PINS["volume_driver.py"]),
        source / "volume_driver.py",
    )
    stage = verified_file(source / "volume_stage.py", SOURCE_PINS["volume_stage.py"])
    prepare, inspector = driver.fixed_code(stage, SOURCE_PINS["volume_stage.py"])
    policy = {
        "image": life.IMAGE,
        "pull": ["docker", "pull", "--platform", "linux/amd64", life.IMAGE],
        "create": life.create_args,
        "prepare": prepare,
        "inspect": inspector,
    }
    builder.build(parent, output, SOURCE_PINS, policy=policy, initial=initial)
    return 0


def main(argv):
    if argv not in (["qualify"], ["reconcile"], ["bundle"]):
        raise ValueError("only fixed route accepted")
    protected(ROOT / "source")
    parent = ROOT / "evidence"
    if (
        parent.resolve(strict=True) != parent
        or parent.stat().st_uid != os.getuid()
        or stat.S_IMODE(parent.stat().st_mode) != 0o700
    ):
        raise ValueError("trusted runner-owned private evidence route required")
    source = ROOT / "source"
    entry = load_buffer(
        verified_file(source / "volume_entry.py", ENTRY_SHA), source / "volume_entry.py"
    )
    budget_module = entry.verified(source / "shared_budget.py", entry.BUDGET_SHA)
    budget = budget_module.Budget(
        normal_seconds=480 if argv == ["qualify"] else 90, cleanup_seconds=240
    )

    def operation(shared):
        baseline = validate_host()
        if argv == ["bundle"]:
            return publish_bundle(parent)
        if argv == ["reconcile"]:
            reconcile(source, parent, entry, shared)
            return 0
        if list(parent.iterdir()):
            raise ValueError("fresh qualification evidence required")
        save(parent / "host-baseline.json", baseline)
        provision_native(parent, shared)
        native_route(ROOT / "native")
        launcher = entry.verified(source / "volume_launch.py", entry.LAUNCH_SHA)
        launcher.launch(source, ROOT / "native", parent, budget=shared)
        return 0

    try:
        result = entry.run_entry(budget, operation)
    except BaseException as error:
        # Local-only bounded traceback. Never selected into the upload bundle.
        try:
            save(
                parent / (argv[0] + "-failure.json"),
                {
                    "status": "HOLD",
                    "error_type": type(error).__name__,
                    "traceback": "".join(
                        traceback.format_exception(
                            type(error), error, error.__traceback__
                        )
                    )[:32768],
                },
            )
        except Exception:
            pass
        raise
    if argv == ["qualify"]:
        save(parent / "foreground.json", {"status": "PASS", "signal_restored": True})
    return result


def fixed_failure():
    return {"status": "HOLD", "classification": "route_failure"}


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception:
        sys.stderr.write(json.dumps(fixed_failure()) + "\n")
        raise SystemExit(1) from None
