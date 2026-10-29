"""Controller-only, offline dev-image validation. Never expose Docker to agents."""
from __future__ import annotations

import os
import json
import math
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .sandbox import SAFE_PATH
from .factory_test_service import ProjectPostgres, ExecutionStopped


PROFILES = {("make", "verify-" + p): p for p in ("targeted", "pr", "strict")}
ENV = {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}


class RedactedOutput:
    """Persist only sanitized bytes; retain a bounded possible password prefix.

    This handles only the Controller's known ephemeral test password, not
    arbitrary secrets. SIGKILL can lose a short pending suffix, never persist it.
    """
    def __init__(self, stream, password=None):
        self.stream, self.password, self.pending = stream, password, b""

    def write(self, data):
        data = self.pending + data
        self.pending = b""
        if self.password:
            while (index := data.find(self.password)) >= 0:
                self.stream.write(data[:index] + b"[TEST_PASSWORD_REDACTED]")
                data = data[index + len(self.password):]
            for size in range(min(len(data), len(self.password) - 1), 0, -1):
                if data.endswith(self.password[:size]):
                    self.pending, data = data[-size:], data[:-size]
                    break
        self.stream.write(data)
        self.stream.flush()

    def finish(self):
        # A truncated final password prefix is not useful diagnostic content.
        if self.pending:
            self.stream.write(b"[TEST_PASSWORD_REDACTED]")
            self.pending = b""
        self.stream.flush()


def consume_output(proc, output, cancel, deadline):
    """One bounded Controller pipe; the child never receives a log file fd."""
    eof = False
    while True:
        if not eof and select.select([proc.stdout], [], [], 0.05)[0]:
            data = os.read(proc.stdout.fileno(), 65536)
            if data:
                output.write(data)
            else:
                eof = True
        elif eof:
            cancel.wait(0.05)
        if cancel.is_set():
            raise ExecutionStopped("CANCELLED")
        if time.monotonic() >= deadline:
            raise ExecutionStopped("TIMEOUT")
        if eof and proc.poll() is not None:
            return


def check_stopped(cancel, deadline):
    if cancel.is_set():
        raise ExecutionStopped("CANCELLED")
    if time.monotonic() >= deadline:
        raise ExecutionStopped("TIMEOUT")


def prepare_dependencies(runtime, argv, cwd, log, cancel, deadline):
    """A preparation client belongs to the same execution as validation."""
    with runtime._execution_lock:
        check_stopped(cancel, deadline)
        if runtime.container_cancel is not cancel:
            raise ExecutionStopped("CANCELLED")
        proc = subprocess.Popen(argv, cwd=cwd, env=ENV, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        runtime.current_process = proc
    output = RedactedOutput(log)
    try:
        consume_output(proc, output, cancel, deadline)
    finally:
        try:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=5)
        finally:
            try:
                proc.stdout.close()
                output.finish()
            finally:
                with runtime._execution_lock:
                    if runtime.current_process is proc:
                        runtime.current_process = None
    return proc.returncode


def validate_policy(policy):
    if (not isinstance(policy, dict) or set(policy) - {"image_id", "profiles", "postgres_image_id"}
            or not {"image_id", "profiles"} <= set(policy)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(policy.get("image_id", "")))
            or ("postgres_image_id" in policy and not re.fullmatch(r"sha256:[0-9a-f]{64}", str(policy["postgres_image_id"])))
            or not isinstance(policy.get("profiles"), list) or not policy["profiles"]
            or any(not isinstance(p, str) for p in policy["profiles"])
            or len(set(policy["profiles"])) != len(policy["profiles"])
            or any(p not in PROFILES.values() for p in policy["profiles"])):
        raise ValueError("container policy requires an exact local image ID and canonical profiles")
    return policy


def inspect_image(policy):
    validate_policy(policy)
    # Deliberately do not inspect/output Config.Env or contact a registry.
    for key in ("image_id", "postgres_image_id"):
        if key not in policy:
            continue
        value = subprocess.check_output(["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}",
                                         policy[key]], env=ENV, stderr=subprocess.PIPE, timeout=15).decode().strip()
        if value != policy[key]:
            raise ValueError("local image identity differs from Controller policy")
    return policy["image_id"]


def source_fingerprint(cwd, head):
    from .factory_project import tracked_source_digest
    return tracked_source_digest(cwd, head)


def binding(spec, cwd, target):
    from .factory_project import verify_target
    verify_target(spec, cwd, target)
    return source_fingerprint(cwd, target["head"])


def argv_for(policy, workspace, name, profile, lifetime=900):
    validate_policy(policy)
    if profile not in policy["profiles"] or type(lifetime) is not int or not 1 <= lifetime <= 86400:
        raise ValueError("canonical validation profile is not authorized")
    return ["/usr/bin/docker", "run", "--pull=never", "--rm", "--name", name,
            "--log-driver=none",
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit=256", "--memory=4g", "--cpus=2",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g,mode=1777", "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
            "--mount", f"type=bind,src={workspace},dst=/app",
            "--mount", f"type=bind,src={workspace / '.git'},dst=/app/.git,readonly",
            "--workdir=/app", "--entrypoint=/usr/bin/env", policy["image_id"], "-i",
            "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8", "TZ=UTC",
            "PYTHONDONTWRITEBYTECODE=1", "DOCKER_DEV_CONTAINER=true", "GATEKEEPER_IN_CONTAINER=1",
            "npm_config_offline=true", "npm_config_fetch_retries=0", "PIP_NO_INDEX=1",
            "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/app",
            "/usr/bin/timeout", "--signal=TERM", "--kill-after=5", str(lifetime),
            "python3", "scripts/devops/validation_profiles.py", profile]


def remove_owned(name, owner, expected_labels=None):
    """Never delete a different task's container, including after lost responses."""
    def query(*args, timeout=15):
        return subprocess.check_output(["/usr/bin/docker", *args], env=ENV, stderr=subprocess.PIPE, timeout=timeout)
    try:
        args = ("ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
        if not query(*args).strip():
            return True, None
        labels = json.loads(query("inspect", "--format", "{{json .Config.Labels}}", name))
        expected = expected_labels or {"cmh.validation.owner": owner}
        if not isinstance(labels, dict) or any(labels.get(k) != v for k, v in expected.items()):
            return False, None
        cleanup = subprocess.run(["/usr/bin/docker", "rm", "--force", "--volumes", name], env=ENV,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        # --rm can already be removing this same container after cancellation.
        # Never repeat deletion; require positive absence within a finite grace.
        end = time.monotonic() + 2
        while query(*args, timeout=max(0.05, end - time.monotonic())).strip():
            if time.monotonic() >= end:
                return False, cleanup.returncode
            time.sleep(0.05)
        return True, cleanup.returncode
    except (OSError, ValueError, subprocess.SubprocessError):
        return False, None


def resources_for(name, spec, target, needs_postgres):
    labels = {"cmh.validation.owner": name, "cmh.validation.mission": spec["mission_id"],
              "cmh.validation.head": target["head"], "cmh.validation.scope": target["mission_scope_sha256"]}
    resources = [{"name": n, "labels": labels} for n in (name, name + "-dependencies")]
    if needs_postgres:
        resources.append({"name": name + "-postgres", "labels": {
            "cmh.qa.owner": (name + "-postgres").removeprefix("cmh-validate-"),
            "cmh.qa.mission": spec["mission_id"], "cmh.qa.head": target["head"],
            "cmh.qa.scope": target["mission_scope_sha256"]}})
    return resources


def recover(policy, spec, target, command, transcript):
    """One-shot cleanup on resume; never retry validation or settle its UNKNOWN."""
    path = Path(transcript).with_suffix(".container.json")
    result = {"target": target, "mission_id": spec["mission_id"], "cleanup_confirmed": False,
              "operation_replayed": False, "resources": []}
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 65536):
            raise ValueError("untrusted container lifecycle record")
        record = json.loads(path.read_text())
        name = record["container_name"]
        profile = PROFILES.get(tuple(command))
        if (not re.fullmatch(r"cmh-validate-[a-f0-9]{32}", name)
                or record["target"] != target or record["mission_id"] != spec["mission_id"]
                or record["policy"] != validate_policy(policy) or record["profile"] != profile
                or profile not in policy["profiles"]):
            raise ValueError("container recovery task/candidate/policy mismatch")
        expected = resources_for(name, spec, target, profile in {"pr", "strict"})
        if record["resources"] != expected:
            raise ValueError("container recovery resource binding mismatch")
        temporary = Path(record["temporary_directory"])
        if (temporary.parent != path.parent or not re.fullmatch(r"cmh-validation-[a-z0-9_]{8}", temporary.name)
                or temporary.is_symlink()):
            raise ValueError("temporary directory escaped operation evidence root")
        # Check directory ownership before any deletion, including parent cleanup.
        if temporary.exists():
            info = temporary.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("temporary directory ownership mismatch")
        for resource in expected:
            cleaned, code = remove_owned(resource["name"], name, resource["labels"])
            result["resources"].append({"name": resource["name"], "cleanup_confirmed": cleaned, "exit_code": code})
        result["cleanup_confirmed"] = all(r["cleanup_confirmed"] for r in result["resources"])
        if result["cleanup_confirmed"] and temporary.exists():
            shutil.rmtree(temporary)
        result["temporary_directory_cleanup_confirmed"] = not temporary.exists()
        result["cleanup_confirmed"] &= result["temporary_directory_cleanup_confirmed"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["error_type"] = type(error).__name__
    return result


def run(runtime, policy, spec, cwd, target, command, transcript, timeout):
    from .factory import git
    profile = PROFILES.get(tuple(command))
    if profile is None or profile not in validate_policy(policy)["profiles"]:
        raise ValueError("Controller container executor only accepts approved canonical profiles")
    needs_postgres = profile in {"pr", "strict"}
    if needs_postgres and "postgres_image_id" not in policy:
        raise ValueError("canonical pr/strict requires a pinned isolated test PostgreSQL image")
    image = inspect_image(policy)
    before = binding(spec, cwd, target)
    result = {"target": target, "mission_id": spec["mission_id"], "scope_sha256": target["mission_scope_sha256"],
              "image_id": image, "profile": profile, "fixture": False, "network": "none",
              "container_policy": policy, "services": {}}
    name = "cmh-validate-" + uuid.uuid4().hex
    resources = resources_for(name, spec, target, needs_postgres)
    started = time.monotonic()
    deadline = started + timeout
    cancel = runtime.container_cancel
    if cancel.is_set():
        raise RuntimeError("container execution cancelled before launch")
    with tempfile.TemporaryDirectory(prefix="cmh-validation-", dir=transcript.parent) as temporary:
        workspace = Path(temporary) / "source"
        git(cwd, "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", str(cwd), str(workspace))
        git(workspace, "remote", "remove", "origin")
        git(workspace, "checkout", "--detach", target["head"])
        git(workspace, "update-ref", "refs/remotes/origin/main", target["base"])
        service, proc, output = None, None, None
        outcome = "EXITED"
        result.update(container_name=name, source_before=before, cleanup_confirmed=False, exit_code=None)
        with transcript.open("x+b") as log:
            os.fchmod(log.fileno(), 0o600)
            # Durable plan precedes the first Docker dispatch. An interrupted
            # Controller can identify only its exact operation's resources.
            record = {"target": target, "mission_id": spec["mission_id"], "policy": policy,
                      "profile": profile, "container_name": name, "resources": resources,
                      "temporary_directory": temporary}
            lifecycle = transcript.with_suffix(".container.json")
            with lifecycle.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(json.dumps(record, sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
            result["lifecycle_record"] = str(lifecycle)
            try:
                dependency_name = name + "-dependencies"
                try:
                    labels = [v for k, value in resources[1]["labels"].items() for v in ("--label", k + "=" + value)]
                    create = ["/usr/bin/docker", "create", "--pull=never", "--name", dependency_name, *labels,
                              "--network=none", "--entrypoint=/usr/bin/true", image]
                    if prepare_dependencies(runtime, create, temporary, log, cancel,
                                            min(deadline, time.monotonic() + 15)):
                        raise RuntimeError("dependency copy container could not start")
                    copied = prepare_dependencies(runtime,
                        ["/usr/bin/docker", "cp", dependency_name + ":/app/node_modules", str(workspace / "node_modules")],
                        temporary, log, cancel, min(deadline, time.monotonic() + 60))
                    result["image_node_dependencies_copied"] = copied == 0
                finally:
                    cleaned, code = remove_owned(dependency_name, name, resources[1]["labels"])
                    result.update(dependencies_cleanup_confirmed=cleaned, dependencies_cleanup_exit_code=code)
                    if not cleaned:
                        raise RuntimeError("dependency copy container cleanup could not be confirmed")
                check_stopped(cancel, deadline)
                snapshot = source_fingerprint(workspace, target["head"])
                result["snapshot_before"] = snapshot
                lifetime = max(1, math.ceil(deadline - time.monotonic()))
                result.update(lifetime_limit_seconds=lifetime, lifetime_kill_grace_seconds=5)
                argv = argv_for(policy, workspace, name, profile, lifetime)
                index = argv.index("/usr/bin/timeout")
                argv[index:index] = ["BASE_REF=" + target["base"], "HEAD_REF=" + target["head"],
                               "MISSION_SCOPE_FILE=/app/" + target["mission_scope_file"]]
                index = argv.index("--workdir=/app")
                argv[index:index] = [v for k, value in resources[0]["labels"].items() for v in ("--label", k + "=" + value)]
                if needs_postgres:
                    service = ProjectPostgres(policy["postgres_image_id"], name + "-postgres", Path(temporary),
                                              target, spec["mission_id"], cancel, deadline, ENV, log)
                    result["services"]["postgres"] = service.evidence
                    service.start()
                    service.check()
                    argv = service.validation_argv(argv)
                    result["network"] = "none_shared_loopback"
                check_stopped(cancel, deadline)
                lifetime = max(1, math.ceil(deadline - time.monotonic()))
                argv[argv.index("--kill-after=5") + 1] = str(lifetime)
                result["lifetime_limit_seconds"] = lifetime
                result["argv"] = argv
                output = RedactedOutput(log, service.password.encode() if service else None)
                with runtime._execution_lock:
                    check_stopped(cancel, deadline)
                    if runtime.container_cancel is not cancel:
                        raise ExecutionStopped("CANCELLED")
                    proc = subprocess.Popen(argv, cwd=temporary, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            start_new_session=True)
                    runtime.current_process = proc
                consume_output(proc, output, cancel, deadline)
            except ExecutionStopped as error:
                outcome = error.outcome
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                outcome = "BLOCKED_ENVIRONMENT"
                result["error_type"] = type(error).__name__
                log.write(("Controller execution failed: " + type(error).__name__ + "\n").encode())
            finally:
                try:
                    if proc is not None:
                        if proc.poll() is None:
                            os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=5)
                        result["exit_code"] = proc.returncode
                finally:
                    try:
                        if proc is not None and proc.stdout is not None:
                            proc.stdout.close()
                        if output is not None:
                            output.finish()
                    finally:  # A broken log sink must not bypass resource cleanup.
                        with runtime._execution_lock:
                            if runtime.current_process is proc:
                                runtime.current_process = None
                        cleaned, code = remove_owned(name, name, resources[0]["labels"])
                        result.update(cleanup_confirmed=cleaned, cleanup_exit_code=code)
                        if service is not None:
                            service.close()
                            result["cleanup_confirmed"] &= service.evidence["cleanup_confirmed"]
                            result["ephemeral_password_redacted"] = True
                if cancel.is_set():
                    outcome = "CANCELLED"
        try:
            after = binding(spec, cwd, target)
            snapshot_after = source_fingerprint(workspace, target["head"])
            unchanged = (before == after and result.get("snapshot_before") == snapshot_after
                         and not git(workspace, "diff", "--name-only", "HEAD"))
        except (OSError, ValueError, subprocess.SubprocessError):
            after, snapshot_after, unchanged = "NOT_VERIFIABLE", "NOT_VERIFIABLE", False
        # 137 can also be OOM or an unrelated SIGKILL; do not invent a
        # timeout diagnosis without the Controller deadline or exit 124.
        if outcome == "EXITED" and result["exit_code"] == 124:
            outcome = "TIMEOUT"
        result.update(outcome=outcome, source_after=after, snapshot_after=snapshot_after,
                      source_unchanged=unchanged, elapsed_seconds=round(time.monotonic() - started, 3))
        result["status"] = (outcome if outcome != "EXITED" else "SOURCE_CHANGED" if not unchanged else
                            "BLOCKED_ENVIRONMENT" if not result["cleanup_confirmed"] else
                            "PASS" if result["exit_code"] == 0 else "FAIL")
    result["temporary_directory_cleanup_confirmed"] = not Path(temporary).exists()
    if not result["temporary_directory_cleanup_confirmed"] and result["status"] == "PASS":
        result["status"] = "BLOCKED_ENVIRONMENT"
    return result
