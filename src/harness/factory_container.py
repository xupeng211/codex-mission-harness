"""Controller-only, offline dev-image validation. Never expose Docker to agents."""
from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .sandbox import SAFE_PATH


PROFILES = {("make", "verify-" + p): p for p in ("targeted", "pr", "strict")}
ENV = {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}


def validate_policy(policy):
    if (not isinstance(policy, dict) or set(policy) != {"image_id", "profiles"}
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(policy.get("image_id", "")))
            or not isinstance(policy.get("profiles"), list) or not policy["profiles"]
            or any(not isinstance(p, str) for p in policy["profiles"])
            or len(set(policy["profiles"])) != len(policy["profiles"])
            or any(p not in PROFILES.values() for p in policy["profiles"])):
        raise ValueError("container policy requires an exact local image ID and canonical profiles")
    return policy


def inspect_image(policy):
    validate_policy(policy)
    # Deliberately do not inspect/output Config.Env or contact a registry.
    value = subprocess.check_output(["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}",
                                     policy["image_id"]], env=ENV, stderr=subprocess.PIPE, timeout=15).decode().strip()
    if value != policy["image_id"]:
        raise ValueError("local dev image identity differs from Controller policy")
    return value


def source_fingerprint(cwd, head):
    from .factory_project import tracked_source_digest
    return tracked_source_digest(cwd, head)


def binding(spec, cwd, target):
    from .factory_project import verify_target
    verify_target(spec, cwd, target)
    return source_fingerprint(cwd, target["head"])


def argv_for(policy, workspace, name, profile):
    validate_policy(policy)
    if profile not in policy["profiles"]:
        raise ValueError("canonical validation profile is not authorized")
    return ["/usr/bin/docker", "run", "--pull=never", "--rm", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit=256", "--memory=4g", "--cpus=2",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g,mode=1777", "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
            "--mount", f"type=bind,src={workspace},dst=/app",
            "--mount", f"type=bind,src={workspace / '.git'},dst=/app/.git,readonly",
            "--workdir=/app", "--entrypoint=/usr/bin/env", policy["image_id"], "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8", "TZ=UTC",
            "PYTHONDONTWRITEBYTECODE=1", "DOCKER_DEV_CONTAINER=true", "GATEKEEPER_IN_CONTAINER=1",
            "npm_config_offline=true", "npm_config_fetch_retries=0", "PIP_NO_INDEX=1",
            "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/app",
            "python3", "scripts/devops/validation_profiles.py", profile]


def run(runtime, policy, spec, cwd, target, command, transcript, timeout):
    from .factory import git
    profile = PROFILES.get(tuple(command))
    if profile is None or profile not in validate_policy(policy)["profiles"]:
        raise ValueError("Controller container executor only accepts approved canonical profiles")
    image = inspect_image(policy)
    before = binding(spec, cwd, target)
    result = {"target": target, "mission_id": spec["mission_id"], "scope_sha256": target["mission_scope_sha256"],
              "image_id": image, "profile": profile, "fixture": False, "network": "none"}
    name = "cmh-validate-" + uuid.uuid4().hex
    started = time.monotonic()
    if runtime.container_cancel.is_set():
        raise RuntimeError("container execution cancelled before launch")
    with tempfile.TemporaryDirectory(prefix="cmh-validation-", dir=transcript.parent) as temporary:
        workspace = Path(temporary) / "source"
        git(cwd, "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", str(cwd), str(workspace))
        git(workspace, "remote", "remove", "origin")
        git(workspace, "checkout", "--detach", target["head"])
        git(workspace, "update-ref", "refs/remotes/origin/main", target["base"])
        # Copy only existing image dependencies to this disposable workspace.
        # Docker copy-out uses the invoking user's uid, unlike root-owned
        # anonymous volume copy-up. No package installation or image startup.
        dependency_name = name + "-dependencies"
        try:
            subprocess.run(["/usr/bin/docker", "create", "--pull=never", "--name", dependency_name,
                            "--network=none", "--entrypoint=/usr/bin/true", image], env=ENV, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            copied = subprocess.run(["/usr/bin/docker", "cp", dependency_name + ":/app/node_modules",
                                     str(workspace / "node_modules")], env=ENV, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=max(0.1, min(60, timeout)))
            result["image_node_dependencies_copied"] = copied.returncode == 0
        finally:
            cleanup = subprocess.run(["/usr/bin/docker", "rm", "--force", "--volumes", dependency_name], env=ENV,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            result["dependencies_cleanup_confirmed"] = cleanup.returncode == 0
            if cleanup.returncode:
                raise RuntimeError("dependency copy container cleanup could not be confirmed")
        snapshot = source_fingerprint(workspace, target["head"])
        argv = argv_for(policy, workspace, name, profile)
        argv[-3:-3] = ["BASE_REF=" + target["base"], "HEAD_REF=" + target["head"],
                       "MISSION_SCOPE_FILE=/app/" + target["mission_scope_file"]]
        result.update(argv=argv, container_name=name, source_before=before, snapshot_before=snapshot)
        with transcript.open("xb") as log:
            os.fchmod(log.fileno(), 0o600)
            proc = subprocess.Popen(argv, cwd=temporary, env=ENV, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            runtime.current_process = proc
            outcome = "EXITED"
            try:
                while proc.poll() is None:
                    if runtime.container_cancel.is_set():
                        outcome = "CANCELLED"
                        break
                    if time.monotonic() - started >= timeout:
                        outcome = "TIMEOUT"
                        break
                    time.sleep(0.05)
            finally:
                # Killing a Docker client alone does not stop its container.
                result.update(cleanup_confirmed=False, cleanup_exit_code=None)
                try:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                    cleanup = subprocess.run(["/usr/bin/docker", "rm", "--force", "--volumes", name], env=ENV,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                    result["cleanup_exit_code"] = cleanup.returncode
                    # A successful daemon query is required to prove absence.
                    names = subprocess.check_output(["/usr/bin/docker", "ps", "-a", "--filter", "name=^/" + name + "$",
                                                     "--format", "{{.Names}}"], env=ENV, stderr=subprocess.PIPE, timeout=15)
                    result["cleanup_confirmed"] = not names.strip()
                except (OSError, subprocess.SubprocessError):
                    pass
                finally:
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                    runtime.current_process = None
                if runtime.container_cancel.is_set():
                    outcome = "CANCELLED"
        try:
            after = binding(spec, cwd, target)
            snapshot_after = source_fingerprint(workspace, target["head"])
            unchanged = before == after and snapshot == snapshot_after and not git(workspace, "diff", "--name-only", "HEAD")
        except (OSError, ValueError, subprocess.SubprocessError):
            after, snapshot_after, unchanged = "NOT_VERIFIABLE", "NOT_VERIFIABLE", False
        result.update(exit_code=proc.returncode, outcome=outcome, source_after=after, snapshot_after=snapshot_after,
                      source_unchanged=unchanged, elapsed_seconds=round(time.monotonic() - started, 3))
        result["status"] = (outcome if outcome != "EXITED" else "SOURCE_CHANGED" if not unchanged else
                            "BLOCKED_ENVIRONMENT" if not result["cleanup_confirmed"] else "PASS" if proc.returncode == 0 else "FAIL")
    return result
