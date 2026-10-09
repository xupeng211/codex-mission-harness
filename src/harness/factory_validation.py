"""Controller-only FootballPrediction profile execution, never candidate Compose."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from .factory_preflight import _git_environment, _read_git
from .sandbox import SAFE_PATH


RESOURCE_CAPABILITIES = ("CpuCfsPeriod", "CpuCfsQuota", "MemoryLimit", "SwapLimit", "PidsLimit")


class ValidationCleanupError(RuntimeError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_policy(policy):
    fields = {"image", "postgres_image", "cpus", "memory_mb", "pids", "tmpfs_mb"}
    if not isinstance(policy, dict) or set(policy) != fields:
        raise ValueError("validation requires the fixed Controller container policy")
    for key in ("image", "postgres_image"):
        if not isinstance(policy[key], str) or not re.fullmatch(r"[a-zA-Z0-9./_-]+@sha256:[0-9a-f]{64}", policy[key]):
            raise ValueError("validation images must be immutable repository digests")
    for key, low, high in (("cpus", 1, 4), ("memory_mb", 256, 8192), ("pids", 32, 512), ("tmpfs_mb", 64, 4096)):
        if type(policy[key]) is not int or not low <= policy[key] <= high:
            raise ValueError("invalid validation resource limit: " + key)
    return policy


def profile_for(command):
    if command not in (["make", "verify-targeted"], ["make", "verify-pr"], ["make", "verify-strict"]):
        raise ValueError("trusted validation only accepts canonical profiles without overrides")
    return command[1].removeprefix("verify-")


class DockerExecutor:
    """Fixed local daemon transport. No Docker config, environment or flags from code."""
    fixture = False

    def call(self, *args, timeout=30):
        # Ignore DOCKER_HOST/context and all inherited credentials/proxies.
        return subprocess.check_output(
            ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", *args],
            env={"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8"},
            stderr=subprocess.STDOUT if args[0] == "logs" else subprocess.PIPE, timeout=timeout)

    def capture(self, container, path, timeout, cancelled):
        # Direct attachment avoids daemon log rotation silently losing earlier
        # output. Only a completed stream can establish complete logs.
        deadline = time.monotonic() + timeout
        with Path(path).open("xb") as log:
            proc = subprocess.Popen(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "start", "--attach", container],
                env={"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8"}, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while proc.poll() is None:
                    if cancelled():
                        raise InterruptedError("validation cancelled")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("validation execution timed out")
                    if Path(path).stat().st_size > 64 * 1024 * 1024:
                        raise RuntimeError("validation log bound exceeded; output is incomplete")
                    time.sleep(0.1)
                if Path(path).stat().st_size > 64 * 1024 * 1024:
                    raise RuntimeError("validation log bound exceeded; output is incomplete")
                return proc.returncode
            finally:
                if proc.poll() is None:
                    import signal
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                log.flush()
                os.fsync(log.fileno())


def limits(policy):
    return ["--cpus", str(policy["cpus"]), "--memory", f"{policy['memory_mb']}m",
            "--memory-swap", f"{policy['memory_mb']}m", "--pids-limit", str(policy["pids"]),
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
            "--restart=no", "--log-driver=none"]


def check_resource_environment(info):
    # Docker reports kernel/cgroup support separately from requested flags.
    # Unknown/missing/string-valued capabilities cannot establish support.
    if (not isinstance(info, dict)
            or any(info.get(key) is not True for key in RESOURCE_CAPABILITIES)
            or info.get("OSType") != "linux"
            or info.get("CgroupVersion") not in {"1", "2"}
            or info.get("CgroupDriver") not in {"systemd", "cgroupfs"}
            or any(not isinstance(info.get(key), str) or not info[key] for key in ("ID", "ServerVersion"))):
        raise ValueError("Docker CPU quota, memory/swap or PID resource support is missing or unknown")
    return {key: info[key] for key in (*RESOURCE_CAPABILITIES, "ID", "ServerVersion", "OSType",
                                     "CgroupVersion", "CgroupDriver")}


def resource_environment(call):
    return check_resource_environment(json.loads(call("info", "--format", "{{json .}}")))


def check_container_resources(info, policy):
    expected = {"NanoCpus": policy["cpus"] * 1_000_000_000,
                "Memory": policy["memory_mb"] * 1024 * 1024,
                "MemorySwap": policy["memory_mb"] * 1024 * 1024, "PidsLimit": policy["pids"]}
    actual = {key: info.get("HostConfig", {}).get(key) for key in expected}
    if actual != expected or any(type(value) is not int for value in actual.values()):
        raise ValueError("container CPU/memory/swap/PID limits differ from trusted policy")
    return actual


def image_identity(executor, image):
    info = json.loads(executor.call("image", "inspect", image))[0]
    if image not in info.get("RepoDigests", []) or not re.fullmatch(r"sha256:[0-9a-f]{64}", info.get("Id", "")):
        raise ValueError("configured image digest is not present locally")
    return {"digest": image, "image_id": info["Id"]}


def preflight(policy, executor=None, expected_locks=None, timeout=90):
    """Positive daemon/image/tool/dependency probe; a config field is never availability."""
    validate_policy(policy)
    executor = executor or DockerExecutor()
    deadline = time.monotonic() + timeout
    def call(*args, timeout=30):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("validation readiness probe timed out")
        return executor.call(*args, timeout=min(timeout, remaining))
    environment = resource_environment(call)
    images = {key: image_identity(executor, policy[key]) for key in ("image", "postgres_image")}
    name = "cmh-preflight-" + uuid.uuid4().hex
    created = False
    try:
        # Images must be prepared outside Factory with locked dependencies in
        # /opt/cmh. Never build/pull candidate-controlled Dockerfiles here.
        created = True  # even an ambiguous create response requires cleanup
        call("create", "--pull=never", "--name", name, "--network=none", "--user=65534:65534",
                      *limits(policy), "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
                      "--entrypoint=/bin/sh", policy["image"], "-ec",
                      "test ! -S /var/run/docker.sock; command -v python3; command -v node; command -v git; "
                      "command -v npm; command -v python; python3 -c 'import pytest,pytest_cov,ruff,mypy'; "
                      "test -r /opt/cmh/package-lock.json; test -r /opt/cmh/requirements.txt; "
                      "test -d /opt/cmh/node_modules; NODE_PATH=/opt/cmh/node_modules "
                      "node -e 'require(\"playwright\");require(\"pg\");require(\"nock\");"
                      "require(\"http-proxy-agent\");require(\"https-proxy-agent\");require(\"socks-proxy-agent\")'; "
                      "test -x /opt/cmh/node_modules/.bin/eslint; test -x /opt/cmh/node_modules/.bin/c8; "
                      "sha256sum /opt/cmh/package-lock.json /opt/cmh/requirements.txt")
        output = call("start", "--attach", name, timeout=30).decode()
        actual_locks = {Path(path).name: sha for sha, path in re.findall(r"(?m)^([0-9a-f]{64})  (/opt/cmh/[^\n]+)$", output)}
        if expected_locks is not None and actual_locks != expected_locks:
            raise ValueError("prepared image dependencies differ from the exact candidate lockfiles")
        inspected = json.loads(call("inspect", name))[0]
        check_container_resources(inspected, policy)
        state = inspected["State"]
        if state.get("Status") != "exited" or state.get("ExitCode") != 0 or state.get("OOMKilled") or state.get("Error"):
            raise ValueError("isolated image readiness probe failed")
        if resource_environment(call) != environment:
            raise ValueError("Docker execution environment changed during readiness probe")
    finally:
        if created:
            try:
                executor.call("rm", "--force", "--volumes", name)
            except Exception as exc:
                raise ValidationCleanupError("readiness container cleanup failed: " + name) from exc
    return {"status": "VERIFIED" if not executor.fixture else "FIXTURE_VERIFIED", "images": images,
            "config_sha256": digest(policy), "dependency_locks": actual_locks,
            "resource_environment": environment}


def dependency_locks(cwd, revision):
    return {name: hashlib.sha256(_read_git(cwd, "show", revision + ":" + name).encode()).hexdigest()
            for name in ("package-lock.json", "requirements.txt")}


def validate_result(result, policy, spec, target, profile, simulation):
    expected = {"mission_id": spec["mission_id"], "head": target["head"], "tree": target["tree"],
                "profile": profile, "config_sha256": digest(policy), "image_digest": policy["image"]}
    if result.get("identity") != expected or result.get("fixture") is not simulation:
        raise ValueError("validation identity or fixture provenance mismatch")
    readiness = result.get("readiness", {})
    environment = check_resource_environment(readiness.get("resource_environment"))
    if (result.get("resource_environment_after") != environment
            or set(result.get("container_resources", {})) != {"database", "validation"}):
        raise ValueError("execution resource environment evidence missing or changed")
    for resources in result["container_resources"].values():
        check_container_resources({"HostConfig": resources}, policy)
    if (readiness.get("config_sha256") != digest(policy)
            or readiness.get("status") != ("FIXTURE_VERIFIED" if simulation else "VERIFIED")
            or set(readiness.get("images", {})) != {"image", "postgres_image"}
            or any(readiness["images"][key].get("digest") != policy[key]
                   for key in ("image", "postgres_image"))):
        raise ValueError("image/config prerequisite evidence missing or inconsistent")
    if (result.get("status") not in {"PASS", "FAIL"} or type(result.get("exit_code")) is not int
            or (result["status"] == "PASS") != (result["exit_code"] == 0)
            or result.get("interrupted") is not False or result.get("cleanup") != "COMPLETE"
            or result.get("logs_complete") is not True or result.get("environment_ready") is not True
            or not isinstance(result.get("started"), (int, float))
            or not isinstance(result.get("ended"), (int, float)) or result["ended"] < result["started"]):
        raise ValueError("validation incomplete, interrupted, unknown or cleanup failed")
    path = Path(result["log_path"])
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != result["log_sha256"]:
        raise ValueError("complete validation log missing or changed")


def run(policy, spec, cwd, target, command, transcript, timeout, executor=None, cancelled=lambda: False):
    validate_policy(policy)
    executor = executor or DockerExecutor()
    profile = profile_for(command)
    result = {"status": "RUNNING", "fixture": executor.fixture,
              "identity": {"mission_id": spec["mission_id"], "head": target["head"], "tree": target["tree"],
                           "profile": profile, "config_sha256": digest(policy), "image_digest": policy["image"]},
              "started": time.time(), "ended": None, "interrupted": None, "exit_code": None,
              "cleanup": "INCOMPLETE", "logs_complete": False, "environment_ready": False,
              "log_path": str(transcript), "log_sha256": None}
    deadline = time.monotonic() + timeout
    token = "cmh-validation-" + uuid.uuid4().hex
    marker = "CMH_ENVIRONMENT_READY_" + uuid.uuid4().hex
    db, container = token + "-db", token + "-profile"
    result["resource_names"] = {"database": db, "validation": container}
    metadata = transcript.with_suffix(".validation.json")
    # A Controller crash leaves a durable RUNNING record with an unknown
    # interruption/end state, never a fabricated completed validation.
    with metadata.open("x") as record:
        record.write(json.dumps(result, sort_keys=True))
        record.flush()
        os.fsync(record.fileno())
    metadata.chmod(0o600)
    resources = []
    temporary = tempfile.TemporaryDirectory(prefix=token + "-")
    snapshot = Path(temporary.name) / "source"
    def call(*args):
        if cancelled():
            raise InterruptedError("validation cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("validation deadline exhausted")
        return executor.call(*args, timeout=min(30, remaining))
    try:
        result["readiness"] = preflight(policy, executor, dependency_locks(cwd, target["head"]), timeout)
        environment = result["readiness"]["resource_environment"]
        def same_environment():
            current = resource_environment(call)
            if current != environment:
                raise ValueError("Docker execution environment changed after readiness")
            return current
        # Independent objects, sanitized metadata, immutable host mount. Neither
        # the original object store nor any Controller evidence enters Docker.
        subprocess.run(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "clone",
                        "--no-local", "--no-hardlinks", "--no-checkout", "--", str(cwd), str(snapshot)],
                       env=_git_environment(), capture_output=True, check=True, timeout=30)
        _read_git(snapshot, "checkout", "-b", "factory-validation", target["head"])
        _read_git(snapshot, "remote", "remove", "origin")
        _read_git(snapshot, "update-ref", "refs/remotes/origin/main", target["base"])
        (snapshot / ".git/config").write_text("[core]\n repositoryformatversion=0\n bare=false\n hooksPath=/dev/null\n")
        if _read_git(snapshot, "rev-parse", "HEAD").strip() != target["head"] or _read_git(snapshot, "rev-parse", "HEAD^{tree}").strip() != target["tree"]:
            raise ValueError("snapshot HEAD/tree differs from frozen candidate")
        # Docker uses uid 65534, which can read only this disposable snapshot.
        Path(temporary.name).chmod(0o755)
        for directory, _, files in os.walk(snapshot):
            Path(directory).chmod(0o755)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        password = uuid.uuid4().hex
        same_environment()
        resources.append(("container", db))
        call("create", "--pull=never", "--name", db, "--network=none",
             "--user=999:999", *limits(policy), "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,size=512m,uid=999,gid=999",
             "--tmpfs", "/var/run/postgresql:rw,nosuid,size=16m,uid=999,gid=999", "--tmpfs", "/tmp:rw,nosuid,size=64m",
             "-e", "PGDATA=/var/lib/postgresql/data", "-e", "POSTGRES_DB=football_validation",
             "-e", "POSTGRES_USER=validation", "-e", "POSTGRES_PASSWORD=" + password, policy["postgres_image"])
        db_info = json.loads(call("inspect", db))[0]
        result["container_resources"] = {"database": check_container_resources(db_info, policy)}
        if db_info.get("HostConfig", {}).get("NetworkMode") != "none":
            raise ValueError("temporary database does not have an isolated loopback-only namespace")
        same_environment()
        call("start", db)
        while True:
            try:
                call("exec", db, "pg_isready", "-U", "validation", "-d", "football_validation")
                break
            except subprocess.CalledProcessError:
                if time.monotonic() >= deadline or cancelled():
                    raise TimeoutError("temporary database did not become ready")
                time.sleep(0.2)
        resources.append(("container", container))
        # Share only the temporary DB's network=none namespace. Source is copied
        # into bounded tmpfs so normal coverage/temp artifacts work. Its Git
        # objects remain a separate read-only mount, and tracked edits fail closed.
        call("create", "--pull=never", "--name", container, "--network", "container:" + db, "--user=65534:65534",
             *limits(policy), "--mount", f"type=bind,src={snapshot},dst=/snapshot,readonly",
             "--tmpfs", f"/app:rw,nosuid,size={policy['tmpfs_mb']}m,uid=65534,gid=65534",
             "--mount", f"type=bind,src={snapshot / '.git'},dst=/app/.git,readonly",
             "--tmpfs", "/tmp:rw,nosuid,size=256m,mode=1777", "--workdir=/app", "--entrypoint=/usr/bin/env",
             policy["image"], "-i", "PATH=" + SAFE_PATH, "HOME=/tmp", "LANG=C.UTF-8",
             "PYTHONDONTWRITEBYTECODE=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
             "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/app", "GITHUB_BASE_REF=main",
             "GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0", "GATEKEEPER_IN_CONTAINER=1",
             "GATEKEEPER_WORKSPACE_ROOT=/app", "DB_HOST=127.0.0.1", "DB_PORT=5432", "DB_NAME=football_validation",
             "DB_USER=validation", "DB_PASSWORD=" + password, "REDIS_HOST=127.0.0.1", "REDIS_PORT=6379",
             "BASE_REF=" + target["base"], "HEAD_REF=" + target["head"], "GATEKEEPER_BUILD=0",
             "/bin/sh", "-ec", "git -c safe.directory=/snapshot -C /snapshot archive HEAD > /tmp/source.tar; "
             "tar -xf /tmp/source.tar -C /app; rm /tmp/source.tar; "
             "cmp package-lock.json /opt/cmh/package-lock.json; mkdir -p node_modules; "
             "cmp requirements.txt /opt/cmh/requirements.txt; cp -R /opt/cmh/node_modules/. /app/node_modules/; "
             "sha256sum package-lock.json | cut -d ' ' -f1 > node_modules/.package-lock.sha256; "
             "before=$(git status --porcelain=v1 -uall); test -z \"$before\"; "
             "printf '%s\\n' " + marker + "; status=0; python3 scripts/devops/validation_profiles.py " + profile + " || status=$?; "
             "after=$(git status --porcelain=v1 -uall); "
             "if test \"$before\" != \"$after\"; then echo CMH_SOURCE_INTEGRITY_FAILURE; exit 125; fi; exit \"$status\"")
        profile_info = json.loads(call("inspect", container))[0]
        result["container_resources"]["validation"] = check_container_resources(profile_info, policy)
        same_environment()
        stream_exit = executor.capture(container, transcript, max(0, deadline - time.monotonic()), cancelled)
        while True:
            inspected = json.loads(call("inspect", container))[0]
            check_container_resources(inspected, policy)
            state = inspected["State"]
            if state.get("Status") == "exited":
                if state.get("OOMKilled") or state.get("Error") or type(state.get("ExitCode")) is not int:
                    raise ValueError("container termination incomplete or resource failure")
                result["exit_code"] = state["ExitCode"]
                if stream_exit != result["exit_code"]:
                    raise ValueError("attached stream exit does not match actual container exit")
                break
            if state.get("Status") != "running":
                raise ValueError("container is not running or exited")
            time.sleep(0.2)
        logs = transcript.read_bytes()
        result["logs_complete"] = True
        if result["exit_code"] < 0 or result["exit_code"] >= 128:
            raise InterruptedError("profile terminated abnormally")
        if b"CMH_SOURCE_INTEGRITY_FAILURE" in logs:
            raise ValueError("executed profile changed the candidate source snapshot")
        if marker.encode() not in logs:
            raise ValueError("dependency preparation did not establish the formal profile environment")
        result["environment_ready"] = True
        check_container_resources(json.loads(call("inspect", db))[0], policy)
        result["resource_environment_after"] = same_environment()
        result["status"] = "PASS" if result["exit_code"] == 0 else "FAIL"
    except BaseException as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["interrupted"] = isinstance(exc, (TimeoutError, subprocess.TimeoutExpired, InterruptedError, KeyboardInterrupt))
        result["status"] = "UNKNOWN"
        if isinstance(exc, ValidationCleanupError):
            result["preflight_cleanup_error"] = str(exc)
        diagnostic = (getattr(exc, "output", None) or b"") + (getattr(exc, "stderr", None) or b"")
        if diagnostic and not transcript.exists():
            transcript.write_bytes(diagnostic)
        if ("container", container) in resources:
            try:
                executor.call("kill", container)
            except Exception:
                pass
            try:
                state = json.loads(executor.call("inspect", container))[0]["State"]
                result["terminal_state"] = state
                if state.get("Status") == "exited" and type(state.get("ExitCode")) is int:
                    result["exit_code"] = state["ExitCode"]
            except Exception:
                pass
        if not transcript.exists():
            transcript.write_bytes(b"")
    finally:
        errors = [result["preflight_cleanup_error"]] if result.get("preflight_cleanup_error") else []
        for kind, name in reversed(resources):
            try:
                executor.call("rm", "--force", "--volumes", name)
            except BaseException as exc:
                errors.append(f"{kind} {name}: {type(exc).__name__}")
        try:
            temporary.cleanup()
        except BaseException as exc:
            errors.append("temporary snapshot: " + type(exc).__name__)
        result["cleanup"] = "FAILED" if errors else "COMPLETE"
        result["cleanup_errors"] = errors
        if errors:
            result["status"] = "UNKNOWN"
        result["ended"] = time.time()
        if result["interrupted"] is None:
            result["interrupted"] = False
        result["log_sha256"] = hashlib.sha256(transcript.read_bytes()).hexdigest()
        metadata.write_text(json.dumps(result, sort_keys=True))
        metadata.chmod(0o400)
        result["project_evidence"] = [{"path": str(metadata), "sha256": hashlib.sha256(metadata.read_bytes()).hexdigest()}]
    return result
