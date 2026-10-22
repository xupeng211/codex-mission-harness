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
# 原项目蓝图 SQL 的 GRANT DATABASE 合同；仅用于一次性隔离实例。
DATABASE_NAME = "football_db"
DATABASE_IDENTITY = "football_db|validation|t|t|t"
QA_PYTHON = "/usr/local/bin/python3"


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

    def capture(self, container, path, timeout, cancelled, *, idle_timeout=None):
        # Direct attachment avoids daemon log rotation silently losing earlier
        # output. Only a completed stream can establish complete logs.
        path = Path(path)
        deadline = time.monotonic() + timeout
        last_activity, size, updates = time.monotonic(), 0, 0
        activity = {"mode": "progress_driven", "idle_timeout_seconds": idle_timeout,
                    "output_updates": 0, "observed_bytes": 0, "stop_reason": None}
        with Path(path).open("xb") as log:
            proc = subprocess.Popen(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "start", "--attach", container],
                env={"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8"}, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while proc.poll() is None:
                    if cancelled():
                        activity["stop_reason"] = "CANCELLED"
                        raise InterruptedError("validation cancelled")
                    observed = Path(path).stat().st_size
                    if observed > size:
                        last_activity, size, updates = time.monotonic(), observed, updates + 1
                    if idle_timeout is not None and time.monotonic() - last_activity >= idle_timeout:
                        activity["stop_reason"] = "NO_OUTPUT_PROGRESS"
                        raise TimeoutError("validation output silent; progress unverified")
                    if idle_timeout is None and time.monotonic() >= deadline:
                        raise TimeoutError("validation execution timed out")
                    if observed > 64 * 1024 * 1024:
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
                if idle_timeout is not None:
                    activity.update(output_updates=updates, observed_bytes=Path(path).stat().st_size)
                    path.with_suffix(".activity.json").write_text(json.dumps(activity, sort_keys=True))


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
                      "test ! -S /var/run/docker.sock; test -x " + QA_PYTHON + "; command -v node; command -v git; "
                      "command -v npm; command -v python; " + QA_PYTHON + " -I -c 'import pytest,pytest_cov,ruff,mypy'; "
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



TRUSTED_QA_FILES = (
    "scripts/devops/validation_profiles.py", "scripts/devops/gatekeeper.sh",
    ".eslintrc.json", "package.json", "package-lock.json", "requirements.txt",
)
QA_ANCHORS = ("package.json", "package-lock.json", ".eslintrc.json")
# Approved main 14633c3: this dispatcher derives cwd from its physical file.
# Unknown/new dispatchers retain the original /snapshot trusted-mode route.
LEGACY_DISPATCHER_SHA256 = "8cadabeaa949eed535943be39d18f69df0a2624095c7d50f53d4704a67478a85"


def workspace_layout(snapshot):
    legacy = hashlib.sha256((snapshot / TRUSTED_QA_FILES[0]).read_bytes()).hexdigest() == LEGACY_DISPATCHER_SHA256
    anchors = (*QA_ANCHORS, "requirements.txt", "scripts") if legacy else QA_ANCHORS
    return legacy, anchors, "/app" if legacy else "/snapshot"



def bind_trusted_qa(snapshot, target, image):
    """Controller 生成的绑定只进入只读快照；候选工作区不能更新它。"""
    if (_read_git(snapshot, "rev-parse", "HEAD").strip() != target["head"]
            or _read_git(snapshot, "rev-parse", "HEAD^{tree}").strip() != target["tree"]):
        raise ValueError("trusted QA snapshot HEAD/tree mismatch")
    files = {}
    for name in TRUSTED_QA_FILES:
        path = snapshot / name
        entry = _read_git(snapshot, "ls-files", "--stage", "--", name).split()
        if (not entry or entry[0] not in {"100644", "100755"}
                or path.is_symlink() or path.resolve() != snapshot / name):
            raise ValueError("trusted QA source is not a regular frozen file: " + name)
        frozen = subprocess.run(["git", "--no-replace-objects", "-C", str(snapshot),
                                 "show", target["head"] + ":" + name],
                                env=_git_environment(), capture_output=True, check=True).stdout
        if path.read_bytes() != frozen:
            raise ValueError("trusted QA source differs from frozen HEAD: " + name)
        files[name] = hashlib.sha256(frozen).hexdigest()
    # 当前合同没有隐式配置；不把未来配置静默替换为空配置。
    package = json.loads((snapshot / "package.json").read_text())
    if any(key in package for key in ("c8", "nyc", "eslintConfig", "eslintIgnore")):
        raise ValueError("unsupported implicit QA package configuration")
    for path in snapshot.rglob("*"):
        if ".git" in path.relative_to(snapshot).parts:
            continue
        if (path.name in {".eslintignore", ".c8rc", ".c8rc.json", ".nycrc", ".nycrc.json"}
                or (path.name.startswith(".eslintrc") and path != snapshot / ".eslintrc.json")):
            raise ValueError("unsupported implicit QA configuration: " + str(path))
    binding = snapshot / ".git/cmh-qa"
    binding.mkdir()
    (binding / "eslint-ignore").write_text("")
    (binding / "c8.json").write_text("{}\n")
    files[".git/cmh-qa/eslint-ignore"] = hashlib.sha256(b"").hexdigest()
    files[".git/cmh-qa/c8.json"] = hashlib.sha256(b"{}\n").hexdigest()
    manifest = {"head": target["head"], "tree": target["tree"], "image": image, "files": files}
    (binding / "binding.json").write_text(json.dumps(manifest, sort_keys=True))
    return manifest

def validate_result(result, policy, spec, target, profile, simulation):
    expected = {"mission_id": spec["mission_id"], "head": target["head"], "tree": target["tree"],
                "profile": profile, "config_sha256": digest(policy), "image_digest": policy["image"]}
    if result.get("identity") != expected or result.get("fixture") is not simulation:
        raise ValueError("validation identity or fixture provenance mismatch")
    binding = result.get("trusted_qa_binding", {})
    if (binding.get("head") != target["head"] or binding.get("tree") != target["tree"]
            or binding.get("image") != policy["image"]
            or set(binding.get("files", {})) != set(TRUSTED_QA_FILES) | {".git/cmh-qa/eslint-ignore", ".git/cmh-qa/c8.json"}
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in binding["files"].values())):
        raise ValueError("trusted QA snapshot binding is missing or inconsistent")
    if result.get("database_identity") != DATABASE_IDENTITY:
        raise ValueError("temporary database identity/initialization privileges are unverified")
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


def run(policy, spec, cwd, target, command, transcript, timeout, executor=None, cancelled=lambda: False,
        *, idle_timeout=None):
    validate_policy(policy)
    if idle_timeout is not None and (type(idle_timeout) is not int or not 1 <= idle_timeout <= 86400):
        raise ValueError("invalid validation idle timeout")
    executor = executor or DockerExecutor()
    profile = profile_for(command)
    # This supplement is selected only by the immutable local authorization.
    # STRICT remains the complete project gate; targeted additionally executes
    # the changed direct Python tests that the full gate does not guarantee.
    from .factory_candidate import requested, STRICT_DIRECT_MARKER
    strict_local = (requested(spec) and profile == "strict" and
                    spec.get("local_candidate_authorization", {}).get("local_acceptance", {}).get("profile") == "strict")
    result = {"status": "RUNNING", "fixture": executor.fixture,
              "identity": {"mission_id": spec["mission_id"], "head": target["head"], "tree": target["tree"],
                           "profile": profile, "config_sha256": digest(policy), "image_digest": policy["image"]},
              "started": time.time(), "ended": None, "interrupted": None, "exit_code": None,
              "cleanup": "INCOMPLETE", "logs_complete": False, "environment_ready": False,
              "log_path": str(transcript), "log_sha256": None}
    # Legacy contracts retain their one absolute deadline. Progress execution
    # bounds each control command/readiness phase; the profile uses output
    # activity instead of total age. No mission fields can select this mode.
    deadline = time.monotonic() + timeout if idle_timeout is None else None
    if idle_timeout is not None:
        result["execution_control"] = {"mode": "progress_driven", "idle_timeout_seconds": idle_timeout}
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
        remaining = deadline - time.monotonic() if deadline is not None else 30
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
        result["trusted_qa_binding"] = bind_trusted_qa(snapshot, target, policy["image"])
        legacy, anchors, qa_root = workspace_layout(snapshot)
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
             "-e", "PGDATA=/var/lib/postgresql/data", "-e", "POSTGRES_DB=" + DATABASE_NAME,
             "-e", "POSTGRES_USER=validation", "-e", "POSTGRES_PASSWORD=" + password, policy["postgres_image"])
        db_info = json.loads(call("inspect", db))[0]
        result["container_resources"] = {"database": check_container_resources(db_info, policy)}
        if db_info.get("HostConfig", {}).get("NetworkMode") != "none":
            raise ValueError("temporary database does not have an isolated loopback-only namespace")
        same_environment()
        call("start", db)
        readiness_deadline = deadline if deadline is not None else time.monotonic() + timeout
        while True:
            try:
                call("exec", db, "pg_isready", "-h", "127.0.0.1", "-p", "5432",
                     "-U", "validation", "-d", DATABASE_NAME)
                break
            except subprocess.CalledProcessError:
                if time.monotonic() >= readiness_deadline or cancelled():
                    raise TimeoutError("temporary database did not become ready")
                time.sleep(0.2)
        # pg_isready 不验证库名、认证或权限。用与 profile 相同的 TCP 参数
        # 实际连接；不执行候选 SQL，不提升现有 POSTGRES_USER 初始化权限。
        identity = call("exec", "-e", "PGPASSWORD=" + password, "-e", "PGCONNECT_TIMEOUT=5",
                        "-e", "PGOPTIONS=-c statement_timeout=5000", db,
                        "psql", "-X", "-w", "-h", "127.0.0.1", "-p", "5432",
                        "-U", "validation", "-d", DATABASE_NAME, "-v", "ON_ERROR_STOP=1", "-A", "-t", "-c",
                        "SELECT current_database(), current_user, rolsuper, rolcreatedb, rolcreaterole "
                        "FROM pg_roles WHERE rolname = current_user").decode().strip()
        if identity != DATABASE_IDENTITY:
            raise ValueError("temporary database identity or initialization privileges mismatch")
        result["database_identity"] = identity
        resources.append(("container", container))
        # Share only the temporary DB's network=none namespace. Source is copied
        # into bounded tmpfs so normal coverage/temp artifacts work. Its Git
        # objects remain a separate read-only mount, and tracked edits fail closed.
        dispatcher = QA_PYTHON + " -I " + qa_root + "/scripts/devops/validation_profiles.py "
        execute_profile = dispatcher + profile + " || status=$?; "
        if strict_local:
            execute_profile += ("if test \"$status\" -eq 0; then printf '%s\\n' " + STRICT_DIRECT_MARKER +
                                "; " + dispatcher + "targeted || status=$?; fi; ")
        call("create", "--pull=never", "--name", container, "--network", "container:" + db, "--user=65534:65534",
             *limits(policy), "--mount", f"type=bind,src={snapshot},dst=/snapshot,readonly",
             "--tmpfs", f"/app:rw,noexec,nosuid,size={policy['tmpfs_mb']}m,uid=65534,gid=65534",
             "--mount", f"type=bind,src={snapshot / '.git'},dst=/app/.git,readonly",
             *[value for name in anchors for value in
               ("--mount", f"type=bind,src={snapshot / name},dst=/app/{name},readonly")],
             *(["--tmpfs", "/app/scripts/ops:rw,noexec,nosuid,size=64m,uid=65534,gid=65534"] if legacy else []),
             "--tmpfs", "/tmp:rw,nosuid,size=256m,mode=1777", "--workdir=/app", "--entrypoint=/usr/bin/env",
             policy["image"], "-i", "PATH=" + SAFE_PATH, "HOME=/tmp", "LANG=C.UTF-8",
             "PYTHONDONTWRITEBYTECODE=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
             *(["PYTHONUNBUFFERED=1"] if idle_timeout is not None else []),
             "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=safe.directory", "GIT_CONFIG_VALUE_0=/app", "GITHUB_BASE_REF=main",
             "GIT_NO_REPLACE_OBJECTS=1", "GIT_OPTIONAL_LOCKS=0", "GATEKEEPER_IN_CONTAINER=1",
             "GATEKEEPER_WORKSPACE_ROOT=/app", "DB_HOST=127.0.0.1", "DB_PORT=5432", "DB_NAME=" + DATABASE_NAME,
             "DB_USER=validation", "DB_PASSWORD=" + password, "REDIS_HOST=127.0.0.1", "REDIS_PORT=6379",
             "BASE_REF=" + target["base"], "HEAD_REF=" + target["head"], "GATEKEEPER_BUILD=0",
             "/bin/sh", "-ec", "git -c safe.directory=/snapshot -C /snapshot archive HEAD > /tmp/source.tar; "
             "tar --anchored " + " ".join("--exclude=" + name for name in anchors) + " "
             "-xf /tmp/source.tar -C /app; rm /tmp/source.tar; " +
             ("cp -R /snapshot/scripts/ops/. /app/scripts/ops/; " if legacy else "") +
             "cmp package-lock.json /opt/cmh/package-lock.json; cmp requirements.txt /opt/cmh/requirements.txt; " +
             "mkdir -p node_modules; " +
             "cp -as /opt/cmh/node_modules/. /app/node_modules/; " +
             "sha256sum package-lock.json | cut -d ' ' -f1 > node_modules/.package-lock.sha256; "
             "before=$(git status --porcelain=v1 -uall); test -z \"$before\"; "
             "printf '%s\\n' " + marker + "; status=0; " + execute_profile +
             "after=$(git status --porcelain=v1 -uall); "
             "if test \"$before\" != \"$after\"; then echo CMH_SOURCE_INTEGRITY_FAILURE; exit 125; fi; exit \"$status\"")
        profile_info = json.loads(call("inspect", container))[0]
        result["container_resources"]["validation"] = check_container_resources(profile_info, policy)
        same_environment()
        capture_control = {"idle_timeout": idle_timeout} if idle_timeout is not None else {}
        stream_exit = executor.capture(container, transcript,
                                      max(0, deadline - time.monotonic()) if deadline is not None else timeout,
                                      cancelled, **capture_control)
        # An attachment claiming completion while its container keeps running
        # is a control-plane anomaly, not continuing business-test progress.
        exit_deadline = deadline if deadline is not None else time.monotonic() + 30
        while True:
            if time.monotonic() >= exit_deadline:
                raise TimeoutError("container did not establish a terminal state after attachment")
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
        activity = transcript.with_suffix(".activity.json")
        if idle_timeout is not None and activity.is_file():
            activity.chmod(0o400)
            result["project_evidence"].append({"path": str(activity), "sha256": hashlib.sha256(activity.read_bytes()).hexdigest()})
    return result
