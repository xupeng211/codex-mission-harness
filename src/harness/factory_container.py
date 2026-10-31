"""Controller-only, offline dev-image validation. Never expose Docker to agents."""
from __future__ import annotations

import os
import io
import json
import math
import re
import select
import shutil
import stat
import subprocess
import sys
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
LIFECYCLE_LIMIT = 65536


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


def consume_output(proc, output, cancel, deadline, *, stderr_output=None, exited=None):
    """Controller-owned pipes; the child never receives a log file fd."""
    streams = {proc.stdout: output}
    if stderr_output is not None and getattr(proc, "stderr", None) is not None:
        streams[proc.stderr] = stderr_output
    while True:
        delay = min(0.05, max(0, deadline - time.monotonic())) if exited is not None else 0.05
        if streams:
            for stream in select.select(list(streams), [], [], delay)[0]:
                data = os.read(stream.fileno(), 65536)
                if data:
                    streams[stream].write(data)
                else:
                    del streams[stream]
        else:
            cancel.wait(delay)
        if cancel.is_set():
            raise ExecutionStopped("CANCELLED")
        if time.monotonic() >= deadline:
            raise ExecutionStopped("TIMEOUT")
        # Gate clients keep their direct-child ownership anchor unreaped until
        # the whole group is stopped. Other existing callers retain poll().
        if not streams and (exited() if exited is not None else proc.poll() is not None):
            return


def check_stopped(cancel, deadline):
    if cancel.is_set():
        raise ExecutionStopped("CANCELLED")
    if time.monotonic() >= deadline:
        raise ExecutionStopped("TIMEOUT")


def _gate_client(runtime, argv, cwd, log, cancel, deadline, *, cleanups, env=ENV,
                 stderr_log=None, password=None):
    """One sequential gate client, including main validation, owns its group."""
    from .factory_runtime import RuntimeFailure
    with runtime._execution_lock:
        check_stopped(cancel, deadline)
        if runtime.container_cancel is not cancel:
            raise ExecutionStopped("CANCELLED")
        if runtime.current_process is not None or runtime._preparation_client is not None:
            raise RuntimeFailure("another client still owns this execution")
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE if stderr_log is not None else subprocess.STDOUT,
                                start_new_session=True)
        runtime.current_process = proc
        client = {"process": proc, "execution": runtime._active_execution,
                  "mission": runtime._active_mission, "identity": None}
        runtime._preparation_client = client
    output = RedactedOutput(log, password)
    error_output = RedactedOutput(stderr_log, password) if stderr_log is not None else None
    original_error = None
    try:
        client["identity"] = runtime._client_process_identity(proc.pid)
        def exited():
            with runtime._execution_lock:
                status = runtime._owned_client_leader(client)
                if status is not None:
                    client["exit_code"] = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                return status is not None
        # Work and shutdown share the caller's remaining total/stage budget.
        # A small reserve allows SIGKILL and observation without a fresh grace.
        work_deadline = deadline - min(0.1, max(0, deadline - time.monotonic()) / 4)
        consume_output(proc, output, cancel, work_deadline, stderr_output=error_output, exited=exited)
    except BaseException as error:
        original_error = error
        raise
    finally:
        try:
            cleanup = runtime._finish_owned_client(client, deadline)
        except Exception as error:
            cleanup = {"identity": client["identity"], "mission": client["mission"],
                       "confirmed": False, "leader_reaped": False,
                       "errors": [f"{type(error).__name__}: {error}"]}
        cleanup["exit_code"] = proc.returncode if proc.returncode is not None else client.get("exit_code")
        cleanup["diagnostics_complete"] = original_error is None
        # Diagnostic failure must neither bypass group shutdown nor replace
        # the original command/cancellation error. Try each sink independently.
        for stream in (proc.stdout, getattr(proc, "stderr", None), output, error_output):
            if stream is None:
                continue
            try:
                stream.finish() if isinstance(stream, RedactedOutput) else stream.close()
            except Exception as error:
                cleanup["diagnostics_complete"] = False
                # A sink exception may quote sensitive output. Keep only its
                # type/errno, as in the existing service diagnostic contract.
                cleanup["errors"].append(f"diagnostic {type(error).__name__} errno={getattr(error, 'errno', None)}")
        cleanups.append(cleanup)
        if original_error is not None:
            original_error.client_cleanup = cleanup
            if not cleanup["confirmed"] or not cleanup["diagnostics_complete"]:
                original_error.add_note("client cleanup/diagnostics unconfirmed; original error retained")
        elif not cleanup["confirmed"] or not cleanup["diagnostics_complete"]:
            error = RuntimeFailure("controlled client cleanup/diagnostics unconfirmed")
            error.client_cleanup = cleanup
            raise error
    try:
        check_stopped(cancel, deadline)
    except ExecutionStopped as error:
        error.client_cleanup = cleanup
        raise
    return proc.returncode


def prepare_client(runtime, argv, cwd, log, cancel, deadline, *, env=ENV, stderr_log=None):
    """A preparation client belongs to the same execution as validation."""
    try:
        return _gate_client(runtime, argv, cwd, log, cancel, deadline,
                            cleanups=runtime._preparation_cleanups, env=env, stderr_log=stderr_log)
    except BaseException as error:
        if hasattr(error, "client_cleanup"):
            error.preparation_cleanup = error.client_cleanup
        raise


def captured_client(runtime, argv, cwd, cancel, deadline, *, env=ENV):
    output, error = io.BytesIO(), io.BytesIO()
    try:
        code = prepare_client(runtime, argv, cwd, output, cancel, deadline, env=env, stderr_log=error)
    except BaseException as failure:
        # Keep already captured, separate output on failure too. These bytes
        # are not placed in cleanup metadata or interpolated into diagnostics.
        failure.stdout, failure.stderr = output.getvalue(), error.getvalue()
        raise
    return subprocess.CompletedProcess(argv, code, output.getvalue(), error.getvalue())


def source_check(runtime, request, phase, log, cancel, deadline):
    """Keep this gate's existing Git/policy/source checks in its process group.

    The Controller code and original verifiers are unchanged. Running this
    bounded local query as a tracked client also covers their nested Git and
    trusted-policy subprocesses, without altering shared Git executors.
    """
    code = """
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from harness.factory_container import binding, source_fingerprint
from harness.factory import git
v=json.loads(Path(sys.argv[2]).read_text()); phase=sys.argv[3]
cwd=Path(v['cwd']); workspace=Path(v['workspace']); target=v['target']
if phase == 'candidate':
    result={'source': binding(v['spec'], cwd, target)}
elif phase == 'snapshot':
    result={'snapshot': source_fingerprint(workspace, target['head'])}
elif phase == 'final':
    result={'source': binding(v['spec'], cwd, target),
            'snapshot': source_fingerprint(workspace, target['head']),
            'snapshot_dirty': bool(git(workspace, 'diff', '--name-only', 'HEAD'))}
else:
    raise ValueError('unknown source-check phase')
print(json.dumps(result))
"""
    result = captured_client(runtime,
        [sys.executable, "-I", "-B", "-c", code, str(Path(__file__).resolve().parents[1]), str(request), phase],
        request.parent, cancel, deadline)
    if result.returncode:
        log.write(result.stdout + result.stderr)
        raise ValueError("Controller source verification failed")
    return json.loads(result.stdout)


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


def inspect_image(policy, *, client=None):
    validate_policy(policy)
    # Deliberately do not inspect/output Config.Env or contact a registry.
    for key in ("image_id", "postgres_image_id"):
        if key not in policy:
            continue
        argv = ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", policy[key]]
        if client is None:  # Standalone availability probe, outside a gate.
            raw = subprocess.check_output(argv, env=ENV, stderr=subprocess.PIPE, timeout=15)
        else:
            result = client(argv, env=ENV, timeout=15)
            if result.returncode:
                raise subprocess.CalledProcessError(result.returncode, argv, result.stdout)
            raw = result.stdout
        value = raw.decode().strip()
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
    from .factory import digest
    path = Path(transcript).with_suffix(".container.json")
    result = {"target": target, "mission_id": spec["mission_id"], "cleanup_confirmed": False,
              "operation_replayed": False, "resources": []}
    try:
        # Old writers embedded the full target. Admit that exact legacy target
        # plus bounded metadata, not an unlimited record or a changed target.
        legacy_limit = len(json.dumps(target, sort_keys=True).encode()) + LIFECYCLE_LIMIT
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > legacy_limit):
            raise ValueError("untrusted container lifecycle record")
        with path.open("rb") as stream:
            raw = stream.read(legacy_limit + 1)
        if len(raw) > legacy_limit:
            raise ValueError("container lifecycle record exceeds bounded recovery capacity")
        record = json.loads(raw)
        if not isinstance(record, dict):
            raise ValueError("invalid container lifecycle record")
        if "version" not in record:
            target_matches = record.get("target") == target
        else:
            target_matches = (type(record["version"]) is int and record["version"] == 2
                              and len(raw) <= LIFECYCLE_LIMIT and record.get("target_sha256") == digest(target))
        name = record["container_name"]
        profile = PROFILES.get(tuple(command))
        if (not re.fullmatch(r"cmh-validate-[a-f0-9]{32}", name)
                or not target_matches or record["mission_id"] != spec["mission_id"]
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
    from .factory import digest
    started = time.monotonic()
    deadline = started + timeout
    cancel = runtime.container_cancel
    preparation_start = len(runtime._preparation_cleanups)
    profile = PROFILES.get(tuple(command))
    if profile is None or profile not in validate_policy(policy)["profiles"]:
        raise ValueError("Controller container executor only accepts approved canonical profiles")
    needs_postgres = profile in {"pr", "strict"}
    if needs_postgres and "postgres_image_id" not in policy:
        raise ValueError("canonical pr/strict requires a pinned isolated test PostgreSQL image")
    result = {"target": target, "mission_id": spec["mission_id"], "scope_sha256": target["mission_scope_sha256"],
              "image_id": policy["image_id"], "profile": profile, "fixture": False, "network": "none",
              "container_policy": policy, "services": {}}
    name = "cmh-validate-" + uuid.uuid4().hex
    resources = resources_for(name, spec, target, needs_postgres)
    with tempfile.TemporaryDirectory(prefix="cmh-validation-", dir=transcript.parent) as temporary:
        workspace = Path(temporary) / "source"
        service = None
        validation_cleanups = []
        before = after = snapshot_after = "NOT_VERIFIABLE"
        unchanged, validation_attempted = False, False
        outcome = "EXITED"
        result.update(container_name=name, source_before=before, cleanup_confirmed=True, exit_code=None)
        with transcript.open("x+b") as log:
            os.fchmod(log.fileno(), 0o600)
            # Durable plan precedes the first Docker dispatch. An interrupted
            # Controller can identify only its exact operation's resources.
            record = {"version": 2, "target_sha256": digest(target), "mission_id": spec["mission_id"], "policy": policy,
                      "profile": profile, "container_name": name, "resources": resources,
                      "temporary_directory": temporary}
            raw = json.dumps(record, sort_keys=True).encode()
            if len(raw) > LIFECYCLE_LIMIT:
                raise ValueError("container lifecycle record exceeds recoverable capacity before dispatch")
            lifecycle = transcript.with_suffix(".container.json")
            with lifecycle.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            result["lifecycle_record"] = str(lifecycle)
            try:
                check_stopped(cancel, deadline)
                request = Path(temporary) / "source-check.json"
                with request.open("x") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    json.dump({"spec": spec, "cwd": str(cwd), "target": target, "workspace": str(workspace)}, stream)
                def client(argv, *, env=ENV, timeout):
                    return captured_client(runtime, argv, temporary, cancel,
                                           min(deadline, time.monotonic() + timeout), env=env)
                before = source_check(runtime, request, "candidate", log, cancel, deadline)["source"]
                result["source_before"] = before
                image = inspect_image(policy, client=client)
                dependency_name = name + "-dependencies"
                try:
                    # Only this preparation path uses the cancellable client;
                    # keep the same Git config/environment protections as git().
                    git_env = {**ENV, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                               "GIT_LITERAL_PATHSPECS": "1"}
                    for repo, args in (
                        (cwd, ["clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", str(cwd), str(workspace)]),
                        (workspace, ["remote", "remove", "origin"]),
                        (workspace, ["checkout", "--detach", target["head"]]),
                        (workspace, ["update-ref", "refs/remotes/origin/main", target["base"]]),
                    ):
                        argv = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                                "-c", "core.quotePath=false", "-c", "core.fsmonitor=false", "-C", str(repo), *args]
                        if prepare_client(runtime, argv, temporary, log, cancel, deadline, env=git_env):
                            raise RuntimeError("validation source preparation failed")
                    # All original diff helpers consume GITHUB_BASE_REF, not
                    # BASE_REF alone. Pin and verify their ref in this snapshot.
                    base_output = io.BytesIO()
                    argv = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                            "-c", "core.fsmonitor=false", "-C", str(workspace),
                            "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"]
                    code = prepare_client(runtime, argv, temporary, base_output, cancel, deadline, env=git_env)
                    log.write(base_output.getvalue())
                    if code or base_output.getvalue().strip() != target["base"].encode():
                        raise ValueError("validation diff reference differs from approved full BASE")
                    labels = [v for k, value in resources[1]["labels"].items() for v in ("--label", k + "=" + value)]
                    create = ["/usr/bin/docker", "create", "--pull=never", "--name", dependency_name, *labels,
                              "--network=none", "--entrypoint=/usr/bin/true", image]
                    if prepare_client(runtime, create, temporary, log, cancel,
                                            min(deadline, time.monotonic() + 15)):
                        raise RuntimeError("dependency copy container could not start")
                    copied = prepare_client(runtime,
                        ["/usr/bin/docker", "cp", dependency_name + ":/app/node_modules", str(workspace / "node_modules")],
                        temporary, log, cancel, min(deadline, time.monotonic() + 60))
                    result["image_node_dependencies_copied"] = copied == 0
                finally:
                    cleaned, code = remove_owned(dependency_name, name, resources[1]["labels"])
                    result.update(dependencies_cleanup_confirmed=cleaned, dependencies_cleanup_exit_code=code)
                    if not cleaned:
                        raise RuntimeError("dependency copy container cleanup could not be confirmed")
                check_stopped(cancel, deadline)
                snapshot = source_check(runtime, request, "snapshot", log, cancel, deadline)["snapshot"]
                result["snapshot_before"] = snapshot
                lifetime = max(1, math.ceil(deadline - time.monotonic()))
                result.update(lifetime_limit_seconds=lifetime, lifetime_kill_grace_seconds=5)
                argv = argv_for(policy, workspace, name, profile, lifetime)
                index = argv.index("/usr/bin/timeout")
                argv[index:index] = ["BASE_REF=" + target["base"], "HEAD_REF=" + target["head"], "GITHUB_BASE_REF=main",
                               "MISSION_SCOPE_FILE=/app/" + target["mission_scope_file"]]
                index = argv.index("--workdir=/app")
                argv[index:index] = [v for k, value in resources[0]["labels"].items() for v in ("--label", k + "=" + value)]
                if needs_postgres:
                    service = ProjectPostgres(policy["postgres_image_id"], name + "-postgres", Path(temporary),
                                              target, spec["mission_id"], cancel, deadline, ENV, log, client=client)
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
                validation_attempted = True
                result["exit_code"] = _gate_client(runtime, argv, temporary, log, cancel, deadline,
                    cleanups=validation_cleanups, password=service.password.encode() if service else None)
            except ExecutionStopped as error:
                outcome = error.outcome
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                outcome = "BLOCKED_ENVIRONMENT"
                result["error_type"] = type(error).__name__
                log.write(("Controller execution failed: " + type(error).__name__ + "\n").encode())
            finally:
                # _gate_client already stopped the owned group before reaping
                # its leader. On uncertainty its slot/identity remain held;
                # neither this finally nor cancel may poll/reap that anchor.
                validation_cleanup = validation_cleanups[-1] if validation_cleanups else None
                result["validation_client_cleanup"] = validation_cleanup
                if validation_cleanup is not None:
                    result["exit_code"] = validation_cleanup["exit_code"]
                client_cleaned = not validation_attempted or bool(validation_cleanup and validation_cleanup["confirmed"])
                cleaned, code = (remove_owned(name, name, resources[0]["labels"])
                                 if validation_attempted else (True, None))
                result.update(cleanup_confirmed=cleaned and client_cleaned, cleanup_exit_code=code)
                if service is not None:
                    service.close()
                    result["cleanup_confirmed"] &= service.evidence["cleanup_confirmed"]
                    result["ephemeral_password_redacted"] = True
                if outcome == "EXITED" and result["exit_code"] == 124:
                    outcome = "TIMEOUT"
                if outcome == "EXITED":
                    # Preserve the original after-cleanup source observation,
                    # but give ordinary queries only the remaining gate time.
                    # A stopped execution runs no more source/Git/policy work.
                    try:
                        final = source_check(runtime, request, "final", log, cancel, deadline)
                        after, snapshot_after = final["source"], final["snapshot"]
                        unchanged = before == after and snapshot == snapshot_after and not final["snapshot_dirty"]
                    except ExecutionStopped as error:
                        outcome = error.outcome
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                        pass  # Unverifiable source can never produce PASS.
                result["preparation_clients"] = runtime._preparation_cleanups[preparation_start:]
                result["preparation_cleanup_confirmed"] = all(c["confirmed"] for c in result["preparation_clients"])
                result["preparation_diagnostics_complete"] = all(c["diagnostics_complete"] for c in result["preparation_clients"])
                result["cleanup_confirmed"] &= result["preparation_cleanup_confirmed"]
                if outcome == "EXITED" and (not result["preparation_cleanup_confirmed"]
                                           or not result["preparation_diagnostics_complete"]):
                    outcome = "BLOCKED_ENVIRONMENT"
                if cancel.is_set():
                    outcome = "CANCELLED"
        # 137 can also be OOM or an unrelated SIGKILL; do not invent a
        # timeout diagnosis without the Controller deadline or exit 124.
        result.update(outcome=outcome, source_after=after, snapshot_after=snapshot_after,
                      source_unchanged=unchanged)
        result["status"] = (outcome if outcome != "EXITED" else "SOURCE_CHANGED" if not unchanged else
                            "BLOCKED_ENVIRONMENT" if not result["cleanup_confirmed"] or
                                (service is not None and not service.evidence["diagnostics_complete"]) else
                            "PASS" if result["exit_code"] == 0 else "FAIL")
    result["temporary_directory_cleanup_confirmed"] = not Path(temporary).exists()
    if not result["temporary_directory_cleanup_confirmed"] and result["status"] == "PASS":
        result["status"] = "BLOCKED_ENVIRONMENT"
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result
