"""Controller-only, offline dev-image validation. Never expose Docker to agents."""
from __future__ import annotations

import os
import io
import hashlib
import json
import math
import re
import select
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .sandbox import SAFE_PATH
from .factory_test_service import ProjectPostgres, ExecutionStopped
from .task_temp import allocate_directory, remove_directory, _validate_directory, TaskTempError


PROFILES = {("make", "verify-" + p): p for p in ("targeted", "pr", "strict")}
ENV = {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
       "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}
LIFECYCLE_LIMIT = 65536


def client_stop_evidence(transcript, record, lifecycle_raw):
    """Read only. A closed, complete journal is required even if Docker is absent.

    This records the existing owned-client group proof, not a restart-time PID
    probe or permission to signal/adopt an old execution. The private evidence
    directory is Controller-owned; completed operations also bind its raw hash.
    """
    path = Path(transcript).with_suffix(".container.clients.jsonl")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > LIFECYCLE_LIMIT):
            raise ValueError("untrusted container client stop evidence")
        raw = stream.read(LIFECYCLE_LIMIT + 1)
    lines = raw.splitlines(keepends=True)
    if len(raw) > LIFECYCLE_LIMIT or len(lines) < 2 or any(not line.endswith(b"\n") for line in lines):
        raise ValueError("incomplete or oversized container client stop evidence")
    rows = [json.loads(line) for line in lines]
    header, seal = rows[0], rows[-1]
    if (not isinstance(header, dict) or header.get("event") != "open"
            or type(header.get("version")) is not int or header["version"] != 1
            or header.get("operation") != str(transcript)
            or header.get("lifecycle_sha256") != hashlib.sha256(lifecycle_raw).hexdigest()
            or header.get("temporary_directory_identity") != record["temporary_directory_identity"]
            or not re.fullmatch(r"[a-f0-9]{32}", str(header.get("execution_id", "")))):
        raise ValueError("container client stop task/operation/allocation binding changed")
    controller = header["controller"]
    if (not isinstance(controller, dict) or controller["uid"] != os.getuid() or type(controller["pid"]) is not int
            or controller["pid"] <= 0 or not isinstance(controller["starttime"], str)
            or not controller["starttime"].isdecimal()):
        raise ValueError("container client Controller identity is incomplete")
    if (not isinstance(seal, dict) or seal.get("event") != "sealed"
            or seal.get("sha256") != hashlib.sha256(b"".join(lines[:-1])).hexdigest()
            or type(seal.get("clients")) is not int or len(rows) != 2 + seal["clients"] * 3):
        raise ValueError("container client dispatch phase is not completely sealed")
    for index in range(seal["clients"]):
        intent, started, stopped = rows[1 + index * 3:4 + index * 3]
        if (any(not isinstance(v, dict) or type(v.get("client")) is not int or v["client"] != index + 1
                for v in (intent, started, stopped))
                or intent.get("event") != "intent" or started.get("event") != "started"
                or stopped.get("event") != "stopped" or intent.get("role") not in {"preparation", "validation"}
                or intent.get("cwd") != record["temporary_directory"]
                or not re.fullmatch(r"[a-f0-9]{64}", str(intent.get("argv_sha256", "")))):
            raise ValueError("container client registration is missing or incomplete")
        identity = started["identity"]
        if (not isinstance(identity, dict)
                or any(type(identity.get(k)) is not int for k in ("pid", "ppid", "uid", "pgid", "sid"))
                or not isinstance(identity.get("starttime"), str) or not identity["starttime"].isdecimal()
                or identity["pid"] <= 0 or identity["ppid"] != controller["pid"]
                or identity["uid"] != controller["uid"] or identity["pgid"] != identity["pid"]
                or identity["sid"] != identity["pid"] or stopped.get("identity") != identity
                or stopped.get("mission") != record["mission_id"] or stopped.get("confirmed") is not True
                or stopped.get("leader_reaped") is not True):
            raise ValueError("container client original owned-group stop is unconfirmed")
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "clients": seal["clients"]}


class _ClientStops:
    """One gate's append-only dispatch/stop journal. No restart-time adoption.

    Intent is fsynced before Popen. Any partial launch/registration/stop/write
    leaves an unsealed journal. Only the synchronous gate owner can seal after
    its last query; sealing disables further dispatch before publishing proof.
    """
    def __init__(self, runtime, transcript, record, raw):
        self.transcript, self.record, self.lifecycle_raw = transcript, record, raw
        self.path = Path(transcript).with_suffix(".container.clients.jsonl")
        self.raw, self.count, self.pending, self.closed, self.failed = b"", 0, None, False, False
        self.stream = self.path.open("xb")
        os.fchmod(self.stream.fileno(), 0o600)
        try:
            self._append({"event": "open", "version": 1, "operation": str(transcript),
                          "lifecycle_sha256": hashlib.sha256(raw).hexdigest(),
                          "temporary_directory_identity": record["temporary_directory_identity"],
                          "execution_id": runtime._execution_id,
                          "controller": runtime._client_process_identity(os.getpid())})
            fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException:
            self.stream.close()
            raise

    def _append(self, value):
        try:
            data = (json.dumps(value, sort_keys=True) + "\n").encode()
            if self.failed or len(self.raw) + len(data) > LIFECYCLE_LIMIT:
                raise ValueError("container client stop evidence capacity/write failure")
            self.stream.write(data)
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.raw += data
        except BaseException:
            self.failed = True
            raise

    def intent(self, argv, cwd, role):
        if self.closed or self.pending is not None:
            raise ValueError("container client dispatch is closed or an earlier stop is unconfirmed")
        self.count += 1
        self.pending = "intent"
        self._append({"event": "intent", "client": self.count, "role": role, "cwd": str(cwd),
                      "argv_sha256": hashlib.sha256(json.dumps(argv).encode()).hexdigest()})

    def started(self, identity):
        self._append({"event": "started", "client": self.count, "identity": identity})
        self.pending = "started"

    def stopped(self, cleanup):
        self._append({"event": "stopped", "client": self.count,
                      **{k: cleanup[k] for k in ("identity", "mission", "confirmed", "leader_reaped")}})
        if self.pending == "started" and cleanup["confirmed"] is True and cleanup["leader_reaped"] is True:
            self.pending = None

    def seal(self):
        if self.closed:
            raise ValueError("container client dispatch was already closed")
        self.closed = True
        if self.pending is not None:
            raise ValueError("container local client stop/registration is incomplete")
        self._append({"event": "sealed", "clients": self.count, "sha256": hashlib.sha256(self.raw).hexdigest()})
        return client_stop_evidence(self.transcript, self.record, self.lifecycle_raw)

    def close(self):
        self.closed = True
        self.stream.close()


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
                 stderr_log=None, password=None, clients=None, role="preparation"):
    """One sequential gate client, including main validation, owns its group."""
    from .factory_runtime import RuntimeFailure
    with runtime._execution_lock:
        check_stopped(cancel, deadline)
        if runtime.container_cancel is not cancel:
            raise ExecutionStopped("CANCELLED")
        if runtime.current_process is not None or runtime._preparation_client is not None:
            raise RuntimeFailure("another client still owns this execution")
        if clients is not None:
            clients.intent(argv, cwd, role)
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
        if clients is not None:
            clients.started(client["identity"])
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
        if clients is not None:
            try:
                clients.stopped(cleanup)
            except (OSError, ValueError) as error:
                cleanup["stop_evidence_error"] = type(error).__name__
                cleanup["diagnostics_complete"] = False
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


def prepare_client(runtime, argv, cwd, log, cancel, deadline, *, env=ENV, stderr_log=None, clients=None):
    """A preparation client belongs to the same execution as validation."""
    try:
        return _gate_client(runtime, argv, cwd, log, cancel, deadline,
                            cleanups=runtime._preparation_cleanups, env=env, stderr_log=stderr_log, clients=clients)
    except BaseException as error:
        if hasattr(error, "client_cleanup"):
            error.preparation_cleanup = error.client_cleanup
        raise


def captured_client(runtime, argv, cwd, cancel, deadline, *, env=ENV, clients=None):
    output, error = io.BytesIO(), io.BytesIO()
    try:
        code = prepare_client(runtime, argv, cwd, output, cancel, deadline, env=env, stderr_log=error, clients=clients)
    except BaseException as failure:
        # Keep already captured, separate output on failure too. These bytes
        # are not placed in cleanup metadata or interpolated into diagnostics.
        failure.stdout, failure.stderr = output.getvalue(), error.getvalue()
        raise
    return subprocess.CompletedProcess(argv, code, output.getvalue(), error.getvalue())


def source_check(runtime, request, phase, log, cancel, deadline, *, clients=None):
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
        request.parent, cancel, deadline, clients=clients)
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
            "--tmpfs", f"/home/cmh:rw,nosuid,nodev,size=16m,mode=0700,uid={os.getuid()},gid={os.getgid()}",
            "--mount", f"type=bind,src={workspace},dst=/app",
            "--mount", f"type=bind,src={workspace / '.git'},dst=/app/.git,readonly",
            "--workdir=/app", "--entrypoint=/usr/bin/env", policy["image_id"], "-i",
            "PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/home/cmh", "LANG=C.UTF-8", "TZ=UTC",
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


def temporary_binding(spec, target, name, transcript):
    from .factory import digest
    return {"mission_id": spec["mission_id"], "operation_id": Path(transcript).stem,
            "target_sha256": digest(target), "container_name": name}


def recover(policy, spec, target, command, transcript):
    """One-shot cleanup on resume; never retry validation or settle its UNKNOWN."""
    from .factory import digest
    path = Path(transcript).with_suffix(".container.json")
    result = {"target": target, "mission_id": spec["mission_id"], "cleanup_confirmed": False,
              "operation_replayed": False, "resources": [], "temporary_directory_cleanup_confirmed": False,
              "local_clients_stop_confirmed": False}
    temporary_fd = -1
    try:
        # Bound reads still permit diagnosis of old records, but missing original
        # allocation identity never authorizes cleanup or an operation replay.
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
        target_matches = (type(record.get("version")) is int and record["version"] == 3
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
        identity = record["temporary_directory_identity"]
        if (not isinstance(identity, dict) or identity.get("path") != str(temporary)
                or identity.get("binding") != temporary_binding(spec, target, name, transcript)
                or not re.fullmatch(r"[a-f0-9]{32}", str(identity.get("nonce", "")))):
            raise ValueError("temporary allocation task/operation identity is missing or changed")
        result["temporary_directory_identity"] = identity
        temporary_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        _validate_directory(temporary_fd, identity)
        # The journal must be sealed after ALL directory-using clients stopped,
        # including preparation, source queries, service startup and validation.
        # Old v3 directory identities without this evidence remain UNKNOWN.
        result["client_stop_evidence"] = client_stop_evidence(transcript, record, raw)
        result["local_clients_stop_confirmed"] = True
        for resource in expected:
            cleaned, code = remove_owned(resource["name"], name, resource["labels"])
            result["resources"].append({"name": resource["name"], "cleanup_confirmed": cleaned, "exit_code": code})
        result["cleanup_confirmed"] = all(r["cleanup_confirmed"] for r in result["resources"])
        if result["cleanup_confirmed"]:
            remove_directory(temporary, identity, held_fd=temporary_fd,
                             claim_log=Path(transcript).with_suffix(".container.claims.jsonl"))
            result["temporary_directory_cleanup_confirmed"] = True
        result["cleanup_confirmed"] &= result["temporary_directory_cleanup_confirmed"]
        if not result["cleanup_confirmed"]:
            result["status"] = "UNKNOWN"
    except (OSError, ValueError, KeyError, TypeError, TaskTempError, subprocess.SubprocessError) as error:
        result["cleanup_confirmed"] = False
        result["temporary_directory_cleanup_confirmed"] = False
        result["status"] = "UNKNOWN"
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
    finally:
        if temporary_fd != -1:
            os.close(temporary_fd)
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
    temporary, temporary_fd, temporary_identity = allocate_directory(
        transcript.parent, "cmh-validation-", temporary_binding(spec, target, name, transcript))
    clients = None
    try:
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
            record = {"version": 3, "target_sha256": digest(target), "mission_id": spec["mission_id"], "policy": policy,
                      "profile": profile, "container_name": name, "resources": resources,
                      "temporary_directory": str(temporary), "temporary_directory_identity": temporary_identity}
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
                clients = _ClientStops(runtime, transcript, record, raw)
                check_stopped(cancel, deadline)
                request = Path(temporary) / "source-check.json"
                with request.open("x") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    json.dump({"spec": spec, "cwd": str(cwd), "target": target, "workspace": str(workspace)}, stream)
                def client(argv, *, env=ENV, timeout):
                    return captured_client(runtime, argv, temporary, cancel,
                                           min(deadline, time.monotonic() + timeout), env=env, clients=clients)
                before = source_check(runtime, request, "candidate", log, cancel, deadline, clients=clients)["source"]
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
                        if prepare_client(runtime, argv, temporary, log, cancel, deadline, env=git_env, clients=clients):
                            raise RuntimeError("validation source preparation failed")
                    # All original diff helpers consume GITHUB_BASE_REF, not
                    # BASE_REF alone. Pin and verify their ref in this snapshot.
                    base_output = io.BytesIO()
                    argv = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                            "-c", "core.fsmonitor=false", "-C", str(workspace),
                            "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"]
                    code = prepare_client(runtime, argv, temporary, base_output, cancel, deadline, env=git_env, clients=clients)
                    log.write(base_output.getvalue())
                    if code or base_output.getvalue().strip() != target["base"].encode():
                        raise ValueError("validation diff reference differs from approved full BASE")
                    labels = [v for k, value in resources[1]["labels"].items() for v in ("--label", k + "=" + value)]
                    create = ["/usr/bin/docker", "create", "--pull=never", "--name", dependency_name, *labels,
                              "--network=none", "--entrypoint=/usr/bin/true", image]
                    if prepare_client(runtime, create, temporary, log, cancel,
                                            min(deadline, time.monotonic() + 15), clients=clients):
                        raise RuntimeError("dependency copy container could not start")
                    copied = prepare_client(runtime,
                        ["/usr/bin/docker", "cp", dependency_name + ":/app/node_modules", str(workspace / "node_modules")],
                        temporary, log, cancel, min(deadline, time.monotonic() + 60), clients=clients)
                    result["image_node_dependencies_copied"] = copied == 0
                finally:
                    cleaned, code = remove_owned(dependency_name, name, resources[1]["labels"])
                    result.update(dependencies_cleanup_confirmed=cleaned, dependencies_cleanup_exit_code=code)
                    if not cleaned:
                        raise RuntimeError("dependency copy container cleanup could not be confirmed")
                check_stopped(cancel, deadline)
                snapshot = source_check(runtime, request, "snapshot", log, cancel, deadline, clients=clients)["snapshot"]
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
                    cleanups=validation_cleanups, password=service.password.encode() if service else None,
                    clients=clients, role="validation")
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
                        final = source_check(runtime, request, "final", log, cancel, deadline, clients=clients)
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
    finally:
        result["temporary_directory_identity"] = temporary_identity
        result["temporary_directory_cleanup_confirmed"] = False
        result["local_clients_stop_confirmed"] = False
        result["local_clients_stop_status"] = "UNKNOWN"
        try:
            if clients is None:
                raise ValueError("container client dispatch evidence was not established")
            result["client_stop_evidence"] = clients.seal()
            result["local_clients_stop_confirmed"] = True
            result["local_clients_stop_status"] = "CONFIRMED"
        except (OSError, ValueError, KeyError, TypeError) as error:
            result.update(cleanup_confirmed=False, local_clients_stop_error=str(error))
            # Keep a known timeout/cancel/execution failure distinct from the
            # UNKNOWN stop fact. Neither can authorize cleanup or delivery.
            if result.get("status") not in {"TIMEOUT", "CANCELLED", "BLOCKED_ENVIRONMENT"}:
                result["status"] = "UNKNOWN"
        finally:
            if clients is not None:
                clients.close()
        try:
            if result.get("cleanup_confirmed") is not True or result.get("dependencies_cleanup_confirmed", True) is not True:
                # A known failed cleanup remains the original failed outcome,
                # with its exact scratch retained for cleanup-only recovery.
                result["temporary_cleanup_error"] = "validation clients/resources not confirmed stopped; retained at " + str(temporary)
                result["cleanup_confirmed"] = False
                if result.get("status") == "PASS":
                    result["status"] = "BLOCKED_ENVIRONMENT"
            else:
                remove_directory(temporary, temporary_identity, held_fd=temporary_fd,
                                 claim_log=transcript.with_suffix(".container.claims.jsonl"))
                result["temporary_directory_cleanup_confirmed"] = True
        except TaskTempError as error:
            result.update(status="UNKNOWN", temporary_cleanup_error=str(error), cleanup_confirmed=False)
        finally:
            os.close(temporary_fd)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result
