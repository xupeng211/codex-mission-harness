"""Durable, identity-bound stage commits for the external Reviewer V2 runners.

The mission journal owns supervised jobs. These standalone reviewer processes use
the same private evidence directory and fsync artifact primitives as their receipts.
An advisory lock covers discovery, invocation, and publication. The lock is released
by the kernel on process death; a private state file, never a bare numeric cursor,
is the recovery authority.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Callable


STATE_VERSION = 1


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_state(fd: int, state: dict) -> None:
    name = f".state.{uuid.uuid4().hex}.tmp"
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, "wb") as stream:
            handle = -1
            stream.write(canonical(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, "state.json", src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        if handle >= 0:
            os.close(handle)
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass


def _start_ticks() -> str | None:
    try:
        return Path(f"/proc/{os.getpid()}/stat").read_text().rsplit(") ", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


class ReviewRun:
    """One serialized review run, with committed artifacts checked on every reuse."""

    def __init__(self, evidence: Path, repository_root: Path, identity: dict,
                 stages: list[tuple[str, str]], storage, *, prefix: str):
        if os.environ.get('CMH_RESOURCE_MISSION_ID') == 'HARNESS_CURRENT_VERSION_DELIVERY':
            from .formal_delivery_gate import load_authorization, require_review_authority
            require_review_authority(load_authorization())
        self.storage = storage
        self.evidence, self.parent_fd = storage.open_private_directory(evidence, repository_root)
        self.lock_fd = os.open(".review-v2.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600,
                               dir_fd=self.parent_fd)
        info = os.fstat(self.lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unsafe review lease")
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("active review lease blocks concurrent resume") from exc
        self.identity = dict(identity)
        self.stages = list(stages)
        self.prefix = prefix
        self.fd = -1
        self.name = ""
        self.state: dict = {}
        try:
            self._select_run()
        except BaseException:
            os.close(self.lock_fd)
            os.close(self.parent_fd)
            raise

    def _select_run(self) -> None:
        candidates = []
        for name in os.listdir(self.parent_fd):
            if not name.startswith(self.prefix) or not name[len(self.prefix):].isalnum():
                continue
            try:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
                try:
                    raw = self.storage.read_private_artifact(fd, "state.json")
                    state = json.loads(raw)
                    candidates.append((state.get("created_at", 0), name, state))
                finally:
                    os.close(fd)
            except FileNotFoundError:
                continue
        for _, name, state in sorted(candidates, reverse=True):
            if state.get("invalidated"):
                continue
            if state.get("identity") != self.identity and os.environ.get("CMH_RESOURCE_MISSION_ID") == "HARNESS_CURRENT_VERSION_DELIVERY":
                from .artifact_lineage import reusable_review_identity, review_history
                try:
                    reusable_review_identity(state['identity'], self.identity)
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
                    try:
                        review_history(state, lambda path: self.storage.read_private_artifact(fd, path))
                    finally:
                        os.close(fd)
                except (ValueError, KeyError):
                    pass  # Ineligible state takes the existing invalidation path.
                else:
                    self.identity = dict(state['identity'])  # Original provenance is never rewritten.
            if state.get("identity") != self.identity:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
                try:
                    state["invalidated"] = True
                    state["invalidation_reason"] = "review identity changed"
                    _atomic_state(fd, state)
                finally:
                    os.close(fd)
                break
            if state.get("last_failure") and not state["last_failure"].get("resume_allowed"):
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
                try:
                    state["invalidated"] = True
                    state["invalidation_reason"] = "terminal review failure"
                    _atomic_state(fd, state)
                finally:
                    os.close(fd)
                break
            if state.get("state_version") != STATE_VERSION or state.get("stages") != [list(item) for item in self.stages]:
                raise ValueError("matching review state has invalid version or plan")
            self.fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent_fd)
            self.name, self.state = name, state
            self.validate_state()
            self.state["lease"] = {"pid": os.getpid(), "start_ticks": _start_ticks(),
                                   "run_id": self.state["review_run_id"]}
            _atomic_state(self.fd, self.state)
            return
        run_id = uuid.uuid4().hex
        self.name = self.prefix + run_id
        self.fd = self.storage.create_private_child_directory(self.parent_fd, self.name)
        self.state = {"state_version": STATE_VERSION, "review_run_id": run_id,
                      "identity": self.identity, "stages": [list(item) for item in self.stages],
                      "completed": {}, "completed_order": [],
                      "current_stage": self.stages[0][0] if self.stages else "receipt",
                      "next_stage": self.stages[0][0] if self.stages else "receipt",
                      "total_chunks": sum(kind == "chunk" for _, kind in self.stages),
                      "completed_chunk_ids": [], "completed_group_ids": [],
                      "cross_group_completed": False, "final_completed": False,
                      "receipt_written": False, "created_at": time.time_ns(),
                      "diagnostic_artifacts": [],
                      "failure_count": 0, "last_failure": None,
                      "lease": {"pid": os.getpid(), "start_ticks": _start_ticks(), "run_id": run_id}}
        _atomic_state(self.fd, self.state)

    @property
    def path(self) -> Path:
        return self.evidence / self.name

    def validate_state(self) -> None:
        completed = self.state.get("completed")
        if not isinstance(completed, dict) or self.state.get("review_run_id") != self.name[len(self.prefix):]:
            raise ValueError("review state is invalid")
        keys = self.state.get("completed_order")
        if not isinstance(keys, list) or keys != [name for name, _ in self.stages[:len(keys)]] or set(keys) != set(completed):
            raise ValueError("review state has a skipped or reordered stage")
        expected_next = self.stages[len(keys)][0] if len(keys) < len(self.stages) else (
            "complete" if self.state.get("receipt_written") else "receipt")
        if self.state.get("next_stage") != expected_next or self.state.get("final_completed") != (len(keys) == len(self.stages)):
            raise ValueError("review stage cursor differs from committed artifacts")
        for name, kind in self.stages[:len(keys)]:
            record = completed[name]
            if (record.get("artifact_path") != name + ".json" or
                    record.get("validator_result") != "PASS" or
                    record.get("input_hash") is None or record.get("output_hash") is None):
                raise ValueError("review stage record is incomplete")
            raw = self.storage.read_private_artifact(self.fd, record["artifact_path"])
            if sha256(raw) != record.get("artifact_sha256") or sha256(raw) != record["output_hash"]:
                raise ValueError("committed review artifact changed")
        for diagnostic in self.state.get("diagnostic_artifacts", []):
            raw = self.storage.read_private_artifact(self.fd, diagnostic["path"])
            if sha256(raw) != diagnostic["sha256"]:
                raise ValueError("review diagnostic artifact changed")

    def stage(self, name: str, kind: str, input_bytes: bytes, execute: Callable[[], bytes],
              validate: Callable[[bytes], object]) -> tuple[bytes, object]:
        index = self.stages.index((name, kind))
        if self.state["completed_order"] != [item[0] for item in self.stages[:index]] and name not in self.state["completed"]:
            raise ValueError("review prerequisite stage incomplete")
        input_hash = sha256(input_bytes)
        record = self.state["completed"].get(name)
        if record is not None:
            if record["input_hash"] != input_hash:
                raise ValueError("committed review stage input changed")
            raw = self.storage.read_private_artifact(self.fd, record["artifact_path"])
            if sha256(raw) != record["artifact_sha256"]:
                raise ValueError("committed review stage artifact changed")
            return raw, validate(raw)
        artifact = name + ".json"
        # A crash after artifact publication but before state commit leaves an
        # uncommitted artifact. It is never reused as a completed model result.
        try:
            self.storage.read_private_artifact(self.fd, artifact)
        except FileNotFoundError:
            pass
        else:
            os.unlink(artifact, dir_fd=self.fd)
            os.fsync(self.fd)
        diagnostic_start = len(self.state.get("diagnostic_artifacts", []))
        try:
            raw = execute()
        except BaseException as exc:
            from .resource_gate import FundingPause
            if not isinstance(exc, FundingPause) and kind in {"chunk", "group", "cross-group"}:
                self._failed_response(name, kind, input_bytes, None, exc, diagnostic_start)
            raise
        try:
            result = validate(raw)
        except BaseException as exc:
            if kind in {"chunk", "group", "cross-group"}:
                self._failed_response(name, kind, input_bytes, raw, exc, diagnostic_start)
            raise
        self.storage.write_private_artifact(self.fd, artifact, raw, uuid.uuid4().hex)
        self.state["completed"][name] = {
            "artifact_path": artifact, "artifact_sha256": sha256(raw),
            "input_hash": input_hash, "output_hash": sha256(raw),
            "completed_at": int(time.time()), "validator_result": "PASS"}
        self.state["completed_order"].append(name)
        self.state["failure_count"] = 0
        self.state["last_failure"] = None
        self.state["funding_status"] = None
        next_index = index + 1
        self.state["current_stage"] = name
        self.state["next_stage"] = self.stages[next_index][0] if next_index < len(self.stages) else "receipt"
        self.state["completed_chunk_ids"] = [n for n, k in self.stages[:next_index] if k == "chunk"]
        self.state["completed_group_ids"] = [n for n, k in self.stages[:next_index] if k == "group"]
        self.state["cross_group_completed"] = any(k == "cross-group" for _, k in self.stages[:next_index])
        self.state["final_completed"] = next_index == len(self.stages)
        _atomic_state(self.fd, self.state)
        return raw, result

    def _failed_response(self, name: str, kind: str, prompt: bytes,
                         raw: bytes | None, exc: BaseException,
                         diagnostic_start: int) -> None:
        """Append private diagnostics before a failing stage can be retried."""
        label = f"{name}-failed-raw-{uuid.uuid4().hex}.json"
        structured = None
        if raw is not None:
            try:
                envelope = json.loads(raw)
                if isinstance(envelope, dict):
                    structured = envelope.get("structured_output", envelope)
            except (ValueError, UnicodeError):
                pass
        source_error = getattr(exc, "__cause__", None) or exc
        request = self._resource_request(name, prompt)
        transport = next((item for item in reversed(self.state.get("diagnostic_artifacts", [])[diagnostic_start:])
                          if item["path"].startswith(name + "-transport-")), None)
        stream_status = "OUTPUT_PRESERVED" if raw is not None else "OUTPUT_NOT_PRODUCED"
        if transport is not None and raw is None:
            captured = json.loads(self.storage.read_private_artifact(self.fd, transport["path"]))
            if captured.get("stdout_size") or captured.get("stderr_size"):
                stream_status = "OUTPUT_PARTIAL"
        record = {"version": "cmh-failed-review-response/v1", "stage": name,
                  "kind": kind, "identity": self.identity,
                  "prompt_sha256": sha256(prompt), "prompt_base64": base64.b64encode(prompt).decode(),
                  "prompt_utf8": prompt.decode("utf-8", "replace"),
                  "raw_model_output_status": "OUTPUT_NOT_PRODUCED" if raw is None else "RETURNED",
                  "stream_status": stream_status, "transport_artifact": transport,
                  "raw_model_output_sha256": sha256(raw) if raw is not None else None,
                  "raw_model_output_base64": base64.b64encode(raw).decode() if raw is not None else None,
                  "raw_model_output_utf8": raw.decode("utf-8", "replace") if raw is not None else None,
                  "structured_output": structured,
                  "parser_error_class": type(source_error).__name__,
                  "parser_error": str(source_error),
                  "source_binding_diagnostic": getattr(source_error, "details", None),
                  "resource_request": request,
                  "resource_stage": os.environ.get("CMH_RESOURCE_STAGE"),
                  "resource_run_id": self.state["review_run_id"]}
        rendered = canonical(record)
        self.storage.write_private_artifact(self.fd, label, rendered, uuid.uuid4().hex)
        self._index_diagnostic(label, rendered)
        self.last_failed_raw_artifact = label
        self.last_failed_raw_sha256 = sha256(rendered)

    def _resource_request(self, name: str, prompt: bytes) -> dict | None:
        request = None
        ledger_path = os.environ.get("CMH_RESOURCE_LEDGER")
        if ledger_path:
            try:
                rows = json.loads(Path(ledger_path).read_bytes())["requests"]
                matches = [row for row in rows
                           if row.get("run_id") == self.state["review_run_id"]
                           and row.get("stage") in {name, name + ".json"}
                           and row.get("prompt_sha256") == sha256(prompt)]
                if len(matches) == 1:
                    row = matches[0]
                    request = {key: row.get(key) for key in
                               ("number", "request_id", "status", "reported_usage")}
            except (OSError, ValueError, KeyError):
                pass
        return request

    def _index_diagnostic(self, label: str, rendered: bytes) -> None:
        # If interrupted between the two fsyncs, the uniquely named private
        # artifact remains discoverable but never becomes a completed stage.
        self.state.setdefault("diagnostic_artifacts", []).append(
            {"path": label, "sha256": sha256(rendered)})
        _atomic_state(self.fd, self.state)

    def capture_transport(self, name: str, prompt: bytes, stdout: bytes | None,
                          stderr: bytes | None, *, secret_echo: bool = False) -> None:
        """Append a private transport snapshot before parsing can discard streams."""
        if secret_echo:
            stdout = stderr = None
        label = f"{name}-transport-{uuid.uuid4().hex}.json"
        record = {"version": "cmh-review-transport/v1", "stage": name,
                  "identity": self.identity, "prompt_sha256": sha256(prompt),
                  "prompt_base64": base64.b64encode(prompt).decode(),
                  "stdout_status": "REDACTED_CREDENTIAL_ECHO" if secret_echo else
                                   "OUTPUT_NOT_PRODUCED" if stdout is None else "CAPTURED",
                  "stdout_sha256": sha256(stdout) if stdout is not None else None,
                  "stdout_size": len(stdout) if stdout is not None else None,
                  "stdout_base64": base64.b64encode(stdout).decode() if stdout is not None else None,
                  "stderr_status": "REDACTED_CREDENTIAL_ECHO" if secret_echo else
                                   "OUTPUT_NOT_PRODUCED" if stderr is None else "CAPTURED",
                  "stderr_sha256": sha256(stderr) if stderr is not None else None,
                  "stderr_size": len(stderr) if stderr is not None else None,
                  "stderr_base64": base64.b64encode(stderr).decode() if stderr is not None else None,
                  "resource_request": self._resource_request(name, prompt),
                  "resource_run_id": self.state["review_run_id"]}
        rendered = canonical(record)
        self.storage.write_private_artifact(self.fd, label, rendered, uuid.uuid4().hex)
        self._index_diagnostic(label, rendered)
        self.last_transport_artifact = label
        self.last_transport_sha256 = sha256(rendered)

    def receipt(self, name: str, raw: bytes, validate: Callable[[], object]) -> Path:
        if not self.state["final_completed"]:
            raise ValueError("review stages incomplete")
        path = self.path / name
        if self.state["receipt_written"]:
            if sha256(self.storage.read_private_artifact(self.fd, name)) != self.state["receipt_sha256"]:
                raise ValueError("committed review receipt changed")
            return path
        validate()
        try:
            existing = self.storage.read_private_artifact(self.fd, name)
        except FileNotFoundError:
            self.storage.write_private_artifact(self.fd, name, raw, uuid.uuid4().hex)
        else:
            if existing != raw:
                raise ValueError("uncommitted review receipt conflicts")
        self.state["receipt_sha256"] = sha256(raw)
        self.state["receipt_written"] = True
        self.state["next_stage"] = "complete"
        _atomic_state(self.fd, self.state)
        return path

    def failure(self, failure: dict, auth_key: str | None = None) -> Path:
        funding = failure.get("failure_category") in {"PAUSED_AWAITING_MANUAL_FUNDING", "PAUSED_SUBSCRIPTION_UNAVAILABLE"}
        failure.pop("integrity_sha256", None)
        failure.pop("auth_hmac_sha256", None)
        attempt = self.state.get("failure_count", 0) + (0 if funding else 1)
        inferred = failure.get("failure_category") in {
            "CANCELLED", "CHILD_PROCESS_TIMEOUT", "MODEL_TIMEOUT", "TRANSPORT_ERROR",
            "TURN_TIMEOUT_UNDIAGNOSED", "TRANSIENT_CAPACITY", "TRANSIENT_TRANSPORT",
            "RATE_LIMIT", "PROVIDER_ERROR"}
        allowed = funding or (bool(failure.get("resume_allowed", inferred)) and attempt <= 1)
        reason = failure.get("resume_policy_reason", "category policy")
        if not allowed and attempt > 1:
            reason = "bounded stage retry exhausted"
        failure.update(stage=self.state["next_stage"],
                       durable_completed_stages=list(self.state["completed_order"]),
                       resume_allowed=allowed, resume_policy_reason=reason,
                       stage_failure_attempt=attempt, max_resumable_failures=1,
                       next_stage=self.state["next_stage"], identity_snapshot=self.identity)
        if "runner_sha256" in failure and "stage_id" in failure:
            failure["integrity_sha256"] = sha256(canonical(failure))
        if auth_key:
            import hmac
            failure["auth_hmac_sha256"] = hmac.new(auth_key.encode(), canonical(failure), hashlib.sha256).hexdigest()
        name = "failure.json"
        try:
            self.storage.read_private_artifact(self.fd, name)
        except FileNotFoundError:
            pass
        else:
            name = f"failure-{uuid.uuid4().hex}.json"
        self.storage.write_private_artifact(self.fd, name, canonical(failure), uuid.uuid4().hex)
        self.state["failure_count"] = attempt
        self.state["funding_status"] = failure["failure_category"] if funding else None
        self.state["last_failure"] = {"artifact_path": name, "resume_allowed": allowed,
                                      "stage": self.state["next_stage"]}
        _atomic_state(self.fd, self.state)
        return self.path / name

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)
        os.close(self.parent_fd)
