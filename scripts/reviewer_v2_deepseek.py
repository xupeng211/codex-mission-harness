#!/usr/bin/env python3
"""Independent DeepSeek lane for Harness self-review; exact diff, bounded source."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import deepseek_review as legacy  # noqa: E402
from harness.reviewer_v2_contract import (  # noqa: E402
    FINDING_GUIDANCE, SUPPLIED_CLAIM_GUIDANCE, SourceBindingError, bind_findings, canonical, parse_chunk, parse_synthesis, sha256,
    validate_bound_result, contract_authorization_identity,
)
from harness.model_registry import load_registry  # noqa: E402
from harness.model_qualification import validate_qualification_receipt  # noqa: E402
from harness import full_diff_manifest as full
from harness.review_resume import ReviewRun
from harness import deepseek_direct as direct  # noqa: E402
from harness.review_failure_diagnostics import (  # noqa: E402
    command_identity, environment_identity, stream_metadata,
)

VERSION = "cmh-reviewer-v2-deepseek/v2"
DECISION_RATIONALE_INSTRUCTION = 'Every decision, including UPHELD and DISPUTED, MUST contain a substantive rationale of at least 24 characters after trimming whitespace, explaining why that disposition is supported. Never omit rationale or use empty or template filler text. For UPHELD only source_quote/source_id are empty, not rationale. Example (use the actual required finding_id and source-specific reasoning, not these illustrative values): {"finding_id":"C000F000","decision":"UPHELD","rationale":"The supplied source still permits the invalid input to bypass validation.","source_quote":"","source_id":""}. '
FAILURE_CATEGORIES = frozenset({
    "CHILD_PROCESS_TIMEOUT", "MODEL_TIMEOUT", "TRANSPORT_ERROR", "AUTH_ERROR",
    "CLI_USAGE_ERROR", "INVALID_ARGUMENT", "RATE_LIMIT", "QUOTA_ERROR",
    "PROVIDER_ERROR", "CONTEXT_LIMIT", "SCHEMA_INVOCATION_ERROR",
    "LOCAL_LAUNCHER_ERROR", "SIGNALLED", "UNKNOWN_NONZERO_EXIT",
    "MALFORMED_JSON", "SCHEMA_VALIDATION_FAILED", "EMPTY_OUTPUT",
    "PARTIAL_OUTPUT", "RECEIPT_WRITE_FAILED", "INTERNAL_EXCEPTION", "CANCELLED", "UNKNOWN",
})


class ReviewStageFailure(RuntimeError):
    def __init__(self, category: str, stage: str):
        if category not in FAILURE_CATEGORIES:
            raise ValueError("invalid review failure category")
        self.category = category
        self.stage = stage
        self.failure_artifact: str | None = None
        super().__init__(f"{stage} review failed: {category}")


def _stderr_markers(stderr: bytes | str | None) -> dict[str, bool]:
    value = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else (stderr or "")
    value = value.casefold()
    return {"auth": bool(re.search(r"\b(?:401|403)\b|unauthori|authentication|invalid.token", value)),
            "transport": bool(re.search(r"connection|network|proxy|disconnect|socket", value)),
            "timeout": "timeout" in value or "timed out" in value,
            "rate_limit": bool(re.search(r"\b429\b|rate.limit", value))}


def _validate_completion_artifact(raw, mission_id=None, prompt=None):
    from harness.formal_delivery_gate import NEW_MISSION
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return  # Existing parser reports malformed/empty output.
    formal = (mission_id == NEW_MISSION or os.environ.get("CMH_RESOURCE_MISSION_ID") == NEW_MISSION)
    if formal or isinstance(value, dict) and "direct_completion" in value:
        try:
            schema = CHUNK_SCHEMA if set(value.get("structured_output", {})) == {"findings"} else SYNTHESIS_SCHEMA
            direct.validate_envelope(raw, schema=schema, prompt=prompt)
        except direct.DirectFailure:
            raise ValueError("invalid Direct completion evidence") from None


def _parse_stage(raw: str, parser, state: dict, *, prompt=None):
    state["parser_entered"] = True
    state["parser_result"] = "FAIL"
    try:
        json.loads(raw)
    except (ValueError, UnicodeError):
        pass
    else:
        state["schema_validation_entered"] = True
        state["schema_validation_result"] = "FAIL"
    try:
        _validate_completion_artifact(raw, prompt=prompt)
        result = parser(raw)
        state["parser_result"] = "PASS"
        state["schema_validation_result"] = "PASS"
        return result
    except (ValueError, UnicodeError, TypeError) as exc:
        state["parser_error_class"] = type(exc).__name__
        if isinstance(exc, SourceBindingError):
            state["source_binding_diagnostic"] = {
                **exc.details, "stage_id": state.get("stage_id"),
                "parser_entered": state["parser_entered"],
                "schema_validation_entered": state["schema_validation_entered"],
                "validation_result": "FAIL"}
        state["resume_allowed"] = False
        state["resume_policy_reason"] = "invalid Direct result cannot trigger automatic resend"
        if not raw.strip():
            category = "EMPTY_OUTPUT"
        else:
            try:
                json.loads(raw)
            except json.JSONDecodeError as invalid:
                category = "PARTIAL_OUTPUT" if invalid.pos >= len(raw) - 1 else "MALFORMED_JSON"
            else:
                category = "SCHEMA_VALIDATION_FAILED"
                state["schema_validation_error_class"] = type(exc).__name__
                safe_reasons = {
                    "unknown disposition finding_id": "UNKNOWN_FINDING_ID",
                    "duplicate disposition finding_id": "DUPLICATE_FINDING_ID",
                    "missing blocker disposition": "MISSING_FINDING_ID",
                    "dispute lacks an exact bound source reference": "INVALID_SOURCE_BINDING",
                }
                state["schema_validation_reason"] = safe_reasons.get(str(exc), "OTHER")
        raise ReviewStageFailure(category, state["stage"]) from exc
FINDING_SCHEMA = {"type": "object", "additionalProperties": False,
                  "required": ["severity", "title", "evidence"], "properties": {
                      "severity": {"enum": ["P0", "P1", "P2", "P3"]},
                      "title": {"type": "string", "minLength": 1},
                      "evidence": {"type": "string", "minLength": 1}}}
DECISION_SCHEMA = {"type": "object", "additionalProperties": False,
                   "required": ["finding_id", "decision", "rationale", "source_quote",
                                "source_id"],
                   "properties": {"finding_id": {"type": "string"},
                                  "decision": {"enum": ["UPHELD", "DISPUTED"]},
                                  "rationale": {"type": "string", "minLength": 24},
                                  "source_quote": {"type": "string"},
                                  "source_id": {"type": "string"}}}
CHUNK_SCHEMA = {"type": "object", "additionalProperties": False,
                "required": ["findings"], "properties": {
                    "findings": {"type": "array", "items": FINDING_SCHEMA}}}
SYNTHESIS_SCHEMA = {"type": "object", "additionalProperties": False,
                    "required": ["findings", "decisions", "summary"], "properties": {
                        "findings": {"type": "array", "items": FINDING_SCHEMA},
                        "decisions": {"type": "array", "items": DECISION_SCHEMA},
                        "summary": {"type": "string", "minLength": 32, "maxLength": 4000}}}


def _render_source(source: bytes) -> str:
    try:
        return "UTF-8 exact diff:\n" + source.decode("utf-8")
    except UnicodeError:
        return "Base64 exact diff bytes:\n" + base64.b64encode(source).decode()


def _bounded(prompt: str) -> str:
    if len(prompt.encode()) > full.MAX_PROMPT_BYTES:
        raise ValueError("review prompt exceeds bounded size")
    return prompt


def _invoke(command: list[str], prompt: str, env: dict, timeout: int, token: str,
            *, stage: str, evidence_fd: int, artifact: str,
            state: dict | None = None, persist: bool = True,
            transport_sink=None) -> tuple[str, str]:
    state = {} if state is None else state
    state.pop("timeout_at", None)
    state.pop("output_sha256", None)
    started_monotonic = time.monotonic()
    state.update(stage=stage, stage_id=artifact, input_sha256=sha256(prompt.encode()),
                 started_at=int(time.time()), timeout_seconds=timeout,
                 command_identity_hash=command_identity(command),
                 environment_identity_hash=environment_identity(env),
                 stdout_present=False, stdout_size=0, stdout_sha256=None,
                 stderr_present=False, stderr_size=0, stderr_sha256=None,
                 stdout_truncated=False, stderr_truncated=False,
                 cli_wrapper={"is_error": None, "api_error_status": None, "subtype": None},
                 exit_code=None, signal_if_any=None, stderr_markers={},
                 sanitized_error_class=None, sanitized_error_markers={},
                 resume_allowed=False, resume_policy_reason="stage not completed",
                 parser_entered=False, parser_result="NOT_ENTERED",
                 schema_validation_entered=False, schema_validation_result="NOT_ENTERED",
                 parser_error_class=None, schema_validation_error_class=None,
                 schema_validation_reason=None, source_binding_diagnostic=None)
    os.environ["CMH_RESOURCE_STAGE"] = artifact
    try:
        schema = json.loads(command[command.index("--json-schema") + 1])
        raw = direct.invoke(_bounded(prompt), token, schema, timeout=timeout, stage=artifact)
        state.update(exit_code=0, output_sha256=sha256(raw),
                     finished_at=int(time.time()),
                     duration_seconds=round(time.monotonic() - started_monotonic, 3),
                     **stream_metadata(raw, b""))
        if transport_sink is not None:
            transport_sink(prompt.encode(), raw, b"")
        if persist:
            legacy.write_private_artifact(evidence_fd, artifact, raw, uuid.uuid4().hex)
        return raw.decode(), sha256(raw)
    except direct.DirectFailure as exc:
        state.update(sanitized_error_class=exc.code, resume_allowed=False,
                     finished_at=int(time.time()),
                     duration_seconds=round(time.monotonic() - started_monotonic, 3),
                     resume_policy_reason="Direct failure cannot trigger automatic resend")
        if transport_sink is not None:
            transport_sink(prompt.encode(), None, exc.code.encode())
        raise ReviewStageFailure("MODEL_TIMEOUT" if exc.code == "REQUEST_TIMEOUT" else "SCHEMA_VALIDATION_FAILED", stage) from None


def _prompt_head(base: str, head: str, diff_hash: str, scope: str) -> str:
    return (FINDING_GUIDANCE + SUPPLIED_CLAIM_GUIDANCE + "Independent restricted code review. Do not use tools or filesystem. "
            "Return only schema JSON. Report all P0/P1/P2 findings. "
            f"Base={base} Head={head} DiffSHA256={diff_hash} Scope={scope}\n")


def _expected(records: list[dict]) -> list[dict]:
    return [item for record in records for item in record["bound_findings"]]


def _receipt_hmac(receipt: dict, token: str) -> str:
    unsigned = dict(receipt)
    unsigned.pop("auth_hmac_sha256", None)
    return hmac.new(token.encode(), canonical(unsigned), hashlib.sha256).hexdigest()


def run(args: argparse.Namespace) -> dict:
    root = Path(args.repo).resolve()
    base, head = legacy.full_sha(args.base), legacy.full_sha(args.head)
    if legacy.git(root, "rev-parse", "HEAD").decode().strip() != head:
        raise ValueError("worktree HEAD differs from requested HEAD")
    if legacy.git(root, "status", "--porcelain"):
        raise ValueError("review worktree is dirty")
    repository = legacy.repository_identity(
        legacy.git(root, "config", "--get", "remote.origin.url").decode().strip())
    diff = full.read_diff(root, base, head)
    chunks, groups = full.plan(diff)
    _, manifest = full.build_manifest(root, base, head, repository)
    full.validate_manifest(root, manifest, repository, base, head, review_ready=True)
    diff_hash = sha256(diff)
    registry_path = getattr(args, "registry", None)
    registry = load_registry(registry_path)
    model = registry.role("independent_reviewer")
    if model.provider != "deepseek":
        raise ValueError("independent reviewer provider is not DeepSeek")
    run = None
    token = ""
    auth_key = ""
    delivery_context = None
    stage_state: dict = {"stage": "setup", "stage_id": "setup", "input_sha256": diff_hash,
                         "started_at": int(time.time()), "stdout_present": False,
                         "exit_code": None, "stderr_markers": {},
                         "parser_error_class": None, "schema_validation_error_class": None}
    previous_signals = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        executable = "DIRECT_DEEPSEEK_API"
        token = legacy.read_token_file(args.token_file, root)
        if not token:
            raise ValueError("missing DeepSeek credential")
        if token.encode() in diff:
            raise ValueError("credential appears in reviewed source; evidence publication blocked")
        auth_key_file = getattr(args, "auth_key_file", None)
        auth_key = legacy.read_token_file(auth_key_file, root) if auth_key_file else token
        if not auth_key:
            raise ValueError("missing review authentication key")
        qualification = getattr(args, "qualification", None)
        if not qualification:
            raise ValueError("live DeepSeek review requires an independent reviewer qualification receipt")
        qualified = validate_qualification_receipt(qualification, model, auth_key=auth_key,
                                       role="independent_reviewer", registry_path=registry_path)
        from harness.formal_delivery_gate import bind_review
        delivery_context = bind_review(args.mission_id, root, base, head,
                                       sha256(registry.path.read_bytes()), model, qualified)
        contract_auth_sha = contract_authorization_identity(args.mission_id)
        identity = {"provider": model.provider, "role": "independent_reviewer",
                    "model": model.model, "model_configuration": model.identity(),
                    "repository": repository, "mission_id": args.mission_id,
                    "base_sha": base, "head_sha": head, "diff_hash": diff_hash,
                    "registry_hash": sha256(registry.path.read_bytes()),
                    "runner_hash": sha256(Path(__file__).read_bytes()),
                    "invocation_hash": sha256(Path(direct.__file__).read_bytes()),
                    "schema_manifest_hash": sha256(canonical({"chunk": CHUNK_SCHEMA,
                                                             "synthesis": SYNTHESIS_SCHEMA})),
                    "source_binding_contract_authorization_sha256": contract_auth_sha,
                    "qualification_receipt_identity": sha256(Path(qualification).read_bytes())
                    if Path(qualification).exists() else sha256(str(qualification).encode()),
                    "input_manifest_identity": sha256(canonical({"chunks": chunks, "groups": groups})),
                    "full_manifest_sha256": manifest["manifest_sha256"],
                    "chunking_policy": full.CHUNKING,
                "manifest_implementation_sha256": sha256(Path(full.__file__).read_bytes())}
        identity["review_execution_identity"] = sha256(canonical(identity))
        stages = [(f"chunk-{i:03d}", "chunk") for i in range(len(chunks))] + [
            (f"group-{i:03d}", "group") for i in range(len(groups))] + [("aggregate", "cross-group")]
        run = ReviewRun(Path(args.evidence), root, identity, stages, legacy, prefix="deepseek-v2-")
        run_id, evidence, evidence_fd = run.state["review_run_id"], run.path, run.fd
        os.environ["CMH_RESOURCE_RUN_ID"] = run_id
        command = [executable, "--model", model.model]
        env = {}  # Credentials never enter argv or captured environment metadata.
        chunk_command = command + ["--json-schema", json.dumps(CHUNK_SCHEMA, separators=(",", ":"))]
        synthesis_command = command + ["--json-schema", json.dumps(SYNTHESIS_SCHEMA, separators=(",", ":"))]
        for chunk in chunks:
            source = diff[chunk["start"]:chunk["end"]]
            prompt = (_prompt_head(base, head, diff_hash, f"chunk {chunk['index']}")
                      + "Manifest=" + manifest["manifest_sha256"] + "\nLocation metadata (not canonical coverage):"
                      + full.chunk_context(manifest, chunk["start"], chunk["end"]) + "\n"
                      + _render_source(source))
            name = f"chunk-{chunk['index']:03d}"
            raw_bytes, findings = run.stage(name, "chunk", prompt.encode(),
                lambda: _invoke(chunk_command, prompt, env, args.timeout, token,
                                stage="chunk", evidence_fd=evidence_fd,
                                artifact=name + ".json", state=stage_state, persist=False,
                                transport_sink=lambda p, out, err, secret_echo=False:
                                    run.capture_transport(name, p, out, err,
                                                          secret_echo=secret_echo))[0].encode(),
                lambda data: _parse_stage(data.decode(), parse_chunk, stage_state, prompt=prompt))
            output_hash = sha256(raw_bytes)
            chunk["bound_findings"] = bind_findings(findings, "C", chunk["index"])
            chunk["output_sha256"] = output_hash
        for group in groups:
            selected = [chunks[i] for i in group["chunk_indexes"]]
            expected = _expected(selected)
            required = [item for item in expected if item["severity"] in {"P0", "P1", "P2"}]
            source = diff[group["start"]:group["end"]]
            prompt = (_prompt_head(base, head, diff_hash, f"group {group['index']}")
                      + "Manifest=" + manifest["manifest_sha256"] + "\nLocation metadata (not canonical coverage):"
                      + full.chunk_context(manifest, group["start"], group["end"]) + "\n"
                      + "Review exact source and cross-chunk interactions. Every supplied "
                      "P0/P1/P2 finding needs exactly one decision keyed by finding_id. "
                      "Output decisions for RequiredFindingIds only; never decide P3 findings. "
                      "Do not invent, omit, or repeat finding_id values. "
                      + DECISION_RATIONALE_INSTRUCTION
                      + "UPHELD preserves the original finding automatically. DISPUTED requires "
                      "a specific rationale and source_quote copied exactly from this source. "
                      "For DISPUTED, source_id must equal GroupSourceId and source_quote "
                      "must be a verbatim, uniquely occurring quote in this group source. "
                      "The verifier computes UTF-8 byte offsets; do not submit offsets. "
                      "For UPHELD use empty source_quote/source_id. "
                      "Each evidence reference belongs to its decision finding_id. "
                      "findings contains only NEW findings; "
                      "never copy supplied findings into it. Summarize interactions for cross-group review.\n"
                      + f"RequiredFindingIds={json.dumps([item['finding_id'] for item in required])}\n"
                      + f"GroupSourceId={sha256(source)}\n"
                      + f"PriorBlockingFindings={json.dumps(required, sort_keys=True)}\n"
                      + _render_source(source))
            name = f"group-{group['index']:03d}"
            raw_bytes, result = run.stage(name, "group", prompt.encode(),
                lambda: _invoke(synthesis_command, prompt, env, args.timeout, token,
                                stage="group", evidence_fd=evidence_fd,
                                artifact=name + ".json", state=stage_state, persist=False,
                                transport_sink=lambda p, out, err, secret_echo=False:
                                    run.capture_transport(name, p, out, err,
                                                          secret_echo=secret_echo))[0].encode(),
                lambda data: _parse_stage(data.decode(), lambda value: parse_synthesis(
                    value, expected, source=source, structured_evidence=True), stage_state, prompt=prompt))
            output_hash = sha256(raw_bytes)
            group["result"] = result
            # Preserve original C identities for carried P3 and UPHELD blockers;
            # only genuinely new findings receive a G identity.
            carried_ids = {item["finding_id"] for item in expected
                           if item["severity"] == "P3" or
                           (item["finding_id"] in {d["finding_id"] for d in result["decisions"]}
                            and next(d for d in result["decisions"]
                                     if d["finding_id"] == item["finding_id"])["decision"] == "UPHELD")}
            carried = [item for item in expected if item["finding_id"] in carried_ids]
            new_bound = bind_findings(result["new_findings"], "G", group["index"])
            group["bound_findings"] = carried + new_bound
            group["output_sha256"] = output_hash
        expected = _expected(groups)
        required = [item for item in expected if item["severity"] in {"P0", "P1", "P2"}]
        summaries = [{"group_index": group["index"], "summary": group["result"]["summary"],
                      "findings": group["bound_findings"],
                      "original_chunk_findings": _expected([chunks[i] for i in group["chunk_indexes"]]),
                      "chunk_dispositions": group["result"]["decisions"]} for group in groups]
        prompt = (_prompt_head(base, head, diff_hash, "cross-group")
                  + "Reevaluate all original disputed findings and their group decisions for cross-group risks; add NEW findings if local disputes are unsound. "
                  "Analyze cross-group interactions using bounded summaries. You have no exact "
                  "source at this stage and must UPHOLD every supplied P0/P1/P2 finding. "
                  "Use empty source_quote/source_id; do not submit quote offsets. "
                  "findings contains only NEW cross-group findings. "
                  "Every blocker needs one decision keyed by finding_id.\n"
                  + DECISION_RATIONALE_INSTRUCTION
                  + "Decide RequiredFindingIds exactly once; no P3 IDs, invented IDs, or repeats.\n"
                  + f"RequiredFindingIds={json.dumps([item['finding_id'] for item in required])}\n"
                  + f"GroupSummaries={json.dumps(summaries, sort_keys=True)}")
        raw_bytes, result = run.stage("aggregate", "cross-group", prompt.encode(),
            lambda: _invoke(synthesis_command, prompt, env, args.timeout, token,
                            stage="cross-group", evidence_fd=evidence_fd,
                            artifact="aggregate.json", state=stage_state, persist=False,
                            transport_sink=lambda p, out, err, secret_echo=False:
                                run.capture_transport("aggregate", p, out, err,
                                                      secret_echo=secret_echo))[0].encode(),
            lambda data: _parse_stage(data.decode(), lambda value: parse_synthesis(
                value, expected, source=None, structured_evidence=True), stage_state, prompt=prompt))
        output_hash = sha256(raw_bytes)
        receipt = {"version": VERSION, "repository": repository,
                   "mission_id": args.mission_id, "base_sha": base, "head_sha": head,
                   "registry_sha256": sha256(registry.path.read_bytes()),
                   "runner_sha256": sha256(Path(__file__).read_bytes()),
                   "source_binding_contract_authorization_sha256": contract_auth_sha,
                   "diff_sha256": diff_hash, "provider": model.provider, "model": model.model,
                   "reasoning_effort": model.reasoning_effort, "chunks": chunks, "groups": groups,
                   "aggregate_result": result, "aggregate_output_sha256": output_hash,
                   "review_result": result["review_result"], "findings": result["findings"],
                   "command_sha256": sha256(canonical({"chunk": command_identity(chunk_command),
                                                      "synthesis": command_identity(synthesis_command)})),
                   "completed_at": run.state["created_at"] // 1_000_000_000}
        receipt['task_assignments'] = full.review_tasks(diff, manifest)
        receipt['full_manifest'] = manifest
        receipt['execution_identity'] = expected_execution(receipt, manifest, sha256(canonical(qualified)), model)
        receipt["integrity_sha256"] = sha256(canonical(receipt))
        receipt["auth_hmac_sha256"] = _receipt_hmac(receipt, auth_key)
        path = evidence / f"deepseek-v2-receipt-{head[:12]}-{run_id}.json"
        stage_state.update(stage="final receipt", stage_id=path.name,
                           input_sha256=sha256(canonical(receipt)), started_at=int(time.time()))
        # Validate the already durable model artifacts before publishing the
        # receipt. A failed run cannot leave an approval-looking receipt.
        validate(receipt, base, head, root, path, args.mission_id, repository, auth_key,
                 registry_path=registry_path)
        try:
            run.receipt(path.name, canonical(receipt), lambda: None)
        except Exception as exc:
            raise ReviewStageFailure("RECEIPT_WRITE_FAILED", "final receipt") from exc
        os.fsync(evidence_fd)
        return {"status": receipt["review_result"], "review_receipt": str(path),
                "head_sha": head}
    except (Exception, KeyboardInterrupt) as exc:
        from harness.resource_gate import FundingPause
        if isinstance(exc, FundingPause):
            if run is not None:
                run.failure(dict(exc.details, failure_category="PAUSED_AWAITING_MANUAL_FUNDING"), auth_key)
            raise
        category = (exc.category if isinstance(exc, ReviewStageFailure) else
                    "CANCELLED" if isinstance(exc, KeyboardInterrupt) else "INTERNAL_EXCEPTION")
        failure = {"status": "BLOCKED", "failure_category": category,
                   "base_sha": base, "head_sha": head, "diff_sha256": diff_hash,
                   "runner_sha256": sha256(Path(__file__).read_bytes()),
                   "registry_sha256": identity["registry_hash"] if run is not None else sha256(registry.path.read_bytes()),
                   "invocation_sha256": identity["invocation_hash"] if run is not None else sha256(Path(direct.__file__).read_bytes()),
                   "schema_manifest_sha256": identity["schema_manifest_hash"] if run is not None else sha256(canonical({"chunk": CHUNK_SCHEMA, "synthesis": SYNTHESIS_SCHEMA})),
                   "qualification_receipt_identity": identity["qualification_receipt_identity"] if run is not None else None,
                   "provider": model.provider, "model": model.model,
                   "role": "independent_reviewer",
                   "reasoning_effort": model.reasoning_effort,
                   "repository": repository, "mission_id": args.mission_id,
                   "stage": stage_state["stage"], "stage_id": stage_state["stage_id"],
                   "input_sha256": stage_state["input_sha256"],
                   "started_at": stage_state["started_at"],
                   "finished_at": int(time.time()),
                   "timeout_at": stage_state.get("timeout_at"),
                   "exit_code": stage_state.get("exit_code"),
                   "signal_if_any": stage_state.get("signal_if_any"),
                   "duration_seconds": stage_state.get("duration_seconds"),
                   "command_identity_hash": stage_state.get("command_identity_hash"),
                   "environment_identity_hash": stage_state.get("environment_identity_hash"),
                   "stdout_size": stage_state.get("stdout_size", 0),
                   "stdout_sha256": stage_state.get("stdout_sha256"),
                   "stdout_truncated": stage_state.get("stdout_truncated", False),
                   "stderr_present": stage_state.get("stderr_present", False),
                   "stderr_size": stage_state.get("stderr_size", 0),
                   "stderr_sha256": stage_state.get("stderr_sha256"),
                   "stderr_truncated": stage_state.get("stderr_truncated", False),
                   "cli_wrapper": stage_state.get("cli_wrapper"),
                   "sanitized_error_class": stage_state.get("sanitized_error_class"),
                   "sanitized_error_markers": stage_state.get("sanitized_error_markers", {}),
                   "parser_entered": stage_state.get("parser_entered", False),
                   "parser_result": stage_state.get("parser_result", "NOT_ENTERED"),
                   "schema_validation_entered": stage_state.get("schema_validation_entered", False),
                   "schema_validation_result": stage_state.get("schema_validation_result", "NOT_ENTERED"),
                   "resume_allowed": stage_state.get("resume_allowed", False),
                   "resume_policy_reason": stage_state.get("resume_policy_reason", "not classified"),
                   "stderr_summary": stage_state.get("stderr_markers", {}),
                   "stdout_present": stage_state.get("stdout_present", False),
                   "parser_error_class": stage_state.get("parser_error_class"),
                   "schema_validation_error_class": stage_state.get("schema_validation_error_class"),
                   "schema_validation_reason": stage_state.get("schema_validation_reason"),
                   "source_binding_diagnostic": stage_state.get("source_binding_diagnostic"),
                   "output_sha256": stage_state.get("output_sha256"),
                   "failed_raw_model_artifact": getattr(run, "last_failed_raw_artifact", None),
                   "failed_raw_model_artifact_sha256": getattr(run, "last_failed_raw_sha256", None)}
        failure["transport_artifact"] = getattr(run, "last_transport_artifact", None)
        failure["transport_artifact_sha256"] = getattr(run, "last_transport_sha256", None)
        failure["integrity_sha256"] = sha256(canonical(failure))
        if auth_key:
            failure["auth_hmac_sha256"] = _receipt_hmac(failure, auth_key)
        failure_path = run.failure(failure, auth_key) if run is not None else None
        if isinstance(exc, ReviewStageFailure):
            exc.failure_artifact = str(failure_path) if failure_path else None
            raise
        wrapped = ReviewStageFailure(category, stage_state["stage"])
        wrapped.failure_artifact = str(failure_path) if failure_path else None
        raise wrapped from exc
    finally:
        from harness.formal_delivery_gate import reset_review
        reset_review(delivery_context)
        signal.signal(signal.SIGTERM, previous_signals[0])
        signal.signal(signal.SIGINT, previous_signals[1])
        token = ""
        auth_key = ""
        if run is not None:
            run.close()


def expected_execution(receipt, manifest, qualification_hash, spec):
    return full.execution_identity(manifest, receipt['mission_id'], qualification_hash,
        role='independent_reviewer', provider=spec.provider, model=spec.model, configuration=spec.identity(),
        registry_hash=receipt['registry_sha256'], runner_hash=receipt['runner_sha256'],
        invocation_hash=sha256(Path(direct.__file__).read_bytes()),
        schema_hash=sha256(canonical({'chunk': CHUNK_SCHEMA, 'synthesis': SYNTHESIS_SCHEMA})))


def validate(receipt: dict, base: str, head: str, root: Path | None = None,
             receipt_path: Path | None = None, mission_id: str | None = None,
             repository: str | None = None, secret: str | None = None,
             registry_path: str | Path | None = None) -> dict:
    from harness.artifact_lineage import artifact_code_hash, authority_matches, review_history
    required = {"version", "repository", "mission_id", "base_sha", "head_sha", "diff_sha256",
                "registry_sha256", "runner_sha256",
                "provider", "model", "reasoning_effort", "chunks", "groups", "aggregate_result",
                "aggregate_output_sha256", "review_result", "findings", "command_sha256",
                "completed_at", "integrity_sha256", "auth_hmac_sha256", "full_manifest", "execution_identity", "task_assignments"}
    required.add("source_binding_contract_authorization_sha256")
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise ValueError("invalid V2 receipt shape")
    if (receipt["version"] != VERSION or receipt["base_sha"] != base
            or receipt["head_sha"] != head or receipt["provider"] != "deepseek"):
        raise ValueError("receipt identity mismatch")
    registry = load_registry(registry_path)
    spec = registry.role("independent_reviewer")
    if (spec.provider != "deepseek" or receipt["model"] != spec.model
            or receipt["reasoning_effort"] != spec.reasoning_effort
            or receipt["registry_sha256"] != sha256(registry.path.read_bytes())
            or receipt["runner_sha256"] != artifact_code_hash(Path(__file__), receipt['source_binding_contract_authorization_sha256'])):
        raise ValueError("receipt model mismatch")
    if mission_id is not None and receipt["mission_id"] != mission_id:
        raise ValueError("receipt mission mismatch")
    if not authority_matches(receipt["source_binding_contract_authorization_sha256"], receipt["mission_id"]):
        raise ValueError("source binding contract authorization mismatch")
    if repository is not None and receipt["repository"] != repository:
        raise ValueError("receipt repository mismatch")
    unsigned = dict(receipt)
    observed = unsigned.pop("integrity_sha256")
    unsigned.pop("auth_hmac_sha256")
    if not hmac.compare_digest(sha256(canonical(unsigned)), observed):
        raise ValueError("receipt integrity mismatch")
    if not isinstance(secret, str) or not secret or not hmac.compare_digest(_receipt_hmac(receipt, secret),
                                                  receipt["auth_hmac_sha256"]):
        raise ValueError("receipt authentication mismatch")
    if root is None:
        raise ValueError("exact source required for validation")
    diff = full.read_diff(root, base, head)
    if sha256(diff) != receipt["diff_sha256"]:
        raise ValueError("receipt diff mismatch")
    _, manifest = full.build_manifest(root, base, head, receipt['repository'])
    full.validate_manifest(root, receipt['full_manifest'], receipt['repository'], base, head, review_ready=True)
    full.validate_tasks(diff, manifest, receipt['task_assignments'])
    execution = receipt['execution_identity']
    qualification_hash = execution.get('qualification_receipt_identity')
    if not isinstance(qualification_hash, str) or not re.fullmatch('[0-9a-f]{64}', qualification_hash):
        raise ValueError('qualification binding missing')
    full.validate_execution(execution, expected_execution(receipt, manifest, qualification_hash, spec))
    expected_chunks, expected_groups = full.plan(diff)
    chunks = receipt["chunks"]
    if len(chunks) != len(expected_chunks):
        raise ValueError("chunk coverage mismatch")
    for chunk, descriptor in zip(chunks, expected_chunks):
        if {key: chunk.get(key) for key in descriptor} != descriptor:
            raise ValueError("chunk descriptor mismatch")
        expected = bind_findings([item["finding"] for item in chunk["bound_findings"]],
                                 "C", descriptor["index"])
        if expected != chunk["bound_findings"]:
            raise ValueError("chunk finding binding mismatch")
    groups = receipt["groups"]
    if len(groups) != len(expected_groups):
        raise ValueError("group coverage mismatch")
    for group, descriptor in zip(groups, expected_groups):
        if {key: group.get(key) for key in descriptor} != descriptor:
            raise ValueError("group descriptor mismatch")
        source = diff[group["start"]:group["end"]]
        selected = [chunks[i] for i in group["chunk_indexes"]]
        validate_bound_result(group["result"], _expected(selected), source,
                              structured_evidence=True)
        carried = [item for item in _expected(selected)
                   if item["severity"] == "P3" or item["finding_id"] in {
                       d["finding_id"] for d in group["result"]["decisions"]
                       if d["decision"] == "UPHELD"}]
        if carried + bind_findings(group["result"]["new_findings"], "G", group["index"]) != group["bound_findings"]:
            raise ValueError("group finding binding mismatch")
    validate_bound_result(receipt["aggregate_result"], _expected(groups), None,
                          structured_evidence=True)
    if (receipt["findings"] != receipt["aggregate_result"]["findings"]
            or receipt["review_result"] != receipt["aggregate_result"]["review_result"]):
        raise ValueError("receipt verdict mismatch")
    if receipt_path is not None:
        _, fd = legacy.open_private_directory(receipt_path.parent, root, create=False)
        try:
            from harness.formal_delivery_gate import NEW_MISSION
            if receipt['mission_id'] == NEW_MISSION:
                state = json.loads(legacy.read_private_artifact(fd, 'state.json'))
                review_history(state, lambda name: legacy.read_private_artifact(fd, name))
            for record, stage in [(item, "chunk") for item in chunks] + [
                    (item, "group") for item in groups]:
                raw = legacy.read_private_artifact(fd, f"{stage}-{record['index']:03d}.json")
                if sha256(raw) != record["output_sha256"]:
                    raise ValueError("review artifact hash mismatch")
                _validate_completion_artifact(raw, receipt["mission_id"])
                if stage == "chunk":
                    if bind_findings(parse_chunk(raw.decode()), "C", record["index"]) != record["bound_findings"]:
                        raise ValueError("chunk artifact differs from receipt")
                else:
                    selected = [chunks[i] for i in record["chunk_indexes"]]
                    source = diff[record["start"]:record["end"]]
                    if parse_synthesis(raw.decode(), _expected(selected), source=source,
                                       structured_evidence=True) != record["result"]:
                        raise ValueError("group artifact differs from receipt")
            raw = legacy.read_private_artifact(fd, "aggregate.json")
            _validate_completion_artifact(raw, receipt["mission_id"])
            if (sha256(raw) != receipt["aggregate_output_sha256"]
                    or parse_synthesis(raw.decode(), _expected(groups), source=None,
                                       structured_evidence=True)
                    != receipt["aggregate_result"]):
                raise ValueError("aggregate artifact differs from receipt")
        finally:
            os.close(fd)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("run", "validate"):
        p = sub.add_parser(name)
        p.add_argument("--repo", default=".")
        p.add_argument("--base", required=True)
        p.add_argument("--head", required=True)
        p.add_argument("--mission-id", default="codex-mission-harness")
        p.add_argument("--token-file", required=True)
        p.add_argument("--auth-key-file")
        if name == "run":
            p.add_argument("--qualification", required=True)
        p.add_argument("--registry")
        if name == "run":
            p.add_argument("--evidence", required=True)
            p.add_argument("--timeout", type=int, default=900)
        else:
            p.add_argument("--receipt", required=True)
    args = parser.parse_args()
    try:
        if args.action == "run":
            print(json.dumps(run(args)))
        else:
            root = Path(args.repo).resolve()
            path = Path(args.receipt).resolve()
            auth_key = legacy.read_token_file(args.auth_key_file or args.token_file, root)
            receipt = json.loads(path.read_text())
            repository = legacy.repository_identity(
                legacy.git(root, "config", "--get", "remote.origin.url").decode().strip())
            validate(receipt, legacy.full_sha(args.base), legacy.full_sha(args.head), root,
                     path, args.mission_id, repository, auth_key, registry_path=args.registry)
            print(json.dumps({"status": receipt["review_result"]}))
    except ReviewStageFailure as exc:
        print(json.dumps({"status": "BLOCKED", "category": exc.category,
                          "failure_artifact": exc.failure_artifact}))
        return 1
    except Exception:
        print(json.dumps({"status": "BLOCKED", "category": "UNKNOWN"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
