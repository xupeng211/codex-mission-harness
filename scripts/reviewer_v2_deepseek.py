#!/usr/bin/env python3
"""Independent DeepSeek lane for Harness self-review; exact diff, bounded source."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import deepseek_review as legacy  # noqa: E402
from harness.reviewer_v2_contract import (  # noqa: E402
    bind_findings, canonical, parse_chunk, parse_synthesis, sha256, validate_bound_result,
)
from harness.model_registry import load_registry  # noqa: E402

VERSION = "cmh-reviewer-v2-deepseek/v1"
FINDING_SCHEMA = {"type": "object", "additionalProperties": False,
                  "required": ["severity", "title", "evidence"], "properties": {
                      "severity": {"enum": ["P0", "P1", "P2", "P3"]},
                      "title": {"type": "string", "minLength": 1},
                      "evidence": {"type": "string", "minLength": 1}}}
DECISION_SCHEMA = {"type": "object", "additionalProperties": False,
                   "required": ["finding_id", "decision", "rationale", "source_quote"],
                   "properties": {"finding_id": {"type": "string"},
                                  "decision": {"enum": ["UPHELD", "DISPUTED"]},
                                  "rationale": {"type": "string", "minLength": 24},
                                  "source_quote": {"type": "string"}}}
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
    if len(prompt.encode()) > legacy.MAX_REVIEW_PROMPT_BYTES:
        raise ValueError("review prompt exceeds bounded size")
    return prompt


def _invoke(command: list[str], prompt: str, env: dict, timeout: int, token: str,
            *, stage: str, evidence_fd: int, artifact: str) -> tuple[str, str]:
    try:
        completed = legacy.invoke_reviewer(command, _bounded(prompt), env, timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"{stage} reviewer invocation failed") from exc
    if legacy._credential_echoed(completed.stdout, completed.stderr, token):
        raise ValueError("reviewer output echoed credential")
    if completed.returncode:
        raise ValueError(f"{stage} reviewer process failed")
    raw = legacy._captured_bytes(completed.stdout)
    legacy.write_private_artifact(evidence_fd, artifact, raw, uuid.uuid4().hex)
    return raw.decode("utf-8"), sha256(raw)


def _prompt_head(base: str, head: str, diff_hash: str, scope: str) -> str:
    return ("Independent restricted code review. Do not use tools or filesystem. "
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
    diff = legacy.git(root, "diff", "--no-ext-diff", "--no-textconv", "--binary",
                      f"{base}..{head}")
    chunks = legacy.chunks(diff)
    groups = legacy.aggregate_groups(diff, chunks)
    diff_hash = sha256(diff)
    model = load_registry().role("independent_reviewer")
    if model.provider != "deepseek":
        raise ValueError("independent reviewer provider is not DeepSeek")
    evidence_root, root_fd = legacy.open_private_directory(args.evidence, root)
    run_id = uuid.uuid4().hex
    evidence = evidence_root / run_id
    evidence_fd = legacy.create_private_child_directory(root_fd, run_id)
    settings = None
    token = ""
    try:
        executable, safe_path = legacy.resolve_claude_launcher(root, os.environ.get("PATH", ""))
        token = legacy.read_token_file(args.token_file, root)
        if not token:
            raise ValueError("missing DeepSeek credential")
        settings = tempfile.NamedTemporaryFile(mode="w", delete=False)
        settings.write('{"permissions":{"allow":[],"deny":["Bash","Edit","Write",'
                       '"Read","Glob","Grep","WebFetch","WebSearch"]}}')
        settings.close()
        command = [executable, "--bare", "--restricted", "--print", "--model",
                   model.model, "--settings", settings.name, "--tools", "",
                   "--disallowed-tools", "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch",
                   "--output-format", "json"]
        env = {"HOME": "/nonexistent", "PATH": safe_path, "LANG": "C.UTF-8",
               "ANTHROPIC_API_KEY": token, "ANTHROPIC_AUTH_TOKEN": token,
               "ANTHROPIC_BASE_URL": legacy.ENDPOINT, "CLAUDE_CODE_SIMPLE": "1",
               **legacy.reviewer_transport_environment()}
        chunk_command = command + ["--json-schema", json.dumps(CHUNK_SCHEMA, separators=(",", ":"))]
        synthesis_command = command + ["--json-schema", json.dumps(SYNTHESIS_SCHEMA, separators=(",", ":"))]
        for chunk in chunks:
            source = diff[chunk["start"]:chunk["end"]]
            prompt = (_prompt_head(base, head, diff_hash, f"chunk {chunk['index']}")
                      + _render_source(source))
            raw, output_hash = _invoke(chunk_command, prompt, env, args.timeout, token,
                                       stage="chunk", evidence_fd=evidence_fd,
                                       artifact=f"chunk-{chunk['index']:03d}.json")
            findings = parse_chunk(raw)
            chunk["bound_findings"] = bind_findings(findings, "C", chunk["index"])
            chunk["output_sha256"] = output_hash
        for group in groups:
            selected = [chunks[i] for i in group["chunk_indexes"]]
            expected = _expected(selected)
            source = diff[group["start"]:group["end"]]
            prompt = (_prompt_head(base, head, diff_hash, f"group {group['index']}")
                      + "Review exact source and cross-chunk interactions. Every supplied "
                      "P0/P1/P2 finding needs one decision keyed by finding_id. "
                      "UPHELD preserves the original finding automatically. DISPUTED requires "
                      "a specific rationale and source_quote copied exactly from this source. "
                      "Use empty source_quote for UPHELD. findings contains only NEW findings; "
                      "never copy supplied findings into it. Summarize interactions for cross-group review.\n"
                      + f"PriorFindings={json.dumps(expected, sort_keys=True)}\n"
                      + _render_source(source))
            raw, output_hash = _invoke(synthesis_command, prompt, env, args.timeout, token,
                                       stage="group", evidence_fd=evidence_fd,
                                       artifact=f"group-{group['index']:03d}.json")
            result = parse_synthesis(raw, expected, source=source)
            group["result"] = result
            group["bound_findings"] = bind_findings(result["findings"], "G", group["index"])
            group["output_sha256"] = output_hash
        expected = _expected(groups)
        summaries = [{"group_index": group["index"], "summary": group["result"]["summary"],
                      "findings": group["bound_findings"]} for group in groups]
        prompt = (_prompt_head(base, head, diff_hash, "cross-group")
                  + "Analyze cross-group interactions using bounded summaries. You have no exact "
                  "source at this stage and must UPHOLD every supplied P0/P1/P2 finding. "
                  "Use empty source_quote. findings contains only NEW cross-group findings. "
                  "Every blocker needs one decision keyed by finding_id.\n"
                  + f"GroupSummaries={json.dumps(summaries, sort_keys=True)}")
        raw, output_hash = _invoke(synthesis_command, prompt, env, args.timeout, token,
                                   stage="cross-group", evidence_fd=evidence_fd,
                                   artifact="aggregate.json")
        result = parse_synthesis(raw, expected, source=None)
        receipt = {"version": VERSION, "repository": repository,
                   "mission_id": args.mission_id, "base_sha": base, "head_sha": head,
                   "diff_sha256": diff_hash, "provider": model.provider, "model": model.model,
                   "reasoning_effort": model.reasoning_effort, "chunks": chunks, "groups": groups,
                   "aggregate_result": result, "aggregate_output_sha256": output_hash,
                   "review_result": result["review_result"], "findings": result["findings"],
                   "command_sha256": sha256(canonical({"chunk": chunk_command,
                                                      "synthesis": synthesis_command})),
                   "completed_at": int(time.time())}
        receipt["integrity_sha256"] = sha256(canonical(receipt))
        receipt["auth_hmac_sha256"] = _receipt_hmac(receipt, token)
        path = evidence / f"deepseek-v2-receipt-{head[:12]}-{run_id}.json"
        # Validate the already durable model artifacts before publishing the
        # receipt. A failed run cannot leave an approval-looking receipt.
        validate(receipt, base, head, root, path, args.mission_id, repository, token)
        legacy.write_private_artifact(evidence_fd, path.name, canonical(receipt), run_id)
        os.fsync(evidence_fd)
        return {"status": receipt["review_result"], "review_receipt": str(path),
                "head_sha": head}
    finally:
        if settings is not None:
            Path(settings.name).unlink(missing_ok=True)
        token = ""
        os.close(evidence_fd)
        os.close(root_fd)


def validate(receipt: dict, base: str, head: str, root: Path | None = None,
             receipt_path: Path | None = None, mission_id: str | None = None,
             repository: str | None = None, secret: str | None = None) -> dict:
    required = {"version", "repository", "mission_id", "base_sha", "head_sha", "diff_sha256",
                "provider", "model", "reasoning_effort", "chunks", "groups", "aggregate_result",
                "aggregate_output_sha256", "review_result", "findings", "command_sha256",
                "completed_at", "integrity_sha256", "auth_hmac_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise ValueError("invalid V2 receipt shape")
    if (receipt["version"] != VERSION or receipt["base_sha"] != base
            or receipt["head_sha"] != head or receipt["provider"] != "deepseek"):
        raise ValueError("receipt identity mismatch")
    spec = load_registry().role("independent_reviewer")
    if (receipt["model"] != spec.model or receipt["reasoning_effort"] != spec.reasoning_effort):
        raise ValueError("receipt model mismatch")
    if mission_id is not None and receipt["mission_id"] != mission_id:
        raise ValueError("receipt mission mismatch")
    if repository is not None and receipt["repository"] != repository:
        raise ValueError("receipt repository mismatch")
    unsigned = dict(receipt)
    observed = unsigned.pop("integrity_sha256")
    unsigned.pop("auth_hmac_sha256")
    if not hmac.compare_digest(sha256(canonical(unsigned)), observed):
        raise ValueError("receipt integrity mismatch")
    if secret is None or not hmac.compare_digest(_receipt_hmac(receipt, secret),
                                                  receipt["auth_hmac_sha256"]):
        raise ValueError("receipt authentication mismatch")
    if root is None:
        raise ValueError("exact source required for validation")
    diff = legacy.git(root, "diff", "--no-ext-diff", "--no-textconv", "--binary",
                      f"{base}..{head}")
    if sha256(diff) != receipt["diff_sha256"]:
        raise ValueError("receipt diff mismatch")
    expected_chunks = legacy.chunks(diff)
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
    expected_groups = legacy.aggregate_groups(diff, expected_chunks)
    groups = receipt["groups"]
    if len(groups) != len(expected_groups):
        raise ValueError("group coverage mismatch")
    for group, descriptor in zip(groups, expected_groups):
        if {key: group.get(key) for key in descriptor} != descriptor:
            raise ValueError("group descriptor mismatch")
        source = diff[group["start"]:group["end"]]
        selected = [chunks[i] for i in group["chunk_indexes"]]
        validate_bound_result(group["result"], _expected(selected), source)
        if bind_findings(group["result"]["findings"], "G", group["index"]) != group["bound_findings"]:
            raise ValueError("group finding binding mismatch")
    validate_bound_result(receipt["aggregate_result"], _expected(groups), None)
    if (receipt["findings"] != receipt["aggregate_result"]["findings"]
            or receipt["review_result"] != receipt["aggregate_result"]["review_result"]):
        raise ValueError("receipt verdict mismatch")
    if receipt_path is not None:
        _, fd = legacy.open_private_directory(receipt_path.parent, root, create=False)
        try:
            for record, stage in [(item, "chunk") for item in chunks] + [
                    (item, "group") for item in groups]:
                raw = legacy.read_private_artifact(fd, f"{stage}-{record['index']:03d}.json")
                if sha256(raw) != record["output_sha256"]:
                    raise ValueError("review artifact hash mismatch")
                if stage == "chunk":
                    if bind_findings(parse_chunk(raw.decode()), "C", record["index"]) != record["bound_findings"]:
                        raise ValueError("chunk artifact differs from receipt")
                else:
                    selected = [chunks[i] for i in record["chunk_indexes"]]
                    source = diff[record["start"]:record["end"]]
                    if parse_synthesis(raw.decode(), _expected(selected), source=source) != record["result"]:
                        raise ValueError("group artifact differs from receipt")
            raw = legacy.read_private_artifact(fd, "aggregate.json")
            if (sha256(raw) != receipt["aggregate_output_sha256"]
                    or parse_synthesis(raw.decode(), _expected(groups), source=None)
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
            token = legacy.read_token_file(args.token_file, root)
            receipt = json.loads(path.read_text())
            repository = legacy.repository_identity(
                legacy.git(root, "config", "--get", "remote.origin.url").decode().strip())
            validate(receipt, legacy.full_sha(args.base), legacy.full_sha(args.head), root,
                     path, args.mission_id, repository, token)
            print(json.dumps({"status": receipt["review_result"]}))
    except Exception:
        print(json.dumps({"status": "BLOCKED_EXTERNAL", "error": "V2 DeepSeek review failed closed"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
