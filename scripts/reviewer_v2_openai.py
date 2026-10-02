#!/usr/bin/env python3
"""Independent bounded OpenAI review of this Harness repository.

The Codex process runs in an empty directory and receives exact diff bytes in
bounded prompts. It cannot discover or edit the reviewed checkout. The model
supplies findings and semantic decisions; this module binds IDs, coverage and
verdicts, and publishes private artifacts before its commit-last receipt.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import deepseek_review as secure  # noqa: E402
from harness.model_registry import ModelSpec, load_registry, preflight  # noqa: E402
from harness.model_qualification import validate_qualification_receipt  # noqa: E402
from harness.openai_invocation import InvocationFailure, invoke_openai  # noqa: E402
import harness.openai_invocation as invocation_module  # noqa: E402
from harness.reviewer_v2_contract import bind_findings, validate_source_binding  # noqa: E402
from harness import full_diff_manifest as full
from harness.review_resume import ReviewRun  # noqa: E402

VERSION = "cmh-reviewer-v2-openai/v2"
BLOCKING = frozenset({"P0", "P1", "P2"})
CHUNK_BYTES = 32000
GROUP_BYTES = 96000
MAX_OUTPUT_BYTES = 128000


def _canon(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _schema_manifest_sha() -> str:
    return _sha(_canon({stage: _schema(stage == "group", stage == "synthesis")
                        for stage in ("chunk", "group", "synthesis")}))


def _result(raw: bytes, *, group: bool = False) -> dict:
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("review output exceeds bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid structured review output") from exc
    required = {"findings", "decisions", "summary"} if group else {"findings"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("invalid review result fields")
    findings = value["findings"]
    if not isinstance(findings, list) or len(findings) > 1000:
        raise ValueError("invalid findings list")
    for finding in findings:
        if (not isinstance(finding, dict) or set(finding) != {"severity", "title", "evidence"}
                or finding["severity"] not in {"P0", "P1", "P2", "P3"}
                or any(not isinstance(finding[key], str) or not finding[key].strip()
                       or len(finding[key]) > 4000 for key in ("title", "evidence"))):
            raise ValueError("invalid finding")
    if group:
        if not isinstance(value["summary"], str) or not 32 <= len(value["summary"].strip()) <= 4000:
            raise ValueError("invalid group summary")
        decisions = value["decisions"]
        if not isinstance(decisions, list):
            raise ValueError("missing blocker decisions")
        for decision in decisions:
            if (not isinstance(decision, dict)
                    or set(decision) != {"finding_id", "decision", "rationale", "source_quote",
                                         "source_id", "quote_start", "quote_end"}
                    or not isinstance(decision["finding_id"], str)
                    or not re.fullmatch(r"C[0-9]{3}F[0-9]{3}", decision["finding_id"])
                    or decision["decision"] not in {"UPHELD", "DISPUTED"}
                    or not isinstance(decision["rationale"], str)
                    or len(decision["rationale"].strip()) < 24
                    or not isinstance(decision["source_quote"], str)
                    or not isinstance(decision["source_id"], str)
                    or type(decision["quote_start"]) is not int
                    or type(decision["quote_end"]) is not int
                    or (decision["decision"] == "UPHELD" and decision["source_quote"] != "")):
                raise ValueError("invalid blocker decision")
    return value


def _plan(diff: bytes) -> tuple[list[dict], list[dict]]:
    return full.plan(diff)


def _schema(group: bool, synthesis: bool = False) -> dict:
    summary = {"type": "string", "minLength": 32, "maxLength": 4000,
               "pattern": r"^\S[\s\S]*\S$"}
    finding = {"type": "object", "additionalProperties": False,
               "required": ["severity", "title", "evidence"],
               "properties": {"severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
                              "title": {"type": "string"}, "evidence": {"type": "string"}}}
    properties = {"findings": {"type": "array", "items": finding}}
    if synthesis:
        properties["summary"] = summary
    elif group:
        properties.update({"summary": summary,
                           "decisions": {"type": "array", "items": {
                               "type": "object", "additionalProperties": False,
                               "required": ["finding_id", "decision", "rationale", "source_quote",
                                            "source_id", "quote_start", "quote_end"],
                               "properties": {"finding_id": {"type": "string"},
                                              "decision": {"type": "string", "enum": ["UPHELD", "DISPUTED"]},
                                              "rationale": {"type": "string"},
                                              "source_quote": {"type": "string"},
                                              "source_id": {"type": "string"},
                                              "quote_start": {"type": "integer", "minimum": 0},
                                              "quote_end": {"type": "integer", "minimum": 0}}}}})
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def _synthesis_result(raw: bytes) -> dict:
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("synthesis output exceeds bound")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid synthesis output") from exc
    if not isinstance(value, dict) or set(value) != {"findings", "summary"}:
        raise ValueError("invalid synthesis fields")
    _result(_canon({"findings": value["findings"]}))
    if not isinstance(value["summary"], str) or not 32 <= len(value["summary"].strip()) <= 4000:
        raise ValueError("invalid synthesis summary")
    return value


def _synthesis_prompt(summaries: list[str], base: str, head: str) -> str:
    return full.bounded_prompt("FINAL CROSS-GROUP REVIEW. Independently inspect interactions between these "
            "bounded source-review summaries. Report any additional cross-group problems. "
            "Existing group blockers are mechanically retained and cannot be removed here. "
            "Reevaluate original disputed findings in disposition_audit for cross-group risks; report a NEW finding if a local dispute is unsound. "
            "Return JSON with findings and a concrete summary of 32 to 4000 characters, "
            "with no leading or trailing whitespace. "
            f"Base {base}; head {head}. Group summaries: " + json.dumps(summaries, ensure_ascii=False))


def invoke_codex(prompt: str, spec: ModelSpec, *, stage: str, timeout: int = 900) -> bytes:
    """One fresh, isolated model call. No implicit model or provider fallback."""
    if spec.provider != "openai" or not spec.reasoning_effort:
        raise ValueError("OpenAI model role is required")
    if stage not in {"chunk", "group", "synthesis"}:
        raise ValueError("invalid OpenAI review stage")
    result = invoke_openai(
        prompt, spec, _schema(stage == "group", stage == "synthesis"),
        timeout=timeout,
    )
    return result.response.encode()


def _prompt(kind: str, *, base: str, head: str, diff: bytes, ids: list[dict] | None = None) -> str:
    # Plain text is cheaper for normal diffs; base64 preserves binary patches.
    introduction = (f"{kind}. You are an independent reviewer of Harness source changes. "
                    "No tools, filesystem access, or external requests are needed. "
                    "Analyze the supplied exact diff independently. Report every concrete issue, "
                    "using P0/P1/P2 for merge blockers and P3 for minor issues. "
                    f"Base {base}; head {head}; exact source SHA256 {_sha(diff)}. ")
    if ids is None:
        introduction += "Return findings only. Do not infer safety from another reviewer. "
    else:
        introduction += ("For every listed blocker ID return exactly one UPHELD or DISPUTED decision. "
                         "A DISPUTED decision needs specific reasoning and a verbatim source quote "
                         "from this supplied group diff only. If no exact quote in this group source "
                         "supports a dispute, choose UPHELD. Never quote another group or chunk. "
                         "For DISPUTED set source_id to GroupSourceId and quote_start/quote_end "
                         "to UTF-8 byte offsets delimiting source_quote in this group source. "
                         "For UPHELD use empty source_quote/source_id and zero offsets. "
                         "Bind each evidence reference to its finding_id. "
                         "Also report any additional problems and summarize cross-file impact "
                         "in 32 to 4000 characters with no leading or trailing whitespace. "
                         f"GroupSourceId: {_sha(diff)}. "
                         f"Blockers: {json.dumps(ids, ensure_ascii=False)}. ")
    try:
        source = "\nEXACT DIFF TEXT (UTF-8):\n" + diff.decode("utf-8")
    except UnicodeDecodeError:
        source = "\nEXACT DIFF BYTES (base64):\n" + base64.b64encode(diff).decode()
    return full.bounded_prompt(introduction + source)


def _decide(blockers: list[dict], result: dict, source: bytes) -> list[dict]:
    expected = {item["finding_id"]: item for item in blockers}
    seen = set()
    for item in result["decisions"]:
        identifier = item["finding_id"]
        if identifier not in expected or identifier in seen:
            raise ValueError("unknown or repeated blocker ID")
        seen.add(identifier)
        validate_source_binding(item, source)
    if seen != set(expected):
        raise ValueError("missing blocker disposition")
    return [expected[item["finding_id"]] for item in result["decisions"]
            if item["decision"] == "UPHELD"]


def synthesis_level(groups, chunks):
    level = []
    for group in groups:
        upheld = {d['finding_id'] for d in group['result']['decisions'] if d['decision'] == 'UPHELD'}
        retained = [f for f in group['source_blockers'] if f['finding_id'] in upheld]
        retained += bind_findings(group['result']['findings'], 'G', group['index'])
        retained += [f for i in group['chunk_indexes'] for f in bind_findings(
            chunks[i]['result']['findings'], 'C', i) if f['severity'] == 'P3']
        level.append({'summary': group['result']['summary'], 'source_groups': [group['index']],
                      'source_findings': retained,
                      'disposition_audit': [{'group_index': group['index'],
                          'original_blockers': group['source_blockers'],
                          'decisions': group['result']['decisions']}]})
    if len({f['finding_id'] for item in level for f in item['source_findings']}) != sum(
            len(item['source_findings']) for item in level):
        raise ValueError('duplicate cross-group finding identity')
    return level


def _assemble(diff: bytes, base: str, head: str, call, persist=None, stage_run=None, manifest=None) -> tuple[dict, list[tuple[str, bytes]]]:
    chunks, groups = _plan(diff)
    artifacts = []
    for item in chunks:
        source = diff[item["start"]:item["end"]]
        prompt = _prompt("CHUNK REVIEW", base=base, head=head, diff=source)
        if manifest is not None:
            prompt = full.bounded_prompt('Manifest=' + manifest['manifest_sha256'] +
                '\nLocation metadata (not canonical coverage):' + full.chunk_context(
                    manifest, item['start'], item['end']) + '\n' + prompt)
        name = f"chunk-{item['index']:03d}"
        if stage_run is None:
            raw = call(prompt, False)
            item["result"] = _result(raw)
            if persist is not None:
                persist(name + ".json", raw)
        else:
            raw, item["result"] = stage_run(name, "chunk", prompt, lambda: call(prompt, False), _result)
        item["output_sha256"] = _sha(raw)
        artifacts.append((f"chunk-{item['index']:03d}.json", raw))
        item["blocker_ids"] = [record["finding_id"] for record in
                                bind_findings(item["result"]["findings"], "C", item["index"])
                                if record["finding"]["severity"] in BLOCKING]
    final_findings = []
    for group in groups:
        selected = [chunks[index] for index in group["chunk_indexes"]]
        blockers = []
        for chunk in selected:
            blockers.extend(record for record in bind_findings(
                chunk["result"]["findings"], "C", chunk["index"])
                if record["finding"]["severity"] in BLOCKING)
        source = diff[group["start"]:group["end"]]
        prompt = _prompt("GROUP REVIEW", base=base, head=head, diff=source, ids=blockers)
        if manifest is not None:
            prompt = full.bounded_prompt('Manifest=' + manifest['manifest_sha256'] +
                '\nLocation metadata (not canonical coverage):' + full.chunk_context(
                    manifest, group['start'], group['end']) + '\n' + prompt)
        name = f"group-{group['index']:03d}"
        def validate_group(raw):
            parsed = _result(raw, group=True)
            _decide(blockers, parsed, source)
            return parsed
        if stage_run is None:
            raw = call(prompt, True)
            result = validate_group(raw)
            if persist is not None:
                persist(name + ".json", raw)
        else:
            raw, result = stage_run(name, "group", prompt, lambda: call(prompt, True), validate_group)
        upheld = _decide(blockers, result, source)
        group["result"] = result
        group["source_blockers"] = blockers
        group["output_sha256"] = _sha(raw)
        artifacts.append((f"group-{group['index']:03d}.json", raw))
        final_findings.extend(item["finding"] for item in upheld)
        final_findings.extend(result["findings"])
        final_findings.extend(finding for chunk in selected for finding in chunk["result"]["findings"]
                              if finding["severity"] == "P3")
    synthesis = []
    # Each pass consumes at most eight bounded summaries. A higher level
    # receives bounded outputs from the previous pass, never an unbounded diff.
    if len(groups) > 1:
        level = synthesis_level(groups, chunks)
        while len(level) > 1:
            next_level = []
            for offset in range(0, len(level), 8):
                batch = level[offset:offset + 8]
                prompt = _synthesis_prompt(batch, base, head)
                name = f"synthesis-{len(synthesis):03d}"
                if stage_run is None:
                    raw = call(prompt, "synthesis")
                    result = _synthesis_result(raw)
                    if persist is not None:
                        persist(name + ".json", raw)
                else:
                    raw, result = stage_run(name, "cross-group", prompt,
                                            lambda: call(prompt, "synthesis"), _synthesis_result)
                source_groups = [index for item in batch for index in item["source_groups"]]
                record = {"index": len(synthesis), "source_groups": source_groups,
                          "input_summaries_sha256": _sha(_canon(batch)),
                          "output_sha256": _sha(raw), "result": result}
                synthesis.append(record)
                artifacts.append((f"synthesis-{record['index']:03d}.json", raw))
                final_findings.extend(result["findings"])
                next_level.append({"summary": result["summary"], "source_groups": source_groups,
                                   "source_findings": [f for item in batch for f in item['source_findings']] +
                                       bind_findings(result['findings'], 'F', record['index']),
                                   'disposition_audit': [audit for item in batch for audit in item['disposition_audit']]})
            level = next_level
    receipt = {"version": VERSION, "provider": "openai", "base_sha": base, "head_sha": head,
               "diff_sha256": _sha(diff), "chunks": chunks, "groups": groups,
               "synthesis": synthesis,
               "findings": final_findings,
               "review_result": "FAIL" if any(f["severity"] in BLOCKING for f in final_findings) else "PASS"}
    return receipt, artifacts


def expected_execution(receipt, manifest, qualification_hash, spec):
    return full.execution_identity(manifest, receipt['mission_id'], qualification_hash,
        role='final_reviewer', provider=spec.provider, model=spec.model, configuration=spec.identity(),
        registry_hash=receipt['registry_sha256'], runner_hash=receipt['runner_sha256'],
        invocation_hash=receipt['invocation_sha256'], schema_hash=receipt['schema_manifest_sha256'])


def validate(receipt: dict, *, root: Path, base: str, head: str, spec: ModelSpec,
             auth_key: str, receipt_path: Path | None = None,
             mission_id: str = "codex-mission-harness",
             registry_path: str | Path | None = None) -> dict:
    if spec.provider != "openai" or not auth_key:
        raise ValueError("invalid OpenAI identity or receipt key")
    repository = secure.repository_identity(
        secure.git(root, "config", "--get", "remote.origin.url").decode().strip())
    registry = load_registry(registry_path)
    if (receipt.get("version") != VERSION or receipt.get("provider") != "openai"
            or spec != registry.role("final_reviewer")
            or receipt.get("model") != spec.model
            or receipt.get("reasoning_effort") != spec.reasoning_effort
            or receipt.get("mission_id") != mission_id
            or receipt.get("repository") != repository
            or receipt.get("registry_sha256") != _sha(registry.path.read_bytes())
            or receipt.get("runner_sha256") != _sha(Path(__file__).read_bytes())
            or receipt.get("invocation_sha256") != _sha(Path(invocation_module.__file__).read_bytes())
            or receipt.get("schema_manifest_sha256") != _schema_manifest_sha()
            or receipt.get("base_sha") != base or receipt.get("head_sha") != head):
        raise ValueError("OpenAI receipt model or exact HEAD mismatch")
    unsigned = dict(receipt)
    observed_hmac = unsigned.pop("auth_hmac_sha256", None)
    expected_hmac = hmac.new(auth_key.encode(), _canon(unsigned), hashlib.sha256).hexdigest()
    if not isinstance(observed_hmac, str) or not hmac.compare_digest(observed_hmac, expected_hmac):
        raise ValueError("OpenAI receipt authentication mismatch")
    diff = full.read_diff(Path(root).resolve(), base, head)
    if receipt["diff_sha256"] != _sha(diff):
        raise ValueError("OpenAI receipt diff mismatch")
    _, manifest = full.build_manifest(root, base, head, repository)
    full.validate_manifest(root, receipt.get('full_manifest'), repository, base, head, review_ready=True)
    full.validate_tasks(diff, manifest, receipt.get('task_assignments'))
    execution = receipt.get('execution_identity', {})
    qualification_hash = execution.get('qualification_receipt_identity')
    if not isinstance(qualification_hash, str) or not re.fullmatch('[0-9a-f]{64}', qualification_hash):
        raise ValueError('qualification binding missing')
    full.validate_execution(execution, expected_execution(receipt, manifest, qualification_hash, spec))
    expected_chunks, expected_groups = _plan(diff)
    if len(receipt.get("chunks", [])) != len(expected_chunks) or len(receipt.get("groups", [])) != len(expected_groups):
        raise ValueError("OpenAI review coverage mismatch")
    for actual, expected in zip(receipt["chunks"], expected_chunks):
        if any(actual.get(key) != value for key, value in expected.items()):
            raise ValueError("OpenAI chunk source mismatch")
        _result(_canon(actual.get("result")))
    for actual, expected in zip(receipt["groups"], expected_groups):
        if any(actual.get(key) != value for key, value in expected.items()):
            raise ValueError("OpenAI group source mismatch")
        result = _result(_canon(actual.get("result")), group=True)
        blockers = actual.get("source_blockers")
        if not isinstance(blockers, list):
            raise ValueError("OpenAI blocker binding missing")
        source = diff[expected["start"]:expected["end"]]
        _decide(blockers, result, source)
    # Recompute the final verdict from the validated, durably bound artifacts.
    findings = []
    for group in receipt["groups"]:
        expected_blockers = []
        for index in group["chunk_indexes"]:
            chunk = receipt["chunks"][index]
            expected_ids = []
            for record in bind_findings(chunk["result"]["findings"], "C", index):
                if record["finding"]["severity"] in BLOCKING:
                    expected_ids.append(record["finding_id"])
                    expected_blockers.append(record)
            if chunk.get("blocker_ids", []) != expected_ids:
                raise ValueError("OpenAI chunk blocker IDs changed")
        if group["source_blockers"] != expected_blockers:
            raise ValueError("OpenAI source blocker mapping changed")
        upheld = _decide(group["source_blockers"], group["result"],
                         diff[group["start"]:group["end"]])
        findings.extend(item["finding"] for item in upheld)
        findings.extend(group["result"]["findings"])
        findings.extend(f for index in group["chunk_indexes"]
                        for f in receipt["chunks"][index]["result"]["findings"] if f["severity"] == "P3")
    synthesis = receipt.get("synthesis")
    if not isinstance(synthesis, list):
        raise ValueError("OpenAI cross-group synthesis missing")
    if len(receipt["groups"]) <= 1 and synthesis:
        raise ValueError("unexpected cross-group synthesis")
    if len(receipt["groups"]) > 1:
        level = synthesis_level(receipt["groups"], receipt["chunks"])
        consumed = 0
        while len(level) > 1:
            next_level = []
            for offset in range(0, len(level), 8):
                batch = level[offset:offset + 8]
                if consumed >= len(synthesis):
                    raise ValueError("incomplete cross-group synthesis")
                record = synthesis[consumed]
                source_groups = [index for item in batch for index in item["source_groups"]]
                if (record.get("index") != consumed
                        or record.get("source_groups") != source_groups
                        or record.get("input_summaries_sha256") != _sha(_canon(batch))):
                    raise ValueError("cross-group source binding mismatch")
                result = _synthesis_result(_canon(record.get("result")))
                findings.extend(result["findings"])
                next_level.append({"summary": result["summary"], "source_groups": source_groups,
                                   "source_findings": [f for item in batch for f in item['source_findings']] +
                                       bind_findings(result['findings'], 'F', record['index']),
                                   'disposition_audit': [audit for item in batch for audit in item['disposition_audit']]})
                consumed += 1
            level = next_level
        if consumed != len(synthesis):
            raise ValueError("unexpected cross-group synthesis output")
    verdict = "FAIL" if any(item["severity"] in BLOCKING for item in findings) else "PASS"
    if findings != receipt.get("findings") or verdict != receipt.get("review_result"):
        raise ValueError("OpenAI final verdict or findings mismatch")
    if receipt_path is not None:
        _, directory_fd = secure.open_private_directory(Path(receipt_path).parent, root, create=False)
        try:
            for item in [*receipt["chunks"], *receipt["groups"], *synthesis]:
                kind = ("group" if "chunk_indexes" in item else "synthesis" if "source_groups" in item
                        else "chunk")
                raw = secure.read_private_artifact(directory_fd, f"{kind}-{item['index']:03d}.json")
                parsed = _synthesis_result(raw) if kind == "synthesis" else _result(raw, group=kind == "group")
                if _sha(raw) != item.get("output_sha256") or parsed != item["result"]:
                    raise ValueError("OpenAI durable artifact mismatch")
        finally:
            os.close(directory_fd)
    return receipt


def run(root: Path, base: str, head: str, evidence: Path, auth_key: str,
        spec: ModelSpec, *, timeout: int = 900,
        mission_id: str = "codex-mission-harness",
        registry_path: str | Path | None = None,
        qualification_path: str | Path | None = None) -> Path:
    root = Path(root).resolve(strict=True)
    base, head = secure.full_sha(base), secure.full_sha(head)
    if secure.git(root, "rev-parse", "HEAD").decode().strip() != head:
        raise ValueError("checkout HEAD differs from reviewed HEAD")
    if secure.git(root, "status", "--porcelain"):
        raise ValueError("review checkout has uncommitted changes")
    diff = full.read_diff(root, base, head)
    repository = secure.repository_identity(
        secure.git(root, "config", "--get", "remote.origin.url").decode().strip())
    registry = load_registry(registry_path)
    if spec != registry.role("final_reviewer"):
        raise ValueError("review model differs from selected registry")
    call = lambda prompt, group: invoke_codex(
        prompt, spec, stage="synthesis" if group == "synthesis" else
        "group" if group else "chunk", timeout=timeout)
    chunks, groups = _plan(diff)
    stage_plan = [(f"chunk-{i:03d}", "chunk") for i in range(len(chunks))] + [
        (f"group-{i:03d}", "group") for i in range(len(groups))]
    stage_plan.extend(full.synthesis_stage_names(len(groups)))
    _, manifest = full.build_manifest(root, base, head, repository)
    full.validate_manifest(root, manifest, repository, base, head, review_ready=True)
    qualification_identity = (_sha(Path(qualification_path).read_bytes())
                              if qualification_path and Path(qualification_path).exists()
                              else _sha(str(qualification_path).encode()))
    identity = {"provider": spec.provider, "role": "final_reviewer", "model": spec.model,
                "model_configuration": spec.identity(), "repository": repository,
                "mission_id": mission_id, "base_sha": base, "head_sha": head,
                "diff_hash": _sha(diff), "registry_hash": _sha(registry.path.read_bytes()),
                "runner_hash": _sha(Path(__file__).read_bytes()),
                "invocation_hash": _sha(Path(invocation_module.__file__).read_bytes()),
                "schema_manifest_hash": _schema_manifest_sha(),
                "qualification_receipt_identity": qualification_identity,
                "input_manifest_identity": _sha(_canon({"chunks": chunks, "groups": groups})),
                "full_manifest_sha256": manifest["manifest_sha256"],
                "chunking_policy": full.CHUNKING,
                "manifest_implementation_sha256": _sha(Path(full.__file__).read_bytes())}
    identity["review_execution_identity"] = _sha(_canon(identity))
    run_state = ReviewRun(evidence, root, identity, stage_plan, secure,
                          prefix="openai-v2-")
    run_id, child_fd = run_state.state["review_run_id"], run_state.fd
    os.environ["CMH_RESOURCE_RUN_ID"] = run_id
    path = run_state.path / "receipt.json"
    artifact_hashes = {}
    def stage_run(name, kind, prompt, execute, validate_result):
        os.environ["CMH_RESOURCE_STAGE"] = name
        raw, result = run_state.stage(name, kind, prompt.encode(), execute, validate_result)
        artifact_hashes[name + ".json"] = _sha(raw)
        return raw, result
    previous_signals = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        if qualification_path is None:
            raise ValueError("live OpenAI review requires a final reviewer qualification receipt")
        qualified = validate_qualification_receipt(qualification_path, spec, auth_key=auth_key,
                                       role="final_reviewer", registry_path=registry_path)
        # Authenticate first, then exercise the same Codex structured
        # invocation path and chunk schema used by the review lane.
        preflight(spec, probe=False, timeout=min(timeout, 120))
        os.environ["CMH_RESOURCE_STAGE"] = "structured-preflight"
        invoke_codex(
            'Return JSON with an empty findings array. Use the exact chunk schema.',
            spec, stage="chunk", timeout=min(timeout, 120),
        )
        receipt, _ = _assemble(diff, base, head, call, stage_run=stage_run, manifest=manifest)
        receipt.update({"model": spec.model, "reasoning_effort": spec.reasoning_effort,
                        "mission_id": mission_id, "repository": repository,
                        "registry_sha256": _sha(registry.path.read_bytes()),
                        "runner_sha256": _sha(Path(__file__).read_bytes()),
                        "invocation_sha256": _sha(Path(invocation_module.__file__).read_bytes()),
                        "schema_manifest_sha256": _schema_manifest_sha()})
        receipt['task_assignments'] = full.review_tasks(diff, manifest)
        receipt['full_manifest'] = manifest
        receipt['execution_identity'] = expected_execution(receipt, manifest, _sha(_canon(qualified)), spec)
        receipt["auth_hmac_sha256"] = hmac.new(auth_key.encode(), _canon(receipt), hashlib.sha256).hexdigest()
        validate(receipt, root=root, base=base, head=head, spec=spec, auth_key=auth_key,
                 mission_id=mission_id, registry_path=registry_path)
        validate(receipt, root=root, base=base, head=head, spec=spec,
                 auth_key=auth_key, receipt_path=path, mission_id=mission_id,
                 registry_path=registry_path)
        # Publish the approval-shaped receipt only after all stage artifacts
        # and semantic checks are durable and complete.
        run_state.receipt(path.name, _canon(receipt), lambda: None)
        return path
    except (Exception, KeyboardInterrupt) as exc:
        failure = {"status": "BLOCKED", "base_sha": base, "head_sha": head,
                   "mission_id": mission_id, "repository": repository,
                   "diff_sha256": _sha(diff), "provider": spec.provider,
                   "model": spec.model, "reasoning_effort": spec.reasoning_effort,
                   "failure_category": exc.category if isinstance(exc, InvocationFailure)
                   else "CANCELLED" if isinstance(exc, KeyboardInterrupt)
                   else "REVIEW_RESULT_INVALID", "error_type": type(exc).__name__,
                   "artifact_sha256": artifact_hashes,
                   "invocation_evidence": dict(exc.evidence) if isinstance(exc, InvocationFailure) else {},
                   "recorded_at": int(time.time())}
        failure_path = run_state.failure(failure, auth_key)
        if isinstance(exc, InvocationFailure):
            exc.evidence["failure_record"] = str(failure_path)
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_signals[0])
        signal.signal(signal.SIGINT, previous_signals[1])
        run_state.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "validate"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--evidence")
    parser.add_argument("--receipt")
    parser.add_argument("--auth-key-file", required=True)
    parser.add_argument("--registry")
    parser.add_argument("--qualification")
    parser.add_argument("--mission-id", default="codex-mission-harness")
    args = parser.parse_args()
    try:
        root = Path(args.repo).resolve(strict=True)
        spec = load_registry(args.registry).role("final_reviewer")
        key = secure.read_token_file(args.auth_key_file, root)
        if args.command == "run":
            if not args.evidence:
                raise ValueError("evidence directory required")
            path = run(root, args.base, args.head, Path(args.evidence), key, spec,
                       mission_id=args.mission_id, registry_path=args.registry,
                       qualification_path=args.qualification)
            value = json.loads(path.read_bytes())
            print(json.dumps({"status": value["review_result"], "receipt": str(path)}))
        else:
            if not args.receipt:
                raise ValueError("receipt path required")
            path = Path(args.receipt)
            _, fd = secure.open_private_directory(path.parent, root, create=False)
            try:
                value = json.loads(secure.read_private_artifact(fd, path.name))
            finally:
                os.close(fd)
            validate(value, root=root, base=args.base, head=args.head, spec=spec,
                     auth_key=key, receipt_path=path, mission_id=args.mission_id,
                     registry_path=args.registry)
            print(json.dumps({"status": value["review_result"], "receipt": str(path)}))
    except InvocationFailure as exc:
        print(json.dumps({"status": "BLOCKED_EXTERNAL", "category": exc.category,
                          "evidence": exc.evidence}))
        return 1
    except Exception:
        print(json.dumps({"status": "BLOCKED_EXTERNAL", "error": "OpenAI review has no valid approval receipt"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
