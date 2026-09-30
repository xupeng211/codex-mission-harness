"""Reusable semantic qualification contract for a configured reviewer model.

Local contract tests and actual provider qualification are deliberately distinct.
Only responses from ``qualify_live`` can yield a live qualification certificate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .model_registry import ModelSpec
from .reviewer_v2_contract import bind_findings, parse_synthesis

QUALIFICATION_VERSION = "cmh-model-qualification/v1"


@dataclass(frozen=True)
class QualificationCase:
    name: str
    source: str
    findings: tuple[dict[str, str], ...]
    expected: dict[str, str]


CASES = (
    QualificationCase("clean", "def total(a, b):\n    return a + b\n", (), {}),
    QualificationCase("single_blocker", "def total(a, b):\n    return a - b\n",
                      ({"severity": "P1",
                        "title": "Subtraction violates total contract",
                        "evidence": "line 2 returns a - b"},), {"F1": "UPHELD"}),
    QualificationCase("source_based_dispute", "def total(a, b):\n    return a + b\n",
                      ({"severity": "P1",
                        "title": "Function subtracts", "evidence": "claimed line 2"},),
                      {"F1": "DISPUTED"}),
    QualificationCase("multiple_blockers", "def total(a, b):\n    return a - b\n\ndef always_true():\n    return False\n",
                      ({"severity": "P1", "title": "Wrong operator",
                        "evidence": "line 2 subtracts"},
                       {"severity": "P2", "title": "Always true returns false",
                        "evidence": "line 5 returns False"}),
                      {"F1": "UPHELD", "F2": "UPHELD"}),
)


def expected_findings(case: QualificationCase) -> list[dict]:
    return bind_findings(list(case.findings), "F", 0)


def qualification_prompt(case: QualificationCase) -> str:
    return ("Review this isolated qualification fixture. Return only JSON with key decisions: "
            "an array of {finding_id, decision, rationale, source_quote}, plus findings "
            "(an array of newly discovered severity/title/evidence objects), and summary "
            "(at least 32 characters). Decide UPHELD or DISPUTED "
            "from the source. For DISPUTED, source_quote must be an exact source substring "
            "of at least 12 characters; for UPHELD use an empty source_quote. "
            "Include every finding exactly once. Do not use tools.\n"
            f"SOURCE:\n{case.source}\nFINDINGS:\n"
            f"{json.dumps(expected_findings(case), sort_keys=True)}")


@dataclass(frozen=True)
class QualificationResult:
    identity: dict[str, str | None]
    mode: str
    cases_passed: tuple[str, ...]
    cases_failed: tuple[str, ...]
    response_sha256: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.mode == "real_provider" and not self.cases_failed \
            and len(self.cases_passed) == len(CASES)


def _evaluate_cases(spec: ModelSpec, invoke: Callable[[ModelSpec, str], str], *,
                    mode: str) -> QualificationResult:
    """Evaluate responses from an invoker; injected invokers cannot certify a model.

    This function does not retry or substitute a model. A provider failure or
    missing/invalid response fails that case and preserves the model identity.
    """
    passed, failed, hashes = [], [], []
    for case in CASES:
        try:
            raw = invoke(spec, qualification_prompt(case))
            bound = parse_synthesis(raw, expected_findings(case), source=case.source.encode())
            decisions = {item["finding_id"]: item["decision"] for item in bound["decisions"]}
            expected = {expected_findings(case)[int(key[1:])-1]["finding_id"]: value
                        for key, value in case.expected.items()}
            if decisions != expected or bound["new_findings"]:
                raise ValueError("semantic decision mismatch")
        except (ValueError, RuntimeError, TimeoutError):
            failed.append(case.name)
        else:
            passed.append(case.name)
            hashes.append(hashlib.sha256(raw.encode("utf-8")).hexdigest())
    return QualificationResult(spec.identity(), mode, tuple(passed),
                               tuple(failed), tuple(hashes))


def evaluate_cases(spec: ModelSpec, invoke: Callable[[ModelSpec, str], str]) -> QualificationResult:
    """Exercise deterministic fixtures; this result can never certify a provider."""
    return _evaluate_cases(spec, invoke, mode="deterministic_fixture")


_SCHEMA = {"type": "object", "properties": {"decisions": {"type": "array", "items": {
    "type": "object", "properties": {
        "finding_id": {"type": "string"},
        "decision": {"type": "string", "enum": ["UPHELD", "DISPUTED"]},
        "rationale": {"type": "string"}, "source_quote": {"type": "string"}},
    "required": ["finding_id", "decision", "rationale", "source_quote"],
    "additionalProperties": False}}, "findings": {"type": "array", "items": {"type": "object",
    "properties": {"severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
                   "title": {"type": "string"}, "evidence": {"type": "string"}},
    "required": ["severity", "title", "evidence"], "additionalProperties": False}},
    "summary": {"type": "string"}},
    "required": ["decisions", "findings", "summary"], "additionalProperties": False}


def _actual_provider_invoke(spec: ModelSpec, prompt: str, *, token: str | None,
                            timeout: int) -> str:
    """One bounded, noninteractive call to the exact configured model."""
    with tempfile.TemporaryDirectory(prefix="cmh-model-qualification-") as temporary:
        root = Path(temporary)
        schema = root / "schema.json"
        schema.write_text(json.dumps(_SCHEMA), encoding="utf-8")
        if spec.provider == "openai":
            output = root / "response.json"
            command = ["codex", "exec", "--ephemeral", "--ignore-user-config",
                       "--skip-git-repo-check", "--sandbox", "read-only", "--model", spec.model,
                       "-c", f'model_reasoning_effort="{spec.reasoning_effort}"',
                       "--output-schema", str(schema), "--output-last-message", str(output), "-"]
            result = subprocess.run(command, input=prompt, capture_output=True, text=True,
                                    cwd=root, timeout=timeout, check=False)
            if result.returncode or not output.is_file():
                raise RuntimeError("OpenAI model qualification provider call failed")
            return output.read_text(encoding="utf-8")
        if spec.provider == "deepseek":
            if token is None:
                raise ValueError("DeepSeek qualification token missing")
            settings = root / "settings.json"
            settings.write_text('{"permissions":{"allow":[],"deny":["Bash","Edit",'
                                '"Write","Read","Glob","Grep","WebFetch","WebSearch"]}}')
            command = ["claude", "--bare", "--restricted", "--print", "--model", spec.model,
                       "--settings", str(settings), "--tools", "", "--disallowed-tools",
                       "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch", "--output-format", "json",
                       "--json-schema", json.dumps(_SCHEMA, separators=(",", ":"))]
            env = {"HOME": "/nonexistent", "PATH": os.environ.get("PATH", os.defpath),
                   "LANG": "C.UTF-8", "ANTHROPIC_API_KEY": token,
                   "ANTHROPIC_AUTH_TOKEN": token,
                   "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
                   "CLAUDE_CODE_SIMPLE": "1"}
            result = subprocess.run(command, input=prompt, capture_output=True, text=True, env=env,
                                    cwd=root, timeout=timeout, check=False)
            if result.returncode:
                raise RuntimeError("DeepSeek model qualification provider call failed")
            try:
                envelope = json.loads(result.stdout)
                if envelope.get("is_error") or not isinstance(envelope.get("structured_output"), dict):
                    raise ValueError("provider returned no structured output")
                return json.dumps(envelope["structured_output"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("DeepSeek qualification output invalid") from exc
    raise ValueError("unsupported provider")


def qualify_live(spec: ModelSpec, *, token_file: str | Path | None = None,
                 timeout: int = 120) -> QualificationResult:
    """Run actual provider calls after noninteractive auth validation."""
    from .model_registry import preflight, read_private_token

    preflight(spec, token_file=token_file)
    token = read_private_token(Path(token_file)) if token_file else None
    return _evaluate_cases(spec,
                           lambda actual, prompt: _actual_provider_invoke(
                               actual, prompt, token=token, timeout=timeout),
                           mode="real_provider")


def qualification_receipt(result: QualificationResult, *, auth_key: str) -> dict:
    """Build an integrity-bound record without storing model responses."""
    from .model_registry import DEFAULT_REGISTRY_PATH
    from . import reviewer_v2_contract

    if not result.passed or not isinstance(auth_key, str) or not auth_key:
        raise ValueError("only a complete real-provider qualification can produce a receipt")
    code = Path(__file__).resolve()
    receipt = {"version": QUALIFICATION_VERSION,
               "mode": result.mode, "identity": result.identity,
               "cases_passed": list(result.cases_passed),
               "response_sha256": list(result.response_sha256),
               "registry_sha256": hashlib.sha256(DEFAULT_REGISTRY_PATH.read_bytes()).hexdigest(),
               "contract_sha256": hashlib.sha256(Path(reviewer_v2_contract.__file__).read_bytes()).hexdigest(),
               "runner_sha256": hashlib.sha256(code.read_bytes()).hexdigest()}
    receipt["integrity_sha256"] = hmac.new(auth_key.encode(),
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return receipt


def validate_qualification_receipt(path: str | Path, spec: ModelSpec, *, auth_key: str) -> dict:
    """Reject stale, incomplete, altered, or different-model qualification."""
    from .model_registry import DEFAULT_REGISTRY_PATH
    from . import reviewer_v2_contract

    receipt = json.loads(Path(path).read_text(encoding="utf-8"))
    expected_keys = {"version", "mode", "identity", "cases_passed", "response_sha256",
                     "registry_sha256", "contract_sha256", "runner_sha256", "integrity_sha256"}
    if not isinstance(receipt, dict) or set(receipt) != expected_keys \
            or receipt["version"] != QUALIFICATION_VERSION \
            or receipt["mode"] != "real_provider" or receipt["identity"] != spec.identity() \
            or receipt["cases_passed"] != [case.name for case in CASES] \
            or not isinstance(receipt["response_sha256"], list) \
            or len(receipt["response_sha256"]) != len(CASES) \
            or any(not isinstance(item, str) or len(item) != 64
                   or any(char not in "0123456789abcdef" for char in item)
                   for item in receipt["response_sha256"]):
        raise ValueError("invalid or mismatched model qualification receipt")
    hashes = {"registry_sha256": DEFAULT_REGISTRY_PATH,
              "contract_sha256": Path(reviewer_v2_contract.__file__),
              "runner_sha256": Path(__file__)}
    if any(receipt[key] != hashlib.sha256(file.read_bytes()).hexdigest()
           for key, file in hashes.items()):
        raise ValueError("model qualification code or registry changed")
    unsigned = {key: value for key, value in receipt.items() if key != "integrity_sha256"}
    if not isinstance(auth_key, str) or not auth_key or not hmac.compare_digest(
            receipt["integrity_sha256"], hmac.new(auth_key.encode(),
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256).hexdigest()):
        raise ValueError("model qualification receipt integrity mismatch")
    return receipt
