"""Deterministic binding for bounded, semantic reviewer decisions.

The model supplies findings and decisions.  This module owns identities,
severity preservation, coverage, and the derived verdict.
"""
from __future__ import annotations

import hashlib
import json
import re


BLOCKING = frozenset({"P0", "P1", "P2"})


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def check_finding(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {"severity", "title", "evidence"}
            or value.get("severity") not in {*BLOCKING, "P3"}
            or not all(isinstance(value.get(k), str) and value[k].strip()
                       for k in ("title", "evidence"))):
        raise ValueError("invalid finding")
    return value


def bind_findings(findings: list, scope: str, index: int) -> list[dict]:
    """Assign identities only after retaining each exact original finding."""
    if not re.fullmatch(r"[CGF]", scope) or type(index) is not int or index < 0:
        raise ValueError("invalid finding scope")
    if not isinstance(findings, list):
        raise ValueError("invalid findings")
    return [{"finding_id": f"{scope}{index:03d}F{number:03d}",
             "source_index": index, "finding_index": number,
             "severity": check_finding(item)["severity"],
             "finding_sha256": sha256(canonical(item)), "finding": item}
            for number, item in enumerate(findings)]


def parse_chunk(raw: str) -> list[dict]:
    """A chunk sees source and proposes findings; the machine derives PASS/FAIL."""
    value = _unwrap(raw)
    if set(value) != {"findings"} or not isinstance(value["findings"], list):
        raise ValueError("invalid chunk output")
    return [check_finding(item) for item in value["findings"]]


def _unwrap(raw: str) -> dict:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("invalid structured output") from None
    if isinstance(value, dict) and "structured_output" in value:
        value = value["structured_output"]
    elif isinstance(value, dict) and "result" in value:
        value = value["result"]
    if not isinstance(value, dict):
        raise ValueError("invalid structured output")
    return value


def parse_synthesis(raw: str, expected: list[dict], *, source: bytes | None) -> dict:
    """Reject unknown, duplicate, or missing decisions without inventing any.

    A group may dispute with an exact source quote.  The final synthesis has
    summaries only and may therefore uphold, but never dispute, group blockers.
    """
    value = _unwrap(raw)
    if (set(value) != {"findings", "decisions", "summary"}
            or not isinstance(value["findings"], list)
            or not isinstance(value["decisions"], list)
            or not isinstance(value["summary"], str)
            or len(value["summary"].strip()) < 32 or len(value["summary"]) > 4000):
        raise ValueError("invalid synthesis output")
    new_findings = [check_finding(item) for item in value["findings"]]
    required = {item["finding_id"]: item for item in expected
                if item["severity"] in BLOCKING}
    if len(required) != sum(item["severity"] in BLOCKING for item in expected):
        raise ValueError("duplicate finding identity")
    observed = {}
    for decision in value["decisions"]:
        if (not isinstance(decision, dict)
                or set(decision) != {"finding_id", "decision", "rationale", "source_quote"}
                or not isinstance(decision.get("finding_id"), str)
                or decision["finding_id"] not in required
                or decision["finding_id"] in observed
                or decision.get("decision") not in {"UPHELD", "DISPUTED"}
                or not isinstance(decision.get("rationale"), str)
                or len(decision["rationale"].strip()) < 24
                or not isinstance(decision.get("source_quote"), str)):
            raise ValueError("invalid or duplicate disposition")
        if decision["decision"] == "DISPUTED":
            quote = decision["source_quote"].strip()
            if (source is None or len(quote) < 12
                    or quote.encode("utf-8") not in source):
                raise ValueError("dispute lacks verifiable source quote")
        elif decision["source_quote"]:
            raise ValueError("upheld disposition has unexpected source quote")
        observed[decision["finding_id"]] = decision
    if set(observed) != set(required):
        raise ValueError("missing blocker disposition")
    carried = [item["finding"] for item in expected
               if item["severity"] == "P3" or
               (item["finding_id"] in observed
                and observed[item["finding_id"]]["decision"] == "UPHELD")]
    findings = carried + new_findings
    return {"decisions": value["decisions"], "new_findings": new_findings,
            "summary": value["summary"], "findings": findings,
            "review_result": "FAIL" if any(item["severity"] in BLOCKING
                                       for item in findings) else "PASS"}


def validate_bound_result(result: dict, expected: list[dict], source: bytes | None) -> None:
    """Recompute every derived field when validating a durable receipt."""
    if not isinstance(result, dict) or set(result) != {
            "decisions", "new_findings", "summary", "findings", "review_result"}:
        raise ValueError("invalid bound result")
    model_fields = {key: result[key] for key in ("decisions", "summary")}
    model_fields["findings"] = result["new_findings"]
    if parse_synthesis(canonical(model_fields).decode(), expected, source=source) != result:
        raise ValueError("bound result differs from model decisions")
