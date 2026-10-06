"""Deterministic binding for bounded, semantic reviewer decisions.

The model supplies findings and decisions.  This module owns identities,
severity preservation, coverage, and the derived verdict.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path

from .resource_gate import _private


# Model-facing clarification of concrete issues; no parser filtering or repair.
FINDING_GUIDANCE = (
    "Formal findings at every severity, including P3, must identify a concrete "
    "correctness, security, reliability, contract, data-integrity, or production-operability "
    "risk supported by the supplied source and applicable claimed contract. Explain the "
    "affected behavior, triggering condition, and consequence in the finding evidence. "
    "Do not invent an input restriction or documentation/type contract. Pure style preferences, "
    "optional refactors, documentation completeness, optional type hints, defensive validation "
    "without a demonstrated defect/risk, and speculative maintainability improvements are "
    "suggestions, not formal findings; omit them from findings. If no concrete issue exists, "
    "return findings=[]. This applies equally to P1/P2/P3: never suppress a real defect merely "
    "because it involves types or documentation. "
    "Non-finding example: an otherwise correct generic addition helper lacking optional "
    "annotations or docstrings, without a required input restriction or demonstrated risk. "
    "Formal finding example: a declared numeric-payment contract accepts strings and "
    "concatenates amounts, producing an incorrect charge. "
    "Formal finding example: an API documents milliseconds but interprets them as seconds, "
    "causing a production timeout or billing error. "
)

BLOCKING = frozenset({"P0", "P1", "P2"})
SOURCE_BINDING_VERSION = "exact-unique-utf8-quote/v1"
FORMAL_MISSION_ID = "HARNESS_AUTONOMOUS_PRE_MERGE_DELIVERY"


def contract_authorization_identity(mission_id: str) -> str:
    """Require the separately signed contract approval for formal review runs."""
    from .formal_delivery_gate import NEW_MISSION, load_authorization
    if mission_id == NEW_MISSION:
        return load_authorization()["_authorization_sha256"]
    if mission_id != FORMAL_MISSION_ID:
        return "OFFLINE_FIXTURE_ONLY"
    path, key_path, expected_hash = (os.environ.get(name) for name in
        ("CMH_SOURCE_BINDING_AUTHORIZATION", "CMH_RESOURCE_GATE_KEY_FILE",
         "CMH_SOURCE_BINDING_AUTH_SHA256"))
    if not path or not key_path or not expected_hash:
        raise ValueError("signed source binding authorization is required")
    raw = _private(Path(path))
    if sha256(raw) != expected_hash:
        raise ValueError("source binding authorization hash mismatch")
    value = json.loads(raw)
    signature = value.pop("authorization_hmac_sha256", None)
    expected = hmac.new(_private(Path(key_path)), canonical(value), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ValueError("source binding authorization signature mismatch")
    if (value.get("version") != "cmh-source-binding-contract-authorization/v1"
            or value.get("mission_id") != mission_id
            or value.get("new_contract") !=
            "model_submitted_verbatim_quote_and_source_id; machine_derived_unique_exact_utf8_range"
            or value.get("resource_limits_unchanged") is not True
            or value.get("chunk_cross_identity_migration_authorized") is not False
            or value.get("historical_requests_286_324_unchanged") is not True
            or value.get("historical_failures_not_pass") is not True):
        raise ValueError("source binding authorization scope mismatch")
    return expected_hash


class SourceBindingError(ValueError):
    """A source rejection with bounded, non-secret diagnostic fields."""

    def __init__(self, subclass: str, field: str, rule: str, decision: dict,
                 source: bytes | None):
        source_id = decision.get("source_id")
        actual_source = source_id if isinstance(source_id, str) and re.fullmatch(r"[0-9a-f]{64}", source_id) else None
        quote = decision.get("source_quote")
        quote_bytes = quote.encode("utf-8") if isinstance(quote, str) else None
        start, end = decision.get("quote_start"), decision.get("quote_end")
        actual_range = ([start, end] if type(start) is int and type(end) is int else None)
        ranged_bytes = (source[start:end] if source is not None and actual_range is not None
                        and 0 <= start < end <= len(source) else None)
        occurrences = []
        if source is not None and quote_bytes:
            cursor = source.find(quote_bytes)
            while cursor >= 0 and len(occurrences) < 2:
                occurrences.append([cursor, cursor + len(quote_bytes)])
                cursor = source.find(quote_bytes, cursor + 1)
        finding_id = decision.get("finding_id")
        safe_finding = (finding_id if isinstance(finding_id, str)
                        and re.fullmatch(r"[CGF][0-9]{3}F[0-9]{3}", finding_id) else None)
        self.details = {
            "error_class": "INVALID_SOURCE_BINDING", "error_subclass": subclass,
            "stage_id": None, "finding_id": safe_finding, "disposition_id": safe_finding,
            "source_id": actual_source, "source_path": None,
            "expected_source_hash": sha256(source) if source is not None else None,
            "actual_source_hash": actual_source,
            "expected_range": occurrences[0] if len(occurrences) == 1 else None,
            "actual_range": actual_range,
            "expected_quote_hash": sha256(ranged_bytes) if ranged_bytes is not None else None,
            "actual_quote_hash": sha256(quote_bytes) if quote_bytes is not None else None,
            "validation_rule": rule, "failure_field": field,
            "quote_occurrence_count": len(occurrences),
        }
        super().__init__("dispute lacks an exact bound source reference")


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


def validate_source_binding(decision: dict, source: bytes | None) -> dict:
    """Locate only the model's verbatim quote in this immutable Group source."""
    source_id = decision.get("source_id")
    if set(decision) != {"finding_id", "decision", "rationale", "source_quote", "source_id"}:
        raise SourceBindingError("INVALID_REFERENCE_FIELDS", "source_reference",
                                 "MODEL_QUOTE_ONLY", decision, source)
    if decision["decision"] == "UPHELD":
        if source_id != "" or decision["source_quote"]:
            raise SourceBindingError("UPHELD_UNEXPECTED_SOURCE", "source_reference",
                                     "UPHELD_REFERENCE_MUST_BE_EMPTY", decision, source)
        return {"finding_id": decision["finding_id"], "validation": "UPHELD_NO_REFERENCE",
                "source_id": "", "source_sha256": None, "quote_sha256": None,
                "quote_start": 0, "quote_end": 0, "locator_version": SOURCE_BINDING_VERSION}
    quote = decision["source_quote"].encode("utf-8")
    if source is None:
        raise SourceBindingError("SOURCE_UNAVAILABLE", "source_id",
                                 "DISPUTE_REQUIRES_GROUP_SOURCE", decision, source)
    if source_id != sha256(source):
        raise SourceBindingError("SOURCE_ID_MISMATCH", "source_id",
                                 "GROUP_SOURCE_HASH_MATCH", decision, source)
    if len(quote.strip()) < 12:
        raise SourceBindingError("QUOTE_TOO_SHORT", "source_quote",
                                 "MINIMUM_QUOTE_BYTES", decision, source)
    start = source.find(quote)
    if start < 0:
        raise SourceBindingError("QUOTE_NOT_EXACT", "source_quote",
                                 "EXACT_UTF8_GROUP_SOURCE", decision, source)
    if source.find(quote, start + 1) >= 0:
        raise SourceBindingError("QUOTE_AMBIGUOUS", "source_quote",
                                 "UNIQUE_UTF8_GROUP_SOURCE", decision, source)
    return {"finding_id": decision["finding_id"], "validation": "EXACT_UNIQUE_UTF8",
            "source_id": source_id, "source_sha256": sha256(source),
            "quote_sha256": sha256(quote), "quote_start": start,
            "quote_end": start + len(quote), "locator_version": SOURCE_BINDING_VERSION}


def parse_synthesis(raw: str, expected: list[dict], *, source: bytes | None,
                    structured_evidence: bool = False) -> dict:
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
    bindings = []
    used_references = set()
    for decision in value["decisions"]:
        if isinstance(decision, dict) and isinstance(decision.get("finding_id"), str):
            if decision["finding_id"] not in required:
                raise ValueError("unknown disposition finding_id")
            if decision["finding_id"] in observed:
                raise ValueError("duplicate disposition finding_id")
        decision_fields = {"finding_id", "decision", "rationale", "source_quote"}
        if structured_evidence:
            decision_fields.add("source_id")
        if (not isinstance(decision, dict)
                or set(decision) != decision_fields
                or not isinstance(decision.get("finding_id"), str)
                or decision["finding_id"] not in required
                or decision["finding_id"] in observed
                or decision.get("decision") not in {"UPHELD", "DISPUTED"}
                or not isinstance(decision.get("rationale"), str)
                or len(decision["rationale"].strip()) < 24
                or not isinstance(decision.get("source_quote"), str)):
            raise ValueError("invalid or duplicate disposition")
        if structured_evidence:
            binding = validate_source_binding(decision, source)
            reference = (binding["source_id"], binding["quote_start"], binding["quote_end"])
            if decision["decision"] == "DISPUTED":
                if reference in used_references:
                    raise SourceBindingError("EVIDENCE_REUSED", "source_quote",
                                             "DISTINCT_FINDING_EVIDENCE", decision, source)
                used_references.add(reference)
            bindings.append(binding)
        elif decision["decision"] == "DISPUTED":
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
    return {"decisions": value["decisions"], "source_bindings": bindings,
            "new_findings": new_findings,
            "summary": value["summary"], "findings": findings,
            "review_result": "FAIL" if any(item["severity"] in BLOCKING
                                       for item in findings) else "PASS"}


def validate_bound_result(result: dict, expected: list[dict], source: bytes | None,
                          *, structured_evidence: bool = False) -> None:
    """Recompute every derived field when validating a durable receipt."""
    if not isinstance(result, dict) or set(result) != {
            "decisions", "source_bindings", "new_findings", "summary", "findings", "review_result"}:
        raise ValueError("invalid bound result")
    model_fields = {key: result[key] for key in ("decisions", "summary")}
    model_fields["findings"] = result["new_findings"]
    if parse_synthesis(canonical(model_fields).decode(), expected, source=source,
                       structured_evidence=structured_evidence) != result:
        raise ValueError("bound result differs from model decisions")
