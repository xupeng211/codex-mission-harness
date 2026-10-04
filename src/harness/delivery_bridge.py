"""Offline validation of a current-version delivery *draft*.

This module has no signing, reservation, launch, or receipt API.  A valid
draft is never an authorization to make a model request.
"""
from __future__ import annotations

import hashlib
import json
import re

from .resource_gate import canonical


class BridgeRejected(ValueError):
    pass


OLD_MISSION = "HARNESS_AUTONOMOUS_PRE_MERGE_DELIVERY"
IDENTITY_FIELDS = ("main_sha", "pr2_head", "pr4_head", "runtime_sha256", "registry_sha256")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def validate_draft(draft: dict, old_ledger_bytes: bytes, current_identity: dict) -> dict:
    """Compare a proposed identity with the supplied immutable history and Git identity.

    The caller must independently authenticate the historical ledger hash and
    current Git identity.  This function never turns either input into trusted
    execution authorization.
    """
    if not isinstance(draft, dict) or not isinstance(current_identity, dict):
        raise BridgeRejected("bridge draft or current identity invalid")
    fields = {"version", "old_mission_id", "old_ledger_sha256", "request_334_sha256",
              "old_acceptance", "old_model_requests_frozen", "new_mission_id", "scope",
              *IDENTITY_FIELDS, "source_binding_version", "models",
              "shared_account_evidence_sha256", "old_deepseek_cost_reserved_microusd",
              "new_authorization_status", "new_mission_executable", "new_model_requests_allowed"}
    if set(draft) != fields or set(current_identity) != set(IDENTITY_FIELDS):
        raise BridgeRejected("bridge identity fields invalid")
    if (draft["version"] != "cmh-current-delivery-bridge-draft/v1"
            or draft["old_mission_id"] != OLD_MISSION
            or draft["old_acceptance"] != "INCOMPLETE"
            or draft["old_model_requests_frozen"] is not True
            or not isinstance(draft["new_mission_id"], str)
            or draft["new_mission_id"] in ("", OLD_MISSION)
            or draft["scope"] != ["PR2_HARNESS_V0_1_1", "PR4_REVIEWER_V2"]
            or draft["source_binding_version"] != "exact-unique-utf8-quote/v1"
            or draft["models"] != {"deepseek": "deepseek-flash", "openai": "gpt-5.6-sol/high"}
            or draft["new_authorization_status"] != "PENDING_USER_APPROVAL"
            or draft["new_mission_executable"] is not False
            or draft["new_model_requests_allowed"] is not False):
        raise BridgeRejected("draft cannot activate or alter the old mission")
    if (draft["old_deepseek_cost_reserved_microusd"] != 28800000
            or draft["shared_account_evidence_sha256"] is not None and
            not isinstance(draft["shared_account_evidence_sha256"], str)):
        raise BridgeRejected("historical or shared accounting invalid")
    for name in IDENTITY_FIELDS:
        length = 40 if name.endswith("head") or name == "main_sha" else 64
        if (not isinstance(draft[name], str) or
                not re.fullmatch(r"[0-9a-f]{%d}" % length, draft[name]) or
                draft[name] != current_identity[name]):
            raise BridgeRejected("current Git or Runtime identity changed")
    if (not isinstance(draft["old_ledger_sha256"], str)
            or draft["old_ledger_sha256"] != _sha(old_ledger_bytes)):
        raise BridgeRejected("old ledger hash changed")
    try:
        rows = json.loads(old_ledger_bytes)["requests"]
    except (TypeError, ValueError, KeyError):
        raise BridgeRejected("old ledger unreadable") from None
    if (not isinstance(rows, list) or len(rows) != 334 or
            any(not isinstance(row, dict) or row.get("number") != n
                for n, row in enumerate(rows, 1))):
        raise BridgeRejected("old ledger sequence changed")
    request = rows[333]
    if (draft["request_334_sha256"] != _sha(canonical(request))
            or request.get("mission_id") != OLD_MISSION
            or request.get("status") != "FAILED"
            or request.get("reported_usage") != "UNKNOWN"
            or request.get("usage_accounting") != "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
            or request.get("provider") != "deepseek"
            or request.get("cost_reservation_microunits") != 400000):
        raise BridgeRejected("request 334 history changed")
    return {"draft_identity_sha256": _sha(canonical(draft)),
            "old_ledger_sha256": _sha(old_ledger_bytes),
            "request_334_sha256": _sha(canonical(request)),
            "old_mission_model_requests_frozen": True,
            "new_mission_executable": False, "new_model_requests_allowed": False,
            "authorization_status": "PENDING_USER_APPROVAL"}
