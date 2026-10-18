"""Deterministic, opt-in task routing. No discovery, qualification or inference.

Pool metadata is operator authority, never proof of provider access or billing.
Every selected entry still passes the existing strict CLIProxyAPI policy.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import date
from decimal import Decimal
from pathlib import Path

TIERS = {"economy": 0, "balanced": 1, "high": 2}
CATEGORIES = {"general", "docs", "tests", "bugfix", "feature", "refactor", "security", "migration"}
EFFORTS = {"low", "medium", "high", "xhigh"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", value)


def validate_request(request):
    if not isinstance(request, dict) or set(request) - {"category", "complexity", "risk", "model", "tier", "effort"}:
        raise ValueError("invalid task model_routing attributes")
    for key, allowed in (("category", CATEGORIES), ("complexity", {"low", "normal", "complex"}),
                         ("risk", {"low", "normal", "high"}), ("tier", TIERS), ("effort", EFFORTS)):
        if key in request and (not isinstance(request[key], str) or request[key] not in allowed):
            raise ValueError("invalid task routing " + key)
    if "model" in request and not identifier(request["model"]):
        raise ValueError("invalid pool model identifier")


def validate_pool(pool):
    from .factory_proxy import validate_transport
    if not isinstance(pool, dict) or set(pool) != {"version", "models"} or type(pool["version"]) is not int or pool["version"] != 1:
        raise ValueError("invalid model routing pool")
    if not isinstance(pool["models"], list) or not 1 <= len(pool["models"]) <= 64:
        raise ValueError("routing pool requires 1..64 explicit models")
    ids = set()
    fields = {"id", "model", "route_id", "tier", "efforts", "categories", "available", "auto", "protocol", "transport", "price"}
    for entry in pool["models"]:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise ValueError("invalid pool model fields")
        if any(not identifier(entry[k]) for k in ("id", "model", "route_id")) or entry["id"] in ids:
            raise ValueError("pool identifiers must be valid and unique")
        ids.add(entry["id"])
        if not isinstance(entry["tier"], str) or entry["tier"] not in TIERS:
            raise ValueError("invalid capability tier")
        for key, allowed in (("efforts", EFFORTS), ("categories", CATEGORIES)):
            values = entry[key]
            if not isinstance(values, list) or not values or any(not isinstance(x, str) or x not in allowed for x in values) or len(set(values)) != len(values):
                raise ValueError("invalid pool " + key)
        if type(entry["available"]) is not bool or type(entry["auto"]) is not bool or entry["protocol"] != "codex_responses":
            raise ValueError("pool requires declared availability and Codex Responses compatibility")
        if not isinstance(entry["transport"], dict) or entry["transport"].get("type") != "cli_proxy":
            raise ValueError("pool entries require a strict cli_proxy transport")
        validate_transport({"provider": "openai", "model": entry["model"], "transport": entry["transport"]})
        price = entry["price"]
        if price == "UNKNOWN":
            continue
        price_fields = {"currency", "input_per_million", "output_per_million", "cached_input_per_million", "source", "as_of", "basis"}
        if not isinstance(price, dict) or set(price) != price_fields or price["currency"] != "USD" or price["basis"] != "operator_verified":
            raise ValueError("price requires explicit operator-verified USD rates or UNKNOWN")
        if not isinstance(price["source"], str) or not re.fullmatch(r"[A-Za-z0-9_.:/ -]{1,240}", price["source"]):
            raise ValueError("price requires a non-secret source reference")
        try:
            date.fromisoformat(price["as_of"])
        except (TypeError, ValueError):
            raise ValueError("price requires an as_of date") from None
        for key in ("input_per_million", "output_per_million", "cached_input_per_million"):
            if not isinstance(price[key], str) or not re.fullmatch(r"\d{1,8}(?:\.\d{1,8})?", price[key]):
                raise ValueError("price rates must be nonnegative decimal strings")
        if Decimal(price["cached_input_per_million"]) > Decimal(price["input_per_million"]):
            raise ValueError("cached price exceeds input price")
    # A route label cannot silently refer to two different endpoints/policies.
    routes = {}
    for entry in pool["models"]:
        old = routes.setdefault(entry["route_id"], entry["transport"])
        if old != entry["transport"]:
            raise ValueError("route_id maps to conflicting transports")


def select(pool, request=None):
    """Return profile plus a reproducible selection receipt, without any I/O."""
    validate_pool(pool)
    request = {} if request is None else request
    validate_request(request)
    category = request.get("category", "general")
    if request.get("risk") == "high" or request.get("complexity") == "complex" or category in {"security", "migration"}:
        required, reason = "high", "complex_or_high_risk"
    elif not {"category", "complexity", "risk"} <= set(request):
        required, reason = "high", "insufficient_attributes_conservative_high"
    elif request["complexity"] == "low" and request["risk"] == "low":
        required, reason = "economy", "explicit_low_complexity_and_low_risk"
    else:
        required, reason = "balanced", "ordinary_development"
    tier = request.get("tier", required)
    if TIERS[tier] < TIERS[required]:
        raise ValueError("manual tier below task capability requirement")
    effort = request.get("effort", {"economy": "low", "balanced": "medium", "high": "high"}[tier])
    candidates = [e for e in pool["models"] if e["available"] and
                  TIERS[e["tier"]] >= TIERS[tier] and category in e["categories"] and effort in e["efforts"] and
                  (e["id"] == request["model"] if "model" in request else e["auto"])]
    if not candidates:
        raise ValueError("no available compatible model meets task/model/tier/effort requirements")
    def rank(entry):
        price = entry["price"]
        known = price != "UNKNOWN"
        # Fixed comparison workload: 100k uncached input + 10k output. This is
        # a selection heuristic, not a prediction of actual task tokens/cost.
        score = Decimal(price["input_per_million"]) / 10 + Decimal(price["output_per_million"]) / 100 if known else Decimal(0)
        return TIERS[entry["tier"]], not known, score, entry["id"]
    chosen = min(candidates, key=rank)
    profile = {"provider": "openai", "model": chosen["model"], "effort": effort, "transport": copy.deepcopy(chosen["transport"])}
    decision = {"policy_version": 1, "pool_sha256": digest(pool), "task_attributes": copy.deepcopy(request),
                "required_tier": required, "selected_tier": chosen["tier"], "reason": reason,
                "selection_mode": "manual_model" if "model" in request else "manual_tier" if "tier" in request else "automatic",
                "pool_model_id": chosen["id"], "route_id": chosen["route_id"], "requested_model": chosen["model"],
                "effort": effort, "price": copy.deepcopy(chosen["price"]),
                "ranking_basis": "capability_then_known_reference_cost_then_id", "upstream_model_identity": "NOT_PROVABLE",
                "actual_bill": "UNKNOWN"}
    return profile, decision


def estimate(price, usage, complete):
    """Conditional requested-model estimate; never a verified provider bill."""
    if price == "UNKNOWN" or complete is not True or not isinstance(usage, dict):
        return "UNKNOWN"
    from .factory_budget import tokens
    if tokens(usage) is None:
        return "UNKNOWN"
    inputs, outputs, cached = (usage.get(k) for k in ("input_tokens", "output_tokens", "cached_input_tokens"))
    if any(type(x) is not int or x < 0 for x in (inputs, outputs, cached)) or cached > inputs:
        return "UNKNOWN"
    cost = sum(Decimal(price[key]) * amount for key, amount in
               (("input_per_million", inputs-cached), ("cached_input_per_million", cached), ("output_per_million", outputs))) / 1_000_000
    return {"amount": str(cost), "currency": price["currency"], "basis": "conditional_requested_model_token_rates",
            "price": price, "actual_bill": "UNKNOWN", "upstream_model_identity": "NOT_PROVABLE"}


def observation(decision, operations):
    runs, qa = [], []
    for op in operations:
        result = json.loads(op["result"]) if op["result"] else {}
        if not op["paid"]:
            if op["stage"] in {"checks", "ci"}:
                qa.append({"stage": op["stage"], "status": result.get("status", "UNKNOWN"), "exit_code": result.get("exit_code", "UNKNOWN")})
            continue
        if op["lane"] != "developer":
            continue
        runtime = result.get("runtime_identity") or {}
        physical = result.get("physical_accounting", runtime.get("physical_accounting", {}))
        attempts = physical.get("physical_attempts", [])
        # Same-thread receipts are cumulative: price only each operation's delta.
        usage = result.get("usage") or {}
        usage = usage.get("total", usage)
        runs.append({"stage": op["stage"], "status": op["status"], "requested_model": decision["requested_model"],
                     "reported_models": sorted({a["reported_model"] for a in attempts if a.get("reported_model")}),
                     "usage": usage, "usage_complete": result.get("usage_complete", False),
                     "elapsed_seconds": round(op["ended"]-op["started"], 3) if op["ended"] else "UNKNOWN",
                     "estimated_cost": estimate(decision["price"], usage, op["status"] == "COMPLETE" and result.get("usage_complete") is True), "actual_bill": "UNKNOWN"})
    return {"selection": decision, "operations": runs, "qa_results": qa,
            "repair_attempts": sum(r["stage"] == "rework" for r in runs), "actual_bill": "UNKNOWN"}


def main():
    parser = argparse.ArgumentParser(description="Offline task route preview; no network or inference")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--mission", type=Path, required=True)
    args = parser.parse_args()
    from .factory import validate_config
    config = validate_config(json.loads(args.config.read_text()))
    mission = json.loads(args.mission.read_text())
    profile, decision = select(config["model_routing"], mission.get("model_routing"))
    print(json.dumps({"profile": profile, "selection": decision, "model_inference_calls": 0,
                      "route_access": "NOT_VERIFIED", "REAL_PROXY_MODEL_DISPATCH_VERIFIED": "NO"}, indent=2))


if __name__ == "__main__":
    main()
