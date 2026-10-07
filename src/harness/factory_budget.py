"""Mission admission accounting, never a provider billing estimate.

Old call-only contracts remain byte-identical. New authorizations reserve token
capacity before each dispatch and keep unknown reservations for life.
"""
from __future__ import annotations


PRESETS = {
    # 1 planning + up to 4/8 tasks + rework + two full reviews per round,
    # plus bounded schema recovery. No autonomous increase of these limits.
    "small": {"max_agent_runs": 16, "max_total_tokens": 2_880_000,
              "max_run_tokens": 180_000, "max_wall_seconds": 7200},
    "standard": {"max_agent_runs": 35, "max_total_tokens": 8_400_000,
                 "max_run_tokens": 240_000, "max_wall_seconds": 21600},
    "large": {"max_agent_runs": 54, "max_total_tokens": 16_200_000,
              "max_run_tokens": 300_000, "max_wall_seconds": 43200},
}
ROUNDS = {"small": 3, "standard": 5, "large": 7}


def tokens(usage):
    if not isinstance(usage, dict):
        return None
    if usage == {"fixture_provider_calls": 0}:
        return 0
    fields = usage.get("total", usage)
    if not isinstance(fields, dict):
        return None
    pairs = (("inputTokens", "outputTokens"), ("input_tokens", "output_tokens"), ("prompt_tokens", "completion_tokens"))
    measured = next((sum(fields[k] for k in pair) for pair in pairs
                     if all(type(fields.get(k)) is int and fields[k] >= 0 for k in pair)), None)
    for key in ("totalTokens", "total_tokens"):
        if key in fields:
            if type(fields[key]) is not int or fields[key] < 0 or measured is not None and fields[key] != measured:
                return None
            return fields[key]
    return measured
    return None


def accounting(operations, budget):
    paid = [op for op in operations if op["paid"]]
    known, unknown, partial = 0, 0, 0
    import json
    for op in paid:
        usage = json.loads(op["usage"]) if op["usage"] else None
        count = tokens(usage)
        if count is None:
            unknown += 1
        else:
            known += count
            result = json.loads(op["result"]) if op["result"] else {}
            complete = result.get("usage_complete", op["status"] == "COMPLETE")
            if complete is not True:
                partial += 1
    # Observed partial telemetry is real and retained, but cannot settle an
    # uncertain dispatch. Keep its full reservation, in addition to observation.
    reserve = (unknown + partial) * budget.get("max_run_tokens", 0)
    return {"agent_runs": len(paid), "limit": budget["max_agent_runs"],
            "observed_tokens": known, "unknown_usage_runs": unknown, "partial_usage_runs": partial,
            "unknown_token_reservation": reserve, "committed_tokens": known + reserve,
            "token_limit": budget.get("max_total_tokens", "LEGACY_NOT_CONFIGURED"),
            "run_token_limit": budget.get("max_run_tokens", "LEGACY_NOT_CONFIGURED"),
            "wall_limit_seconds": budget.get("max_wall_seconds", "LEGACY_PER_RUN_ONLY")}
