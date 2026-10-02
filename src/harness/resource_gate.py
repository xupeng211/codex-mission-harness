"""Mission-scoped, fail-closed reservations for real reviewer invocations.

The original request ledger remains the logical-call counter.  Token and cost
reservations are forward-looking accounting debits: an unknown or failed call
keeps its entire debit.  A provider's reported usage is evidence, not a bill.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path


class ResourceGateDenied(RuntimeError):
    pass


_active_reservation: ContextVar[Reservation | None] = ContextVar("cmh_active_resource_reservation", default=None)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _private(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise ResourceGateDenied("resource gate path must be absolute and non-symlinked")
    info = path.stat()
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ResourceGateDenied("resource gate parent directory must be private")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ResourceGateDenied("resource gate artifact must be private")
    return path.read_bytes()


@contextmanager
def _locked(path: Path):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ResourceGateDenied("unsafe resource ledger lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def sign_authorization(payload: dict, key: bytes) -> dict:
    """Used only after an explicit human budget authorization is recorded."""
    unsigned = {k: v for k, v in payload.items() if k != "authorization_hmac_sha256"}
    return dict(unsigned, authorization_hmac_sha256=hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest())


def _authorization(path: Path, key_path: Path, approval_sha256: str) -> dict:
    raw = _private(path)
    if digest(raw) != approval_sha256:
        raise ResourceGateDenied("resource authorization version/hash differs from approved version")
    value = json.loads(raw)
    signature = value.pop("authorization_hmac_sha256", None)
    expected = hmac.new(_private(key_path), canonical(value), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ResourceGateDenied("resource authorization signature invalid")
    if (value.get("version") != "cmh-resource-budget/v1" or
            value.get("token_authorization") != "APPROVED" or
            value.get("cost_authorization") != "APPROVED"):
        raise ResourceGateDenied("token and cost budgets require explicit approval")
    if (not isinstance(value.get("authorization_id"), str) or not value["authorization_id"] or
            not isinstance(value.get("approval_source"), str) or not value["approval_source"] or
            type(value.get("approved_at_epoch")) not in (int, float)):
        raise ResourceGateDenied("budget authorization provenance is incomplete")
    call_wall_path = Path(value.get("call_wall_authorization_path", ""))
    call_wall_raw = _private(call_wall_path)
    if digest(call_wall_raw) != value.get("call_wall_authorization_sha256"):
        raise ResourceGateDenied("call/wall authorization hash changed")
    call_wall = json.loads(call_wall_raw)
    approved = call_wall.get("after", {})
    if (call_wall.get("mission_id") != value.get("mission_id") or
            call_wall.get("original_started_epoch") != value.get("original_started_epoch") or
            value.get("max_logical_model_calls") != approved.get("max_logical_model_calls") or
            value.get("max_wall_clock_seconds") != approved.get("max_wall_clock_seconds") or
            value.get("baseline_calls") != approved.get("calls_used") or
            value.get("baseline_ledger_sha256") != call_wall.get("before", {}).get("ledger_sha256")):
        raise ResourceGateDenied("ordinary configuration cannot raise call/wall hard limits")
    return value


def _frozen_prefix(path: Path, key_path: Path, expected_sha256: str,
                   mission_id: str, ledger_path: Path) -> dict:
    raw = _private(path)
    if digest(raw) != expected_sha256:
        raise ResourceGateDenied("frozen ledger attestation hash changed")
    value = json.loads(raw)
    signature = value.pop("authorization_hmac_sha256", None)
    expected = hmac.new(_private(key_path), canonical(value), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ResourceGateDenied("frozen ledger attestation signature invalid")
    if (value.get("version") != "cmh-ledger-freeze/v1" or
            value.get("mission_id") != mission_id or
            value.get("ledger_path") != str(ledger_path) or
            type(value.get("frozen_calls")) is not int or value["frozen_calls"] < 1 or
            not isinstance(value.get("frozen_requests_sha256"), str)):
        raise ResourceGateDenied("frozen ledger attestation identity invalid")
    return value


def _write_atomic(path: Path, payload: dict) -> None:
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(payload) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _limits(value: dict, provider: str, model: str) -> dict:
    lane = value.get("providers", {}).get(provider)
    if not isinstance(lane, dict) or lane.get("model") != model:
        raise ResourceGateDenied("provider/model budget identity mismatch")
    if lane.get("unknown_policy") != "DEBIT_FULL_RESERVATION_STOP_ON_OVERAGE":
        raise ResourceGateDenied("unknown usage policy is not authorized")
    tokens = lane.get("token_reservation", {})
    maxima = lane.get("token_limit", {})
    if set(tokens) != {"input", "output", "reasoning", "cache"} or set(maxima) != set(tokens):
        raise ResourceGateDenied("token categories incomplete")
    if any(type(tokens[k]) is not int or tokens[k] <= 0 or
           type(maxima[k]) is not int or maxima[k] <= 0 for k in tokens):
        raise ResourceGateDenied("invalid token budget")
    if (type(lane.get("cost_reservation_microunits")) is not int or
            lane["cost_reservation_microunits"] <= 0 or
            type(lane.get("cost_limit_microunits")) is not int or
            lane["cost_limit_microunits"] <= 0 or
            lane.get("cost_unit") not in {"USD", "CODEX_SUBSCRIPTION_UNITS"}):
        raise ResourceGateDenied("invalid cost budget")
    if provider == "deepseek":
        if lane.get("billing_route_verified") is not True:
            raise ResourceGateDenied("DeepSeek billing route is not verified")
        for label in ("price_source", "billing_route_evidence"):
            raw_path = lane.get(label + "_path")
            source_hash = lane.get(label + "_sha256")
            if (not isinstance(raw_path, str) or not Path(raw_path).is_absolute() or
                    Path(raw_path).is_symlink() or not isinstance(source_hash, str) or
                    len(source_hash) != 64):
                raise ResourceGateDenied("DeepSeek " + label + " is not bound to signed evidence")
            try:
                source = Path(raw_path).read_bytes()
            except OSError as exc:
                raise ResourceGateDenied("DeepSeek " + label + " cannot be read") from exc
            if digest(source) != source_hash:
                raise ResourceGateDenied("DeepSeek " + label + " hash changed")
        prices = lane.get("price_microusd_per_million", {})
        if set(prices) != {"input_cache_miss", "output", "cache_hit"} or any(
                type(price) is not int or price <= 0 for price in prices.values()):
            raise ResourceGateDenied("DeepSeek cost estimate requires an authorized price table")
    return lane


def _approved_billing_recovery(auth: dict, lane: dict, frozen: dict,
                               rows: list[dict], key_path: Path) -> set[int]:
    """Permit only explicitly signed dispositions of immutable CLI fallback estimates.

    This never changes a ledger row or its debit.  The original authorization
    has no recovery policy and therefore continues to block requests 255/256.
    """
    policy = lane.get("cli_cost_policy")
    if policy is None:
        return set()
    if policy != "VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK" or (
            auth.get("billing_recovery_approved") is not True or
            not isinstance(auth.get("billing_recovery_approval_source"), str) or
            not auth["billing_recovery_approval_source"]):
        raise ResourceGateDenied("official billing recovery requires explicit signed approval")
    for label in ("official_billing_export", "billing_recovery"):
        name, expected = lane.get(label + "_path"), lane.get(label + "_sha256")
        if (not isinstance(name, str) or not Path(name).is_absolute() or
                Path(name).is_symlink() or not isinstance(expected, str) or len(expected) != 64):
            raise ResourceGateDenied("billing recovery evidence path/hash missing")
        try:
            raw = _private(Path(name)) if label == "billing_recovery" else Path(name).read_bytes()
        except OSError as exc:
            raise ResourceGateDenied("billing recovery evidence unavailable") from exc
        if digest(raw) != expected:
            raise ResourceGateDenied("billing recovery evidence hash changed")
        if label == "billing_recovery":
            evidence_raw = raw
    evidence = json.loads(evidence_raw)
    signature = evidence.pop("authorization_hmac_sha256", None)
    expected_signature = hmac.new(_private(key_path), canonical(evidence), hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise ResourceGateDenied("billing recovery evidence signature invalid")
    if (evidence.get("version") != "cmh-deepseek-official-billing-recovery/v1" or
            evidence.get("mission_id") != auth["mission_id"] or
            evidence.get("frozen_calls") != frozen["frozen_calls"] or
            evidence.get("frozen_requests_sha256") != frozen["frozen_requests_sha256"] or
            evidence.get("source_daily_export_sha256") != lane["official_billing_export_sha256"] or
            evidence.get("model") != lane["model"] or
            not isinstance(lane.get("billing_account_key_name"), str) or
            not lane["billing_account_key_name"] or
            evidence.get("account_key_name") != lane["billing_account_key_name"] or
            evidence.get("price_source_sha256") != lane["price_source_sha256"] or
            evidence.get("billing_route_evidence_sha256") != lane["billing_route_evidence_sha256"] or
            evidence.get("official_price_microusd_per_million") != lane["price_microusd_per_million"] or
            evidence.get("resumption_approved") is not True or
            evidence.get("approval_source") != auth["billing_recovery_approval_source"]):
        raise ResourceGateDenied("billing recovery approval/evidence identity mismatch")
    dispositions = evidence.get("dispositions")
    if not isinstance(dispositions, list) or not dispositions:
        raise ResourceGateDenied("billing recovery requires exact request dispositions")
    permitted: set[int] = set()
    for item in dispositions:
        number = item.get("number") if isinstance(item, dict) else None
        if type(number) is not int or number in permitted or not 1 <= number <= frozen["frozen_calls"]:
            raise ResourceGateDenied("billing recovery request number invalid")
        row = rows[number - 1]
        usage = row.get("reported_usage")
        tokens = usage.get("tokens") if isinstance(usage, dict) else None
        raw_name, raw_hash = item.get("raw_cli_artifact_path"), item.get("raw_cli_artifact_sha256")
        if (not isinstance(raw_name, str) or not Path(raw_name).is_absolute() or
                Path(raw_name).is_symlink() or not isinstance(raw_hash, str) or len(raw_hash) != 64):
            raise ResourceGateDenied("billing recovery raw CLI evidence missing")
        try:
            raw_bytes = Path(raw_name).read_bytes()
        except OSError as exc:
            raise ResourceGateDenied("billing recovery raw CLI evidence unavailable") from exc
        if digest(raw_bytes) != raw_hash:
            raise ResourceGateDenied("billing recovery raw CLI evidence hash changed")
        raw_cli = json.loads(raw_bytes)
        raw_usage = raw_cli.get("usage") if isinstance(raw_cli, dict) else None
        raw_model = raw_cli.get("modelUsage", {}).get(row.get("model")) if isinstance(raw_cli, dict) else None
        read = raw_usage.get("cache_read_input_tokens") if isinstance(raw_usage, dict) else None
        created = raw_usage.get("cache_creation_input_tokens") if isinstance(raw_usage, dict) else None
        if (not isinstance(tokens, dict) or
                any(type(tokens.get(k)) is not int for k in ("input", "output", "reasoning", "cache")) or
                type(read) is not int or read < 0 or
                type(created) is not int or created < 0 or
                raw_usage.get("input_tokens") != tokens.get("input") or
                raw_usage.get("output_tokens") != tokens.get("output") or
                read + created != tokens.get("cache") or
                (raw_usage.get("output_tokens_details") or {}).get("thinking_tokens") != tokens.get("reasoning") or
                not isinstance(raw_model, dict) or raw_model.get("costBasis") != "unknown" or
                type(raw_cli.get("total_cost_usd")) not in (int, float) or
                round(raw_cli["total_cost_usd"] * 1_000_000) != usage.get("cli_reported_cost_microunits")):
            raise ResourceGateDenied("billing recovery raw usage does not match ledger")
        prices = lane["price_microusd_per_million"]
        estimate = ((tokens["input"] + created) * prices["input_cache_miss"] +
                    read * prices["cache_hit"] + tokens["output"] * prices["output"] + 999_999) // 1_000_000
        if (row.get("provider") != "deepseek" or row.get("status") != "RETURNED" or
                any(type(tokens.get(k)) is not int or tokens[k] < 0 or
                    tokens[k] > row["token_reservation"][k]
                    for k in ("input", "output", "reasoning", "cache")) or
                tokens["reasoning"] > tokens["output"] or
                estimate > row["cost_reservation_microunits"] or
                item.get("official_usd_snapshot_estimate_microusd") != estimate or
                (type(row.get("estimated_cost_microusd")) is int and
                 row["estimated_cost_microusd"] != estimate) or
                type(usage.get("cli_reported_cost_microunits")) is not int or
                usage["cli_reported_cost_microunits"] <= row.get("cost_reservation_microunits", -1) or
                row.get("cost_overage_source") == "AUTHORIZED_PRICE_ESTIMATE" or
                (type(row.get("estimated_cost_microusd")) is int and
                 row["estimated_cost_microusd"] > row["cost_reservation_microunits"]) or
                item.get("request_id") != row.get("request_id") or
                item.get("row_sha256") != digest(canonical(row)) or
                item.get("classification") != "CLI_FALLBACK_ESTIMATE_NOT_BILLED" or
                item.get("settlement_status") != "ESTIMATED_ONLY" or
                item.get("confirmed_billed_cost") != "UNKNOWN" or
                item.get("reservation_refund_microusd") != 0 or
                item.get("retain_original_overage") is not True):
            raise ResourceGateDenied("billing recovery request evidence invalid")
        permitted.add(number)
    return permitted


def _disclosed_cli_fallback(row: dict) -> bool:
    usage = row.get("reported_usage")
    model_usage = usage.get("raw_model_usage") if isinstance(usage, dict) else None
    return (row.get("cost_basis_policy") == "VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK" and
            row.get("cli_fallback_over_reservation_observed") is True and
            row.get("estimated_cost_classification") == "ESTIMATED_NOT_BILLED" and
            type(row.get("estimated_cost_microusd")) is int and
            row["estimated_cost_microusd"] <= row.get("cost_reservation_microunits", -1) and
            isinstance(model_usage, dict) and model_usage.get("costBasis") == "unknown")


def normalize_deepseek_usage(usage: dict | None, cli_cost_usd: object = None,
                             model_usage: dict | None = None) -> dict:
    """Keep Claude CLI's disjoint input/cache fields and session cost visible."""
    raw = usage if isinstance(usage, dict) else {}
    read = raw.get("cache_read_input_tokens")
    created = raw.get("cache_creation_input_tokens")
    observed = {"tokens": {
        "input": raw.get("input_tokens"), "output": raw.get("output_tokens"),
        "reasoning": (raw.get("output_tokens_details") or {}).get("thinking_tokens")
        if isinstance(raw.get("output_tokens_details"), dict) else None,
        "cache": read + created if type(read) is int and type(created) is int else None},
        "cache_read_tokens": read, "cache_creation_tokens": created,
        "usage_scope": "CLI_SESSION_AGGREGATE", "raw_usage_fields": raw,
        "raw_model_usage": model_usage if isinstance(model_usage, dict) else None,
        "cost_classification": "OBSERVED_UNBILLED"}
    if type(cli_cost_usd) in (int, float) and cli_cost_usd >= 0:
        observed["cli_reported_cost_microunits"] = round(cli_cost_usd * 1_000_000)
    return observed


class Reservation:
    def __init__(self, ledger: Path, request_id: str, authorization_sha256: str,
                 provider: str, model: str):
        self.ledger, self.request_id, self.authorization_sha256 = ledger, request_id, authorization_sha256
        self.provider, self.model = provider, model
        self.reported_usage: dict | None = None

    def observe(self, usage: dict | None) -> None:
        if usage is not None and not isinstance(usage, dict):
            raise ResourceGateDenied("reported usage must be structured")
        self.reported_usage = usage

    def settle(self, status: str) -> None:
        lock = self.ledger.with_name(self.ledger.name + ".lock")
        with _locked(lock):
            ledger = json.loads(_private(self.ledger))
            matches = [entry for entry in ledger["requests"] if entry.get("request_id") == self.request_id]
            if len(matches) != 1 or matches[0].get("status") != "STARTED":
                raise ResourceGateDenied("request settlement identity/state mismatch")
            record = matches[0]
            record["status"] = status
            record["finished_epoch"] = time.time()
            record["duration_seconds"] = round(record["finished_epoch"] - record["started_epoch"], 3)
            record["reported_usage"] = self.reported_usage if self.reported_usage is not None else "UNKNOWN"
            record["usage_accounting"] = "FULL_RESERVATION_RETAINED"
            if self.reported_usage is None and self.provider == "deepseek":
                record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
            if self.reported_usage is not None:
                tokens = self.reported_usage.get("tokens", {})
                complete = isinstance(tokens, dict) and all(
                    type(tokens.get(k)) is int and tokens[k] >= 0
                    for k in ("input", "output", "reasoning", "cache"))
                if not complete:
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                elif any(tokens[k] > record["token_reservation"][k]
                         for k in ("input", "output", "reasoning", "cache")):
                    record["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
                if complete and tokens["reasoning"] > tokens["output"]:
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                prices = record.get("price_microusd_per_million")
                read = self.reported_usage.get("cache_read_tokens")
                created = self.reported_usage.get("cache_creation_tokens")
                if prices and complete and (type(read) is not int or read < 0 or
                        type(created) is not int or created < 0 or
                        read + created != tokens["cache"]):
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                model_usage = self.reported_usage.get("raw_model_usage")
                if prices and model_usage is not None and (
                        not isinstance(model_usage, dict) or
                        any(model_usage.get(name) != expected for name, expected in (
                            ("inputTokens", tokens.get("input") if isinstance(tokens, dict) else None),
                            ("outputTokens", tokens.get("output") if isinstance(tokens, dict) else None),
                            ("cacheReadInputTokens", read),
                            ("cacheCreationInputTokens", created),
                            ("thinkingTokens", tokens.get("reasoning") if isinstance(tokens, dict) else None)))):
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                if prices and complete and type(read) is int and read >= 0 and (
                        type(created) is int and created >= 0 and
                        read + created == tokens["cache"] and
                        tokens["reasoning"] <= tokens["output"]):
                    # Claude CLI input_tokens excludes cache read/creation.
                    # output_tokens already contains thinking_tokens.
                    numerator = ((tokens["input"] + created) * prices["input_cache_miss"] +
                                 tokens["output"] * prices["output"] +
                                 read * prices["cache_hit"])
                    estimate = (numerator + 999_999) // 1_000_000
                    record["estimated_cost_microusd"] = estimate
                    record["estimated_cost_classification"] = "ESTIMATED_NOT_BILLED"
                    if estimate > record["cost_reservation_microunits"]:
                        record["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
                        record["cost_overage_source"] = "AUTHORIZED_PRICE_ESTIMATE"
                cli_cost = self.reported_usage.get("cli_reported_cost_microunits")
                if prices and isinstance(model_usage, dict) and (
                        type(model_usage.get("costUSD")) not in (int, float) or
                        round(model_usage["costUSD"] * 1_000_000) != cli_cost):
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                if prices and (type(cli_cost) is not int or cli_cost < 0):
                    record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                elif prices and cli_cost > record["cost_reservation_microunits"] and (
                        record["usage_accounting"] != "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"):
                    if record.get("cost_basis_policy") == (
                            "VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK"):
                        if not isinstance(model_usage, dict) or model_usage.get("costBasis") != "unknown":
                            record["usage_accounting"] = "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS"
                        else:
                            # Preserve the high CLI estimate as evidence.  Only the signed,
                            # account-bound official price determines the budget estimate.
                            record["cli_fallback_over_reservation_observed"] = True
                    else:
                        record["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
                        record["cost_overage_source"] = "CLI_ESTIMATE_UNBILLED"
            _write_atomic(self.ledger, ledger)


def reserve(*, provider: str, model: str, prompt: bytes, stage: str,
            environment: dict[str, str] | None = None) -> Reservation:
    env = os.environ if environment is None else environment
    needed = ("CMH_RESOURCE_AUTHORIZATION", "CMH_RESOURCE_AUTH_SHA256", "CMH_RESOURCE_GATE_KEY_FILE",
              "CMH_RESOURCE_LEDGER", "CMH_RESOURCE_MISSION_ID", "CMH_RESOURCE_RUN_ID",
              "CMH_RESOURCE_FREEZE", "CMH_RESOURCE_FREEZE_SHA256")
    if any(not env.get(name) for name in needed):
        raise ResourceGateDenied("complete approved resource context is required before model launch")
    auth_path, key_path, ledger_path = (Path(env[name]) for name in
                                       ("CMH_RESOURCE_AUTHORIZATION", "CMH_RESOURCE_GATE_KEY_FILE",
                                        "CMH_RESOURCE_LEDGER"))
    auth = _authorization(auth_path, key_path, env["CMH_RESOURCE_AUTH_SHA256"])
    if str(ledger_path) != auth.get("ledger_path"):
        raise ResourceGateDenied("budget authorization is bound to the original request ledger")
    if auth.get("mission_id") != env["CMH_RESOURCE_MISSION_ID"] or not env["CMH_RESOURCE_RUN_ID"].strip():
        raise ResourceGateDenied("mission/run authorization mismatch")
    frozen = _frozen_prefix(Path(env["CMH_RESOURCE_FREEZE"]), key_path,
                            env["CMH_RESOURCE_FREEZE_SHA256"], auth["mission_id"], ledger_path)
    lane = _limits(auth, provider, model)
    lock = ledger_path.with_name(ledger_path.name + ".lock")
    with _locked(lock):
        ledger = json.loads(_private(ledger_path))
        rows = ledger.get("requests")
        if not isinstance(rows, list) or any(x.get("number") != i for i, x in enumerate(rows, 1)):
            raise ResourceGateDenied("original request accounting is not consecutive")
        baseline = auth.get("baseline_calls")
        if type(baseline) is not int or baseline < 0 or len(rows) < baseline or \
                digest(canonical(rows[:baseline])) != auth.get("baseline_requests_sha256"):
            raise ResourceGateDenied("historical request ledger differs from authorized baseline")
        if (frozen["frozen_calls"] < baseline or len(rows) < frozen["frozen_calls"] or
                digest(canonical(rows[:frozen["frozen_calls"]])) != frozen["frozen_requests_sha256"]):
            raise ResourceGateDenied("frozen request history differs from signed checkpoint")
        # The historical stop is mission-wide: the same signed disposition
        # must be checked before either provider can resume.
        recovery_lane = auth.get("providers", {}).get("deepseek", {})
        if recovery_lane.get("cli_cost_policy") is not None:
            _limits(auth, "deepseek", recovery_lane.get("model"))
        permitted = _approved_billing_recovery(auth, recovery_lane, frozen, rows, key_path)
        if any(row.get("status") in {"STARTED", "UNKNOWN"} or
               row.get("usage_accounting") == "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS" or
               (row.get("usage_accounting") == "OVER_RESERVATION_BLOCK_FUTURE_CALLS" and
                row["number"] not in permitted) for row in rows):
            raise ResourceGateDenied("unreconciled or over-reservation request blocks new launch")
        if any(row.get("provider") == "deepseek" and
               isinstance(row.get("reported_usage"), dict) and
               type(row["reported_usage"].get("cli_reported_cost_microunits")) is int and
               row["reported_usage"]["cli_reported_cost_microunits"] >
               row.get("cost_reservation_microunits", -1) and
               row["number"] not in permitted and not _disclosed_cli_fallback(row)
               for row in rows[baseline:]):
            raise ResourceGateDenied("unreconciled historical cost estimate over reservation")
        if (len(rows) >= auth.get("max_logical_model_calls", -1) or
                time.time() - auth.get("original_started_epoch", 0) >= auth.get("max_wall_clock_seconds", -1)):
            raise ResourceGateDenied("logical-call or wall-clock hard stop reached")
        prior = [row for row in rows[baseline:] if row.get("provider") == provider]
        for category, cap in lane["token_limit"].items():
            if sum(row["token_reservation"][category] for row in prior) + lane["token_reservation"][category] > cap:
                raise ResourceGateDenied("provider token budget exhausted: " + category)
        if sum(row["cost_reservation_microunits"] for row in prior) + lane["cost_reservation_microunits"] > lane["cost_limit_microunits"]:
            raise ResourceGateDenied("provider cost budget exhausted")
        request_id = uuid.uuid4().hex
        rows.append({"number": len(rows) + 1, "request_id": request_id, "provider": provider,
                     "model": model, "stage": stage, "run_id": env["CMH_RESOURCE_RUN_ID"],
                     "mission_id": auth["mission_id"], "authorization_sha256": env["CMH_RESOURCE_AUTH_SHA256"],
                     "invocation_identity_sha256": digest(canonical({"provider": provider, "model": model,
                         "stage": stage, "run_id": env["CMH_RESOURCE_RUN_ID"],
                         "prompt_sha256": digest(prompt)})), "prompt_sha256": digest(prompt),
                     "input_bytes": len(prompt), "started_epoch": time.time(), "status": "STARTED",
                     "token_reservation": lane["token_reservation"],
                     "cost_reservation_microunits": lane["cost_reservation_microunits"],
                     "cost_unit": lane["cost_unit"], "usage_accounting": "FULL_RESERVATION_RETAINED"})
        if provider == "deepseek":
            rows[-1]["price_microusd_per_million"] = lane["price_microusd_per_million"]
            if lane.get("cli_cost_policy") is not None:
                rows[-1]["cost_basis_policy"] = lane["cli_cost_policy"]
        _write_atomic(ledger_path, ledger)
    return Reservation(ledger_path, request_id, env["CMH_RESOURCE_AUTH_SHA256"], provider, model)


@contextmanager
def model_request(*, provider: str, model: str, prompt: bytes, stage: str,
                  environment: dict[str, str] | None = None):
    active = _active_reservation.get()
    if active is not None:
        if (active.provider, active.model) != (provider, model):
            raise ResourceGateDenied("nested model differs from active reservation")
        yield active
        return
    reservation = reserve(provider=provider, model=model, prompt=prompt, stage=stage,
                          environment=environment)
    token = _active_reservation.set(reservation)
    try:
        yield reservation
    except BaseException:
        reservation.settle("FAILED")
        raise
    else:
        reservation.settle("RETURNED")
    finally:
        _active_reservation.reset(token)
