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
        prices = lane.get("price_microusd_per_million", {})
        if set(prices) != {"input_cache_miss", "output", "cache_hit"} or any(
                type(price) is not int or price <= 0 for price in prices.values()):
            raise ResourceGateDenied("DeepSeek cost estimate requires an authorized price table")
    return lane


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
            if self.reported_usage is not None:
                tokens = self.reported_usage.get("tokens", {})
                if any(type(tokens.get(k)) is not int or tokens[k] < 0 or
                       tokens[k] > record["token_reservation"][k]
                       for k in ("input", "output", "reasoning", "cache")):
                    record["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
                prices = record.get("price_microusd_per_million")
                if prices and all(type(tokens.get(k)) is int and tokens[k] >= 0
                                  for k in ("input", "output", "cache")):
                    numerator = (tokens["input"] * prices["input_cache_miss"] +
                                 tokens["output"] * prices["output"] +
                                 tokens["cache"] * prices["cache_hit"])
                    estimate = (numerator + 999_999) // 1_000_000
                    record["estimated_cost_microusd"] = estimate
                    record["estimated_cost_classification"] = "ESTIMATED_NOT_BILLED"
                    if estimate > record["cost_reservation_microunits"]:
                        record["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
            _write_atomic(self.ledger, ledger)


def reserve(*, provider: str, model: str, prompt: bytes, stage: str,
            environment: dict[str, str] | None = None) -> Reservation:
    env = os.environ if environment is None else environment
    needed = ("CMH_RESOURCE_AUTHORIZATION", "CMH_RESOURCE_AUTH_SHA256", "CMH_RESOURCE_GATE_KEY_FILE",
              "CMH_RESOURCE_LEDGER", "CMH_RESOURCE_MISSION_ID", "CMH_RESOURCE_RUN_ID")
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
        if any(row.get("status") in {"STARTED", "UNKNOWN"} or
               row.get("usage_accounting") == "OVER_RESERVATION_BLOCK_FUTURE_CALLS" for row in rows):
            raise ResourceGateDenied("unreconciled or over-reservation request blocks new launch")
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
