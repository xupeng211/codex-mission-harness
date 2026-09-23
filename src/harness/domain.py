from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class State(StrEnum):
    CREATED = "CREATED"
    PREPARING = "PREPARING"
    IMPLEMENT = "IMPLEMENT"
    TEST = "TEST"
    REVIEW = "REVIEW"
    CI = "CI"
    MERGE = "MERGE"
    POST_MERGE = "POST_MERGE"
    DELIVER = "DELIVER"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    PASS = "PASS"
    BLOCKED_EXTERNAL = "BLOCKED_EXTERNAL"
    BLOCKED_POLICY = "BLOCKED_POLICY"
    FAILED_FATAL = "FAILED_FATAL"


TERMINAL = {State.PASS, State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY, State.FAILED_FATAL}
FLOW = [
    State.CREATED, State.PREPARING, State.IMPLEMENT, State.TEST, State.REVIEW,
    State.CI, State.MERGE, State.POST_MERGE, State.DELIVER, State.PASS,
]
ALLOWED: dict[State, set[State]] = {
    current: {FLOW[index + 1], State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY, State.FAILED_FATAL}
    for index, current in enumerate(FLOW[:-1])
}
ALLOWED[State.TEST].add(State.IMPLEMENT)
ALLOWED[State.REVIEW].add(State.IMPLEMENT)
ALLOWED[State.CI].add(State.IMPLEMENT)
ALLOWED[State.MERGE].add(State.WAITING_APPROVAL)
ALLOWED[State.WAITING_APPROVAL] = {State.MERGE, State.BLOCKED_EXTERNAL, State.BLOCKED_POLICY, State.FAILED_FATAL}


class InvalidTransition(RuntimeError):
    pass


@dataclass(frozen=True)
class MissionSpec:
    mission_id: str
    repository: str
    objective: str
    adapter: str = "footballprediction"
    schema_version: int = 1
    required_gates: tuple[str, ...] = ("verify-pr",)
    reviews: tuple[str, ...] = ("codex", "deepseek")
    merge_policy: str = "owner_approval"
    post_merge_gates: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "MissionSpec":
        """Decode the durable v1 contract without accepting schema drift."""
        data = dict(raw)
        required = {"schema_version", "mission_id", "repository", "objective"}
        allowed = set(cls.__dataclass_fields__)
        if type(data.get("schema_version")) is not int or data.get("schema_version") != 1 or not required <= data.keys():
            raise ValueError("mission spec must be v1 and include mission_id, repository, objective")
        if unknown := set(data) - allowed:
            raise ValueError(f"unknown mission spec fields: {sorted(unknown)}")
        for field in ("required_gates", "reviews", "post_merge_gates", "forbidden_actions"):
            if field in data:
                value = data[field]
                if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
                    raise ValueError(f"{field} must be a string list")
                data[field] = tuple(value)
        adapter = data.get("adapter", "footballprediction")
        if not isinstance(adapter, str) or adapter not in {"footballprediction", "simulation"}:
            raise ValueError("adapter must be exactly footballprediction or simulation")
        if data.get("merge_policy", "owner_approval") not in {"owner_approval", "auto"}:
            raise ValueError("merge_policy must be exactly owner_approval or auto")
        for field in ("mission_id", "repository", "objective"):
            if not isinstance(data[field], str) or not data[field]:
                raise ValueError(f"{field} must be a non-empty string")
        return cls(**data)


@dataclass(frozen=True)
class Observation:
    state: State
    head: str | None
    worktree: str | None
    pending_gate: str | None
    background_jobs: int
    terminal: bool
