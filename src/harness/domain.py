from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


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


@dataclass(frozen=True)
class Observation:
    state: State
    head: str | None
    worktree: str | None
    pending_gate: str | None
    background_jobs: int
    terminal: bool
