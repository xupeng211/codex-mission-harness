from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class GateResult:
    status: str  # PASS, FAIL, PENDING, BLOCKED_EXTERNAL
    evidence: str = ""


class FootballPredictionAdapter:
    """Calls FootballPrediction's canonical commands; it deliberately contains no business validator."""
    GATES = {
        "verify-targeted": ["make", "verify-targeted"],
        "verify-pr": ["make", "verify-pr"],
        "verify-strict": ["make", "verify-strict"],
        "agent-preflight": ["make", "agent-preflight"],
    }

    def exact_head(self, worktree: str) -> str:
        return subprocess.check_output(["git", "-C", worktree, "rev-parse", "HEAD"], text=True).strip()

    def gate_argv(self, gate: str) -> list[str]:
        if gate not in self.GATES:
            raise ValueError(f"unsupported canonical gate: {gate}")
        return self.GATES[gate]

    def ci(self, worktree: str, head: str) -> GateResult:
        # v0.1 intentionally does not claim GitHub truth without a project-specific authenticated query.
        return GateResult("PENDING", f"GitHub query required for exact head {head}")

    def review(self, reviewer: str, head: str) -> GateResult:
        return GateResult("BLOCKED_EXTERNAL", f"canonical {reviewer} review command/receipt is required for exact head {head}")

    def merge(self, worktree: str, head: str) -> GateResult:
        return GateResult("BLOCKED_POLICY", "project merge requires owner-controlled canonical evidence")

    def post_merge(self, gate: str, head: str) -> GateResult:
        return GateResult("BLOCKED_EXTERNAL", f"canonical post-merge gate {gate} required for {head}")


class SimulatedAdapter(FootballPredictionAdapter):
    """Deterministic non-production adapter used only by tests and the safe demonstration."""
    def __init__(self, heads: list[str] | None = None, reviews: list[str] | None = None, ci: list[str] | None = None):
        self.heads, self.reviews, self.ci_results = heads or ["a" * 40], reviews or ["PASS", "PASS"], ci or ["PASS"]
        self.head_index = self.review_index = self.ci_index = 0

    def exact_head(self, worktree: str) -> str:
        return self.heads[min(self.head_index, len(self.heads) - 1)]

    def gate_argv(self, gate: str) -> list[str]:
        return ["/bin/sh", "-c", "exit 0"]

    def review(self, reviewer: str, head: str) -> GateResult:
        value = self.reviews[min(self.review_index, len(self.reviews) - 1)]
        self.review_index += 1
        return GateResult(value, f"fixture {reviewer} {head}")

    def ci(self, worktree: str, head: str) -> GateResult:
        value = self.ci_results[min(self.ci_index, len(self.ci_results) - 1)]
        self.ci_index += 1
        return GateResult(value, f"fixture CI {head}")

    def merge(self, worktree: str, head: str) -> GateResult:
        return GateResult("PASS", f"fixture merge {head}")

    def post_merge(self, gate: str, head: str) -> GateResult:
        return GateResult("PASS", f"fixture post-merge {gate} {head}")
