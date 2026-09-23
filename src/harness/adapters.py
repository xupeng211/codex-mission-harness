"""Thin, fail-closed bridge to FootballPrediction's existing authorities."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GateResult:
    status: str  # PASS, FAIL, PENDING, BLOCKED_EXTERNAL
    evidence: str = ""
    artifact: str | None = None
    data: dict[str, Any] | None = None


class FootballPredictionAdapter:
    """Call project commands/GitHub; never duplicate their safety policy."""
    GATES = {"verify-targeted": ["make", "verify-targeted"], "verify-pr": ["make", "verify-pr"],
             "verify-strict": ["make", "verify-strict"], "agent-preflight": ["make", "agent-preflight"]}

    def exact_head(self, worktree: str) -> str:
        dirty = self._run(["git", "-C", worktree, "status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise RuntimeError("canonical evidence requires a clean committed worktree")
        return self._run(["git", "-C", worktree, "rev-parse", "HEAD"]).strip().lower()

    def gate_argv(self, gate: str) -> list[str]:
        if gate not in self.GATES: raise ValueError(f"unsupported canonical gate: {gate}")
        return self.GATES[gate]

    def review_argv(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                    scope_file: str, evidence_dir: str) -> list[str]:
        programs = {"codex": "scripts/devops/codex_independent_review.py",
                    "deepseek": "scripts/devops/claude_deepseek_independent_review.py"}
        if reviewer not in programs: raise ValueError(f"unsupported independent reviewer: {reviewer}")
        command = ["python3", programs[reviewer]]
        if reviewer == "codex":
            command.append("run")
        return command + ["--repo-root", worktree, "--base-sha", base,
                "--head-sha", head, "--mission-id", mission_id, "--mission-scope-file", scope_file,
                "--evidence-dir", evidence_dir]

    def review(self, reviewer: str, head: str) -> GateResult:
        """Compatibility guard: production review needs bound scope/context.

        Supervisor v0.1 callers cannot supply those mandatory canonical inputs,
        so this path refuses rather than manufacturing a receipt.
        """
        return GateResult("BLOCKED_EXTERNAL", "review requires mission_scope_file and exact base/worktree context")

    def review_result(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                      scope_file: str, stdout_path: str) -> GateResult:
        """Accept only a canonical receipt, revalidated against exact inputs."""
        payload = self._json_last_line(stdout_path)
        receipt = payload.get("review_receipt") if payload else None
        if not isinstance(receipt, str) or not Path(receipt).is_file():
            return GateResult("BLOCKED_EXTERNAL", "canonical review did not publish a receipt")
        if reviewer == "codex":
            argv = ["python3", "scripts/devops/codex_independent_review.py", "validate", "--repo-root", worktree,
                    "--receipt", receipt, "--current-head", head, "--base-sha", base, "--mission-id", mission_id,
                    "--mission-scope-file", scope_file, "--json"]
        elif reviewer == "deepseek":
            # Project-owned validator verifies aggregate/chunk evidence.  The
            # reviewer receives embedded diff chunks, not repository tools.
            # The runner validates the chunk aggregate before its commit-last
            # receipt write. Verify the durable binding again here without
            # inventing a competing review protocol.
            try:
                evidence = json.loads(Path(receipt).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt is unreadable", receipt)
            if evidence.get("base_sha") != base or evidence.get("reviewed_head_sha") != head or evidence.get("mission_id") != mission_id:
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt binding is incomplete or stale", receipt)
            if evidence.get("review_result") != "PASS":
                return GateResult("FAIL", "canonical DeepSeek receipt reports findings", receipt, evidence)
            return GateResult("PASS", "canonical DeepSeek aggregate receipt validated", receipt, evidence)
        else: return GateResult("BLOCKED_EXTERNAL", f"unknown reviewer {reviewer}")
        result = self._call(argv, cwd=worktree)
        if result.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or result.stdout.strip(), receipt)
        if payload.get("status") != "PASS":
            return GateResult("FAIL", "canonical receipt reports findings", receipt, payload)
        return GateResult("PASS", "canonical exact-head receipt validated", receipt, payload)

    def discover_pr(self, worktree: str, head: str) -> GateResult:
        try:
            repo = json.loads(self._run(["gh", "repo", "view", "--json", "nameWithOwner"], cwd=worktree))["nameWithOwner"]
            branch = self._run(["git", "branch", "--show-current"], cwd=worktree)
            pulls = json.loads(self._run(["gh", "api", f"repos/{repo}/pulls?state=open&head={repo.split('/')[0]}:{branch}"], cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"GitHub PR discovery unavailable: {exc}")
        matches = [p for p in pulls if str((p.get("head") or {}).get("sha", "")).lower() == head.lower()
                   and str((p.get("head") or {}).get("ref", "")) == branch]
        if len(matches) != 1:
            return GateResult("BLOCKED_EXTERNAL", f"expected one open PR for branch={branch} head={head}; found {len(matches)}")
        return GateResult("PASS", f"PR #{matches[0]['number']}", data={"number": int(matches[0]["number"]), "repo": repo})

    def ci(self, worktree: str, head: str) -> GateResult:
        pr = self.discover_pr(worktree, head)
        if pr.status != "PASS": return pr
        result = self._call(["make", "pr-ready", f"PR={pr.data['number']}", "JSON=1"], cwd=worktree)
        try: data = json.loads(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical pr-ready returned no JSON")
        observed = str((data.get("pr") or {}).get("head_sha", "")).lower()
        if observed != head.lower(): return GateResult("BLOCKED_EXTERNAL", f"PR HEAD {observed or 'MISSING'} does not equal {head}")
        checks = [f for f in data.get("findings", []) if str(f.get("name", "")).startswith("required-check:")]
        if not checks: return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready reported no required checks")
        messages = "\n".join(str(f.get("message", "")) for f in checks)
        if all(bool(f.get("passed")) for f in checks): return GateResult("PASS", messages, data=data)
        if "status=queued" in messages or "status=in_progress" in messages or "no run for exact HEAD" in messages:
            return GateResult("PENDING", messages, data=data)
        return GateResult("FAIL", messages, data=data)

    def merge(self, worktree: str, head: str) -> GateResult:
        pr = self.discover_pr(worktree, head)
        if pr.status != "PASS": return pr
        result = self._call(["gh", "pr", "merge", str(pr.data["number"]), "--squash", "--match-head-commit", head], cwd=worktree)
        if result.returncode != 0: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "merge command failed")
        return self.merge_status(worktree, head, pr.data["number"])

    def merge_status(self, worktree: str, reviewed_head: str, pr_number: int | None = None) -> GateResult:
        if pr_number is None:
            return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR identity")
        try:
            repo = json.loads(self._run(["gh", "repo", "view", "--json", "nameWithOwner"], cwd=worktree))["nameWithOwner"]
            data = json.loads(self._run(["gh", "api", f"repos/{repo}/pulls/{pr_number}"], cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot reconcile merge state: {exc}")
        if data.get("merged") is True:
            merge_sha = str(data.get("merge_commit_sha") or "").lower()
            if len(merge_sha) != 40: return GateResult("BLOCKED_EXTERNAL", "merged PR lacks a full merge SHA")
            return GateResult("PASS", f"merged PR #{pr_number}", data={"pr": pr_number, "merge_sha": merge_sha, "repo": repo})
        if str(data.get("state", "")).upper() == "OPEN" and str((data.get("head") or {}).get("sha", "")).lower() == reviewed_head.lower():
            return GateResult("PENDING", f"PR #{pr_number} is still open; merge provably not completed", data={"pr": pr_number})
        return GateResult("BLOCKED_EXTERNAL", f"ambiguous merge state for PR #{pr_number}")

    def post_merge(self, worktree: str, merge_sha: str, pr_number: int, branch: str) -> GateResult:
        result = self._call(["python3", "scripts/devops/pr_post_merge_check.py", "--pr", str(pr_number),
                             "--merge-commit", merge_sha, "--branch", branch, "--json"], cwd=worktree)
        try: data = json.loads(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if str(data.get("ci_head_sha", "")).lower() != merge_sha.lower():
            return GateResult("BLOCKED_EXTERNAL", "Production Gate is not bound to exact merge SHA")
        if data.get("verdict") == "PASS": return GateResult("PASS", "canonical Production Gate passed", data=data)
        if str(data.get("ci_status")) in {"queued", "in_progress", "requested", ""}: return GateResult("PENDING", json.dumps(data), data=data)
        return GateResult("FAIL", json.dumps(data), data=data)

    @staticmethod
    def _call(argv, cwd=None): return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False, timeout=60)
    @staticmethod
    def _run(argv, cwd=None): return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.PIPE, timeout=60)
    @staticmethod
    def _json_last_line(path):
        try:
            for line in reversed(Path(path).read_text(encoding="utf-8").splitlines()):
                value = json.loads(line)
                if isinstance(value, dict): return value
        except (OSError, json.JSONDecodeError): pass
        return {}


class SimulatedAdapter(FootballPredictionAdapter):
    """Deterministic non-production adapter used only by tests and the safe demonstration."""
    def __init__(self, heads=None, reviews=None, ci=None, merge=None, post_merge=None):
        self.heads, self.reviews, self.ci_results = heads or ["a" * 40], reviews or ["PASS", "PASS"], ci or ["PASS"]
        self.merge_results, self.post_results = merge or ["PASS"], post_merge or ["PASS"]
        self.head_index = self.review_index = self.ci_index = self.merge_index = self.post_index = 0
        self.merged_heads: set[str] = set()
    def exact_head(self, worktree): return self.heads[min(self.head_index, len(self.heads)-1)]
    def gate_argv(self, gate): return ["/bin/sh", "-c", "exit 0"]
    def discover_pr(self, worktree, head): return GateResult("PASS", "fixture PR", data={"number": 1, "repo": "fixture/repo"})
    def review_argv(self, *args, **kwargs): return ["/bin/sh", "-c", "exit 0"]
    def review(self, reviewer, head):
        value=self.reviews[min(self.review_index,len(self.reviews)-1)]; self.review_index+=1; return GateResult(value, f"fixture {reviewer}", "/tmp/fake")
    def review_result(self, reviewer, **kwargs):
        value=self.reviews[min(self.review_index,len(self.reviews)-1)]; self.review_index+=1; return GateResult(value, f"fixture {reviewer}", "/tmp/fake")
    def ci(self, worktree, head):
        value=self.ci_results[min(self.ci_index,len(self.ci_results)-1)]; self.ci_index+=1; return GateResult(value, f"fixture CI {head}")
    def merge(self, worktree, head):
        self.merged_heads.add(head); value=self.merge_results[min(self.merge_index,len(self.merge_results)-1)]; self.merge_index+=1; return GateResult(value, f"fixture merge {head}", data={"pr":1,"merge_sha":"c"*40})
    def merge_status(self, worktree, reviewed_head, pr_number=None): return GateResult("PASS" if reviewed_head in self.merged_heads else "NOT_STARTED", f"fixture merge status {reviewed_head}")
    def post_merge(self, *args):
        value=self.post_results[min(self.post_index,len(self.post_results)-1)]; self.post_index+=1; return GateResult(value, "fixture post merge")
