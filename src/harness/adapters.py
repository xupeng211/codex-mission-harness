"""Thin, fail-closed bridge to FootballPrediction's existing authorities."""
from __future__ import annotations

import json
import hashlib
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
    REVIEW_CONTRACT_PATHS = (
        "Makefile", "scripts/devops/codex_independent_review.py",
        "scripts/devops/codex_review_classification.py", "scripts/devops/codex_review_contract.py",
        "scripts/devops/codex_review_output.py", "scripts/devops/codex_review_provenance.py",
        "scripts/devops/codex_review_receipt.py", "scripts/devops/claude_deepseek_independent_review.py",
        "scripts/devops/deepseek_chunk_receipt_validation.py", "scripts/devops/deepseek_receipt_evidence.py",
        "scripts/devops/independent_review_protocol.py", "scripts/devops/independent_review_receipt.py",
        "scripts/devops/review_policy.py", "scripts/devops/agent_workflow.py",
        "scripts/devops/pr_post_merge_check.py", "scripts/devops/exact_head.py",
        "docs/agentic/independent_review_backends.json",
        "schemas/agentic/codex_review_result.schema.json", "schemas/agentic/codex_review_receipt.schema.json",
        "schemas/agentic/independent_review_result.schema.json", "schemas/agentic/independent_review_receipt.schema.json",
    )

    def exact_head(self, worktree: str) -> str:
        dirty = self._run(["git", "-C", worktree, "status", "--porcelain=v1", "--untracked-files=all"])
        if dirty:
            raise RuntimeError("canonical evidence requires a clean committed worktree")
        return self._run(["git", "-C", worktree, "rev-parse", "HEAD"]).strip().lower()

    def gate_argv(self, gate: str) -> list[str]:
        if gate not in self.GATES: raise ValueError(f"unsupported canonical gate: {gate}")
        return self.GATES[gate]

    def review_preflight(self, worktree: str, base: str, head: str) -> GateResult:
        """Prove both immutable commits exist; policy executes from base checkout."""
        for revision in (base, head):
            present = self._call(["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=worktree)
            if present.returncode != 0:
                return GateResult("BLOCKED_EXTERNAL", f"canonical review commit is unavailable: {revision}")
        return GateResult("PASS", "canonical policy will execute from trusted base")

    def _trusted_base_checkout(self, worktree: str, base: str, evidence_dir: str) -> Path:
        root = Path(evidence_dir).resolve().parents[2] / "trusted-base" / base
        if not root.exists():
            root.parent.mkdir(parents=True, exist_ok=True)
            added = self._call(["git", "worktree", "add", "--detach", str(root), base], cwd=worktree)
            if added.returncode != 0:
                raise RuntimeError(added.stderr.strip() or "cannot create trusted base checkout")
        observed = self._run(["git", "rev-parse", "HEAD"], cwd=str(root)).strip().lower()
        dirty = self._run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=str(root))
        if observed != base.lower() or dirty:
            raise RuntimeError("trusted base checkout identity is invalid")
        return root

    def review_argv(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                    scope_file: str, evidence_dir: str) -> list[str]:
        trusted = self._trusted_base_checkout(worktree, base, evidence_dir)
        common = ["--repo-root", worktree, "--base-sha", base, "--head-sha", head,
                  "--mission-id", mission_id, "--mission-scope-file", scope_file,
                  "--evidence-dir", evidence_dir]
        if reviewer == "codex":
            return ["python3", str(trusted / "scripts/devops/codex_independent_review.py"), "run", *common]
        if reviewer == "deepseek":
            return ["python3", str(trusted / "scripts/devops/claude_deepseek_independent_review.py"), *common]
        raise ValueError(f"unsupported independent reviewer: {reviewer}")

    def review(self, reviewer: str, head: str) -> GateResult:
        """Compatibility guard: production review needs bound scope/context.

        Supervisor v0.1 callers cannot supply those mandatory canonical inputs,
        so this path refuses rather than manufacturing a receipt.
        """
        return GateResult("BLOCKED_EXTERNAL", "review requires mission_scope_file and exact base/worktree context")

    def review_result(self, reviewer: str, *, worktree: str, base: str, head: str, mission_id: str,
                      scope_file: str, stdout_path: str) -> GateResult:
        """Accept only a canonical receipt, revalidated against exact inputs."""
        preflight = self.review_preflight(worktree, base, head)
        if preflight.status != "PASS":
            return preflight
        payload = self._json_last_line(stdout_path)
        receipt = payload.get("review_receipt") if payload else None
        if not isinstance(receipt, str) or not Path(receipt).is_file():
            return GateResult("BLOCKED_EXTERNAL", "canonical review did not publish a receipt")
        if reviewer == "codex":
            trusted = self._trusted_base_checkout(worktree, base, str(Path(receipt).parent))
            argv = ["python3", str(trusted / "scripts/devops/codex_independent_review.py"), "classify", "--repo-root", worktree,
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
            if evidence.get("receipt_version") == "independent-review-receipt/v1":
                trusted = self._trusted_base_checkout(worktree, base, str(Path(receipt).parent))
                # Re-run the target's canonical evidence consumer. Its code is
                # accepted only after review_preflight proves it is unchanged
                # from the trusted base.
                required = {"receipt_version", "base_sha", "head_sha", "mission_id", "diff_sha256", "review_result", "findings", "integrity"}
            else:
                return GateResult("BLOCKED_EXTERNAL", "unknown DeepSeek receipt contract", receipt)
            if not required <= set(evidence) or evidence.get("base_sha") != base or evidence.get("head_sha") != head or evidence.get("mission_id") != mission_id:
                return GateResult("BLOCKED_EXTERNAL", "DeepSeek receipt binding is incomplete or stale", receipt)
            if evidence.get("receipt_version") == "independent-review-receipt/v1":
                try:
                    relative_scope = Path(scope_file).resolve().relative_to(Path(worktree).resolve()).as_posix()
                    scope_bytes = subprocess.check_output(
                        ["git", "show", f"{head}:{relative_scope}"], cwd=worktree,
                        stderr=subprocess.PIPE, timeout=60,
                    )
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    return GateResult("BLOCKED_EXTERNAL", f"cannot bind reviewed mission scope: {exc}", receipt)
                scope_hash = hashlib.sha256(scope_bytes).hexdigest()
                validator = (
                    "from dataclasses import asdict; import json,sys; from pathlib import Path; "
                    "from scripts.devops.deepseek_receipt_evidence import _deepseek_receipt_evidence as v; "
                    "print(json.dumps(asdict(v(Path(sys.argv[1]),repo_root=Path(sys.argv[2]),"
                    "expected_base=sys.argv[3],expected_head=sys.argv[4],expected_mission_id=sys.argv[5],expected_scope_hash=sys.argv[6]))))"
                )
                checked = self._call(["python3", "-c", validator, receipt, worktree, base, head, mission_id, scope_hash], cwd=str(trusted))
                canonical = self._json_last_text(checked.stdout)
                if checked.returncode != 0 or canonical.get("trusted") is not True:
                    return GateResult("BLOCKED_EXTERNAL", checked.stderr.strip() or "canonical DeepSeek receipt validation failed", receipt)
                if canonical.get("result") != evidence.get("review_result"):
                    return GateResult("BLOCKED_EXTERNAL", "canonical DeepSeek verdict mismatch", receipt)
            blocking = any(isinstance(finding, dict) and finding.get("severity") in {"P0", "P1", "P2"}
                           for finding in evidence.get("findings", []))
            if evidence.get("review_result") != "PASS" or blocking:
                return GateResult("FAIL", "canonical DeepSeek receipt reports findings", receipt, evidence)
            return GateResult("PASS", "canonical DeepSeek aggregate receipt validated", receipt, evidence)
        else: return GateResult("BLOCKED_EXTERNAL", f"unknown reviewer {reviewer}")
        result = self._call(argv, cwd=worktree)
        if result.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or result.stdout.strip(), receipt)
        classification = self._json_last_text(result.stdout)
        if classification.get("classification", {}).get("classification") != "VALID_CURRENT":
            return GateResult("BLOCKED_EXTERNAL", "canonical Codex receipt is not VALID_CURRENT", receipt, classification)
        if payload.get("status") != "PASS":
            return GateResult("FAIL", "canonical receipt reports findings", receipt, payload)
        return GateResult("PASS", "canonical exact-head receipt validated", receipt, payload)

    def discover_pr(self, worktree: str, head: str) -> GateResult:
        try:
            repo = json.loads(self._run(["gh", "repo", "view", "--json", "nameWithOwner"], cwd=worktree))["nameWithOwner"]
            branch = self._run(["git", "branch", "--show-current"], cwd=worktree).strip()
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

    def merge(self, worktree: str, head: str, pr_number: int | None = None) -> GateResult:
        if pr_number is None: return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR identity")
        before = self.merge_status(worktree, head, pr_number)
        if before.status != "NOT_STARTED": return before
        result = self._call(["gh", "pr", "merge", str(pr_number), "--squash", "--match-head-commit", head], cwd=worktree)
        if result.returncode != 0: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "merge command failed")
        return self.merge_status(worktree, head, pr_number)

    def merge_status(self, worktree: str, reviewed_head: str, pr_number: int | None = None) -> GateResult:
        if pr_number is None:
            return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR identity")
        try:
            repo = json.loads(self._run(["gh", "repo", "view", "--json", "nameWithOwner"], cwd=worktree))["nameWithOwner"]
            data = json.loads(self._run(["gh", "api", f"repos/{repo}/pulls/{pr_number}"], cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot reconcile merge state: {exc}")
        if data.get("merged") is True:
            merged_head = str((data.get("head") or {}).get("sha", "")).lower()
            if merged_head != reviewed_head.lower():
                return GateResult("BLOCKED_EXTERNAL", f"merged PR head {merged_head or 'MISSING'} differs from reviewed head {reviewed_head}")
            merge_sha = str(data.get("merge_commit_sha") or "").lower()
            if len(merge_sha) != 40: return GateResult("BLOCKED_EXTERNAL", "merged PR lacks a full merge SHA")
            return GateResult("PASS", f"merged PR #{pr_number}", data={"pr": pr_number, "merge_sha": merge_sha, "repo": repo})
        if str(data.get("state", "")).upper() == "OPEN" and str((data.get("head") or {}).get("sha", "")).lower() == reviewed_head.lower():
            return GateResult("NOT_STARTED", f"PR #{pr_number} is still open at the reviewed HEAD; merge retry is safe", data={"pr": pr_number})
        return GateResult("BLOCKED_EXTERNAL", f"ambiguous merge state for PR #{pr_number}")

    def post_merge(self, worktree: str, merge_sha: str, pr_number: int, branch: str, base: str) -> GateResult:
        trusted = self._trusted_base_checkout(worktree, base, str(Path(worktree).parent / ".cmh-review-evidence" / "post-merge" / merge_sha))
        result = self._call(["python3", str(trusted / "scripts/devops/pr_post_merge_check.py"), "--pr", str(pr_number),
                             "--merge-commit", merge_sha, "--branch", branch, "--json"], cwd=worktree)
        try: data = json.loads(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if str(data.get("ci_head_sha", "")).lower() != merge_sha.lower():
            return GateResult("BLOCKED_EXTERNAL", "Production Gate is not bound to exact merge SHA")
        if data.get("verdict") == "PASS":
            try:
                self._run(["git", "fetch", "origin", "main"], cwd=worktree)
                main_sha = self._run(["git", "rev-parse", "origin/main"], cwd=worktree).strip().lower()
                tree_sha = self._run(["git", "rev-parse", "origin/main^{tree}"], cwd=worktree).strip().lower()
                reachable = self._call(["git", "merge-base", "--is-ancestor", merge_sha, "origin/main"], cwd=worktree)
            except (subprocess.SubprocessError, OSError) as exc:
                return GateResult("BLOCKED_EXTERNAL", f"cannot record post-merge main truth: {exc}")
            if reachable.returncode != 0:
                return GateResult("BLOCKED_EXTERNAL", "merged SHA is not reachable from origin/main")
            data.update({"main_sha": main_sha, "tree_sha": tree_sha})
            return GateResult("PASS", "canonical Production Gate passed", data=data)
        if str(data.get("ci_status")) in {"queued", "in_progress", "requested"}: return GateResult("PENDING", json.dumps(data), data=data)
        if not data.get("ci_status"): return GateResult("BLOCKED_EXTERNAL", "Production Gate omitted CI status", data=data)
        return GateResult("FAIL", json.dumps(data), data=data)

    @staticmethod
    def _call(argv, cwd=None): return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False, timeout=60)
    @staticmethod
    def _run(argv, cwd=None): return subprocess.check_output(argv, cwd=cwd, text=True, stderr=subprocess.PIPE, timeout=60)
    @staticmethod
    def _json_last_line(path):
        try:
            for line in reversed(Path(path).read_text(encoding="utf-8").splitlines()):
                try: value = json.loads(line)
                except json.JSONDecodeError: continue
                if isinstance(value, dict): return value
        except OSError: pass
        return {}

    @staticmethod
    def _json_last_text(text: str) -> dict[str, Any]:
        for line in reversed(text.splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
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
    def merge(self, worktree, head, pr_number=None):
        self.merged_heads.add(head); value=self.merge_results[min(self.merge_index,len(self.merge_results)-1)]; self.merge_index+=1; return GateResult(value, f"fixture merge {head}", data={"pr":1,"merge_sha":"c"*40})
    def merge_status(self, worktree, reviewed_head, pr_number=None):
        return GateResult("PASS" if reviewed_head in self.merged_heads else "NOT_STARTED", f"fixture merge status {reviewed_head}", data={"pr":1,"merge_sha":"c"*40})
    def post_merge(self, *args):
        value=self.post_results[min(self.post_index,len(self.post_results)-1)]; self.post_index+=1
        return GateResult(value, "fixture post merge", data={"main_sha":"d"*40,"tree_sha":"e"*40})
