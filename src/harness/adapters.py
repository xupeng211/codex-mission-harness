"""Thin, fail-closed bridge to FootballPrediction's existing authorities."""
from __future__ import annotations

import json
import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit


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

    def gate_argv(self, gate: str, **_context: Any) -> list[str]:
        if gate not in self.GATES: raise ValueError(f"unsupported canonical gate: {gate}")
        return self.GATES[gate]

    @staticmethod
    def _gh(*args: str) -> list[str]:
        return ["gh", *args]

    @staticmethod
    def _private_dir(path: Path) -> Path:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.stat()
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise RuntimeError(f"evidence directory is not owned by the current user: {path}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            path.chmod(0o700)
            if stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise RuntimeError(f"evidence directory is not owner-only: {path}")
        return path

    def prepare_gate(self, gate: str, *, worktree: str, base: str, head: str,
                     mission_id: str, scope_file: str) -> GateResult:
        """Prepare explicit inputs required by FootballPrediction preflight."""
        if gate != "agent-preflight":
            return GateResult("PASS")
        pr = self.discover_pr(worktree, head)
        if pr.status != "PASS":
            return pr
        facts = pr.data if isinstance(pr.data, dict) else {}
        detail = self._pr_state(worktree, int(facts["number"]), str(facts["repo"]))
        body = (detail.data or {}).get("body") if isinstance(detail.data, dict) else None
        if not isinstance(body, str):
            return GateResult("BLOCKED_EXTERNAL", "PR discovery omitted a usable PR body")
        evidence = self._private_dir(Path(worktree).parent / ".cmh-gate-evidence" / mission_id / head)
        body_path = evidence / "pr-body.md"
        body_path.write_text(body, encoding="utf-8")
        body_path.chmod(0o600)
        return GateResult("PASS", "canonical preflight inputs prepared", data={"env": {
            "PR_BODY": str(body_path), "MISSION_SCOPE_FILE": scope_file,
            "BASE_REF": base, "HEAD_REF": head, "JSON": "1",
        }})

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
        # The classifier is policy code from the trusted base checkout.  Its
        # imports must resolve there, never from the candidate HEAD worktree.
        result = self._call(argv, cwd=str(trusted))
        if result.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or result.stdout.strip(), receipt)
        classification = self._json_last_text(result.stdout)
        if classification.get("classification", {}).get("classification") != "VALID_CURRENT":
            return GateResult("BLOCKED_EXTERNAL", "canonical Codex receipt is not VALID_CURRENT", receipt, classification)
        validated = classification.get("receipt")
        verdict = validated.get("review_result") if isinstance(validated, dict) else None
        if verdict not in {"PASS", "FAIL"}:
            return GateResult("BLOCKED_EXTERNAL", "canonical Codex classifier omitted a valid receipt verdict", receipt, classification)
        if verdict == "FAIL":
            return GateResult("FAIL", "canonical receipt reports findings", receipt, validated)
        return GateResult("PASS", "canonical exact-head receipt validated", receipt, validated)

    def discover_pr(self, worktree: str, head: str) -> GateResult:
        try:
            repo = self._repo_from_origin(worktree)
            branch = self._run(["git", "branch", "--show-current"], cwd=worktree).strip()
            if not branch:
                return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery requires a named branch")
            owner = repo.split("/", 1)[0]
            head_filter = quote(f"{owner}:{branch}", safe="")
            pulls = json.loads(self._run(self._gh(
                "api", f"repos/{repo}/pulls?state=open&head={head_filter}",
            ), cwd=worktree))
            if not isinstance(pulls, list) or not all(isinstance(pull, dict) for pull in pulls):
                return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery returned an invalid response")
        except (subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"GitHub PR discovery unavailable: {exc}", data={"retryable": True})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"GitHub PR discovery returned invalid evidence: {exc}")
        matches = []
        for pull in pulls:
            pull_head, pull_base = pull.get("head"), pull.get("base")
            if not isinstance(pull_head, dict) or not isinstance(pull_base, dict):
                continue
            if (pull_head.get("sha") == head.lower()
                    and pull_head.get("ref") == branch
                    and pull_base.get("ref") == "main"):
                matches.append(pull)
        if len(matches) == 0:
            return GateResult("BLOCKED_EXTERNAL", f"no open PR for branch={branch} head={head}; publication may still be pending",
                              data={"retryable": True, "branch": branch, "head": head.lower()})
        if len(matches) != 1:
            return GateResult("BLOCKED_EXTERNAL", f"expected one open PR for branch={branch} head={head}; found {len(matches)}")
        number = matches[0].get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR discovery omitted a valid PR number")
        return GateResult("PASS", f"PR #{number}", data={
            "number": number, "repo": repo, "head": head.lower(),
            "base": "main", "state": "OPEN",
        })

    def _repo_from_origin(self, worktree: str) -> str:
        """Derive GitHub identity from this checkout's origin, not ambient gh config."""
        remote = self._run(
            ["git", "remote", "get-url", "origin"], cwd=worktree,
        ).strip()
        if "://" in remote:
            parsed = urlsplit(remote)
            host, path = parsed.hostname, parsed.path
        elif remote.startswith("git@") and ":" in remote:
            host, path = remote.split("@", 1)[1].split(":", 1)
        else:
            raise ValueError("origin is not a supported GitHub remote")
        if host is None or host.lower() != "github.com":
            raise ValueError("origin does not identify github.com")
        parts = path.strip("/").split("/")
        if len(parts) != 2:
            raise ValueError("origin does not identify one GitHub repository")
        owner, name = parts
        if name.endswith(".git"):
            name = name[:-4]
        if (not re.fullmatch(r"[A-Za-z0-9_.-]+", owner)
                or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or owner in {".", ".."} or name in {".", ".."}):
            raise ValueError("origin does not identify one GitHub repository")
        return f"{owner}/{name}"

    def ci(self, worktree: str, head: str, pr_number: int | None = None,
           pr_repo: str | None = None, base_sha: str | None = None) -> GateResult:
        if pr_number is None:
            pr = self.discover_pr(worktree, head)
            if pr.status != "PASS": return pr
            facts = pr.data if isinstance(pr.data, dict) else {}
            pr_number, pr_repo = facts.get("number"), facts.get("repo")
            if (not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number <= 0
                    or not isinstance(pr_repo, str) or not re.fullmatch(
                        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pr_repo)):
                return GateResult("BLOCKED_EXTERNAL", "PR discovery returned an invalid durable identity")
            bound = self._pr_state(worktree, pr_number, pr_repo)
            bound_facts = bound.data or {}
            if (bound.status != "PASS" or bound_facts.get("head") != head.lower()
                    or bound_facts.get("base") != "main" or bound_facts.get("state") != "OPEN"):
                return GateResult("BLOCKED_EXTERNAL", f"discovered PR #{pr_number} is no longer open at exact HEAD {head}")
        else:
            if not pr_repo: return GateResult("BLOCKED_EXTERNAL", "durable PR identity has no repository")
            bound = self._pr_state(worktree, pr_number, pr_repo)
            if bound.status != "PASS": return bound
            facts = bound.data or {}
            if facts.get("head") != head.lower() or facts.get("base") != "main" or facts.get("state") != "OPEN":
                return GateResult("BLOCKED_EXTERNAL", f"durable PR #{pr_number} no longer matches open main PR at {head}")
        try:
            if not base_sha:
                result = self._call(["make", "pr-ready", f"PR={pr_number}", "JSON=1"], cwd=worktree,
                                    env={"GH_REPO": pr_repo, "GH_HOST": "github.com"})
            else:
                trusted = self._trusted_base_checkout(
                    worktree, base_sha,
                    str(Path(worktree).parent / ".cmh-review-evidence" / "pr-ready" / head),
                )
                code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                        "from scripts.devops import pr_ready_check as m; m.ROOT=Path(sys.argv[2]); "
                        "sys.argv=['pr-ready-check','--pr',sys.argv[3],'--json']; raise SystemExit(m.main())")
                result = self._call(
                    ["python3", "-c", code, str(trusted), worktree, str(pr_number)],
                    cwd=str(trusted), env={"GH_REPO": pr_repo, "GH_HOST": "github.com"},
                )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"trusted PR readiness unavailable: {exc}")
        try: data = self._json_document_prefix(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical pr-ready returned no JSON")
        pr_data = data.get("pr")
        findings = data.get("findings")
        if (not isinstance(pr_data, dict) or not isinstance(findings, list)
                or not all(isinstance(finding, dict) for finding in findings)):
            return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready returned malformed PR/check evidence")
        data["pr_number"] = pr_number
        data["pr_repo"] = pr_repo
        observed = str(pr_data.get("head_sha", "")).lower()
        if observed != head.lower(): return GateResult("BLOCKED_EXTERNAL", f"PR HEAD {observed or 'MISSING'} does not equal {head}")
        checks = [finding for finding in findings
                  if str(finding.get("name", "")).startswith("required-check:")]
        if not checks: return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready reported no required checks")
        messages = "\n".join(str(f.get("message", "")) for f in checks)
        if (result.returncode == 0 and data.get("verdict") == "PASS"
                and all(f.get("passed") is True for f in checks)):
            return GateResult("PASS", messages, data=data)
        if "status=queued" in messages or "status=in_progress" in messages or "no run for exact HEAD" in messages:
            return GateResult("PENDING", messages, data=data)
        if data.get("verdict") == "FAIL":
            return GateResult("FAIL", messages or "canonical pr-ready reported FAIL", data=data)
        return GateResult("BLOCKED_EXTERNAL", "canonical pr-ready returned contradictory or invalid check evidence", data=data)

    def merge_ready(self, *, worktree: str, base: str, head: str, mission_id: str,
                    scope_file: str, pr_number: int, pr_repo: str,
                    receipts: dict[str, str], ci_status: str) -> GateResult:
        """Delegate the final merge-readiness decision to the target project."""
        codex_receipt = receipts.get("codex")
        deepseek_receipt = receipts.get("deepseek")
        if not codex_receipt and not deepseek_receipt:
            return GateResult("BLOCKED_EXTERNAL", "canonical merge-readiness requires a durable review receipt")
        pr_state = self._pr_state(worktree, pr_number, pr_repo)
        if pr_state.status != "PASS":
            return pr_state
        body = (pr_state.data or {}).get("body") if isinstance(pr_state.data, dict) else None
        if not isinstance(body, str):
            return GateResult("BLOCKED_EXTERNAL", "canonical merge-readiness requires the PR body")
        evidence = self._private_dir(Path(worktree).parent / ".cmh-merge-evidence" / mission_id / head)
        body_path = evidence / "pr-body.md"
        body_path.write_text(body, encoding="utf-8")
        body_path.chmod(0o600)
        scope = Path(scope_file).resolve()
        # The candidate Makefile is not an authority boundary.  This preflight
        # is deliberately run with a scrubbed environment: even though the
        # project contract describes it as read-only, a changed target must not
        # inherit the controller's credentials before the owner has approved a
        # merge.  The trusted-base merge-readiness command below remains the
        # canonical policy authority.
        local = self._call(
            ["make", "agent-preflight"], cwd=worktree,
            env={"PR_BODY": str(body_path), "MISSION_SCOPE_FILE": str(scope),
                 "BASE_REF": base, "HEAD_REF": head, "JSON": "1", "GH_HOST": "github.com",
                 "HOME": "/nonexistent", "PATH": os.defpath, "LANG": "C.UTF-8"},
            inherit_environment=False,
        )
        if local.returncode != 0:
            return GateResult("BLOCKED_EXTERNAL", local.stderr.strip() or "canonical agent-preflight failed")
        try:
            local_json = self._json_document_prefix(local.stdout)
        except json.JSONDecodeError as exc:
            return GateResult("BLOCKED_EXTERNAL", f"canonical agent-preflight returned invalid JSON: {exc}")
        local_path = evidence / "local-preflight.json"
        local_path.write_text(json.dumps(local_json, sort_keys=True), encoding="utf-8")
        local_path.chmod(0o600)
        trusted = self._trusted_base_checkout(worktree, base, str(evidence))
        code = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
                "from scripts.devops import agent_workflow as m, agent_workflow_preflight as p, pr_ready_check as r; "
                "from scripts.ops import ai_workflow_gate as g; from scripts.ops.helpers import git_change_helpers as h; "
                "p.ROOT=r.ROOT=g.ROOT=Path(sys.argv[2]); h.ROOT_HELPER=Path(sys.argv[2]); "
                "sys.argv=['agent-workflow']+sys.argv[3:]; raise SystemExit(m.main())")
        argv = ["python3", "-c", code, str(trusted), worktree, "merge-ready",
                "--repo-root", worktree, "--base-sha", base, "--head-sha", head,
                "--mission-id", mission_id, "--mission-scope-file", str(scope),
                "--local-preflight-json", str(local_path)]
        if codex_receipt:
            argv += ["--receipt", codex_receipt]
        if deepseek_receipt:
            argv += ["--deepseek-receipt", deepseek_receipt]
        argv += ["--selected-backend", "codex" if codex_receipt else "deepseek",
                "--pr", str(pr_number), "--remote-ci-status", ci_status,
                "--protected-invariants", "PASS", "--forbidden-side-effects", "NO",
                "--required-pr-governance", "PASS", "--json"]
        result = self._call(argv, cwd=str(trusted), env={"GH_HOST": "github.com", "GH_REPO": pr_repo})
        data = self._json_last_text(result.stdout)
        if result.returncode == 0 and data.get("merge_ready") == "YES":
            return GateResult("PASS", "canonical agent-merge-ready passed", data=data)
        return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "canonical agent-merge-ready rejected merge", data=data)

    def _pr_state(self, worktree: str, pr_number: int, pr_repo: str) -> GateResult:
        try:
            raw = json.loads(self._run(self._gh("api", f"repos/{pr_repo}/pulls/{pr_number}"), cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot inspect durable PR identity: {exc}")
        if not isinstance(raw, dict):
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR lookup returned a non-object JSON value")
        head, base = raw.get("head"), raw.get("base")
        number = raw.get("number")
        if (not isinstance(head, dict) or not isinstance(base, dict)
                or not isinstance(number, int) or isinstance(number, bool)
                or number != pr_number):
            return GateResult("BLOCKED_EXTERNAL", "GitHub PR lookup returned malformed or mismatched identity")
        return GateResult("PASS", f"{pr_repo} PR #{pr_number}", data={"repo": pr_repo, "raw": raw,
            "head": str(head.get("sha", "")).lower(),
            "base": str(base.get("ref", "")),
            "state": str(raw.get("state", "")).upper(), "body": raw.get("body", "")})

    def merge(self, worktree: str, head: str, pr_number: int | None = None,
              pr_repo: str | None = None) -> GateResult:
        if pr_number is None or not pr_repo: return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR identity")
        before = self.merge_status(worktree, head, pr_number, pr_repo, allow_open_retry=True)
        if before.status != "NOT_STARTED": return before
        result = self._call(self._gh("pr", "merge", str(pr_number), "--repo", pr_repo,
                             "--squash", "--match-head-commit", head), cwd=worktree)
        if result.returncode != 0: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "merge command failed")
        return self.merge_status(worktree, head, pr_number, pr_repo)

    def merge_status(self, worktree: str, reviewed_head: str, pr_number: int | None = None,
                     pr_repo: str | None = None, allow_open_retry: bool = False) -> GateResult:
        if pr_number is None or not pr_repo:
            return GateResult("BLOCKED_EXTERNAL", "merge claim has no durable PR identity")
        try:
            data = json.loads(self._run(self._gh("api", f"repos/{pr_repo}/pulls/{pr_number}"), cwd=worktree))
        except (KeyError, json.JSONDecodeError, subprocess.SubprocessError, OSError) as exc:
            return GateResult("BLOCKED_EXTERNAL", f"cannot reconcile merge state: {exc}")
        if not isinstance(data, dict):
            return GateResult("BLOCKED_EXTERNAL", "GitHub merge-status lookup returned a non-object JSON value")
        number, head, base = data.get("number"), data.get("head"), data.get("base")
        if (not isinstance(number, int) or isinstance(number, bool) or number != pr_number
                or not isinstance(head, dict) or not isinstance(base, dict)):
            return GateResult("BLOCKED_EXTERNAL", "GitHub merge-status lookup returned malformed or mismatched PR identity")
        if data.get("merged") is True:
            merged_head = str(head.get("sha", "")).lower()
            if merged_head != reviewed_head.lower():
                return GateResult("BLOCKED_EXTERNAL", f"merged PR head {merged_head or 'MISSING'} differs from reviewed head {reviewed_head}")
            if str(base.get("ref", "")) != "main":
                return GateResult("BLOCKED_EXTERNAL", "merged PR base differs from main")
            merge_sha = str(data.get("merge_commit_sha") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
                return GateResult("BLOCKED_EXTERNAL", "merged PR lacks a full merge SHA")
            return GateResult("PASS", f"merged {pr_repo} PR #{pr_number}", data={"pr": pr_number, "merge_sha": merge_sha, "repo": pr_repo})
        queued = data.get("auto_merge") is not None or data.get("merge_queue_entry") is not None
        if (allow_open_retry and data.get("merged") is False and not queued
                and str(data.get("state", "")).upper() == "OPEN"
                and str(base.get("ref", "")) == "main"
                and str(head.get("sha", "")).lower() == reviewed_head.lower()):
            return GateResult("NOT_STARTED", f"PR #{pr_number} is still open at the reviewed HEAD; merge retry is safe", data={"pr": pr_number})
        return GateResult("BLOCKED_EXTERNAL", f"ambiguous merge state for PR #{pr_number}")

    def post_merge(self, worktree: str, merge_sha: str, pr_number: int, pr_repo: str,
                   branch: str, base: str) -> GateResult:
        trusted = self._trusted_base_checkout(worktree, base, str(Path(worktree).parent / ".cmh-review-evidence" / "post-merge" / merge_sha))
        result = self._call(["python3", str(trusted / "scripts/devops/pr_post_merge_check.py"), "--pr", str(pr_number),
                             "--merge-commit", merge_sha, "--branch", branch, "--json"], cwd=worktree,
                            env={"GH_REPO": pr_repo, "GH_HOST": "github.com"})
        try: data = self._json_document_prefix(result.stdout)
        except json.JSONDecodeError: return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if not isinstance(data, dict):
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate check returned no JSON")
        if str(data.get("ci_head_sha", "")).lower() != merge_sha.lower():
            return GateResult("BLOCKED_EXTERNAL", "Production Gate is not bound to exact merge SHA")
        if str(data.get("ci_status")) in {"queued", "in_progress", "requested"}:
            return GateResult("PENDING", json.dumps(data), data=data)
        if result.returncode != 0 and data.get("verdict") == "PASS":
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate exit status contradicts PASS", data=data)
        if result.returncode != 0 and data.get("verdict") != "FAIL":
            return GateResult("BLOCKED_EXTERNAL", result.stderr.strip() or "Production Gate command failed", data=data)
        if data.get("verdict") == "PASS":
            try:
                self._run(["git", "fetch", "origin", "main"], cwd=worktree)
                # Capture the remote-tracking ref once, then derive every
                # related fact from that immutable full SHA.  A concurrent
                # fetch may advance origin/main between commands, but it can
                # no longer produce a mixed commit/tree observation.
                main_sha = self._run(["git", "rev-parse", "origin/main"], cwd=worktree).strip().lower()
                tree_sha = self._run(["git", "rev-parse", f"{main_sha}^{{tree}}"], cwd=worktree).strip().lower()
                reachable = self._call(["git", "merge-base", "--is-ancestor", merge_sha, main_sha], cwd=worktree)
            except (subprocess.SubprocessError, OSError) as exc:
                return GateResult("BLOCKED_EXTERNAL", f"cannot record post-merge main truth: {exc}")
            if reachable.returncode != 0:
                return GateResult("BLOCKED_EXTERNAL", "merged SHA is not reachable from origin/main")
            data.update({"main_sha": main_sha, "tree_sha": tree_sha})
            return GateResult("PASS", "canonical Production Gate passed", data=data)
        if not data.get("ci_status"): return GateResult("BLOCKED_EXTERNAL", "Production Gate omitted CI status", data=data)
        if data.get("verdict") == "FAIL": return GateResult("FAIL", json.dumps(data), data=data)
        return GateResult("BLOCKED_EXTERNAL", "Production Gate returned an invalid verdict", data=data)

    @staticmethod
    def _call(argv, cwd=None, env=None, inherit_environment=True):
        child_env = os.environ.copy() if inherit_environment else {}
        if env: child_env.update(env)
        try:
            child_env["GH_HOST"] = "github.com"
            return subprocess.run(argv, cwd=cwd, env=child_env, text=True, capture_output=True, check=False, timeout=60)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return subprocess.CompletedProcess(argv, 124, stdout, f"command timed out after 60 seconds: {argv[0]}")
        except OSError as exc:
            return subprocess.CompletedProcess(argv, 127, "", f"cannot execute command: {exc}")
    @staticmethod
    def _run(argv, cwd=None):
        env = os.environ.copy()
        env["GH_HOST"] = "github.com"
        return subprocess.check_output(argv, cwd=cwd, env=env, text=True, stderr=subprocess.PIPE, timeout=60)
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

    @staticmethod
    def _json_document_prefix(text: str) -> dict[str, Any]:
        """Read the first JSON document while ignoring canonical human footer text."""
        decoder = json.JSONDecoder()
        value, _ = decoder.raw_decode(text.lstrip())
        if not isinstance(value, dict):
            raise json.JSONDecodeError("expected JSON object", text, 0)
        return value


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
    def ci(self, worktree, head, pr_number=None, pr_repo=None):
        value=self.ci_results[min(self.ci_index,len(self.ci_results)-1)]; self.ci_index+=1; return GateResult(value, f"fixture CI {head}", data={"pr_number": pr_number or 1, "pr_repo": pr_repo or "fixture/repo"})
    def merge_ready(self, **kwargs): return GateResult("PASS", "fixture merge readiness")
    def merge(self, worktree, head, pr_number=None, pr_repo=None):
        value = self.merge_results[min(self.merge_index, len(self.merge_results)-1)]
        self.merge_index += 1
        if value == "PASS":
            self.merged_heads.add(head)
            return GateResult(value, f"fixture merge {head}", data={
                "pr": pr_number or 1, "repo": pr_repo or "fixture/repo", "merge_sha": "c" * 40,
            })
        return GateResult(value, f"fixture merge {head}")
    def merge_status(self, worktree, reviewed_head, pr_number=None, pr_repo=None):
        if reviewed_head in self.merged_heads:
            return GateResult("PASS", f"fixture merge status {reviewed_head}", data={
                "pr": pr_number or 1, "repo": pr_repo or "fixture/repo", "merge_sha": "c" * 40,
            })
        return GateResult("NOT_STARTED", f"fixture merge status {reviewed_head}")
    def post_merge(self, *args):
        value=self.post_results[min(self.post_index,len(self.post_results)-1)]; self.post_index+=1
        return GateResult(value, "fixture post merge", data={"main_sha":"d"*40,"tree_sha":"e"*40})
