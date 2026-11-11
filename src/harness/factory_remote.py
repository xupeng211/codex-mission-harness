"""Controller PR publication and read-only reconciliation; no merge/deploy API.

Writes are attempted once by Factory.operation. Recovery only observes GitHub.
This module never interprets a candidate script as publication/CI authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .adapters import FootballPredictionAdapter
from .factory_project import FootballPredictionContract, LANES, verify_target, review_lanes
from .sandbox import SAFE_PATH


def validate_policy(value):
    if (not isinstance(value, dict) or set(value) != {"repository", "base_branch"}
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", str(value.get("repository", "")))
            or any(p in {".", ".."} for p in value["repository"].split("/"))
            or value.get("base_branch") != "main"):
        raise ValueError("project delivery requires an exact GitHub repository and main base")
    return value


def project_branch(spec):
    """One dedicated identity for local preparation, publication and resume."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", spec["mission_id"]):
        raise ValueError("invalid publication mission")
    if not re.fullmatch(r"[0-9a-f]{40}", spec["base"]):
        raise ValueError("invalid publication base")
    return f"factory/{spec['mission_id']}-{spec['base'][:12]}"


def identity(policy, spec, target):
    validate_policy(policy)
    branch = project_branch(spec)
    if spec["base"] != target["base"]:
        raise ValueError("publication base mismatch")
    frozen = {"repository": policy["repository"], "base": target["base"], "mission": spec["mission_id"],
              "scope_sha256": target["mission_scope_sha256"]}
    marker = "<!-- cmh-publication " + hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest() + " -->"
    return branch, marker


def render_body(policy, spec, target, reviews, validations):
    _, marker = identity(policy, spec, target)
    template = spec.get("pr_body_template")
    if (not isinstance(template, str) or not template.strip() or len(template.encode()) > 60000
            or "cmh-publication" in template or "cmh-candidate" in template):
        raise ValueError("Controller-approved PR body template is required")
    primary = next(r for r in reviews if r["lane"] == "reviewer")
    timestamp = primary["canonical_receipt_data"]["review_completed_at"]
    body = template.replace("{{candidate_head}}", target["head"]).replace("{{review_timestamp}}", timestamp)
    if "{{" in body:
        raise ValueError("unsupported PR template placeholder")
    evidence = [{k: v[k] for k in ("profile", "exit_code", "image_id", "evidence_key") if k in v}
                for v in validations]
    return (body.rstrip() + "\n\n## Harness validation evidence\n\n```json\n" +
            json.dumps(evidence, ensure_ascii=False, sort_keys=True) + "\n```\n\n" + marker +
            "\n<!-- cmh-candidate " + target["head"] + " -->\n")


class Remote:
    def __init__(self, cwd, transcript, timeout, adapter=None, *, deadline=None):
        self.cwd, self.transcript = str(cwd), Path(transcript)
        self.deadline = time.monotonic() + timeout
        if deadline is not None:
            self.deadline = min(self.deadline, deadline)
        self.adapter = adapter or FootballPredictionAdapter()
        self.env = self.adapter._trusted_subprocess_environment(env={"LANG": "C.UTF-8"})
        self.env["GIT_SSH_COMMAND"] = "/usr/bin/ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15"

    def command(self, argv, *, data=None, cwd=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("PR/CI deadline exhausted")
        result = subprocess.run(argv, cwd=cwd or self.cwd, env=self.env, input=data, text=True,
                                capture_output=True, timeout=min(60, remaining))
        with self.transcript.open("a") as log:
            # No credentials, raw API bodies, or complete diffs in logs.
            log.write(json.dumps({"argv": argv, "exit_code": result.returncode,
                "stdout_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}) + "\n")
        if result.returncode:
            raise RuntimeError("trusted remote command failed; mutation outcome may be UNKNOWN")
        return result.stdout

    def api(self, endpoint, method="GET", data=None):
        argv = ["/usr/bin/gh", "api", "--hostname", "github.com", "--method", method, endpoint]
        if data is not None:
            argv += ["--input", "-"]
        return json.loads(self.command(argv, data=json.dumps(data) if data is not None else None))

    def main_head(self, policy, target):
        ref = self.api(f"repos/{policy['repository']}/git/ref/heads/main")
        if ref.get("object", {}).get("sha") != target["base"]:
            raise ValueError("remote main changed; approved base/policy is stale")

    def pulls(self, policy, branch):
        repo = policy["repository"]
        pulls = self.api(f"repos/{repo}/pulls?state=all&head={repo.split('/')[0]}:{branch}&base=main&per_page=100")
        if not isinstance(pulls, list) or len(pulls) >= 100 or len(pulls) > 1:
            raise ValueError("dedicated branch PR discovery is ambiguous")
        return pulls

    def check_pull(self, raw, policy, branch, target, marker, *, exact_body=None, expected_head=None):
        repo, head, base = policy["repository"], raw.get("head", {}), raw.get("base", {})
        if (type(raw.get("number")) is not int or raw["number"] <= 0 or raw.get("state") != "open"
                or head.get("repo", {}).get("full_name") != repo or base.get("repo", {}).get("full_name") != repo
                or head.get("ref") != branch or base.get("ref") != "main" or base.get("sha") != target["base"]
                or head.get("sha") != (expected_head or target["head"])
                or not isinstance(raw.get("body"), str) or raw["body"].count(marker) != 1):
            raise ValueError("PR repository/branch/base/head/scope ownership mismatch")
        if exact_body is not None and raw["body"] != exact_body:
            raise ValueError("PR body differs from exact Controller publication")

    def check_local_branch(self, branch):
        current = self.command(["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                                "-c", "core.fsmonitor=false", "symbolic-ref", "--quiet", "--short", "HEAD"]).strip()
        if current != branch:
            raise ValueError("local candidate branch differs from exact publication identity")

    def observe(self, policy, spec, target, body):
        branch, marker = identity(policy, spec, target)
        self.check_local_branch(branch)
        self.main_head(policy, target)
        pulls = self.pulls(policy, branch)
        if len(pulls) != 1:
            raise ValueError("exact publication is not observable; UNKNOWN write was not retried")
        raw = self.api(f"repos/{policy['repository']}/pulls/{pulls[0]['number']}")
        self.check_pull(raw, policy, branch, target, marker, exact_body=body)
        remote_head = self.api(f"repos/{policy['repository']}/git/ref/heads/{branch}")
        if remote_head.get("object", {}).get("sha") != target["head"]:
            raise ValueError("dedicated branch differs from current candidate")
        return {"status": "PASS", "target": target, "repository": policy["repository"], "branch": branch,
                "pr_number": raw["number"], "pr_repo": policy["repository"], "pr_base_sha": target["base"],
                "body_sha256": hashlib.sha256(body.encode()).hexdigest(), "fixture": False, "MERGE_PERFORMED": False}

    def publish(self, policy, spec, target, body, previous_head=None):
        objective = spec.get("objective")
        title = ""
        if isinstance(objective, str):
            title = next((line.strip() for line in objective.splitlines() if line.strip()), "")[:200]
        if not title:
            raise ValueError("publication requires a nonempty PR title")
        branch, marker = identity(policy, spec, target)
        self.check_local_branch(branch)
        self.main_head(policy, target)
        pulls = self.pulls(policy, branch)
        if pulls:
            raw = self.api(f"repos/{policy['repository']}/pulls/{pulls[0]['number']}")
            # A proven previous Controller publication is required to update.
            self.check_pull(raw, policy, branch, target, marker, expected_head=previous_head or target["head"])
            if previous_head is None:
                return self.observe(policy, spec, target, body)
        # The empty result is a successful Git query, not a swallowed 404/auth error.
        destination = f"https://github.com/{policy['repository']}.git"
        remote = self.command(["/usr/bin/git", "ls-remote", "--heads", destination, "refs/heads/" + branch]).strip()
        expected = previous_head if pulls else None
        if remote != (f"{expected}\trefs/heads/{branch}" if expected else ""):
            raise ValueError("dedicated branch precondition failed; no unrelated branch was overwritten")
        # Publish from fresh Controller Git metadata, never candidate config/hooks.
        with tempfile.TemporaryDirectory(prefix="cmh-publish-", dir=self.transcript.parent) as temporary:
            self.command(["/usr/bin/git", "init", "--bare", temporary])
            self.command(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "fetch", "--no-tags", "--no-recurse-submodules",
                          "--", self.cwd, target["head"]], cwd=temporary)
            self.command(["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
                          "-c", "credential.helper=!/usr/bin/gh auth git-credential", "push", "--", destination,
                          target["head"] + ":refs/heads/" + branch], cwd=temporary)
        payload = {"title": title, "body": body}
        if pulls:
            self.api(f"repos/{policy['repository']}/pulls/{pulls[0]['number']}", "PATCH", payload)
        else:
            self.api(f"repos/{policy['repository']}/pulls", "POST", {**payload, "head": branch, "base": "main"})
        return self.observe(policy, spec, target, body)

    def ci(self, policy, spec, target, body, *, wait):
        while True:
            publication = self.observe(policy, spec, target, body)
            gate = self.adapter.ci(self.cwd, target["head"], pr_number=publication["pr_number"],
                pr_repo=publication["pr_repo"], base_sha=target["base"], pr_base_sha=target["base"])
            result = {**publication, "status": gate.status, "reason": gate.evidence, "ci_data": gate.data}
            if gate.status != "PENDING" or not wait:
                return result
            time.sleep(min(2, max(0, self.deadline - time.monotonic())))
            if time.monotonic() >= self.deadline:
                # The last observation was PENDING. Do not start another remote
                # observation after the deadline and lose this confirmed wait.
                return {**result, "status": "TIMEOUT", "reason": "exact PR checks missing or unfinished at deadline"}


def run(action, policy, spec, cwd, target, body, transcript, timeout, reviews=None, previous_head=None, deadline=None):
    remote = Remote(cwd, transcript, timeout, deadline=deadline)
    # No project executable is run before canonical policy/body admission.
    contract = FootballPredictionContract(remote.adapter)
    verify_target(spec, Path(cwd), target)
    contract.validate_pr_body(spec, Path(cwd), target, body)
    if action in {"publish", "verify"}:
        from .factory_project import validate_review_stop
        if {r["lane"] for r in reviews or []} != set(review_lanes(target)):
            raise ValueError("publication/final gate requires selected original review lifecycles")
        for review in reviews:
            validate_review_stop(spec, Path(cwd), target, review["lane"], review["canonical_execution"])
    if action == "publish":
        return remote.publish(policy, spec, target, body, previous_head)
    if action == "reconcile":
        return remote.observe(policy, spec, target, body)
    if action in {"ci", "verify"}:
        result = remote.ci(policy, spec, target, body, wait=action == "ci")
        if action == "ci" or result["status"] != "PASS":
            return result
        receipts = {LANES[r["lane"]]: r["canonical_receipt"] for r in reviews or []}
        gate = contract.final_gate(spec, Path(cwd), target, receipts, context={
            "pr_number": result["pr_number"], "pr_repo": result["pr_repo"], "pr_base_sha": result["pr_base_sha"],
            "ci_status": "PASS"}, executions={r["lane"]: r["canonical_execution"] for r in reviews})
        # Recheck identity/checks after the local final gate as well.
        after = remote.ci(policy, spec, target, body, wait=False)
        if after["status"] != "PASS":
            return after
        return {**result, "status": gate.status, "reason": gate.evidence, "final_gate_data": gate.data}
    raise ValueError("unsupported project remote action")


if __name__ == "__main__":
    print(json.dumps(run(**json.load(sys.stdin))))
