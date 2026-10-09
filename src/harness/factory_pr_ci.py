"""FootballPrediction PR evidence over existing GitHub Actions, with no merge API."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .factory_preflight import _read_git
from .sandbox import SAFE_PATH


WORKFLOW = "production-gate.yml"
CHECK_NAMES = {"production-gate": "Environment / Proxy / Static / Unit Gate",
               "docker-build": "Docker Build Validation"}
SHA = re.compile(r"[0-9a-f]{40}")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_policy(policy):
    if (not isinstance(policy, dict) or set(policy) != {"repository", "workflow", "base_branch"}
            or not isinstance(policy["repository"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", policy["repository"])
            or policy["workflow"] != WORKFLOW or policy["base_branch"] != "main"):
        raise ValueError("project PR CI requires an exact repository and existing Production Gate on main")


def expected_jobs(text):
    # FootballPrediction currently has two literal jobs, no matrix or job-level
    # conditions. Unknown/matrix/conditional revisions need explicit adaptation;
    # guessing a successful subset is never permitted.
    class UniqueLoader(yaml.SafeLoader):
        pass
    def unique(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if key in result:
                raise ValueError("duplicate workflow field")
            result[key] = loader.construct_object(value_node)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique)
    data = yaml.load(text, Loader=UniqueLoader)
    events = data.get("on", data.get(True))
    if not isinstance(events, dict) or "pull_request" not in events or "pull_request_target" in events:
        raise ValueError("workflow does not have the trusted PR event contract")
    jobs = data.get("jobs", {})
    if set(jobs) != set(CHECK_NAMES):
        raise ValueError("unknown Production Gate job set")
    for key, name in CHECK_NAMES.items():
        job = jobs[key]
        if job.get("name") != name or "if" in job or "strategy" in job or "uses" in job:
            raise ValueError("conditional, matrix or reusable jobs require separate trusted adaptation")
        checkout = [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith("actions/checkout@")]
        if (len(checkout) != 1 or checkout[0].get("uses") != "actions/checkout@v4"
                or job["steps"][0] != checkout[0] or checkout[0].get("name") != "Checkout code"
                or set(checkout[0].get("with", {})) - {"fetch-depth"}
                or checkout[0].get("with", {}).get("ref") is not None or "if" in checkout[0]
                or checkout[0].get("continue-on-error") or job.get("continue-on-error")):
            raise ValueError("unknown tested revision or checkout contract")
    return CHECK_NAMES.copy()


def workflow_at(cwd, revision):
    return _read_git(cwd, "show", revision + ":.github/workflows/" + WORKFLOW)


def branch_for(spec, target):
    return f"factory/{spec['mission_id']}-{target['head']}"


def repository_identity(spec, policy):
    remote = _read_git(spec["repository"], "config", "--local", "--get", "remote.origin.url").strip()
    if remote.startswith("git@github.com:"):
        name = remote.removeprefix("git@github.com:")
    else:
        parsed = urlsplit(remote)
        if (parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username
                or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443)):
            raise ValueError("project origin does not identify an approved GitHub repository")
        name = parsed.path.removeprefix("/")
    name = name.removesuffix(".git")
    if name != policy["repository"]:
        raise ValueError("configured PR repository differs from the mission's source origin")
    return name


def validate_approval(approval, policy, spec, target):
    expected = {"mission_id": spec["mission_id"], "repository": policy["repository"],
                "branch": branch_for(spec, target), "base": target["base"],
                "head": target["head"], "tree": target["tree"], "policy_sha256": digest(policy)}
    if not isinstance(approval, dict) or approval.get("identity") != expected:
        raise ValueError("separate exact-candidate PR publication approval is missing or stale")
    expiry = datetime.fromisoformat(approval["expires_at"])
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise ValueError("PR publication approval expired")
    if not approval.get("approval_id") or not isinstance(approval.get("body"), str) or not approval["body"].strip():
        raise ValueError("publication approval needs a concrete approved PR body")
    if hashlib.sha256(approval["body"].encode()).hexdigest() != approval.get("body_sha256"):
        raise ValueError("approved PR body changed")
    return expected


class GitHub:
    """Controller-only gh transport; candidates never receive its credentials."""
    fixture = False

    def __init__(self, cwd, transcript, timeout, cancelled=lambda: False):
        self.cwd, self.transcript = cwd, Path(transcript)
        self.deadline = time.monotonic() + timeout
        self.cancelled = cancelled

    def command(self, argv, input=None):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.cancelled():
            raise TimeoutError("PR CI deadline exhausted")
        # Use gh's Controller authentication store. No candidate git config,
        # inherited GH_TOKEN, alternate host, proxy or shell is accepted.
        env = {"PATH": SAFE_PATH, "HOME": str(Path.home()), "LANG": "C.UTF-8", "GH_HOST": "github.com",
               "GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1"}
        result = subprocess.run(argv, cwd=self.cwd, env=env, input=input, text=True,
                                capture_output=True, timeout=min(60, remaining))
        with self.transcript.open("a") as stream:
            stream.write(json.dumps({"argv": argv, "exit_code": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if result.returncode:
            raise RuntimeError("GitHub transport failed; no success inferred")
        return result.stdout

    def get(self, path, text=False):
        value = self.command(["/usr/bin/gh", "api", "--hostname", "github.com", path])
        return value if text else json.loads(value)

    def post(self, path, value):
        return json.loads(self.command(["/usr/bin/gh", "api", "--hostname", "github.com", "--method", "POST",
                                        path, "--input", "-"], json.dumps(value)))

    def push(self, repository, head, branch):
        # HTTPS credentials are invoked by git in the Controller only. Neither
        # destination nor hooks/helper come from candidate repository config.
        self.command(["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                      "-c", "core.fsmonitor=false", "-c", "credential.helper=",
                      "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                      "push", "--", f"https://github.com/{repository}.git", f"{head}:refs/heads/{branch}"])

    def protection(self, repository):
        owner, name = repository.split("/")
        query = "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){nameWithOwner ref(qualifiedName:\"refs/heads/main\"){name branchProtectionRule{requiresStatusChecks requiredStatusChecks{context app{databaseId}}}}}}"
        response = self.post("graphql", {"query": query, "variables": {"owner": owner, "name": name}})
        if response.get("errors"):
            raise ValueError("classic branch protection lookup failed")
        repo = response["data"]["repository"]
        if repo.get("nameWithOwner") != repository or repo.get("ref", {}).get("name") != "main":
            raise ValueError("classic branch protection repository/ref identity missing")
        return repo["ref"]["branchProtectionRule"]


def pages(api, path, key=None):
    result = []
    for page in range(1, 101):
        value = api.get(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
        items = value[key] if key else value
        if not isinstance(items, list):
            raise ValueError("GitHub pagination response incomplete")
        result.extend(items)
        if len(items) < 100:
            return result
    raise ValueError("GitHub evidence pagination bound exceeded")


def required_checks(rules, jobs, protection=None):
    required = {}
    if protection is not None:
        if not isinstance(protection, dict) or type(protection.get("requiresStatusChecks")) is not bool:
            raise ValueError("classic branch protection is unknown")
        if protection["requiresStatusChecks"]:
            rules = [*rules, {"type": "required_status_checks", "parameters": {"required_status_checks": [
                {"context": c["context"], "integration_id": (c.get("app") or {}).get("databaseId")}
                for c in protection["requiredStatusChecks"]]}}]
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            for check in rule.get("parameters", {}).get("required_status_checks", []):
                name, app = check.get("context"), check.get("integration_id")
                if name not in jobs.values() or app not in (None, 15368):
                    raise ValueError("unknown required check or app; cannot accept partial CI")
                if name in required and required[name] != app:
                    raise ValueError("conflicting required check app identities")
                required[name] = app
    if not required or set(jobs.values()) - set(required):
        raise ValueError("active branch rules do not establish both project required checks")
    return required


def check_pr(pr, number, policy, spec, target, require_merge=True):
    repo, branch = policy["repository"], branch_for(spec, target)
    if (type(pr.get("number")) is not int or pr["number"] != number or pr.get("state") != "open"
            or pr.get("draft") is not False or pr.get("merged") is not False
            or pr.get("head", {}).get("sha") != target["head"] or pr["head"].get("ref") != branch
            or pr["head"].get("repo", {}).get("full_name") != repo
            or pr.get("base", {}).get("sha") != target["base"] or pr["base"].get("ref") != "main"
            or pr["base"].get("repo", {}).get("full_name") != repo
            or require_merge and (not SHA.fullmatch(pr.get("merge_commit_sha") or "") or pr.get("mergeable") is not True)):
        raise ValueError("PR repository/branch/base/head/merge/draft identity is not established")
    scope_reference = f"Mission scope contract: `{target['mission_scope_file']}`"
    if scope_reference not in pr.get("body", ""):
        raise ValueError("PR body does not name frozen project mission scope")


def checkout_sha(log):
    lines = [re.sub(r"^\d{4}-\d\d-\d\dT\S+\s+", "", line) for line in log.splitlines()]
    starts = [i for i, line in enumerate(lines) if line == "##[group]Run actions/checkout@v4"]
    if len(starts) != 1:
        raise ValueError("checkout log provenance missing or ambiguous")
    start = starts[0]
    stop = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("##[group]Run ")), len(lines))
    # Only the checkout action's own final git log output counts. Candidate
    # program output in later steps cannot supply the tested SHA.
    found = [lines[i + 1].strip() for i in range(start, stop - 1)
             if re.fullmatch(r"\[command\].*/git log -1 --format=(?:%H|'%H'|\"%H\")", lines[i])
             and SHA.fullmatch(lines[i + 1].strip())]
    if len(found) != 1:
        raise ValueError("actual checkout SHA is not proven by the checkout step")
    return found[0]


def validate_bundle(bundle, policy, spec, target, workflow_text):
    validate_policy(policy)
    jobs = expected_jobs(workflow_text)
    number = bundle["pr"]["number"]
    check_pr(bundle["pr"], number, policy, spec, target)
    check_pr(bundle["pr_after"], number, policy, spec, target)
    merge = bundle["pr"]["merge_commit_sha"]
    if bundle["pr_after"]["merge_commit_sha"] != merge:
        raise ValueError("PR merge identity changed during observation")
    body_sha = hashlib.sha256(bundle["pr"]["body"].encode()).hexdigest()
    if hashlib.sha256(bundle["pr_after"]["body"].encode()).hexdigest() != body_sha:
        raise ValueError("PR governance body changed during observation")
    if bundle["base_branch"]["commit"]["sha"] != target["base"]:
        raise ValueError("remote base moved from approved baseline")
    commit = bundle["merge_commit"]
    if commit.get("sha") != merge or [p["sha"] for p in commit.get("parents", [])] != [target["base"], target["head"]]:
        raise ValueError("synthetic merge parents differ from approved base/head")
    if bundle["workflow_text"] != workflow_text:
        raise ValueError("executed workflow revision differs from trusted base workflow")
    # GitHub contents returned for the synthetic merge revision; its blob
    # identity and exact bytes must agree with the trusted source.
    blob = hashlib.sha1(b"blob " + str(len(workflow_text.encode())).encode() + b"\0" + workflow_text.encode()).hexdigest()
    if bundle["workflow_blob"] != blob:
        raise ValueError("workflow blob identity mismatch")
    required = required_checks(bundle["rules"], jobs, bundle["protection"])
    if bundle["rules_after"] != bundle["rules"] or bundle["protection_after"] != bundle["protection"]:
        raise ValueError("required-check rules changed during observation")
    workflow = bundle["workflow"]
    run = bundle["run"]
    if (workflow.get("path") != ".github/workflows/" + WORKFLOW or workflow.get("state") != "active"
            or type(workflow.get("id")) is not int or workflow["id"] <= 0 or run.get("workflow_id") != workflow["id"]
            or run.get("repository", {}).get("full_name") != policy["repository"]
            or run.get("head_repository", {}).get("full_name") != policy["repository"]
            or run.get("head_sha") != target["head"] or run.get("head_branch") != branch_for(spec, target)
            or run.get("path") != workflow["path"] or run.get("event") != "pull_request"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or type(run.get("id")) is not int or run["id"] <= 0
            or type(run.get("run_attempt")) is not int or run["run_attempt"] <= 0
            or type(run.get("check_suite_id")) is not int or run["check_suite_id"] <= 0
            or run.get("html_url") != f"https://github.com/{policy['repository']}/actions/runs/{run['id']}"):
        raise ValueError("workflow run identity/version/event/status mismatch")
    associations = run.get("pull_requests", [])
    if len(associations) != 1 or associations[0].get("number") != number:
        raise ValueError("workflow run belongs to a different or unknown PR")
    for side, sha in (("head", target["head"]), ("base", target["base"])):
        if associations[0].get(side, {}).get("sha") != sha:
            raise ValueError("run PR base/head association mismatch")
    if bundle["run_after"] != run:
        raise ValueError("workflow run attempt changed during observation")
    if run["id"] != bundle["latest_run_id"] or run["run_attempt"] != bundle["latest_run_attempt"]:
        raise ValueError("old workflow run or attempt cannot authorize this candidate")
    if datetime.fromisoformat(run["created_at"].replace("Z", "+00:00")) < datetime.fromisoformat(bundle["pr"]["created_at"].replace("Z", "+00:00")):
        raise ValueError("workflow run predates this PR")
    actual_jobs = bundle["jobs"]
    if len(actual_jobs) != len(jobs) or {j.get("name") for j in actual_jobs} != set(jobs.values()):
        raise ValueError("required job/matrix missing, duplicated or unexpected")
    for job in actual_jobs:
        if (job.get("run_id") != run["id"] or job.get("run_attempt") != run["run_attempt"]
                or job.get("head_sha") != target["head"] or job.get("status") != "completed"
                or job.get("conclusion") != "success" or not job.get("completed_at")
                or type(job.get("id")) is not int or job["id"] <= 0
                or job.get("html_url") != f"https://github.com/{policy['repository']}/actions/runs/{run['id']}/job/{job['id']}"
                or job.get("check_run_url") != f"https://api.github.com/repos/{policy['repository']}/check-runs/{job['id']}"):
            raise ValueError("required job failed, skipped, unfinished or from another attempt")
        checkout_steps = [s for s in job.get("steps", []) if s.get("name") == "Checkout code"]
        if len(checkout_steps) != 1 or checkout_steps[0].get("conclusion") != "success" or checkout_steps[0].get("status") != "completed":
            raise ValueError("checkout step incomplete")
        tested = checkout_sha(bundle["checkout_logs"][str(job["id"])])
        if tested != merge:
            raise ValueError("actual tested synthetic merge SHA mismatch")
        checks = [c for c in bundle["checks"] if c.get("name") == job["name"]
                  and c.get("check_suite", {}).get("id") == run.get("check_suite_id")]
        if (len(checks) != 1 or checks[0].get("head_sha") != target["head"]
                or checks[0].get("id") != job["id"]
                or checks[0].get("status") != "completed" or checks[0].get("conclusion") != "success"
                or checks[0].get("app", {}).get("id") != 15368
                or checks[0].get("details_url") != job.get("html_url")
                or job.get("check_run_url") != checks[0].get("url")):
            raise ValueError("required check is not the matching GitHub Actions job")
    return {"pr_number": number, "pr_repo": policy["repository"], "pr_base_sha": target["base"], "ci_status": "PASS",
            "pr_head_sha": target["head"], "synthetic_merge_sha": merge, "tested_revision": "PR_SYNTHETIC_MERGE",
            "workflow_id": workflow["id"], "workflow_revision": merge, "workflow_blob": blob,
            "run_id": run["id"], "run_attempt": run["run_attempt"], "required_checks": sorted(required),
            "pr_body_sha256": body_sha}


def latest_run(api, root, workflow_id, number, target):
    runs = pages(api, root + f"/actions/workflows/{workflow_id}/runs?event=pull_request&head_sha={target['head']}", "workflow_runs")
    matches = [r for r in runs if r.get("head_sha") == target["head"]
               and any(p.get("number") == number for p in r.get("pull_requests", []))]
    if not matches:
        return None
    return max(matches, key=lambda r: (r["id"], r["run_attempt"]))


def collect(api, policy, spec, target, number):
    import base64
    root = "repos/" + policy["repository"]
    pr = api.get(root + f"/pulls/{number}")
    check_pr(pr, number, policy, spec, target, require_merge=False)
    if pr.get("mergeable") is None:
        return None
    check_pr(pr, number, policy, spec, target)
    workflow = api.get(root + "/actions/workflows/" + WORKFLOW)
    latest = latest_run(api, root, workflow["id"], number, target)
    if latest is None or latest.get("status") != "completed":
        return None
    run = api.get(root + f"/actions/runs/{latest['id']}")
    if run.get("status") != "completed":
        return None
    revision = pr["merge_commit_sha"]
    source = api.get(root + f"/contents/.github/workflows/{WORKFLOW}?ref={revision}")
    if source.get("encoding") != "base64" or source.get("type") != "file":
        raise ValueError("workflow revision source missing")
    jobs = pages(api, root + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs")
    bundle = {"pr": pr, "workflow": workflow, "run": run,
              "latest_run_id": latest["id"], "latest_run_attempt": latest["run_attempt"],
              "base_branch": api.get(root + "/branches/main"), "merge_commit": api.get(root + "/commits/" + revision),
              "workflow_text": base64.b64decode(source["content"]).decode(), "workflow_blob": source["sha"],
              "rules": pages(api, root + "/rules/branches/main"), "jobs": jobs,
              "protection": api.protection(policy["repository"]),
              "checks": pages(api, root + f"/commits/{target['head']}/check-runs?filter=latest", "check_runs"),
              "checkout_logs": {str(j["id"]): api.get(root + f"/actions/jobs/{j['id']}/logs", text=True) for j in jobs}}
    bundle["pr_after"] = api.get(root + f"/pulls/{number}")
    bundle["rules_after"] = pages(api, root + "/rules/branches/main")
    bundle["protection_after"] = api.protection(policy["repository"])
    bundle["run_after"] = api.get(root + f"/actions/runs/{run['id']}")
    current = latest_run(api, root, workflow["id"], number, target)
    if current is None or (current["id"], current["run_attempt"]) != (run["id"], run["run_attempt"]):
        raise ValueError("a newer workflow run/attempt exists")
    return bundle


def validate_result(result, policy, spec, cwd, target, simulation, api=None):
    repository_identity(spec, policy)
    if (result.get("target") != target or result.get("mission_id") != spec["mission_id"]
            or result.get("policy_sha256") != digest(policy) or result.get("fixture") is not simulation
            or result.get("MERGE_PERFORMED") is not False or result.get("status") != "PASS"):
        raise ValueError("PR CI evidence is unknown or bound to another task")
    source = workflow_at(cwd, target["base"])
    if workflow_at(cwd, target["head"]) != source:
        raise ValueError("candidate modified the trusted workflow")
    context = validate_bundle(result["bundle"], policy, spec, target, source)
    if result.get("context") != context or result.get("approved_body_sha256") != context["pr_body_sha256"]:
        raise ValueError("CI verdict contradicts underlying evidence")
    if api is not None:
        current = collect(api, policy, spec, target, context["pr_number"])
        if current is None or validate_bundle(current, policy, spec, target, source) != context:
            raise ValueError("cached CI evidence is stale or current CI is incomplete")
    return context


def run(policy, spec, cwd, target, approval, transcript, timeout, api=None, cancelled=lambda: False):
    validate_policy(policy)
    repository_identity(spec, policy)
    validate_approval(approval, policy, spec, target)
    source = workflow_at(cwd, target["base"])
    expected_jobs(source)
    if workflow_at(cwd, target["head"]) != source:
        raise ValueError("candidate workflow differs from trusted base")
    api = api or GitHub(cwd, transcript, timeout, cancelled)
    deadline = time.monotonic() + timeout
    root = "repos/" + policy["repository"]
    branch = branch_for(spec, target)
    if api.get(root + "/branches/main")["commit"]["sha"] != target["base"]:
        raise ValueError("remote base moved; do not publish")
    prs = pages(api, root + f"/pulls?state=open&base=main&head={policy['repository'].split('/')[0]}:{branch}")
    if len(prs) > 1:
        raise ValueError("ambiguous candidate PR")
    if prs:
        number = prs[0]["number"]
        existing = api.get(root + f"/pulls/{number}")
        check_pr(existing, number, policy, spec, target, require_merge=False)
        if existing.get("body") != approval["body"]:
            raise ValueError("existing PR body differs from concrete publication approval")
    else:
        # Authorization was checked before either write. Never change draft
        # state, close/reopen a PR, retry an ambiguous write or force-push.
        api.push(policy["repository"], target["head"], branch)
        created = api.post(root + "/pulls", {"title": f"Factory: {spec['mission_id']}", "head": branch,
                                            "base": "main", "body": approval["body"], "draft": False})
        number = created["number"]
    while time.monotonic() < deadline:
        if cancelled():
            raise InterruptedError("PR CI observation cancelled")
        bundle = collect(api, policy, spec, target, number)
        if bundle is not None:
            context = validate_bundle(bundle, policy, spec, target, source)
            if context["pr_body_sha256"] != approval["body_sha256"]:
                raise ValueError("PR governance body differs from publication approval")
            result = {"status": "PASS", "target": target, "mission_id": spec["mission_id"], "fixture": api.fixture,
                      "policy_sha256": digest(policy), "approval_id": approval["approval_id"], "bundle": bundle,
                      "approved_body_sha256": approval["body_sha256"],
                      "context": context, "MERGE_PERFORMED": False}
            with Path(transcript).open("a") as stream:
                stream.write(json.dumps(result) + "\n")
            return result
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise TimeoutError("PR CI missing/unfinished; UNKNOWN is never PASS")
