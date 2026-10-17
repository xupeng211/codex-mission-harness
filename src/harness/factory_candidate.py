"""Explicit local stopping boundary for the existing Factory, never a receipt.

Resource authority limits dispatches/tokens/time, not physical provider billing.
The immutable task must separately acknowledge that monetary limit is unproven.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path


LOCAL_READY = "LOCAL_CANDIDATE_READY"
LOCAL_MODE = "local_candidate"
LOCAL_STAGES = {"implement", "rework", "checks", "ci"}
BILLING = "USER_APPROVED_USAGE_WITH_UNPROVEN_MONETARY_CAP"


def requested(spec):
    return spec.get("delivery_mode") == LOCAL_MODE


def usage_increment(snapshot, previous):
    """Validate cumulative thread usage and return a nonnegative operation delta."""
    from .factory_budget import tokens
    if not isinstance(snapshot, dict) or tokens(snapshot) is None:
        return None
    fields = snapshot.get("total", snapshot)
    total = tokens(snapshot)
    if previous is None:
        delta = dict(fields)
        if "totalTokens" not in delta and "total_tokens" not in delta:
            delta["total"] = total
    else:
        if not isinstance(previous, dict) or set(fields) != set(previous):
            return None
        delta = {}
        for key, value in fields.items():
            if type(value) is not int or type(previous[key]) is not int or value < previous[key]:
                return None
            delta[key] = value - previous[key]
        if "totalTokens" in delta and delta["totalTokens"] != delta.get("inputTokens", 0) + delta.get("outputTokens", 0):
            return None
        if "total_tokens" in delta and delta["total_tokens"] != delta.get("input_tokens", 0) + delta.get("output_tokens", 0):
            return None
        if "totalTokens" not in delta and "total_tokens" not in delta:
            delta["total"] = sum(delta.values())
    return delta, dict(fields)


def validate_policy(config):
    policy = config.get("local_acceptance")
    if policy is None:
        return
    if (not isinstance(policy, dict) or set(policy) != {"profile", "test_paths"}
            or policy["profile"] != "targeted" or not config.get("trusted_validation")
            or config.get("project_contract") != "footballprediction"
            or config["checks"] != [["make", "verify-targeted"]]
            or not isinstance(policy["test_paths"], list) or not policy["test_paths"]
            or any(not re.fullmatch(r"tests/[A-Za-z0-9_/]+\.py", p) for p in policy["test_paths"])
            or len(set(policy["test_paths"]) ) != len(policy["test_paths"])):
        raise ValueError("local acceptance requires trusted targeted validation and explicit Python tests")


def targeted(spec, config):
    return requested(spec) and "local_acceptance" in config


def acceptance(spec, config, target, results):
    if not targeted(spec, config):
        return None
    tests = config["local_acceptance"]["test_paths"]
    changed = set(target["files"]) - {spec.get("mission_scope_file")}
    if (not set(tests) <= changed or not any(p.startswith("src/") and p.endswith(".py") for p in changed)
            or any(not p.endswith(".py") for p in changed) or len(results) != 1):
        raise ValueError("local targeted requires changed Python source and all authorized direct tests")
    result = results[0]
    log = Path(result["log_path"])
    data = log.read_bytes()
    text = re.sub(r"\x1b\[[0-9;]*m", "", data.decode("utf-8", errors="replace"))
    command = "[Validation] changed Python tests: /usr/local/bin/python3 -m pytest -q " + " ".join(sorted(tests))
    if (result.get("status") != "PASS" or result.get("exit_code") != 0
            or hashlib.sha256(data).hexdigest() != result.get("log_sha256")
            or "profile=targeted changed_files=" not in text or "profile is a no-op" in text
            or "[Validation] Python changed-line static check:" not in text
            or "[Validation] Python format check:" not in text or command not in text
            or not re.search(r"\b[1-9][0-9]* passed\b", text)
            or re.search(r"\b[1-9][0-9]* (?:skipped|deselected|xfailed|xpassed)\b", text)):
        raise ValueError("local targeted lacks executed static/format/business-test PASS evidence")
    return {"mode": "targeted", "status": "PASS", "target": target, "test_paths": tests,
            "exit_code": 0, "log_sha256": result["log_sha256"], "evidence_key": result["evidence_key"]}


def authorize(spec, config, candidate=None, executor=None, *, executing=True):
    """Bind opt-in to exact task, execution policy and Controller-owned checkout."""
    if not requested(spec):
        if "delivery_mode" in spec or "local_candidate_authorization" in spec:
            raise ValueError("unknown delivery mode or unrequested local authorization")
        return
    draft_text = "\n".join([spec.get("objective", ""), *spec.get("constraints", []), *spec.get("acceptance", [])])
    if re.search(r"(?:待批准|等待用户批准|pending approval|approval required before (?:execution|implementation|model)|must be approved before (?:execution|implementation|model))", draft_text, re.I):
        raise ValueError("task text conflicts with verified execution authority; Controller stopped before dispatch")
    value = spec.get("local_candidate_authorization")
    fields = {"approval_id", "mission_id", "repository", "base", "worktree", "allowed_paths",
              "acceptance", "executor_identity", "checks", "ci", "budget", "max_rounds",
              "timeout_seconds", "simulation", "billing", "remote_write", "formal_review",
              "executor_permissions", "expires_at"}
    if "local_acceptance" in config:
        fields.add("local_acceptance")
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("explicit complete local_candidate_authorization required")
    if (not isinstance(value["approval_id"], str) or not value["approval_id"].strip()
            or value["billing"] != BILLING or value["remote_write"] != "FORBIDDEN"
            or value["formal_review"] != "NOT_AUTHORIZED"
            or value["executor_permissions"] != "ISOLATED_CANDIDATE_ONLY_NO_NETWORK"):
        raise ValueError("local execution requires explicit bounded authority and stop permissions")
    if {"hosted_ci", "project_pr_ci", "task_budget"} & set(config):
        raise ValueError("local candidate cannot authorize publication or a shared task wallet")
    if (not spec.get("acceptance") or not spec.get("scope") or "**" in spec["scope"]
            or not {"max_agent_runs", "max_run_tokens", "max_total_tokens", "max_wall_seconds",
                    "max_first_turn_tokens", "max_repair_incremental_tokens"}
            <= set(config["budget"])):
        raise ValueError("local candidate requires explicit acceptance, paths and stage-specific resource ceilings")
    if config["budget"]["max_agent_runs"] < 2:
        raise ValueError("local candidate budget must permit initial execution and one repair")
    bindings = {key: spec[key] for key in ("mission_id", "repository", "base", "acceptance")}
    bindings.update(allowed_paths=spec["scope"])
    if "local_acceptance" in config:
        bindings["local_acceptance"] = config["local_acceptance"]
        if not set(config["local_acceptance"]["test_paths"]) <= set(spec["scope"]):
            raise ValueError("local acceptance tests outside authorized scope")
    bindings.update({key: config[key] for key in
                     ("checks", "ci", "budget", "max_rounds", "timeout_seconds", "simulation")})
    if any(json.dumps(value[key], sort_keys=True) != json.dumps(expected, sort_keys=True)
           for key, expected in bindings.items()):
        raise ValueError("local authorization differs from task or resource/test policy")
    path = Path(value["worktree"])
    if not path.is_absolute() or (candidate is not None and path != candidate):
        raise ValueError("local authorization worktree identity mismatch")
    if not isinstance(value["executor_identity"], dict) or not value["executor_identity"]:
        raise ValueError("local executor identity required")
    if executor is not None and value["executor_identity"] != executor:
        raise ValueError("local executor identity changed; new authorization required")
    if not isinstance(value["expires_at"], str):
        raise ValueError("local authorization expiry must be a timestamp")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or executing and expiry <= datetime.now(timezone.utc):
        raise ValueError("local authorization expired or lacks timezone")


def check_dispatch(factory, mission, stage):
    """Also guard direct method calls, not only the happy-path state machine."""
    from .factory import FactoryBlocked
    row = factory.row(mission)
    spec = json.loads(row["spec"])
    if not requested(spec):
        return
    authorize(spec, factory.config, Path(row["candidate"]), factory.profile_identities["developer"])
    stopped = factory.db.execute(
        "SELECT 1 FROM events WHERE mission=? AND kind='local_candidate'", (mission,)).fetchone()
    if stage not in LOCAL_STAGES or stopped or targeted(spec, factory.config) and stage == "ci" or stage == "rework" and factory.db.execute(
            "SELECT COUNT(*) FROM operations WHERE mission=? AND stage='rework'", (mission,)).fetchone()[0] >= 1:
        raise FactoryBlocked("BLOCKED_LOCAL_AUTHORITY", "local candidate has no formal/remote/resume dispatch authority")


def complete(factory, spec, cwd, target, work, tests, ci):
    """Persist patch plus existing immutable operation identities in one transition."""
    from .factory import git, private_dir
    from .factory_budget import accounting
    mission = spec["mission_id"]
    patch = git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-renames",
                spec["base"], target["head"], "--").encode()
    path = private_dir(factory.root / "evidence" / mission) / (target["diff_sha256"] + ".patch")
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(patch)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o400)
    evidence = {"task_id": mission, "target": target, "worktree": str(cwd),
                "executor_identity": factory.profile_identities["developer"],
                "execution_status": "SIMULATED_EXECUTION_COMPLETE" if factory.config["simulation"] else "COMPLETE",
                "simulation": factory.config["simulation"], "repair_attempts": factory.db.execute(
                    "SELECT COUNT(*) FROM operations WHERE mission=? AND stage='rework'", (mission,)).fetchone()[0],
                "implemented": work["summary"], "risks": work["known_risks"],
                "patch": {"path": str(path), "sha256": target["diff_sha256"]},
                "validation_results": {"checks": tests, "ci": ci},
                "budget_authorization": spec["local_candidate_authorization"],
                "budget_usage": {**accounting(factory.db.execute(
                    "SELECT * FROM operations WHERE mission=?", (mission,)).fetchall(), factory.config["budget"]),
                    "money": "FIXTURE_NO_PROVIDER_COST" if factory.config["simulation"] else "UNKNOWN"},
                "formal_review": "NOT_EXECUTED", "qualification": "NOT_EXECUTED",
                "dual_receipt": "PENDING", "remote_write": "NOT_EXECUTED",
                "evidence_keys": [r[0] for r in factory.db.execute(
                    "SELECT key FROM operations WHERE mission=? ORDER BY started", (mission,))]}
    evidence["execution_operations"] = evidence["evidence_keys"]
    records = [json.loads(r[0]) for r in factory.db.execute(
        "SELECT result FROM operations WHERE mission=? AND paid=1 ORDER BY started", (mission,)).fetchall()]
    evidence["observed_token_usage"] = {"total": sum(
        (r.get("usage_delta", {}).get("totalTokens", r.get("usage_delta", {}).get("total", 0))
         if isinstance(r.get("usage_delta"), dict) else 0) for r in records),
        "snapshots": [r.get("usage_snapshot") for r in records],
        "operation_deltas": [r.get("usage_delta") for r in records], "money": "UNKNOWN"}
    evidence["wall_clock_time"] = round(__import__("time").monotonic() - getattr(factory, "_local_started", __import__("time").monotonic()), 3)
    if targeted(spec, factory.config):
        evidence["local_acceptance"] = acceptance(spec, factory.config, target, tests)
    verify(factory, spec, cwd, evidence)
    factory.event(mission, "local_candidate", evidence)
    factory.state(mission, LOCAL_READY)
    return factory.report(mission)


def verify(factory, spec, cwd, evidence):
    """Fail closed on status/resume without replaying any execution or gate."""
    from .factory import FactoryBlocked, git
    def require(ok, reason):
        if not ok:
            raise FactoryBlocked("UNKNOWN", reason)
    authorize(spec, factory.config, cwd, factory.profile_identities["developer"], executing=False)
    require(cwd.resolve() == cwd and (cwd / ".git").is_dir() and not (cwd / ".git").is_symlink()
            and not (cwd / ".git/objects/info/alternates").exists()
            and git(cwd, "branch", "--show-current") == "factory/" + spec["mission_id"]
            and not git(cwd, "remote"), "local repository isolation identity changed")
    target = factory.target(spec, cwd)
    require(target == evidence.get("target") and evidence.get("worktree") == str(cwd),
            "local candidate HEAD/tree/scope/worktree changed")
    require(bool(set(target["files"]) - {spec.get("mission_scope_file")}) and
            bool(evidence.get("implemented", "").strip()), "local implementation evidence missing")
    require(evidence.get("budget_authorization") == spec["local_candidate_authorization"] and
            evidence.get("executor_identity") == factory.profile_identities["developer"] and
            evidence.get("simulation") is factory.config["simulation"], "local authority/identity changed")
    patch = evidence.get("patch", {})
    path = Path(patch.get("path", ""))
    require(path.is_file() and not path.is_symlink() and path.resolve() == path and
            hashlib.sha256(path.read_bytes()).hexdigest() == patch.get("sha256") == target["diff_sha256"],
            "local full patch is missing or changed")
    operations = factory.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started",
                                    (spec["mission_id"],)).fetchall()
    require(evidence.get("evidence_keys") == [op["key"] for op in operations], "local evidence set changed")
    indexed = {}
    for op in operations:
        require(op["status"] == "COMPLETE" and op["stage"] in LOCAL_STAGES, "local execution incomplete or unauthorized")
        factory.verify_evidence(op)
        result = json.loads(op["result"])
        if op["paid"]:
            require(json.loads(op["identity"])["profile"] == factory.profile_identities["developer"] and
                    isinstance(result.get("runtime_identity"), dict) and bool(result["runtime_identity"]) and
                    result.get("status") in {None, "COMPLETE"}, "executor success/identity missing")
        indexed[op["key"]] = op
    require(any(op["stage"] == "implement" for op in operations), "actual execution required")
    local = targeted(spec, factory.config)
    if local:
        require(evidence.get("validation_results", {}).get("ci") == [], "local targeted cannot claim formal CI")
        try:
            expected = acceptance(spec, factory.config, target, evidence["validation_results"]["checks"])
        except (ValueError, KeyError, OSError) as exc:
            raise FactoryBlocked("UNKNOWN", str(exc)) from exc
        require(evidence.get("local_acceptance") == expected, "local acceptance evidence changed")
    for kind in (("checks",) if local else ("checks", "ci")):
        results = evidence.get("validation_results", {}).get(kind, [])
        require(len(results) == len(factory.config[kind]), "local required test evidence missing")
        for command, result in zip(factory.config[kind], results):
            op = indexed.get(result.get("evidence_key"))
            require(op is not None and op["stage"] == kind, "local test operation missing")
            payload, recorded = json.loads(op["input"]), json.loads(op["result"])
            require(payload["command"] == command and payload["target"] == target and
                    {k: v for k, v in result.items() if k != "evidence_key"} == recorded and
                    recorded.get("status") == "PASS" and type(recorded.get("exit_code")) is int and
                    recorded["exit_code"] == 0 and bool(recorded.get("raw_evidence")),
                    "local test exit/target/log evidence missing or failed")
            if factory.config.get("trusted_validation"):
                from .factory_validation import validate_result, profile_for
                validate_result(recorded, factory.config["trusted_validation"], spec, target,
                                profile_for(command), factory.config["simulation"])


def report(factory, row, operations, preflights, events):
    from .factory import FactoryBlocked
    from .factory_budget import accounting
    candidates = [json.loads(e["payload"]) for e in events if e["kind"] == "local_candidate"]
    evidence = candidates[-1] if candidates else {}
    status, reason = row["status"], row["reason"]
    if candidates:
        try:
            verify(factory, json.loads(row["spec"]), Path(row["candidate"]), evidence)
            if status == LOCAL_READY:
                reason = "user authorization required for any subsequent stage"
        except FactoryBlocked as exc:
            status, reason = exc.status, exc.reason
        except Exception as exc:
            status, reason = "UNKNOWN", str(exc)
    ready = status == LOCAL_READY and bool(candidates)
    local = {"MISSION": row["id"], "DELIVERY_STATUS": status, "LOCAL_CANDIDATE_READY": ready,
            "AUTHORIZATION_IDENTITY": evidence.get("budget_authorization", {}).get("approval_id", "UNKNOWN"),
            "BASE_SHA": evidence.get("target", {}).get("base", "UNKNOWN"),
            "FINAL_HEAD_SHA": evidence.get("target", {}).get("head", "UNKNOWN"),
            "FINAL_TREE_SHA": evidence.get("target", {}).get("tree", "UNKNOWN"),
            "FULL_DIFF": evidence.get("patch", "UNKNOWN"),
            "SCOPE_RESULT": "PASS" if ready else "UNKNOWN",
            "TRUSTED_QA_RESULT": evidence.get("validation_results", "UNKNOWN"),
            "EXECUTION_OPERATIONS": evidence.get("execution_operations", []),
            "OBSERVED_TOKEN_USAGE": evidence.get("observed_token_usage", "UNKNOWN"),
            "WALL_CLOCK_TIME": evidence.get("wall_clock_time", "UNKNOWN"),
            "SIMULATION": factory.config["simulation"], "DONE": False,
            "IMPLEMENTED": evidence.get("implemented", "UNKNOWN"),
            "TEST_RESULT": ("OFFLINE_FIXTURE_PASS" if factory.config["simulation"] else "PASS") if ready else "UNKNOWN",
            "CI_RESULT": "NOT_EXECUTED" if targeted(json.loads(row["spec"]), factory.config) else "LOCAL_ONLY_PASS" if ready else "UNKNOWN",
            "LOCAL_CI": "NOT_EXECUTED" if targeted(json.loads(row["spec"]), factory.config) else "PASS" if ready else "UNKNOWN",
            "LOCAL_ACCEPTANCE": evidence.get("local_acceptance", "NOT_RUN"),
            "HOSTED_CI": "NOT_EXECUTED", "REVIEW_RESULT": "NOT_EXECUTED",
            "FORMAL_REVIEW": "NOT_EXECUTED", "QUALIFICATION": "NOT_EXECUTED", "DUAL_RECEIPT": "PENDING",
            "REMOTE_WRITE_STATUS": "NOT_EXECUTED", "REMOTE_PR": "NOT_CREATED",
            "READY_FOR_MERGE": False, "READY_FOR_PRODUCTION": False, "MERGE_PERFORMED": False,
            "EXACT_TARGET": evidence.get("target", "UNKNOWN"),
            "TARGET_HEAD": evidence.get("target", {}).get("head", "UNKNOWN"),
            "CANDIDATE": row["candidate"], "CANDIDATE_BRANCH": "factory/" + row["id"],
            "LOCAL_CANDIDATE_EVIDENCE": evidence, "KNOWN_RISKS": evidence.get("risks", []),
            "DELIVERY_EVIDENCE": [op["evidence"] for op in operations if op["evidence"]],
            "PREPAID_PREFLIGHT": preflights[-1] if preflights else "NOT_RUN",
            "BUDGET_USED": {**accounting(operations, factory.config["budget"]),
                            "money": "FIXTURE_NO_PROVIDER_COST" if factory.config["simulation"] else "UNKNOWN"},
            "HUMAN_APPROVAL_REQUIRED": ["formal-review", "remote-publication", "merge", "release"],
            "BLOCKERS_REMAINING": [reason or status]}
    return local
