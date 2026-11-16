"""Software delivery governance: one mission, bounded work, exact evidence, no merge.

No workflow DSL, review DAG or custom agent runtime. Durable operations wrap
official Codex turns, local project gates and an independent provider review.
Historical v1 journals and review receipts are never opened by this module.
"""
from __future__ import annotations

import fnmatch
import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import subprocess
import time
import uuid
from pathlib import Path

from .factory_runtime import LocalRuntime, RuntimeFailure, official_rubric, VENDOR
from .sandbox import SAFE_PATH
from .factory_budget import accounting, operation_token_limit, planning_limits
from .factory_project import (PROJECT, OFFLINE_PASS, LANES, BACKENDS, approved_scope,
                              materialize_scope, scope_binding, review_manifest, validate_review_limits,
                              review_lanes, configured_review_lanes)
from . import factory_candidate as candidate_stage


READY = "READY_FOR_USER_ACCEPTANCE"


class FactoryBlocked(RuntimeError):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason
        super().__init__(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def observed_usage(value, simulation=False):
    """Keep raw telemetry separately; empty/invalid telemetry is not known zero."""
    if not isinstance(value, dict):
        return None
    if simulation and value == {"fixture_provider_calls": 0} and type(value["fixture_provider_calls"]) is int:
        return value
    fields = value.get("total", value)
    if not isinstance(fields, dict):
        return None
    contracts = ({"inputTokens", "outputTokens", "totalTokens"},
                 {"prompt_tokens", "completion_tokens"}, {"input_tokens", "output_tokens"})
    contract = next((keys for keys in contracts if keys <= set(fields)), None)
    if contract is None or any(type(fields[k]) is not int or fields[k] < 0 for k in contract):
        return None
    if any(type(v) is not int or v < 0 for k, v in fields.items() if "token" in k.lower() and not isinstance(v, dict)):
        return None
    from .factory_budget import tokens
    if tokens(value) is None:
        return None
    return value


def private_dir(path: Path) -> Path:
    path = path.absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("factory storage cannot contain symlinks")
        if parent.exists():
            mode = parent.stat().st_mode
            sticky_root = parent.stat().st_uid == 0 and bool(mode & 0o1000)
            private_group = parent.stat().st_uid == parent.stat().st_gid and not mode & 0o002
            if parent.stat().st_uid not in (0, os.getuid()) or mode & 0o022 and not (sticky_root or private_group):
                raise ValueError("factory storage has an untrusted ancestor")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir() or path.stat().st_uid != os.getuid():
        raise ValueError("factory storage must be an owned directory")
    path.chmod(0o700)
    return path.resolve()


def git(repo: Path, *args: str) -> str:
    env = {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
           "GIT_NO_LAZY_FETCH": "1", "GIT_LITERAL_PATHSPECS": "1"}
    data = subprocess.check_output(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                                    "-c", "core.quotePath=false",
                                    "-c", "core.fsmonitor=false", "-C", str(repo), *args],
                                   env=env, stderr=subprocess.PIPE, timeout=60).decode()
    return data if args[0] in ("diff", "show") and "--name-only" not in args else data.rstrip("\n")


def bounded_int(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer in {lower}..{upper}")
    return value


def validate_config(raw: dict) -> dict:
    """Operator policy is separate from the customer's product requirement."""
    allowed = {"version", "simulation", "budget", "max_rounds", "timeout_seconds", "checks", "ci",
               "profiles", "independent_review_required", "max_review_bytes", "max_context_bytes", "repository", "hosted_ci", "project_contract",
               "trusted_validation", "project_pr_ci", "local_acceptance", "model_routing",
               "project_container", "project_delivery", "project_review_limits", "review_mode"}
    if not isinstance(raw, dict) or set(raw) - allowed or type(raw.get("version")) is not int or raw.get("version") != 1:
        raise ValueError("invalid factory configuration")
    config = json.loads(encoded(raw))
    config.setdefault("simulation", False)
    config.setdefault("independent_review_required", True)
    for key in ("simulation", "independent_review_required"):
        if type(config[key]) is not bool:
            raise ValueError(f"{key} must be boolean")
    if "review_mode" in config:
        if (not isinstance(config["review_mode"], str) or config["review_mode"] not in {"single_openai", "dual"}
                or not config["independent_review_required"]):
            raise ValueError("review_mode must explicitly select single_openai or dual with independent review enabled")
    if "project_contract" in config:
        if config["project_contract"] != PROJECT or not config["independent_review_required"]:
            raise ValueError("project mode is explicit and requires independent review")
        if "hosted_ci" in config:
            raise ValueError("project mode requires explicit PR CI; push CI is incompatible")
    if {"trusted_validation", "project_pr_ci"} & set(config) and config.get("project_contract") != PROJECT:
        raise ValueError("trusted validation/PR CI are only available in explicit project mode")
    candidate_stage.validate_policy(config)
    if "trusted_validation" in config:
        from .factory_validation import validate_policy, profile_for
        validate_policy(config["trusted_validation"])
        if len(config.get("checks", [])) != 1 or len(config.get("ci", [])) != 1:
            raise ValueError("project validation requires one canonical check and PR profile")
        profile_for(config["checks"][0])
        if config["ci"] != [["make", "verify-pr"]]:
            raise ValueError("project CI must use canonical verify-pr")
    if "project_pr_ci" in config:
        from .factory_pr_ci import validate_policy
        validate_policy(config["project_pr_ci"])
        if "trusted_validation" not in config:
            raise ValueError("project PR readiness also requires trusted formal validation")
    for key in ("project_container", "project_delivery", "project_review_limits"):
        if key in config and config.get("project_contract") != PROJECT:
            raise ValueError("project execution policies require explicit FootballPrediction contract")
    if "project_container" in config:
        from .factory_container import validate_policy, PROFILES
        validate_policy(config["project_container"])
        if any(not isinstance(cmd, list) or any(not isinstance(x, str) for x in cmd) or tuple(cmd) not in PROFILES
               for kind in ("checks", "ci") for cmd in config.get(kind, [])):
            raise ValueError("project container gates require exact canonical make profiles")
    if "project_delivery" in config:
        from .factory_remote import validate_policy
        validate_policy(config["project_delivery"])
    if "project_review_limits" in config:
        validate_review_limits(config["project_review_limits"])
    if ({"trusted_validation", "project_pr_ci"} & set(config)
            and {"project_container", "project_delivery"} & set(config)):
        raise ValueError("trusted QA/PR CI and Controller execution policies cannot be mixed")
    budget = config.get("budget")
    budget_fields = {"max_agent_runs", "max_total_tokens", "max_run_tokens", "max_wall_seconds",
                     "max_first_turn_tokens", "max_repair_incremental_tokens", "max_plan_tokens"}
    if not isinstance(budget, dict) or "max_agent_runs" not in budget or set(budget) - budget_fields:
        raise ValueError("invalid mission resource authority; monetary usage remains UNKNOWN")
    if ("max_total_tokens" in budget) != ("max_run_tokens" in budget):
        raise ValueError("total and per-run token authority must be specified together")
    for name, upper in (("max_total_tokens", 100_000_000), ("max_run_tokens", 2_000_000), ("max_wall_seconds", 86400)):
        if name in budget:
            bounded_int(budget[name], name, 1, upper)
    if "max_plan_tokens" in budget:
        bounded_int(budget["max_plan_tokens"], "max_plan_tokens", 1, 2_000_000)
        if budget["max_plan_tokens"] > budget.get("max_run_tokens", 0):
            raise ValueError("planning token authority exceeds authorized max_run_tokens")
    staged_fields = {"max_first_turn_tokens", "max_repair_incremental_tokens"}
    if bool(staged_fields & set(budget)) and not staged_fields <= set(budget):
        raise ValueError("first-turn and repair token authorities must be specified together")
    for name in staged_fields & set(budget):
        bounded_int(budget[name], name, 1, 2_000_000)
        if budget[name] > budget.get("max_total_tokens", 0):
            raise ValueError("stage token authority exceeds mission token authority")
    if budget.get("max_run_tokens", 0) > budget.get("max_total_tokens", 0):
        raise ValueError("per-run token reservation exceeds mission token authority")
    if "repository" in config and (not isinstance(config["repository"], str) or not Path(config["repository"]).is_absolute()):
        raise ValueError("configured project must be an absolute repository path")
    bounded_int(budget["max_agent_runs"], "max_agent_runs", 1, 100)
    for key, default, low, high in [("max_rounds", 3, 1, 10), ("timeout_seconds", 900, 1, 3600),
                                   ("max_review_bytes", 1024 * 1024, 1, 8 * 1024 * 1024),
                                   ("max_context_bytes", 2 * 1024 * 1024, 1, 16 * 1024 * 1024)]:
        config[key] = bounded_int(config.get(key, default), key, low, high)
    for kind in ("checks", "ci"):
        commands = config.get(kind)
        if not isinstance(commands, list) or not commands:
            raise ValueError(f"{kind} requires at least one explicit project command")
        for command in commands:
            if not isinstance(command, list) or not command or any(not isinstance(x, str) or not x or "\0" in x for x in command):
                raise ValueError(f"invalid {kind} argv")
    if "hosted_ci" in config:
        hosted = config["hosted_ci"]
        if not isinstance(hosted, dict) or set(hosted) != {"repository", "workflows"} or not isinstance(hosted["repository"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", hosted["repository"]):
            raise ValueError("hosted CI requires an explicit GitHub owner/repository")
        if not isinstance(hosted["workflows"], list) or not hosted["workflows"] or len(set(hosted["workflows"])) != len(hosted["workflows"]) or any(not isinstance(w, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", w) for w in hosted["workflows"]):
            raise ValueError("hosted CI requires exact workflow filenames")
    profiles = config.get("profiles")
    expected = {"developer", *configured_review_lanes(config)}
    if not isinstance(profiles, dict) or set(profiles) != expected:
        raise ValueError("profiles must define the required execution lanes")
    for lane, profile in profiles.items():
        if not isinstance(profile, dict) or set(profile) - {"provider", "model", "effort", "codex_profile", "codex_home", "token_file", "max_output_tokens", "transport"}:
            raise ValueError("invalid lane profile")
        expected_provider = "deepseek" if lane == "second_reviewer" else "openai"
        if profile.get("provider") != expected_provider:
            raise ValueError("independent review requires genuinely different providers")
        if expected_provider == "openai":
            from .factory_proxy import validate_transport
            validate_transport(profile, reviewer=lane == "reviewer")
        elif profile.get("transport", {"type": "direct"}) != {"type": "direct"}:
            raise ValueError("DeepSeek reviewer remains a direct official provider; endpoint override forbidden")
        for field in ("model", "codex_profile"):
            if field in profile and (not isinstance(profile[field], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]+", profile[field])):
                raise ValueError(f"invalid {field}")
        if "effort" in profile and profile["effort"] not in ("low", "medium", "high", "xhigh"):
            raise ValueError("invalid Codex reasoning effort")
        if "codex_home" in profile and (not isinstance(profile["codex_home"], str) or not Path(profile["codex_home"]).is_absolute()):
            raise ValueError("codex_home must be an absolute private authentication directory")
        if lane == "second_reviewer":
            if not profile.get("model") or not Path(profile.get("token_file", "")).is_absolute():
                raise ValueError("DeepSeek requires a model and an absolute private token file")
            bounded_int(profile.get("max_output_tokens", 8192), "max_output_tokens", 1, 32768)
    if "model_routing" in config:
        from .factory_routing import validate_pool
        validate_pool(config["model_routing"])
    return config


def policy_identity(config):
    # Switching one profile changes only that lane's evidence key. Budgets,
    # provider independence, timeouts and test policy remain immutable.
    return {key: value for key, value in config.items() if key not in ("profiles", "repository")}


def validate_mission(raw):
    keys = {"version", "mission_id", "repository", "objective", "acceptance", "constraints", "scope", "base", "mission_scope_file", "approved_mission_scope", "delivery_mode", "local_candidate_authorization", "model_routing", "pr_body_template"}
    if not isinstance(raw, dict) or set(raw) - keys or type(raw.get("version")) is not int or raw.get("version") != 2:
        raise ValueError("factory missions require version 2")
    mission = json.loads(encoded(raw))
    if "model_routing" in mission:
        from .factory_routing import validate_request
        validate_request(mission["model_routing"])
    if "pr_body_template" in mission and (not isinstance(mission["pr_body_template"], str)
            or not mission["pr_body_template"].strip() or len(mission["pr_body_template"].encode()) > 60000):
        raise ValueError("invalid Controller PR body template")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", mission.get("mission_id", "")):
        raise ValueError("invalid mission_id")
    repo = Path(mission["repository"]).resolve(strict=True)
    if Path(git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ValueError("repository must be a Git root")
    mission["repository"] = str(repo)
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("原项目有未保存到 Git 的改动；请由项目维护者保存版本后再提交。原文件未被修改，也没有发起模型调用。")
    if not isinstance(mission.get("objective"), str) or not mission["objective"].strip():
        raise ValueError("a product request is required")
    for key, default in [("acceptance", []), ("constraints", []), ("scope", ["**"])]:
        mission.setdefault(key, default)
        if not isinstance(mission[key], list) or any(not isinstance(s, str) or not s for s in mission[key]):
            raise ValueError(f"invalid {key}")
    if not mission["scope"] or any(p.startswith("/") or ".." in Path(p).parts for p in mission["scope"]):
        raise ValueError("scope must contain relative repository patterns")
    base = mission.get("base", "HEAD")
    if not isinstance(base, str) or base.startswith("-") or "\0" in base:
        raise ValueError("invalid base")
    mission["base"] = git(repo, "rev-parse", "--verify", base + "^{commit}")
    if "approved_mission_scope" in mission:
        approval = approved_scope(mission)
        if mission.get("mission_scope_file", approval["path"]) != approval["path"]:
            raise ValueError("mission scope reference conflicts with approval")
        mission["mission_scope_file"] = approval["path"]
    if "mission_scope_file" in mission:
        scope_file = mission["mission_scope_file"]
        if not isinstance(scope_file, str) or Path(scope_file).is_absolute() or ".." in Path(scope_file).parts or not scope_file:
            raise ValueError("mission_scope_file must be a tracked relative path")
        if "approved_mission_scope" not in mission:
            git(repo, "cat-file", "-e", mission["base"] + ":" + scope_file)
    if "delivery_mode" in mission and mission["delivery_mode"] != candidate_stage.LOCAL_MODE:
        raise ValueError("unknown delivery mode")
    if "local_candidate_authorization" in mission and not candidate_stage.requested(mission):
        raise ValueError("local authorization requires explicit local_candidate mode")
    return mission


def changed_lines(diff):
    """Validate source locations against Git hunks; this is evidence, not review reasoning."""
    result, path, old_path, side = {}, None, None, "head"
    for line in diff.splitlines():
        if line.startswith("--- a/"):
            old_path = line[6:]
        elif line.startswith("+++ b/"):
            path = line[6:]
            side = "head"
        elif line.startswith("+++ /dev/null"):
            path, side = old_path, "base"
        elif path and line.startswith("@@ "):
            match = re.search((r"\+" if side == "head" else r"-") + r"(\d+)(?:,(\d+))?", line)
            if match:
                start, count = int(match[1]), int(match[2] or "1")
                result.setdefault(path, []).append((max(1, start), max(1, start + max(count, 1) - 1), side))
    return result


def review_verdict(output, cwd: Path, target: dict):
    """Malformed/missing/contradictory output is UNKNOWN, never an empty PASS."""
    required = {"findings", "overall_correctness", "overall_explanation", "overall_confidence_score"}
    if not isinstance(output, dict) or set(output) != required:
        raise ValueError("review does not match the official output contract")
    if output["overall_correctness"] not in ("patch is correct", "patch is incorrect"):
        raise ValueError("missing explicit review correctness")
    def score(value):
        return type(value) in (float, int) and math.isfinite(value) and 0 <= value <= 1
    if not score(output["overall_confidence_score"]) or not isinstance(output["overall_explanation"], str) or not output["overall_explanation"].strip():
        raise ValueError("review explanation/confidence missing")
    findings = output["findings"]
    if not isinstance(findings, list):
        raise ValueError("invalid review findings")
    hunks = changed_lines(git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0", target["base"], target["head"], "--"))
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) - {"title", "body", "confidence_score", "priority", "code_location"} or not {"title", "body", "confidence_score", "code_location"} <= set(finding):
            raise ValueError("malformed official finding")
        if any(not isinstance(finding[k], str) or not finding[k].strip() for k in ("title", "body")) or not score(finding["confidence_score"]):
            raise ValueError("invalid finding content")
        priority = finding.get("priority")
        if priority is not None and (type(priority) is not int or not 0 <= priority <= 3):
            raise ValueError("invalid priority")
        location = finding["code_location"]
        if not isinstance(location, dict) or set(location) != {"absolute_file_path", "line_range"}:
            raise ValueError("missing source reference")
        path = Path(location["absolute_file_path"])
        if not path.is_absolute() or path != path.resolve() or path.is_symlink():
            raise ValueError("source reference is not a canonical absolute file")
        relative = path.relative_to(cwd).as_posix()
        lines = location["line_range"]
        if not isinstance(lines, dict) or set(lines) != {"start", "end"} or any(type(lines[k]) is not int for k in lines):
            raise ValueError("invalid source line range")
        start, end = lines["start"], lines["end"]
        intervals = hunks.get(relative, [])
        source_commit = target[intervals[0][2]] if intervals else target["head"]
        blob = git(cwd, "show", f"{source_commit}:{relative}")
        if not 1 <= start <= end <= len(blob.splitlines()) or not any(start <= b and end >= a for a, b, _ in intervals):
            raise ValueError("finding source does not overlap the exact target diff")
        normalized.append({**finding, "source": {"path": relative, "commit": source_commit, "target_head": target["head"],
                                                 "start": start, "end": end}})
    if output["overall_correctness"] == "patch is correct" and any(f.get("priority") in (None, 0, 1, 2) for f in findings):
        raise ValueError("correctness verdict contradicts actionable findings")
    # All findings are reworked, without inventing severity or adjudication logic.
    return ("PASS" if not findings and output["overall_correctness"] == "patch is correct" else "FAIL"), normalized


class Factory:
    def __init__(self, root: Path, config: dict, runtime=None, progress=None):
        self.config = validate_config(config)
        self.progress = progress
        self.runtime = runtime or LocalRuntime()
        if bool(self.runtime.simulation) != self.config["simulation"]:
            raise ValueError("fixture/live runtime does not match operator policy")
        if hasattr(self.runtime, "resource_policy"):
            self.runtime.resource_policy = self.config["budget"]
        self.project = self.config.get("project_contract") == PROJECT
        self.profile_identities = {lane: self.runtime.profile_identity(profile) if hasattr(self.runtime, "profile_identity") else {"configured": profile, "fixture": True}
                                   for lane, profile in self.config["profiles"].items()
                                   if (not self.project or lane == "developer") and not (lane == "developer" and "model_routing" in self.config)}
        self._routing_identities = {}
        requested_root = Path(root).absolute()
        metadata = [parent / ".git" for parent in (requested_root, *requested_root.parents)]
        if any(p.is_file() or p.is_symlink() or ((p / "HEAD").is_file() and (p / "config").is_file()) for p in metadata):
            raise ValueError("factory state must be outside Git repositories")
        self.root = private_dir(root)
        path = private_dir(self.root / "control") / "factory.sqlite"
        if path.is_symlink():
            raise ValueError("factory database cannot be a symlink")
        if path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid() or path.stat().st_nlink != 1):
            raise ValueError("factory database must be an owned, unlinked regular file")
        for suffix in ("-wal", "-shm"):
            if path.with_name(path.name + suffix).is_symlink():
                raise ValueError("factory SQLite sidecars cannot be symlinks")
        self.db = sqlite3.connect(path, timeout=30)
        path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS missions(
          id TEXT PRIMARY KEY, spec TEXT NOT NULL, policy TEXT NOT NULL,
          status TEXT NOT NULL, round INTEGER NOT NULL DEFAULT 0,
          reason TEXT NOT NULL DEFAULT '', candidate TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS operations(
          id TEXT PRIMARY KEY, mission TEXT NOT NULL, key TEXT NOT NULL,
          stage TEXT NOT NULL, lane TEXT NOT NULL, paid INTEGER NOT NULL,
          identity TEXT NOT NULL, input TEXT NOT NULL, status TEXT NOT NULL,
          result TEXT, evidence TEXT, evidence_hash TEXT, usage TEXT,
          started REAL NOT NULL, ended REAL,
          UNIQUE(mission,key));
        CREATE TABLE IF NOT EXISTS events(
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, mission TEXT NOT NULL,
          kind TEXT NOT NULL, payload TEXT NOT NULL, at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS approvals(
          id TEXT PRIMARY KEY, mission TEXT NOT NULL, target TEXT NOT NULL,
          action TEXT NOT NULL, reason TEXT NOT NULL, at REAL NOT NULL);
        CREATE TRIGGER IF NOT EXISTS immutable_completed_operations
          BEFORE UPDATE ON operations WHEN OLD.status != 'RUNNING'
          BEGIN SELECT RAISE(ABORT,'completed accounting/evidence is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_operation_delete BEFORE DELETE ON operations
          BEGIN SELECT RAISE(ABORT,'accounting/evidence cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS no_event_update BEFORE UPDATE ON events
          BEGIN SELECT RAISE(ABORT,'audit events are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_event_delete BEFORE DELETE ON events
          BEGIN SELECT RAISE(ABORT,'audit events cannot be deleted'); END;
        CREATE TRIGGER IF NOT EXISTS immutable_mission_authority BEFORE UPDATE ON missions
          WHEN NEW.spec != OLD.spec OR NEW.policy != OLD.policy OR NEW.candidate != OLD.candidate
          BEGIN SELECT RAISE(ABORT,'mission authority is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_approval_update BEFORE UPDATE ON approvals
          BEGIN SELECT RAISE(ABORT,'human approvals are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS no_approval_delete BEFORE DELETE ON approvals
          BEGIN SELECT RAISE(ABORT,'human approvals cannot be deleted'); END;
        """)
        self.db.commit()

    def close(self):
        self.db.close()

    def event(self, mission, kind, payload):
        self.db.execute("INSERT INTO events(mission,kind,payload,at) VALUES(?,?,?,?)",
                        (mission, kind, encoded(payload), time.time()))

    def row(self, mission):
        row = self.db.execute("SELECT * FROM missions WHERE id=?", (mission,)).fetchone()
        if row is None:
            raise KeyError(mission)
        if json.loads(row["policy"]) != policy_identity(self.config):
            raise ValueError("operator policy/budget differs from the immutable mission authority")
        return row

    def developer_binding(self, spec):
        """Resolve once per identity; the submitted route cannot change on resume."""
        if "model_routing" not in self.config:
            if "model_routing" in spec:
                raise ValueError("task routing requires an explicit operator model pool")
            return self.config["profiles"]["developer"], self.profile_identities["developer"]
        from .factory_routing import select
        profile, decision = select(self.config["model_routing"], spec.get("model_routing"))
        key = digest({"profile": profile, "selection": decision})
        if key not in self._routing_identities:
            identity = (self.runtime.profile_identity(profile) if hasattr(self.runtime, "profile_identity")
                        else {"configured": profile, "fixture": True})
            self._routing_identities[key] = {**identity, "model_selection": decision}
        identity = self._routing_identities[key]
        submitted = self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='submitted'",
                                    (spec["mission_id"],)).fetchone()
        if submitted and json.loads(submitted[0]).get("routing_executor") != identity:
            raise ValueError("bound task route changed; new task authorization required")
        return profile, identity

    def state(self, mission, status, reason=""):
        self.db.execute("UPDATE missions SET status=?,reason=? WHERE id=?", (status, reason, mission))
        self.event(mission, "state", {"status": status, "reason": reason})
        self.db.commit()
        if self.progress is not None:
            try:
                self.progress(mission, status)
            except OSError:
                pass  # A disconnected progress stream cannot rewrite proven state.

    def submit(self, raw):
        spec = validate_mission(raw)
        _, executor = self.developer_binding(spec)
        if candidate_stage.requested(spec):
            candidate_stage.authorize(spec, self.config)
        if self.project:
            approved_scope(spec)
            if candidate_stage.requested(spec):
                # Project scope is still an authorization boundary for local
                # candidates; validate it before any execution can be dispatched.
                self.runtime.project_policy(spec, Path(spec["repository"]), spec["scope"])
            elif "project_pr_ci" in self.config:
                from .factory_pr_ci import repository_identity
                repository_identity(spec, self.config["project_pr_ci"])
        elif "approved_mission_scope" in spec:
            raise ValueError("Controller scope approval requires explicit project_contract mode")
        mission = spec["mission_id"]
        repository = Path(spec["repository"])
        if self.root == repository or repository in self.root.parents:
            raise ValueError("factory state must be outside the target repository")
        existing = self.db.execute("SELECT spec FROM missions WHERE id=?", (mission,)).fetchone()
        if existing:
            if json.loads(existing["spec"]) != spec:
                raise ValueError("product requirement differs from the immutable mission")
            self.row(mission)
            return mission
        candidate = self.root / "candidates" / mission
        if self.project:
            # The existing adapter places trusted-base worktrees next to the
            # candidate. Independent Factory clones need independent parents.
            candidate = candidate / "source"
        if candidate.exists():
            raise ValueError("unowned candidate path already exists")
        if candidate_stage.requested(spec):
            candidate_stage.authorize(spec, self.config, candidate, executor)
        self.db.execute("INSERT INTO missions(id,spec,policy,status,candidate) VALUES(?,?,?,?,?)",
                        (mission, encoded(spec), encoded(policy_identity(self.config)), "CREATED", str(candidate)))
        self.event(mission, "submitted", {"spec": spec, "profiles": self.config["profiles"],
                   **({"routing_executor": executor} if "model_routing" in self.config else {})})
        self.db.commit()
        return mission

    def prepare(self, mission):
        row = self.row(mission)
        spec, cwd = json.loads(row["spec"]), Path(row["candidate"])
        from .factory_remote import project_branch
        # Local-only candidates keep the mission branch used by execution and
        # revalidation; the BASE suffix belongs to project publication.
        branch = (project_branch(spec) if self.project and not candidate_stage.requested(spec)
                  else f"factory/{mission}")
        if row["status"] == "CREATED":
            if cwd.exists():
                raise FactoryBlocked("UNKNOWN", "candidate preparation interrupted; unverified path was not reused")
            cwd.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.project:
                private_dir(self.root / "candidates")
                private_dir(cwd.parent)
            git(Path(spec["repository"]), "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", spec["repository"], str(cwd))
            git(cwd, "remote", "remove", "origin")
            git(cwd, "checkout", "-b", branch, spec["base"])
            if self.project:
                materialize_scope(spec, cwd, git)
                if not candidate_stage.requested(spec):
                    paths = [spec["mission_scope_file"]]
                    if self.config.get("review_mode") == "single_openai":
                        scope = json.loads(approved_scope(spec)["content"])
                        if scope.get("authorized_prefixes"):
                            raise FactoryBlocked("BLOCKED_SCOPE", "single-review pilot requires exact authorized paths")
                        paths = scope["authorized_paths"]
                    policy = self.project_policy(spec, cwd, paths)
                    if self.config.get("review_mode") == "single_openai":
                        review_lanes({"review_mode": "single_openai", "project_policy": policy})
            self.state(mission, "PLAN")
        if cwd.resolve() != cwd or not (cwd / ".git").is_dir() or (cwd / ".git").is_symlink():
            raise FactoryBlocked("UNKNOWN", "candidate isolation identity is invalid")
        if (cwd / ".git" / "objects" / "info" / "alternates").exists():
            raise FactoryBlocked("UNKNOWN", "candidate must not share a writable Git database")
        if self.project and git(cwd, "branch", "--show-current") != branch:
            raise FactoryBlocked("UNKNOWN", "candidate branch differs from task publication identity; no branch recreated")
        return spec, cwd

    def target(self, spec, cwd):
        if git(cwd, "status", "--porcelain", "--untracked-files=all"):
            raise FactoryBlocked("UNKNOWN", "target contains uncommitted/untracked changes")
        head = git(cwd, "rev-parse", "HEAD")
        git(cwd, "merge-base", "--is-ancestor", spec["base"], head)
        files = [p for p in git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "--no-renames", spec["base"], head, "--").split("\0") if p]
        if any(not any(fnmatch.fnmatchcase(path, pattern) for pattern in spec["scope"]) for path in files):
            raise FactoryBlocked("BLOCKED_SCOPE", "changes exceed the customer-authorized scope")
        for path in files:
            for commit in (spec["base"], head):
                entry = git(cwd, "ls-tree", commit, "--", path)
                if entry.startswith("160000 "):
                    raise FactoryBlocked("BLOCKED_SCOPE", "changed submodule content cannot be certified from a gitlink alone")
        diff = git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-renames", spec["base"], head, "--")
        if len(diff.encode()) > self.config["max_review_bytes"]:
            raise FactoryBlocked("BLOCKED_SCOPE", "full diff exceeds authorized review capacity; nothing was truncated")
        target = {"repository": spec["repository"], "base": spec["base"], "head": head,
                "commit": head, "tree": git(cwd, "rev-parse", "HEAD^{tree}"),
                "scope": spec["scope"], "files": files, "diff_sha256": hashlib.sha256(diff.encode()).hexdigest()}
        if self.project:
            try:
                target.update(scope_binding(spec, cwd, head, git))
                if not candidate_stage.requested(spec):
                    target["review_range"] = review_manifest(cwd, target, git)
                # Local candidates keep the project scope boundary without
                # entering the formal review path.
                target["project_policy"] = self.project_policy(spec, cwd, files)
                if self.config.get("review_mode") == "single_openai":
                    target["review_mode"] = "single_openai"
                    review_lanes(target)
            except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as exc:
                raise FactoryBlocked("BLOCKED_SCOPE", str(exc)) from exc
        elif spec.get("mission_scope_file"):
            scope_file = spec["mission_scope_file"]
            baseline = git(cwd, "rev-parse", spec["base"] + ":" + scope_file)
            if git(cwd, "rev-parse", head + ":" + scope_file) != baseline:
                raise FactoryBlocked("BLOCKED_SCOPE", "committed mission scope authority changed during implementation")
            target["mission_scope_file"] = scope_file
            target["scope_blob"] = baseline
        if "hosted_ci" in self.config:
            # Publication happens before review. An agent must not be able to
            # add a privileged workflow that executes merely on candidate push.
            if any(path.startswith(".github/workflows/") for path in files):
                raise FactoryBlocked("BLOCKED_SCOPE", "candidate changes GitHub workflows; an independently authorized CI policy is required before publication")
            for workflow in self.config["hosted_ci"]["workflows"]:
                path = ".github/workflows/" + workflow
                if git(cwd, "rev-parse", spec["base"] + ":" + path) != git(cwd, "rev-parse", head + ":" + path):
                    raise FactoryBlocked("BLOCKED_SCOPE", "authorized hosted workflow was changed; its success cannot certify this task")
        return target

    def project_policy(self, spec, cwd, paths):
        if self.config.get("review_mode") == "single_openai":
            return self.runtime.project_policy(spec, cwd, paths, review_mode="single_openai")
        return self.runtime.project_policy(spec, cwd, paths)

    def checkpoint(self, spec, cwd):
        if self.project:
            approval = approved_scope(spec)
            path = cwd / approval["path"]
            if path.is_symlink() or not path.is_file() or path.read_bytes() != approval["content"].encode():
                raise FactoryBlocked("BLOCKED_SCOPE", "Builder changed or removed Controller scope; not committed")
        if git(cwd, "status", "--porcelain", "--untracked-files=all"):
            git(cwd, "add", "--all", "--", ".")
            git(cwd, "-c", "user.name=Delivery Factory", "-c", "user.email=factory@localhost",
                "commit", "-m", f"Implement mission {spec['mission_id']}")
        return self.target(spec, cwd)

    def operation(self, mission, key, stage, lane, identity, payload, paid, invoke, prepare=None):
        """Reserve before dispatch. A lost response is never replayed under a new guise."""
        candidate_stage.check_dispatch(self, mission, stage)
        if self.project and not self.config["simulation"] and isinstance(self.runtime, LocalRuntime):
            try:
                self.runtime.assert_canonical_lifecycles(self.root / "evidence" / mission, mission)
            except Exception as error:
                raise FactoryBlocked("UNKNOWN", str(error)) from error
        routing_decision = None
        if paid and lane == "developer" and "model_routing" in self.config:
            spec = json.loads(self.row(mission)["spec"])
            _, expected = self.developer_binding(spec)
            if identity.get("profile") != expected:
                raise FactoryBlocked("BLOCKED_LOCAL_AUTHORITY", "dispatch differs from bound task model/route")
            routing_decision = expected["model_selection"]
        old = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, key)).fetchone()
        if old:
            if old["status"] != "COMPLETE":
                raise FactoryBlocked("UNKNOWN", f"{stage} dispatch/result is uncertain; operation {old['id']} was not repeated")
            self.verify_evidence(old)
            return json.loads(old["result"])
        if self.cancel_requested(mission):
            raise FactoryBlocked("CANCELLED", "user cancelled; completed evidence and all reservations are retained")
        budget = self.config["budget"]
        local_mode = candidate_stage.requested(json.loads(self.row(mission)["spec"])) if paid else False
        effective_limit = operation_token_limit(budget, stage, local_candidate=local_mode) if paid else None
        if paid and effective_limit is not None:
            identity = {**identity, "operation_token_limit": effective_limit}
        if paid:
            uncertain = self.uncertain_operations(mission)
            if uncertain:
                raise FactoryBlocked("UNKNOWN", "unresolved operation prevents a new paid dispatch; no replay or refund")
            has_paid = self.db.execute("SELECT 1 FROM operations WHERE mission=? AND paid=1 LIMIT 1", (mission,)).fetchone()
            if has_paid and self.row(mission)["status"] == "BLOCKED_PREFLIGHT":
                raise FactoryBlocked("BLOCKED_PREFLIGHT", "preflight resume requires no paid operations; prior accounting is retained")
            if not has_paid:
                from .factory_preflight import inspect_prepaid
                preflight = inspect_prepaid(json.loads(self.row(mission)["spec"]), self.config)
                self.event(mission, "prepaid_preflight", preflight)
                self.db.commit()
                blockers = [f for f in preflight["findings"] if f["level"] == "HARD_BLOCKER"
                            and not (local_mode and f["check"] in {"first_paid_execution", "independent_context"})]
                if blockers:
                    detail = "; ".join(f["check"] + ": " + f["detail"] for f in blockers)
                    raise FactoryBlocked("BLOCKED_PREFLIGHT", detail)
        # Trusted local preparation is not a paid dispatch. Keep it after the
        # cache/uncertainty guards and outside the reservation transaction.
        prepared = prepare() if prepare is not None else None
        operation_id = uuid.uuid4().hex
        evidence_dir = private_dir(self.root / "evidence" / mission)
        evidence = evidence_dir / f"{operation_id}.json"
        transcript = evidence_dir / f"{operation_id}.raw"
        try:
            self.db.execute("BEGIN IMMEDIATE")
            budget = self.config["budget"]
            operations = self.db.execute("SELECT * FROM operations WHERE mission=?", (mission,)).fetchall()
            resources = accounting(operations, budget)
            started = self.db.execute("SELECT MIN(at) FROM events WHERE mission=? AND kind='submitted'", (mission,)).fetchone()[0]
            if "max_wall_seconds" in budget and time.time() - started >= budget["max_wall_seconds"]:
                raise FactoryBlocked("BLOCKED_BUDGET", "authorized mission wall-clock exhausted")
            if paid and "max_total_tokens" in budget and resources["committed_tokens"] + effective_limit > budget["max_total_tokens"]:
                raise FactoryBlocked("BLOCKED_BUDGET", "token admission exhausted; UNKNOWN reservations are permanent")
            used = self.db.execute("SELECT COUNT(*) FROM operations WHERE mission=? AND paid=1", (mission,)).fetchone()[0]
            local_mode = candidate_stage.requested(json.loads(self.row(mission)["spec"])) if paid else False
            effective_run_limit = min(self.config["budget"]["max_agent_runs"], 2 if local_mode else self.config["budget"]["max_agent_runs"])
            if paid and used >= effective_run_limit:
                raise FactoryBlocked("BLOCKED_BUDGET", "authorized agent-run budget exhausted; failures and UNKNOWN remain charged")
            self.db.execute("INSERT INTO operations(id,mission,key,stage,lane,paid,identity,input,status,started) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (operation_id, mission, key, stage, lane, int(paid), encoded(identity), encoded(payload), "RUNNING", time.time()))
            self.event(mission, "reserved", {"operation": operation_id, "stage": stage, "lane": lane, "identity": identity})
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        try:
            result = invoke(transcript, prepared) if prepare is not None else invoke(transcript)
            if not isinstance(result, dict):
                raise ValueError("runtime returned a non-object result")
            if routing_decision is not None and not self.config["simulation"]:
                actual = result.get("runtime_identity") or {}
                if (actual.get("route_identity") != expected.get("route_identity") or
                        actual.get("reported_model") != routing_decision["requested_model"] or
                        result.get("usage_complete") is not True):
                    raise RuntimeFailure("task route/model/usage evidence differs from authorization", result.get("usage"), actual)
            result.setdefault("usage_complete", observed_usage(result.get("usage"), self.config["simulation"]) is not None)
            status = "UNKNOWN" if result.get("status") == "UNKNOWN" else "COMPLETE"
            if status == "UNKNOWN":
                result.setdefault("error", "runtime result was incomplete or uncertain; no replay authorized")
        except Exception as exc:
            result, status = {"error": f"{type(exc).__name__}: {exc}",
                              "usage": getattr(exc, "usage", None),
                              "runtime_identity": getattr(exc, "identity", None),
                              "usage_complete": getattr(exc, "usage_complete", False)}, "UNKNOWN"
            if getattr(exc, "usage_telemetry", None) is not None:
                result["usage_telemetry"] = exc.usage_telemetry
            if getattr(exc, "remote_cleanup", None) is not None:
                result["remote_cleanup"] = exc.remote_cleanup
        raw_paths = [p for p in (transcript, transcript.with_suffix(".stderr"), transcript.with_suffix(".proxy.jsonl"),
                                transcript.with_suffix(".container.json"), transcript.with_suffix(".container.clients.jsonl"),
                                transcript.with_suffix(".stdout"),
                                transcript.with_suffix(".cleanup.json"), transcript.with_suffix(".temp.json"),
                                transcript.with_suffix(".temp.cleanup.jsonl")) if p.is_file()]
        # Also bind this operation's retained lifecycle originals on UNKNOWN;
        # no recursive scan of retained reviewer HOME or credentials.
        if self.project:
            sidecars = [transcript.with_suffix(suffix) for suffix in (
                ".review", ".review.stderr", ".review.process.jsonl", ".review.stop.json",
                ".raw.stderr", ".raw.process.jsonl", ".raw.stop.json", ".remote.jsonl", ".input.json")]
            sidecars.extend(transcript.parent.glob(transcript.stem + ".validator-*"))
            raw_paths.extend(p for p in sidecars if p.is_file() and not p.is_symlink() and p not in raw_paths)
        result["raw_evidence"] = [{"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in raw_paths]
        data = encoded({"operation": operation_id, "identity": identity, "input": payload, "result": result}).encode()
        with evidence.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        evidence.chmod(0o400)
        usage = observed_usage(result.get("usage"), self.config["simulation"])
        self.db.execute("UPDATE operations SET status=?,result=?,evidence=?,evidence_hash=?,usage=?,ended=? WHERE id=? AND status='RUNNING'",
                        (status, encoded(result), str(evidence), hashlib.sha256(data).hexdigest(),
                         encoded(usage) if usage is not None else None, time.time(), operation_id))
        self.event(mission, "completed", {"operation": operation_id, "status": status, "evidence": str(evidence)})
        self.db.commit()
        if paid and effective_limit is not None:
            from .factory_budget import tokens
            if (tokens(usage) or 0) > effective_limit:
                raise FactoryBlocked("BLOCKED_BUDGET", "run token allowance exceeded; telemetry retained, no further dispatch")
        if paid and stage == "plan":
            from .factory_budget import tokens
            if (tokens(usage) or 0) > planning_limits(self.config["budget"], self.config["timeout_seconds"])["max_tokens"]:
                raise FactoryBlocked("BLOCKED_BUDGET", "planning token allowance exceeded; telemetry and UNKNOWN reservations retained")
        if self.cancel_requested(mission):
            raise FactoryBlocked("CANCELLED", "user cancelled; in-flight usage may remain UNKNOWN and is never refunded")
        if status != "COMPLETE":
            raise FactoryBlocked("UNKNOWN", f"{stage} failed; retained raw evidence and consumed run reservation: {result['error']}")
        return result

    def uncertain_operations(self, mission):
        """Keep UNKNOWN rows intact; re-derive narrowly bound recovery evidence."""
        resolved = set()
        for event in self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='publication_reconciled'", (mission,)):
            value = json.loads(event[0])
            proof = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, value["evidence_key"])).fetchone()
            if proof is None or proof["status"] != "COMPLETE" or proof["stage"] != "project_reconcile":
                raise FactoryBlocked("UNKNOWN", "publication reconciliation evidence missing")
            self.verify_evidence(proof)
            result = json.loads(proof["result"])
            original = self.db.execute("SELECT * FROM operations WHERE id=? AND mission=?", (value["operation_id"], mission)).fetchone()
            if (original is None or original["stage"] != "project_publish" or result.get("status") != "PASS"
                    or result.get("target") != json.loads(original["input"])["target"]
                    or result.get("fixture") is not False):
                raise FactoryBlocked("UNKNOWN", "publication reconciliation binding invalid")
            resolved.add(value["operation_id"])
        for event in self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='remote_observation_recovered'", (mission,)):
            value = json.loads(event[0])
            original = self.db.execute("SELECT * FROM operations WHERE mission=? AND id=?", (mission, value["operation_id"])).fetchone()
            proof = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, value["evidence_key"])).fetchone()
            self.validate_observation_recovery(mission, original, proof)
            resolved.add(original["id"])
        return [op for op in self.db.execute("SELECT * FROM operations WHERE mission=? AND status IN ('RUNNING','UNKNOWN')", (mission,))
                if op["id"] not in resolved]

    def verify_evidence(self, operation):
        if (self.project and not self.config["simulation"] and operation["stage"] == "review"
                and isinstance(self.runtime, LocalRuntime)):
            from .factory_project import validate_review_stop
            result = json.loads(operation["result"])
            expected = self.root / "evidence" / operation["mission"] / (operation["id"] + ".raw")
            if result.get("stdout_path") != str(expected):
                raise FactoryBlocked("UNKNOWN", "review lifecycle belongs to another paid operation")
            spec = json.loads(self.row(operation["mission"])["spec"])
            validate_review_stop(spec, Path(self.row(operation["mission"])["candidate"]),
                                 json.loads(operation["identity"])["target"], operation["lane"], result)
        evidence = Path(operation["evidence"] or "")
        if not evidence.is_file() or evidence.is_symlink() or evidence.resolve() != evidence or hashlib.sha256(evidence.read_bytes()).hexdigest() != operation["evidence_hash"]:
            raise FactoryBlocked("UNKNOWN", "operation evidence is missing or changed")
        if operation["stage"] == "plan":
            try:
                envelope = json.loads(evidence.read_bytes())
                expected = {"operation": operation["id"], "identity": json.loads(operation["identity"]),
                            "input": json.loads(operation["input"]), "result": json.loads(operation["result"])}
                if envelope != expected:
                    raise ValueError("planning envelope differs from its operation")
            except (OSError, ValueError, TypeError) as error:
                raise FactoryBlocked("UNKNOWN", "planning evidence binding is invalid") from error
        for raw in json.loads(operation["result"]).get("raw_evidence", []):
            path = Path(raw["path"])
            if not path.is_file() or path.is_symlink() or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != raw["sha256"]:
                raise FactoryBlocked("UNKNOWN", "raw execution evidence is missing or changed")
        for raw in json.loads(operation["result"]).get("project_evidence", []):
            path = Path(raw["path"])
            if not path.is_file() or path.is_symlink() or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != raw["sha256"]:
                raise FactoryBlocked("UNKNOWN", "canonical project evidence is missing or changed")

    def guard_plan_cache_miss(self, mission):
        """Agent preparation hook: after cache/stop checks, before reservation."""
        completed = self.db.execute(
            "SELECT * FROM operations WHERE mission=? AND stage='plan' AND status='COMPLETE'",
            (mission,)).fetchall()
        for plan in completed:
            self.verify_evidence(plan)
        if completed:
            # A changed prompt/profile is not authority to buy another plan
            # or repeat implementation against the same candidate.
            raise FactoryBlocked("BLOCKED_LIMIT", "completed plan key differs; no new paid planning or implementation authorized")

    def agent(self, spec, cwd, stage, round_, payload):
        candidate_stage.check_dispatch(self, spec["mission_id"], stage)
        if self.project:
            approval = approved_scope(spec)
            payload = {**payload, "mission_scope_file": approval["path"], "mission_scope_sha256": approval["sha256"]}
        lane = "developer"
        profile, profile_identity = self.developer_binding(spec)
        identity = {"profile": profile_identity, "engine": "codex-app-server", "stage": stage,
                    "repository": spec["repository"], "base": spec["base"], "dispatch_head": git(cwd, "rev-parse", "HEAD"),
                    "scope": spec["scope"]}
        key = digest({"stage": stage, "round": round_, "profile": profile_identity, "payload": payload})
        if stage == "plan":
            # Dispatch facts are not part of the cache key: a checkpoint may
            # advance HEAD before a completed plan is consumed on resume. They
            # still belong in the durable input and evidence for this dispatch.
            payload = {**payload, "workspace": {
                "base": spec["base"], "dispatch_head": identity["dispatch_head"],
                "branch": git(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
                "has_remotes": bool(git(cwd, "remote")),
            }}
        call_payload = dict(payload)
        if "model_selection" in profile_identity and not self.config["simulation"]:
            call_payload["_authorized_route"] = profile_identity["route_identity"]
        return self.operation(spec["mission_id"], key, stage, lane, identity, payload, True,
                              lambda transcript, prepared=None: self.runtime.agent(stage, profile, cwd, call_payload, transcript,
                                                                                  self.operation_timeout(spec["mission_id"]),
                                                                                  [self.root, Path(spec["repository"])]),
                              prepare=(lambda: self.guard_plan_cache_miss(spec["mission_id"])) if stage == "plan" else None)

    def review_context(self, spec, cwd, target, lane):
        # Fresh, isolated repository for EACH lane. It has no prior findings,
        # plan/implementation conversation, test logs or factory evidence.
        path = self.root / "reviews" / spec["mission_id"] / digest({"target": target, "lane": lane})
        if not path.exists():
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            git(cwd, "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", str(cwd), str(path))
            git(path, "remote", "remove", "origin")
            git(path, "checkout", "--detach", target["head"])
        if self.target(spec, path) != target:
            raise FactoryBlocked("UNKNOWN", "review checkout differs from exact delivery target")
        return path

    def review(self, spec, cwd, target, lane):
        if self.project:
            return self.project_review(spec, cwd, target, lane)
        profile = self.config["profiles"][lane]
        review_cwd = self.review_context(spec, cwd, target, lane)
        from .factory_runtime import REVIEW_SCHEMA
        payload = {"objective": spec["objective"], "acceptance": spec["acceptance"], "constraints": spec["constraints"],
                   "target": target, "review_root": str(review_cwd), "required_output_schema": REVIEW_SCHEMA,
                   "instruction": "Review the ENTIRE base..head diff and surrounding repository code using the official rubric. Return JSON matching required_output_schema. Every absolute_file_path must be under review_root, NOT target.repository; source lines must overlap this diff. Do not modify code.",
                   "diff": git(review_cwd, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--no-renames", target["base"], target["head"], "--")}
        if lane == "second_reviewer":
            if "GIT binary patch" in payload["diff"]:
                raise FactoryBlocked("BLOCKED_SCOPE", "independent text reviewer cannot certify binary changes")
            context, size = {}, 0
            for name in filter(None, git(review_cwd, "ls-tree", "-r", "--name-only", "-z", target["head"]).split("\0")):
                mode = git(review_cwd, "ls-tree", target["head"], "--", name).split()[0]
                if mode not in ("100644", "100755"):
                    continue
                try:
                    text = git(review_cwd, "show", f"{target['head']}:{name}")
                except UnicodeDecodeError:
                    continue
                if "\0" in text:
                    continue
                size += len(text.encode())
                if size > self.config["max_context_bytes"]:
                    raise FactoryBlocked("BLOCKED_SCOPE", "independent full source context exceeds authorized capacity; nothing was truncated")
                context[name] = text
            payload["repository_context"] = context
        rubric = json.loads((VENDOR / "provenance.json").read_text())
        identity = {"target": target, "profile": self.profile_identities[lane], "engine": "codex-official-rubric-structured-turn" if lane == "reviewer" else "deepseek-chat-completions",
                    "rubric": rubric}
        key = digest(identity)
        if lane == "reviewer":
            invoke = lambda transcript: self.runtime.agent("review", profile, review_cwd, payload, transcript,
                                                           self.operation_timeout(spec["mission_id"]),
                                                           [self.root, Path(spec["repository"])] )
        else:
            invoke = lambda transcript: self.runtime.second_review(profile, review_cwd, payload, transcript,
                                                                   self.operation_timeout(spec["mission_id"]))
        # Only a PROVEN completed result can get one fresh formatting/source
        # validation attempt. Dispatch uncertainty is never retried by operation().
        for attempt in range(2):
            attempt_key = key if attempt == 0 else digest({"review": key, "validation_attempt": attempt})
            result = self.operation(spec["mission_id"], attempt_key, "review", lane, identity, payload, True, invoke)
            if self.target(spec, review_cwd) != target:
                raise FactoryBlocked("UNKNOWN", "reviewer mutated its exact target")
            try:
                verdict, findings = review_verdict(result.get("output"), review_cwd, target)
            except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                self.event(spec["mission_id"], "review_validation_unknown", {"key": attempt_key, "reason": str(exc)})
                self.db.commit()
                if attempt == 1:
                    raise FactoryBlocked("UNKNOWN", f"review contract/source validation failed after bounded recovery: {exc}") from exc
            else:
                key = attempt_key
                break
        return {"status": verdict, "findings": findings, "output": result["output"], "evidence_key": key,
                "provider": profile["provider"], "profile": profile, "profile_identity": self.profile_identities[lane],
                "lane": lane, "target": target}

    def project_review(self, spec, cwd, target, lane):
        if lane not in review_lanes(target) or lane not in configured_review_lanes(self.config):
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "review lane is not enabled")
        identity = {"target": target, "backend": BACKENDS[LANES[lane]],
                    "policy": target["project_policy"], "engine": "project-canonical-runner"}
        payload = {"target": target, "review_range": target["review_range"], "lane": lane}
        key = digest(identity)
        def prepare():
            try:
                if Path(cwd).absolute() != Path(self.row(spec["mission_id"])["candidate"]):
                    raise ValueError("canonical review must use the Controller-owned candidate")
                # parents=True during clone preparation can leave this owned
                # intermediate directory group-writable under umask 0002.
                private_dir(self.root / "candidates")
                private_dir(Path(cwd).parent)
                if not self.config["simulation"]:
                    if self.target(spec, cwd) != target:
                        raise ValueError("candidate changed before review admission")
                    admission = self.runtime.project_review_admission(spec, cwd, target, self.config.get("project_review_limits"))
                    self.event(spec["mission_id"], "review_admission", {"lane": lane, "admission": admission})
                    self.db.commit()
                runner = self.runtime.prepare_project_review(spec, cwd, target, lane,
                    self.operation_timeout(spec["mission_id"]))
                return runner if self.config["simulation"] else {"runner": runner, "admission": admission}
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", f"canonical local preparation failed: {exc}") from exc
        result = self.operation(spec["mission_id"], key, "review", lane, identity, payload, True,
            lambda transcript, prepared: self.runtime.project_review(spec, cwd, target, lane, transcript,
                self.operation_timeout(spec["mission_id"]), prepared=prepared),
            prepare=prepare)
        if self.target(spec, cwd) != target:
            raise FactoryBlocked("UNKNOWN", "canonical reviewer changed the exact target")
        try:
            self.verify_evidence(self.db.execute(
                "SELECT * FROM operations WHERE mission=? AND key=?", (spec["mission_id"], key)).fetchone())
            checked = self.runtime.project_validate_review(spec, cwd, target, lane, result)
            if checked.status not in {"PASS", "FAIL"} or not checked.artifact or not isinstance(checked.data, dict):
                raise ValueError("project validator has no current receipt verdict")
            findings = checked.data.get("findings")
            if not isinstance(findings, list):
                raise ValueError("canonical receipt omitted findings")
            if result.get("fixture", False) is not self.config["simulation"]:
                raise ValueError("fixture/live canonical evidence mismatch")
        except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
            raise FactoryBlocked("UNKNOWN", f"canonical receipt validation failed: {exc}") from exc
        # Do not lower the existing Factory barrier without an Owner decision.
        status = "PASS" if checked.status == "PASS" and not findings else "FAIL"
        return {"status": status, "findings": findings,
                "output": {"overall_explanation": checked.evidence},
                "evidence_key": key, "provider": "openai" if lane == "reviewer" else "deepseek",
                "lane": lane, "backend": BACKENDS[LANES[lane]], "target": target,
                "canonical_receipt": checked.artifact, "canonical_receipt_data": checked.data,
                "canonical_execution": result,
                "review_range": target["review_range"], "fixture": self.config["simulation"]}

    def observation_result(self, spec, payload, result):
        from .factory_remote import identity
        branch, _ = identity(payload["policy"], spec, payload["target"])
        expected = payload.get("expected_pr")
        if (not isinstance(result, dict) or result.get("target") != payload["target"] or result.get("fixture") is not False
                or result.get("repository") != payload["policy"]["repository"] or result.get("pr_repo") != payload["policy"]["repository"]
                or result.get("branch") != branch or result.get("pr_base_sha") != payload["target"]["base"]
                or result.get("body_sha256") != hashlib.sha256(payload["body"].encode()).hexdigest()
                or type(result.get("pr_number")) is not int or result["pr_number"] <= 0
                or (expected is not None and expected != {k: result[k] for k in ("pr_number", "pr_repo", "pr_base_sha")})):
            raise FactoryBlocked("UNKNOWN", "remote observation does not bind the exact repository/PR/candidate/body")
        return result

    def validate_observation_recovery(self, mission, original, proof):
        """Re-derive a narrow read-only recovery from immutable operation evidence."""
        stages = {"project_reconcile": "reconcile", "project_ci": "ci", "project_verify": "verify"}
        if (not self.project or original is None or proof is None or original["paid"] or proof["paid"]
                or original["status"] != "UNKNOWN" or proof["status"] != "COMPLETE"
                or original["stage"] not in stages or original["stage"] != proof["stage"]
                or original["lane"] != "github" or proof["lane"] != "github"
                or original["ended"] is None or proof["started"] < original["ended"] or original["id"] == proof["id"]):
            raise FactoryBlocked("UNKNOWN", "recovery is restricted to ended unpaid remote observations")
        payload = json.loads(original["input"])
        if (payload != json.loads(proof["input"]) or payload.get("action") != stages[original["stage"]]
                or not isinstance(payload.get("expected_pr"), dict)
                or payload["policy"] != self.config.get("project_delivery")):
            raise FactoryBlocked("UNKNOWN", "observation kind/policy/known PR binding changed")
        spec = json.loads(self.row(mission)["spec"])
        # The new observation checks the current candidate before becoming
        # COMPLETE. A historical exact-target relation remains evidence about
        # that target; it does not certify any later candidate's delivery.
        for operation in (original, proof):
            self.verify_evidence(operation)
            envelope = json.loads(Path(operation["evidence"]).read_text())
            if (envelope != {"operation": operation["id"], "identity": json.loads(operation["identity"]),
                            "input": payload, "result": json.loads(operation["result"])}
                    or json.loads(operation["identity"]) != payload):
                raise FactoryBlocked("UNKNOWN", "observation evidence differs from durable operation binding")
        result = self.observation_result(spec, payload, json.loads(proof["result"]))
        if result.get("status") != "PASS":
            raise FactoryBlocked("UNKNOWN", "fresh observation did not establish successful verification")

    def project_remote_read(self, action, spec, cwd, target, body, reviews=None, expected_pr=None):
        if action not in {"reconcile", "ci", "verify"}:
            raise FactoryBlocked("UNKNOWN", "only canonical read-only observation kinds are supported")
        self.require_project_validation(spec, cwd, target)
        payload = {"target": target, "policy": self.config["project_delivery"], "body": body,
                   "action": action, "reviews": reviews or [], "expected_pr": None}
        # A first discovery may establish a PR, but cannot retroactively prove
        # an unknown numeric PR. Automatic recovery requires a previously bound PR.
        if expected_pr is None:
            for old in self.db.execute("SELECT * FROM operations WHERE mission=? AND paid=0 AND lane='github' AND status='COMPLETE' ORDER BY started DESC", (spec["mission_id"],)):
                old_payload = json.loads(old["input"])
                if all(old_payload.get(k) == payload[k] for k in ("target", "policy", "body")):
                    self.verify_evidence(old)
                    expected_pr = self.observation_result(spec, payload, json.loads(old["result"]))
                    break
        if expected_pr is not None:
            keys = {"pr_number", "pr_repo", "pr_base_sha"}
            if set(expected_pr) == keys:
                if (type(expected_pr["pr_number"]) is not int or expected_pr["pr_number"] <= 0
                        or expected_pr["pr_repo"] != payload["policy"]["repository"]
                        or expected_pr["pr_base_sha"] != target["base"]):
                    raise FactoryBlocked("UNKNOWN", "invalid expected numeric PR binding")
                payload["expected_pr"] = dict(expected_pr)
            else:
                checked = self.observation_result(spec, payload, expected_pr)
                payload["expected_pr"] = {k: checked[k] for k in keys}
        key = digest({"action": action, **payload, "observation": uuid.uuid4().hex})
        def observe(transcript):
            result = self.runtime.project_remote(action, payload["policy"], spec, cwd, target, body, transcript,
                                                 self.operation_timeout(spec["mission_id"]), reviews=reviews)
            self.observation_result(spec, payload, result)
            if self.target(spec, cwd) != target:
                raise FactoryBlocked("UNKNOWN", "candidate changed during remote operation")
            return result
        result = self.operation(spec["mission_id"], key, "project_reconcile" if action == "reconcile" else "project_" + action,
            "github", payload, payload, False, observe)
        if result.get("status") == "PASS" and payload["expected_pr"] is not None:
            proof = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (spec["mission_id"], key)).fetchone()
            for original in self.uncertain_operations(spec["mission_id"]):
                if original["status"] != "UNKNOWN" or original["stage"] != proof["stage"] or original["input"] != encoded(payload):
                    continue
                self.validate_observation_recovery(spec["mission_id"], original, proof)
                self.event(spec["mission_id"], "remote_observation_recovered", {"operation_id": original["id"], "evidence_key": key})
            self.db.commit()
        return {**result, "evidence_key": key}

    def recover_publication(self, spec, cwd, operation):
        payload = json.loads(operation["input"])
        if self.target(spec, cwd) != payload["target"] or payload["policy"] != self.config.get("project_delivery"):
            raise FactoryBlocked("UNKNOWN", "uncertain publication belongs to another candidate/policy; no write retried")
        proof = self.project_remote_read("reconcile", spec, cwd, payload["target"], payload["body"])
        if proof["status"] != "PASS":
            raise FactoryBlocked("UNKNOWN", "uncertain publication could not be observed; no write retried")
        self.event(spec["mission_id"], "publication_reconciled", {"operation_id": operation["id"], "evidence_key": proof["evidence_key"]})
        self.db.commit()
        return proof

    def project_pr_ci(self, spec, cwd, target, reviews, validations):
        from .factory_remote import render_body
        policy = self.config.get("project_delivery")
        if policy is None:
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "Controller project PR publication policy missing")
        if self.target(spec, cwd) != target:
            raise FactoryBlocked("UNKNOWN", "candidate changed before PR publication")
        required = self.require_project_validation(spec, cwd, target)
        required_keys = {item["evidence_key"] for item in required}
        validations = [item for item in validations if item.get("evidence_key") not in required_keys] + required
        body = render_body(policy, spec, target, reviews, validations)
        payload = {"target": target, "policy": policy, "body": body}
        key = digest({"project_publish": payload})
        old = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (spec["mission_id"], key)).fetchone()
        if old is not None and old["status"] != "COMPLETE":
            publication = self.recover_publication(spec, cwd, old)
        else:
            previous_head = None
            for previous in self.db.execute("SELECT * FROM operations WHERE mission=? AND stage IN ('project_publish','project_reconcile') AND status='COMPLETE' ORDER BY started", (spec["mission_id"],)):
                self.verify_evidence(previous)
                value = json.loads(previous["result"])
                if value.get("status") == "PASS":
                    previous_head = value["target"]["head"]
            publication = self.operation(spec["mission_id"], key, "project_publish", "github", payload, payload, False,
                lambda transcript: self.runtime.project_remote("publish", policy, spec, cwd, target, body, transcript,
                    self.operation_timeout(spec["mission_id"]), reviews=reviews, previous_head=previous_head))
            if publication.get("status") != "PASS" or publication.get("target") != target or publication.get("fixture") is not False:
                raise FactoryBlocked("UNKNOWN", "publication did not establish exact live PR identity")
            # Cached success is never current remote truth.
            publication = self.project_remote_read("reconcile", spec, cwd, target, body, expected_pr=publication)
        ci = self.project_remote_read("ci", spec, cwd, target, body, expected_pr=publication)
        if ci["status"] not in {"PASS", "FAIL"}:
            raise FactoryBlocked("BLOCKED_CI", ci.get("reason", "required exact PR checks are unfinished/unknown"))
        return {"publication": publication, "ci": ci, "body": body}

    def project_final_gate(self, spec, cwd, target, reviews, remote=None):
        self.require_project_validation(spec, cwd, target)
        if {r["lane"] for r in reviews} != set(review_lanes(target)) or any(r["status"] != "PASS" for r in reviews):
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "selected validated canonical receipts are required")
        context = None
        if "project_pr_ci" in self.config:
            context = self.project_ci_context(spec, cwd, target, remote or [])
        if not self.config["simulation"] and "project_delivery" in self.config:
            if remote is None or remote["ci"]["status"] != "PASS":
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "exact live PR/CI context missing")
            checked = self.project_remote_read("verify", spec, cwd, target, remote["body"], reviews, expected_pr=remote["publication"])
            if checked["status"] != "PASS":
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", checked.get("reason", "canonical final gate rejected delivery"))
            return checked
        payload = {"target": target, "receipts": {r["backend"]: r["canonical_receipt"] for r in reviews},
                   **({"context": context} if context is not None else {})}
        key = digest({"project_final_gate": payload})
        result = self.operation(spec["mission_id"], key, "project_gate", "project", payload, payload, False,
            lambda transcript: self.runtime.project_final_gate(spec, cwd, target, reviews, transcript,
                                                               self.operation_timeout(spec["mission_id"]),
                                                               **({"context": context} if context is not None else {})))
        if (result.get("status") != "PASS" or result.get("target") != target
                or result.get("fixture") is not self.config["simulation"]):
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", result.get("reason", "project final validator rejected candidate"))
        if not self.config["simulation"] and context is None:
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "exact PR/CI context is required")
        return {**result, "evidence_key": key}

    def project_ci_context(self, spec, cwd, target, ci):
        results = [r for r in ci if r.get("department") == "project_pr_ci"]
        if len(results) != 1:
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "exact PR CI evidence is missing")
        try:
            context = self.runtime.project_validate_ci(self.config["project_pr_ci"], spec, cwd, target,
                                                       results[0], refresh=True)
        except Exception as exc:
            raise FactoryBlocked("UNKNOWN", "PR CI evidence rejected: " + str(exc)) from exc
        return {k: context[k] for k in ("pr_number", "pr_repo", "pr_base_sha", "ci_status")}

    def approve_pr_publication(self, mission, expected_head, reason, body, expires_seconds=3600):
        """Record separate human publication approval. This method performs no remote write."""
        from datetime import datetime, timedelta, timezone
        from .factory_pr_ci import branch_for, digest as policy_digest, PUBLICATION_ACTIONS
        if not self.project or "project_pr_ci" not in self.config or not isinstance(reason, str) or not reason.strip():
            raise ValueError("project PR publication needs explicit policy and human reason")
        bounded_int(expires_seconds, "publication approval lifetime", 1, 86400)
        row = self.row(mission)
        if self.db.execute("SELECT 1 FROM operations WHERE mission=? AND status IN ('RUNNING','UNKNOWN')", (mission,)).fetchone():
            raise ValueError("unresolved operation prevents publication authorization")
        spec, cwd = json.loads(row["spec"]), Path(row["candidate"])
        target = self.target(spec, cwd)
        if target["head"] != expected_head or not target["files"] or git(cwd, "status", "--porcelain", "--untracked-files=all"):
            raise ValueError("publication requires the clean frozen exact candidate HEAD")
        if not isinstance(body, str) or f"Mission scope contract: `{target['mission_scope_file']}`" not in body:
            raise ValueError("approved PR body must name the frozen canonical mission scope")
        policy = self.config["project_pr_ci"]
        approval = {"approval_id": uuid.uuid4().hex,
                    "identity": {"mission_id": mission, "repository": policy["repository"], "base": target["base"],
                                 "head": target["head"], "tree": target["tree"], "branch": branch_for(spec, target),
                                 "policy_sha256": policy_digest(policy), "actions": PUBLICATION_ACTIONS.copy()},
                    "body": body, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=expires_seconds)).isoformat()}
        self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?)",
                        (approval["approval_id"], mission, encoded(target), "publish-pr", reason, time.time()))
        self.event(mission, "pr_publication_approval", approval)
        self.db.commit()
        return {"APPROVAL": "RECORDED", "ACTION": "publish-pr", "TARGET_HEAD": expected_head,
                "REMOTE_PR_CREATED": False, "MERGE_PERFORMED": False}

    def publication_approval(self, spec, target):
        from .factory_pr_ci import validate_approval
        row = self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='pr_publication_approval' ORDER BY sequence DESC LIMIT 1",
                              (spec["mission_id"],)).fetchone()
        try:
            approval = json.loads(row[0]) if row else None
            validate_approval(approval, self.config["project_pr_ci"], spec, target)
            return approval
        except Exception as exc:
            raise FactoryBlocked("BLOCKED_PUBLICATION_AUTH", str(exc)) from exc

    def project_validation_binding(self, spec, cwd, target):
        """Bind new strict executions to this task, source, contract and executor.

        The full target is reconstructed by the existing trusted-base policy
        path, never from a caller's profile declaration or reduced path list.
        No old gate/fixture result is upgraded to this execution format.
        """
        if self.target(spec, cwd) != target:
            raise FactoryBlocked("UNKNOWN", "validation candidate/task/policy changed")
        from .factory_project import tracked_source_digest
        try:
            source = tracked_source_digest(cwd, target["head"], require_committed=True)
        except (OSError, ValueError) as exc:
            raise FactoryBlocked("UNKNOWN", "validation source bytes/mode changed: " + str(exc)) from exc
        policy = self.config.get("project_container")
        if policy is None or "strict" not in policy["profiles"] or not policy.get("postgres_image_id"):
            raise FactoryBlocked("BLOCKED_VALIDATION", "make verify-strict requires Controller authorization and pinned dev/PostgreSQL images; no profile added or downgraded")
        implementations = ("factory.py", "factory_container.py", "factory_test_service.py",
                           "factory_runtime.py", "factory_project.py", "adapters.py")
        return {"version": "factory-strict-execution/v1", "mission_id": spec["mission_id"],
                "spec_sha256": digest(spec), "target": target, "profile": "strict", "source_sha256": source,
                "container_policy": policy, "simulation": self.config["simulation"],
                "timeout_seconds": self.config["timeout_seconds"],
                "executor_sha256": digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                           for name in implementations})}

    def check_project_strict_result(self, spec, target, result):
        if (result.get("status") != "PASS" or type(result.get("exit_code")) is not int or result["exit_code"] != 0
                or result.get("profile") != "strict" or result.get("fixture") is not False
                or result.get("target") != target or result.get("mission_id") != spec["mission_id"]
                or result.get("scope_sha256") != target["mission_scope_sha256"]
                or result.get("container_policy") != self.config["project_container"]
                or result.get("image_id") != self.config["project_container"]["image_id"]):
            raise FactoryBlocked("BLOCKED_VALIDATION", "current make verify-strict has no bound successful container execution")

    def require_project_validation(self, spec, cwd, target):
        """Consume actual strict success before publication, recovery and READY.

        STRICT's pre-PR requirement comes from the fixed original contract.
        NORMAL and CRITICAL retain their existing paths; simulation never
        establishes live success. Configuration only permits execution.
        """
        if not self.project or self.config["simulation"]:
            return []
        current = self.target(spec, cwd)
        if current != target:
            raise FactoryBlocked("UNKNOWN", "validation candidate/task/policy changed")
        workflow = current["project_policy"].get("workflow_class")
        if workflow not in {"NORMAL", "STRICT", "CRITICAL"}:
            raise FactoryBlocked("BLOCKED_VALIDATION", "original workflow classification unavailable")
        if "trusted_validation" in self.config:
            if workflow not in {"STRICT", "CRITICAL"}:
                return []
            # Main's formal executor has its own established evidence schema.
            # Consume its actual strict operation; never translate it into a
            # Controller container receipt or accept a configured profile alone.
            from .factory_project import tracked_source_digest
            from .factory_validation import validate_result
            tracked_source_digest(cwd, target["head"], require_committed=True)
            for op in self.db.execute("SELECT * FROM operations WHERE mission=? AND stage='checks' "
                                      "AND lane='local' AND status='COMPLETE' ORDER BY started DESC",
                                      (spec["mission_id"],)):
                payload = json.loads(op["input"])
                if (op["paid"] or op["ended"] is None
                        or set(payload) != {"command", "target", "round", "validation", "mission_id"}
                        or payload["command"] != ["make", "verify-strict"]
                        or payload["target"] != target or payload["mission_id"] != spec["mission_id"]
                        or payload["validation"] != self.config["trusted_validation"]
                        or json.loads(op["identity"]) != {"target": target}):
                    continue
                self.verify_evidence(op)
                result = json.loads(op["result"])
                if json.loads(Path(op["evidence"]).read_text()) != {
                        "operation": op["id"], "identity": {"target": target},
                        "input": payload, "result": result}:
                    raise FactoryBlocked("UNKNOWN", "trusted strict operation envelope changed")
                try:
                    validate_result(result, self.config["trusted_validation"], spec, target, "strict", False)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    raise FactoryBlocked("BLOCKED_VALIDATION", "trusted strict execution rejected: " + str(exc)) from exc
                if result["status"] != "PASS":
                    raise FactoryBlocked("BLOCKED_VALIDATION", "trusted strict execution failed")
                return [{**result, "evidence_key": op["key"]}]
            raise FactoryBlocked("BLOCKED_VALIDATION", "current successful trusted strict execution is missing; configuration or old evidence cannot substitute")
        if workflow != "STRICT":
            return []
        binding = self.project_validation_binding(spec, cwd, target)
        payload = {"command": ["make", "verify-strict"], "target": target, "validation_binding": binding}
        key = digest({"canonical_validation": binding})
        op = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (spec["mission_id"], key)).fetchone()
        if (op is None or op["status"] != "COMPLETE" or op["stage"] not in {"checks", "ci"}
                or op["lane"] != "local" or op["paid"] or op["ended"] is None
                or json.loads(op["input"]) != payload
                or json.loads(op["identity"]) != {"target": target, "validation_binding": binding}):
            raise FactoryBlocked("BLOCKED_VALIDATION", "STRICT requires an actually successful current make verify-strict before PR; configured targeted/PR or unexecuted strict cannot substitute; no extra dispatch authorized")
        self.verify_evidence(op)
        result = json.loads(op["result"])
        if json.loads(Path(op["evidence"]).read_text()) != {
                "operation": op["id"], "identity": json.loads(op["identity"]), "input": payload, "result": result}:
            raise FactoryBlocked("UNKNOWN", "strict operation envelope/binding changed")
        self.check_project_strict_result(spec, target, result)
        return [{**result, "evidence_key": key}]

    def gates(self, spec, cwd, target, kind, round_):
        candidate_stage.check_dispatch(self, spec["mission_id"], kind)
        if candidate_stage.requested(spec) and kind == "checks":
            round_ = getattr(self, "_single_qa_round", round_)
        results = []
        for index, command in enumerate(self.config[kind]):
            validation = self.config.get("trusted_validation")
            if validation and kind == "checks" and target.get("project_policy", {}).get("workflow_class") in {"STRICT", "CRITICAL"} and command != ["make", "verify-strict"]:
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "STRICT/CRITICAL require the formal strict validation profile")
            payload = {"command": command, "target": target, "round": round_,
                       **({"validation": validation, "mission_id": spec["mission_id"]} if validation else {})}
            key = digest({"kind": kind, "index": index, **payload})
            strict = False
            if validation:
                result = self.operation(spec["mission_id"], key, kind, "local", {"target": target}, payload, False,
                                        lambda transcript: self.runtime.project_validation(validation, spec, command, cwd, target, transcript, self.operation_timeout(spec["mission_id"]))
                                        if validation else self.runtime.gate(command, cwd, target, transcript, self.operation_timeout(spec["mission_id"])))
                if validation:
                    from .factory_validation import validate_result, profile_for
                    try:
                        validate_result(result, validation, spec, target, profile_for(command), self.config["simulation"])
                    except Exception as exc:
                        raise FactoryBlocked("UNKNOWN", "trusted validation rejected: " + str(exc)) from exc
            else:
                identity = {"target": target}
                strict = self.project and not self.config["simulation"] and command == ["make", "verify-strict"]
                if strict:
                    binding = self.project_validation_binding(spec, cwd, target)
                    payload = {"command": command, "target": target, "validation_binding": binding}
                    identity = {"target": target, "validation_binding": binding}
                    # Same valid strict execution can satisfy checks/ci and resume;
                    # a new round alone does not require another expensive run.
                    key = digest({"canonical_validation": binding})
                def invoke(transcript):
                    if self.project and not self.config["simulation"]:
                        if "project_container" not in self.config:
                            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "Controller container policy is required; host fallback forbidden")
                        return self.runtime.container_gate(self.config["project_container"], spec, cwd, target, command,
                                                           transcript, self.operation_timeout(spec["mission_id"]))
                    return self.runtime.gate(command, cwd, target, transcript, self.operation_timeout(spec["mission_id"]))
                result = self.operation(spec["mission_id"], key, kind, "local", identity, payload, False, invoke)
                if self.project and not self.config["simulation"]:
                    if (result.get("target") != target or result.get("fixture") is not False
                            or result.get("image_id") != self.config["project_container"]["image_id"]):
                        raise FactoryBlocked("UNKNOWN", "container evidence identity mismatch")
                    if result.get("status") not in {"PASS", "FAIL"}:
                        raise FactoryBlocked("BLOCKED_VALIDATION", result.get("status", "container validation unavailable"))
            if result.get("status") not in ("PASS", "FAIL") or type(result.get("exit_code")) is not int or (result["status"] == "PASS") != (result["exit_code"] == 0):
                raise FactoryBlocked("UNKNOWN", "test/CI command lacks a proven exit status")
            if self.target(spec, cwd) != target:
                raise FactoryBlocked("UNKNOWN", "test/CI changed the reviewed target")
            if strict and result["status"] == "PASS":
                self.check_project_strict_result(spec, target, result)
            results.append({**result, "evidence_key": key})
        if kind == "ci" and "project_pr_ci" in self.config:
            self.require_project_validation(spec, cwd, target)
            policy = self.config["project_pr_ci"]
            approval = self.publication_approval(spec, target)
            payload = {"target": target, "policy": policy, "approval_id": approval["approval_id"],
                       "runner_sha256": hashlib.sha256(Path(__file__).with_name("factory_pr_ci.py").read_bytes()).hexdigest()}
            key = digest({"project_pr_ci": payload})
            result = self.operation(spec["mission_id"], key, "project_pr_ci", "github", payload, payload, False,
                lambda transcript: self.runtime.project_ci(policy, spec, cwd, target, approval, transcript,
                                                          self.operation_timeout(spec["mission_id"])))
            if result.get("status") == "BLOCKED_PUBLICATION_AUTH":
                from .factory_pr_ci import digest as policy_digest
                if (result.get("target") != target or result.get("mission_id") != spec["mission_id"]
                        or result.get("fixture") is not self.config["simulation"]
                        or result.get("policy_sha256") != policy_digest(policy)
                        or result.get("approval_id") != approval["approval_id"]
                        or result.get("publication_progress") not in (
                            {"push": "NOT_STARTED", "create_pr": "NOT_STARTED"},
                            {"push": "COMPLETE", "create_pr": "NOT_STARTED"})
                        or result.get("MERGE_PERFORMED") is not False):
                    raise FactoryBlocked("UNKNOWN", "publication stop identity or partial state is unknown")
                raise FactoryBlocked("BLOCKED_PUBLICATION_AUTH", result["reason"])
            try:
                self.runtime.project_validate_ci(policy, spec, cwd, target, result, refresh=True)
            except Exception as exc:
                raise FactoryBlocked("UNKNOWN", "PR CI evidence rejected: " + str(exc)) from exc
            if self.target(spec, cwd) != target:
                raise FactoryBlocked("UNKNOWN", "PR CI candidate HEAD/tree changed")
            results.append({**result, "evidence_key": key, "department": "project_pr_ci"})
        if kind == "ci" and "hosted_ci" in self.config:
            policy = self.config["hosted_ci"]
            branch = f"factory/{spec['mission_id']}-{target['head'][:12]}"
            payload = {"target": target, "policy": policy, "branch": branch,
                       "runner_sha256": hashlib.sha256(Path(__file__).with_name("factory_hosted.py").read_bytes()).hexdigest()}
            key = digest({"kind": "hosted_ci", **payload})
            result = self.operation(spec["mission_id"], key, "hosted_ci", "github", payload, payload, False,
                       lambda transcript: self.runtime.hosted_ci(policy, cwd, target, branch, transcript, self.operation_timeout(spec["mission_id"])))
            if result.get("status") not in ("PASS", "FAIL") or result.get("target") != target:
                raise FactoryBlocked("UNKNOWN", "hosted CI has no exact-target proven result")
            try:
                if result["repository"] != policy["repository"] or result["branch"] != branch or result["MERGE_PERFORMED"] is not False or set(result["runs"]) != set(policy["workflows"]):
                    raise ValueError("hosted identity/workflow mismatch")
                all_success = True
                for workflow_runs in result["runs"].values():
                    if not workflow_runs:
                        raise ValueError("hosted workflow evidence missing")
                    for run in workflow_runs:
                        if type(run["databaseId"]) is not int or run["databaseId"] <= 0 or run["headSha"] != target["head"] or run["event"] != "push" or run["status"] != "completed" or run["url"] != f"https://github.com/{policy['repository']}/actions/runs/{run['databaseId']}":
                            raise ValueError("hosted run is not an exact completed GitHub push check")
                        jobs = result["jobs"][str(run["databaseId"])]
                        if not jobs or any(j["status"] != "completed" for j in jobs):
                            raise ValueError("hosted matrix/job evidence missing or incomplete")
                        all_success &= run["conclusion"] == "success" and all(j["conclusion"] == "success" for j in jobs)
                if (result["status"] == "PASS") != all_success:
                    raise ValueError("hosted verdict contradicts run/job evidence")
            except (KeyError, TypeError, ValueError) as exc:
                raise FactoryBlocked("UNKNOWN", f"hosted evidence validation failed: {exc}") from exc
            if self.target(spec, cwd) != target:
                raise FactoryBlocked("UNKNOWN", "hosted CI candidate HEAD/tree changed")
            results.append({**result, "evidence_key": key, "department": "hosted_ci"})
        return results

    def active_temporary_allocation(self, mission, operation, identity, read):
        """Report-only, pending assessment; never a stop/cleanup proof or replay permit.

        The kernel lock owner, original operation and private allocation must agree.
        Once present, the supervisor journal additionally binds this execution. A
        constructor/close handoff may be incomplete, but cannot establish readiness.
        """
        from .appserver_process import process_identity
        execution = self.db.execute("SELECT payload,at FROM events WHERE mission=? AND kind='controller_execution' "
                                    "ORDER BY sequence DESC LIMIT 1", (mission,)).fetchone()
        if execution is None or operation["started"] < execution["at"]:
            raise ValueError("temporary allocation belongs to no current controller execution")
        execution = json.loads(execution["payload"])
        lock = self.root / "control" / f"{mission}.lock"
        info = lock.lstat()
        if not stat.S_ISREG(info.st_mode) or lock.is_symlink() or info.st_uid != os.getuid():
            raise ValueError("active controller lock identity differs")
        device = f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}"
        with open("/proc/locks", "rb") as stream:
            locks = stream.read(1024 * 1024 + 1)
        if len(locks) > 1024 * 1024:
            raise ValueError("active controller locks exceed inspection capacity")
        owners = [int(v[4]) for line in locks.decode().splitlines() if
                  len(v := line.split()) == 8 and v[1:4] == ["FLOCK", "ADVISORY", "WRITE"]
                  and v[5] == device and v[6:] == ["0", "EOF"]]
        if len(owners) != 1:
            raise ValueError("temporary allocation has no live mission controller lock")
        controller = process_identity(owners[0])
        if (controller["uid"] != os.getuid() or controller["state"] in ("Z", "X")
                or any(controller[k] != v for k, v in execution["controller"].items() if k != "state")
                or execution["lock"] != {"device": info.st_dev, "inode": info.st_ino}):
            raise ValueError("active mission controller identity is unavailable")
        spec = json.loads(self.row(mission)["spec"])
        original = json.loads(operation["identity"])
        if (operation["mission"] != mission or operation["lane"] != "developer"
                or operation["stage"] not in ("implement", "rework") or not operation["paid"]
                or (operation["status"] == "RUNNING") != (operation["ended"] is None)
                or any(original.get(k) != v for k, v in {
                    "stage": operation["stage"], "repository": spec["repository"],
                    "base": spec["base"], "scope": spec["scope"], "engine": "codex-app-server"}.items())):
            raise ValueError("active temporary operation binding differs")
        transcript = self.root / "evidence" / mission / (operation["id"] + ".raw")
        journal = transcript.with_suffix(".process.jsonl")
        if identity is None:
            if (operation["status"] != "RUNNING" or operation["result"] is not None
                    or operation["evidence"] is not None or journal.exists() or journal.is_symlink()):
                raise ValueError("temporary allocation record is incomplete outside startup")
            return {"operation": operation["id"], "status": "PENDING", "phase": "STARTING"}
        rows = []
        if journal.exists() or journal.is_symlink():
            data = read(journal, None)
            # One bounded snapshot can end during an append. Validate every
            # complete row; an unfinished tail supplies no additional proof.
            rows = [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith(b"\n")]
            if data and not rows:
                raise ValueError("active temporary journal has no complete binding")
        if rows:
            binding, supervisor = rows[0]["binding"], rows[0]["supervisor"]
            events = [v.get("event") for v in rows]
            if (events not in (["allocated"], ["allocated", "started"], ["allocated", "started", "stopped"])
                    or any(v.get("binding") != binding or v.get("supervisor") != supervisor for v in rows)
                    or rows[0]["at"] < operation["started"]
                    or binding.get("worktree") != identity["worktree"]
                    or binding.get("permission_profile") != identity["permission_profile"]
                    or binding.get("temporary_workspace") != identity or binding.get("operation") != str(transcript)
                    or binding.get("context", {}) != {"mission_id": mission, "runtime_execution": execution["runtime_execution"]}
                    or any(not isinstance(v, str) or re.fullmatch(r"[0-9a-f]{32}", v) is None
                           for v in (binding.get("execution_id"), binding.get("context", {}).get("runtime_execution")))
                    or supervisor.get("ppid") != controller["pid"] or supervisor.get("uid") != controller["uid"]
                    or supervisor.get("pid") != supervisor.get("pgid") or supervisor.get("pid") != supervisor.get("sid")):
                raise ValueError("active temporary execution/resource binding differs")
            native = (json.loads(operation["result"] or "{}").get("runtime_identity") or {}).get("native_runtime", {})
            if native and (native.get("temporary_workspace") != identity
                           or native.get("process_ownership") != {"binding": binding, "supervisor": supervisor}):
                raise ValueError("active temporary original execution differs")
            if events[-1] == "stopped":
                stop = rows[-1]["result"]
                if (stop.get("confirmed") is not True or stop.get("proof") != "ECHILD"
                        or stop.get("binding") != binding
                        or stop.get("supervisor") != {k:v for k,v in supervisor.items() if k != "state"}):
                    raise ValueError("active temporary execution stop is unconfirmed")
            else:
                actual = process_identity(supervisor["pid"])
                if actual["state"] in ("Z", "X") or any(actual[k] != v for k, v in supervisor.items() if k != "state"):
                    raise ValueError("active temporary supervisor identity changed")
        elif operation["status"] != "RUNNING" or operation["result"] is not None or operation["evidence"] is not None:
            raise ValueError("temporary final operation lacks original execution journal")
        path = Path(identity["path"])
        if path.exists() or path.is_symlink():
            actual = path.lstat()
            if (path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISDIR(actual.st_mode)
                    or (actual.st_dev, actual.st_ino, actual.st_uid, oct(stat.S_IMODE(actual.st_mode))) !=
                       (identity["device"], identity["inode"], identity["uid"], identity["mode"])):
                raise ValueError("active temporary directory identity changed")
        elif not rows or rows[-1]["event"] != "stopped":
            raise ValueError("active temporary directory disappeared before confirmed stop")
        receipt = transcript.with_suffix(".temp.cleanup.jsonl")
        if receipt.exists() or receipt.is_symlink():
            if not rows or rows[-1]["event"] != "stopped":
                raise ValueError("active temporary cleanup precedes confirmed execution stop")
            data = read(receipt, None)
            for line in data.splitlines(keepends=True):
                if not line.endswith(b"\n"):
                    break  # In-progress receipt write is still only PENDING.
                entry = json.loads(line)
                if (entry.get("cleanup_confirmed") is not True or entry.get("identity") != identity
                        or entry.get("process_stop") != rows[-1]["result"]):
                    raise ValueError("active temporary cleanup is unconfirmed or foreign")
        # This is intentionally PENDING even after ECHILD: immutable final
        # operation/receipt binding is still required after the controller exits.
        return {"operation": operation["id"], "status": "PENDING",
                "phase": "FINALIZING" if rows and rows[-1]["event"] == "stopped" else
                         "EXECUTING" if len(rows) == 2 else "STARTING"}

    def verify_temporary_cleanup(self, mission, *, allow_active=False):
        """Strict by default; public reports may describe bound active work as pending."""
        try:
            candidate = self.row(mission)["candidate"]
            root = self.root / "evidence" / mission
            allocations, proofs, native_identities, process_owners = {}, [], [], {}
            pending, operations = {}, {}
            def read(path, expected_hash):
                info = path.lstat()
                if (path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 65536):
                    raise ValueError("untrusted temporary cleanup evidence")
                data = path.read_bytes()
                if expected_hash is not None and hashlib.sha256(data).hexdigest() != expected_hash:
                    raise ValueError("temporary cleanup evidence hash changed")
                return data
            for operation in self.db.execute("SELECT * FROM operations WHERE mission=?", (mission,)):
                result = json.loads(operation["result"] or "{}")
                raw = result.get("raw_evidence", [])
                allocation = root / (operation["id"] + ".temp.json")
                entries = [v for v in raw if v["path"] == str(allocation)]
                native_runtime = (result.get("runtime_identity") or {}).get("native_runtime", {})
                native = native_runtime.get("temporary_workspace")
                if native is not None:
                    native_identities.append(native)
                    if native_runtime.get("process_ownership") is not None:
                        if native["path"] in process_owners and process_owners[native["path"]] != native_runtime["process_ownership"]:
                            raise ValueError("temporary allocation execution ownership changed")
                        process_owners[native["path"]] = native_runtime["process_ownership"]
                if entries or allocation.exists() or allocation.is_symlink():
                    unfinished = (allow_active and operation["status"] == "RUNNING"
                                  and operation["result"] is None and operation["evidence"] is None)
                    if (not unfinished and len(entries) != 1) or operation["lane"] != "developer":
                        raise ValueError("temporary allocation lacks original operation binding")
                    if not unfinished:
                        self.verify_evidence(operation)
                        original = json.loads(Path(operation["evidence"]).read_bytes())
                        if original != {"operation": operation["id"], "identity": json.loads(operation["identity"]),
                                        "input": json.loads(operation["input"]), "result": result}:
                            raise ValueError("temporary allocation differs from immutable operation evidence")
                    data = read(allocation, None if unfinished else entries[0]["sha256"])
                    if unfinished and not data.endswith(b"\n"):
                        pending[operation["id"]] = self.active_temporary_allocation(mission, operation, None, read)
                        continue  # An in-progress constructor write is not an allocation/cleanup proof.
                    identity = json.loads(data)
                    if (not isinstance(identity, dict) or identity.get("worktree") != candidate
                            or Path(identity["path"]).parent != Path("/tmp")
                            or identity.get("uid") != os.getuid() or identity.get("mode") != "0o700"
                            or any(type(identity.get(k)) is not int for k in ("device", "inode"))
                            or not isinstance(identity.get("permission_profile"), str)):
                        raise ValueError("temporary allocation candidate/directory identity differs")
                    reference = {"path": str(allocation), "sha256": hashlib.sha256(data).hexdigest()}
                    allocations[operation["id"]] = (identity, reference)
                    operations[operation["id"]] = operation
                    if unfinished:
                        pending[operation["id"]] = self.active_temporary_allocation(mission, operation, identity, read)
                    receipt = allocation.with_suffix(".cleanup.jsonl")
                    proofs.extend((operation["id"], v, None) for v in raw if v["path"] == str(receipt))
            for event in self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='agent_temporary_cleanup' ORDER BY sequence", (mission,)):
                payload = json.loads(event[0])
                if payload.get("cleanup_confirmed") is not True:
                    raise ValueError("task temporary cleanup is unconfirmed; no replay or resource adoption")
                source = payload.get("operation_id")
                if (payload.get("mission_id") != mission or source not in allocations
                        or payload.get("allocation") != allocations[source][1]
                        or payload.get("identity") != allocations[source][0]):
                    raise ValueError("temporary cleanup event task/operation/allocation binding differs")
                proofs.append((source, payload["evidence"], payload))
            covered = set()
            for source, evidence, event in proofs:
                identity, allocation = allocations[source]
                receipt = Path(allocation["path"]).with_suffix(".cleanup.jsonl")
                if evidence["path"] != str(receipt):
                    raise ValueError("temporary cleanup receipt path binding differs")
                rows = [json.loads(line) for line in read(receipt, evidence["sha256"]).splitlines()]
                if not rows or any(v.get("cleanup_confirmed") is not True or v.get("identity") != identity for v in rows):
                    raise ValueError("temporary cleanup receipt contains unconfirmed or foreign allocation")
                owner = process_owners.get(identity["path"])
                for entry in rows:
                    stop = entry.get("process_stop")
                    if owner is not None:
                        binding = owner["binding"]
                        if (not isinstance(stop, dict) or stop.get("confirmed") is not True
                                or stop.get("proof") != "ECHILD" or stop.get("binding") != binding
                                or stop.get("supervisor") != {k:v for k,v in owner["supervisor"].items() if k != "state"}
                                or binding.get("temporary_workspace") != identity
                                or binding.get("operation") != str(root / (source + ".raw"))
                                or binding.get("context", {}).get("mission_id") != mission):
                            raise ValueError("temporary cleanup lacks its original execution stop proof")
                    elif stop is not None and stop.get("confirmed") is not True:
                        raise ValueError("temporary cleanup execution stop is unconfirmed")
                if event is not None and any(event.get(k) != rows[-1].get(k) for k in ("identity", "cleanup_confirmed", "at")):
                    raise ValueError("temporary cleanup event differs from original receipt")
                covered.add(source)
            for source in set(allocations) - covered:
                if allow_active:
                    pending[source] = self.active_temporary_allocation(mission, operations[source], allocations[source][0], read)
                else:
                    raise ValueError("temporary allocation has no confirmed cleanup proof")
            if any(v not in [a[0] for a in allocations.values()] for v in native_identities):
                raise ValueError("temporary allocation has no confirmed cleanup proof")
            return list(pending.values())
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise FactoryBlocked("UNKNOWN", "temporary cleanup evidence invalid: " + str(error)) from error

    def verify_container_client_stops(self, mission):
        """Read only; neither a late event nor container absence supplies stops."""
        if not self.project or self.config["simulation"] or "project_container" not in self.config:
            return
        from .factory_container import client_stop_evidence, LIFECYCLE_LIMIT, temporary_binding
        try:
            for operation in self.db.execute("SELECT * FROM operations WHERE mission=? AND paid=0 "
                                             "AND stage IN ('checks','ci')", (mission,)):
                result = json.loads(operation["result"] or "{}")
                transcript = self.root / "evidence" / mission / (operation["id"] + ".raw")
                lifecycle = transcript.with_suffix(".container.json")
                if not result.get("lifecycle_record") and not lifecycle.exists():
                    payload = json.loads(operation["input"])
                    if ("trusted_validation" in self.config
                            and payload.get("validation") == self.config["trusted_validation"]):
                        continue  # The distinct formal executor has its own receipt.
                    raise ValueError("container client lifecycle/stop evidence is missing")
                with os.fdopen(os.open(lifecycle, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > LIFECYCLE_LIMIT):
                        raise ValueError("untrusted container lifecycle evidence")
                    raw = stream.read(LIFECYCLE_LIMIT + 1)
                if len(raw) > LIFECYCLE_LIMIT:
                    raise ValueError("container lifecycle evidence exceeds capacity")
                record = json.loads(raw)
                payload = json.loads(operation["input"])
                spec = json.loads(self.row(mission)["spec"])
                identity = record["temporary_directory_identity"]
                if (not isinstance(identity, dict) or record["mission_id"] != mission
                        or record.get("target_sha256") != digest(payload["target"])
                        or identity.get("binding") != temporary_binding(spec, payload["target"], record["container_name"], transcript)):
                    raise ValueError("container client lifecycle task/operation/target changed")
                proof = client_stop_evidence(transcript, record, raw)
                if operation["evidence"]:
                    self.verify_evidence(operation)
                    if (json.loads(Path(operation["evidence"]).read_bytes()) != {
                            "operation": operation["id"], "identity": json.loads(operation["identity"]),
                            "input": payload, "result": result}
                            or result.get("local_clients_stop_confirmed") is not True
                            or result.get("client_stop_evidence") != proof
                            or {"path": proof["path"], "sha256": proof["sha256"]} not in result.get("raw_evidence", [])):
                        raise ValueError("container client stop evidence lacks its immutable operation binding")
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise FactoryBlocked("UNKNOWN", "container local clients not confirmed stopped: " + str(error)) from error

    def report(self, mission):
        temporary_error, pending = None, []
        # SQLite settlement and filesystem receipts are not one transaction.
        # Re-read once on rejection, without waiting, adopting resources or writing state.
        for _ in range(2):
            mission_row = self.row(mission)
            try:
                pending = self.verify_temporary_cleanup(mission, allow_active=True)
                self.verify_container_client_stops(mission)
                temporary_error = None
                break
            except FactoryBlocked as error:
                temporary_error = error.reason
        report = self._report(mission, temporary_error, pending, mission_row=mission_row)
        report["TEMPORARY_CLEANUP"] = {"status": "INVALID" if temporary_error else "PENDING" if pending else "VERIFIED",
                                       "operations": pending}
        if "model_routing" in self.config:
            from .factory_routing import observation
            event = self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='submitted'", (mission,)).fetchone()
            decision = json.loads(event[0])["routing_executor"]["model_selection"]
            operations = self.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started", (mission,)).fetchall()
            report["MODEL_ROUTING"] = observation(decision, operations)
        return report

    def _report(self, mission, temporary_error=None, temporary_pending=None, *, mission_row=None):
        from .factory_remote import project_branch
        # Do not promote a later terminal status using an earlier cleanup snapshot.
        row = self.row(mission) if mission_row is None else mission_row
        if temporary_error is not None:
            row = {**dict(row), "status": "UNKNOWN", "reason": temporary_error}
        elif temporary_pending:
            row = {**dict(row), "status": "RUNNING" if row["status"] in (READY, OFFLINE_PASS, "CANCELLED") else row["status"],
                   "reason": "temporary cleanup verification pending for active mission controller"}
        operations = self.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started", (mission,)).fetchall()
        events = self.db.execute("SELECT kind,payload FROM events WHERE mission=? ORDER BY sequence", (mission,)).fetchall()
        spec = json.loads(row["spec"])
        if candidate_stage.requested(spec):
            preflights = [json.loads(e["payload"]) for e in events if e["kind"] == "prepaid_preflight"]
            return candidate_stage.report(self, row, operations, preflights, events)
        deliveries = [json.loads(e["payload"]) for e in events if e["kind"] == "delivery"]
        delivery = deliveries[-1] if deliveries else {}
        preflights = [json.loads(e["payload"]) for e in events if e["kind"] == "prepaid_preflight"]
        status, reason = row["status"], row["reason"]
        fresh = None
        if status == READY or self.project and status == OFFLINE_PASS:
            try:
                spec, cwd = json.loads(row["spec"]), Path(row["candidate"])
                if self.project and status == READY and (self.config["simulation"] or not {"project_pr_ci", "project_delivery"} & set(self.config)):
                    raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "live readiness requires explicit PR CI and live evidence")
                if self.target(spec, cwd) != delivery.get("target"):
                    raise FactoryBlocked("UNKNOWN", "delivery HEAD/tree/scope changed after verification")
                for validation in self.require_project_validation(spec, cwd, delivery["target"]):
                    if validation["evidence_key"] not in delivery["evidence_keys"]:
                        raise FactoryBlocked("UNKNOWN", "required strict operation absent from delivery evidence")
                if not delivery.get("target", {}).get("files") or not isinstance(delivery.get("implemented"), str) or not delivery["implemented"].strip():
                    raise FactoryBlocked("UNKNOWN", "delivery implementation/change evidence is missing")
                expected_lanes = set(configured_review_lanes(self.config))
                if {r["lane"] for r in delivery.get("reviews", [])} != expected_lanes:
                    raise FactoryBlocked("UNKNOWN", "required independent reviewer evidence is missing")
                for key in delivery["evidence_keys"]:
                    operation = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, key)).fetchone()
                    if operation is None or operation["status"] != "COMPLETE":
                        raise FactoryBlocked("UNKNOWN", "delivery evidence is incomplete")
                    self.verify_evidence(operation)
                for review in delivery["reviews"]:
                    if self.project:
                        key = review["evidence_key"]
                        if key not in delivery["evidence_keys"]:
                            raise FactoryBlocked("UNKNOWN", "review operation is absent from delivery evidence")
                        op = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, key)).fetchone()
                        if op is None or op["stage"] != "review" or op["lane"] != review["lane"]:
                            raise FactoryBlocked("UNKNOWN", "review operation identity mismatch")
                        checked = self.runtime.project_validate_review(spec, cwd, delivery["target"], review["lane"], json.loads(op["result"]))
                        if (checked.status != "PASS" or checked.artifact != review["canonical_receipt"]
                                or checked.data != review["canonical_receipt_data"] or checked.data.get("findings")
                                or review["status"] != "PASS"):
                            raise FactoryBlocked("UNKNOWN", "canonical validator no longer approves the recorded receipt")
                    elif review["profile_identity"] != self.profile_identities[review["lane"]]:
                        raise FactoryBlocked("PENDING_REVIEW", "review lane configuration changed; only that lane requires fresh evidence")
                if self.project:
                    if "trusted_validation" in self.config:
                        from .factory_validation import validate_result, profile_for
                        recorded = delivery.get("validation_results", {})
                        for kind in ("checks", "ci"):
                            local = [r for r in recorded.get(kind, []) if not r.get("department")]
                            if len(local) != len(self.config[kind]):
                                raise FactoryBlocked("UNKNOWN", "formal validation evidence missing")
                            for command, result in zip(self.config[kind], local):
                                if result["evidence_key"] not in delivery["evidence_keys"]:
                                    raise FactoryBlocked("UNKNOWN", "validation absent from delivery evidence")
                                validate_result(result, self.config["trusted_validation"], spec, delivery["target"],
                                                profile_for(command), self.config["simulation"])
                    if "project_pr_ci" in self.config:
                        context = self.project_ci_context(spec, cwd, delivery["target"], delivery.get("validation_results", {}).get("ci", []))
                        if not self.config["simulation"]:
                            transcript = self.root / "evidence" / mission / ("report-final-" + uuid.uuid4().hex + ".raw")
                            fresh = self.runtime.project_final_gate(spec, cwd, delivery["target"],
                                delivery["reviews"], transcript, 60, context=context)
                            if fresh["status"] != "PASS":
                                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", fresh.get("reason", "canonical final consumer unconfirmed"))
                    gate = delivery["project_gate"]
                    if gate["evidence_key"] not in delivery["evidence_keys"] or gate.get("fixture") is not self.config["simulation"]:
                        raise FactoryBlocked("UNKNOWN", "project gate evidence is incomplete")
                    op = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, gate["evidence_key"])).fetchone()
                    if (op is None or op["stage"] != ("project_verify" if not self.config["simulation"] and "project_delivery" in self.config else "project_gate") or json.loads(op["result"]).get("status") != "PASS"
                            or json.loads(op["result"]).get("target") != delivery["target"]):
                        raise FactoryBlocked("UNKNOWN", "project final gate evidence is missing or rejected")
                    if not self.config["simulation"] and "project_delivery" in self.config:
                        fresh = self.project_remote_read("verify", spec, cwd, delivery["target"], delivery["remote"]["body"], delivery["reviews"], expected_pr=delivery["remote"]["publication"])
                        if fresh["status"] != "PASS":
                            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", fresh.get("reason", "remote PR/CI/final gate is no longer current"))
            except FactoryBlocked as exc:
                status, reason = exc.status, exc.reason
            except Exception as exc:
                status, reason = "UNKNOWN", str(exc)
        verified = status == READY or self.project and status == OFFLINE_PASS
        operations = self.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started", (mission,)).fetchall()
        return {"MISSION": mission, "DELIVERY_STATUS": status,
                "REVIEW_MODE": "single_openai" if configured_review_lanes(self.config) == ("reviewer",) else "dual",
                "SECOND_REVIEW_STATUS": "NOT_ENABLED" if configured_review_lanes(self.config) == ("reviewer",) else "REQUIRED",
                "CURRENT_REMOTE_VERIFICATION": fresh if fresh is not None else "NOT_RUN",
                "PREPAID_PREFLIGHT": preflights[-1] if preflights else "NOT_RUN",
                "IMPLEMENTED": delivery.get("implemented", "UNKNOWN"),
                "TEST_RESULT": delivery.get("tests", "UNKNOWN") if verified else "UNKNOWN",
                "CI_RESULT": delivery.get("ci", "UNKNOWN") if verified else "UNKNOWN",
                "REVIEW_RESULT": delivery.get("reviews", "UNKNOWN") if verified else "UNKNOWN",
                "BLOCKERS_REMAINING": ["live validation, exact PR/CI and business delivery are not established"] if self.project and status == OFFLINE_PASS else [] if status == READY else [reason or status],
                "PROJECT_CONTRACT": PROJECT if self.project else "NOT_CONFIGURED",
                "PROJECT_ACCEPTANCE": "OFFLINE_FIXTURE_ONLY" if self.project and status == OFFLINE_PASS else ("MERGE_READY" if "project_pr_ci" in self.config else "EXACT_PR_PREMERGE_VERIFIED") if self.project and status == READY else "NOT_ESTABLISHED",
                "DONE": False,
                "KNOWN_RISKS": delivery.get("risks", []),
                "BUDGET_USED": {**accounting(operations, self.config["budget"]),
                                "money": "UNKNOWN" if not self.config["simulation"] else "FIXTURE_NO_PROVIDER_COST"},
                "LOCAL_CI": delivery.get("ci", "UNKNOWN") if status == READY else "UNKNOWN",
                "HOSTED_CI": delivery.get("hosted_ci", "NOT_CONFIGURED") if status == READY else "UNKNOWN" if {"hosted_ci", "project_pr_ci", "project_delivery"} & set(self.config) else "NOT_CONFIGURED",
                "PROJECT_PR_CI": [r.get("context") for r in delivery.get("validation_results", {}).get("ci", [])
                                  if r.get("department") == "project_pr_ci"] if verified else "NOT_ESTABLISHED",
                "PROJECT_PR": delivery.get("remote", {}).get("publication", "NOT_RUN") if verified else "UNKNOWN",
                "TARGET_HEAD": delivery.get("target", {}).get("head", "UNKNOWN"),
                "EXACT_TARGET": delivery.get("target", "UNKNOWN"),
                "DELIVERY_EVIDENCE": [op["evidence"] for op in operations if op["evidence"]],
                "CANDIDATE": row["candidate"],
                "CANDIDATE_BRANCH": project_branch(json.loads(row["spec"])) if self.project else f"factory/{mission}",
                "SIMULATION": self.config["simulation"],
                "HUMAN_APPROVAL_REQUIRED": ["merge", "release"], "MERGE_PERFORMED": False}

    def cancel_requested(self, mission):
        return (self.root / "control" / f"{mission}.cancel").is_file()

    def cancel(self, mission):
        self.row(mission)
        path = self.root / "control" / f"{mission}.cancel"
        with path.open("a") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        self.event(mission, "cancel_requested", {"authority": "user"})
        self.db.commit()
        return {"MISSION": mission, "CANCELLATION": "REQUESTED", "DISPATCH_REPLAY": False,
                "NOTE": "Current process is stopped by the controller; reservations are retained."}

    def operation_timeout(self, mission):
        timeout = self.config["timeout_seconds"]
        limit = self.config["budget"].get("max_wall_seconds")
        if limit:
            started = self.db.execute("SELECT MIN(at) FROM events WHERE mission=? AND kind='submitted'", (mission,)).fetchone()[0]
            timeout = min(timeout, max(1, int(limit - (time.time() - started))))
        return timeout

    def run(self, mission):
        self.row(mission)
        lock = self.root / "control" / f"{mission}.lock"
        with lock.open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {**self.report(mission), "DELIVERY_STATUS": "RUNNING", "BLOCKERS_REMAINING": ["another controller owns this mission"]}
            pending = self.runtime.unconfirmed_appserver() if hasattr(self.runtime, "unconfirmed_appserver") else None
            if pending:
                # A retry is a read-only UNKNOWN assessment, not an attempt to
                # create a replacement execution or reconstruct missing proof.
                return {**self.report(mission), "DELIVERY_STATUS": "UNKNOWN", "BLOCKERS_REMAINING": [pending]}
            import threading
            stopped = threading.Event()
            execution = self.runtime.begin_execution(mission) if hasattr(self.runtime, "begin_execution") else None
            def watch_cancel():
                while not stopped.wait(0.2):
                    if self.cancel_requested(mission) and hasattr(self.runtime, "cancel"):
                        if execution is not None:
                            self.runtime.cancel(execution)
                        else:
                            self.runtime.cancel()
            if hasattr(self.runtime, "resource_policy"):
                self.runtime.resource_policy = self.config["budget"]
            watcher = threading.Thread(target=watch_cancel, daemon=True)
            watcher.start()
            cleanup = None
            try:
                if execution is not None:
                    from .appserver_process import process_identity
                    info = os.fstat(stream.fileno())
                    self.event(mission, "controller_execution", {
                        "controller": process_identity(os.getpid()),
                        "runtime_execution": getattr(self.runtime, "_execution_id", None),
                        "lock": {"device": info.st_dev, "inode": info.st_ino}})
                    self.db.commit()
                result = self._run(mission)
            finally:
                stopped.set()
                watcher.join(timeout=1)
                try:
                    if hasattr(self.runtime, "close_session"):
                        from .task_temp import TaskTempError
                        try:
                            cleanup = self.runtime.close_session()
                        except TaskTempError as error:
                            self.event(mission, "agent_temporary_cleanup", {"cleanup_confirmed": False,
                                       "identity": error.identity, "error": str(error)})
                            self.state(mission, "UNKNOWN", str(error))
                            raise FactoryBlocked("UNKNOWN", str(error)) from error
                        if cleanup is not None:
                            cleanup = {**cleanup, "mission_id": mission,
                                       "operation_id": Path(cleanup.get("allocation", {}).get("path", "")).name.removesuffix(".temp.json")}
                            self.event(mission, "agent_temporary_cleanup", cleanup)
                            self.db.commit()
                finally:
                    if execution is not None:
                        self.runtime.end_execution(execution)
            # Single-session receipts are created only by the finally above.
            # Do not return the earlier, pre-cleanup delivery assessment.
            return self.report(mission) if cleanup is not None else result

    def recover_interrupted_containers(self, mission):
        """Cleanup only: no candidate preparation, dispatch replay or settlement."""
        cleanups = []
        if not self.project or self.config["simulation"] or "project_container" not in self.config:
            return cleanups
        spec = json.loads(self.row(mission)["spec"])
        for pending in self.db.execute("SELECT * FROM operations WHERE mission=? AND paid=0 "
                                       "AND stage IN ('checks','ci') AND status IN ('RUNNING','UNKNOWN','COMPLETE')",
                                       (mission,)).fetchall():
            try:
                payload = json.loads(pending["input"])
                transcript = self.root / "evidence" / mission / (pending["id"] + ".raw")
                if pending["status"] == "COMPLETE":
                    # COMPLETE means the check returned, not that all its
                    # resources disappeared. Trust only its immutable proof.
                    self.verify_evidence(pending)
                    result = json.loads(pending["result"])
                    proof = json.loads(Path(pending["evidence"]).read_text())
                    lifecycle = str(transcript.with_suffix(".container.json"))
                    if (proof != {"operation": pending["id"], "identity": json.loads(pending["identity"]),
                                  "input": payload, "result": result}
                            or result.get("target") != payload["target"] or result.get("mission_id") != mission
                            or result.get("lifecycle_record") != lifecycle
                            or not any(raw["path"] == lifecycle for raw in result.get("raw_evidence", []))):
                        raise ValueError("completed container cleanup proof is incomplete or mismatched")
                    if all(result.get(key) is True for key in ("cleanup_confirmed", "dependencies_cleanup_confirmed",
                                                              "temporary_directory_cleanup_confirmed")):
                        # Already-cleaned resources still require original stop
                        # evidence; the operation's hash is checked above.
                        from .factory_container import client_stop_evidence
                        record = json.loads(Path(lifecycle).read_bytes())
                        proof = client_stop_evidence(transcript, record, Path(lifecycle).read_bytes())
                        if (result.get("local_clients_stop_confirmed") is not True
                                or result.get("client_stop_evidence") != proof):
                            raise ValueError("completed container local stop evidence is missing or changed")
                        continue
                cleanup = self.runtime.recover_container(self.config["project_container"], spec, payload["target"],
                                                         payload["command"], transcript)
            except Exception as error:
                cleanup = {"cleanup_confirmed": False, "operation_replayed": False, "status": "UNKNOWN",
                           "error_type": type(error).__name__}
            cleanups.append(cleanup)
            self.event(mission, "container_cleanup_recovered", {"operation_id": pending["id"], "cleanup": cleanup})
            self.db.commit()  # Append evidence only; the operation/UNKNOWN is immutable.
        return cleanups

    def _run(self, mission):
        try:
            self.verify_temporary_cleanup(mission)
            cleanups = self.recover_interrupted_containers(mission)
            self.verify_container_client_stops(mission)
            if self.cancel_requested(mission):
                note = ("; cleanup confirmed" if all(c.get("cleanup_confirmed") for c in cleanups)
                        else "; cleanup not confirmed; see exact operation evidence") if cleanups else ""
                raise FactoryBlocked("CANCELLED", "user cancelled; no dispatch or validation replay authorized" + note)
            authority_spec = json.loads(self.row(mission)["spec"])
            if candidate_stage.requested(authority_spec):
                return self._run_local_candidate(authority_spec, Path(self.row(mission)["candidate"]), self.row(mission))
            spec, cwd = self.prepare(mission)
            row = self.row(mission)
            for pending in self.uncertain_operations(mission):
                if pending["id"] not in {p["id"] for p in self.uncertain_operations(mission)}:
                    continue
                if self.project and pending["stage"] == "project_publish":
                    self.recover_publication(spec, cwd, pending)
                    self.state(mission, "PR_CI", "publication observed; original UNKNOWN/reservation retained")
                    row = self.row(mission)
            for pending in self.uncertain_operations(mission):
                if pending["id"] not in {p["id"] for p in self.uncertain_operations(mission)}:
                    continue
                payload = json.loads(pending["input"])
                if (self.project and pending["status"] == "UNKNOWN" and not pending["paid"]
                        and pending["stage"] in {"project_reconcile", "project_ci", "project_verify"}
                        and payload.get("expected_pr") and payload.get("action")
                        and payload.get("policy") == self.config.get("project_delivery")
                        and self.target(spec, cwd) == payload.get("target")):
                    proof = self.project_remote_read(payload["action"], spec, cwd, payload["target"], payload["body"],
                                                     payload["reviews"], expected_pr=payload["expected_pr"])
                    if proof["status"] == "PASS" and row["status"] == "UNKNOWN":
                        self.state(mission, "PR_CI", "fresh exact read-only evidence; original UNKNOWN retained")
                        row = self.row(mission)
            uncertain = self.uncertain_operations(mission)
            if uncertain:
                raise FactoryBlocked("UNKNOWN", f"unresolved operation {uncertain[0]['id']}; no duplicate paid dispatch was authorized")
            if self.project and row["status"] == OFFLINE_PASS:
                return self.report(mission)
            if row["status"] == READY:
                observed = self.report(mission)
                if observed["DELIVERY_STATUS"] == READY:
                    return observed
                if observed["DELIVERY_STATUS"] != "PENDING_REVIEW":
                    raise FactoryBlocked(observed["DELIVERY_STATUS"], observed["BLOCKERS_REMAINING"][0])
                # A model/profile change does not authorize rewriting delivered
                # source, replaying tests or calling the unaffected provider.
                delivery = json.loads(self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='delivery' ORDER BY sequence DESC LIMIT 1", (mission,)).fetchone()[0])
                self.state(mission, "REVIEW")
                lanes = configured_review_lanes(self.config)
                reviews = [self.review(spec, cwd, delivery["target"], lane) for lane in lanes]
                feedback = [{"department": r["lane"], "findings": r["findings"], "explanation": r["output"]["overall_explanation"]} for r in reviews if r["status"] != "PASS"]
                if not feedback:
                    delivery["reviews"] = reviews
                    delivery["evidence_keys"] = [op[0] for op in self.db.execute("SELECT key FROM operations WHERE mission=? AND status='COMPLETE'", (mission,))]
                    self.event(mission, "delivery", delivery)
                    self.state(mission, READY)
                    return self.report(mission)
                self.db.execute("UPDATE missions SET round=round+1 WHERE id=?", (mission,))
                self.event(mission, "rework", {"target": delivery["target"], "feedback": feedback})
                self.state(mission, "REWORK")
                row = self.row(mission)
            if row["status"] == "BLOCKED_PREFLIGHT":
                if self.db.execute("SELECT 1 FROM operations WHERE mission=? AND paid=1 LIMIT 1", (mission,)).fetchone():
                    return self.report(mission)
                # First-paid operation rechecks preflight and appends a fresh
                # event. Preserve spec, policy, round, submission time and usage.
                self.state(mission, "PLAN")
            elif row["status"] in ("UNKNOWN", "BLOCKED_BUDGET", "BLOCKED_SCOPE", "BLOCKED_LIMIT", "BLOCKED_VALIDATION"):
                return self.report(mission)
            planning_payload = {"objective": spec["objective"], "acceptance": spec["acceptance"], "constraints": spec["constraints"],
                                "execution_guidance": (
                                    "Follow all applicable repository instructions, scope, authorization contracts and acceptance requirements. "
                                    "Only instructions confirmed automatically loaded at the same version need not be printed in full again. "
                                    "Read missing or changed instructions, required workflow documents and applicable nested rules. "
                                    "Use the Controller workspace facts for BASE and dispatch identity; if has_remotes is false, "
                                    "do not query origin/main or fetch. Batch independent reads where appropriate, "
                                    "use targeted searches and necessary excerpts, and return the bounded plan once information is sufficient. "
                                    "Never omit necessary context or requirements to save tokens."),
                                "scope": spec["scope"], "instruction": (
                                    "Act as technical lead. Understand the repository, plan a minimal complete solution and acceptance tests. "
                                    "Authorization facts belong in the mission constraints, supplied by the Controller before freezing the input. "
                                    "Distinguish preparation pending approval from explicit Controller-verified execution authority: "
                                    "use the stated source, versions, scope, budget and window without requesting the same approval again. "
                                    "This instruction, task submission and user tone are not proof of approval; Factory does not authenticate "
                                    "human approval. Report missing or conflicting authority rather than assuming it. "
                                    "The current PLAN session is intentionally read-only, with no writable temporary workspace. "
                                    "Implementation runs later in separate sessions; the existing runtime allocates and checks their "
                                    "authorized candidate writes and private temporary resources. PLAN's read-only permissions alone "
                                    "do not establish a Builder permission defect, and future environment readiness is not yet proven. "
                                    "Report concrete permission conflicts or missing prerequisites if observed. "
                                    "Each tasks entry becomes one separately charged implementation assignment, including its product "
                                    "regression tests; tasks is not a list of delivery stages. Do not put Harness validation, independent "
                                    "review, Controller checkpoints, PR publication or release work in tasks. Split implementation only "
                                    "as needed within the remaining operation budget, leaving room for the configured independent reviews; "
                                    "do not assume one task for every project or promise room for rework. "
                                    "Decide ordinary engineering questions yourself. Only unresolved major product ambiguity, safety, "
                                    "independence, authority, budget or irreversible changes belong in decisions_required. "
                                    "Do not edit files, execute tests, perform review or prepare release receipts during planning. "
                                    "Return the complete plan, bounded implementation tasks, acceptance and genuine decisions_required "
                                    "once change locations, requirements, authority boundaries, verification route and unresolved facts are clear.")}
            # Reconciliation may find an implementation awaiting its controller
            # checkpoint. A cached plan is read before touching that working tree.
            plan = self.agent(spec, cwd, "plan", 0, planning_payload).get("output")
            if not isinstance(plan, dict) or set(plan) != {"plan", "tasks", "acceptance", "decisions_required"} or not isinstance(plan["plan"], str) or not plan["plan"].strip() or any(not isinstance(plan[k], list) or any(not isinstance(t, str) or not t.strip() for t in plan[k]) for k in ("tasks", "acceptance", "decisions_required")):
                raise FactoryBlocked("UNKNOWN", "technical lead did not provide a valid bounded plan")
            if plan["decisions_required"]:
                raise FactoryBlocked("WAITING_PRODUCT_DECISION", "; ".join(plan["decisions_required"]))
            if not 1 <= len(plan["tasks"]) <= 8:
                raise FactoryBlocked("UNKNOWN", "technical lead task count is outside the bounded contract")
            if row["round"] == 0 and "max_total_tokens" in self.config["budget"]:
                remaining = self.config["budget"]["max_agent_runs"] - self.db.execute("SELECT COUNT(*) FROM operations WHERE mission=? AND paid=1", (mission,)).fetchone()[0]
                if len(plan["tasks"]) + len(configured_review_lanes(self.config)) > remaining:
                    raise FactoryBlocked("BLOCKED_BUDGET", "plan cannot fit implementation and independent review in authorized remaining runs")
            feedback = []
            if row["round"]:
                previous = self.db.execute("SELECT payload FROM events WHERE mission=? AND kind='rework' ORDER BY sequence DESC LIMIT 1", (mission,)).fetchone()
                feedback = json.loads(previous[0])["feedback"]
            while self.row(mission)["round"] < self.config["max_rounds"]:
                round_ = self.row(mission)["round"]
                if round_ == 0:
                    payload = {"objective": spec["objective"], "acceptance": spec["acceptance"], "constraints": spec["constraints"],
                               "scope": spec["scope"], "plan": plan, "instruction": "Implement your assigned task, including regression tests, in the shared candidate repository. Other planned tasks are handled in separate official Codex threads. You own ordinary engineering decisions. Do not commit, merge, release, contact providers, or change external resources. The controller checkpoints your files. Return summary and known_risks."}
                    stage = "implement"
                else:
                    payload = {"objective": spec["objective"], "acceptance": spec["acceptance"], "constraints": spec["constraints"],
                               "scope": spec["scope"], "plan": plan, "feedback": feedback,
                               "instruction": "Fix all test, CI and review findings autonomously. Add regression tests. Preserve requirements and production behavior. Do not commit, merge or release. Return summary and known_risks."}
                    stage = "rework"
                self.state(mission, "IMPLEMENT" if round_ == 0 else "REWORK")
                assignments = [{**payload, "task_index": index, "current_task": task} for index, task in enumerate(plan["tasks"])] if round_ == 0 else [payload]
                outputs = []
                for assignment in assignments:
                    output = self.agent(spec, cwd, stage, round_, assignment).get("output")
                    if not isinstance(output, dict) or set(output) != {"summary", "known_risks"} or not isinstance(output["summary"], str) or not output["summary"].strip() or not isinstance(output["known_risks"], list) or any(not isinstance(r, str) for r in output["known_risks"]):
                        raise FactoryBlocked("UNKNOWN", "implementation result is missing or malformed")
                    outputs.append(output)
                work = {"summary": "\n".join(o["summary"] for o in outputs), "known_risks": [risk for o in outputs for risk in o["known_risks"]]}
                target = self.checkpoint(spec, cwd)
                if not target["files"] or self.project and set(target["files"]) == {spec["mission_scope_file"]}:
                    raise FactoryBlocked("UNKNOWN", "implementation produced no candidate changes or acceptance tests; no delivery was asserted")
                self.state(mission, "TEST")
                tests = self.gates(spec, cwd, target, "checks", round_)
                self.state(mission, "CI")
                ci = self.gates(spec, cwd, target, "ci", round_)
                feedback = [{"department": kind, "result": result} for kind, results in (("test", tests), ("ci", ci)) for result in results if result["status"] != "PASS"]
                reviews = []
                if not feedback:
                    self.require_project_validation(spec, cwd, target)
                    self.state(mission, "REVIEW")
                    lanes = configured_review_lanes(self.config)
                    # Do not send the first lane's findings/results to the second.
                    for lane in lanes:
                        review = self.review(spec, cwd, target, lane)
                        reviews.append(review)
                        if review["status"] != "PASS":
                            feedback.append({"department": lane, "findings": review["findings"], "explanation": review["output"]["overall_explanation"]})
                if not feedback:
                    remote = None
                    if self.project and not self.config["simulation"] and "project_delivery" in self.config:
                        self.state(mission, "PR_CI")
                        remote = self.project_pr_ci(spec, cwd, target, reviews, tests + ci)
                        if remote["ci"]["status"] != "PASS":
                            feedback.append({"department": "pr_ci", "result": remote["ci"]})
                if not feedback:
                    if self.target(spec, cwd) != target:
                        raise FactoryBlocked("UNKNOWN", "final delivery target changed after gates")
                    project_gate = self.project_final_gate(spec, cwd, target, reviews, ci if "project_pr_ci" in self.config else remote) if self.project else None
                    delivery = {"target": target, "implemented": work["summary"], "risks": work["known_risks"],
                                "tests": "PASS", "ci": "PASS", "hosted_ci": "PASS" if {"hosted_ci", "project_pr_ci"} & set(self.config) else "NOT_CONFIGURED", "reviews": reviews,
                                "evidence_keys": [op[0] for op in self.db.execute("SELECT key FROM operations WHERE mission=? AND status='COMPLETE'", (mission,))]}
                    if self.project:
                        delivery.update(project_gate=project_gate, validation_results={"checks": tests, "ci": ci})
                        if self.config["simulation"]:
                            delivery.update(tests="OFFLINE_FIXTURE_PASS", ci="OFFLINE_FIXTURE_PASS")
                        elif "project_delivery" in self.config:
                            delivery.update(remote=remote, hosted_ci="EXACT_PR_CHECKS_PASS")
                    self.event(mission, "delivery", delivery)
                    self.state(mission, OFFLINE_PASS if self.project and self.config["simulation"] else READY)
                    return self.report(mission)
                self.db.execute("UPDATE missions SET round=round+1 WHERE id=?", (mission,))
                self.event(mission, "rework", {"target": target, "feedback": feedback})
                self.state(mission, "REWORK")
            raise FactoryBlocked("BLOCKED_LIMIT", "bounded rework rounds exhausted; no delivery PASS was asserted")
        except FactoryBlocked as exc:
            self.state(mission, exc.status, exc.reason)
        except Exception as exc:
            self.state(mission, "UNKNOWN", f"{type(exc).__name__}: {exc}")
        return self.report(mission)

    def _run_local_candidate(self, spec, cwd, row):
        """Explicitly authorized one-thread local delivery; legacy path is untouched."""
        mission = spec["mission_id"]
        self._local_started = time.monotonic()
        try:
            candidate_stage.authorize(spec, self.config, Path(row["candidate"]),
                                      self.developer_binding(spec)[1])
            if row["status"] in ("UNKNOWN", "BLOCKED_BUDGET", "BLOCKED_SCOPE", "BLOCKED_LIMIT",
                                 "BLOCKED_LOCAL_AUTHORITY", candidate_stage.LOCAL_READY):
                return self.report(mission)
            if row["status"] == "CREATED":
                row = self.row(mission)
            spec, cwd = self.prepare(mission)
            row = self.row(mission)
            operation_rows = self.db.execute("SELECT * FROM operations WHERE mission=?", (mission,)).fetchall()
            if operation_rows:
                # A completed first turn is resumed only in this live process;
                # any persisted unresolved operation remains governed by the global UNKNOWN guard.
                raise FactoryBlocked("UNKNOWN", "single-agent turn evidence already exists but its in-memory thread is unavailable")
            instruction = self._authorization_summary(spec, Path(row["candidate"]))
            payload = {"objective": spec["objective"], "acceptance": spec["acceptance"],
                       "constraints": spec["constraints"], "scope": spec["scope"],
                       "authorization": instruction,
                       "execution_guidance": (
                           "Follow repository instructions already supplied in the conversation; do not fetch or print "
                           "the same unchanged instructions again. If instructions are missing or changed, read them. "
                           "Still read required workflow documents and applicable nested instructions. "
                           "Use the Controller workspace facts below to record the required pre-edit Git identity; "
                           "this isolated clone has no remotes, so use BASE_SHA rather than origin/main and never fetch. "
                           "Batch independent instruction/document reads, focused source/test reads and one tool-availability "
                           "probe where possible. Read relevant excerpts; do not dump unrelated configuration or test "
                           "bootstrap files merely to investigate tools/dependencies that are unavailable. "
                           "Once the defect is understood, implement it and its required regression tests. "
                           "Batch independent post-edit checks and diff inspection in one tool round where possible. "
                           "If dependencies are unavailable, report unrun checks and finish with the required JSON; "
                           "the Controller still runs independent formal QA. Never omit needed source/context, "
                           "regression coverage or required project checks to save tokens."),
                       "instruction": "You are the sole Codex execution agent. Understand the repository, plan and implement the complete task, add regression coverage, and make ordinary fixes. Do not ask for a separate planner or reviewer. Do not commit, merge, publish, push, deploy, contact external services, or change files outside scope. Return JSON with summary and known_risks."}
            self.state(mission, "IMPLEMENT")
            self._single_thread_id = None
            self._single_usage_snapshot = None
            self._single_qa_round = 0
            result = self._single_agent_operation(spec, cwd, payload, "implement", 0, None)
            work = result["output"]
            target = self.checkpoint(spec, cwd)
            if not target["files"]:
                raise FactoryBlocked("UNKNOWN", "implementation produced no candidate changes; no delivery asserted")
            self.state(mission, "TEST")
            checks = self.gates(spec, cwd, target, "checks", 0)
            ci = []
            if not candidate_stage.targeted(spec, self.config):
                self.state(mission, "CI")
                ci = self.gates(spec, cwd, target, "ci", 0)
            failed = [r for r in checks + ci if r["status"] != "PASS"]
            if failed:
                if self._single_thread_id is None:
                    raise FactoryBlocked("UNKNOWN", "same-thread repair unavailable; no new thread authorized")
                self._verify_local_resume(spec, cwd, target)
                repair_payload = {**payload, "diagnostics": self._local_qa_feedback(mission, failed),
                    "instruction": "The trusted Controller QA below failed. Fix only these concrete failures, add/update regression tests as needed, and return summary and known_risks. This is the one authorized ordinary repair; do not start another task or take external actions."}
                self.state(mission, "REWORK")
                result = self._single_agent_operation(spec, cwd, repair_payload, "rework", 1, self._single_thread_id)
                work = result["output"]
                target = self.checkpoint(spec, cwd)
                if not target["files"]:
                    raise FactoryBlocked("UNKNOWN", "repair removed all candidate changes")
                self.state(mission, "TEST")
                self._single_qa_round = 1
                checks = self.gates(spec, cwd, target, "checks", 1)
                ci = []
                if not candidate_stage.targeted(spec, self.config):
                    self.state(mission, "CI")
                    ci = self.gates(spec, cwd, target, "ci", 1)
                if any(r["status"] != "PASS" for r in checks + ci):
                    raise FactoryBlocked("BLOCKED_LIMIT", "trusted QA still fails after the one authorized same-thread repair")
                target = self.checkpoint(spec, cwd)
                checks = self.gates(spec, cwd, target, "checks", 1)
                if not candidate_stage.targeted(spec, self.config):
                    ci = self.gates(spec, cwd, target, "ci", 1)
                if any(r["status"] != "PASS" for r in checks + ci):
                    raise FactoryBlocked("BLOCKED_LIMIT", "post-repair full QA failed")
            if any(r["status"] != "PASS" for r in checks + ci):
                raise FactoryBlocked("BLOCKED_LIMIT", "trusted QA failed; no local candidate delivered")
            self._verify_local_resume(spec, cwd, target)
            result = candidate_stage.complete(self, spec, cwd, target, work, checks, ci)
            return result
        except FactoryBlocked as exc:
            self.state(mission, exc.status, exc.reason)
        except Exception as exc:
            self.state(mission, "UNKNOWN", f"{type(exc).__name__}: {exc}")
        return self.report(mission)

    def _authorization_summary(self, spec, cwd):
        auth = spec["local_candidate_authorization"]
        limits = dict(self.config["budget"])
        # max_run_tokens remains the legacy-mode cap; local_candidate uses the
        # explicitly authorized first-turn and repair caps below.
        limits.pop("max_run_tokens", None)
        return {"AUTHORIZATION_VERIFIED": True, "AUTHORIZATION_IDENTITY": auth["approval_id"],
                "AUTHORIZED_TASK": spec["objective"], "REPOSITORY_AND_BASE": {"repository": spec["repository"], "base": spec["base"]},
                "CANDIDATE_WORKSPACE": str(cwd), "ALLOWED_SCOPE": spec["scope"],
                "FORBIDDEN_ACTIONS": ["network", "push", "pull", "PR", "merge", "release", "deployment", "external API"],
                "EXECUTION_LIMITS": {"max_turns": 2, "max_repairs": 1, **limits}}

    def _local_qa_feedback(self, mission, failed):
        """Copy bounded, verified QA output across the Controller read boundary."""
        feedback = []
        for result in failed:
            op = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?",
                                 (mission, result["evidence_key"])).fetchone()
            if op is None or op["stage"] not in {"checks", "ci"}:
                raise FactoryBlocked("UNKNOWN", "repair diagnostics have no QA operation")
            self.verify_evidence(op)
            recorded = json.loads(op["result"])
            if {k: v for k, v in result.items() if k != "evidence_key"} != recorded:
                raise FactoryBlocked("UNKNOWN", "repair diagnostics differ from QA evidence")
            excerpts = []
            for evidence in recorded.get("raw_evidence", []):
                path = Path(evidence["path"])
                if path.suffix != ".raw":
                    continue
                with path.open("rb") as stream:
                    stream.seek(max(0, path.stat().st_size - 16384))
                    excerpts.append(stream.read(16384).decode("utf-8", errors="replace"))
            feedback.append({"command": json.loads(op["input"])["command"],
                             "status": result["status"], "exit_code": result.get("exit_code"),
                             "log_tail": "\n".join(excerpts), "evidence_key": result["evidence_key"]})
        return feedback

    def _verify_local_resume(self, spec, cwd, target):
        candidate_stage.authorize(spec, self.config, cwd, self.developer_binding(spec)[1])
        if self.target(spec, cwd) != target or git(cwd, "remote"):
            raise FactoryBlocked("BLOCKED_SCOPE", "candidate identity, HEAD, scope, or remote boundary changed")

    def _single_agent_operation(self, spec, cwd, payload, stage, round_, thread_id):
        lane = "developer"
        profile, profile_identity = self.developer_binding(spec)
        token_limit = operation_token_limit(self.config["budget"], stage, local_candidate=True)
        target = self.target(spec, cwd)
        branch = git(cwd, "branch", "--show-current")
        if branch != "factory/" + spec["mission_id"] or git(cwd, "remote"):
            raise FactoryBlocked("BLOCKED_SCOPE", "local candidate branch or remote identity changed")
        # Refresh on both turns: QA may have checkpointed a different HEAD.
        # These facts complement the immutable authorization, never replace it.
        payload = {**payload, "workspace": {
            "PROJECT_ROOT": str(cwd), "CURRENT_BRANCH": branch,
            "CURRENT_HEAD": target["head"], "CURRENT_DIRTY_STATE": "clean",
            "BASE_SHA": spec["base"], "REMOTES": []}}
        identity = {"profile": profile_identity, "engine": "codex-app-server",
                    "stage": stage, "repository": spec["repository"], "base": spec["base"],
                    "dispatch_head": git(cwd, "rev-parse", "HEAD"), "scope": spec["scope"],
                    "operation_token_limit": token_limit,
                    "thread_id": thread_id}
        key = digest({"stage": stage, "round": round_, "profile": profile_identity, "payload": payload})
        self._single_thread_id = thread_id
        def invoke(transcript):
            call_payload = {**payload, "_thread_id": thread_id, "_return_thread": True,
                            "_reuse_session": True, "_operation_token_limit": token_limit}
            if "model_selection" in profile_identity and not self.config["simulation"]:
                call_payload["_authorized_route"] = profile_identity["route_identity"]
            if self.project:
                approval = approved_scope(spec)
                call_payload.update(mission_scope_file=approval["path"],
                                    mission_scope_sha256=approval["sha256"])
            try:
                result = self.runtime.agent(stage, profile, cwd, call_payload, transcript,
                        self.operation_timeout(spec["mission_id"]), [self.root, Path(spec["repository"])])
            except RuntimeFailure as exc:
                # Even uncertain repair telemetry is cumulative thread usage;
                # retain only this operation's observed increment, plus its
                # permanent UNKNOWN reservation in the existing ledger.
                if self._single_usage_snapshot is not None:
                    measured = candidate_stage.usage_increment(exc.usage, self._single_usage_snapshot)
                    exc.usage = {"total": measured[0]} if measured else None
                raise
            if result.get("thread_id"):
                if thread_id is not None and result["thread_id"] != thread_id:
                    raise FactoryBlocked("UNKNOWN", "runtime changed execution thread between turns")
                self._single_thread_id = result["thread_id"]
            elif isinstance(self.runtime, LocalRuntime):
                raise FactoryBlocked("UNKNOWN", "official App Server did not return a thread identity")
            measured = candidate_stage.usage_increment(result.get("usage"), self._single_usage_snapshot)
            if measured is None:
                raise FactoryBlocked("UNKNOWN", "thread usage snapshot missing, regressed, or incomplete")
            delta, snapshot = measured
            self._single_usage_snapshot = snapshot
            result["usage_delta"] = delta
            result["usage_snapshot"] = result.get("usage")
            result["usage"] = {"total": delta} if "totalTokens" in delta or "total_tokens" in delta else delta
            return result
        result = self.operation(spec["mission_id"], key, stage, lane, identity, payload, True, invoke)
        return result

    def approve(self, mission, action, reason, expected_head):
        if action not in ("merge", "release") or not isinstance(reason, str) or not reason.strip():
            raise ValueError("explicit human action and reason are required")
        report = self.run(mission)  # Reconcile all target/profile/evidence gates first.
        if report["DELIVERY_STATUS"] != READY or report["SIMULATION"] or report["TARGET_HEAD"] != expected_head:
            raise ValueError("approval requires a live, verified delivery at the explicitly accepted exact HEAD")
        self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?)",
                        (uuid.uuid4().hex, mission, encoded(report["EXACT_TARGET"]), action, reason, time.time()))
        self.event(mission, "human_approval", {"action": action, "reason": reason, "target": report["EXACT_TARGET"]})
        self.db.commit()
        # Approval is audit evidence; this factory has no merge/release executor.
        return {"APPROVAL": "RECORDED", "ACTION": action, "TARGET_HEAD": expected_head, "MERGE_PERFORMED": False}
