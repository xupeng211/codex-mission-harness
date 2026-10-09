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
import subprocess
import time
import uuid
from pathlib import Path

from .factory_runtime import LocalRuntime, official_rubric, VENDOR
from .sandbox import SAFE_PATH
from .factory_budget import accounting, planning_limits
from .factory_project import (PROJECT, OFFLINE_PASS, LANES, BACKENDS, approved_scope,
                              materialize_scope, scope_binding, review_manifest)


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
               "trusted_validation", "project_pr_ci"}
    if not isinstance(raw, dict) or set(raw) - allowed or type(raw.get("version")) is not int or raw.get("version") != 1:
        raise ValueError("invalid factory configuration")
    config = json.loads(encoded(raw))
    config.setdefault("simulation", False)
    config.setdefault("independent_review_required", True)
    for key in ("simulation", "independent_review_required"):
        if type(config[key]) is not bool:
            raise ValueError(f"{key} must be boolean")
    if "project_contract" in config:
        if config["project_contract"] != PROJECT or not config["independent_review_required"]:
            raise ValueError("project mode is explicit and retains both independent reviewers")
        if "hosted_ci" in config:
            raise ValueError("project mode requires explicit PR CI; push CI is incompatible")
    if {"trusted_validation", "project_pr_ci"} & set(config) and config.get("project_contract") != PROJECT:
        raise ValueError("trusted validation/PR CI are only available in explicit project mode")
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
    budget = config.get("budget")
    if not isinstance(budget, dict) or "max_agent_runs" not in budget or set(budget) - {"max_agent_runs", "max_total_tokens", "max_run_tokens", "max_wall_seconds"}:
        raise ValueError("invalid mission resource authority; monetary usage remains UNKNOWN")
    if ("max_total_tokens" in budget) != ("max_run_tokens" in budget):
        raise ValueError("total and per-run token authority must be specified together")
    for name, upper in (("max_total_tokens", 100_000_000), ("max_run_tokens", 2_000_000), ("max_wall_seconds", 86400)):
        if name in budget:
            bounded_int(budget[name], name, 1, upper)
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
    expected = {"developer", "reviewer", "second_reviewer"} if config["independent_review_required"] else {"developer", "reviewer"}
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
    return config


def policy_identity(config):
    # Switching one profile changes only that lane's evidence key. Budgets,
    # provider independence, timeouts and test policy remain immutable.
    return {key: value for key, value in config.items() if key not in ("profiles", "repository")}


def validate_mission(raw):
    keys = {"version", "mission_id", "repository", "objective", "acceptance", "constraints", "scope", "base", "mission_scope_file", "approved_mission_scope"}
    if not isinstance(raw, dict) or set(raw) - keys or type(raw.get("version")) is not int or raw.get("version") != 2:
        raise ValueError("factory missions require version 2")
    mission = json.loads(encoded(raw))
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
                                   for lane, profile in self.config["profiles"].items() if not self.project or lane == "developer"}
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
        if self.project:
            approved_scope(spec)
            if "project_pr_ci" in self.config:
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
        self.db.execute("INSERT INTO missions(id,spec,policy,status,candidate) VALUES(?,?,?,?,?)",
                        (mission, encoded(spec), encoded(policy_identity(self.config)), "CREATED", str(candidate)))
        self.event(mission, "submitted", {"spec": spec, "profiles": self.config["profiles"]})
        self.db.commit()
        return mission

    def prepare(self, mission):
        row = self.row(mission)
        spec, cwd = json.loads(row["spec"]), Path(row["candidate"])
        if row["status"] == "CREATED":
            if cwd.exists():
                raise FactoryBlocked("UNKNOWN", "candidate preparation interrupted; unverified path was not reused")
            cwd.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            git(Path(spec["repository"]), "clone", "--no-local", "--no-hardlinks", "--no-checkout", "--", spec["repository"], str(cwd))
            git(cwd, "remote", "remove", "origin")
            git(cwd, "checkout", "-b", f"factory/{mission}", spec["base"])
            if self.project:
                materialize_scope(spec, cwd, git)
                self.runtime.project_policy(spec, cwd, [spec["mission_scope_file"]])
            self.state(mission, "PLAN")
        if cwd.resolve() != cwd or not (cwd / ".git").is_dir() or (cwd / ".git").is_symlink():
            raise FactoryBlocked("UNKNOWN", "candidate isolation identity is invalid")
        if (cwd / ".git" / "objects" / "info" / "alternates").exists():
            raise FactoryBlocked("UNKNOWN", "candidate must not share a writable Git database")
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
                target["review_range"] = review_manifest(cwd, target, git)
                target["project_policy"] = self.runtime.project_policy(spec, cwd, files)
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
        old = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, key)).fetchone()
        if old:
            if old["status"] != "COMPLETE":
                raise FactoryBlocked("UNKNOWN", f"{stage} dispatch/result is uncertain; operation {old['id']} was not repeated")
            self.verify_evidence(old)
            return json.loads(old["result"])
        if self.cancel_requested(mission):
            raise FactoryBlocked("CANCELLED", "user cancelled; completed evidence and all reservations are retained")
        if paid:
            uncertain = self.db.execute("SELECT id FROM operations WHERE mission=? AND status IN ('RUNNING','UNKNOWN') LIMIT 1", (mission,)).fetchone()
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
                if preflight["status"] == "HARD_BLOCKER":
                    detail = "; ".join(f["check"] + ": " + f["detail"] for f in preflight["findings"] if f["level"] == "HARD_BLOCKER")
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
            if paid and "max_total_tokens" in budget and resources["committed_tokens"] + budget["max_run_tokens"] > budget["max_total_tokens"]:
                raise FactoryBlocked("BLOCKED_BUDGET", "token admission exhausted; UNKNOWN reservations are permanent")
            used = self.db.execute("SELECT COUNT(*) FROM operations WHERE mission=? AND paid=1", (mission,)).fetchone()[0]
            if paid and used >= self.config["budget"]["max_agent_runs"]:
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
            result.setdefault("usage_complete", observed_usage(result.get("usage"), self.config["simulation"]) is not None)
            status = "UNKNOWN" if result.get("status") == "UNKNOWN" else "COMPLETE"
            if status == "UNKNOWN":
                result.setdefault("error", "runtime result was incomplete or uncertain; no replay authorized")
        except Exception as exc:
            result, status = {"error": f"{type(exc).__name__}: {exc}",
                              "usage": getattr(exc, "usage", None),
                              "runtime_identity": getattr(exc, "identity", None),
                              "usage_complete": getattr(exc, "usage_complete", False)}, "UNKNOWN"
        raw_paths = [p for p in (transcript, transcript.with_suffix(".stderr"), transcript.with_suffix(".proxy.jsonl")) if p.is_file()]
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
        if paid and "max_run_tokens" in self.config["budget"]:
            from .factory_budget import tokens
            if (tokens(usage) or 0) > self.config["budget"]["max_run_tokens"]:
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

    def verify_evidence(self, operation):
        evidence = Path(operation["evidence"] or "")
        if not evidence.is_file() or evidence.is_symlink() or evidence.resolve() != evidence or hashlib.sha256(evidence.read_bytes()).hexdigest() != operation["evidence_hash"]:
            raise FactoryBlocked("UNKNOWN", "operation evidence is missing or changed")
        for raw in json.loads(operation["result"]).get("raw_evidence", []):
            path = Path(raw["path"])
            if not path.is_file() or path.is_symlink() or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != raw["sha256"]:
                raise FactoryBlocked("UNKNOWN", "raw execution evidence is missing or changed")
        for raw in json.loads(operation["result"]).get("project_evidence", []):
            path = Path(raw["path"])
            if not path.is_file() or path.is_symlink() or path.resolve() != path or hashlib.sha256(path.read_bytes()).hexdigest() != raw["sha256"]:
                raise FactoryBlocked("UNKNOWN", "canonical project evidence is missing or changed")

    def agent(self, spec, cwd, stage, round_, payload):
        if self.project:
            approval = approved_scope(spec)
            payload = {**payload, "mission_scope_file": approval["path"], "mission_scope_sha256": approval["sha256"]}
        lane = "developer"
        profile = self.config["profiles"][lane]
        identity = {"profile": self.profile_identities[lane], "engine": "codex-app-server", "stage": stage,
                    "repository": spec["repository"], "base": spec["base"], "dispatch_head": git(cwd, "rev-parse", "HEAD"),
                    "scope": spec["scope"]}
        key = digest({"stage": stage, "round": round_, "profile": self.profile_identities[lane], "payload": payload})
        return self.operation(spec["mission_id"], key, stage, lane, identity, payload, True,
                              lambda transcript: self.runtime.agent(stage, profile, cwd, payload, transcript,
                                                                    self.operation_timeout(spec["mission_id"]),
                                                                    [self.root, Path(spec["repository"])]))

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
                return self.runtime.prepare_project_review(spec, cwd, target, lane,
                    self.operation_timeout(spec["mission_id"]))
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", f"canonical local preparation failed: {exc}") from exc
        result = self.operation(spec["mission_id"], key, "review", lane, identity, payload, True,
            lambda transcript, prepared: self.runtime.project_review(spec, cwd, target, lane, transcript,
                self.operation_timeout(spec["mission_id"]), prepared=prepared),
            prepare=prepare)
        if self.target(spec, cwd) != target:
            raise FactoryBlocked("UNKNOWN", "canonical reviewer changed the exact target")
        try:
            checked = self.runtime.project_validate_review(spec, cwd, target, lane, result)
            if checked.status not in {"PASS", "FAIL"} or not checked.artifact or not isinstance(checked.data, dict):
                raise ValueError("project validator has no current receipt verdict")
            findings = checked.data.get("findings")
            if not isinstance(findings, list):
                raise ValueError("canonical receipt omitted findings")
            if result.get("fixture", False) is not self.config["simulation"]:
                raise ValueError("fixture/live canonical evidence mismatch")
        except (ValueError, KeyError, TypeError, OSError) as exc:
            raise FactoryBlocked("UNKNOWN", f"canonical receipt validation failed: {exc}") from exc
        # Do not lower the existing Factory barrier without an Owner decision.
        status = "PASS" if checked.status == "PASS" and not findings else "FAIL"
        return {"status": status, "findings": findings,
                "output": {"overall_explanation": checked.evidence},
                "evidence_key": key, "provider": "openai" if lane == "reviewer" else "deepseek",
                "lane": lane, "backend": BACKENDS[LANES[lane]], "target": target,
                "canonical_receipt": checked.artifact, "canonical_receipt_data": checked.data,
                "review_range": target["review_range"], "fixture": self.config["simulation"]}

    def project_final_gate(self, spec, cwd, target, reviews, ci=None):
        if {r["lane"] for r in reviews} != set(LANES) or any(r["status"] != "PASS" for r in reviews):
            raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "both validated canonical receipts are required")
        context = None
        if "project_pr_ci" in self.config:
            context = self.project_ci_context(spec, cwd, target, ci or [])
        payload = {"target": target, "receipts": {r["backend"]: r["canonical_receipt"] for r in reviews}, "context": context}
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
        from .factory_pr_ci import branch_for, digest as policy_digest
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
                                 "policy_sha256": policy_digest(policy)},
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

    def gates(self, spec, cwd, target, kind, round_):
        results = []
        for index, command in enumerate(self.config[kind]):
            validation = self.config.get("trusted_validation")
            if validation and kind == "checks" and target["project_policy"]["workflow_class"] in {"STRICT", "CRITICAL"} and command != ["make", "verify-strict"]:
                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "STRICT/CRITICAL require the formal strict validation profile")
            payload = {"command": command, "target": target, "round": round_,
                       **({"validation": validation, "mission_id": spec["mission_id"]} if validation else {})}
            key = digest({"kind": kind, "index": index, **payload})
            result = self.operation(spec["mission_id"], key, kind, "local", {"target": target}, payload, False,
                                    lambda transcript: self.runtime.project_validation(validation, spec, command, cwd, target, transcript, self.operation_timeout(spec["mission_id"]))
                                    if validation else self.runtime.gate(command, cwd, target, transcript, self.operation_timeout(spec["mission_id"])))
            if validation:
                from .factory_validation import validate_result, profile_for
                try:
                    validate_result(result, validation, spec, target, profile_for(command), self.config["simulation"])
                except Exception as exc:
                    raise FactoryBlocked("UNKNOWN", "trusted validation rejected: " + str(exc)) from exc
            if result.get("status") not in ("PASS", "FAIL") or type(result.get("exit_code")) is not int or (result["status"] == "PASS") != (result["exit_code"] == 0):
                raise FactoryBlocked("UNKNOWN", "test/CI command lacks a proven exit status")
            if self.target(spec, cwd) != target:
                raise FactoryBlocked("UNKNOWN", "test/CI changed the reviewed target")
            results.append({**result, "evidence_key": key})
        if kind == "ci" and "project_pr_ci" in self.config:
            policy = self.config["project_pr_ci"]
            approval = self.publication_approval(spec, target)
            payload = {"target": target, "policy": policy, "approval_id": approval["approval_id"],
                       "runner_sha256": hashlib.sha256(Path(__file__).with_name("factory_pr_ci.py").read_bytes()).hexdigest()}
            key = digest({"project_pr_ci": payload})
            result = self.operation(spec["mission_id"], key, "project_pr_ci", "github", payload, payload, False,
                lambda transcript: self.runtime.project_ci(policy, spec, cwd, target, approval, transcript,
                                                          self.operation_timeout(spec["mission_id"])))
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

    def report(self, mission):
        row = self.row(mission)
        operations = self.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started", (mission,)).fetchall()
        events = self.db.execute("SELECT kind,payload FROM events WHERE mission=? ORDER BY sequence", (mission,)).fetchall()
        deliveries = [json.loads(e["payload"]) for e in events if e["kind"] == "delivery"]
        delivery = deliveries[-1] if deliveries else {}
        preflights = [json.loads(e["payload"]) for e in events if e["kind"] == "prepaid_preflight"]
        status, reason = row["status"], row["reason"]
        if status == READY or self.project and status == OFFLINE_PASS:
            try:
                spec, cwd = json.loads(row["spec"]), Path(row["candidate"])
                if self.project and status == READY and (self.config["simulation"] or "project_pr_ci" not in self.config):
                    raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", "live readiness requires explicit PR CI and live evidence")
                if self.target(spec, cwd) != delivery.get("target"):
                    raise FactoryBlocked("UNKNOWN", "delivery HEAD/tree/scope changed after verification")
                if not delivery.get("target", {}).get("files") or not isinstance(delivery.get("implemented"), str) or not delivery["implemented"].strip():
                    raise FactoryBlocked("UNKNOWN", "delivery implementation/change evidence is missing")
                expected_lanes = {"reviewer", "second_reviewer"} if self.config["independent_review_required"] else {"reviewer"}
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
                            from .factory_project import FootballPredictionContract
                            checked = FootballPredictionContract().final_gate(spec, cwd, delivery["target"],
                                {LANES[r["lane"]]: r["canonical_receipt"] for r in delivery["reviews"]}, context)
                            if checked.status != "PASS":
                                raise FactoryBlocked("BLOCKED_PROJECT_CONTRACT", checked.evidence)
                    gate = delivery["project_gate"]
                    if gate["evidence_key"] not in delivery["evidence_keys"] or gate.get("fixture") is not self.config["simulation"]:
                        raise FactoryBlocked("UNKNOWN", "project gate evidence is incomplete")
                    op = self.db.execute("SELECT * FROM operations WHERE mission=? AND key=?", (mission, gate["evidence_key"])).fetchone()
                    if (op is None or op["stage"] != "project_gate" or json.loads(op["result"]).get("status") != "PASS"
                            or json.loads(op["result"]).get("target") != delivery["target"]):
                        raise FactoryBlocked("UNKNOWN", "project final gate evidence is missing or rejected")
            except FactoryBlocked as exc:
                status, reason = exc.status, exc.reason
            except Exception as exc:
                status, reason = "UNKNOWN", str(exc)
        verified = status == READY or self.project and status == OFFLINE_PASS
        return {"MISSION": mission, "DELIVERY_STATUS": status,
                "PREPAID_PREFLIGHT": preflights[-1] if preflights else "NOT_RUN",
                "IMPLEMENTED": delivery.get("implemented", "UNKNOWN"),
                "TEST_RESULT": delivery.get("tests", "UNKNOWN") if verified else "UNKNOWN",
                "CI_RESULT": delivery.get("ci", "UNKNOWN") if verified else "UNKNOWN",
                "REVIEW_RESULT": delivery.get("reviews", "UNKNOWN") if verified else "UNKNOWN",
                "BLOCKERS_REMAINING": ["live validation, exact PR/CI and business delivery are not established"] if self.project and status == OFFLINE_PASS else [] if status == READY else [reason or status],
                "PROJECT_CONTRACT": PROJECT if self.project else "NOT_CONFIGURED",
                "PROJECT_ACCEPTANCE": "OFFLINE_FIXTURE_ONLY" if self.project and status == OFFLINE_PASS else "MERGE_READY" if self.project and status == READY else "NOT_ESTABLISHED",
                "DONE": False,
                "KNOWN_RISKS": delivery.get("risks", []),
                "BUDGET_USED": {**accounting(operations, self.config["budget"]),
                                "money": "UNKNOWN" if not self.config["simulation"] else "FIXTURE_NO_PROVIDER_COST"},
                "LOCAL_CI": delivery.get("ci", "UNKNOWN") if status == READY else "UNKNOWN",
                "HOSTED_CI": delivery.get("hosted_ci", "NOT_CONFIGURED") if status == READY else "UNKNOWN" if {"hosted_ci", "project_pr_ci"} & set(self.config) else "NOT_CONFIGURED",
                "PROJECT_PR_CI": [r.get("context") for r in delivery.get("validation_results", {}).get("ci", [])
                                  if r.get("department") == "project_pr_ci"] if verified else "NOT_ESTABLISHED",
                "TARGET_HEAD": delivery.get("target", {}).get("head", "UNKNOWN"),
                "EXACT_TARGET": delivery.get("target", "UNKNOWN"),
                "DELIVERY_EVIDENCE": [op["evidence"] for op in operations if op["evidence"]],
                "CANDIDATE": row["candidate"], "CANDIDATE_BRANCH": f"factory/{mission}", "SIMULATION": self.config["simulation"],
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
            import threading
            stopped = threading.Event()
            def watch_cancel():
                while not stopped.wait(0.2):
                    if self.cancel_requested(mission) and hasattr(self.runtime, "cancel"):
                        self.runtime.cancel()
            if hasattr(self.runtime, "resource_policy"):
                self.runtime.resource_policy = self.config["budget"]
            watcher = threading.Thread(target=watch_cancel, daemon=True)
            watcher.start()
            try:
                return self._run(mission)
            finally:
                stopped.set()
                watcher.join(timeout=1)

    def _run(self, mission):
        try:
            if self.cancel_requested(mission):
                raise FactoryBlocked("CANCELLED", "user cancelled; no dispatch or resume is authorized")
            spec, cwd = self.prepare(mission)
            row = self.row(mission)
            uncertain = self.db.execute("SELECT id FROM operations WHERE mission=? AND status IN ('RUNNING','UNKNOWN') LIMIT 1", (mission,)).fetchone()
            if uncertain:
                raise FactoryBlocked("UNKNOWN", f"unresolved operation {uncertain[0]}; no duplicate paid dispatch was authorized")
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
                lanes = ["reviewer", "second_reviewer"] if self.config["independent_review_required"] else ["reviewer"]
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
            elif row["status"] in ("UNKNOWN", "BLOCKED_BUDGET", "BLOCKED_SCOPE", "BLOCKED_LIMIT"):
                return self.report(mission)
            planning_payload = {"objective": spec["objective"], "acceptance": spec["acceptance"], "constraints": spec["constraints"],
                                "scope": spec["scope"], "instruction": "Act as technical lead. Understand the repository, plan a minimal complete solution and acceptance tests. Decide ordinary engineering questions yourself. Only unresolved major product ambiguity, safety, independence, budget or irreversible changes belong in decisions_required. Do not edit files. Return plan, bounded tasks, acceptance and decisions_required."}
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
                if len(plan["tasks"]) + (2 if self.config["independent_review_required"] else 1) > remaining:
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
                    self.state(mission, "REVIEW")
                    lanes = ["reviewer", "second_reviewer"] if self.config["independent_review_required"] else ["reviewer"]
                    # Do not send the first lane's findings/results to the second.
                    for lane in lanes:
                        review = self.review(spec, cwd, target, lane)
                        reviews.append(review)
                        if review["status"] != "PASS":
                            feedback.append({"department": lane, "findings": review["findings"], "explanation": review["output"]["overall_explanation"]})
                if not feedback:
                    if self.target(spec, cwd) != target:
                        raise FactoryBlocked("UNKNOWN", "final delivery target changed after gates")
                    project_gate = self.project_final_gate(spec, cwd, target, reviews, ci) if self.project else None
                    delivery = {"target": target, "implemented": work["summary"], "risks": work["known_risks"],
                                "tests": "PASS", "ci": "PASS", "hosted_ci": "PASS" if {"hosted_ci", "project_pr_ci"} & set(self.config) else "NOT_CONFIGURED", "reviews": reviews,
                                "evidence_keys": [op[0] for op in self.db.execute("SELECT key FROM operations WHERE mission=? AND status='COMPLETE'", (mission,))]}
                    if self.project:
                        delivery.update(project_gate=project_gate, validation_results={"checks": tests, "ci": ci})
                        if self.config["simulation"]:
                            delivery.update(tests="OFFLINE_FIXTURE_PASS", ci="OFFLINE_FIXTURE_PASS")
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
