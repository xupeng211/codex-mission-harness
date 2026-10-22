"""Small opt-in progress policy over existing mission/operation/wire evidence.

No billing guarantee, semantic AI supervisor, receipt migration or retry engine.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def enabled(config):
    return config.get("execution_policy", {}).get("mode") == "progress_driven"


def validate(config):
    policy = config.get("execution_policy")
    if policy is None:
        return
    if policy == {"mode": "strict_budget"}:
        return
    if (not isinstance(policy, dict) or set(policy) != {"mode", "idle_timeout_seconds"}
            or policy.get("mode") != "progress_driven"
            or type(policy["idle_timeout_seconds"]) is not int
            or not 1 <= policy["idle_timeout_seconds"] <= 86400):
        raise ValueError("invalid explicit execution_policy")
    if config.get("budget") != {}:
        raise ValueError("progress mode requires budget={} to avoid ambiguous legacy ceilings")
    if "max_rounds" in config:
        raise ValueError("progress mode uses evidence-based rework, not max_rounds")
    if "trusted_validation" in config:
        raise ValueError("trusted container validation has fixed wall-clock interface; progress compatibility unsupported")
    if {"hosted_ci", "project_pr_ci"} & set(config):
        raise ValueError("progress mode has no remote write authority")
    if config.get("independent_review_required", True) is not True:
        raise ValueError("progress mode retains independent dual review")


def authorize(factory, spec, candidate, *, executing=True):
    from .factory import digest, policy_identity
    if not enabled(factory.config):
        if "progress_authorization" in spec:
            raise ValueError("progress authorization requires explicit progress policy")
        return
    value = spec.get("progress_authorization")
    fields = {"approval_id", "mission_id", "repository", "base", "objective", "acceptance",
              "allowed_paths", "worktree", "policy_sha256", "lane_identities", "financial", "expires_at"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("explicit complete progress_authorization required")
    if (not isinstance(value["approval_id"], str) or not value["approval_id"].strip()
            or not spec["acceptance"] or "**" in spec["scope"]):
        raise ValueError("progress authority requires approval, acceptance and bounded scope")
    expected = {k: spec[k] for k in ("mission_id", "repository", "base", "objective", "acceptance")}
    identities = dict(factory.profile_identities)
    identities["developer"] = factory.developer_binding(spec)[1]
    expected.update(allowed_paths=spec["scope"], worktree=str(candidate),
                    policy_sha256=digest(policy_identity(factory.config)), lane_identities=identities)
    if any(value[k] != v for k, v in expected.items()):
        raise ValueError("progress authority differs from exact task/policy/runtime binding")
    financial = value["financial"]
    if (not isinstance(financial, dict) or set(financial) != set(identities)
            or any(v not in ("prepaid_only", "not_authorized") for v in financial.values())
            or financial.get("second_reviewer") != "not_authorized"):
        raise ValueError("extra paid lanes need separate proven financial admission; unsupported here")
    if not isinstance(value["expires_at"], str):
        raise ValueError("progress expiry must be an explicit timestamp")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or executing and expiry <= datetime.now(timezone.utc):
        raise ValueError("progress authority expired or lacks timezone")


def check_dispatch(factory, mission, stage, lane, paid):
    if not enabled(factory.config):
        return
    from .factory import FactoryBlocked
    row = factory.row(mission)
    spec = json.loads(row["spec"])
    try:
        authorize(factory, spec, Path(row["candidate"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise FactoryBlocked("BLOCKED_PROGRESS", str(exc)) from exc
    if row["status"] in {"BLOCKED_PROGRESS", "BLOCKED_SCOPE", "UNKNOWN", "CANCELLED"}:
        raise FactoryBlocked(row["status"], "stopped progress task cannot redispatch")
    if stage in {"hosted_ci", "project_pr_ci", "push", "merge", "release", "deploy"}:
        raise FactoryBlocked("BLOCKED_PROGRESS", "remote/irreversible operation requires separate Owner authority")
    if not paid:
        return
    if factory.project and stage == "review":
        raise FactoryBlocked("BLOCKED_PROGRESS", "canonical project reviewer has fixed timeout interface; progress compatibility unproven")
    if not factory.config["simulation"]:
        if spec["progress_authorization"]["financial"].get(lane) != "prepaid_only" or lane == "second_reviewer":
            raise FactoryBlocked("BLOCKED_FINANCIAL", "extra paid dispatch has no separate proven financial admission")
        profile = factory.developer_binding(spec)[0] if lane == "developer" else factory.config["profiles"][lane]
        if profile.get("transport", {"type": "official"})["type"] == "official":
            # API-key identities need separate financial admission. The ChatGPT
            # marker is identity evidence, never proof of the upstream bill.
            home = Path(profile.get("codex_home") or Path.home()/".codex")
            try:
                auth = json.loads((home/"auth.json").read_text())
            except (OSError, ValueError):
                auth = {}
            if auth.get("auth_mode") != "chatgpt" or auth.get("OPENAI_API_KEY"):
                raise FactoryBlocked("BLOCKED_FINANCIAL", "prepaid lane requires explicit ChatGPT auth; API/credits not authorized")


def check_restart(factory, mission, stage, lane, identity, payload):
    if not enabled(factory.config):
        return
    from .factory import encoded, FactoryBlocked
    count = factory.db.execute(
        "SELECT COUNT(*) FROM operations WHERE mission=? AND stage=? AND lane=? AND identity=? AND input=?",
        (mission, stage, lane, encoded(identity), encoded(payload))).fetchone()[0]
    if count:
        factory.event(mission, "progress_diagnostic", {"stage": stage, "same_dispatch_count": count,
            "diagnosis": "same task/input/runtime without new evidence; reuse completed result or change approach"})
        factory.db.commit()
    if count >= 2:
        raise FactoryBlocked("BLOCKED_PROGRESS", "same task restarted without new evidence after diagnostic")


def check_rework(factory, mission, target, feedback):
    """Same candidate bytes AND same failed evidence: diagnose, then stop.

    A changed tree or changed failure is new evidence, regardless of token/time.
    """
    if not enabled(factory.config):
        return
    from .factory import digest, FactoryBlocked
    def stable(value):
        if isinstance(value, dict):
            return {k: stable(v) for k,v in value.items() if k not in {"evidence_key", "raw_evidence", "evidence", "log_path", "log_sha256"}}
        if isinstance(value, list):
            return [stable(v) for v in value]
        return value
    fingerprint = digest({"tree": target["tree"], "feedback": stable(feedback)})
    prior = [json.loads(r[0]) for r in factory.db.execute(
        "SELECT payload FROM events WHERE mission=? AND kind='progress_rework'", (mission,))]
    count = sum(p["fingerprint"] == fingerprint for p in prior) + 1
    factory.event(mission, "progress_rework", {"fingerprint": fingerprint, "tree": target["tree"],
        "same_evidence_count": count, "diagnosis": "compare unchanged candidate and repeated test/review failure; change approach"})
    factory.db.commit()
    if count >= 3:
        raise FactoryBlocked("BLOCKED_PROGRESS", "same candidate and same failure persisted after diagnostic; no blind restart")


class ProgressGuard:
    """Conservative wire checks, never infer business correctness from line counts."""

    def __init__(self, cwd, scope, emit):
        self.cwd, self.scope, self.emit = Path(cwd), scope, emit
        self.counts = Counter()
        self.rationales = set()
        self.seen_observations = set()

    def observe(self, message):
        method, params = message.get("method"), message.get("params", {})
        if method == "model/rerouted":
            raise RuntimeError("model reroute requires new authority")
        if method != "item/completed":
            return
        item = params.get("item", {})
        if item.get("type") == "agentMessage":
            text = item.get("text", "").strip()
            if text and text not in self.rationales:
                self.rationales.add(text)
                # A new explanation permits rereading; it cannot excuse the
                # same failed command and error forever.
                self.counts = Counter({k:v for k,v in self.counts.items() if k[0] == "failure"})
            return
        if item.get("type") not in {"commandExecution", "fileChange"}:
            return
        from .factory import git as controller_git
        def git(*args):
            return controller_git(self.cwd, *args).encode()
        changed = git("diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z", "HEAD", "--").split(b"\0")
        changed += git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
        names = [p.decode() for p in changed if p]
        if any(not any(fnmatch.fnmatchcase(p, pattern) for pattern in self.scope) for p in names):
            self.emit({"event": "SCOPE_DRIFT", "paths": names})
            raise RuntimeError("working changes exceed authorized scope; execution stopped")
        if item.get("type") != "commandExecution":
            return
        # Working content and command output are evidence. Changes to either
        # permit a new attempt. Token/time and modification size are irrelevant.
        state = hashlib.sha256(git("diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--"))
        for name in sorted(names):
            state.update(name.encode() + b"\0")
            path = self.cwd/name
            if path.is_file() and not path.is_symlink():
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(65536), b""):
                        state.update(block)
        actions = item.get("commandActions") or []
        reading = bool(actions) and all(a.get("type") in {"read", "search", "listFiles"} for a in actions)
        failed = type(item.get("exitCode")) is int and item["exitCode"] != 0
        observation = (state.hexdigest(), item.get("command"), item.get("exitCode"),
                       hashlib.sha256((item.get("aggregatedOutput") or "").encode()).hexdigest())
        if not failed and observation not in self.seen_observations:
            # A new successful diagnostic/source observation is concrete new
            # context. Merely alternating old commands cannot reset the guard.
            self.counts.clear()
        self.seen_observations.add(observation)
        if not failed and not reading:
            return
        key = ("failure" if failed else "read", *observation)
        self.counts[key] += 1
        count = self.counts[key]
        warn, stop = (2, 3) if failed else (6, 12)
        if count in {warn, stop}:
            self.emit({"event": "REPEATED_UNCHANGED_EVIDENCE", "kind": key[0], "count": count,
                       "command": item.get("command"), "output_sha256": key[-1], "state_sha256": key[1],
                       "diagnosis": "unchanged input/output; supply new evidence or change approach"})
        if count >= stop:
            raise RuntimeError("repeated unchanged action/evidence after diagnostic; safe stop")


def watchdog(argv):
    """Independent process-group watchdog: silence or Controller death, not age."""
    idle, owner, heartbeat, *command = argv
    proc = subprocess.Popen(command)
    while proc.poll() is None:
        try:
            activity = Path(heartbeat)
            parked = activity.read_text() == "idle_between_verified_turns"
            stale = not parked and time.time() - activity.stat().st_mtime >= int(idle)
        except OSError:
            stale = True
        if os.getppid() != int(owner) or stale:
            try:
                Path(heartbeat).with_suffix(".watchdog.json").write_text(json.dumps({
                    "event": "WATCHDOG_STOP", "reason": "CONTROLLER_LOST" if os.getppid() != int(owner) else "NO_EFFECTIVE_EVENTS",
                    "idle_timeout_seconds": int(idle)}))
            except OSError:
                pass
            # Wrapper is the session/group leader; kill tools and model runtime.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.killpg(os.getpgrp(), signal.SIGTERM)
            time.sleep(1)
            os.killpg(os.getpgrp(), signal.SIGKILL)
        time.sleep(0.2)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(watchdog(sys.argv[1:]))
