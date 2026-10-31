"""Real fixed policy/Git/Factory admission; container and GitHub I/O are offline doubles.

No test executes FootballPrediction validation, Docker, providers or remote CI.
Synthetic PASS exercises evidence consumption, never establishes live delivery.
"""
from __future__ import annotations

import copy
import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, READY, git
from harness.factory_project import FootballPredictionContract, sha256
import test_factory_controller_gates as gates
import test_factory_project_integration as original
from test_factory_preflight_inspection import publication_body


class StrictRuntime(gates.LiveProtocolDouble):
    def __init__(self):
        super().__init__()
        self.commands, self.remote_calls, self.preflights = [], [], []
        self.outcome = "PASS"
        self.alter = lambda result: result

    def project_policy(self, spec, cwd, paths):
        return FootballPredictionContract().policy(spec, cwd, paths)

    def container_gate(self, policy, spec, cwd, target, command, transcript, timeout):
        self.commands.append(list(command))
        result = super().container_gate(policy, spec, cwd, target, command, transcript, timeout)
        if self.outcome == "exception":
            raise TimeoutError("OFFLINE interrupted container response")
        return self.alter({**result, "status": self.outcome,
                          "exit_code": 0 if self.outcome == "PASS" else 1,
                          "mission_id": spec["mission_id"], "scope_sha256": target["mission_scope_sha256"],
                          "container_policy": policy})

    def project_remote(self, action, policy, spec, cwd, target, body, *args, **kwargs):
        self.remote_calls.append(action)
        if action == "publish":
            # Original trusted PR body/scope preflight remains real.
            FootballPredictionContract().validate_pr_body(spec, cwd, target, body)
            self.preflights.append(target["head"])
        return super().project_remote(action, policy, spec, cwd, target, body, *args, **kwargs)


class StrictProfileAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.CanonicalRuntimeIntegrationTests.setUpClass()
        cls.addClassCleanup(original.CanonicalRuntimeIntegrationTests.doClassCleanups)

    def setUp(self):
        self.fx = original.CanonicalRuntimeIntegrationTests("test_pr_body_uses_original_trusted_preflight")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.f.close()
        self.runtime = StrictRuntime()
        self.serial = 0

    def start(self, *, workflow="STRICT", checks=None, ci=None, container=None):
        self.config = {**self.fx.config, "project_container": container or gates.CONTAINER,
                       "project_delivery": gates.DELIVERY,
                       "checks": checks or [["make", "verify-targeted"]],
                       "ci": ci or [["make", "verify-targeted"]]}
        self.f = Factory(self.fx.root / "strict-state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.fx.f = self.f
        self.fx.scope["workflow_class"] = workflow
        content = json.dumps(self.fx.scope, indent=2) + "\n"
        template = publication_body(self.fx, {"head": "{{candidate_head}}", "files": ["score.py", self.fx.path]})
        template = template.replace("CRITICAL", workflow)
        self.spec = {"version": 2, "mission_id": "feature", "repository": str(self.fx.repo),
                     "base": self.fx.base, "objective": "Offline strict admission fixture",
                     "pr_body_template": template,
                     "approved_mission_scope": {"approval_id": "offline-owner-fixture", "mission_id": "feature",
                         "base": self.fx.base, "path": self.fx.path, "content": content,
                         "sha256": sha256(content.encode()),
                         "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}}
        self.f.submit(self.spec)
        self.spec, self.cwd = self.f.prepare("feature")
        business = self.cwd / ("src/ui/strict_fixture.py" if workflow == "NORMAL" else "score.py")
        business.parent.mkdir(parents=True, exist_ok=True)
        business.write_text("def score():\n    return 2\n")
        self.target = self.f.checkpoint(self.spec, self.cwd)
        self.reviews = [{"lane": lane, "status": "PASS", "canonical_receipt_data": {
            "review_completed_at": "2026-10-28T00:00:00Z"}} for lane in ("reviewer", "second_reviewer")]
        self.assertEqual(self.target["project_policy"]["workflow_class"], workflow)

    def run_gates(self):
        return (self.f.gates(self.spec, self.cwd, self.target, "checks", 0) +
                self.f.gates(self.spec, self.cwd, self.target, "ci", 0))

    def save(self, label, **extra):
        root = os.environ.get("STRICT_PROFILE_EVIDENCE_DIR")
        if root:
            path = Path(root)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            operations = [dict(row) for row in self.f.db.execute("SELECT * FROM operations")]
            value = {"real": ["fixed original policy/classification", "Git", "Factory operations/admission"],
                     "external_doubles": ["container result", "GitHub I/O", "review metadata"],
                     "target": self.target, "commands": self.runtime.commands,
                     "remote_calls": self.runtime.remote_calls, "original_preflights": self.runtime.preflights,
                     "operations": operations, **extra}
            # Fixtures are cleaned; retain complete operation envelopes and raw transcripts here.
            value["evidence"] = {op["key"]: {"envelope": Path(op["evidence"]).read_text(),
                "raw": {r["path"]: Path(r["path"]).read_text(errors="replace")
                        for r in json.loads(op["result"]).get("raw_evidence", [])}}
                for op in operations if op["evidence"]}
            (path / (self._testMethodName + "." + label + ".json")).write_text(json.dumps(value, indent=2) + "\n")

    def blocked_publication(self, validations, label):
        with self.assertRaises(FactoryBlocked) as blocked:
            self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, validations)
        self.assertEqual(blocked.exception.status, "BLOCKED_VALIDATION")
        self.assertIn("verify-strict", blocked.exception.reason)
        self.assertEqual(self.runtime.remote_calls, [])
        self.save(label, rejection=blocked.exception.reason)

    def test_strict_targeted_only_cannot_publish(self):
        self.start(container={"image_id": gates.IMAGE, "profiles": ["targeted"]})
        validations = self.run_gates()
        self.assertEqual([v["status"] for v in validations], ["PASS", "PASS"])
        self.blocked_publication(validations, "targeted-only")

    def test_targeted_and_pr_cannot_replace_strict(self):
        self.start(ci=[["make", "verify-pr"]])
        self.blocked_publication(self.run_gates(), "targeted-pr")

    def test_configured_strict_without_execution_cannot_publish(self):
        self.start(ci=[["make", "verify-strict"]])
        self.blocked_publication([], "configured-only")

    def test_current_strict_allows_original_publication_preflight_and_is_reused(self):
        self.start(ci=[["make", "verify-strict"]])
        validations = self.run_gates()
        before = [dict(row) for row in self.f.db.execute("SELECT * FROM operations")]
        remote = self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, [])
        self.assertEqual(remote["ci"]["status"], "PASS")
        self.assertEqual(self.runtime.preflights, [self.target["head"]])
        self.assertIn('"profile": "strict"', remote["body"])
        # Same HEAD across restart, phase and round: read immutable success, do not re-execute.
        self.f.close()
        self.f = Factory(self.fx.root / "strict-state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.f.gates(self.spec, self.cwd, self.target, "ci", 1)
        self.f.project_final_gate(self.spec, self.cwd, self.target, self.reviews, remote)
        self.assertEqual(self.runtime.commands.count(["make", "verify-strict"]), 1)
        after = {row["id"]: dict(row) for row in self.f.db.execute("SELECT * FROM operations")}
        self.assertTrue(all(after[op["id"]] == op for op in before))
        self.save("current-bound-success", validations=validations)


    def new_head(self):
        self.serial += 1
        path = self.cwd / "score.py"
        path.write_text(path.read_text() + f"\n# New source fixture {self.serial}\n")
        self.target = self.f.checkpoint(self.spec, self.cwd)

    def test_failed_timeout_cancelled_unknown_and_interrupted_strict_never_publish(self):
        self.start(ci=[["make", "verify-strict"]])
        for outcome in ("FAIL", "TIMEOUT", "CANCELLED", "UNKNOWN", "exception"):
            with self.subTest(outcome=outcome):
                self.runtime.outcome = outcome
                try:
                    self.f.gates(self.spec, self.cwd, self.target, "ci", 0)
                except FactoryBlocked:
                    self.assertNotEqual(outcome, "FAIL")
                self.blocked_publication([], outcome)
                self.new_head()

    def test_wrong_execution_identity_cannot_be_consumed(self):
        self.start(ci=[["make", "verify-strict"]])
        mutations = {"profile": "pr", "mission_id": "other-task", "fixture": True,
                     "target": {"head": "0" * 40}, "exit_code": 1,
                     "scope_sha256": "0" * 64, "image_id": "sha256:" + "b" * 64,
                     "container_policy": {**gates.CONTAINER, "postgres_image_id": "sha256:" + "b" * 64}}
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.runtime.alter = lambda result, k=field, v=value: {**result, k: v}
                with self.assertRaises(FactoryBlocked):
                    self.f.gates(self.spec, self.cwd, self.target, "ci", 0)
                with self.assertRaises(FactoryBlocked):
                    self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, [])
                self.assertEqual(self.runtime.remote_calls, [])
                self.save(field)
                self.new_head()

    def test_source_new_head_and_caller_target_reduction_do_not_reuse_strict(self):
        self.start(ci=[["make", "verify-strict"]])
        self.run_gates()
        old = copy.deepcopy(self.target)
        for key, value in (("files", []), ("project_policy", {"workflow_class": "NORMAL"})):
            with self.subTest(key=key), self.assertRaises(FactoryBlocked):
                self.f.project_pr_ci(self.spec, self.cwd, {**self.target, key: value}, self.reviews, [])
        self.new_head()
        self.blocked_publication([], "new-source-head")
        # Even the old exact target and its old PASS cannot authorize the new HEAD.
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci(self.spec, self.cwd, old, self.reviews, [])
        self.assertEqual(self.runtime.commands.count(["make", "verify-strict"]), 1)

    def test_stat_cache_cannot_hide_changed_source_bytes_after_strict(self):
        self.start(ci=[["make", "verify-strict"]])
        self.run_gates()
        business = self.cwd / "score.py"
        git(self.cwd, "update-index", "--assume-unchanged", "score.py")
        business.write_text("def score():\n    return 9\n")
        self.assertEqual(git(self.cwd, "status", "--porcelain"), "")
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, [])
        self.assertEqual(self.runtime.remote_calls, [])
        self.save("actual-source-bytes")

    def test_task_and_executor_input_change_invalidates_strict(self):
        self.start(ci=[["make", "verify-strict"]])
        self.run_gates()
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci({**self.spec, "objective": "Another task"}, self.cwd, self.target, self.reviews, [])
        original_read = Path.read_bytes
        def changed(path):
            data = original_read(path)
            return data + b"\n# OFFLINE executor-upgrade fixture\n" if path.name == "factory_container.py" else data
        with patch.object(Path, "read_bytes", changed):
            self.blocked_publication([], "changed-executor")
        self.save("task-executor-invalidated")

    def test_changed_image_policy_and_raw_evidence_invalidate_strict(self):
        self.start(ci=[["make", "verify-strict"]])
        validations = self.run_gates()
        policy = copy.deepcopy(self.f.config["project_container"])
        self.f.config["project_container"]["image_id"] = "sha256:" + "b" * 64
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, [])
        self.f.config["project_container"] = policy
        op = self.f.db.execute("SELECT * FROM operations WHERE key=?", (validations[-1]["evidence_key"],)).fetchone()
        raw = Path(json.loads(op["result"])["raw_evidence"][0]["path"])
        raw.write_text("OFFLINE evidence corruption fixture")
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, [])
        self.assertEqual(self.runtime.remote_calls, [])
        self.save("changed-image-raw")

    def test_other_mission_strict_pass_cannot_be_reused(self):
        self.start(ci=[["make", "verify-strict"]])
        result = self.run_gates()[-1]
        other = copy.deepcopy(self.spec)
        other["mission_id"] = "other"
        scope = json.loads(other["approved_mission_scope"]["content"])
        scope["mission_id"] = "other"
        path = "docs/agentic/missions/other.json"
        scope["authorized_paths"] = ["score.py", path]
        content = json.dumps(scope, indent=2) + "\n"
        other["approved_mission_scope"].update(mission_id="other", path=path, content=content, sha256=sha256(content.encode()))
        other["mission_scope_file"] = path
        self.f.submit(other)
        other, cwd = self.f.prepare("other")
        (cwd / "score.py").write_text("def score(): return 3\n")
        target = self.f.checkpoint(other, cwd)
        self.runtime.alter = lambda _: result
        with self.assertRaises(FactoryBlocked):
            self.f.gates(other, cwd, target, "ci", 0)
        with self.assertRaises(FactoryBlocked):
            self.f.project_pr_ci(other, cwd, target, self.reviews, [result])
        self.assertEqual(self.runtime.remote_calls, [])
        self.save("other-mission", other_target=target)

    def test_legacy_strict_pass_is_not_retroactively_live_proof(self):
        from harness.factory import digest
        self.start(ci=[["make", "verify-strict"]])
        payload = {"command": ["make", "verify-strict"], "target": self.target, "round": 0}
        key = digest({"kind": "ci", "index": 0, **payload})
        old = self.f.operation("feature", key, "ci", "local", {"target": self.target}, payload, False,
            lambda transcript: self.runtime.container_gate(gates.CONTAINER, self.spec, self.cwd,
                self.target, payload["command"], transcript, 1))
        self.blocked_publication([{**old, "evidence_key": key}], "legacy-success")

    def test_phase_round_and_restart_do_not_repeat_successful_strict(self):
        self.start(checks=[["make", "verify-strict"]], ci=[["make", "verify-strict"]])
        results = self.run_gates()
        self.assertEqual(results[0]["evidence_key"], results[1]["evidence_key"])
        self.f.gates(self.spec, self.cwd, self.target, "ci", 2)
        self.assertEqual(self.runtime.commands, [["make", "verify-strict"]])
        self.save("one-execution")

    def test_recovery_and_final_entrypoints_block_before_external_io(self):
        self.start(ci=[["make", "verify-strict"]])
        for action in ("ci", "verify", "reconcile"):
            with self.subTest(action=action), self.assertRaises(FactoryBlocked):
                self.f.project_remote_read(action, self.spec, self.cwd, self.target, "body")
        with self.assertRaises(FactoryBlocked):
            self.f.project_final_gate(self.spec, self.cwd, self.target, self.reviews,
                                     {"ci": {"status": "PASS"}})
        payload = {"target": self.target, "policy": gates.DELIVERY, "body": "old response lost"}
        def interrupted(_):
            raise TimeoutError("OFFLINE old publication response lost")
        with self.assertRaises(FactoryBlocked):
            self.f.operation("feature", "legacy-publication", "project_publish", "github", payload, payload, False, interrupted)
        op = self.f.db.execute("SELECT * FROM operations WHERE key='legacy-publication'").fetchone()
        with self.assertRaises(FactoryBlocked):
            self.f.recover_publication(self.spec, self.cwd, op)
        self.assertEqual(self.runtime.remote_calls, [])
        self.save("blocked-recovery-final")

    def test_normal_keeps_targeted_and_pr_semantics(self):
        self.fx.scope["authorized_paths"].append("src/ui/strict_fixture.py")
        self.start(workflow="NORMAL", ci=[["make", "verify-pr"]])
        remote = self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, self.run_gates())
        self.assertEqual(remote["ci"]["status"], "PASS")
        self.assertEqual(self.runtime.commands, [["make", "verify-targeted"], ["make", "verify-pr"]])
        self.save("normal-original-preflight")

    def test_original_classifier_rejects_normal_claim_for_earlier_high_risk_change(self):
        self.fx.scope["authorized_paths"].extend(["src/ui/strict_fixture.py", "src/api/strict_probe.py"])
        self.start(workflow="NORMAL", ci=[["make", "verify-pr"]])
        high_risk = self.cwd / "src/api/strict_probe.py"
        high_risk.parent.mkdir(parents=True, exist_ok=True)
        high_risk.write_text("def health(): return True\n")
        self.f.checkpoint(self.spec, self.cwd)
        ui = self.cwd / "src/ui/strict_fixture.py"
        ui.write_text(ui.read_text() + "\n# Later ordinary UI change\n")
        self.target = self.f.checkpoint(self.spec, self.cwd)
        with self.assertRaises(FactoryBlocked) as blocked:
            self.f.project_pr_ci(self.spec, self.cwd, self.target, self.reviews, self.run_gates())
        self.assertIn("STRICT_REVIEW_CLASSIFICATION_REQUIRED", blocked.exception.reason)
        self.assertIsNone(self.runtime.remote)  # Original preflight refused before fake GitHub I/O.
        self.assertEqual(self.runtime.commands, [["make", "verify-targeted"], ["make", "verify-pr"]])
        self.save("original-classifier-full-range", rejection=blocked.exception.reason)


class StrictProfileStateTests(unittest.TestCase):
    """Real Factory state machine; named synthetic project/review/container/remote fixtures."""
    def setUp(self):
        self.flow = gates.FactoryLiveProtocolTests("test_state_flow_current_delivery_rechecks_ci_and_candidate")
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.f, self.runtime = self.flow.f, self.flow.runtime
        self.commands = []
        original_gate = self.runtime.container_gate
        def observe(*args):
            self.commands.append(list(args[4]))
            return original_gate(*args)
        self.patcher = patch.object(self.runtime, "container_gate", side_effect=observe)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def save(self, factory, report, label):
        root = os.environ.get("STRICT_PROFILE_EVIDENCE_DIR")
        if root:
            path = Path(root)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            operations = [dict(row) for row in factory.db.execute("SELECT * FROM operations")]
            value = {"real": ["Factory state machine", "Git", "immutable operation/evidence checks"],
                     "external_doubles": ["project policy", "container", "review", "GitHub I/O"],
                     "report": report, "commands": self.commands, "operations": operations,
                     "events": [dict(row) for row in factory.db.execute("SELECT * FROM events")],
                     "evidence": {op["key"]: {"envelope": Path(op["evidence"]).read_text(),
                         "raw": {r["path"]: Path(r["path"]).read_text(errors="replace")
                                 for r in json.loads(op["result"]).get("raw_evidence", [])}}
                         for op in operations if op["evidence"]}}
            (path / (self._testMethodName + "." + label + ".json")).write_text(json.dumps(value, indent=2) + "\n")

    def test_ready_and_run_reconsume_current_strict_without_reexecution(self):
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        count = self.commands.count(["make", "verify-strict"])
        self.assertGreater(count, 0)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], READY)
        self.assertEqual(self.commands.count(["make", "verify-strict"]), count)

        self.assertEqual(self.runtime.remote.writes, ["push", "create"])
        self.assertFalse(report["DONE"])
        self.save(self.f, report, "synthetic-current-ready")
        # A READY flag and synthetic final PASS cannot replace required evidence membership.
        row = self.f.db.execute("SELECT payload FROM events WHERE kind='delivery' ORDER BY sequence DESC LIMIT 1").fetchone()
        delivery = json.loads(row[0])
        strict_keys = {op["key"] for op in self.f.db.execute("SELECT * FROM operations WHERE stage IN ('checks','ci')")
                       if json.loads(op["result"]).get("profile") == "strict"}
        delivery["evidence_keys"] = [key for key in delivery["evidence_keys"] if key not in strict_keys]
        self.f.event("feature", "delivery", delivery)
        self.f.state("feature", READY)
        self.assertNotEqual(self.f.report("feature")["DELIVERY_STATUS"], READY)
        self.assertNotEqual(self.f.run("feature")["DELIVERY_STATUS"], READY)
        self.assertEqual(self.commands.count(["make", "verify-strict"]), count)
        self.save(self.f, self.f.report("feature"), "missing-evidence-membership")

    def test_targeted_only_state_flow_stops_before_review_and_publication(self):
        self.f.config["ci"] = [["make", "verify-targeted"]]
        # Construct a fresh journal under the authorized targeted-only operator policy.
        f = Factory(self.flow.fx.root / "targeted-state", self.f.config, self.runtime)
        self.addCleanup(f.close)
        f.submit(self.flow.spec)
        report = f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_VALIDATION", report)
        self.assertIsNone(self.runtime.remote)
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM operations WHERE stage='review'").fetchone()[0], 0)
        before = [dict(row) for row in f.db.execute("SELECT * FROM operations")]
        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
        self.assertEqual(before, [dict(row) for row in f.db.execute("SELECT * FROM operations")])
        self.save(f, report, "main-flow-rejected")

    def test_legacy_ready_with_no_executed_strict_is_blocked_in_report_resume_and_approval(self):
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").write_text("def score(): return 2\n")
        target = self.f.checkpoint(spec, cwd)
        self.f.event("feature", "delivery", {"target": target, "implemented": "OFFLINE legacy READY",
            "tests": "PASS", "ci": "PASS", "evidence_keys": [], "project_gate": {"status": "PASS"}})
        self.f.state("feature", READY)
        self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
        with self.assertRaises(ValueError):
            self.f.approve("feature", "merge", "OFFLINE probe", target["head"])
        self.assertEqual(self.commands, [])
        self.assertIsNone(self.runtime.remote)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM approvals").fetchone()[0], 0)
        self.save(self.f, self.f.report("feature"), "legacy-ready-rejected")

if __name__ == "__main__":
    unittest.main()
