"""Offline staged repair against the FootballPrediction container receipt shape."""
import copy
import json
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, IMPLEMENTATION_CHECKPOINT, READY, digest, git
from test_factory_controller_gates import CONTAINER, DELIVERY, LIMITS, LiveProtocolDouble
from test_factory_implementation_checkpoints import DependentRuntime
import test_factory_project as project_fixtures


VALIDATOR = "src/infrastructure/odds_staging/validators.js"
ESLINT = f"""[Validation] profile=targeted changed_files=4
[Validation] JavaScript static check: npm run lint

/app/{VALIDATOR}
  91:1  error  Function 'validateTimeAndProvenance' has a complexity of 16. Maximum allowed is 15  complexity

✖ 1 problem (1 error, 0 warnings)

[Validation] JavaScript static check failed with exit code 1.
"""


class StagedRepairRuntime(LiveProtocolDouble):
    def __init__(self, mode):
        super().__init__()
        self.builder = DependentRuntime()
        self.dispatches = []
        self.mode = mode

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        self.dispatches.append((role, payload.get("task_index")))
        if role == "rework":
            self.assert_repair_scope = payload["scope"]
            self.repair_feedback = payload["feedback"]
            transcript.write_text("offline repair\n")
            if self.mode == "unknown-repair":
                return {"status": "UNKNOWN"}
            edit = {"before": "// complexity fixture", "after": "// repaired offline"}
            if self.mode == "out-of-scope-repair":
                edit["path"] = "consumer.py"
            return {"output": {"summary": "Simplified validation", "known_risks": [], "edit": edit},
                    "usage": {"input_tokens": 30, "output_tokens": 0}}
        result = self.builder.agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        if role == "implement" and payload.get("task_index") == 0:
            path = cwd / VALIDATOR
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"// complexity fixture\r\n" if self.mode == "crlf" else b"// complexity fixture\n")
        return result

    def container_gate(self, policy, spec, cwd, target, command, transcript, timeout):
        result = super().container_gate(policy, spec, cwd, target, command, transcript, timeout)
        if (cwd / "consumer.py").is_file():
            if self.mode == "final-failure":
                transcript.write_text("final fixture failed\n")
                return {**result, "status": "FAIL", "exit_code": 1}
            return result
        text = (cwd / VALIDATOR).read_text()
        if (text == "// repaired offline\n" and self.mode != "repair-fails"
                or self.mode == "recorded-extra-edit" and text.startswith("// repaired offline\n")):
            if self.mode == "missing-retest-log":
                transcript.unlink()
            return result
        if self.mode != "missing-log":
            transcript.write_text("infrastructure outage\n" if self.mode == "infrastructure" else ESLINT)
        else:
            transcript.unlink()
        return {**result, "status": "UNKNOWN" if self.mode == "unknown-check" else "FAIL",
                "exit_code": 1, "outcome": "EXITED", "source_unchanged": True,
                "preparation_diagnostics_complete": True, "preparation_cleanup_confirmed": True,
                "validation_client_cleanup": {"confirmed": True, "diagnostics_complete": True, "exit_code": 1}}


class CheckpointReworkTests(unittest.TestCase):
    def prepare(self, mode, *, rounds=2, calls=6, tokens=300, wall=None, permission=True):
        fx = project_fixtures.ProjectContractTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        if mode == "crlf":
            (fx.repo / ".gitattributes").write_text("*.js text eol=crlf\n")
            git(fx.repo, "add", ".gitattributes")
            git(fx.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost",
                "commit", "-qm", "Set CRLF checkout")
            fx.base = git(fx.repo, "rev-parse", "HEAD")
        self.outputs = ["score.py", "tests/test_average.py", VALIDATOR]
        fx.scope["authorized_paths"] += [*self.outputs[1:], "consumer.py", "tests/test_consumer.py"]
        approval = fx.approval()
        if permission is not None:
            approval["intermediate_rework"] = permission
        self.spec = {**fx.spec, "base": fx.base, "approved_mission_scope": approval,
                     "pr_body_template": "OFFLINE PR {{candidate_head}} {{review_timestamp}}"}
        self.config = {**copy.deepcopy(fx.config), "review_mode": "single_openai", "simulation": False,
                       "implementation_checkpoints": True, "implementation_checkpoint_outputs": [self.outputs],
                       "max_rounds": rounds, "project_container": CONTAINER, "project_delivery": DELIVERY,
                       "project_review_limits": LIMITS, "checks": [["make", "verify-targeted"]],
                       "ci": [["make", "verify-strict"]],
                       "budget": {"max_agent_runs": calls, "max_run_tokens": 50, "max_total_tokens": tokens}}
        if wall is not None:
            self.config["budget"]["max_wall_seconds"] = wall
        self.config["profiles"].pop("second_reviewer")
        self.state = fx.root / "staged-repair"
        self.mode = mode

    def open(self):
        self.runtime = StagedRepairRuntime(self.mode)
        return closing(Factory(self.state, self.config, self.runtime))

    @staticmethod
    def paid(factory):
        return [dict(row) for row in factory.db.execute("SELECT * FROM operations WHERE paid=1 ORDER BY rowid")]

    def run_first(self):
        with self.open() as factory:
            mission = factory.submit(self.spec)
            with patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
                return factory.run(mission), self.paid(factory)

    @staticmethod
    def original_operations(factory):
        rows = [dict(row) for row in factory.db.execute("SELECT * FROM operations ORDER BY rowid")]
        files = [Path(row["evidence"]) for row in rows]
        files += [Path(ref["path"]) for row in rows for ref in json.loads(row["result"])["raw_evidence"]]
        return rows, {path: path.read_bytes() for path in files}

    def test_approved_complexity_repair_resumes_and_preserves_old_operations(self):
        self.prepare("pass")
        first, paid = self.run_first()
        self.assertEqual(first["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT)
        self.assertEqual([row["stage"] for row in paid], ["plan", "implement", "rework"])
        self.assertEqual(self.runtime.assert_repair_scope, [VALIDATOR])
        diagnosis = self.runtime.repair_feedback[0]["diagnostics"][0]
        self.assertIn("has a complexity of 16", diagnosis["log_tail"])
        event = first["IMPLEMENTATION_CHECKPOINTS"][0]
        self.assertNotEqual(event["target"]["head"], diagnosis["head"])
        cwd = Path(first["CANDIDATE"])
        self.assertEqual(git(cwd, "rev-parse", "HEAD^"), diagnosis["head"])
        self.assertEqual(event["repair"], paid[-1]["key"])
        binding = json.loads(paid[-1]["input"])["checkpoint_repair"]
        self.assertEqual(binding["approval_sha256"], digest(self.spec["approved_mission_scope"]))
        with self.open() as factory:
            rows, before = self.original_operations(factory)
        with self.open() as factory:
            final = factory.run(self.spec["mission_id"])
            self.assertEqual(final["DELIVERY_STATUS"], READY, final["BLOCKERS_REMAINING"])
            self.assertEqual(self.runtime.dispatches, [("implement", 1)])
            after = self.paid(factory)
            self.assertEqual(after[:3], paid)
            self.assertEqual([op["stage"] for op in after], ["plan", "implement", "rework", "implement", "review"])
            self.assertEqual(self.original_operations(factory)[0][:len(rows)], rows)
            self.assertEqual({p: Path(p).read_bytes() for p in before}, before)

    def test_failed_or_unknown_repair_preserves_accounting_and_stops(self):
        for mode, expected in (("repair-fails", "BLOCKED_VALIDATION"), ("unknown-repair", "UNKNOWN"),
                               ("missing-retest-log", "UNKNOWN"),
                               ("out-of-scope-repair", "BLOCKED_SCOPE")):
            with self.subTest(mode=mode):
                self.prepare(mode)
                result, paid = self.run_first()
                self.assertEqual(result["DELIVERY_STATUS"], expected, result["BLOCKERS_REMAINING"])
                self.assertEqual([row["stage"] for row in paid], ["plan", "implement", "rework"])
                self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", result)
                if mode == "unknown-repair":
                    self.assertEqual(result["BUDGET_USED"]["unknown_token_reservation"], 50)
                with self.open() as factory:
                    self.assertEqual(factory.run(self.spec["mission_id"])["DELIVERY_STATUS"], expected)
                    self.assertEqual(self.runtime.dispatches, [])
                    self.assertEqual(self.paid(factory), paid)

    def test_unknown_evidence_authority_and_remaining_budget_reject_before_repair(self):
        scenarios = [
            ("missing-log", {}, "UNKNOWN"),
            ("infrastructure", {}, "BLOCKED_VALIDATION"),
            ("unknown-check", {}, "UNKNOWN"),
            ("pass", {"rounds": 1}, "BLOCKED_VALIDATION"),
            ("pass", {"calls": 4}, "BLOCKED_BUDGET"),
            ("pass", {"tokens": 190}, "BLOCKED_BUDGET"),
            ("pass", {"wall": 60}, "BLOCKED_BUDGET"),
        ]
        for mode, kwargs, expected in scenarios:
            with self.subTest(mode=mode, **kwargs):
                self.prepare(mode, **kwargs)
                result, paid = self.run_first()
                self.assertEqual(result["DELIVERY_STATUS"], expected, result["BLOCKERS_REMAINING"])
                self.assertEqual([row["stage"] for row in paid], ["plan", "implement"])

    def test_final_failure_cannot_buy_a_second_shared_repair(self):
        self.prepare("final-failure")
        first, paid = self.run_first()
        self.assertEqual(first["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT)
        with self.open() as factory:
            final = factory.run(self.spec["mission_id"])
            self.assertEqual(final["DELIVERY_STATUS"], "BLOCKED_LIMIT", final["BLOCKERS_REMAINING"])
            after = self.paid(factory)
            self.assertEqual(after[:3], paid)
            self.assertEqual([row["stage"] for row in after], ["plan", "implement", "rework", "implement"])
            self.assertEqual(self.runtime.dispatches, [("implement", 1)])

    def test_intermediate_repair_requires_structured_permission_before_reservation(self):
        for label, permission, constraints in (
            ("absent", None, []),
            ("text only", None, ["Allow one intermediate repair."]),
            ("explicit denial", False, ["No intermediate repair."]),
            ("final only", None, ["Allow a shared repair only after final QA or review."]),
        ):
            with self.subTest(label=label):
                self.prepare("pass", permission=permission)
                self.spec["constraints"] = constraints
                first, paid = self.run_first()
                self.assertEqual(first["DELIVERY_STATUS"], "BLOCKED_VALIDATION")
                self.assertIn("does not authorize intermediate", first["BLOCKERS_REMAINING"][0])
                self.assertEqual([op["stage"] for op in paid], ["plan", "implement"])
                self.assertEqual(self.runtime.dispatches, [("plan", None), ("implement", 0)])
                self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", first)

    def test_drift_at_write_and_before_commit_never_reaches_retest(self):
        apply = Factory.apply_checkpoint_repair

        def append(source):
            with source.open("ab") as stream:
                stream.write(b"// unrelated edit\n")

        def drift_before_write(source, original, replacement):
            append(source)
            apply(source, original, replacement)

        def drift_after_write(source, original, replacement):
            apply(source, original, replacement)
            append(source)

        for inject, text in ((drift_before_write, "bytes or identity changed"),
                             (drift_after_write, "not the exact replacement")):
            with self.subTest(inject=inject.__name__):
                self.prepare("pass")
                with patch.object(Factory, "apply_checkpoint_repair", staticmethod(inject)):
                    first, paid = self.run_first()
                self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN", first["BLOCKERS_REMAINING"])
                self.assertIn(text, first["BLOCKERS_REMAINING"][0])
                self.assertNotIn("IMPLEMENTATION_CHECKPOINTS", first)
                self.assertIn(b"// unrelated edit", (Path(first["CANDIDATE"]) / VALIDATOR).read_bytes())
                with self.open() as factory:
                    self.assertEqual(factory.run(self.spec["mission_id"])["DELIVERY_STATUS"], "UNKNOWN")
                    self.assertEqual(self.runtime.dispatches, [])
                    self.assertEqual(self.paid(factory), paid)
                    self.assertEqual(factory.db.execute("SELECT COUNT(*) FROM operations WHERE stage='checks'").fetchone()[0], 1)

    def test_reopen_rejects_even_a_recorded_pass_for_wrong_repair_blob(self):
        self.prepare("recorded-extra-edit")
        apply = Factory.apply_checkpoint_repair

        def extra_edit(source, original, replacement):
            apply(source, original, replacement + b"// unrelated edit\n")

        # Model a receipt already persisted using the prior, path-only check.
        with (patch.object(Factory, "apply_checkpoint_repair", staticmethod(extra_edit)),
              patch.object(Factory, "verify_checkpoint_repair_commit")):
            first, paid = self.run_first()
        self.assertEqual(first["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, first["BLOCKERS_REMAINING"])
        with self.open() as factory:
            rows, evidence = self.original_operations(factory)
            result = factory.run(self.spec["mission_id"])
            self.assertEqual(result["DELIVERY_STATUS"], "UNKNOWN")
            self.assertIn("not the exact replacement", result["BLOCKERS_REMAINING"][0])
            self.assertEqual(self.runtime.dispatches, [])
            self.assertEqual(self.paid(factory), paid)
            self.assertEqual(self.original_operations(factory), (rows, evidence))

    def test_repair_verifies_committed_blob_with_crlf_checkout(self):
        self.prepare("crlf")
        first, _ = self.run_first()
        self.assertEqual(first["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, first["BLOCKERS_REMAINING"])
        cwd = Path(first["CANDIDATE"])
        self.assertEqual((cwd / VALIDATOR).read_bytes(), b"// repaired offline\r\n")
        self.assertEqual(git(cwd, "show", f"HEAD:{VALIDATOR}").encode(), b"// repaired offline\n")
        with self.open() as factory:
            observed = factory.report(self.spec["mission_id"])
            self.assertEqual(observed["DELIVERY_STATUS"], IMPLEMENTATION_CHECKPOINT, observed["BLOCKERS_REMAINING"])
            self.assertEqual(observed["IMPLEMENTATION_CHECKPOINTS"], first["IMPLEMENTATION_CHECKPOINTS"])
