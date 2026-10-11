"""Real LocalRuntime/adapter/project-validator integration; fake providers only.

Reads the exact project commit into temporary fixtures, never its working tree.
Set FOOTBALLPREDICTION_CONTRACT_REPO when the read-only source is not a sibling.
Missing source is an explicit skip, not a canonical integration PASS.
"""
from __future__ import annotations

import copy
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter
from harness.factory import Factory, FactoryBlocked, digest, git
from harness.factory_fixture import fixture_config
from harness.factory_project import BACKENDS, LANES, FootballPredictionContract, sha256
from harness.factory_runtime import LocalRuntime


PROJECT_BASE = "05dc75eb9c2e9e5ec042840d91fee4a3d480ce60"
DRIVER = Path(__file__).parent / "fixtures/footballprediction_fake_backend.py"


class CanonicalRuntimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ.get("FOOTBALLPREDICTION_CONTRACT_REPO",
            str(Path(__file__).resolve().parents[2] / "FootballPrediction")))
        if not source.is_dir():
            raise unittest.SkipTest("real canonical source unavailable; integration UNVERIFIED")
        cls.snapshot_tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.snapshot_tmp.cleanup)
        cls.snapshot = Path(cls.snapshot_tmp.name)
        archive = subprocess.check_output(["git", "--no-optional-locks", "-C", str(source),
            "archive", PROJECT_BASE, "scripts", "schemas/agentic", "Makefile",
            "docs/agentic/independent_review_backends.json"])
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(cls.snapshot, filter="data")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        shutil.copytree(self.snapshot, self.repo)
        (self.repo / "score.py").write_text("def score():\n    return 1\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.path = "docs/agentic/missions/feature.json"
        self.scope = {"schema_version": "agentic-mission-scope/v1", "mission_id": "feature",
            "task_type": "source-code", "workflow_class": "CRITICAL",
            "authorized_paths": ["score.py", self.path], "authorized_prefixes": [],
            "excluded_paths": [], "excluded_prefixes": [], "excluded_tokens": [],
            "protected_invariants": ["No production resources"],
            "forbidden_side_effects": ["No live providers"]}
        self.runtime = LocalRuntime()
        self.config = {**fixture_config(), "simulation": False, "project_contract": "footballprediction"}
        # No developer lane is invoked. Avoid unrelated authenticated profile probes.
        with patch.object(self.runtime, "profile_identity", return_value={"offline_test": True}):
            self.f = Factory(self.root / "state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.binary = self.root / "offline-fake-codex"
        self.binary.write_text("#!/bin/sh\nprintf 'codex-cli 0.0.1\\n'\n")
        self.binary.chmod(0o700)
        self.starts = []
        self.original_popen = subprocess.Popen
        # Only substitute canonical runner launchers. Git and the original
        # validators remain real subprocesses with the restricted environment.
        self.enter_patch(patch.object(FootballPredictionAdapter, "_trusted_base_checkout",
                                     return_value=self.snapshot))
        self.enter_patch(patch.object(FootballPredictionAdapter, "review_environment",
                                     return_value=FootballPredictionAdapter._trusted_git_environment()))
        self.enter_patch(patch("harness.factory_runtime.subprocess.Popen", side_effect=self.launch))

    def enter_patch(self, context):
        result = context.start()
        self.addCleanup(context.stop)
        return result

    def launch(self, argv, *args, **kwargs):
        argv = list(argv)
        script = next((i for i, value in enumerate(argv) if str(value) in {
            str(self.snapshot / "scripts/devops/codex_independent_review.py"),
            str(self.snapshot / "scripts/devops/claude_deepseek_independent_review.py")}), None)
        if script is not None:
            mode = "deepseek" if "claude_deepseek" in str(argv[script]) else "codex"
            arguments = argv[script + 1:]
            if "--evidence-dir" in arguments:
                evidence = Path(arguments[arguments.index("--evidence-dir") + 1])
                self.assertTrue(evidence.is_dir())
                FootballPredictionAdapter._validate_review_evidence_dir(evidence)
                self.starts.append((mode, evidence))
                operations = self.f.db.execute("SELECT * FROM operations WHERE stage='review'").fetchall()
                self.assertTrue(any(row["status"] == "RUNNING" and row["paid"] for row in operations))
            argv[script:script + 1] = [str(DRIVER), str(self.snapshot), mode, str(self.binary)]
        return self.original_popen(argv, *args, **kwargs)

    def candidate(self, newline="\n"):
        content = (json.dumps(self.scope, indent=2) + "\n").replace("\n", newline)
        spec = {"version": 2, "mission_id": "feature", "repository": str(self.repo),
                "base": self.base, "objective": "Offline integration probe",
                "approved_mission_scope": {"approval_id": "offline-owner-fixture", "mission_id": "feature",
                    "base": self.base, "path": self.path, "content": content,
                    "sha256": sha256(content.encode()),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}}
        self.f.submit(spec)
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").write_text("def score():\n    return 2\n")
        target = self.f.checkpoint(spec, cwd)
        return spec, cwd, target

    def review(self, spec, cwd, target, lane):
        # Only prepaid environmental availability is simulated. Actual local
        # directory preparation, operation reservation and canonical APIs run.
        with patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
            return self.f.project_review(spec, cwd, target, lane)

    def test_fresh_mission_both_real_runners_and_validators_with_fake_backends(self):
        spec, cwd, target = self.candidate()
        self.assertFalse((cwd.parent / ".cmh-review-evidence").exists())
        original = self.runtime.prepare_project_review
        prepared_lanes = []
        def prepare(*args):
            lane = args[3]
            self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations WHERE lane=?", (lane,)).fetchone()[0], 0)
            prepared = original(*args)
            self.assertTrue(prepared[1].is_dir())
            self.assertEqual(len(self.starts), 0 if lane == "reviewer" else 1)
            prepared_lanes.append(lane)
            return prepared
        with patch.object(self.runtime, "prepare_project_review", side_effect=prepare):
            reviews = [self.review(spec, cwd, target, lane) for lane in LANES]
        self.assertEqual(prepared_lanes, list(LANES))
        self.assertEqual([review["status"] for review in reviews], ["PASS", "PASS"])
        self.assertEqual([mode for mode, _ in self.starts], ["codex", "deepseek"])
        for mode, evidence in self.starts:
            calls = [json.loads(line) for line in (evidence / "offline-fake-backend-calls.jsonl").read_text().splitlines()]
            self.assertEqual(calls, [{"fixture": True, "backend": mode}])
        operations = [dict(row) for row in self.f.db.execute("SELECT * FROM operations")]
        # Reuse cached evidence; no second paid operation or launcher dispatch.
        for lane in LANES:
            self.review(spec, cwd, target, lane)
        self.assertEqual(len(self.starts), 2)
        self.assertEqual(operations, [dict(row) for row in self.f.db.execute("SELECT * FROM operations")])
        with self.assertRaises(FactoryBlocked):
            self.f.project_final_gate(spec, cwd, target, reviews)
        self.assertNotIn(self.f.row("feature")["status"], {"READY_FOR_USER_ACCEPTANCE", "MERGE_READY", "DONE"})

    def test_lf_scope_passes_original_deepseek_validator(self):
        spec, cwd, target = self.candidate()
        self.assertEqual(self.review(spec, cwd, target, "second_reviewer")["status"], "PASS")

    def test_crlf_scope_passes_original_validator_and_one_byte_tamper_rejected(self):
        spec, cwd, target = self.candidate("\r\n")
        self.assertEqual(target["mission_scope_sha256"], sha256((cwd / self.path).read_bytes()))
        self.assertEqual(self.review(spec, cwd, target, "second_reviewer")["status"], "PASS")
        row = self.f.db.execute("SELECT result FROM operations WHERE lane='second_reviewer'").fetchone()
        result = json.loads(row[0])
        scope = cwd / self.path
        scope.write_bytes(scope.read_bytes().replace(b"No production", b"no production", 1))
        with self.assertRaises(FactoryBlocked):
            self.f.target(spec, cwd)
        # The durable receipt certifies the committed scope, not mutable local
        # text. Even a re-sealed receipt cannot borrow a different byte hash.
        receipt_path = Path(result["canonical_receipt"])
        receipt = json.loads(receipt_path.read_text())
        receipt["mission_scope_sha256"] = sha256(scope.read_bytes())
        payload = {key: value for key, value in receipt.items() if key != "integrity"}
        receipt["integrity"]["receipt_payload_sha256"] = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
        receipt_path.write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            self.runtime.project_validate_review(spec, cwd, target, "second_reviewer", result)
        self.assertEqual(len(self.starts), 1)

    def test_evidence_conflicts_fail_before_reservation_and_dispatch(self):
        spec, cwd, target = self.candidate()
        root = cwd.parent / ".cmh-review-evidence"
        evidence = FootballPredictionAdapter.review_evidence_dir(str(cwd), "feature", "codex", target["head"])
        for conflict in ("file", "symlink", "nested-file", "nested-symlink"):
            with self.subTest(conflict=conflict):
                outside = self.root / "outside"
                outside.mkdir(exist_ok=True)
                if conflict == "file": root.write_text("conflict")
                elif conflict == "symlink": root.symlink_to(outside, target_is_directory=True)
                else:
                    evidence.parent.mkdir(parents=True, mode=0o700)
                    if conflict == "nested-file": evidence.write_text("conflict")
                    else: evidence.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(FactoryBlocked, "local preparation"):
                    self.review(spec, cwd, target, "reviewer")
                self.assertEqual(self.starts, [])
                self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
                self.assertEqual(list(outside.iterdir()), [])
                if root.is_symlink() or root.is_file(): root.unlink()
                else: shutil.rmtree(root)
        # A local environment/argv preparation failure is also unpaid.
        with patch.object(FootballPredictionAdapter, "review_environment", side_effect=RuntimeError("offline config unavailable")):
            with self.assertRaises(FactoryBlocked): self.review(spec, cwd, target, "reviewer")
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        self.assertEqual(self.starts, [])

    def test_traversal_and_candidate_symlink_are_not_accepted(self):
        spec, cwd, target = self.candidate()
        bad = copy.deepcopy(spec)
        bad["mission_id"] = "../outside"
        with self.assertRaises(ValueError):
            self.runtime.prepare_project_review(bad, cwd, target, "reviewer", 20)
        link = cwd.parent / "linked-candidate"
        link.symlink_to(cwd, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.runtime.prepare_project_review(spec, link, target, "reviewer", 20)
        with self.assertRaises(FactoryBlocked):
            self.review(spec, link, target, "reviewer")
        self.assertEqual(self.starts, [])
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)

    def test_existing_unknown_and_running_skip_preparation_and_dispatch(self):
        spec, cwd, target = self.candidate()
        identity = {"target": target, "backend": BACKENDS[LANES["reviewer"]],
                    "policy": target["project_policy"], "engine": "project-canonical-runner"}
        # Seed synthetic in-flight operations in isolated test databases only.
        # No existing ledger is opened, reset, refunded or reclassified.
        for status in ("UNKNOWN", "RUNNING"):
            db = Factory(self.root / status, self.config, type("OfflineIdentityRuntime", (LocalRuntime,), {
                "profile_identity": lambda *args: {"offline_test": True}})())
            try:
                db.submit(spec)
                db.prepare("feature")
                db.db.execute("INSERT INTO operations(id,mission,key,stage,lane,paid,identity,input,status,started) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (status, "feature", digest(identity), "review", "reviewer", 1,
                     json.dumps(identity), "{}", status, 1))
                db.db.commit()
                before = [tuple(row) for row in db.db.execute("SELECT * FROM operations")]
                authority = tuple(db.db.execute("SELECT spec,policy FROM missions").fetchone())
                with patch.object(db.runtime, "prepare_project_review", side_effect=AssertionError("must not prepare")):
                    for lane in LANES:
                        with self.assertRaisesRegex(FactoryBlocked, "not repeated|unresolved"):
                            db.project_review(spec, cwd, target, lane)
                self.assertEqual(before, [tuple(row) for row in db.db.execute("SELECT * FROM operations")])
                self.assertEqual(authority, tuple(db.db.execute("SELECT spec,policy FROM missions").fetchone()))
            finally:
                db.close()
        self.assertEqual(self.starts, [])
