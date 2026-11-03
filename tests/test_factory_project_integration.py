"""Real LocalRuntime/adapter/project-validator integration; fake providers only.

Reads the exact project commit into temporary fixtures, never its working tree.
Set FOOTBALLPREDICTION_CONTRACT_REPO when the read-only source is not a sibling.
Missing/stale source is a mandatory prerequisite error, never an integration PASS.
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

from harness.adapters import FootballPredictionAdapter, GateResult
from harness.factory import Factory, FactoryBlocked, digest, git, validate_mission
from harness.factory_fixture import fixture_config
from harness.factory_project import BACKENDS, LANES, FootballPredictionContract, sha256
from harness.factory_runtime import LocalRuntime
from footballprediction_contract import CONTRACT_HEAD as PROJECT_BASE, require_source


DRIVER = Path(__file__).parent / "fixtures/footballprediction_fake_backend.py"


class CanonicalRuntimeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = require_source()
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
        self.config["project_review_limits"] = {"approval_id": "offline-fake-provider-test-only",
            "max_deepseek_chunks": 4, "max_canonical_diff_bytes": 100000,
            "allow_unknown_provider_usage": True}
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
        if "-c" in argv:
            index = argv.index("-c") + 1
            marker = "from harness.factory_project import FootballPredictionContract; "
            if marker in argv[index]:
                setup = ("sys.path.insert(0," + repr(str(DRIVER.parent)) + "); "
                         "from footballprediction_validator_bootstrap import configure; "
                         "configure(" + repr(str(self.snapshot)) + "," + repr(str(DRIVER)) + "," + repr(str(self.binary)) + "); ")
                argv[index] = argv[index].replace(marker, marker + setup)
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

    def test_restarted_runtime_blocks_before_reservation_for_unfinished_validator(self):
        spec, cwd, target = self.candidate()
        evidence = self.f.root / "evidence" / spec["mission_id"]
        evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        pending = evidence / ("0" * 32 + ".validator-" + "1" * 32 + ".input.json")
        pending.write_text("{}"); pending.chmod(0o600)
        with patch.object(self.runtime, "prepare_project_review") as prepare:
            with self.assertRaisesRegex(FactoryBlocked, "UNKNOWN"):
                self.review(spec, cwd, target, "reviewer")
            prepare.assert_not_called()
        self.assertEqual(self.starts, [])
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        self.assertEqual(pending.read_text(), "{}")

    def test_lf_scope_passes_original_deepseek_validator(self):
        spec, cwd, target = self.candidate()
        self.assertEqual(self.review(spec, cwd, target, "second_reviewer")["status"], "PASS")

    def test_actual_canonical_chunks_exceed_authority_before_reservation_or_fake_backend(self):
        spec, cwd, target = self.candidate()
        (cwd / "score.py").write_text("\n".join(f"value_{i} = {i}" for i in range(2600)) + "\n")
        target = self.f.checkpoint(spec, cwd)
        limits = {**self.config["project_review_limits"], "max_deepseek_chunks": 8}
        plan = self.runtime.project_review_admission(spec, cwd, target, limits)
        self.assertGreater(plan["deepseek_backend_runs"], 1)
        self.assertEqual(plan["canonical_diff_sha256"], plan["chunk_manifest"]["full_diff_sha256"])
        with self.assertRaises(ValueError):
            self.runtime.project_review_admission(spec, cwd, target, {**limits, "max_deepseek_chunks": 1})
        # Enforce the same rejection through Factory's real prepare-before-reserve path.
        with patch.object(self.runtime, "project_review_admission", side_effect=lambda s, c, t, ignored:
                FootballPredictionContract().review_admission(s, c, t, {**limits, "max_deepseek_chunks": 1})):
            with self.assertRaises(FactoryBlocked): self.review(spec, cwd, target, "second_reviewer")
        self.assertEqual(self.starts, [])
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0)

    def test_pr_body_uses_original_trusted_preflight(self):
        spec, cwd, target = self.candidate()
        body = f"""## Summary
Offline fixture changes score.
## Scope
| Field | Value |
| --- | --- |
| Task type | source-code |
| Workflow class | CRITICAL |
| Mission ID | feature |
| Mission scope contract | {self.path} |
| Changed paths | score.py, {self.path} |
| Authorized paths | score.py, {self.path} |
| Excluded paths | none |
| Runtime behavior changed | yes |
| Business progress | Offline interface test |
## Documentation Impact
| Field | Value |
| --- | --- |
| Capability changed? | no |
| Milestone changed? | no |
| Canonical entrypoint changed? | no |
| Current blocker changed? | no |
| Data/model/authorization contract changed? | no |
| Repository structure/authority navigation changed? | no |
| Project vision / target-state changed? | no |
| Source-of-truth docs updated | no |
| Updated authoritative docs | none |
| If not updated, explicit reason | Synthetic score fixture preserves all project contracts and lifecycle boundaries. |
## Tests
Offline fixture only.
## Risk
No network, DB, model or production operations.
## Rollback
Revert the isolated fixture commit.
## Strict Review Evidence
| Field | Value |
| --- | --- |
| Version | 1 |
| Task type | CRITICAL |
| Provider | codex-cli, claude-code-deepseek |
| Reviewed full SHA | {target['head']} |
| Result | PASS |
| Timestamp | 2026-10-28T00:00:00Z |
"""
        path = FootballPredictionContract().validate_pr_body(spec, cwd, target, body)
        self.assertEqual(path.read_text(), body)
        with self.assertRaises(ValueError):
            FootballPredictionContract().validate_pr_body(spec, cwd, target, body.replace("CRITICAL", "NORMAL"))

    def publication_candidate(self, newline="\n"):
        from harness.factory_remote import render_body
        from test_factory_controller_gates import DELIVERY
        from test_factory_preflight_inspection import publication_body
        spec, cwd, target = self.candidate()
        template = publication_body(self, target).replace(
            "Offline source-policy contract probe.", "离线 UTF-8 正文 probe.").replace("\n", newline)
        spec = validate_mission({**spec, "pr_body_template": template})
        from test_factory_review_lifecycle import offline_review_summaries
        reviews = offline_review_summaries(self.root, spec, cwd, target)
        body = render_body(DELIVERY, spec, target, reviews, [])
        self.assertEqual(spec["pr_body_template"], template)
        self.assertEqual(body.count("\r\n"), template.rstrip().count("\r\n"))
        return spec, cwd, target, body, reviews

    def repeated_publication(self, newline):
        from harness.factory_remote import run as remote_run
        from test_factory_contract_binding import evidence
        from test_factory_controller_gates import DELIVERY, FakeRemote
        spec, cwd, target, body, reviews = self.publication_candidate(newline)
        events, preflights = [], []

        class RecordingRemote(FakeRemote):
            # Actual Remote publication/idempotency/observation code, with only
            # the existing Git/GitHub API response double at its I/O boundary.
            def publish(remote, *args, **kwargs):
                events.append("publish")
                return super().publish(*args, **kwargs)

            def observe(remote, *args, **kwargs):
                events.append("observe")
                return super().observe(*args, **kwargs)

            def ci(remote, *args, **kwargs):
                events.append("ci:wait" if kwargs["wait"] else "ci:read")
                return super().ci(*args, **kwargs)

        remote = RecordingRemote(cwd, self.root / "remote.raw", spec, target, body)
        remote.adapter = adapter = FootballPredictionAdapter()
        original_call = adapter._call
        current_action = None

        def original_preflight(argv, **kwargs):
            result = original_call(argv, **kwargs)
            path = Path(argv[-4])
            preflights.append({"action": current_action, "exit_code": result.returncode,
                "cwd": kwargs["cwd"], "trusted_root": argv[-6], "base": argv[-2], "head": argv[-1],
                "body_path": str(path), "body_sha256": sha256(path.read_bytes())})
            return result

        cached = cwd.parent / ".cmh-publication" / (sha256(body.encode("utf-8")) + ".md")
        first_stat = None
        outcomes = []
        with patch("harness.factory_remote.Remote", return_value=remote), \
                patch.object(adapter, "_call", side_effect=original_preflight), \
                patch.object(adapter, "ci", return_value=GateResult("PASS", "OFFLINE CI facts only")):
            for index, action in enumerate(("publish", "reconcile", "ci", "verify", "publish")):
                current_action = action
                result = remote_run(action, DELIVERY, spec, cwd, target, body,
                    self.root / f"publication-{index}.raw", 5, reviews=reviews)
                outcomes.append({"action": action, "status": result["status"]})
                if action == "verify":
                    # The original final gate still refuses absent dual receipts.
                    # Only the cache/body admission and remote paths are proved.
                    self.assertEqual(result["status"], "BLOCKED_EXTERNAL")
                    self.assertTrue(result["reason"], "original validator must explain absent canonical receipts")
                else:
                    self.assertEqual(result["status"], "PASS")
                self.assertEqual(cached.read_bytes(), body.encode("utf-8"))
                self.assertEqual(cached.stat().st_mode & 0o777, 0o600)
                self.assertEqual(cached.parent.stat().st_mode & 0o777, 0o700)
                current_stat = (cached.stat().st_ino, cached.stat().st_mtime_ns)
                if first_stat is None: first_stat = current_stat
                self.assertEqual(current_stat, first_stat, "重复检查不得重写已批准正文")
        self.assertEqual(events, ["publish", "observe", "observe", "ci:wait", "observe",
                                  "ci:read", "observe", "ci:read", "observe", "publish", "observe"])
        self.assertEqual(remote.writes, ["push", "create"], "同一正文不得重复发布写入")
        self.assertEqual([row["action"] for row in preflights], [row["action"] for row in outcomes])
        for row in preflights:
            self.assertEqual(row["exit_code"], 0)
            self.assertEqual(row["trusted_root"], str(self.snapshot))
            self.assertEqual((row["cwd"], row["base"], row["head"]), (str(cwd), target["base"], target["head"]))
            self.assertEqual(row["body_sha256"], sha256(body.encode("utf-8")))
        self.assertEqual(self.starts, [])
        evidence(self.id(), {"OFFLINE_ONLY": True, "original_rules_baseline": PROJECT_BASE,
            "body_sha256": sha256(body.encode("utf-8")), "body_crlf_count": body.count("\r\n"),
            "outcomes": outcomes, "remote_events": events, "write_double_events": remote.writes,
            "original_preflights": preflights, "final_gate": "blocked by original missing dual-receipt requirement"})

    def test_lf_body_repeats_actual_publication_observation_and_ci_paths(self):
        self.repeated_publication("\n")

    def test_crlf_body_repeats_actual_publication_observation_and_ci_paths(self):
        self.repeated_publication("\r\n")

    def test_cached_body_rejects_actual_changes_including_only_newline_bytes(self):
        spec, cwd, target, body, _ = self.publication_candidate()
        adapter = FootballPredictionAdapter()
        contract = FootballPredictionContract(adapter)
        path = contract.validate_pr_body(spec, cwd, target, body)
        original = body.encode("utf-8")
        for modified in (original.replace(b"\n", b"\r\n"), original + b" ", original.replace(b"probe", b"other")):
            with self.subTest(modified_sha256=sha256(modified)):
                path.write_bytes(modified)
                with patch.object(adapter, "_call", wraps=adapter._call) as preflight:
                    with self.assertRaisesRegex(ValueError, "publication body evidence changed"):
                        contract.validate_pr_body(spec, cwd, target, body)
                preflight.assert_not_called()
                self.assertEqual(path.read_bytes(), modified, "拒绝不得改写原证据")

    def test_publication_cache_symlinks_and_wrong_path_type_are_rejected(self):
        spec, cwd, target, body, _ = self.publication_candidate()
        contract = FootballPredictionContract()
        path = contract.validate_pr_body(spec, cwd, target, body)
        victim = self.root / "unrelated-body.md"
        victim.write_bytes(body.encode("utf-8"))
        victim.chmod(0o640)
        path.unlink()
        for destination in (victim, self.root / "missing-body.md"):
            with self.subTest(destination=destination):
                path.symlink_to(destination)
                with self.assertRaises((ValueError, RuntimeError)):
                    contract.validate_pr_body(spec, cwd, target, body)
                path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RuntimeError): contract.validate_pr_body(spec, cwd, target, body)
        path.parent.unlink()
        path.parent.write_text("not an evidence directory")
        with self.assertRaises(RuntimeError): contract.validate_pr_body(spec, cwd, target, body)
        self.assertEqual(victim.read_bytes(), body.encode("utf-8"))
        self.assertEqual(victim.stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.root / "missing-body.md").exists())

    def test_crlf_invalid_metadata_and_wrong_target_still_prevent_publication(self):
        from harness.factory_remote import run as remote_run
        from test_factory_controller_gates import DELIVERY, FakeRemote
        spec, cwd, target, body, reviews = self.publication_candidate("\r\n")
        remote = FakeRemote(cwd, self.root / "remote.raw", spec, target, body)
        remote.adapter = FootballPredictionAdapter()
        with patch("harness.factory_remote.Remote", return_value=remote):
            with self.assertRaisesRegex(ValueError, "canonical PR body/scope preflight rejected"):
                remote_run("publish", DELIVERY, spec, cwd, target, body.replace("CRITICAL", "NORMAL"),
                    self.root / "invalid-metadata.raw", 5, reviews=reviews)
            for key, value in (("head", "0" * 40), ("mission_scope_sha256", "0" * 64)):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    remote_run("publish", DELIVERY, spec, cwd, {**target, key: value}, body,
                        self.root / (key + ".raw"), 5, reviews=reviews)
        self.assertEqual(remote.writes, [])
        self.assertIsNone(remote.raw)
        self.assertEqual(self.starts, [])

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
