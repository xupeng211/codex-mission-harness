"""Offline contract fixtures. No fixture is a real project approval or delivery."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from harness.adapters import FootballPredictionAdapter, GateResult
from harness.factory import Factory, FactoryBlocked, READY, git, validate_config
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_project import (FootballPredictionContract, OFFLINE_PASS, approved_scope,
                                    review_manifest, sha256)
from harness.factory_runtime import LocalRuntime


class FixtureReceiptAdapter:
    """Synthetic receipt validator; intentionally has no CLI/provider provenance."""

    def review_result(self, reviewer, **args):
        try:
            payload = json.loads(Path(args["stdout_path"]).read_text())
            path = Path(payload["review_receipt"])
            receipt = json.loads(path.read_text())
            if receipt.get("fixture") is not True or receipt.get("valid") is not True:
                raise ValueError("fixture receipt rejected")
            if receipt.get("executed_identity") != f"fixture-{reviewer}-session":
                raise ValueError("fixture execution mismatch")
            return GateResult(receipt["review_result"], "FIXTURE validator; no real review", str(path), receipt)
        except (ValueError, OSError, KeyError):
            return GateResult("BLOCKED_EXTERNAL", "FIXTURE receipt invalid/missing")


class ProjectRuntime(AcceptanceRuntime):
    def __init__(self):
        super().__init__()
        self.contract = FootballPredictionContract(FixtureReceiptAdapter())
        self.mutate_receipt = lambda receipt, lane: None
        self.final_status = "PASS"
        self.final_calls = 0

    def project_policy(self, spec, cwd, paths, *, review_mode="dual"):
        scope = json.loads(approved_scope(spec)["content"])
        if set(paths) - set(scope["authorized_paths"]):
            raise ValueError("FIXTURE scope rejects path")
        workflow = scope["workflow_class"]
        return {"workflow_class": workflow,
                "required_backends": ["codex-cli"] if review_mode == "single_openai" else ["claude-code-deepseek"] if workflow == "NORMAL" else
                    ["codex-cli"] if workflow == "STRICT" else ["codex-cli", "claude-code-deepseek"],
                "codex_model": "fixture-current-pin", "codex_effort": "medium",
                **({"single_review_eligible": workflow in {"NORMAL", "STRICT"}} if review_mode == "single_openai" else {}),
                "factory_required_backends": ["codex-cli"] if review_mode == "single_openai" else ["codex-cli", "claude-code-deepseek"], "factory_p3_blocks": True}

    def prepare_project_review(self, spec, cwd, target, lane, timeout):
        return None  # Synthetic runtime; real LocalRuntime integration is tested separately.

    def project_review(self, spec, cwd, target, lane, transcript, timeout, *, prepared=None):
        self.calls.append({"role": "canonical-review-fixture", "lane": lane})
        reviewer = "codex" if lane == "reviewer" else "deepseek"
        findings = []
        if " // " in (cwd / "score.py").read_text():
            findings = [{"severity": "P2", "title": "Fractional average", "summary": "Use true division"}]
        receipt = {"fixture": True, "valid": True, "base_sha": target["base"],
                   "reviewed_head_sha": target["head"], "mission_id": spec["mission_id"],
                   "diff_sha256": target["diff_sha256"], "mission_scope_sha256": target["mission_scope_sha256"],
                   "model_provenance": {"review_model": "fixture-current-pin", "review_reasoning_effort": "medium"},
                   "executed_identity": f"fixture-{reviewer}-session",
                   "review_result": "FAIL" if findings else "PASS", "findings": findings}
        self.mutate_receipt(receipt, lane)
        evidence = transcript.parent / (transcript.stem + "-fixture-artifacts")
        evidence.mkdir(mode=0o700)
        path = evidence / "fixture-receipt.json"
        path.write_text(json.dumps(receipt))
        path.chmod(0o600)
        transcript.write_text(json.dumps({"fixture": True, "review_receipt": str(path)}))
        stderr = transcript.with_suffix(".stderr")
        stderr.write_text("")
        return {"stdout_path": str(transcript), "stderr_path": str(stderr), "evidence_dir": str(evidence),
                "exit_code": 0, "fixture": True, "usage": {"fixture_provider_calls": 0},
                "project_evidence": [{"path": str(path), "sha256": sha256(path.read_bytes())}]}

    def project_validate_review(self, *args):
        return self.contract.validate_review(*args)

    def project_final_gate(self, spec, cwd, target, reviews, transcript, timeout):
        self.final_calls += 1
        result = {"status": self.final_status, "target": target, "fixture": True,
                  "reason": "FIXTURE project final gate; no PR/CI or real readiness"}
        transcript.write_text(json.dumps(result))
        return result


class ProjectContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "score.py").write_text("def add(a,b):\n    return a+b\n")
        # Preflight checks only source presence. These are named fixture stubs,
        # never executed or described as the FootballPrediction implementation.
        for name in FootballPredictionAdapter.REVIEW_CONTRACT_PATHS:
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# offline fixture stub\n")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "base")
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.config = {**fixture_config(), "project_contract": "footballprediction", "max_context_bytes": 1}
        self.runtime = ProjectRuntime()
        self.f = Factory(self.root / "state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.path = "docs/agentic/missions/feature.json"
        self.scope = {"schema_version": "agentic-mission-scope/v1", "mission_id": "feature",
                      "task_type": "source-code", "workflow_class": "STRICT",
                      "authorized_paths": ["score.py", "tests/test_score.py", self.path],
                      "authorized_prefixes": [], "excluded_paths": [], "excluded_prefixes": [],
                      "excluded_tokens": [], "protected_invariants": ["No production resources"],
                      "forbidden_side_effects": ["network", "training"]}
        self.spec = {"version": 2, "mission_id": "feature", "repository": str(self.repo),
                     "base": self.base, "objective": "Add average", "approved_mission_scope": self.approval()}

    def approval(self):
        content = json.dumps(self.scope, ensure_ascii=False, indent=2) + "\n"
        return {"approval_id": "owner-offline-fixture", "mission_id": "feature", "base": self.base,
                "path": self.path, "content": content, "sha256": sha256(content.encode()),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}

    def submit(self):
        self.f.submit(self.spec)

    def ready_fixture(self):
        self.submit()
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], OFFLINE_PASS, report)
        self.assertNotEqual(report["DELIVERY_STATUS"], READY)
        return report

    def single_factory(self, name="single", workflow="NORMAL"):
        config = copy.deepcopy(self.config)
        config["review_mode"] = "single_openai"
        config["profiles"].pop("second_reviewer")
        self.scope["workflow_class"] = workflow
        self.spec["approved_mission_scope"] = self.approval()
        runtime = ProjectRuntime()
        factory = Factory(self.root / name, config, runtime)
        self.addCleanup(factory.close)
        return factory, runtime

    def test_single_review_rework_new_head_and_no_second_reservation(self):
        factory, runtime = self.single_factory()
        factory.submit(self.spec)
        report = factory.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], OFFLINE_PASS, report)
        self.assertEqual(report["REVIEW_MODE"], "single_openai")
        self.assertEqual(report["SECOND_REVIEW_STATUS"], "NOT_ENABLED")
        from harness.factory_cli import readable
        self.assertIn("单审模式（OpenAI 独立审核）；第二审未启用", readable(report))
        self.assertEqual([r["lane"] for r in report["REVIEW_RESULT"]], ["reviewer"])
        operations = list(factory.db.execute("SELECT * FROM operations"))
        self.assertFalse(any(o["lane"] == "second_reviewer" for o in operations))
        reviews = [json.loads(o["input"])["target"]["head"] for o in operations if o["stage"] == "review"]
        self.assertEqual(len(reviews), 2)
        self.assertNotEqual(reviews[0], reviews[1])
        self.assertEqual(report["TARGET_HEAD"], reviews[-1])
        repairs = [c for c in runtime.calls if c["role"] == "rework"]
        self.assertEqual(len(repairs), 1)
        self.assertEqual(repairs[0]["payload"]["feedback"][0]["department"], "reviewer")
        self.assertEqual(len([o for o in operations if o["paid"]]), 5)
        spec, cwd = factory.prepare("feature")
        with self.assertRaisesRegex(FactoryBlocked, "not enabled"):
            factory.project_review(spec, cwd, factory.target(spec, cwd), "second_reviewer")

    def test_single_invalid_incomplete_stale_reviews_never_pass(self):
        mutations = [lambda r: r.update(valid=False), lambda r: r.pop("findings"),
                     lambda r: r.update(review_result="NO_VERDICT"),
                     lambda r: r.update(reviewed_head_sha="b" * 40)]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                factory, runtime = self.single_factory(f"single-invalid-{index}")
                runtime.mutate_receipt = lambda r, lane, m=mutation: m(r)
                factory.submit(self.spec)
                report = factory.run("feature")
                self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
                self.assertEqual(runtime.final_calls, 0)
                calls = len(runtime.calls)
                factory.run("feature")
                self.assertEqual(len(runtime.calls), calls)
                self.assertEqual(factory.db.execute("SELECT COUNT(*) FROM operations WHERE lane='second_reviewer'").fetchone()[0], 0)

    def test_single_rejects_higher_risk_and_unknown_path_eligibility_before_model(self):
        for index, workflow in enumerate(("CRITICAL", "NORMAL", "STRICT")):
            factory, runtime = self.single_factory(f"single-risk-{index}", workflow)
            if workflow != "CRITICAL":
                original = runtime.project_policy
                runtime.project_policy = lambda *a, **kw: {**original(*a, **kw), "single_review_eligible": False}
            factory.submit(self.spec)
            report = factory.run("feature")
            self.assertNotEqual(report["DELIVERY_STATUS"], OFFLINE_PASS)
            self.assertEqual(runtime.calls, [])

    def test_review_mode_is_explicit_and_profiles_cannot_hide_second_lane(self):
        config = copy.deepcopy(self.config)
        config["review_mode"] = "single_openai"
        with self.assertRaises(ValueError): validate_config(config)
        config["profiles"].pop("second_reviewer")
        self.assertEqual(validate_config(config)["review_mode"], "single_openai")
        for mode in ("auto", "", False, "dual"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                validate_config({**config, "review_mode": mode})

    def test_single_preflight_does_not_require_disabled_provider_authorization(self):
        from harness.factory_preflight import inspect_prepaid
        config = copy.deepcopy(self.config)
        config["simulation"] = False
        spec = {**self.spec, "base": self.base, "pr_body_template": "Bounded offline fixture"}
        dual = inspect_prepaid(spec, config)
        self.assertTrue(any(f["check"] == "first_paid_execution" for f in dual["findings"]))
        config["review_mode"] = "single_openai"
        config["profiles"].pop("second_reviewer")
        single = inspect_prepaid(spec, config)
        self.assertFalse(any(f["check"] in {"first_paid_execution", "review_authorization"} for f in single["findings"]))
        # Missing real validation/publication prerequisites still fail closed.
        self.assertEqual(single["status"], "HARD_BLOCKER")
        self.assertTrue(any(f["check"] == "project_container" for f in single["findings"]))

    def test_scope_materialized_only_in_candidate_and_bound_to_exact_head(self):
        before = {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()}
        self.submit()
        spec, cwd = self.f.prepare("feature")
        target = self.f.target(spec, cwd)
        self.assertEqual((cwd / self.path).read_bytes(), self.spec["approved_mission_scope"]["content"].encode())
        self.assertEqual(target["mission_scope_sha256"], self.spec["approved_mission_scope"]["sha256"])
        self.assertNotEqual(target["head"], self.base)
        self.assertEqual(before, {str(p.relative_to(self.repo)): p.read_bytes() for p in self.repo.rglob("*") if p.is_file()})

    def test_modified_deleted_or_symlink_scope_never_committed(self):
        self.submit()
        spec, cwd = self.f.prepare("feature")
        head = git(cwd, "rev-parse", "HEAD")
        path = cwd / self.path
        for action in ("modify", "delete", "symlink"):
            with self.subTest(action=action):
                if path.exists() or path.is_symlink(): path.unlink()
                if action == "modify": path.write_text("{}")
                if action == "symlink": path.symlink_to(cwd / "score.py")
                with self.assertRaises((FactoryBlocked, ValueError, OSError)):
                    self.f.checkpoint(spec, cwd)
                self.assertEqual(git(cwd, "rev-parse", "HEAD"), head)

    def test_scope_identity_hash_expiry_and_reference_reject_before_dispatch(self):
        for field, value in (("base", "a" * 40), ("mission_id", "other"), ("sha256", "0" * 64),
                             ("expires_at", "2000-01-01T00:00:00Z"), ("approval_id", ""),
                             ("path", "../scope.json")):
            spec = copy.deepcopy(self.spec)
            spec["approved_mission_scope"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.f.submit(spec)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM missions").fetchone()[0], 0)

    def test_missing_approval_and_duplicate_scope_keys_rejected(self):
        with self.assertRaises(ValueError): self.f.submit({k: v for k, v in self.spec.items() if k != "approved_mission_scope"})
        value = self.spec["approved_mission_scope"]
        value["content"] = '{"mission_id":"feature","mission_id":"other","workflow_class":"STRICT"}'
        value["sha256"] = sha256(value["content"].encode())
        with self.assertRaisesRegex(ValueError, "duplicate"): self.submit()

    def test_normal_strict_critical_keep_two_receipts_and_p3_barrier(self):
        for workflow, expected in (("NORMAL", ["claude-code-deepseek"]), ("STRICT", ["codex-cli"]),
                                   ("CRITICAL", ["codex-cli", "claude-code-deepseek"])):
            with self.subTest(workflow=workflow):
                self.scope["workflow_class"] = workflow
                spec = {**self.spec, "approved_mission_scope": self.approval()}
                policy = self.runtime.project_policy(spec, self.repo, [])
                self.assertEqual(policy["required_backends"], expected)
                self.assertEqual(len(policy["factory_required_backends"]), 2)
                self.assertTrue(policy["factory_p3_blocks"])
        config = copy.deepcopy(self.config)
        config["independent_review_required"] = False
        with self.assertRaises(ValueError): validate_config(config)

    def test_offline_success_cannot_authorize_merge_and_reuses_evidence(self):
        report = self.ready_fixture()
        self.assertFalse(report["DONE"])
        self.assertEqual(report["PROJECT_ACCEPTANCE"], "OFFLINE_FIXTURE_ONLY")
        self.assertEqual(report["TEST_RESULT"], "OFFLINE_FIXTURE_PASS")
        calls = len(self.runtime.calls)
        operations = self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], OFFLINE_PASS)
        self.assertEqual(len(self.runtime.calls), calls)
        self.assertEqual(self.f.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], operations)
        with self.assertRaises(ValueError): self.f.approve("feature", "merge", "fixture cannot approve", report["TARGET_HEAD"])

    def test_invalid_stale_wrong_model_execution_scope_or_missing_receipt_is_unknown(self):
        mutations = [lambda r: r.update(valid=False), lambda r: r.update(reviewed_head_sha="b" * 40),
                     lambda r: r.update(mission_scope_sha256="0" * 64),
                     lambda r: r["model_provenance"].update(review_model="old-pin"),
                     lambda r: r["model_provenance"].update(review_reasoning_effort="high"),
                     lambda r: r.update(executed_identity="another-session")]
        # New isolated mission databases, never reset/rewrite a previous run.
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                runtime = ProjectRuntime()
                runtime.mutate_receipt = lambda r, lane, m=mutation: m(r)
                f = Factory(self.root / f"case-{index}", self.config, runtime)
                try:
                    f.submit(self.spec)
                    self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
                finally: f.close()

    def test_project_final_validator_rejection_never_ready(self):
        self.runtime.final_status = "FAIL"
        self.submit()
        report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_PROJECT_CONTRACT")
        self.assertEqual(report["PROJECT_ACCEPTANCE"], "NOT_ESTABLISHED")

    def test_critical_missing_second_receipt_blocks(self):
        self.scope["workflow_class"] = "CRITICAL"
        self.spec["approved_mission_scope"] = self.approval()
        original = self.runtime.project_review
        def missing(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[3] == "second_reviewer":
                Path(result["stdout_path"]).write_text('{"fixture":true}')
            return result
        self.runtime.project_review = missing
        self.submit()
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.final_calls, 0)

    def test_p3_still_requires_rework(self):
        self.runtime.mutate_receipt = lambda r, lane: r.update(findings=[{"severity": "P3", "title": "fixture minor"}])
        self.submit()
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "BLOCKED_LIMIT")
        self.assertEqual(self.runtime.final_calls, 0)

    def test_unknown_not_redispatched_and_budget_authority_retained(self):
        self.config["budget"].update(max_run_tokens=100, max_total_tokens=1600)
        self.f.close()
        self.f = Factory(self.root / "guarded-state", self.config, self.runtime)
        self.submit()
        self.runtime.project_review = Mock(side_effect=RuntimeError("fixture lost response"))
        first = self.f.run("feature")
        self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN")
        budget = first["BUDGET_USED"]
        authority = tuple(self.f.db.execute("SELECT spec,policy FROM missions").fetchone())
        self.f.run("feature")
        self.runtime.project_review.assert_called_once()
        self.assertEqual(self.f.report("feature")["BUDGET_USED"], budget)
        self.assertEqual(tuple(self.f.db.execute("SELECT spec,policy FROM missions").fetchone()), authority)
        self.assertEqual(budget["unknown_token_reservation"], 100)

    def test_missing_or_changed_canonical_artifact_invalidates_offline_result(self):
        report = self.ready_fixture()
        Path(report["REVIEW_RESULT"][0]["canonical_receipt"]).unlink()
        self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_project_validator_is_rerun_on_status(self):
        self.ready_fixture()
        with patch.object(self.runtime.contract.adapter, "review_result", return_value=GateResult("BLOCKED_EXTERNAL")):
            self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_range_enumerates_all_files_hunks_and_exact_hashes(self):
        report = self.ready_fixture()
        target = report["EXACT_TARGET"]
        manifest = target["review_range"]
        self.assertEqual({f["path"] for f in manifest["files"]}, set(target["files"]))
        self.assertEqual(manifest["semantic_coverage"], "NOT_MACHINE_PROVEN")
        self.assertTrue(next(f for f in manifest["files"] if f["path"] == "score.py")["hunks"])
        self.assertEqual(manifest, review_manifest(Path(report["CANDIDATE"]), target, git))
        self.assertEqual(manifest["diff_sha256"], target["diff_sha256"])

    def test_range_keeps_rename_deletion_empty_file_and_zero_count_hunks(self):
        self.scope["authorized_paths"] += ["renamed[1].py", "empty.txt"]
        self.spec["approved_mission_scope"] = self.approval()
        self.submit()
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").rename(cwd / "renamed[1].py")
        (cwd / "empty.txt").touch()
        target = self.f.checkpoint(spec, cwd)
        files = {item["path"]: item for item in target["review_range"]["files"]}
        self.assertEqual(set(files), {self.path, "score.py", "renamed[1].py", "empty.txt"})
        self.assertIsNone(files["score.py"]["versions"]["head"])
        self.assertIsNone(files["renamed[1].py"]["versions"]["base"])
        self.assertEqual(files["score.py"]["hunks"][0]["head_count"], 0)
        self.assertEqual(files["renamed[1].py"]["hunks"][0]["base_count"], 0)
        self.assertEqual(files["empty.txt"]["hunks"], [])
        self.assertEqual(files["empty.txt"]["versions"]["head"]["sha256"], sha256(b""))

    def test_mode_only_change_still_has_file_identity(self):
        self.submit()
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").chmod(0o755)
        target = self.f.checkpoint(spec, cwd)
        entry = next(item for item in target["review_range"]["files"] if item["path"] == "score.py")
        self.assertEqual(entry["hunks"], [])
        self.assertEqual(entry["versions"]["base"]["mode"], "100644")
        self.assertEqual(entry["versions"]["head"]["mode"], "100755")

    def test_binary_change_cannot_claim_text_review_coverage(self):
        self.submit()
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").write_bytes(b"binary\0payload")
        with self.assertRaisesRegex(FactoryBlocked, "binary"):
            self.f.checkpoint(spec, cwd)

    def test_stale_project_receipt_classification_blocks_without_retry(self):
        self.submit()
        with patch.object(self.runtime.contract.adapter, "review_result",
                          return_value=GateResult("BLOCKED_EXTERNAL", "FIXTURE STALE_TOOLING")):
            self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
            calls = len(self.runtime.calls)
            self.f.run("feature")
            self.assertEqual(len(self.runtime.calls), calls)
        self.assertEqual(self.runtime.final_calls, 0)

    def test_receiptless_contract_failure_never_invents_legacy_model(self):
        evidence = self.root / "receiptless-evidence"
        evidence.mkdir(mode=0o700)
        stdout = self.root / "receiptless.raw"
        stdout.write_text("{}")
        stdout.chmod(0o600)
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_repo_from_origin", return_value="fixture/repo"), \
             patch.object(adapter, "_canonical_codex_reviewer_policy") as policy:
            result = adapter._receiptless_review_failure(
                reviewer="codex", worktree=str(self.repo), base=self.base, head="b" * 40,
                mission_id="feature", evidence_dir=evidence, attempt_id=None,
                stdout_path=str(stdout), stderr_path=None, terminal_status="EXITED",
                exit_code=1, contract_failure=True)
        policy.assert_not_called()
        record = json.loads(Path(result.data["failure_evidence_path"]).read_text())
        self.assertEqual(record["model"], "unknown")
        self.assertIsNone(record["reasoning_effort"])
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_live_runtime_cannot_invent_phase2_final_gate(self):
        target = {"head": "b" * 40}
        result = LocalRuntime().project_final_gate({}, self.repo, target, [], self.root / "gate.json", 1)
        self.assertEqual(result["status"], "BLOCKED_EXTERNAL")
        self.assertFalse(result["fixture"])

    def test_live_policy_rejects_fixture_runtime_and_incompatible_push_mode(self):
        config = copy.deepcopy(self.config)
        config["simulation"] = False
        with self.assertRaises(ValueError): Factory(self.root / "live", config, ProjectRuntime())
        config["simulation"] = True
        config["hosted_ci"] = {"repository": "fixture/repo", "workflows": ["ci.yml"]}
        with self.assertRaises(ValueError): validate_config(config)

    def test_final_bridge_delegates_project_policy_without_backend_override(self):
        adapter = Mock()
        adapter.merge_ready.return_value = GateResult("FAIL", "canonical rejection")
        contract = FootballPredictionContract(adapter)
        target = {"base": self.base, "head": "b" * 40, "mission_scope_file": self.path}
        self.assertEqual(contract.final_gate(self.spec, self.repo, target, {"codex": "one"}, {}).status, "BLOCKED_EXTERNAL")
        result = contract.final_gate(self.spec, self.repo, target, {"codex": "one", "deepseek": "two"},
                                    {"pr_number": 1, "pr_repo": "fixture/repo", "pr_base_sha": self.base, "ci_status": "UNKNOWN"})
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(adapter.merge_ready.call_args.kwargs["use_project_policy"])

    def test_current_pin_is_read_from_trusted_policy_not_legacy_constants(self):
        trusted = self.root / "trusted-policy"
        modules = trusted / "scripts/devops"
        modules.mkdir(parents=True)
        (modules / "codex_reviewer_isolation.py").write_text(
            "from pathlib import Path\n"
            "def canonical_codex_binary(): return Path('/usr/lib/chatgpt/resources/codex')\n"
            "def canonical_reviewer_environment(source=None): return {'CODEX_HOME':'/fixture/official-home'}\n")
        (modules / "codex_review_contract.py").write_text(
            "REVIEW_MODEL_PINNED = 'fixture-new-project-model'\nREVIEW_REASONING_EFFORT_PINNED = 'medium'\n")
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
             patch.object(adapter, "_validate_canonical_codex_home", return_value="/fixture/official-home"):
            policy = adapter._canonical_codex_reviewer_policy(worktree=str(self.repo), base=self.base)
        self.assertEqual(policy["model"], "fixture-new-project-model")
        self.assertEqual(policy["reasoning_effort"], "medium")

    def test_project_policy_query_uses_canonical_functions_from_trusted_base(self):
        trusted = self.root / "trusted-query-fixture"
        helpers = trusted / "scripts/ops/helpers"
        devops = trusted / "scripts/devops"
        helpers.mkdir(parents=True)
        devops.mkdir(parents=True)
        # Tiny project API doubles: test delegation, not project semantics.
        (helpers / "agent_workflow_contract.py").write_text(
            "from types import SimpleNamespace\n"
            "class MissionScope:\n"
            " @staticmethod\n"
            " def from_mapping(value): return SimpleNamespace(**value)\n"
            "def validate_mission_scope(paths, scope):\n"
            " return ['rejected by fixture project policy'] if any(p not in scope.authorized_paths for p in paths) else []\n")
        (devops / "review_policy.py").write_text(
            "def required_backends(workflow, selected_backend=None):\n"
            " return ('claude-code-deepseek',) if workflow=='NORMAL' else ('codex-cli',) if workflow=='STRICT' else ('codex-cli','claude-code-deepseek')\n"
            "def load_active_backend_eligibility(path):\n"
            " return {'codex-cli':{'NORMAL','STRICT','CRITICAL'}, 'claude-code-deepseek':{'NORMAL','CRITICAL'}}\n")
        (devops / "codex_review_contract.py").write_text("REVIEW_MODEL_PINNED='fixture-current-pin'\nREVIEW_REASONING_EFFORT_PINNED='medium'\n")
        (helpers / "strict_review_evidence.py").write_text(
            "def _strict_classification_reasons(paths, task): return []\n"
            "def _critical_classification_reasons(paths, task): return []\n")
        adapter = FootballPredictionAdapter()
        contract = FootballPredictionContract(adapter)
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted):
            for workflow in ("NORMAL", "STRICT", "CRITICAL"):
                self.scope["workflow_class"] = workflow
                spec = {**self.spec, "approved_mission_scope": self.approval()}
                policy = contract.policy(spec, self.repo, ["score.py", self.path])
                self.assertEqual(policy, self.runtime.project_policy(spec, self.repo, ["score.py", self.path]))
            with self.assertRaises(ValueError): contract.policy(spec, self.repo, ["unauthorized.py"])
            with self.assertRaises(ValueError): contract.policy(spec, self.repo, ["scripts/devops/review_policy.py"])

    def test_oversized_full_diff_blocks_without_truncation(self):
        self.submit()
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").write_text("# large change\n" * 100)
        self.f.config["max_review_bytes"] = 20
        with self.assertRaisesRegex(FactoryBlocked, "nothing was truncated"):
            self.f.checkpoint(spec, cwd)

    def test_scope_only_changes_are_not_business_implementation(self):
        original = self.runtime.agent
        def no_implementation(role, *args):
            if role in {"implement", "rework"}:
                return {"output": {"summary": "fixture no-op", "known_risks": []}, "usage": {"fixture_provider_calls": 0}}
            return original(role, *args)
        self.runtime.agent = no_implementation
        self.submit()
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(self.runtime.final_calls, 0)


if __name__ == "__main__":
    unittest.main()
