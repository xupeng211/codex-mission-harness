"""Deterministic contract tests; these do not qualify a real provider model."""
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import reviewer_v2_gate as gate  # noqa: E402
import reviewer_v2_openai as review  # noqa: E402
from harness.model_registry import ModelSpec  # noqa: E402
from harness.openai_invocation import InvocationFailure  # noqa: E402


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


class OpenAIContractTests(unittest.TestCase):
    def test_schema_selection_uses_stage_not_labels_inside_reviewed_source(self):
        prompt = "CHUNK REVIEW source contains GROUP REVIEW and FINAL CROSS-GROUP REVIEW"
        with patch.object(review, "invoke_openai", return_value=SimpleNamespace(response='{"findings":[]}')) as invoke:
            for stage, required in (("chunk", {"findings"}),
                                    ("group", {"findings", "decisions", "summary"}),
                                    ("synthesis", {"findings", "summary"})):
                review.invoke_codex(prompt, ModelSpec("openai", "gpt-5.6-sol", "high"), stage=stage)
                self.assertEqual(set(invoke.call_args.args[2]["required"]), required)
        with self.assertRaises(ValueError):
            review.invoke_codex(prompt, ModelSpec("openai", "gpt-5.6-sol", "high"), stage="unknown")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "remote", "add", "origin", "git@github.com:example/harness.git")
        (self.root / "x.py").write_text("def f():\n    return 1\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "base")
        self.base = git(self.root, "rev-parse", "HEAD")
        (self.root / "x.py").write_text("def f():\n    return 2\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "change")
        self.head = git(self.root, "rev-parse", "HEAD")
        self.spec = ModelSpec("openai", "gpt-5.6-sol", "high")
        self.diff = review.secure.git(self.root, "diff", "--no-ext-diff", "--no-textconv",
                                      "--binary", f"{self.base}..{self.head}")

    def _signed(self, receipt):
        receipt.update(model=self.spec.model, reasoning_effort=self.spec.reasoning_effort,
                       mission_id="codex-mission-harness",
                       repository="ssh://github.com/example/harness.git",
                       registry_sha256=review._sha(review.load_registry().path.read_bytes()),
                       runner_sha256=review._sha(Path(review.__file__).read_bytes()),
                       invocation_sha256=review._sha(Path(review.invocation_module.__file__).read_bytes()),
                       schema_manifest_sha256=review._schema_manifest_sha())
        receipt["auth_hmac_sha256"] = hmac.new(b"test-key", review._canon(receipt), hashlib.sha256).hexdigest()
        return receipt

    def test_no_blockers_bounded_source_and_exact_receipt(self):
        calls = []
        def call(prompt, group):
            calls.append((prompt, group))
            if group:
                return json.dumps({"findings": [], "decisions": [],
                                   "summary": "The changed return value has no blocking impact."}).encode()
            return b'{"findings":[]}'
        receipt, _ = review._assemble(self.diff, self.base, self.head, call)
        self._signed(receipt)
        self.assertEqual(receipt["review_result"], "PASS")
        self.assertEqual([group for _, group in calls], [False, True])
        self.assertIn(self.head, calls[0][0])
        review.validate(receipt, root=self.root, base=self.base, head=self.head,
                        spec=self.spec, auth_key="test-key")
        original_read = Path.read_bytes
        def changed_runner(path):
            return b"changed runner" if path == Path(review.__file__) else original_read(path)
        with patch.object(Path, "read_bytes", changed_runner):
            with self.assertRaises(ValueError):
                review.validate(receipt, root=self.root, base=self.base,
                                head=self.head, spec=self.spec, auth_key="test-key")
        changed_mission = dict(receipt, mission_id="another-mission")
        with self.assertRaises(ValueError):
            review.validate(changed_mission, root=self.root, base=self.base,
                            head=self.head, spec=self.spec, auth_key="test-key")
        changed_repository = dict(receipt, repository="ssh://github.com/other/repo.git")
        with self.assertRaises(ValueError):
            review.validate(changed_repository, root=self.root, base=self.base,
                            head=self.head, spec=self.spec, auth_key="test-key")
        with self.assertRaises(ValueError):
            review.validate(receipt, root=self.root, base=self.base, head="0" * 40,
                            spec=self.spec, auth_key="test-key")

    def test_failed_invocation_publishes_failure_only_for_exact_head(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        def fail(_prompt, _group):
            raise InvocationFailure("TURN_TIMEOUT_UNDIAGNOSED", "no terminal event",
                                    {"observed_event_types": ["turn.started"]})
        with patch.object(review, "validate_qualification_receipt"), \
             patch.object(review, "preflight"), \
             patch.object(review, "invoke_codex", side_effect=lambda *_args, **_kwargs: fail(None, None)), \
             self.assertRaises(InvocationFailure) as caught:
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                       qualification_path="fixture-qualification")
        failure_path = Path(caught.exception.evidence["failure_record"])
        record = json.loads(failure_path.read_text())
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(record["head_sha"], self.head)
        self.assertEqual(record["diff_sha256"], hashlib.sha256(self.diff).hexdigest())
        self.assertEqual(record["failure_category"], "TURN_TIMEOUT_UNDIAGNOSED")
        self.assertEqual(list(failure_path.parent.iterdir()), [failure_path])

    def test_invalid_group_result_preserves_raw_stage_and_never_publishes_receipt(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        blocker = {"severity": "P1", "title": "Concrete issue", "evidence": "x.py:2"}
        raw_group = json.dumps({"findings": [], "decisions": [{
            "finding_id": "C000F000", "decision": "DISPUTED",
            "rationale": "This rationale claims the blocker does not apply.",
            "source_quote": "a quotation absent from the diff", "source_id": review._sha(self.diff),
            "quote_start": 0, "quote_end": 32}],
            "summary": "The group was reviewed but its dispute lacks source evidence."}).encode()
        calls = 0
        def invoke(_prompt, _spec, *, stage, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                return b'{"findings":[]}'  # preflight
            return raw_group if stage == "group" else json.dumps({"findings": [blocker]}).encode()
        with patch.object(review, "validate_qualification_receipt"), \
             patch.object(review, "preflight"), \
             patch.object(review, "invoke_codex", side_effect=invoke), \
             self.assertRaisesRegex(ValueError, "bound source reference"):
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                       qualification_path="fixture-qualification")
        run_dir, = evidence.iterdir()
        self.assertEqual((run_dir / "group-000.json").read_bytes(), raw_group)
        failure = json.loads((run_dir / "failure.json").read_text())
        self.assertEqual(failure["status"], "BLOCKED")
        self.assertEqual(failure["failure_category"], "REVIEW_RESULT_INVALID")
        self.assertEqual(failure["artifact_sha256"]["group-000.json"], hashlib.sha256(raw_group).hexdigest())
        self.assertFalse((run_dir / "receipt.json").exists())

    def test_preflight_provider_failure_publishes_no_approval_receipt(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        error = InvocationFailure("AUTHENTICATION_FAILURE", "provider rejected auth",
                                  {"failure_markers": {"http_401": True}})
        with patch.object(review, "validate_qualification_receipt"), \
             patch.object(review, "preflight", side_effect=error) as preflight:
            with self.assertRaises(InvocationFailure) as caught:
                review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                           qualification_path="fixture-qualification")
        preflight.assert_called_once()
        path = Path(caught.exception.evidence["failure_record"])
        record = json.loads(path.read_text())
        self.assertEqual(record["failure_category"], "AUTHENTICATION_FAILURE")
        self.assertEqual(record["head_sha"], self.head)
        self.assertFalse(list(evidence.rglob("receipt.json")))

    def test_live_review_requires_matching_final_reviewer_qualification(self):
        evidence = Path(self.temp.name) / "evidence"
        with self.assertRaisesRegex(ValueError, "qualification receipt"):
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec)
        self.assertFalse(list(evidence.rglob("receipt.json")))
        self.assertEqual(len(list(evidence.rglob("failure.json"))), 1)
        with patch.object(review, "validate_qualification_receipt",
                          side_effect=ValueError("role mismatch")) as validate:
            with self.assertRaisesRegex(ValueError, "role mismatch"):
                review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                           qualification_path="untrusted-receipt")
        self.assertEqual(validate.call_args.kwargs["role"], "final_reviewer")
        self.assertFalse(list(evidence.rglob("receipt.json")))

    def test_missing_unknown_and_duplicate_blocker_id_fail_closed(self):
        blocker = {"severity": "P1", "title": "Concrete issue", "evidence": "x.py:2"}
        for ids in ([], ["C000F001"], ["C000F000", "C000F000"]):
            with self.subTest(ids=ids):
                def call(prompt, group):
                    if not group:
                        return json.dumps({"findings": [blocker]}).encode()
                    decisions = [{"finding_id": identifier, "decision": "UPHELD",
                                  "rationale": "The changed source makes the issue persist.",
                                  "source_quote": "", "source_id": "",
                                  "quote_start": 0, "quote_end": 0} for identifier in ids]
                    return json.dumps({"findings": [], "decisions": decisions,
                                       "summary": "The source was reviewed with its original finding."}).encode()
                with self.assertRaises(ValueError):
                    review._assemble(self.diff, self.base, self.head, call)

    def test_upheld_blocker_forces_fail_and_dispute_needs_source_quote(self):
        blocker = {"severity": "P2", "title": "Concrete issue", "evidence": "x.py:2"}
        def call(prompt, group):
            if not group:
                return json.dumps({"findings": [blocker]}).encode()
            return json.dumps({"findings": [], "decisions": [{"finding_id": "C000F000",
                "decision": "UPHELD", "rationale": "The changed source makes the issue persist.",
                "source_quote": "", "source_id": "", "quote_start": 0, "quote_end": 0}],
                "summary": "The blocker remains in the reviewed source."}).encode()
        receipt, _ = review._assemble(self.diff, self.base, self.head, call)
        self.assertEqual(receipt["review_result"], "FAIL")
        self._signed(receipt)
        review.validate(receipt, root=self.root, base=self.base, head=self.head,
                        spec=self.spec, auth_key="test-key")
        receipt["groups"][0]["source_blockers"][0]["finding"]["severity"] = "P3"
        self._signed_after_change(receipt)
        with self.assertRaises(ValueError):
            review.validate(receipt, root=self.root, base=self.base, head=self.head,
                            spec=self.spec, auth_key="test-key")

    @staticmethod
    def _signed_after_change(receipt):
        receipt.pop("auth_hmac_sha256")
        receipt["auth_hmac_sha256"] = hmac.new(b"test-key", review._canon(receipt), hashlib.sha256).hexdigest()

    def test_gate_requires_two_valid_independent_exact_lanes(self):
        diff_hash = hashlib.sha256(self.diff).hexdigest()
        deepseek = {"provider": "deepseek", "model": "deepseek-flash", "base_sha": self.base,
                    "head_sha": self.head, "diff_sha256": diff_hash, "review_result": "PASS", "findings": [],
                    "mission_id": "codex-mission-harness", "repository": "ssh://github.com/example/harness.git"}
        openai = {**deepseek, "provider": "openai", "model": "gpt-5.6-sol",
                  "reasoning_effort": "high"}
        validate = lambda value: value
        proof = gate.validate_gate(root=self.root, base=self.base, head=self.head,
                    deepseek_receipt=deepseek, openai_receipt=openai,
                    deepseek_validator=validate, openai_validator=validate,
                    mission_id="codex-mission-harness", repository="ssh://github.com/example/harness.git")
        self.assertEqual(proof["status"], "PASS")
        openai["findings"] = [{"severity": "P1"}]
        with self.assertRaises(ValueError):
            gate.validate_gate(root=self.root, base=self.base, head=self.head,
                deepseek_receipt=deepseek, openai_receipt=openai,
                deepseek_validator=validate, openai_validator=validate,
                mission_id="codex-mission-harness", repository="ssh://github.com/example/harness.git")

    def test_gate_rechecks_checkout_after_lane_validation(self):
        diff_hash = hashlib.sha256(self.diff).hexdigest()
        identity = {"base_sha": self.base, "head_sha": self.head,
                    "diff_sha256": diff_hash, "review_result": "PASS", "findings": [],
                    "mission_id": "codex-mission-harness",
                    "repository": "ssh://github.com/example/harness.git"}
        deepseek = dict(identity, provider="deepseek", model="deepseek-flash")
        openai = dict(identity, provider="openai", model="gpt-5.6-sol",
                      reasoning_effort="high")
        def mutate(value):
            (self.root / "x.py").write_text("uncommitted mutation\n")
            return value
        with self.assertRaisesRegex(ValueError, "changed during validation"):
            gate.validate_gate(root=self.root, base=self.base, head=self.head,
                deepseek_receipt=deepseek, openai_receipt=openai,
                deepseek_validator=lambda value: value, openai_validator=mutate,
                mission_id="codex-mission-harness", repository=identity["repository"])


if __name__ == "__main__":
    unittest.main()
