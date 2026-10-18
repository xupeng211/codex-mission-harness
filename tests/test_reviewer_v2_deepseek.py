"""Local end-to-end receipt test; no provider requests or qualification claim."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import reviewer_v2_deepseek as reviewer
from direct_deepseek_fixture import envelope


class DeepSeekV2ReceiptTests(unittest.TestCase):
    def test_p3_disposition_failure_has_safe_reason_code(self):
        finding = {"severity": "P3", "title": "Minor issue", "evidence": "source.py:2"}
        expected = reviewer.bind_findings([finding], "C", 0)
        raw = json.dumps({"findings": [], "decisions": [{
            "finding_id": expected[0]["finding_id"], "decision": "UPHELD",
            "rationale": "This source confirms the original minor issue.",
            "source_quote": "", "source_id": ""}],
            "summary": "The change contains one nonblocking finding only."})
        state = {"stage": "group"}
        with self.assertRaises(reviewer.ReviewStageFailure):
            reviewer._parse_stage(raw, lambda value: reviewer.parse_synthesis(
                value, expected, source=b"source", structured_evidence=True), state)
        self.assertEqual(state["schema_validation_reason"], "UNKNOWN_FINDING_ID")

    def test_group_failures_are_private_classified_and_never_publish_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()
            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            git("remote", "add", "origin", "git@github.com:example/harness.git")
            (root / "source.py").write_text("value = 1\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "source.py").write_text("value = 2\n")
            git("add", ".")
            git("commit", "-qm", "head")
            head = git("rev-parse", "HEAD")
            good_chunk = {"findings": [{"severity": "P1", "title": "Synthetic blocker",
                                        "evidence": "source.py changed"}]}
            for code in ("REQUEST_TIMEOUT", "HTTP_429", "INCOMPLETE_COMPLETION", "INVALID_SCHEMA"):
                with self.subTest(code=code):
                    evidence = Path(temporary) / code.lower()
                    args = SimpleNamespace(repo=str(root), base=base, head=head,
                        evidence=str(evidence), token_file=str(Path(temporary) / "token"),
                        mission_id="test", timeout=1, qualification="fixture-qualification")
                    calls = []
                    def invoke(prompt, token, schema, **kwargs):
                        calls.append(prompt)
                        if "Scope=chunk" in prompt:
                            return envelope(good_chunk, prompt, schema)
                        raise reviewer.direct.DirectFailure(code)
                    with (patch.object(reviewer.legacy, "read_token_file", return_value="fixture-token"),
                          patch.object(reviewer, "validate_qualification_receipt", return_value={}),
                          patch.object(reviewer.direct, "invoke", side_effect=invoke)):
                        with self.assertRaises(reviewer.ReviewStageFailure) as caught:
                            reviewer.run(args)
                    self.assertEqual(len(calls), 2)  # chunk + one group, no automatic resend
                    failure_path = Path(caught.exception.failure_artifact)
                    failure = json.loads(failure_path.read_text())
                    self.assertEqual(failure["stage"], "group-000")
                    self.assertEqual(failure["sanitized_error_class"], code)
                    self.assertEqual(failure["failure_category"], "MODEL_TIMEOUT" if code == "REQUEST_TIMEOUT" else "SCHEMA_VALIDATION_FAILED")
                    self.assertFalse(failure["resume_allowed"])
                    self.assertFalse(failure["parser_entered"])
                    self.assertNotIn("fixture-token", failure_path.read_text())
                    self.assertFalse(list(evidence.rglob("deepseek-v2-receipt-*.json")))
                    state = json.loads((failure_path.parent / "state.json").read_bytes())
                    self.assertFalse(state['receipt_written'])
                    self.assertEqual(state['completed_chunk_ids'], ['chunk-000'])

    def test_commit_last_receipt_and_exact_source_validation(self):
        self._exercise_receipt()

    def test_separate_signing_key_never_replaces_provider_credential(self):
        self._exercise_receipt(separate_auth=True)

    def test_funding_pause_keeps_completed_chunk_and_same_run(self):
        self._exercise_receipt(funding_pause=True)

    def test_credential_in_source_cannot_enter_failure_evidence(self):
        self._exercise_receipt(secret_in_source=True)

    def _exercise_receipt(self, separate_auth=False, funding_pause=False, secret_in_source=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()
            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            git("remote", "add", "origin", "git@github.com:example/harness.git")
            (root / "source.py").write_text("value = 1\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "source.py").write_text("value = 2\n" + ("fixture-token\n" if secret_in_source else ""))
            git("add", ".")
            git("commit", "-qm", "head")
            head = git("rev-parse", "HEAD")
            evidence = Path(temporary) / "evidence"
            args = SimpleNamespace(repo=str(root), base=base, head=head,
                                   evidence=str(evidence), token_file=str(Path(temporary) / "token"),
                                   mission_id="test", timeout=30, qualification="fixture-qualification")
            signing_file=Path(temporary)/"signing-key"
            if separate_auth:args.auth_key_file=str(signing_file)
            receipt_key="fixture-signing-key" if separate_auth else "fixture-token"
            summary = "The source change preserves the relevant contract and control flow."
            paused, chunk_calls = [], []
            def invoke(prompt, token, schema, **kwargs):
                if funding_pause and "Scope=group" in prompt and not paused:
                    from harness.resource_gate import FundingPause
                    paused.append(True)
                    raise FundingPause("OFFLINE funds exhausted", required=2, available=1)
                if "Scope=chunk" in prompt:
                    chunk_calls.append(True)
                self.assertEqual(token, "fixture-token")
                if "Scope=cross-group" in prompt:
                    self.assertIn("original_chunk_findings",prompt)
                    self.assertIn("chunk_dispositions",prompt)
                    self.assertIn("Reevaluate all original disputed findings",prompt)
                result = ({"findings": []} if "Scope=chunk" in prompt else
                          {"findings": [], "decisions": [], "summary": summary})
                return envelope(result, prompt, schema)
            with (patch.object(reviewer.legacy, "resolve_claude_launcher",
                               return_value=("/bin/true", "/usr/bin:/bin")),
                  patch.object(reviewer.legacy, "read_token_file", side_effect=lambda path,_root: "fixture-signing-key" if str(path)==str(signing_file) else "fixture-token"),
                  patch.object(reviewer, "validate_qualification_receipt", return_value={}) as qualified,
                  patch.object(reviewer.direct, "invoke", side_effect=invoke) as transport):
                if secret_in_source:
                    with self.assertRaises(reviewer.ReviewStageFailure) as caught:
                        reviewer.run(args)
                    self.assertNotIn("fixture-token", str(caught.exception))
                    self.assertIsNone(caught.exception.failure_artifact)
                    self.assertFalse(evidence.exists())
                    transport.assert_not_called()
                    qualified.assert_not_called()
                    return
                if funding_pause:
                    from harness.resource_gate import FundingPause
                    with self.assertRaises(FundingPause): reviewer.run(args)
                    state_path, = evidence.glob("*/state.json")
                    funding_state = json.loads(state_path.read_bytes())
                    self.assertEqual(funding_state['failure_count'], 0)
                    self.assertEqual(funding_state['funding_status'], 'PAUSED_AWAITING_MANUAL_FUNDING')
                    self.assertEqual(funding_state['next_stage'], 'group-000')
                response = reviewer.run(args)
                if funding_pause:
                    self.assertEqual(len(chunk_calls), 1)
                    self.assertEqual(len(list(evidence.glob("*/state.json"))), 1)
            self.assertEqual(qualified.call_args.kwargs["auth_key"],receipt_key)
            receipt_path = Path(response["review_receipt"])
            self.assertEqual(response["status"], "PASS")
            state = json.loads((receipt_path.parent / "state.json").read_text())
            self.assertTrue(state["receipt_written"])
            self.assertEqual(state["next_stage"], "complete")
            self.assertEqual(state["completed_order"], ["chunk-000", "group-000", "aggregate"])
            self.assertTrue({"provider", "role", "model", "model_configuration", "repository",
                             "mission_id", "base_sha", "head_sha", "diff_hash", "registry_hash",
                             "runner_hash", "invocation_hash", "schema_manifest_hash",
                             "qualification_receipt_identity", "input_manifest_identity"}
                            <= set(state["identity"]))
            receipt = json.loads(receipt_path.read_text())
            reviewer.validate(receipt, base, head, root, receipt_path, "test",
                              "ssh://github.com/example/harness.git", receipt_key)
            original_chunk = (receipt_path.parent / "chunk-000.json").read_bytes()
            bad_chunk = json.loads(original_chunk)
            bad_chunk["direct_completion"]["finish_reason"] = "length"
            bad_raw = reviewer.canonical(bad_chunk)
            (receipt_path.parent / "chunk-000.json").write_bytes(bad_raw)
            bad_receipt = json.loads(json.dumps(receipt))
            bad_receipt["chunks"][0]["output_sha256"] = reviewer.sha256(bad_raw)
            bad_receipt.pop("integrity_sha256"); bad_receipt.pop("auth_hmac_sha256")
            bad_receipt["integrity_sha256"] = reviewer.sha256(reviewer.canonical(bad_receipt))
            bad_receipt["auth_hmac_sha256"] = reviewer._receipt_hmac(bad_receipt, receipt_key)
            with self.assertRaisesRegex(ValueError, "Direct completion"):
                reviewer.validate(bad_receipt, base, head, root, receipt_path, "test",
                                  "ssh://github.com/example/harness.git", receipt_key)
            (receipt_path.parent / "chunk-000.json").write_bytes(original_chunk)
            original_read = Path.read_bytes
            def changed_runner(path):
                return b"changed runner" if path == Path(reviewer.__file__) else original_read(path)
            with patch.object(Path, "read_bytes", changed_runner):
                with self.assertRaises(ValueError):
                    reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                      "ssh://github.com/example/harness.git", receipt_key)
            with tempfile.TemporaryDirectory() as custom_dir:
                registry = Path(custom_dir) / "models.json"
                registry.write_bytes(reviewer.load_registry().path.read_bytes() + b" ")
                with self.assertRaises(ValueError):
                    reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                      "ssh://github.com/example/harness.git", "fixture-token",
                                      registry_path=registry)
            with self.assertRaises(ValueError):
                reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                  "ssh://github.com/example/harness.git", "")
            receipt["chunks"][0]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                  "ssh://github.com/example/harness.git", receipt_key)


if __name__ == "__main__":
    unittest.main()
