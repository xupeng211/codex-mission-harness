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


class DeepSeekV2ReceiptTests(unittest.TestCase):
    def test_p3_disposition_failure_has_safe_reason_code(self):
        finding = {"severity": "P3", "title": "Minor issue", "evidence": "source.py:2"}
        expected = reviewer.bind_findings([finding], "C", 0)
        raw = json.dumps({"findings": [], "decisions": [{
            "finding_id": expected[0]["finding_id"], "decision": "UPHELD",
            "rationale": "This source confirms the original minor issue.",
            "source_quote": "", "source_id": "", "quote_start": 0, "quote_end": 0}],
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
            good_chunk = subprocess.CompletedProcess([], 0,
                json.dumps({"structured_output": {"findings": [{"severity": "P1",
                    "title": "Synthetic blocker", "evidence": "source.py changed"}]}}).encode(), b"")
            cases = {
                "CHILD_PROCESS_TIMEOUT": subprocess.TimeoutExpired("claude", 1,
                    output=b"partial output", stderr=b"fixture-token should stay private"),
                "UNKNOWN_NONZERO_EXIT": subprocess.CompletedProcess([], 1, b"partial result", b"unknown failure"),
                "MALFORMED_JSON": subprocess.CompletedProcess([], 0, b"not json", b""),
                "EMPTY_OUTPUT": subprocess.CompletedProcess([], 0, b"", b""),
                "SCHEMA_VALIDATION_FAILED": subprocess.CompletedProcess([], 0,
                    json.dumps({"structured_output": {"findings": [], "decisions": [{
                        "finding_id": "C000F000", "decision": "DISPUTED",
                        "rationale": "Synthetic rationale with enough length for this decision.",
                        "source_quote": "diff --git a/source.py", "source_id": "0" * 64,
                        "quote_start": 0, "quote_end": 22}],
                        "summary": "This synthetic group response has an invalid source identity."}}).encode(), b""),
            }
            for category, group_response in cases.items():
                with self.subTest(category=category):
                    evidence = Path(temporary) / category.lower()
                    args = SimpleNamespace(repo=str(root), base=base, head=head,
                        evidence=str(evidence), token_file=str(Path(temporary) / "token"),
                        mission_id="test", timeout=1, qualification="fixture-qualification")
                    def invoke(_command, prompt, _env, _timeout):
                        if "Scope=chunk" in prompt:
                            return good_chunk
                        if isinstance(group_response, Exception):
                            raise group_response
                        return group_response
                    with (patch.object(reviewer.legacy, "resolve_claude_launcher",
                                       return_value=("/bin/true", "/usr/bin:/bin")),
                          patch.object(reviewer.legacy, "read_token_file", return_value="fixture-token"),
                          patch.object(reviewer, "validate_qualification_receipt"),
                          patch.object(reviewer.legacy, "invoke_reviewer", side_effect=invoke)):
                        with self.assertRaises(reviewer.ReviewStageFailure) as caught:
                            reviewer.run(args)
                    self.assertEqual(caught.exception.category, category)
                    failure_path = Path(caught.exception.failure_artifact)
                    failure = json.loads(failure_path.read_text())
                    self.assertEqual(failure["stage"], "group-000")
                    self.assertEqual(failure["head_sha"], head)
                    self.assertEqual(failure["failure_category"], category)
                    self.assertEqual(len(failure["runner_sha256"]), 64)
                    self.assertEqual(failure["role"], "independent_reviewer")
                    self.assertEqual(len(failure["command_identity_hash"]), 64)
                    self.assertEqual(len(failure["environment_identity_hash"]), 64)
                    if category == "UNKNOWN_NONZERO_EXIT":
                        self.assertFalse(failure["parser_entered"])
                        self.assertFalse(failure["schema_validation_entered"])
                        self.assertFalse(failure["resume_allowed"])
                        self.assertTrue(failure["stdout_present"])
                        self.assertEqual(failure["stdout_sha256"], reviewer.sha256(b"partial result"))
                        self.assertEqual(failure["stderr_sha256"], reviewer.sha256(b"unknown failure"))
                        self.assertEqual(failure["sanitized_error_class"], category)
                    if category == "SCHEMA_VALIDATION_FAILED":
                        detail = failure["source_binding_diagnostic"]
                        self.assertEqual(detail["error_subclass"], "SOURCE_ID_MISMATCH")
                        self.assertEqual(detail["finding_id"], "C000F000")
                        self.assertEqual(detail["stage_id"], "group-000.json")
                        self.assertEqual(detail["validation_rule"], "GROUP_SOURCE_HASH_MATCH")
                        self.assertEqual(detail["validation_result"], "FAIL")
                    self.assertNotIn("fixture-token", failure_path.read_text())
                    self.assertFalse(list(evidence.rglob("deepseek-v2-receipt-*.json")))

    def test_commit_last_receipt_and_exact_source_validation(self):
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
            evidence = Path(temporary) / "evidence"
            args = SimpleNamespace(repo=str(root), base=base, head=head,
                                   evidence=str(evidence), token_file=str(Path(temporary) / "token"),
                                   mission_id="test", timeout=30, qualification="fixture-qualification")
            summary = "The source change preserves the relevant contract and control flow."
            def invoke(command, prompt, env, timeout):
                result = ({"findings": []} if "Scope=chunk" in prompt else
                          {"findings": [], "decisions": [], "summary": summary})
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "structured_output": result}).encode(), b"")
            with (patch.object(reviewer.legacy, "resolve_claude_launcher",
                               return_value=("/bin/true", "/usr/bin:/bin")),
                  patch.object(reviewer.legacy, "read_token_file", return_value="fixture-token"),
                  patch.object(reviewer, "validate_qualification_receipt"),
                  patch.object(reviewer.legacy, "invoke_reviewer", side_effect=invoke)):
                response = reviewer.run(args)
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
                              "ssh://github.com/example/harness.git", "fixture-token")
            original_read = Path.read_bytes
            def changed_runner(path):
                return b"changed runner" if path == Path(reviewer.__file__) else original_read(path)
            with patch.object(Path, "read_bytes", changed_runner):
                with self.assertRaises(ValueError):
                    reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                      "ssh://github.com/example/harness.git", "fixture-token")
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
                                  "ssh://github.com/example/harness.git", "fixture-token")


if __name__ == "__main__":
    unittest.main()
