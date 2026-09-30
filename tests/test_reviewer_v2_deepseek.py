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
                json.dumps({"structured_output": {"findings": []}}).encode(), b"")
            cases = {
                "CHILD_PROCESS_TIMEOUT": subprocess.TimeoutExpired("claude", 1,
                    output=b"partial output", stderr=b"fixture-token should stay private"),
                "NONZERO_EXIT": subprocess.CompletedProcess([], 1, b"", b"unknown failure"),
                "MALFORMED_JSON": subprocess.CompletedProcess([], 0, b"not json", b""),
                "EMPTY_OUTPUT": subprocess.CompletedProcess([], 0, b"", b""),
                "SCHEMA_VALIDATION_FAILED": subprocess.CompletedProcess([], 0,
                    json.dumps({"structured_output": {"findings": []}}).encode(), b""),
            }
            for category, group_response in cases.items():
                with self.subTest(category=category):
                    evidence = Path(temporary) / category.lower()
                    args = SimpleNamespace(repo=str(root), base=base, head=head,
                        evidence=str(evidence), token_file=str(Path(temporary) / "token"),
                        mission_id="test", timeout=1)
                    def invoke(_command, prompt, _env, _timeout):
                        if "Scope=chunk" in prompt:
                            return good_chunk
                        if isinstance(group_response, Exception):
                            raise group_response
                        return group_response
                    with (patch.object(reviewer.legacy, "resolve_claude_launcher",
                                       return_value=("/bin/true", "/usr/bin:/bin")),
                          patch.object(reviewer.legacy, "read_token_file", return_value="fixture-token"),
                          patch.object(reviewer.legacy, "invoke_reviewer", side_effect=invoke)):
                        with self.assertRaises(reviewer.ReviewStageFailure) as caught:
                            reviewer.run(args)
                    self.assertEqual(caught.exception.category, category)
                    failure_path = Path(caught.exception.failure_artifact)
                    failure = json.loads(failure_path.read_text())
                    self.assertEqual(failure["stage"], "group")
                    self.assertEqual(failure["head_sha"], head)
                    self.assertEqual(failure["failure_category"], category)
                    self.assertEqual(len(failure["runner_sha256"]), 64)
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
                                   mission_id="test", timeout=30)
            summary = "The source change preserves the relevant contract and control flow."
            def invoke(command, prompt, env, timeout):
                result = ({"findings": []} if "Scope=chunk" in prompt else
                          {"findings": [], "decisions": [], "summary": summary})
                return subprocess.CompletedProcess(command, 0, json.dumps({
                    "structured_output": result}).encode(), b"")
            with (patch.object(reviewer.legacy, "resolve_claude_launcher",
                               return_value=("/bin/true", "/usr/bin:/bin")),
                  patch.object(reviewer.legacy, "read_token_file", return_value="fixture-token"),
                  patch.object(reviewer.legacy, "invoke_reviewer", side_effect=invoke)):
                response = reviewer.run(args)
            receipt_path = Path(response["review_receipt"])
            self.assertEqual(response["status"], "PASS")
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
