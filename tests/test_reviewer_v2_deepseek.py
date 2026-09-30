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
            receipt["chunks"][0]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                reviewer.validate(receipt, base, head, root, receipt_path, "test",
                                  "ssh://github.com/example/harness.git", "fixture-token")


if __name__ == "__main__":
    unittest.main()
