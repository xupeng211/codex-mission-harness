"""Deterministic contract tests; these do not qualify a real provider model."""
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import reviewer_v2_gate as gate  # noqa: E402
import reviewer_v2_openai as review  # noqa: E402
from harness.model_registry import ModelSpec  # noqa: E402


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


class OpenAIContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "Test")
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
        receipt.update(model=self.spec.model, reasoning_effort=self.spec.reasoning_effort)
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
        with self.assertRaises(ValueError):
            review.validate(receipt, root=self.root, base=self.base, head="0" * 40,
                            spec=self.spec, auth_key="test-key")

    def test_missing_unknown_and_duplicate_blocker_id_fail_closed(self):
        blocker = {"severity": "P1", "title": "Concrete issue", "evidence": "x.py:2"}
        for ids in ([], ["C000F001"], ["C000F000", "C000F000"]):
            with self.subTest(ids=ids):
                def call(prompt, group):
                    if not group:
                        return json.dumps({"findings": [blocker]}).encode()
                    decisions = [{"finding_id": identifier, "decision": "UPHELD",
                                  "rationale": "The changed source makes the issue persist.",
                                  "source_quote": ""} for identifier in ids]
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
                "source_quote": ""}], "summary": "The blocker remains in the reviewed source."}).encode()
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
                    "head_sha": self.head, "diff_sha256": diff_hash, "review_result": "PASS", "findings": []}
        openai = {**deepseek, "provider": "openai", "model": "gpt-5.6-sol",
                  "reasoning_effort": "high"}
        validate = lambda value: value
        proof = gate.validate_gate(root=self.root, base=self.base, head=self.head,
                    deepseek_receipt=deepseek, openai_receipt=openai,
                    deepseek_validator=validate, openai_validator=validate)
        self.assertEqual(proof["status"], "PASS")
        openai["findings"] = [{"severity": "P1"}]
        with self.assertRaises(ValueError):
            gate.validate_gate(root=self.root, base=self.base, head=self.head,
                deepseek_receipt=deepseek, openai_receipt=openai,
                deepseek_validator=validate, openai_validator=validate)


if __name__ == "__main__":
    unittest.main()
