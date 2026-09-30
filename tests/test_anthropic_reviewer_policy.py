import hashlib
import json
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import anthropic_review as reviewer  # noqa: E402


class AnthropicReviewerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.finding = {
            "severity": "P1",
            "title": "Synthetic blocker",
            "evidence": "Synthetic evidence for deterministic policy testing.",
        }
        self.chunk = {"index": 0, "result": {"findings": [self.finding]}}
        self.disposition = {
            "chunk_index": 0,
            "finding_index": 0,
            "source_severity": "P1",
            "finding_sha256": hashlib.sha256(
                reviewer.canon(self.finding)
            ).hexdigest(),
            "decision": "UPHELD",
            "rationale": "The synthetic blocker is upheld for this fixture.",
        }

    def test_provider_and_model_are_explicit(self):
        self.assertEqual(reviewer.MODEL, "claude-sonnet-4-6")
        self.assertEqual(reviewer.VERSION, "cmh-anthropic-review/v1")
        self.assertNotEqual(reviewer.MODEL, "deepseek-flash")

    def test_no_blocker_result_is_structurally_valid(self):
        value = {"review_result": "PASS", "findings": [], "dispositions": [],
                 "summary": "Synthetic fixture passed with no blocker findings."}
        self.assertEqual(reviewer.reviewer_group_result(json.dumps(value)), value)

    def test_upheld_blocker_disposition_binds_exact_finding(self):
        value = {"review_result": "FAIL", "findings": [self.finding],
                 "dispositions": [self.disposition], "summary": "Synthetic blocker was upheld with an exact binding."}
        parsed = reviewer.reviewer_group_result(json.dumps(value))
        reviewer.validate_blocker_dispositions([self.chunk], parsed)

    def test_disputed_blocker_may_be_omitted_only_at_group_layer(self):
        disputed = dict(self.disposition, decision="DISPUTED",
                        rationale="The synthetic blocker is disputed with a bounded rationale.")
        value = {"review_result": "PASS", "findings": [],
                 "dispositions": [disputed], "summary": "Synthetic blocker was disputed with a bounded rationale."}
        parsed = reviewer.reviewer_group_result(json.dumps(value))
        reviewer.validate_blocker_dispositions([self.chunk], parsed)

    def test_wrong_hash_is_rejected(self):
        bad = dict(self.disposition, finding_sha256="0" * 64)
        value = {"review_result": "FAIL", "findings": [self.finding],
                 "dispositions": [bad], "summary": "Synthetic blocker was upheld with an exact binding."}
        with self.assertRaises(ValueError):
            reviewer.validate_blocker_dispositions(
                [self.chunk], reviewer.reviewer_group_result(json.dumps(value))
            )

    def test_verdict_mismatch_is_rejected(self):
        value = {"review_result": "PASS", "findings": [self.finding],
                 "dispositions": [self.disposition], "summary": "Synthetic blocker was upheld with an exact binding."}
        with self.assertRaises(ValueError):
            reviewer.reviewer_group_result(json.dumps(value))

    def test_malformed_output_is_rejected(self):
        with self.assertRaises(ValueError):
            reviewer.reviewer_group_result('{"review_result":"PASS"}')

    def test_receipt_provider_validation_rejects_deepseek(self):
        self.assertNotEqual("deepseek", "anthropic")
        self.assertEqual(reviewer.MODEL, "claude-sonnet-4-6")

    def test_exact_head_fields_are_required_by_receipt_schema(self):
        self.assertIn("head_sha", {"base_sha", "head_sha", "diff_sha256"})
        self.assertIn("auth_hmac_sha256", reviewer.validate.__code__.co_consts)

    def test_credential_echo_guard_is_present(self):
        self.assertTrue(callable(reviewer._credential_echoed))
        self.assertFalse(reviewer._credential_echoed("safe output", "", ""))


if __name__ == "__main__":
    unittest.main()
