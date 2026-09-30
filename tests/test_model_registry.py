import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.model_qualification import (CASES, QualificationResult, expected_findings,
                                         evaluate_cases, qualification_receipt,
                                         validate_qualification_receipt)
from harness.model_registry import load_registry, preflight
from harness.review_failures import ReviewFailureClassification, classify_process_failure
from harness.reviewer_v2_contract import parse_synthesis


class RegistryTests(unittest.TestCase):
    def test_openai_preflight_checks_canonical_binary_and_home(self):
        with patch("harness.model_registry.subprocess.run") as run:
            run.return_value.returncode = 0
            result = preflight(load_registry().role("final_reviewer"))
        self.assertTrue(result.authenticated)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["/usr/lib/chatgpt/resources/codex", "login", "status"])
        self.assertEqual(run.call_args.kwargs["env"]["CODEX_HOME"],
                         "/home/xupeng/.footballprediction/canonical-codex-reviewer")

    def test_default_registry_uses_two_providers(self):
        registry = load_registry()
        self.assertEqual(registry.role("independent_reviewer").provider, "deepseek")
        self.assertEqual(registry.role("final_reviewer").model, "gpt-5.6-sol")

    def test_rejects_same_provider_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "models.json"
            data = json.loads(load_registry().path.read_text())
            data["roles"]["final_reviewer"]["provider"] = "deepseek"
            data["roles"]["final_reviewer"].pop("reasoning_effort")
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_registry(path)
            data["roles"]["final_reviewer"]["provider"] = "openai"
            data["roles"]["final_reviewer"]["reasoning_effort"] = "high"
            data["roles"]["builder"]["fallback"] = "other"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                load_registry(path)


class QualificationContractTests(unittest.TestCase):
    def setUp(self):
        self.case = CASES[3]
        self.findings = expected_findings(self.case)
        self.summary = "Qualification response checked against exact source."

    def raw(self, decisions, *, findings=None):
        return json.dumps({"findings": [] if findings is None else findings,
                           "decisions": decisions, "summary": self.summary})

    def decision(self, finding_id, decision="UPHELD", rationale=None, source_quote=""):
        return {"finding_id": finding_id, "decision": decision,
                "rationale": rationale or "The named source line directly supports this decision.",
                "source_quote": source_quote}

    def test_complete_decisions(self):
        raw = self.raw([self.decision(item["finding_id"]) for item in self.findings])
        self.assertEqual(len(parse_synthesis(raw, self.findings,
                                             source=self.case.source.encode())["decisions"]), 2)

    def test_missing_unknown_duplicate_and_invalid_rejected(self):
        good = self.decision(self.findings[0]["finding_id"])
        for decisions in ([good], [good, good], [good, self.decision("F999F999")]):
            with self.assertRaises(ValueError):
                parse_synthesis(self.raw(decisions), self.findings,
                                source=self.case.source.encode())
        with self.assertRaises(ValueError):
            parse_synthesis("not-json", self.findings, source=self.case.source.encode())

    def test_dispute_requires_source_detail(self):
        disputed_case = CASES[2]
        disputed = expected_findings(disputed_case)
        for quote in ("", "source text not present"):
            with self.assertRaises(ValueError):
                parse_synthesis(self.raw([self.decision(disputed[0]["finding_id"],
                    "DISPUTED", source_quote=quote)]), disputed,
                    source=disputed_case.source.encode())

    def test_real_source_quote_allows_dispute(self):
        disputed_case = CASES[2]
        disputed = expected_findings(disputed_case)
        result = parse_synthesis(self.raw([self.decision(disputed[0]["finding_id"],
            "DISPUTED", source_quote="return a + b")]), disputed,
            source=disputed_case.source.encode())
        self.assertEqual(result["review_result"], "PASS")

    def test_mock_invoker_cannot_be_reported_as_real_qualification(self):
        # A caller can use this function for fixtures, but certificates from a
        # mock are not accepted by the external qualification gate.
        spec = load_registry().role("independent_reviewer")
        result = evaluate_cases(spec, lambda _spec, _prompt: self.raw([]))
        self.assertFalse(result.passed)
        self.assertIn("single_blocker", result.cases_failed)

    def test_provider_errors_are_not_format_retries(self):
        for message, expected in (("HTTP 401", ReviewFailureClassification.AUTHENTICATION_FAILURE),
                                  ("HTTP 429", ReviewFailureClassification.TRANSIENT_CAPACITY),
                                  ("model_not_found", ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED)):
            with self.subTest(message=message):
                self.assertEqual(classify_process_failure([message]).classification, expected)

    def test_qualification_receipt_exact_identity_and_integrity(self):
        spec = load_registry().role("final_reviewer")
        result = QualificationResult(spec.identity(), "real_provider",
                                     tuple(case.name for case in CASES), (), ("a" * 64,) * len(CASES))
        receipt = qualification_receipt(result, auth_key="owner-test-key")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_text(json.dumps(receipt))
            self.assertEqual(validate_qualification_receipt(path, spec, auth_key="owner-test-key"), receipt)
            with self.assertRaises(ValueError):
                validate_qualification_receipt(path,
                    load_registry().role("independent_reviewer"), auth_key="owner-test-key")
            receipt["cases_passed"] = []
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                validate_qualification_receipt(path, spec, auth_key="owner-test-key")


if __name__ == "__main__":
    unittest.main()
