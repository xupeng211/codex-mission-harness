import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.model_qualification import (CASES, QualificationResult, expected_findings,
                                         qualification_prompt,
                                         evaluate_cases, qualification_receipt, QualificationEvidence,
                                         _evaluate_cases,
                                         _actual_provider_invoke_unmetered,
                                         validate_qualification_receipt,
                                         require_builder_qualification)
from harness.openai_invocation import InvocationFailure, InvocationResult, canonical_environment
from trusted_invocation_fixture import canonical_fixture
from harness.model_registry import load_registry, preflight, trusted_claude_launcher
from harness.review_failures import ReviewFailureClassification, classify_process_failure
from harness.reviewer_v2_contract import parse_synthesis


class RegistryTests(unittest.TestCase):
    def test_openai_preflight_checks_canonical_binary_and_home(self):
        with canonical_fixture() as (binary, home), \
             patch("harness.openai_invocation.canonical_environment", side_effect=lambda:
                   canonical_environment({}, binary=binary, codex_home=home)) as environment, \
             patch("harness.model_registry.subprocess.run") as run:
            run.return_value.returncode = 0
            result = preflight(load_registry().role("final_reviewer"))
        self.assertTrue(result.authenticated)
        environment.assert_called_once_with()
        argv = run.call_args.args[0]
        self.assertEqual(argv[:3], ["/usr/lib/chatgpt/resources/codex", "login", "status"])
        self.assertEqual(run.call_args.kwargs["env"]["CODEX_HOME"],
                         str(home))

    def test_default_registry_uses_two_providers(self):
        registry = load_registry()
        self.assertEqual(registry.role("independent_reviewer").provider, "deepseek")
        self.assertEqual(registry.role("final_reviewer").model, "gpt-5.6-sol")

    def test_deepseek_qualification_rejects_untrusted_path_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "bin"
            directory.mkdir(mode=0o777)
            directory.chmod(0o777)
            launcher = directory / "claude"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            with patch.dict("os.environ", {"PATH": str(directory)}):
                with self.assertRaises(RuntimeError):
                    trusted_claude_launcher()

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

    def test_custom_registry_requires_private_owner_controlled_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "models.json"
            path.write_bytes(load_registry().path.read_bytes())
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                load_registry(path)
            path.chmod(0o600)
            self.assertEqual(load_registry(path).role("builder"), load_registry().role("builder"))
            alias = Path(temporary) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                load_registry(alias)


class QualificationContractTests(unittest.TestCase):
    def test_builder_execution_gate_requires_builder_role(self):
        with self.assertRaisesRegex(ValueError, "builder qualification"):
            require_builder_qualification(None, None)
        with patch("harness.model_registry.read_private_token", return_value="fixture-key"), \
             patch("harness.model_qualification.validate_qualification_receipt",
                   return_value={"role": "builder"}) as validate:
            self.assertEqual(require_builder_qualification("builder-receipt", "key-file"),
                             {"role": "builder"})
        self.assertEqual(validate.call_args.kwargs["role"], "builder")

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

    def test_upheld_chunk_blocker_is_carried_into_group_findings(self):
        case = CASES[3]
        expected = expected_findings(case)
        result = parse_synthesis(self.raw([
            self.decision(item["finding_id"]) for item in expected
        ]), expected, source=case.source.encode())
        self.assertEqual(result["review_result"], "FAIL")
        self.assertEqual(result["findings"], [item["finding"] for item in expected])

    def test_mock_invoker_cannot_be_reported_as_real_qualification(self):
        # A caller can use this function for fixtures, but certificates from a
        # mock are not accepted by the external qualification gate.
        spec = load_registry().role("independent_reviewer")
        result = evaluate_cases(spec, lambda _spec, _prompt: self.raw([]))
        self.assertFalse(result.passed)
        self.assertIn("single_blocker", result.cases_failed)

    def test_failed_case_keeps_exact_raw_and_verdict_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            result = evaluate_cases(load_registry().role("independent_reviewer"),
                                    lambda _spec, _prompt: self.raw([]), evidence=evidence)
            self.assertFalse(result.passed)
            case = json.loads((root / "diagnostics" / "single_blocker.json").read_text())
            self.assertEqual(case["structured_output_raw"], self.raw([]))
            self.assertEqual(case["exact_failure_reason"], "missing blocker disposition")
            self.assertEqual(case["failure_phase"], "PARSER_OR_SOURCE_BINDING")
            self.assertEqual((root / "diagnostics" / "single_blocker.json").stat().st_mode & 0o777, 0o600)
            evidence.capture_transport("single_blocker", b'{"structured_output":{}}', b"cli-error", 0)
            self.assertEqual((root / "diagnostics" / "single_blocker.stdout").read_bytes(),
                             b'{"structured_output":{}}')
            self.assertEqual((root / "diagnostics" / "single_blocker.stderr").read_bytes(), b"cli-error")

    def test_false_clean_finding_is_recorded_as_verdict_failure(self):
        false_finding = {"severity": "P1", "title": "Invented blocker", "evidence": "No support"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            result = evaluate_cases(load_registry().role("independent_reviewer"),
                                    lambda _spec, _prompt: self.raw([], findings=[false_finding]),
                                    evidence=evidence)
            self.assertIn("clean", result.cases_failed)
            record = json.loads((root / "diagnostics" / "clean.json").read_text())
            self.assertEqual(record["failure_phase"], "QUALIFICATION_VERDICT")
            self.assertEqual(record["exact_failure_reason"], "semantic decision mismatch")
            self.assertEqual(record["parser_result"], "PASS")
            self.assertEqual(record["parsed_result"]["new_findings"], [false_finding])

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_local_fixture_transport_bytes_are_preserved_before_parse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            fake = root / "fixture-local-launcher"
            envelope = json.dumps({"structured_output": {"decisions": [], "findings": [],
                                                          "summary": self.summary},
                                   "usage": {"input_tokens": 1, "output_tokens": 1}})
            fake.write_text("#!/usr/bin/python3\nimport sys\n"
                            f"sys.stdout.write({envelope!r})\n"
                            "sys.stderr.write('fixture-stderr')\n")
            fake.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            with patch("harness.model_registry.trusted_claude_launcher",
                       return_value=(str(fake), "/usr/bin")):
                result = _actual_provider_invoke_unmetered(
                    load_registry().role("independent_reviewer"), "fixture prompt",
                    token="synthetic-fixture-token", timeout=5,
                    transport_sink=lambda stdout, stderr, code:
                        evidence.capture_transport("clean", stdout, stderr, code))
            self.assertEqual(json.loads(result.response)["findings"], [])
            self.assertEqual((root / "diagnostics" / "clean.stdout").read_bytes(), envelope.encode())
            self.assertEqual((root / "diagnostics" / "clean.stderr").read_bytes(), b"fixture-stderr")

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_failed_cli_partial_output_and_request_usage_are_durable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            fake = root / "fixture-failing-launcher"
            fake.write_text("#!/usr/bin/python3\nimport sys\n"
                            "sys.stdout.write('partial model output')\n"
                            "sys.stderr.write('synthetic CLI failure')\n"
                            "raise SystemExit(1)\n")
            fake.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            ledger = root / "ledger.json"
            ledger.write_text(json.dumps({"requests": [{"number": 295,
                "request_id": "synthetic-295", "status": "FAILED",
                "reported_usage": {"tokens": {"input": 3, "output": 5}}}]}))
            with patch("harness.model_registry.trusted_claude_launcher",
                       return_value=(str(fake), "/usr/bin")), \
                 patch.dict("os.environ", {"CMH_RESOURCE_LEDGER": str(ledger)}):
                evidence.capture_prompt("clean", qualification_prompt(CASES[0]))
                evidence.capture_reservation("clean", "synthetic-295")
                with self.assertRaises(RuntimeError):
                    _actual_provider_invoke_unmetered(
                        load_registry().role("independent_reviewer"),
                        qualification_prompt(CASES[0]), token="synthetic-fixture-token",
                        timeout=5, transport_sink=lambda stdout, stderr, code:
                            evidence.capture_transport("clean", stdout, stderr, code))
                evidence.record_case("clean", {"case_id": "clean", "verdict": "FAIL",
                    "exact_failure_reason": "DeepSeek model qualification provider call failed"})
            record = json.loads((root / "diagnostics" / "clean.json").read_text())
            self.assertEqual(record["resource_request_number"], 295)
            self.assertEqual(record["invocation_usage"]["tokens"]["output"], 5)
            self.assertEqual((root / "diagnostics" / "clean.stdout").read_bytes(),
                             b"partial model output")
            self.assertEqual((root / "diagnostics" / "clean.stderr").read_bytes(),
                             b"synthetic CLI failure")
            checkpoint = json.loads((root / "diagnostics" / "checkpoint.json").read_text())
            self.assertIn("clean.transport.json", checkpoint["files"])

    def test_diagnostic_binds_structured_response_to_usage_and_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            usage = {"input_tokens": 4, "output_tokens": 7}
            evaluate_cases(load_registry().role("independent_reviewer"),
                           lambda _spec, _prompt: InvocationResult(
                               self.raw([]), {"resource_request_id": "synthetic-request",
                                              "usage": usage}), evidence=evidence)
            record = json.loads((root / "diagnostics" / "clean.json").read_text())
            self.assertEqual(record["resource_request_id"], "synthetic-request")
            self.assertEqual(record["invocation_usage"], usage)

    def test_provider_invocation_failure_stops_remaining_qualification_calls(self):
        calls = []
        def fail_once(_spec, _prompt):
            calls.append(1)
            raise InvocationFailure("AUTHENTICATION_FAILURE", "auth failed", {})
        result = evaluate_cases(load_registry().role("final_reviewer"), fail_once)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.cases_failed, ("clean",))

    def test_provider_timeout_is_a_failed_qualification_case(self):
        def timeout(_spec, _prompt):
            raise subprocess.TimeoutExpired("deepseek", 1)
        result = evaluate_cases(load_registry().role("independent_reviewer"), timeout)
        self.assertFalse(result.passed)
        self.assertEqual(result.cases_failed, tuple(case.name for case in CASES))

    def test_real_qualification_failures_stop_and_leave_private_hashed_checkpoint(self):
        false_finding = {"severity": "P1", "title": "Invented blocker", "evidence": "No support"}
        scenarios = [
            ("false_clean", lambda case: self.raw([], findings=[false_finding])),
            ("missed_blocker", lambda case: self.raw([])),
            ("schema_invalid", lambda case: '{"decisions":"wrong"}'),
            ("parser_exception", lambda case: 'not-json'),
            ("cli_incomplete", lambda case: (_ for _ in ()).throw(RuntimeError("partial CLI output"))),
            ("source_binding", lambda case: self.raw([self.decision(
                expected_findings(case)[0]["finding_id"], "DISPUTED",
                source_quote="not in source")]) if case.name == "single_blocker" else self.raw([])),
        ]
        for label, response in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); root.chmod(0o700)
                evidence = QualificationEvidence(root / "diagnostics")
                calls = []
                def invoke(_spec, prompt):
                    case = next(item for item in CASES if qualification_prompt(item) == prompt)
                    calls.append(case.name)
                    return response(case)
                # Skip clean only for the blocker and binding cases; a synthetic
                # clean response is supplied to reach the intended fixture.
                if label in ("missed_blocker", "source_binding"):
                    original = invoke
                    def invoke(_spec, prompt):
                        case = next(item for item in CASES if qualification_prompt(item) == prompt)
                        return self.raw([]) if case.name == "clean" else original(_spec, prompt)
                result = _evaluate_cases(load_registry().role("independent_reviewer"), invoke,
                                         mode="real_provider", evidence=evidence)
                self.assertFalse(result.passed)
                self.assertLessEqual(len(calls), 2)
                self.assertEqual(len(result.cases_failed), 1)
                checkpoint = json.loads((root / "diagnostics" / "checkpoint.json").read_text())
                for filename, sha in checkpoint["files"].items():
                    self.assertEqual(hashlib.sha256((root / "diagnostics" / filename).read_bytes()).hexdigest(), sha)
                failed = json.loads((root / "diagnostics" /
                                     (result.cases_failed[0] + ".json")).read_text())
                self.assertIsNotNone(failed["exact_failure_reason"])
                self.assertTrue((root / "diagnostics" /
                                 (result.cases_failed[0] + ".prompt")).exists())

    def test_interrupted_qualification_preserves_checkpoint_before_reraising(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            evidence = QualificationEvidence(root / "diagnostics")
            with self.assertRaises(KeyboardInterrupt):
                _evaluate_cases(load_registry().role("independent_reviewer"),
                                lambda _spec, _prompt: (_ for _ in ()).throw(KeyboardInterrupt()),
                                mode="real_provider", evidence=evidence)
            record = json.loads((root / "diagnostics" / "clean.json").read_text())
            self.assertEqual(record["failure_phase"], "INTERRUPTED")
            self.assertTrue((root / "diagnostics" / "checkpoint.json").exists())

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
        receipt = qualification_receipt(result, auth_key="owner-test-key", role="final_reviewer")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_text(json.dumps(receipt))
            path.chmod(0o600)
            self.assertEqual(validate_qualification_receipt(path, spec, auth_key="owner-test-key",
                                                             role="final_reviewer"), receipt)
            alias = Path(temporary) / "receipt-alias.json"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                validate_qualification_receipt(alias, spec, auth_key="owner-test-key",
                                               role="final_reviewer")
            oversized = Path(temporary) / "oversized.json"
            oversized.write_bytes(b"x" * 65_537)
            oversized.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "bounded"):
                validate_qualification_receipt(oversized, spec, auth_key="owner-test-key",
                                               role="final_reviewer")
            with self.assertRaises(ValueError):
                validate_qualification_receipt(path, spec, auth_key="owner-test-key", role="builder")
            self.assertIn("cli_runner_sha256", receipt)
            self.assertIn("invocation_sha256", receipt)
            original_read = Path.read_bytes
            for changed_name, changed_parent in (("model_qualification.py", "scripts"),
                                                 ("openai_invocation.py", "harness")):
                with self.subTest(changed_name=changed_name):
                    def changed_file(source):
                        if source.name == changed_name and source.parent.name == changed_parent:
                            return b"changed implementation"
                        return original_read(source)
                    with patch.object(Path, "read_bytes", changed_file):
                        with self.assertRaises(ValueError):
                            validate_qualification_receipt(path, spec, auth_key="owner-test-key",
                                                           role="final_reviewer")
            with tempfile.TemporaryDirectory() as custom_dir:
                alternate = Path(custom_dir) / "models.json"
                alternate.write_bytes(load_registry().path.read_bytes() + b" ")
                with self.assertRaises(ValueError):
                    validate_qualification_receipt(path, spec, auth_key="owner-test-key",
                                                   role="final_reviewer", registry_path=alternate)
            with self.assertRaises(ValueError):
                validate_qualification_receipt(path,
                    load_registry().role("independent_reviewer"), auth_key="owner-test-key",
                    role="final_reviewer")
            receipt["cases_passed"] = []
            path.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError):
                validate_qualification_receipt(path, spec, auth_key="owner-test-key",
                                               role="final_reviewer")


if __name__ == "__main__":
    unittest.main()
