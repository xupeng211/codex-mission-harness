import json
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.model_qualification import (CASES, QualificationResult, expected_findings,
                                         evaluate_cases, qualification_receipt,
                                         validate_qualification_receipt,
                                         require_builder_qualification)
from harness.openai_invocation import InvocationFailure, canonical_environment
from trusted_invocation_fixture import canonical_fixture
from harness.model_registry import load_registry, preflight, trusted_claude_launcher
from harness.review_failures import ReviewFailureClassification, classify_process_failure
from harness.reviewer_v2_contract import parse_synthesis


class RegistryTests(unittest.TestCase):
    def test_candidate_registry_is_explicit_and_preserves_baseline(self):
        baseline = load_registry()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "candidate.json"
            binary = Path("/usr/bin/git")
            value = json.loads(baseline.path.read_text())
            value["roles"]["final_reviewer"] = {
                "provider": "openai", "model": "gpt-6.1-sol", "reasoning_effort": "high",
                "executable": str(binary),
                "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            candidate = load_registry(path)
            self.assertEqual(baseline.role("final_reviewer").model, "gpt-5.6-sol")
            self.assertEqual(candidate.role("final_reviewer").model, "gpt-6.1-sol")
            self.assertEqual(candidate.role("builder"), baseline.role("builder"))
            self.assertEqual(candidate.role("independent_reviewer"), baseline.role("independent_reviewer"))
            self.assertNotEqual(candidate.role("final_reviewer").identity(),
                                baseline.role("final_reviewer").identity())
            from harness.openai_invocation import selected_binary
            self.assertEqual(selected_binary(candidate.role("final_reviewer")), binary)
            with self.assertRaisesRegex(ValueError, "differs from selected"):
                selected_binary(candidate.role("final_reviewer"), Path("/usr/bin/false"))
            value["roles"]["final_reviewer"]["executable_sha256"] = "0" * 64
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                selected_binary(load_registry(path).role("final_reviewer"))

    def test_candidate_preflight_uses_only_its_pinned_binary(self):
        from harness.model_registry import ModelSpec
        spec = ModelSpec("openai", "gpt-6.1-sol", "high", "/usr/bin/git",
                         hashlib.sha256(Path("/usr/bin/git").read_bytes()).hexdigest())
        with patch("harness.openai_invocation.canonical_environment", return_value={}) as environment, \
             patch("harness.model_registry.subprocess.run") as run:
            run.return_value.returncode = 0
            result = preflight(spec)
        self.assertEqual(result.identity, spec.identity())
        self.assertEqual(run.call_args.args[0], ["/usr/bin/git", "login", "status"])
        environment.assert_called_once_with(binary=Path("/usr/bin/git"))

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
    def test_old_qualification_cannot_authorize_candidate_model(self):
        baseline = load_registry().role("final_reviewer")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            registry_path = directory / "candidate.json"
            value = json.loads(load_registry().path.read_text())
            binary = Path("/usr/bin/git")
            value["roles"]["final_reviewer"] = {
                "provider": "openai", "model": "gpt-6.1-sol", "reasoning_effort": "high",
                "executable": str(binary),
                "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            registry_path.write_text(json.dumps(value))
            registry_path.chmod(0o600)
            candidate = load_registry(registry_path).role("final_reviewer")
            def signed(spec, registry=None):
                result = QualificationResult(spec.identity(), "real_provider",
                                             tuple(case.name for case in CASES), (),
                                             ("a" * 64,) * len(CASES))
                return qualification_receipt(result, auth_key="fixture-key",
                                             role="final_reviewer", registry_path=registry)
            old_path = directory / "old.json"
            old_path.write_text(json.dumps(signed(baseline)))
            old_path.chmod(0o600)
            with self.assertRaises(ValueError):
                validate_qualification_receipt(old_path, candidate, auth_key="fixture-key",
                                               role="final_reviewer", registry_path=registry_path)
            new_path = directory / "candidate-receipt.json"
            new_path.write_text(json.dumps(signed(candidate, registry_path)))
            new_path.chmod(0o600)
            self.assertEqual(validate_qualification_receipt(
                new_path, candidate, auth_key="fixture-key", role="final_reviewer",
                registry_path=registry_path)["identity"], candidate.identity())
            with self.assertRaises(ValueError):
                validate_qualification_receipt(new_path, baseline, auth_key="fixture-key",
                                               role="final_reviewer")

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

    def test_provider_invocation_failure_stops_remaining_qualification_calls(self):
        calls = []
        def fail_once(_spec, _prompt):
            calls.append(1)
            raise InvocationFailure("AUTHENTICATION_FAILURE", "auth failed", {})
        result = evaluate_cases(load_registry().role("final_reviewer"), fail_once)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.cases_failed, tuple(case.name for case in CASES))

    def test_provider_timeout_is_a_failed_qualification_case(self):
        def timeout(_spec, _prompt):
            raise subprocess.TimeoutExpired("deepseek", 1)
        result = evaluate_cases(load_registry().role("independent_reviewer"), timeout)
        self.assertFalse(result.passed)
        self.assertEqual(result.cases_failed, tuple(case.name for case in CASES))

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
