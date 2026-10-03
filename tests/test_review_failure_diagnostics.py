"""Reviewer CLI failures retain bounded diagnostics without retaining secrets."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import review_failure_diagnostics as d
from harness.review_resume import ReviewRun

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deepseek_review as storage  # noqa: E402
import reviewer_v2_deepseek as runner  # noqa: E402


class DiagnosticTests(unittest.TestCase):
    def test_explicit_nonzero_categories_and_resume_policy(self):
        cases = {
            b"Usage: claude --print": ("CLI_USAGE_ERROR", False),
            b"invalid argument for --model": ("INVALID_ARGUMENT", False),
            b"HTTP 401 authentication failed": ("AUTH_ERROR", False),
            b"HTTP 429 rate limit": ("RATE_LIMIT", True),
            b"quota exceeded": ("QUOTA_ERROR", False),
            b"connection reset": ("TRANSPORT_ERROR", True),
            b"HTTP 503": ("PROVIDER_ERROR", True),
            b"context length exceeded": ("CONTEXT_LIMIT", False),
            b"invalid JSON schema": ("SCHEMA_INVOCATION_ERROR", False),
            b"cannot find module": ("LOCAL_LAUNCHER_ERROR", False),
            b"unclassified error": ("UNKNOWN_NONZERO_EXIT", False),
            b"": ("UNKNOWN_NONZERO_EXIT", False),
        }
        for stderr, expected in cases.items():
            with self.subTest(stderr=stderr):
                category, markers, allowed, reason = d.classify_nonzero(b"", stderr, 1)
                self.assertEqual((category, allowed), expected)
                self.assertTrue(reason)
                self.assertEqual(set(markers), set(d._PATTERNS))

    def test_conflicting_markers_are_unknown_and_signal_is_distinct(self):
        category, markers, allowed, reason = d.classify_nonzero(b"", b"401 and 429", 1)
        self.assertEqual(category, "UNKNOWN_NONZERO_EXIT")
        self.assertFalse(allowed)
        self.assertTrue(markers["AUTH_ERROR"] and markers["RATE_LIMIT"])
        self.assertIn("conflicting", reason)
        self.assertEqual(d.classify_nonzero(b"", b"", -15)[0], "SIGNALLED")

    def test_stdout_error_wrapper_is_classified_without_source_false_positive(self):
        wrapper = json.dumps({"is_error": True, "result": "HTTP 429 rate limit"}).encode()
        self.assertEqual(d.classify_nonzero(wrapper, b"", 1)[0], "RATE_LIMIT")
        self.assertEqual(d.cli_wrapper_summary(wrapper)["is_error"], True)
        source = json.dumps({"is_error": False, "result": "diff contains HTTP 401"}).encode()
        self.assertEqual(d.classify_nonzero(source, b"", 1)[0], "UNKNOWN_NONZERO_EXIT")
        self.assertIsNone(d.cli_wrapper_summary(b"not json")["api_error_status"])

    def test_environment_hash_omits_secret_and_proxy_values(self):
        first = {"HOME": "/nonexistent", "PATH": "/usr/bin", "LANG": "C.UTF-8",
                 "ANTHROPIC_BASE_URL": "https://example.invalid", "CLAUDE_CODE_SIMPLE": "1",
                 "ANTHROPIC_API_KEY": "secret-a", "HTTPS_PROXY": "https://user:pass@proxy"}
        second = {**first, "ANTHROPIC_API_KEY": "secret-b",
                  "HTTPS_PROXY": "https://other:password@proxy"}
        self.assertEqual(d.environment_identity(first), d.environment_identity(second))
        self.assertNotEqual(d.environment_identity(first), d.environment_identity({**first, "LANG": "C"}))

    def test_command_hash_binds_settings_content_not_random_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            a, b = Path(temporary) / "a", Path(temporary) / "b"
            a.write_text("{}")
            b.write_text("{}")
            first = d.command_identity(["/bin/claude", "--settings", str(a), "--print"])
            self.assertEqual(first, d.command_identity(["/bin/claude", "--settings", str(b), "--print"]))
            b.write_text('{"changed":true}')
            self.assertNotEqual(first, d.command_identity(["/bin/claude", "--settings", str(b), "--print"]))

    def test_stream_hash_size_and_truncation(self):
        raw = b"partial-secret-output"
        result = d.stream_metadata(raw, b"x" * d.STREAM_LIMIT)
        self.assertEqual(result["stdout_size"], len(raw))
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertEqual(result["stderr_size"], d.STREAM_LIMIT)

    def test_invoke_nonzero_records_hashes_without_parser_or_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings = Path(temporary) / "settings.json"
            settings.write_text("{}")
            stdout = b'{"is_error":true,"result":"HTTP 429 rate limit"}'
            stderr = b"transient rate limit"
            completed = subprocess.CompletedProcess([], 1, stdout, stderr)
            state = {}
            with patch.object(runner.legacy, "invoke_reviewer", return_value=completed):
                with self.assertRaises(runner.ReviewStageFailure) as caught:
                    runner._invoke(["/bin/claude", "--settings", str(settings)], "prompt",
                                   {"HOME": "/nonexistent", "ANTHROPIC_API_KEY": "fixture-secret"},
                                   30, "fixture-secret", stage="group", evidence_fd=0,
                                   artifact="group-000.json", state=state, persist=False)
            self.assertEqual(caught.exception.category, "RATE_LIMIT")
            self.assertTrue(state["resume_allowed"])
            self.assertEqual(state["stdout_sha256"], d.digest(stdout))
            self.assertEqual(state["stderr_sha256"], d.digest(stderr))
            self.assertFalse(state["parser_entered"])
            self.assertFalse(state["schema_validation_entered"])
            self.assertNotIn("fixture-secret", json.dumps(state))

    def test_chunk_nonzero_passes_exact_streams_to_private_sink(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings = Path(temporary) / "settings.json"
            settings.write_text("{}")
            stdout, stderr = b'{"is_error":true}', b"cli failed"
            completed = subprocess.CompletedProcess([], 1, stdout, stderr)
            captured = []
            with patch.object(runner.legacy, "invoke_reviewer", return_value=completed):
                with self.assertRaises(runner.ReviewStageFailure):
                    runner._invoke(["/bin/claude", "--settings", str(settings)], "chunk prompt",
                                   {"HOME": "/nonexistent"}, 30, "fixture-secret",
                                   stage="chunk", evidence_fd=0, artifact="chunk-001.json",
                                   state={}, persist=False,
                                   transport_sink=lambda prompt, out, err, **kwargs:
                                       captured.append((prompt, out, err, kwargs)))
            self.assertEqual(captured[0][:3], (b"chunk prompt", stdout, stderr))
            self.assertFalse(captured[0][3]["secret_echo"])

    def test_success_then_parser_and_schema_failure_flags(self):
        state = {"stage": "group"}
        self.assertEqual(runner._parse_stage('{"ok":true}', json.loads, state), {"ok": True})
        self.assertEqual((state["parser_result"], state["schema_validation_result"]), ("PASS", "PASS"))
        state = {"stage": "group"}
        with self.assertRaises(runner.ReviewStageFailure):
            runner._parse_stage('{"ok":true}', lambda raw: (_ for _ in ()).throw(ValueError("bad schema")), state)
        self.assertEqual((state["parser_result"], state["schema_validation_result"]), ("FAIL", "FAIL"))
        state = {"stage": "group"}
        with self.assertRaises(runner.ReviewStageFailure):
            runner._parse_stage('{', json.loads, state)
        self.assertTrue(state["parser_entered"])
        self.assertFalse(state.get("schema_validation_entered", False))

    def test_failure_evidence_write_failure_never_approves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            run = ReviewRun(Path(temporary) / "evidence", root, {"runner_hash": "a"},
                            [("chunk-000", "chunk")], storage, prefix="fixture-")
            try:
                with patch.object(storage, "write_private_artifact", side_effect=OSError("disk full")):
                    with self.assertRaises(OSError):
                        run.failure({"failure_category": "UNKNOWN_NONZERO_EXIT"})
                self.assertFalse(run.state["receipt_written"])
                self.assertFalse((run.path / "receipt.json").exists())
            finally:
                run.close()

    def test_transient_retry_is_bounded_and_terminal_state_starts_new_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            evidence = Path(temporary) / "evidence"
            def open_run():
                return ReviewRun(evidence, root, {"runner_hash": "a"},
                                 [("chunk-000", "chunk")], storage, prefix="fixture-")
            first = open_run()
            path = first.path
            failure = json.loads(first.failure({"failure_category": "RATE_LIMIT",
                                                "resume_allowed": True}).read_text())
            self.assertTrue(failure["resume_allowed"])
            first.close()
            second = open_run()
            self.assertEqual(second.path, path)
            failure = json.loads(second.failure({"failure_category": "RATE_LIMIT",
                                                 "resume_allowed": True}).read_text())
            self.assertFalse(failure["resume_allowed"])
            second.close()
            third = open_run()
            self.assertNotEqual(third.path, path)
            self.assertEqual(third.state["next_stage"], "chunk-000")
            third.close()


if __name__ == "__main__":
    unittest.main()
