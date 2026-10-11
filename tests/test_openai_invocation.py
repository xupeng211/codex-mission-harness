import json
import os
import tempfile
import unittest
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from trusted_invocation_fixture import canonical_fixture
from harness.model_registry import ModelSpec
from harness.openai_invocation import (InvocationFailure, MAX_EVENT_STREAM_BYTES, _failure_category,
                                       _failure_markers, _observed_events, _matches_schema,
                                       canonical_environment, parse_events)


class OpenAIInvocationTests(unittest.TestCase):
    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_preflight_result_requires_exact_structured_schema(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        from harness.model_registry import load_registry
        from reviewer_v2_openai import _schema
        schema = _schema(False)
        self.assertTrue(_matches_schema({"findings": []}, schema))
        self.assertFalse(_matches_schema({"decisions": []}, schema))
        self.assertFalse(_matches_schema({"findings": [], "extra": True}, schema))
        self.assertFalse(_matches_schema({}, schema))
        complete = (b'{"type":"thread.started"}\n{"type":"turn.started"}\n'
                    b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
                    b'{"type":"turn.completed"}\n')
        for result in ('not json', '{"findings":1}', '{"findings":[]}'):
            with self.subTest(result=result):
                process = Mock(pid=1234, returncode=0)
                process.communicate.return_value = (complete, b"")
                def start(command, **_kwargs):
                    Path(command[command.index("--output-last-message") + 1]).write_text(result)
                    return process
                with patch("harness.openai_invocation.canonical_environment", return_value={}), \
                     patch("harness.openai_invocation.subprocess.Popen", side_effect=start):
                    if result == '{"findings":[]}':
                        self.assertTrue(invoke_openai("review", load_registry().role("final_reviewer"),
                                                     schema, timeout=1).evidence["structured_result_present"])
                    else:
                        with self.assertRaises(InvocationFailure):
                            invoke_openai("review", load_registry().role("final_reviewer"),
                                          schema, timeout=1)

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_zero_exit_error_event_is_rejected_and_classified_for_bounded_resume(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        for message, category in [('stream disconnected: connection reset', 'TRANSIENT_TRANSPORT'),
                                  ('HTTP 401 unauthorized', 'AUTHENTICATION_FAILURE')]:
            stream = (b'{"type":"thread.started"}\n{"type":"turn.started"}\n' +
                      json.dumps({'type': 'error', 'message': message}).encode() + b'\n' +
                      b'{"type":"item.completed","item":{"type":"agent_message"}}\n' +
                      b'{"type":"turn.completed"}\n')
            process = Mock(pid=1234, returncode=0); process.communicate.return_value=(stream,b'')
            with self.subTest(category=category), \
                 patch('harness.openai_invocation.canonical_environment', return_value={}), \
                 patch('harness.openai_invocation.subprocess.Popen', return_value=process):
                with self.assertRaises(InvocationFailure) as caught:
                    invoke_openai('source', ModelSpec('openai','gpt-5.6-sol','high'), {}, timeout=1)
            self.assertEqual(caught.exception.category, category)
            self.assertTrue(caught.exception.evidence['terminal_observed'])
            self.assertEqual(caught.exception.evidence['exit_code'], 0)
            self.assertFalse(caught.exception.evidence.get('structured_result_present', False))

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_agent_message_cannot_invent_retryable_transport_failure(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        stream = (b'{"type":"thread.started"}\n{"type":"turn.started"}\n' +
                  json.dumps({'type':'item.completed','item':{'type':'agent_message',
                              'text':'connection reset 401 unauthorised'}}).encode()+b'\n')
        process=Mock(pid=1234,returncode=0);process.communicate.return_value=(stream,b'')
        with patch('harness.openai_invocation.canonical_environment',return_value={}), \
             patch('harness.openai_invocation.subprocess.Popen',return_value=process):
            with self.assertRaises(InvocationFailure) as caught:
                invoke_openai('source',ModelSpec('openai','gpt-5.6-sol','high'),{},timeout=1)
        self.assertEqual(caught.exception.category,'CLI_OR_CONFIG_FAILURE')

    def test_started_turn_without_terminal_is_unresolved_timeout(self):
        stream = b'{"type":"thread.started"}\n{"type":"turn.started"}\n'
        observed = _observed_events(stream)
        self.assertTrue(observed["turn_started_observed"])
        self.assertFalse(observed["terminal_observed"])
        self.assertEqual(_failure_category(b"", stream, timed_out=True),
                         "TURN_TIMEOUT_UNDIAGNOSED")
        with self.assertRaises(ValueError):
            parse_events(stream)

    def test_auth_refresh_error_is_classified_without_persisting_provider_text(self):
        stderr = b"HTTP 401 unauthorized during token refresh: sensitive-provider-text"
        self.assertEqual(_failure_category(stderr, b"", timed_out=False),
                         "AUTHENTICATION_FAILURE")
        markers = _failure_markers(stderr, b"")
        self.assertTrue(markers["http_401"])
        self.assertTrue(markers["auth_refresh_mentioned"])
        self.assertNotIn("sensitive-provider-text", json.dumps(markers))

    def test_event_parser_requires_terminal_completion_and_message(self):
        good = b'{"type":"thread.started"}\n{"type":"turn.started"}\n{"type":"item.completed","item":{"type":"agent_message"}}\n{"type":"turn.completed"}\n'
        self.assertTrue(parse_events(good)["terminal_completion"])
        for bad in (good.replace(b'turn.completed', b'turn.failed'), good[:40]):
            with self.assertRaises(ValueError):
                parse_events(bad)

    def test_large_bounded_event_stream_keeps_structured_completion(self):
        prefix = b'{"type":"thread.started"}\n{"type":"turn.started"}\n'
        message = b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
        event = b'{"type":"item.completed","item":{"type":"reasoning","text":"' + b'x' * 850_000 + b'"}}\n'
        complete = prefix + event + message + b'{"type":"turn.completed"}\n'
        self.assertGreater(len(complete), 4 * 128_000)
        self.assertTrue(parse_events(complete)["terminal_completion"])
        with self.assertRaisesRegex(ValueError, "exceeds bound"):
            parse_events(complete + b" " * MAX_EVENT_STREAM_BYTES)

    def test_environment_does_not_inherit_provider_routing(self):
        with canonical_fixture() as (binary, home):
            env = canonical_environment({"HTTP_PROXY":"http://proxy.invalid",
                                         "ANTHROPIC_BASE_URL":"https://bad.invalid",
                                         "OPENAI_BASE_URL":"https://bad.invalid"},
                                        binary=binary, codex_home=home)
            self.assertEqual(env["HTTP_PROXY"], "http://proxy.invalid")
            self.assertNotIn("ANTHROPIC_BASE_URL", env)
            self.assertNotIn("OPENAI_BASE_URL", env)

    def test_untrusted_ca_root_is_not_inherited(self):
        with canonical_fixture() as (binary, home):
            ca = home.parent / "attacker-ca.pem"
            ca.write_text("untrusted")
            env = canonical_environment({"SSL_CERT_FILE": str(ca)}, binary=binary, codex_home=home)
            self.assertNotIn("SSL_CERT_FILE", env)

    def test_canonical_metadata_fixture_preserves_fail_closed_checks(self):
        with canonical_fixture() as (binary, home):
            binary.chmod(0o777)
            with self.assertRaises(ValueError): canonical_environment({}, binary=binary, codex_home=home)
            binary.chmod(0o755)
            (home / 'auth.json').chmod(0o644)
            with self.assertRaises(ValueError): canonical_environment({}, binary=binary, codex_home=home)
            (home / 'auth.json').chmod(0o600)
            home.chmod(0o755)
            with self.assertRaises(ValueError): canonical_environment({}, binary=binary, codex_home=home)

    def test_ca_path_rejects_symlink_ancestor(self):
        from harness.openai_invocation import _trusted_ca_path
        with tempfile.TemporaryDirectory() as tmp:
            alias = Path(tmp) / "trusted"
            alias.symlink_to("/etc/ssl/certs", target_is_directory=True)
            self.assertFalse(_trusted_ca_path(alias / "ca-certificates.crt", directory=False))

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_model_identity_is_required(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        with self.assertRaises(ValueError):
            invoke_openai("x", ModelSpec("openai", "", "high"), {}, timeout=1)

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_process_exit_and_missing_result_never_pass(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        complete = (b'{"type":"thread.started"}\n{"type":"turn.started"}\n'
                    b'{"type":"item.completed","item":{"type":"agent_message"}}\n'
                    b'{"type":"turn.completed"}\n')
        for exit_code, stdout in ((1, b'{"type":"turn.failed"}\n'), (0, complete)):
            with self.subTest(exit_code=exit_code):
                process = Mock(pid=1234, returncode=exit_code)
                process.communicate.return_value = (stdout, b"")
                with patch("harness.openai_invocation.canonical_environment", return_value={}), \
                     patch("harness.openai_invocation.subprocess.Popen", return_value=process):
                    with self.assertRaises(InvocationFailure) as caught:
                        invoke_openai("review", ModelSpec("openai", "gpt-5.6-sol", "high"),
                                      {"type": "object"}, timeout=1)
                self.assertFalse(caught.exception.evidence.get("structured_result_present", False))

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_timeout_kills_process_group_and_retains_incomplete_events(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        process = Mock(pid=1234, returncode=-9)
        process.communicate.side_effect = [subprocess.TimeoutExpired("codex", 1),
            (b'{"type":"thread.started"}\n{"type":"turn.started"}\n', b"")]
        with patch("harness.openai_invocation.canonical_environment", return_value={}), \
             patch("harness.openai_invocation.subprocess.Popen", return_value=process), \
             patch("harness.openai_invocation.os.killpg") as killpg:
            with self.assertRaises(InvocationFailure) as caught:
                invoke_openai("review", ModelSpec("openai", "gpt-5.6-sol", "high"),
                              {"type": "object"}, timeout=1)
        killpg.assert_called_once()
        self.assertEqual(caught.exception.category, "TURN_TIMEOUT_UNDIAGNOSED")
        self.assertTrue(caught.exception.evidence["turn_started_observed"])
        self.assertFalse(caught.exception.evidence["terminal_observed"])

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_timeout_process_group_exit_race_is_classified(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        process = Mock(pid=1234, returncode=-9)
        process.communicate.side_effect = [subprocess.TimeoutExpired("codex", 1), (b"", b"")]
        with patch("harness.openai_invocation.canonical_environment", return_value={}), \
             patch("harness.openai_invocation.subprocess.Popen", return_value=process), \
             patch("harness.openai_invocation.os.killpg", side_effect=ProcessLookupError):
            with self.assertRaises(InvocationFailure) as caught:
                invoke_openai("review", ModelSpec("openai", "gpt-5.6-sol", "high"),
                              {"type": "object"}, timeout=1)
        self.assertEqual(caught.exception.category, "TURN_TIMEOUT_UNDIAGNOSED")

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args, **_kwargs: None)
    def test_broken_provider_pipe_is_classified_and_cleanup_attempted(self):
        from harness.openai_invocation import _invoke_openai_unmetered as invoke_openai
        process = Mock(pid=1234)
        process.communicate.side_effect = [BrokenPipeError(), (b"", b"")]
        with patch("harness.openai_invocation.canonical_environment", return_value={}), \
             patch("harness.openai_invocation.subprocess.Popen", return_value=process), \
             patch("harness.openai_invocation.os.killpg") as killpg:
            with self.assertRaises(InvocationFailure) as caught:
                invoke_openai("review", ModelSpec("openai", "gpt-5.6-sol", "high"),
                              {"type": "object"}, timeout=1)
        self.assertEqual(caught.exception.evidence["io_error_class"], "BrokenPipeError")
        killpg.assert_called_once()


if __name__ == "__main__":
    unittest.main()
