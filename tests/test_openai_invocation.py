import json
import os
import tempfile
import unittest
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

from harness.model_registry import ModelSpec
from harness.openai_invocation import (InvocationFailure, _failure_category,
                                       _failure_markers, _observed_events,
                                       canonical_environment, parse_events)


class OpenAIInvocationTests(unittest.TestCase):
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

    def test_environment_does_not_inherit_provider_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"; home.mkdir(mode=0o700)
            (home / "auth.json").write_text("{}")
            (home / "auth.json").chmod(0o600)
            binary = Path("/usr/lib/chatgpt/resources/codex")
            env = canonical_environment({"HTTP_PROXY":"http://proxy.invalid",
                                         "ANTHROPIC_BASE_URL":"https://bad.invalid",
                                         "OPENAI_BASE_URL":"https://bad.invalid"},
                                        binary=binary, codex_home=home)
            self.assertEqual(env["HTTP_PROXY"], "http://proxy.invalid")
            self.assertNotIn("ANTHROPIC_BASE_URL", env)
            self.assertNotIn("OPENAI_BASE_URL", env)

    def test_model_identity_is_required(self):
        from harness.openai_invocation import invoke_openai
        with self.assertRaises(ValueError):
            invoke_openai("x", ModelSpec("openai", "", "high"), {}, timeout=1)

    def test_process_exit_and_missing_result_never_pass(self):
        from harness.openai_invocation import invoke_openai
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

    def test_timeout_kills_process_group_and_retains_incomplete_events(self):
        from harness.openai_invocation import invoke_openai
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


if __name__ == "__main__":
    unittest.main()
