import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.model_registry import ModelSpec
from harness.openai_invocation import InvocationFailure, canonical_environment, parse_events


class OpenAIInvocationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
