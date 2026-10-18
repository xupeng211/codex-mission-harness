"""Exercise real CLI parsing/dispatch with synthetic Factory results, no inference."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import cli, factory_cli
from harness.factory_fixture import fixture_config


class FactoryCliExitTests(unittest.TestCase):
    def invoke(self, result, command="factory-run", public=False, run_error=None, close_error=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = fixture_config()
            config["simulation"] = False
            config_path = root / "operator.json"
            config_path.write_text(json.dumps(config))
            mission = root / "mission.json"
            mission.write_text(json.dumps({"mission_id": "cli-only"}))
            if command == "factory-run":
                args = [command, str(mission)]
            elif command == "submit":
                args = [command, "CLI contract test", "--repository", str(root)]
            else:
                args = [command, "cli-only"]
            args += ["--config", str(config_path), "--state-dir", str(root / "unused-state"), "--json"]
            output, errors = io.StringIO(), io.StringIO()
            with patch("harness.factory_cli.Factory") as constructor, \
                    patch("sys.stdout", output), patch("sys.stderr", errors):
                factory = constructor.return_value
                factory.submit.return_value = "cli-only"
                factory.run.return_value = result
                factory.report.return_value = result
                factory.run.side_effect = run_error
                factory.close.side_effect = close_error
                code = 0
                try:
                    if public:
                        with patch("sys.argv", ["harness", *args]):
                            cli.main()
                    else:
                        factory_cli.main(args)
                except SystemExit as exc:
                    code = exc.code
                factory.close.assert_called_once_with()
            self.assertFalse((root / "unused-state").exists(), "Factory must stay mocked")
            return code, output.getvalue(), errors.getvalue()

    def test_live_local_delivery_status_returns_zero_for_every_execution_entrypoint(self):
        # This is E2E_08's success contract, not a synthetic provider execution.
        report = {"DELIVERY_STATUS": "LOCAL_CANDIDATE_READY",
                  "LOCAL_CANDIDATE_READY": True, "SIMULATION": False}
        for command in ("submit", "factory-run", "factory-resume", "resume"):
            for public in (False, True):
                with self.subTest(command=command, public=public):
                    code, output, _ = self.invoke(report, command, public)
                    self.assertEqual(code, 0)
                    self.assertEqual(json.loads(output), report)

    def test_formal_delivery_success_still_returns_zero(self):
        report = {"DELIVERY_STATUS": "READY_FOR_USER_ACCEPTANCE", "SIMULATION": False}
        code, output, _ = self.invoke(report, public=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), report)

    def test_blocked_unknown_incomplete_and_missing_status_remain_nonzero(self):
        for status in ("UNKNOWN", "BLOCKED_BUDGET", "BLOCKED_SCOPE", "BLOCKED_LIMIT",
                       "CANCELLED", "RUNNING", "IMPLEMENT", "TEST", "OFFLINE_FIXTURE_PASS", None):
            report = {} if status is None else {"DELIVERY_STATUS": status}
            for command in ("submit", "factory-run", "factory-resume", "resume"):
                with self.subTest(status=status, command=command):
                    code, output, _ = self.invoke(report, command, public=True)
                    self.assertEqual(code, 1)
                    self.assertEqual(json.loads(output), report)

    def test_ready_boolean_cannot_hide_an_unknown_status(self):
        code, _, _ = self.invoke({"DELIVERY_STATUS": "UNKNOWN", "LOCAL_CANDIDATE_READY": True})
        self.assertEqual(code, 1)

    def test_runtime_error_is_not_hidden(self):
        code, output, errors = self.invoke({}, run_error=RuntimeError("execution failed"))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("execution failed", errors)

    def test_cleanup_error_after_success_is_not_hidden(self):
        code, output, errors = self.invoke({"DELIVERY_STATUS": "LOCAL_CANDIDATE_READY"},
                                           close_error=RuntimeError("cleanup failed"))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("cleanup failed", errors)

    def test_read_only_status_retains_zero_even_when_mission_is_unknown(self):
        code, output, _ = self.invoke({"DELIVERY_STATUS": "UNKNOWN"}, "factory-status", public=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["DELIVERY_STATUS"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
