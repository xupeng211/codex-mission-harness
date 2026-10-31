"""Offline Docker doubles for the Controller's single test PostgreSQL lifecycle."""
from __future__ import annotations

import errno
import io
import json
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory_container import argv_for, validate_policy, remove_owned
from harness.factory_test_service import ProjectPostgres, ExecutionStopped


IMAGE = "sha256:" + "a" * 64


class BrokenDiagnosticLog(io.BytesIO):
    """Only the diagnostic sink fails; the Docker double still executes."""
    def __init__(self, *, command=None, flush=False, message="synthetic full log filesystem"):
        super().__init__()
        self.command, self.fail_flush, self.message = command, flush, message

    def write(self, value):
        if not self.fail_flush and (self.command is None or json.loads(value)["service_command"][0] == self.command):
            raise OSError(errno.ENOSPC, self.message)
        return super().write(value)

    def flush(self):
        if self.fail_flush:
            raise OSError(errno.ENOSPC, self.message)
        return super().flush()


class TestPostgresLifecycle(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root, self.log, self.cancel = Path(temporary.name), io.BytesIO(), threading.Event()
        self.target = {"head": "a" * 40, "mission_scope_sha256": "b" * 64, "base": "c" * 40}
        self.service = ProjectPostgres(IMAGE, "cmh-validate-" + "d" * 32 + "-postgres", self.root,
                                      self.target, "QA_TEST", self.cancel, time.monotonic() + 30, {}, self.log)
        self.calls, self.exists, self.labels = [], False, self.service.labels.copy()
        self.health = "ready"
        self.patcher = patch("harness.factory_test_service.subprocess.run", side_effect=self.command)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def command(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        code, out = 0, b""
        if "--detach" in argv:
            self.exists = True
            if self.health == "lost_start": raise OSError("OFFLINE lost response")
        elif "exec" in argv:
            if self.health == "cancel": self.cancel.set()
            code, out = (0, b"1\n") if self.health == "ready" else (1, b"")
        elif "inspect" in argv:
            value = ({"network": "none", "ports": {}, "mounts": [], "tmpfs": {}}
                     if any("HostConfig.NetworkMode" in a for a in argv) else self.labels)
            code, out = (0, json.dumps(value).encode()) if self.exists else (1, b"")
        elif "rm" in argv:
            self.exists = False
        elif "ps" in argv:
            out = self.service.name.encode() if self.exists else b""
        return subprocess.CompletedProcess(argv, code, out, b"")

    def test_service_and_validation_only_share_offline_loopback_and_task_credentials(self):
        self.service.start()
        start = self.calls[0][0]
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--user=postgres", "--pull=never", "--rm", "--entrypoint=/usr/bin/timeout"):
            self.assertIn(flag, start)
        self.assertNotIn("--publish", start)
        self.assertNotIn("--volume", start)
        self.assertNotIn("--mount", start)
        self.assertEqual(start.count("--tmpfs"), 3)
        self.assertIn("cmh.qa.head=" + self.target["head"], start)
        self.assertEqual(stat.S_IMODE(self.service.secret_file.stat().st_mode), 0o600)
        policy = {"image_id": IMAGE, "postgres_image_id": IMAGE, "profiles": ["pr"]}
        argv = self.service.validation_argv(argv_for(policy, self.root, "validation", "pr"))
        self.assertIn("--network=container:" + self.service.name, argv)
        self.assertIn("DB_USER=" + self.service.user, argv)
        self.assertIn("DB_NAME=football_db", argv)
        self.assertIn("DB_HOST=127.0.0.1", argv)
        self.assertNotIn(self.service.password, " ".join(argv))
        self.assertIn('exec /usr/bin/env -i DB_PASSWORD="$password" "$@"', " ".join(argv))
        self.assertNotIn(self.service.password.encode(), self.log.getvalue())
        self.assertEqual(self.service.evidence["target"], self.target)
        self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertFalse(self.service.secret_file.exists() or self.service.env_file.exists())

    def test_validation_rejected_before_readiness(self):
        with self.assertRaises(RuntimeError): self.service.validation_argv([])

    def test_cancel_during_readiness_stops_and_cleans(self):
        self.health = "cancel"
        with self.assertRaises(ExecutionStopped) as caught: self.service.start()
        self.assertEqual(caught.exception.outcome, "CANCELLED")
        self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])

    def test_readiness_timeout_stops_and_cleanup_still_works_after_deadline(self):
        self.health = "not_ready"
        clock = [0]
        self.service.deadline = 5
        original = self.command
        def delayed(argv, **kwargs):
            result = original(argv, **kwargs)
            if "exec" in argv: clock[0] = 10
            return result
        with patch("harness.factory_test_service.time.monotonic", side_effect=lambda: clock[0]), \
                patch("harness.factory_test_service.subprocess.run", side_effect=delayed), \
                patch.object(self.cancel, "wait", return_value=False):
            with self.assertRaises(ExecutionStopped) as caught: self.service.start()
            self.assertEqual(caught.exception.outcome, "TIMEOUT")
            self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])

    def test_lost_start_response_is_not_retried_and_owned_container_is_cleaned(self):
        self.health = "lost_start"
        with self.assertRaises(OSError): self.service.start()
        self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertEqual(sum("--detach" in args for args, _ in self.calls), 1)

    def test_foreign_container_is_never_removed(self):
        self.service.start()
        self.labels["cmh.qa.owner"] = "another-task"
        self.service.close()
        self.assertFalse(self.service.evidence["cleanup_confirmed"])
        self.assertFalse(any("rm" in args for args, _ in self.calls))

    def test_log_capture_failure_does_not_skip_resource_cleanup(self):
        self.service.start()
        original = self.command
        def missing_logs(argv, **kwargs):
            if "logs" in argv: raise subprocess.TimeoutExpired(argv, 1)
            return original(argv, **kwargs)
        with patch("harness.factory_test_service.subprocess.run", side_effect=missing_logs):
            self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertEqual(self.service.evidence["logs_error_type"], "TimeoutExpired")

    def test_inspect_diagnostic_write_or_flush_failure_cannot_skip_owned_cleanup(self):
        for flush in (False, True):
            with self.subTest(flush=flush):
                self.service.log = io.BytesIO()
                self.service.cancel = threading.Event()
                self.service.start()
                self.calls.clear()
                self.service.log = BrokenDiagnosticLog(flush=flush)
                # Cleanup retains its separate bounded allowance after cancellation.
                self.service.cancel.set()
                self.service.close()
                self.assertEqual([args[1] for args, _ in self.calls], ["inspect", "logs", "rm", "ps"])
                self.assertTrue(all(kwargs["timeout"] == 15 for _, kwargs in self.calls))
                self.assertTrue(all(args[-1] == self.service.name for args, _ in self.calls[:3]))
                self.assertFalse(self.exists)
                self.assertTrue(self.service.evidence["cleanup_confirmed"])
                self.assertTrue(self.service.evidence["cleanup_ownership_confirmed"])
                self.assertTrue(self.service.evidence["cleanup_absence_confirmed"])
                self.assertFalse(self.service.evidence["diagnostics_complete"])
                failure = self.service.evidence["diagnostic_errors"][-4]
                self.assertEqual((failure["service_command"], failure["exit_code"], failure["errno"]),
                                 ("inspect", 0, errno.ENOSPC))
                self.assertFalse(self.service.secret_file.exists() or self.service.env_file.exists())

    def test_rm_diagnostic_failure_preserves_the_actual_removal_result(self):
        self.service.start()
        self.service.log = BrokenDiagnosticLog(command="rm")
        self.service.close()
        self.assertFalse(self.exists)
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertEqual(self.service.evidence["cleanup_exit_code"], 0)
        self.assertFalse(self.service.evidence["diagnostics_complete"])
        failure = self.service.evidence["diagnostic_errors"][0]
        self.assertEqual((failure["service_command"], failure["exit_code"]), ("rm", 0))

    def test_invalid_or_foreign_inspection_never_deletes_with_a_broken_sink(self):
        self.service.start()
        self.service.log = BrokenDiagnosticLog()
        cases = [("failed", 1, b""), ("broken", 0, b"{"), ("wrong type", 0, b"[]")]
        for label in self.labels:
            for missing in (False, True):
                actual = self.labels.copy()
                if missing: actual.pop(label)
                else: actual[label] = "another-task-or-target"
                cases.append((label + str(missing), 0, json.dumps(actual).encode()))
        for description, code, output in cases:
            with self.subTest(description=description):
                self.calls.clear()
                def inspect(argv, **kwargs):
                    if argv[1] == "inspect":
                        self.calls.append((argv, kwargs))
                        return subprocess.CompletedProcess(argv, code, output, b"")
                    return self.command(argv, **kwargs)
                with patch("harness.factory_test_service.subprocess.run", side_effect=inspect):
                    self.service.close()
                self.assertTrue(self.exists)
                self.assertFalse(any(args[1] == "rm" for args, _ in self.calls))
                self.assertFalse(self.service.evidence["cleanup_confirmed"])

    def test_inspect_exception_never_deletes_even_if_error_logging_fails(self):
        self.service.start()
        self.calls.clear()
        self.service.log = BrokenDiagnosticLog()
        with patch("harness.factory_test_service.subprocess.run", side_effect=subprocess.TimeoutExpired("inspect", 15)):
            self.service.close()
        self.assertTrue(self.exists)
        self.assertFalse(self.service.evidence["cleanup_confirmed"])
        self.assertEqual(self.service.evidence["cleanup_error_type"], "TimeoutExpired")
        self.assertEqual(self.service.evidence["diagnostic_errors"][0]["command_error_type"], "TimeoutExpired")

    def test_failed_or_unknown_rm_is_never_confirmed_even_if_container_disappeared(self):
        for lost_response, broken_sink in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(lost_response=lost_response, broken_sink=broken_sink):
                self.service.log = io.BytesIO()
                self.service.start()
                self.calls.clear()
                self.service.log = BrokenDiagnosticLog(command="rm") if broken_sink else io.BytesIO()
                def remove(argv, **kwargs):
                    if argv[1] == "rm":
                        self.calls.append((argv, kwargs))
                        self.exists = False  # Empty later ps cannot repair an unconfirmed rm response.
                        if lost_response: raise subprocess.TimeoutExpired(argv, 15)
                        return subprocess.CompletedProcess(argv, 9, b"", b"synthetic rm failure")
                    return self.command(argv, **kwargs)
                with patch("harness.factory_test_service.subprocess.run", side_effect=remove):
                    self.service.close()
                self.assertFalse(self.service.evidence["cleanup_confirmed"])
                self.assertEqual(sum(args[1] == "rm" for args, _ in self.calls), 1)
                if lost_response:
                    self.assertEqual(self.service.evidence["cleanup_error_type"], "TimeoutExpired")
                    if broken_sink:
                        self.assertEqual(self.service.evidence["diagnostic_errors"][-1]["command_error_type"], "TimeoutExpired")
                else:
                    self.assertEqual(self.service.evidence["cleanup_exit_code"], 9)
                    if broken_sink:
                        self.assertEqual(self.service.evidence["diagnostic_errors"][-1]["exit_code"], 9)

    def test_closed_diagnostic_stream_does_not_block_cleanup(self):
        self.service.start()
        self.log.close()
        self.service.close()
        self.assertFalse(self.exists)
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertFalse(self.service.evidence["diagnostics_complete"])
        self.assertEqual(self.service.evidence["diagnostic_errors"][0]["error_type"], "ValueError")

    def test_absence_query_must_succeed_and_be_empty_to_confirm_cleanup(self):
        for code, output in ((1, b""), (0, self.service.name.encode())):
            with self.subTest(code=code, output=output):
                self.service.start()
                def absence(argv, **kwargs):
                    if argv[1] == "ps": return subprocess.CompletedProcess(argv, code, output, b"")
                    return self.command(argv, **kwargs)
                with patch("harness.factory_test_service.subprocess.run", side_effect=absence):
                    self.service.close()
                self.assertFalse(self.service.evidence["cleanup_confirmed"])

    def test_command_failure_survives_a_second_failure_recording_its_error(self):
        self.service.log = BrokenDiagnosticLog()
        error = OSError(errno.EIO, "synthetic command failure")
        with patch("harness.factory_test_service.subprocess.run", side_effect=error):
            with self.assertRaises(OSError) as caught:
                self.service.command(["logs", self.service.name], cleanup=True)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.service.evidence["diagnostic_errors"][0]["command_error_type"], "OSError")

    def test_noncleanup_diagnostic_failure_remains_an_error(self):
        self.service.log = BrokenDiagnosticLog()
        with self.assertRaises(OSError): self.service.command(["logs", self.service.name])
        self.assertFalse(self.service.evidence["diagnostics_complete"])

    def test_repeated_close_checks_absence_without_repeating_removal_or_reusing_success(self):
        self.service.start()
        self.service.close()
        self.service.close()
        self.assertTrue(self.service.evidence["cleanup_confirmed"])
        self.assertEqual(sum(args[1] == "rm" for args, _ in self.calls), 1)
        with patch("harness.factory_test_service.subprocess.run", side_effect=OSError(errno.EIO, "offline query failed")):
            self.service.close()
        self.assertFalse(self.service.evidence["cleanup_confirmed"])

    def test_synthetic_password_is_redacted_from_output_and_diagnostic_error_metadata(self):
        password = self.service.password
        with patch("harness.factory_test_service.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0, password.encode(), password.encode())):
            self.service.command(["logs", self.service.name], cleanup=True)
            self.service.log = BrokenDiagnosticLog(message=password)
            self.service.command(["logs", self.service.name], cleanup=True)
        self.assertNotIn(password.encode(), self.log.getvalue())
        self.assertIn(b"[TEST_PASSWORD_REDACTED]", self.log.getvalue())
        self.assertNotIn(password, json.dumps(self.service.evidence))

    def test_invalid_and_missing_service_policy_fail_before_project_execution(self):
        for value in ("postgres:15", "sha256:short", None):
            with self.assertRaises(ValueError):
                validate_policy({"image_id": IMAGE, "profiles": ["pr"], "postgres_image_id": value})
        with patch("harness.factory_container.subprocess.check_output", side_effect=[b"owned", b'{"cmh.validation.owner":"foreign"}']):
            with patch("harness.factory_container.subprocess.run") as run:
                self.assertEqual(remove_owned("owned", "this-task"), (False, None))
                run.assert_not_called()
