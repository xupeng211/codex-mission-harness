"""Offline Docker doubles for the Controller's single test PostgreSQL lifecycle."""
from __future__ import annotations

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

    def test_invalid_and_missing_service_policy_fail_before_project_execution(self):
        for value in ("postgres:15", "sha256:short", None):
            with self.assertRaises(ValueError):
                validate_policy({"image_id": IMAGE, "profiles": ["pr"], "postgres_image_id": value})
        with patch("harness.factory_container.subprocess.check_output", side_effect=[b"owned", b'{"cmh.validation.owner":"foreign"}']):
            with patch("harness.factory_container.subprocess.run") as run:
                self.assertEqual(remove_owned("owned", "this-task"), (False, None))
                run.assert_not_called()

