"""Offline, event-controlled public status snapshots of a delegated session."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from harness.appserver_process import AppServerProcess
from harness.factory import Factory, git
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.task_temp import TaskTemp


class ControlledRuntime(AcceptanceRuntime):
    """Fixture development only; the real supervisor owns an inert local child."""
    def __init__(self, phase="started", immediate=False):
        super().__init__()
        self.phase, self.immediate = phase, immediate
        self.reached, self.release = threading.Event(), threading.Event()
        self.owner = self.temp = None
        self._execution_id = "1" * 32

    def begin_execution(self, mission):
        return self.release

    def end_execution(self, execution):
        return True

    def pause(self, phase):
        if phase == self.phase:
            self.reached.set()
            if not self.release.wait(10):
                raise RuntimeError("fixture synchronization timed out")

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        if role != "implement":
            return super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        self.pause("before-allocation")
        self.temp = TaskTemp(str(cwd), "cmh_delegated_fixture", record=transcript.with_suffix(".temp.json"))
        if self.phase == "allocating":
            allocation = self.temp._record.read_bytes()
            self.temp._record.write_bytes(b"{")
            self.pause("allocating")
            self.temp._record.write_bytes(allocation)
        self.pause("allocated")
        self.owner = AppServerProcess({"worktree": str(cwd), "permission_profile": self.temp.identity["permission_profile"],
            "temporary_workspace": self.temp.identity, "operation": str(transcript),
            "context": {"mission_id": "active-temp", "runtime_execution": "1" * 32}},
            transcript.with_suffix(".process.jsonl"))
        self.owner.start([sys.executable, "-I", "-B", "-c", "import sys; sys.stdin.read()"], cwd=cwd,
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pause("started")
        # A correct fixture implementation avoids manufacturing a review finding.
        result = super().agent("rework", profile, cwd, payload, transcript, timeout, denied_roots)
        result["runtime_identity"]["native_runtime"] = {"temporary_workspace": self.temp.identity,
            "process_ownership": {"binding": self.owner.binding, "supervisor": self.owner.identity}}
        if self.immediate:
            self.cleanup()
            if self.phase == "cleanup-record":
                receipt = self.temp.cleanup_log.read_bytes()
                self.temp.cleanup_log.write_bytes(b"{")
                self.pause("cleanup-record")
                self.temp.cleanup_log.write_bytes(receipt)
            self.pause("cleaned")
        return result

    def cleanup(self):
        if self.temp is None:
            return None
        if self.owner is not None:
            self.temp._process_stop = self.owner.stop()
            self.owner.proc.stdin.close()
        self.pause("stopped")
        receipt = self.temp.close()
        allocation = self.temp._record
        return {**receipt, "allocation": {"path": str(allocation), "sha256": hashlib.sha256(allocation.read_bytes()).hexdigest()},
                "evidence": {"path": str(self.temp.cleanup_log), "sha256": hashlib.sha256(self.temp.cleanup_log.read_bytes()).hexdigest()}}

    def close_session(self):
        return self.cleanup()

    def cancel(self, execution=None):
        self.release.set()


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux process ownership required")
class ActiveTempStatusTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="cmh-active-status-")
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "score.py").write_text("def add(a, b):\n    return a+b\n")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-qm", "baseline")
        self.config = fixture_config()
        self.factory = Factory(self.root / "state", self.config, AcceptanceRuntime())
        self.addCleanup(self.factory.close)
        self.factory.submit({"version": 2, "mission_id": "active-temp", "repository": str(self.repo),
                             "objective": "Offline fixture average", "scope": ["score.py", "tests/test_score.py"]})

    def start(self, phase="started", immediate=False):
        self.runtime = ControlledRuntime(phase, immediate)
        self.result, self.errors = [], []
        def work():
            factory = Factory(self.factory.root, self.config, self.runtime)
            try:
                self.result.append(factory.run("active-temp"))
            except BaseException as error:
                self.errors.append(error)
            finally:
                factory.close()
        self.worker = threading.Thread(target=work)
        self.worker.start()
        self.addCleanup(self.finish)
        self.assertTrue(self.runtime.reached.wait(10), self.errors)

    def finish(self):
        self.runtime.release.set()
        self.worker.join(15)
        self.assertFalse(self.worker.is_alive(), "fixture worker did not exit")
        self.assertEqual(self.errors, [])
        self.assertFalse(self.runtime.temp.path.exists())
        if self.runtime.owner is not None:
            self.assertTrue(self.runtime.owner.stopped["confirmed"])

    def snapshot(self):
        return {table: [tuple(row) for row in self.factory.db.execute(f"SELECT * FROM {table}")]
                for table in ("missions", "operations", "events")}

    def report(self):
        before = self.snapshot()
        report = self.factory.report("active-temp")
        self.assertEqual(self.snapshot(), before, "public status must not write state or accounting")
        return report

    def assert_pending(self):
        report = self.report()
        self.assertNotEqual(report["DELIVERY_STATUS"], "UNKNOWN", report["BLOCKERS_REMAINING"])
        self.assertEqual(report["TEMPORARY_CLEANUP"]["status"], "PENDING")
        self.assertNotEqual(report["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
        self.assertEqual(report["TEST_RESULT"], "UNKNOWN")

    def test_running_developer_public_report_does_not_require_final_result(self):
        self.start()
        operation = self.factory.db.execute("SELECT * FROM operations WHERE stage='implement'").fetchone()
        self.assertEqual(operation["status"], "RUNNING")
        self.assertIsNone(operation["result"])
        self.assert_pending()

    def check_handoff(self, phase, immediate=False):
        self.start(phase, immediate)
        self.assert_pending()
        self.finish()
        self.assertEqual(self.report()["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")

    def test_in_progress_allocation_record_is_pending_not_pass(self):
        self.check_handoff("allocating")

    def test_in_progress_cleanup_record_is_pending_not_pass(self):
        self.check_handoff("cleanup-record", immediate=True)

    def test_startup_before_supervisor_is_pending_not_pass(self):
        self.check_handoff("allocated")

    def test_stopped_before_cleanup_is_pending_not_pass(self):
        self.check_handoff("stopped")

    def test_cleaned_before_result_settlement_is_pending_not_pass(self):
        self.check_handoff("cleaned", immediate=True)

    def test_completed_and_cleaned_report_is_verified(self):
        self.start()
        self.finish()
        report = self.report()
        self.assertEqual(report["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
        self.assertEqual(report["TEMPORARY_CLEANUP"]["status"], "VERIFIED")

    def test_cancelled_stopped_and_cleaned_report_keeps_cancelled(self):
        self.start()
        self.factory.cancel("active-temp")
        self.finish()
        report = self.report()
        self.assertEqual(report["DELIVERY_STATUS"], "CANCELLED")
        self.assertEqual(report["TEMPORARY_CLEANUP"]["status"], "VERIFIED")

    def test_finished_missing_or_damaged_evidence_still_blocks(self):
        self.start()
        self.finish()
        receipt = self.runtime.temp.cleanup_log
        original = receipt.read_bytes()
        receipt.unlink()
        self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
        receipt.write_bytes(original + b" ")
        self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
        receipt.write_bytes(original)
        envelope = Path(self.factory.db.execute("SELECT evidence FROM operations WHERE stage='implement'").fetchone()[0])
        envelope.unlink()
        self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")

    def test_running_binding_mismatch_is_not_hidden_by_live_lock(self):
        self.start()
        journal = self.runtime.owner.record
        original = journal.read_bytes()
        for field, value in (("operation", "/unrelated.raw"), ("context", {"mission_id": "foreign", "runtime_execution": "1" * 32}),
                             ("temporary_workspace", {**self.runtime.temp.identity, "inode": 0})):
            with self.subTest(field=field):
                rows = [json.loads(line) for line in original.splitlines()]
                for row in rows:
                    row["binding"][field] = value
                journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
                try:
                    self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
                finally:
                    journal.write_bytes(original)

    def test_stale_execution_and_controller_identity_do_not_allow_pending(self):
        self.start()
        event = self.factory.db.execute("SELECT sequence,payload,at FROM events WHERE kind='controller_execution'").fetchone()
        original = json.loads(event["payload"])
        for mode in ("new-execution", "reused-pid", "foreign-lock", "old-operation"):
            with self.subTest(mode=mode):
                payload = json.loads(event["payload"])
                at = event["at"]
                if mode == "new-execution":
                    payload["runtime_execution"] = "2" * 32
                elif mode == "reused-pid":
                    payload["controller"]["starttime"] = "0"
                elif mode == "foreign-lock":
                    payload["lock"]["inode"] = 0
                else:
                    at += 1000
                self.factory.db.execute("INSERT INTO events(mission,kind,payload,at) VALUES(?,?,?,?)",
                                        ("active-temp", "controller_execution", json.dumps(payload), at))
                self.factory.db.commit()
                try:
                    self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
                finally:
                    self.factory.db.execute("INSERT INTO events(mission,kind,payload,at) VALUES(?,?,?,?)",
                                            ("active-temp", "controller_execution", json.dumps(original), event["at"]))
                    self.factory.db.commit()

    def test_corrupt_active_records_are_not_treated_as_startup(self):
        self.start()
        for path in (self.runtime.temp._record, self.runtime.owner.record):
            original = path.read_bytes()
            for data in (b"{", b"{}\n"):
                with self.subTest(path=path.name, data=data):
                    path.write_bytes(data)
                    try:
                        self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
                    finally:
                        path.write_bytes(original)

    def test_final_envelope_and_unconfirmed_stop_are_not_deferred(self):
        self.start("stopped")
        operation = self.factory.db.execute("SELECT * FROM operations WHERE stage='implement'").fetchone()
        self.assertEqual(operation["status"], "COMPLETE")
        envelope = Path(operation["evidence"])
        original = envelope.read_bytes()
        envelope.chmod(0o600)
        envelope.write_bytes(original + b" ")
        try:
            self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
        finally:
            envelope.write_bytes(original)
            envelope.chmod(0o400)
        receipt = self.runtime.temp.cleanup_log
        receipt.write_text(json.dumps({"identity": self.runtime.temp.identity, "cleanup_confirmed": False}) + "\n")
        receipt.chmod(0o600)
        try:
            self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
        finally:
            receipt.unlink()
        journal = self.runtime.owner.record
        original = journal.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        rows[-1]["result"]["confirmed"] = False
        journal.write_text("".join(json.dumps(row) + "\n" for row in rows))
        try:
            self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")
        finally:
            journal.write_bytes(original)

    def test_status_cannot_promote_newer_terminal_row_using_older_cleanup_snapshot(self):
        self.start("before-allocation")
        verify = self.factory.verify_temporary_cleanup
        def finish_after_snapshot(*args, **kwargs):
            result = verify(*args, **kwargs)  # Actual verifier, before any allocation exists.
            self.finish()
            return result
        with patch.object(self.factory, "verify_temporary_cleanup", side_effect=finish_after_snapshot):
            report = self.factory.report("active-temp")
        self.assertNotEqual(report["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
        self.assertEqual(self.report()["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")

    def test_running_field_without_controller_lock_cannot_adopt_allocation(self):
        self.factory.prepare("active-temp")
        cwd = Path(self.factory.row("active-temp")["candidate"])
        root = self.factory.root / "evidence/active-temp"
        root.mkdir(parents=True, exist_ok=True)
        operation = "f" * 32
        temp = TaskTemp(str(cwd), "cmh_delegated_fixture", record=root / (operation + ".temp.json"))
        self.addCleanup(temp.close)
        self.factory.db.execute("INSERT INTO operations(id,mission,key,stage,lane,paid,identity,input,status,started) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", (operation, "active-temp", operation, "implement", "developer", 1, "{}", "{}", "RUNNING", 1))
        self.factory.db.commit()
        self.assertEqual(self.report()["DELIVERY_STATUS"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
