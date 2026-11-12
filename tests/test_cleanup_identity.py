"""Real local file operations; Docker/RPC/Provider are never started."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

from harness.factory import Factory, git
from harness.factory_container import recover, resources_for, temporary_binding
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_runtime import LocalRuntime
from harness.task_temp import TaskTemp, TaskTempError, allocate_directory
import harness.task_temp as temporary


def save(name, value):
    destination = os.environ.get("CMH_CLEANUP_EVIDENCE")
    if destination:
        path = Path(destination)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        (path / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


def facts(path):
    info = path.lstat()
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino,
            "mode": oct(stat.S_IMODE(info.st_mode)), "uid": info.st_uid,
            "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in path.iterdir() if p.is_file() and not p.is_symlink()}}


class DirectoryIdentityTests(unittest.TestCase):
    def setUp(self):
        # TaskTemp allocates in /tmp; replacement injection needs same-filesystem rename.
        self.fixture = tempfile.TemporaryDirectory(prefix="cleanup-identity-", dir="/tmp")
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)

    def test_tasktemp_swap_at_atomic_claim_preserves_both_objects(self):
        resource = TaskTemp(str(self.root), "cmh_delegated_fixture", record=self.root / "task.temp.json")
        source, moved = resource.path, self.root / "original"
        (source / "marker").write_text("owned-original")
        before = facts(source)
        rename = temporary._rename_noreplace
        substituted = False
        def substitute(src_fd, src, dst_fd, dst):
            nonlocal substituted
            if src == source.name and not substituted:
                source.rename(moved)
                source.mkdir(mode=0o700)
                (source / "marker").write_text("replacement-must-survive")
                substituted = True
            return rename(src_fd, src, dst_fd, dst)
        try:
            with patch.object(temporary, "_rename_noreplace", side_effect=substitute):
                with self.assertRaises(TaskTempError):
                    resource.close()
            self.assertTrue(substituted)
            self.assertEqual((moved / "marker").read_text(), "owned-original")
            self.assertEqual((source / "marker").read_text(), "replacement-must-survive")
            receipt = json.loads(resource.cleanup_log.read_text())
            self.assertFalse(receipt["cleanup_confirmed"])
            save("tasktemp-claim-race", {"before": before, "original_after": facts(moved),
                 "replacement_after": facts(source), "receipt": receipt, "external_io": "none"})
        finally:
            if moved.exists():
                shutil.rmtree(source)  # Exact fixture replacement, never a product fallback.
                moved.rename(source)
            resource.close()

    def test_recreated_source_during_private_delete_is_preserved_and_unknown(self):
        resource = TaskTemp(str(self.root), "cmh_delegated_fixture")
        original = resource.path
        rmtree = shutil.rmtree
        def substitute(path, *args, **kwargs):
            if path == "object":
                original.mkdir(mode=0o700)
                (original / "marker").write_text("new-resource")
            return rmtree(path, *args, **kwargs)
        try:
            with patch.object(temporary.shutil, "rmtree", side_effect=substitute):
                with self.assertRaises(TaskTempError):
                    resource.close()
            self.assertEqual((original / "marker").read_text(), "new-resource")
        finally:
            rmtree(original)
            if resource._fd != -1:
                os.close(resource._fd)

    def test_unsupported_atomic_primitive_never_falls_back_to_path_delete(self):
        resource = TaskTemp(str(self.root), "cmh_delegated_fixture")
        try:
            with patch.object(temporary.sys, "platform", "unsupported"):
                with self.assertRaises(TaskTempError):
                    resource.close()
            self.assertTrue(resource.path.is_dir())
        finally:
            resource.close()

    def recovery_fixture(self, label):
        parent = self.root / label
        parent.mkdir(mode=0o700)
        transcript = parent / "operation.raw"
        spec = {"mission_id": "fixture-mission"}
        target = {"head": "b" * 40, "mission_scope_sha256": "c" * 64}
        policy = {"image_id": "sha256:" + "d" * 64, "profiles": ["targeted"]}
        name = "cmh-validate-" + "a" * 32
        path, fd, identity = allocate_directory(parent, "cmh-validation-", temporary_binding(spec, target, name, transcript))
        os.close(fd)  # Simulate Controller death: no live directory descriptor survives.
        (path / "marker").write_text("original")
        record = {"version": 3, "target_sha256": temporary_binding(spec, target, name, transcript)["target_sha256"],
                  "mission_id": spec["mission_id"], "policy": policy, "profile": "targeted",
                  "container_name": name, "resources": resources_for(name, spec, target, False),
                  "temporary_directory": str(path), "temporary_directory_identity": identity}
        return path, transcript, record, (policy, spec, target, ["make", "verify-targeted"], transcript)

    @staticmethod
    def write_record(transcript, record):
        path = transcript.with_suffix(".container.json")
        path.write_text(json.dumps(record)); path.chmod(0o600)
        if "temporary_directory_identity" in record:
            from test_factory_container_lifecycle import seal_no_clients
            seal_no_clients(transcript, record)

    def test_interrupted_container_recovers_only_original_allocation(self):
        path, transcript, record, args = self.recovery_fixture("normal")
        before = facts(path)
        self.write_record(transcript, record)
        with patch("harness.factory_container.remove_owned", return_value=(True, None)) as external:
            result = recover(*args)
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertFalse(result["operation_replayed"])
        self.assertFalse(path.exists())
        self.assertEqual(external.call_count, 2)
        save("container-original-recovery", {"before": before, "result": result,
             "external_io": "container absence/removal double only; no Docker; deletion is real product code"})

    def test_recovery_rejects_missing_legacy_symlink_and_mismatched_identity(self):
        for mode in ("legacy", "missing", "device", "operation", "nonce", "symlink", "replaced", "absent"):
            with self.subTest(mode=mode):
                path, transcript, record, args = self.recovery_fixture(mode)
                moved = path.parent / "held-original"
                if mode == "legacy":
                    record["version"] = 2; record.pop("temporary_directory_identity")
                elif mode == "missing":
                    record.pop("temporary_directory_identity")
                elif mode == "device":
                    record["temporary_directory_identity"]["device"] += 1
                elif mode == "operation":
                    record["temporary_directory_identity"]["binding"]["operation_id"] = "other-operation"
                elif mode == "nonce":
                    (path / ".cmh-allocation.json").write_text("{}")
                else:
                    path.rename(moved)
                    if mode == "symlink": path.symlink_to(moved, target_is_directory=True)
                    if mode == "replaced":
                        path.mkdir(mode=0o700); (path / "marker").write_text("replacement")
                self.write_record(transcript, record)
                with patch("harness.factory_container.remove_owned", return_value=(True, None)) as external:
                    result = recover(*args)
                self.assertFalse(result["cleanup_confirmed"], result)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertFalse(result["operation_replayed"])
                external.assert_not_called()
                if moved.exists(): self.assertEqual((moved / "marker").read_text(), "original")
                if mode == "replaced": self.assertEqual((path / "marker").read_text(), "replacement")
                save("container-reject-" + mode, {"result": result, "record": record,
                     "original_preserved": (moved if moved.exists() else path).exists()})

    def test_container_swap_after_validation_before_claim_preserves_both(self):
        path, transcript, record, args = self.recovery_fixture("race")
        self.write_record(transcript, record)
        moved = path.parent / "held-original"
        rename = temporary._rename_noreplace
        substituted = False
        def substitute(src_fd, src, dst_fd, dst):
            nonlocal substituted
            if src == path.name and not substituted:
                path.rename(moved); path.mkdir(mode=0o700)
                (path / "marker").write_text("replacement")
                substituted = True
            return rename(src_fd, src, dst_fd, dst)
        with patch("harness.factory_container.remove_owned", return_value=(True, None)), \
                patch.object(temporary, "_rename_noreplace", side_effect=substitute):
            result = recover(*args)
        self.assertTrue(substituted)
        self.assertFalse(result["cleanup_confirmed"])
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertEqual((path / "marker").read_text(), "replacement")
        self.assertEqual((moved / "marker").read_text(), "original")
        save("container-claim-race", {"result": result, "replacement_after": facts(path), "original_after": facts(moved)})

    def test_failed_claim_restore_preserves_captured_and_new_public_objects(self):
        path, transcript, record, args = self.recovery_fixture("restore-collision")
        self.write_record(transcript, record)
        moved = path.parent / "held-original"
        rename = temporary._rename_noreplace
        def substitute(src_fd, src, dst_fd, dst):
            if src == path.name:
                path.rename(moved); path.mkdir(mode=0o700)
                (path / "marker").write_text("captured-replacement")
                rename(src_fd, src, dst_fd, dst)
                path.mkdir(mode=0o700)
                (path / "marker").write_text("new-public-object")
                return
            return rename(src_fd, src, dst_fd, dst)
        with patch("harness.factory_container.remove_owned", return_value=(True, None)), \
                patch.object(temporary, "_rename_noreplace", side_effect=substitute):
            result = recover(*args)
        plan = json.loads(transcript.with_suffix(".container.claims.jsonl").read_text())
        retained = Path(plan["claim"]["path"]) / "object"
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["cleanup_confirmed"])
        self.assertIn(str(retained), result["error"])
        self.assertEqual((moved / "marker").read_text(), "original")
        self.assertEqual((retained / "marker").read_text(), "captured-replacement")
        self.assertEqual((path / "marker").read_text(), "new-public-object")
        save("container-claim-restore-collision", {"result": result, "plan": plan,
             "original_after": facts(moved), "captured_after": facts(retained), "public_after": facts(path)})


class ReceiptRuntime(AcceptanceRuntime):
    """Only TaskTemp/LocalRuntime cleanup is real; all development/review is fixture."""
    def __init__(self, mode="normal"):
        super().__init__(); self.holder = LocalRuntime(); self.temp = None; self.mode = mode
    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        if role == "implement" and self.temp is None or role == "rework" and self.mode == "immediate-each":
            self.temp = TaskTemp(str(cwd), "cmh_delegated_fixture_receipt", record=transcript.with_suffix(".temp.json"))
            self.holder._single_server = types.SimpleNamespace(proc=None, _task_temp=self.temp, close=self.close_temp)
        result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        if role in ("implement", "rework") and self.mode in ("immediate", "immediate-each"):
            self.holder.close_session()
        return result
    def close_temp(self):
        self.holder._single_server._task_temp_cleanup = self.temp.close()
    def close_session(self):
        result = self.holder.close_session()
        if result and self.mode == "foreign-journal":
            path = Path(result["evidence"]["path"])
            row = json.loads(path.read_text()); row["identity"]["path"] = "/tmp/foreign-task-fixture"
            path.write_text(json.dumps(row) + "\n")
            result["evidence"]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        return None if self.mode == "missing-event" else result


class CleanupReceiptTests(unittest.TestCase):
    def fixture(self, mode="normal"):
        fixture = tempfile.TemporaryDirectory(prefix="cleanup-receipt-")
        self.addCleanup(fixture.cleanup)
        root = Path(fixture.name); source = root / "source"; source.mkdir(mode=0o700)
        subprocess = __import__("subprocess")
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "score.py").write_text("def add(a,b):\n    return a+b\n")
        git(source, "add", "."); git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-qm", "base")
        runtime = ReceiptRuntime(mode); factory = Factory(root / "state", fixture_config(), runtime)
        self.addCleanup(factory.close)
        mission = factory.submit({"version": 2, "mission_id": "receipt-fixture", "repository": str(source),
                                  "objective": "Add average preserving fractions", "scope": ["score.py", "tests/test_score.py"]})
        return factory, runtime, mission

    def test_valid_final_and_immediate_receipts_allow_completion_and_reopen_without_replay(self):
        for mode in ("normal", "immediate"):
            with self.subTest(mode=mode):
                factory, runtime, mission = self.fixture(mode)
                self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
                before = list(runtime.calls)
                self.assertEqual(factory.report(mission)["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
                self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
                self.assertEqual(runtime.calls, before)
                reopened_runtime = ReceiptRuntime()
                reopened = Factory(factory.root, fixture_config(), reopened_runtime)
                try:
                    self.assertEqual(reopened.run(mission)["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
                    self.assertEqual(reopened_runtime.calls, [])
                finally: reopened.close()
                save("receipt-valid-" + mode, {"status": "READY_FOR_USER_ACCEPTANCE", "replay_calls": len(reopened_runtime.calls)})

    def test_deleted_changed_foreign_or_earlier_failed_receipt_blocks_report_and_resume(self):
        for mode in ("deleted", "changed", "foreign-mission", "foreign-directory", "earlier-failure"):
            with self.subTest(mode=mode):
                factory, runtime, mission = self.fixture()
                initial = factory.run(mission)
                self.assertEqual(initial["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
                event = json.loads(factory.db.execute("SELECT payload FROM events WHERE kind='agent_temporary_cleanup'").fetchone()[0])
                receipt = Path(event["evidence"]["path"])
                original_hash = hashlib.sha256(receipt.read_bytes()).hexdigest()
                if mode == "deleted": receipt.unlink()
                elif mode == "changed": receipt.write_text(receipt.read_text() + " ")
                elif mode == "foreign-mission":
                    factory.event(mission, "agent_temporary_cleanup", {**event, "mission_id": "other-mission"})
                elif mode == "foreign-directory":
                    factory.event(mission, "agent_temporary_cleanup", {**event, "identity": {**event["identity"], "path": "/tmp/other-task-fixture"}})
                else:
                    factory.event(mission, "agent_temporary_cleanup", {**event, "cleanup_confirmed": False})
                    factory.event(mission, "agent_temporary_cleanup", event)
                factory.db.commit()
                operations = [dict(v) for v in factory.db.execute("SELECT * FROM operations ORDER BY id")]
                before = list(runtime.calls)
                report = factory.report(mission)
                resumed = factory.run(mission)
                self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
                self.assertEqual(resumed["DELIVERY_STATUS"], "UNKNOWN", resumed)
                self.assertEqual(runtime.calls, before, "no development/review/external operation replay")
                self.assertEqual([dict(v) for v in factory.db.execute("SELECT * FROM operations ORDER BY id")], operations)
                reopened_runtime = ReceiptRuntime(); reopened = Factory(factory.root, fixture_config(), reopened_runtime)
                try:
                    self.assertEqual(reopened.report(mission)["DELIVERY_STATUS"], "UNKNOWN")
                    self.assertEqual(reopened.run(mission)["DELIVERY_STATUS"], "UNKNOWN")
                    self.assertEqual(reopened_runtime.calls, [])
                finally: reopened.close()
                save("receipt-reject-" + mode, {"initial": initial["DELIVERY_STATUS"], "receipt_sha256": original_hash,
                     "event": event, "report": report["DELIVERY_STATUS"], "resume": resumed["DELIVERY_STATUS"],
                     "blockers": resumed["BLOCKERS_REMAINING"], "operations_unchanged": True, "replay_calls": 0})

    def test_unbound_final_or_hash_matched_foreign_journal_cannot_complete(self):
        for mode in ("missing-event", "foreign-journal"):
            with self.subTest(mode=mode):
                factory, runtime, mission = self.fixture(mode)
                self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "UNKNOWN")
                before = list(runtime.calls)
                self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "UNKNOWN")
                self.assertEqual(runtime.calls, before)

    def test_earlier_allocation_cannot_be_hidden_by_later_successful_cleanup(self):
        factory, runtime, mission = self.fixture("immediate-each")
        self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "READY_FOR_USER_ACCEPTANCE")
        originals = []
        for row in factory.db.execute("SELECT result FROM operations ORDER BY started"):
            originals.extend(Path(v["path"]) for v in json.loads(row[0])["raw_evidence"]
                             if v["path"].endswith(".temp.cleanup.jsonl"))
        self.assertEqual(len(originals), 2)
        originals[0].unlink()
        self.assertTrue(originals[1].is_file())
        before = list(runtime.calls)
        with patch.object(runtime, "agent", side_effect=AssertionError("no replay")), \
                patch.object(runtime, "gate", side_effect=AssertionError("no validation replay")), \
                patch.object(runtime, "second_review", side_effect=AssertionError("no review replay")):
            self.assertEqual(factory.report(mission)["DELIVERY_STATUS"], "UNKNOWN")
            self.assertEqual(factory.run(mission)["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(runtime.calls, before)


if __name__ == "__main__":
    unittest.main()
