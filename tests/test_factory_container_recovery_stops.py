"""Real Factory recovery, local owned clients and files; no Docker or Provider.

Only Docker I/O and designated failure windows are substituted. Group stopping,
stop-evidence writing/reading and directory deletion use production code.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import patch

from harness.appserver_process import process_identity
from harness.factory import FactoryBlocked
from harness.factory_runtime import LocalRuntime
import harness.factory_container as container
import test_factory_container_lifecycle as lifecycle
import test_factory_controller_gates as fixtures


def save(name, value):
    root = os.environ.get("CMH_CONTAINER_RECOVERY_EVIDENCE")
    if root:
        (Path(root) / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")


class ControllerInterrupted(BaseException):
    pass


class RecoveryStopTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.FactoryLiveProtocolTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.f = self.fx.f
        self.spec, self.cwd = self.f.prepare("feature")
        self.target = self.f.target(self.spec, self.cwd)
        self.runtime = self.f.runtime = LocalRuntime()
        self.double = lifecycle.DockerDouble(self, self.runtime)
        self.addCleanup(self.double.close)
        self.control = self.double.real_popen([sys.executable, "-I", "-B", "-c", "import time;time.sleep(120)"],
                                             start_new_session=True)
        self.control_identity = process_identity(self.control.pid)
        self.addCleanup(self.stop_fixture, self.control, self.control_identity)
        marker = self.f.root / "unrelated-marker"
        marker.write_text("unrelated Controller resource must remain unchanged")
        info = marker.stat()
        self.addCleanup(self.check_marker, marker, (info.st_dev, info.st_ino), marker.read_bytes())

    def check_marker(self, path, identity, content):
        info = path.stat()
        self.assertEqual((info.st_dev, info.st_ino), identity)
        self.assertEqual(path.read_bytes(), content)

    def assert_same(self, proc, expected):
        actual = process_identity(proc.pid)
        self.assertEqual({k:v for k,v in actual.items() if k != "state"},
                         {k:v for k,v in expected.items() if k != "state"})
        self.assertNotIn(actual["state"], {"Z", "X"})
        return actual

    def stop_fixture(self, proc, identity):
        """Test teardown only, after checking product preservation; exact pidfd."""
        if proc.returncode is None:
            actual = process_identity(proc.pid)
            self.assertEqual({k:v for k,v in actual.items() if k != "state"},
                             {k:v for k,v in identity.items() if k != "state"})
            fd = os.pidfd_open(proc.pid)
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            finally:
                os.close(fd)
            proc.wait(timeout=2)
        self.assertFalse(Path("/proc", str(proc.pid)).exists())
        save("process-cleanup-" + str(proc.pid) + "-" + identity["starttime"],
             {"identity": identity, "returncode": proc.returncode, "absent": True,
              "phase": "test teardown AFTER product preservation checks; exact pidfd only"})

    def operation(self, key, state="COMPLETE", profile="targeted"):
        result = {}
        def invoke(transcript):
            result.update(self.runtime.container_gate(fixtures.CONTAINER, self.spec, self.cwd, self.target,
                          ["make", "verify-" + profile], transcript, 1.5))
            if state == "RUNNING":
                raise ControllerInterrupted()
            if state == "UNKNOWN":
                raise RuntimeError("controlled loss after gate return, before result settlement")
            return result
        try:
            self.f.operation("feature", key, "checks", "local", {"target": self.target},
                             {"target": self.target, "command": ["make", "verify-" + profile]}, False, invoke)
        except (ControllerInterrupted, FactoryBlocked):
            pass
        row = dict(self.f.db.execute("SELECT * FROM operations WHERE key=?", (key,)).fetchone())
        expected = "UNKNOWN" if state == "COMPLETE" and result.get("status") == "UNKNOWN" else state
        self.assertEqual(row["status"], expected, row)
        transcript = self.f.root / "evidence" / "feature" / (row["id"] + ".raw")
        return result, row, transcript

    def assert_unknown_without_replay(self, row, directory):
        self.f.runtime = LocalRuntime()  # No ownership from the original runtime survives.
        before = dict(row)
        raw = {p: p.read_bytes() for p in directory.parent.glob(row["id"] + ".*") if p.is_file()}
        launched = len(self.double.clients)
        self.double.calls.clear()
        with self.double.hooks(), \
                patch.object(self.f, "prepare", side_effect=AssertionError("no preparation replay")), \
                patch.object(self.f, "agent", side_effect=AssertionError("no model replay")), \
                patch.object(self.f.runtime, "container_gate", side_effect=AssertionError("no validation replay")), \
                patch.object(self.f.runtime, "project_remote", side_effect=AssertionError("no external replay")):
            cleanup = self.f.recover_interrupted_containers("feature")
            self.assertTrue(cleanup)
            self.assertTrue(all(v["cleanup_confirmed"] is False and v.get("status") == "UNKNOWN" for v in cleanup))
            for _ in range(2):
                self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")
                self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertTrue(directory.is_dir(), "product must preserve the resource BEFORE test teardown")
        self.assertEqual(launched, len(self.double.clients))
        self.assertNotIn("rm", [phase for phase, _ in self.double.calls])
        self.assertEqual(before, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()))
        for path, data in raw.items():
            self.assertEqual(path.read_bytes(), data)
        self.assert_same(self.control, self.control_identity)
        events = [json.loads(v[0]) for v in self.f.db.execute(
            "SELECT payload FROM events WHERE kind='container_cleanup_recovered'")]
        self.assertTrue(all(v["cleanup"]["cleanup_confirmed"] is False for v in events))
        return cleanup

    def live_client(self, phase, state="COMPLETE"):
        ready = self.f.root / (phase + "-" + state + ".ready")
        held = []
        original_popen = self.double.popen
        def launch(argv, *args, **kwargs):
            selected = ("clone" if "clone" in argv else
                        "query" if argv[:3] == ["/usr/bin/docker", "image", "inspect"] else
                        "postgres" if argv[:2] == ["/usr/bin/docker", "run"] and "--detach" in argv else
                        "validation" if argv[:2] == ["/usr/bin/docker", "run"] else
                        argv[1] if argv[0] == "/usr/bin/docker" else None)
            if selected != phase:
                return original_popen(argv, *args, **kwargs)
            code = ("import os,signal,sys,time;from pathlib import Path;"
                    "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                    "fd=os.open('.',os.O_RDONLY|os.O_DIRECTORY);Path(sys.argv[1]).write_text(str(fd));time.sleep(60)")
            proc = self.double.real_popen([sys.executable, "-I", "-B", "-c", code, str(ready)], *args, **kwargs)
            identity = process_identity(proc.pid)
            held.append((proc, identity))
            self.double.clients.append(proc)
            self.addCleanup(self.stop_fixture, proc, identity)
            return proc
        self.double.popen = launch
        real_signal = self.runtime._signal_owned_client
        def denied(client, sig):
            if held and client["process"] is held[0][0]:
                raise PermissionError("controlled exact-client stop failure")
            return real_signal(client, sig)
        with self.double.hooks(), patch.object(self.runtime, "_signal_owned_client", side_effect=denied):
            # Exercise the real query route too, not the double's image shortcut.
            with patch.object(container, "inspect_image", side_effect=lambda policy, *, client:
                              client(["/usr/bin/docker", "image", "inspect", policy["image_id"]], timeout=15)) \
                    if phase == "query" else patch.object(container, "inspect_image", return_value=fixtures.IMAGE):
                result, row, transcript = self.operation(phase + state, state,
                                                        "pr" if phase == "postgres" else "targeted")
        self.assertEqual(len(held), 1, result)
        self.assertTrue(ready.exists())
        self.assertFalse(result["local_clients_stop_confirmed"])
        directory = Path(result["temporary_directory_identity"]["path"])
        before = self.assert_same(*held[0])
        cleanup = self.assert_unknown_without_replay(row, directory)
        after = self.assert_same(*held[0])
        self.assertIsNotNone(self.runtime._preparation_client)
        save(phase + "-" + state, {"before": before, "after": after, "directory": str(directory),
             "result": result, "recovery": cleanup, "original_operation_unchanged": True,
             "teardown": "exact test-owned pidfd after product preservation assertions"})

    def test_live_copy_client_survives_unknown_recovery_in_each_operation_state(self):
        for state in ("RUNNING", "UNKNOWN", "COMPLETE"):
            with self.subTest(state=state):
                self.runtime = self.f.runtime = LocalRuntime()
                self.double.runtime = self.runtime
                self.live_client("cp", state)

    def test_live_clone_client_blocks_recovery(self): self.live_client("clone")
    def test_live_dependency_create_client_blocks_recovery(self): self.live_client("create")
    def test_live_image_query_client_blocks_recovery(self): self.live_client("query")
    def test_live_service_start_client_blocks_recovery(self): self.live_client("postgres")
    def test_live_main_validation_client_blocks_recovery(self): self.live_client("validation")

    def test_complete_stop_proof_allows_cleanup_only_in_each_operation_state(self):
        for state in ("RUNNING", "UNKNOWN", "COMPLETE"):
            with self.subTest(state=state):
                self.double.cleanup_blocked = True
                with self.double.hooks():
                    result, row, transcript = self.operation("safe-" + state, state)
                self.assertTrue(result["local_clients_stop_confirmed"], result)
                directory = Path(result["temporary_directory_identity"]["path"])
                record_path = transcript.with_suffix(".container.json")
                raw = record_path.read_bytes()
                proof_path = transcript.with_suffix(".container.clients.jsonl")
                proof_raw = proof_path.read_bytes()
                self.assertGreater(result["client_stop_evidence"]["clients"], 0)
                self.double.cleanup_blocked = False
                self.f.runtime = LocalRuntime()
                calls = len(self.double.clients)
                with self.double.hooks():
                    cleanups = self.f.recover_interrupted_containers("feature")
                recovered = next(v for v in cleanups if v.get("temporary_directory_identity") == result["temporary_directory_identity"])
                self.assertTrue(recovered["cleanup_confirmed"], recovered)
                self.assertTrue(recovered["local_clients_stop_confirmed"])
                self.assertFalse(recovered["operation_replayed"])
                self.assertFalse(directory.exists())
                self.assertEqual(proof_path.read_bytes(), proof_raw)
                self.assertEqual(record_path.read_bytes(), raw)
                self.assertEqual(len(self.double.clients), calls)
                self.assertEqual(row, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()))
                save("safe-" + state, {"result": result, "recovery": recovered, "operation_unchanged": True})

    def test_normal_cleanup_proof_is_rechecked_even_after_directory_is_gone(self):
        with self.double.hooks():
            result, row, transcript = self.operation("normal")
        self.assertEqual(result["status"], "PASS", result)
        self.assertTrue(result["local_clients_stop_confirmed"])
        self.assertTrue(result["temporary_directory_cleanup_confirmed"])
        self.f.runtime = LocalRuntime()
        for _ in range(2):
            self.f.verify_container_client_stops("feature")
            self.assertNotEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")
            with self.double.hooks():
                self.assertEqual(self.f.recover_interrupted_containers("feature"), [])
        transcript.with_suffix(".container.clients.jsonl").unlink()
        with self.double.hooks(), patch.object(self.f, "agent", side_effect=AssertionError("no replay")), \
                patch.object(self.f, "prepare", side_effect=AssertionError("no prepare")):
            self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")
            self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(row, dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone()))

    def test_invalid_missing_or_incomplete_proofs_cannot_clean_or_deliver(self):
        self.double.cleanup_blocked = True
        with self.double.hooks():
            result, row, transcript = self.operation("proof-cases")
        self.double.cleanup_blocked = False
        directory = Path(result["temporary_directory_identity"]["path"])
        path = transcript.with_suffix(".container.clients.jsonl")
        original = path.read_bytes()
        rows = [json.loads(line) for line in original.splitlines()]
        outcomes = {}
        for kind in ("missing", "corrupt", "hash", "task", "operation", "target", "directory", "lifecycle",
                     "unsealed", "unregistered", "unstopped", "earlier-unconfirmed", "identity", "unreaped",
                     "extra-after-seal", "truncated", "oversize", "symlink"):
            changed = copy.deepcopy(rows)
            if kind == "task": changed[0]["temporary_directory_identity"]["binding"]["mission_id"] = "other"
            if kind == "operation": changed[0]["operation"] = str(transcript.parent / "other.raw")
            if kind == "target": changed[0]["temporary_directory_identity"]["binding"]["target_sha256"] = "0" * 64
            if kind == "directory": changed[0]["temporary_directory_identity"]["inode"] += 1
            if kind == "lifecycle": changed[0]["lifecycle_sha256"] = "0" * 64
            if kind == "unregistered": del changed[2]
            if kind == "unstopped": del changed[3]
            if kind == "earlier-unconfirmed": changed[3]["confirmed"] = False
            if kind == "identity": changed[3]["identity"]["starttime"] = "0"
            if kind == "unreaped": changed[3]["leader_reaped"] = False
            prefix = b"".join((json.dumps(v, sort_keys=True) + "\n").encode() for v in changed[:-1])
            changed[-1]["sha256"] = hashlib.sha256(prefix).hexdigest()
            data = prefix + (json.dumps(changed[-1]) + "\n").encode()
            if kind == "hash": data = prefix + (json.dumps({**changed[-1], "sha256": "0" * 64}) + "\n").encode()
            if kind == "unsealed": data = prefix
            if kind == "corrupt": data = b"{\n"
            if kind == "extra-after-seal": data += b'{}\n'
            if kind == "truncated": data = data[:-1]
            if kind == "oversize": data += b" " * container.LIFECYCLE_LIMIT
            path.write_bytes(data)
            if kind == "missing": path.unlink()
            if kind == "symlink":
                own_copy = path.with_suffix(".own-copy")
                own_copy.write_bytes(original); path.unlink(); path.symlink_to(own_copy)
            try:
                with self.subTest(kind=kind), self.double.hooks():
                    # Direct recovery tests the proof parser independently of
                    # COMPLETE's additional immutable raw-hash rejection.
                    rejected = container.recover(fixtures.CONTAINER, self.spec, self.target,
                                                  ["make", "verify-targeted"], transcript)
                    self.assertEqual(rejected["status"], "UNKNOWN", rejected)
                    self.assertFalse(rejected["cleanup_confirmed"])
                    self.assertTrue(directory.is_dir())
                    outcomes[kind] = self.assert_unknown_without_replay(row, directory)
            finally:
                if path.is_symlink(): path.unlink()
                path.write_bytes(original)
        save("proof-rejections", outcomes)

    def test_launch_registration_and_stop_persistence_windows_remain_unknown(self):
        append = container._ClientStops._append
        for event in ("intent", "started", "stopped", "sealed"):
            with self.subTest(event=event):
                self.runtime = self.f.runtime = LocalRuntime()
                self.double.runtime = self.runtime
                fired = []
                def interrupted(journal, entry):
                    # For intent, persist it then interrupt Popen's registration
                    # window. For the others interrupt before their durable write.
                    if entry["event"] == event and not fired:
                        fired.append(True)
                        if event == "intent": append(journal, entry)
                        raise OSError("controlled journal persistence interruption")
                    return append(journal, entry)
                with self.double.hooks(), patch.object(container._ClientStops, "_append", interrupted):
                    result, row, transcript = self.operation("window-" + event)
                self.assertTrue(fired)
                self.assertFalse(result["local_clients_stop_confirmed"], result)
                directory = Path(result["temporary_directory_identity"]["path"])
                self.assert_unknown_without_replay(row, directory)


if __name__ == "__main__":
    unittest.main()
