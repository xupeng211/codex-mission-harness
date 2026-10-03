"""Offline crash and process restart probes for Reviewer V2 stage storage."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import review_resume

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deepseek_review as storage  # noqa: E402

STAGES = [(f"chunk-{n:03d}", "chunk") for n in range(5)] + [
    (f"group-{n:03d}", "group") for n in range(2)] + [
    ("cross-group", "cross-group"), ("final", "final")]


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.evidence = Path(self.temp.name) / "evidence"
        self.identity = {"provider": "fixture", "role": "test", "head_sha": "a" * 40,
                         "schema_manifest_hash": "b" * 64, "runner_hash": "c" * 64}
        self.counts = {name: 0 for name, _ in STAGES}

    def open(self, identity=None):
        return review_resume.ReviewRun(self.evidence, self.root, identity or self.identity,
                                       STAGES, storage, prefix="fixture-")

    def do_stage(self, run, index, *, fail=None):
        name, kind = STAGES[index]
        self.assertEqual(run.state["next_stage"], name)
        if kind == "group":
            self.assertEqual(len(run.state["completed_chunk_ids"]), 5)
        if kind == "cross-group":
            self.assertEqual(len(run.state["completed_group_ids"]), 2)
        if kind == "final":
            self.assertTrue(run.state["cross_group_completed"])
        def execute():
            self.counts[name] += 1
            if fail == "during_model":
                raise KeyboardInterrupt()
            return json.dumps({"stage": name}).encode()
        def validate(raw):
            value = json.loads(raw)
            self.assertEqual(value, {"stage": name})
            if fail == "after_model":
                raise KeyboardInterrupt()
            return value
        return run.stage(name, kind, name.encode(), execute, validate)

    def finish(self, run, start):
        for index in range(start, len(STAGES)):
            self.do_stage(run, index)
        path = run.receipt("receipt.json", b'{"result":"PASS"}', lambda: None)
        self.assertTrue(path.exists())
        self.assertEqual(len(list(run.path.glob("receipt.json"))), 1)
        return path

    def test_interruption_boundaries_a_through_i(self):
        # A, D, E, F, G, H and I: restart at each durable boundary.
        for boundary in (0, 1, 2, 5, 6, 7, 8, 9):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                old_evidence, old_counts = self.evidence, self.counts
                self.evidence = Path(tmp) / "evidence"
                self.counts = {name: 0 for name, _ in STAGES}
                first = self.open()
                for index in range(boundary):
                    self.do_stage(first, index)
                first.close()
                resumed = self.open()
                self.assertEqual(len(resumed.state["completed_order"]), boundary)
                self.finish(resumed, boundary)
                resumed.close()
                self.assertEqual(self.counts, {name: 1 for name, _ in STAGES})
                self.evidence, self.counts = old_evidence, old_counts

    def test_model_return_before_artifact_and_during_model_reexecute(self):
        for failure in ("during_model", "after_model"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                self.evidence = Path(tmp) / "evidence"
                self.counts = {name: 0 for name, _ in STAGES}
                run = self.open()
                with self.assertRaises(KeyboardInterrupt):
                    self.do_stage(run, 0, fail=failure)
                self.assertFalse((run.path / "chunk-000.json").exists())
                run.close()
                resumed = self.open()
                self.assertEqual(resumed.state["next_stage"], "chunk-000")
                self.finish(resumed, 0)
                resumed.close()
                self.assertEqual(self.counts["chunk-000"], 2)

    def test_artifact_before_state_commit_reexecutes_without_conflict(self):
        run = self.open()
        original = review_resume._atomic_state
        def crash(fd, state):
            if state["completed_order"]:
                raise KeyboardInterrupt()
            return original(fd, state)
        with patch.object(review_resume, "_atomic_state", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.do_stage(run, 0)
        self.assertTrue((run.path / "chunk-000.json").exists())
        run.close()
        resumed = self.open()
        self.assertEqual(resumed.state["next_stage"], "chunk-000")
        self.finish(resumed, 0)
        resumed.close()
        self.assertEqual(self.counts["chunk-000"], 2)
        self.assertEqual(len(list(self.evidence.rglob("chunk-000.json"))), 1)

    def test_source_binding_retry_keeps_chunks_once_then_stops(self):
        run = self.open()
        for index in range(5):
            self.do_stage(run, index)
        original = run.path
        first = json.loads(run.failure({"failure_category": "SCHEMA_VALIDATION_FAILED",
            "resume_allowed": True, "resume_policy_reason": "bounded source binding retry"}).read_text())
        self.assertTrue(first["resume_allowed"])
        self.assertEqual(first["next_stage"], "group-000")
        run.close()
        resumed = self.open()
        self.assertEqual(resumed.path, original)
        self.assertEqual(resumed.state["completed_chunk_ids"],
                         [f"chunk-{i:03d}" for i in range(5)])
        second = json.loads(resumed.failure({"failure_category": "SCHEMA_VALIDATION_FAILED",
            "resume_allowed": True, "resume_policy_reason": "bounded source binding retry"}).read_text())
        self.assertFalse(second["resume_allowed"])
        self.assertEqual(second["resume_policy_reason"], "bounded stage retry exhausted")
        resumed.close()
        fresh = self.open()
        self.assertNotEqual(fresh.path, original)
        self.assertEqual(fresh.state["next_stage"], "chunk-000")
        self.assertTrue(json.loads((original / "state.json").read_text())["invalidated"])
        fresh.close()

    def test_group_validation_failure_retains_exact_prompt_and_raw_response(self):
        run = self.open()
        for index in range(5):
            self.do_stage(run, index)
        with self.assertRaisesRegex(ValueError, "synthetic binding failure"):
            run.stage("group-000", "group", b"exact group prompt",
                      lambda: b'{"decisions":[{"source_quote":"exact model bytes"}]}',
                      lambda _raw: (_ for _ in ()).throw(ValueError("synthetic binding failure")))
        self.assertFalse((run.path / "group-000.json").exists())
        captures = list(run.path.glob("group-000-failed-raw-*.json"))
        self.assertEqual(len(captures), 1)
        record = json.loads(captures[0].read_bytes())
        self.assertEqual(record["prompt_utf8"], "exact group prompt")
        self.assertEqual(record["raw_model_output_utf8"],
                         '{"decisions":[{"source_quote":"exact model bytes"}]}')
        self.assertEqual(run.state["next_stage"], "group-000")
        run.close()
        resumed = self.open()
        self.assertEqual(len(resumed.state["diagnostic_artifacts"]), 1)
        resumed.close()

    def test_group_invocation_failure_marks_output_not_produced(self):
        run = self.open()
        for index in range(5):
            self.do_stage(run, index)
        def broken():
            run.capture_transport("group-000", b"exact prompt", b"partial stdout", b"cli error")
            raise RuntimeError("CLI failed")
        with self.assertRaisesRegex(RuntimeError, "CLI failed"):
            run.stage("group-000", "group", b"exact prompt", broken, lambda _: None)
        capture, = run.path.glob("group-000-failed-raw-*.json")
        record = json.loads(capture.read_bytes())
        self.assertEqual(record["raw_model_output_status"], "OUTPUT_NOT_PRODUCED")
        transport, = run.path.glob("group-000-transport-*.json")
        stream = json.loads(transport.read_bytes())
        self.assertEqual(stream["stdout_base64"], "cGFydGlhbCBzdGRvdXQ=")
        self.assertFalse((run.path / "receipt.json").exists())
        self.assertEqual(len(run.state["diagnostic_artifacts"]), 2)
        run.close()

    def test_cross_group_failure_append_only_and_private(self):
        run = self.open()
        for index in range(7):
            self.do_stage(run, index)
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "bad schema"):
                run.stage("cross-group", "cross-group", b"same prompt", lambda: b"{bad",
                          lambda _: (_ for _ in ()).throw(ValueError("bad schema")))
        captures = list(run.path.glob("cross-group-failed-raw-*.json"))
        self.assertEqual(len(captures), 2)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in captures))
        self.assertEqual(run.state["next_stage"], "cross-group")
        run.close()

    def test_identity_invalidation_and_artifact_tamper_fail_closed(self):
        for changed in ("head_sha", "schema_manifest_hash", "runner_hash"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                self.evidence = Path(tmp) / "evidence"
                run = self.open()
                self.do_stage(run, 0)
                old = run.path
                run.close()
                identity = dict(self.identity)
                identity[changed] = "d" * len(identity[changed])
                fresh = self.open(identity)
                self.assertNotEqual(fresh.path, old)
                self.assertEqual(fresh.state["next_stage"], "chunk-000")
                self.assertTrue(json.loads((old / "state.json").read_text())["invalidated"])
                fresh.close()
        self.evidence = Path(self.temp.name) / "tamper"
        run = self.open()
        self.do_stage(run, 0)
        path = run.path / "chunk-000.json"
        run.close()
        path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            self.open()

    def test_accounting_runtime_revision_invalidates_completed_chunk(self):
        old = self.open()
        self.do_stage(old, 0)
        old_path = old.path
        old.close()
        revised_identity = dict(self.identity, runner_hash="e" * 64,
                                invocation_hash="f" * 64)
        revised = self.open(revised_identity)
        self.assertNotEqual(revised.path, old_path)
        self.assertEqual(revised.state["completed_order"], [])
        self.assertEqual(revised.state["next_stage"], "chunk-000")
        revised.close()

    def test_concurrent_lease_and_stale_lease_recovery(self):
        run = self.open()
        with self.assertRaisesRegex(RuntimeError, "active review lease"):
            self.open()
        path = run.path
        run.close()
        replacement = self.open()
        self.assertEqual(replacement.path, path)
        self.assertEqual(replacement.state["lease"]["pid"], os.getpid())
        replacement.close()

    def test_five_chunk_sigterm_then_new_process_starts_chunk_three(self):
        script = Path(self.temp.name) / "worker.py"
        script.write_text('''import json, os, signal, sys
from pathlib import Path
from harness.review_resume import ReviewRun
import deepseek_review as storage
evidence, root, calls, stop = map(Path, sys.argv[1:5])
stages = [(f"chunk-{i:03d}", "chunk") for i in range(5)] + [(f"group-{i:03d}", "group") for i in range(2)] + [("cross-group", "cross-group"), ("final", "final")]
run = ReviewRun(evidence, root, {"head_sha":"a"*40}, stages, storage, prefix="fixture-")
for name, kind in stages:
  def invoke():
    with calls.open("a") as stream:
      stream.write(name + "\\n"); stream.flush(); os.fsync(stream.fileno())
    return json.dumps({"name": name}).encode()
  run.stage(name, kind, name.encode(), invoke, lambda raw: json.loads(raw))
  if stop.name == "yes" and name == "chunk-002": os.kill(os.getpid(), signal.SIGTERM)
run.receipt("receipt.json", b"{}", lambda: None)
run.close()
''')
        calls = Path(self.temp.name) / "calls"
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT / "scripts")}
        command = [sys.executable, str(script), str(self.evidence), str(self.root), str(calls)]
        first = subprocess.run(command + [str(Path(self.temp.name) / "yes")], env=env, check=False)
        self.assertEqual(first.returncode, -signal.SIGTERM)
        second = subprocess.run(command + [str(Path(self.temp.name) / "no")], env=env, check=False)
        self.assertEqual(second.returncode, 0)
        names = calls.read_text().splitlines()
        self.assertEqual(names, [name for name, _ in STAGES])
        self.assertEqual({name: names.count(name) for name, _ in STAGES[:5]},
                         {f"chunk-{n:03d}": 1 for n in range(5)})
        self.assertEqual(len(list(self.evidence.rglob("receipt.json"))), 1)


if __name__ == "__main__":
    unittest.main()
