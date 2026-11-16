"""Completed native rework survives Controller restart at checkpoint boundaries."""
from __future__ import annotations

import copy
import json
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

import test_factory as fixtures
from harness.factory import FactoryBlocked, READY, git


class ReworkResumeTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.FactoryAcceptanceTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        network = patch.object(socket.socket, "connect", side_effect=AssertionError("offline only"))
        network.start()
        self.addCleanup(network.stop)
        self.evidence = []

    def interrupt(self, qa_failed, timing):
        f = self.fx.factory
        original_gate, checkpoint = self.fx.runtime.gate, f.checkpoint

        def gate(command, cwd, target, transcript, timeout):
            if qa_failed and not f.row("feature")["round"]:
                transcript.write_text("score.py:8:12: RUF001 concrete initial QA failure\n")
                return {"status": "FAIL", "exit_code": 1}
            return original_gate(command, cwd, target, transcript, timeout)

        def interrupted(spec, cwd):
            complete = f.db.execute(
                "SELECT 1 FROM operations WHERE stage='rework' AND status='COMPLETE'").fetchone()
            if complete:
                if timing == "after-checkpoint":
                    checkpoint(spec, cwd)
                raise KeyboardInterrupt("Controller stopped after COMPLETE rework")
            return checkpoint(spec, cwd)

        with patch.object(self.fx.runtime, "gate", side_effect=gate), \
                patch.object(f, "checkpoint", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                f.run("feature")
        return f

    def rows(self, f):
        return [dict(row) for row in f.db.execute("SELECT * FROM operations ORDER BY started")]

    def test_four_completed_rework_restart_boundaries(self):
        # Same four scenarios as the independent review probe, with durable
        # row/original preservation and post-resume target assertions added.
        for qa_failed in (False, True):
            for timing in ("before-checkpoint", "after-checkpoint"):
                with self.subTest(qa_failed=qa_failed, timing=timing):
                    if self.evidence:
                        self.fx.doCleanups()
                        self.fx.setUp()
                    f = self.interrupt(qa_failed, timing)
                    before = self.rows(f)
                    rework = next(row for row in before if row["stage"] == "rework")
                    self.assertEqual(rework["status"], "COMPLETE")
                    original_input = json.loads(rework["input"])
                    previous = json.loads(f.db.execute(
                        "SELECT payload FROM events WHERE kind='rework' ORDER BY sequence DESC LIMIT 1"
                    ).fetchone()[0])
                    failed_head = previous["target"]["head"]
                    cwd = Path(f.row("feature")["candidate"])
                    head = git(cwd, "rev-parse", "HEAD")
                    dirty = git(cwd, "status", "--porcelain=v1", "-uall")
                    self.assertEqual(bool(dirty), timing == "before-checkpoint")
                    self.assertEqual(head == failed_head, timing == "before-checkpoint")
                    if qa_failed:
                        diagnostic = original_input["feedback"][0]["diagnostics"][0]
                        self.assertEqual(diagnostic["head"], failed_head)
                        self.assertIn("score.py:8:12: RUF001", diagnostic["log_tail"])
                    originals = {}
                    for row in before:
                        paths = [row["evidence"]] + [raw["path"] for raw in
                                 json.loads(row["result"]).get("raw_evidence", [])]
                        originals.update({p: Path(p).read_bytes() for p in paths})
                    # Actually close/reopen the SQLite Controller, not an
                    # in-process second call with hidden session state.
                    self.fx.reopen()
                    f = self.fx.factory
                    qa_targets = []
                    gate = self.fx.runtime.gate
                    def capture_gate(command, cwd, target, transcript, timeout):
                        qa_targets.append(copy.deepcopy(target))
                        return gate(command, cwd, target, transcript, timeout)
                    with patch.object(self.fx.runtime, "gate", side_effect=capture_gate):
                        report = f.run("feature")
                    self.assertEqual(report["DELIVERY_STATUS"], READY, report)
                    self.assertNotEqual(report["TARGET_HEAD"], failed_head)
                    after = self.rows(f)
                    after_by_id = {row["id"]: row for row in after}
                    for row in before:
                        self.assertEqual(after_by_id[row["id"]], row)
                    for path, raw in originals.items():
                        self.assertEqual(Path(path).read_bytes(), raw)
                    for stage in ("plan", "implement", "rework"):
                        self.assertEqual(sum(r["stage"] == stage for r in after), 1)
                    calls = self.fx.runtime.calls
                    self.assertTrue(calls)  # New candidate still needs review.
                    self.assertTrue(all(c["role"] == "review" for c in calls))
                    self.assertEqual(len(qa_targets), 2)  # checks and ci
                    for target in qa_targets + [c["payload"]["target"] for c in calls]:
                        self.assertEqual(target["head"], report["TARGET_HEAD"])
                    self.evidence.append({
                        "qa_failed": qa_failed, "interrupt": timing,
                        "dirty_on_resume": dirty, "failed_head": failed_head,
                        "head_on_resume": head, "final_head": report["TARGET_HEAD"],
                        "operations_before": before, "operations_after": after,
                        "rework_input": original_input, "new_runtime_calls": calls,
                        "qa_targets": qa_targets, "resume_status": report["DELIVERY_STATUS"],
                        "old_operations_and_originals_unchanged": True,
                    })

    def test_new_dispatch_still_requires_original_clean_failed_target(self):
        for checkpointed in (False, True):
            with self.subTest(checkpointed=checkpointed):
                if checkpointed:
                    self.fx.doCleanups()
                    self.fx.setUp()
                f = self.fx.factory
                agent = f.agent
                def stop(spec, cwd, stage, round_, payload):
                    if stage == "rework":
                        raise KeyboardInterrupt("before new rework")
                    return agent(spec, cwd, stage, round_, payload)
                with patch.object(f, "agent", side_effect=stop), self.assertRaises(KeyboardInterrupt):
                    f.run("feature")
                spec = json.loads(f.row("feature")["spec"])
                cwd = Path(f.row("feature")["candidate"])
                (cwd / "score.py").write_text((cwd / "score.py").read_text() + "\n# unexpected drift\n")
                if checkpointed:
                    f.checkpoint(spec, cwd)
                self.fx.reopen()
                report = self.fx.factory.run("feature")
                self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
                self.assertEqual(self.fx.runtime.calls, [])
                self.assertFalse(any(r["stage"] == "rework" for r in self.rows(self.fx.factory)))

    def test_completed_rework_cache_rejects_changed_round_profile_or_input(self):
        f = self.interrupt(False, "before-checkpoint")
        row = next(r for r in self.rows(f) if r["stage"] == "rework")
        spec = json.loads(f.row("feature")["spec"])
        cwd = Path(f.row("feature")["candidate"])
        payload = json.loads(row["input"])
        self.fx.reopen()
        f = self.fx.factory
        for mode in ("round", "profile", "input"):
            with self.subTest(mode=mode):
                modified = {**payload, "objective": "changed input"} if mode == "input" else payload
                with patch.dict(f.config["profiles"]["developer"],
                                {"model": "changed-profile"} if mode == "profile" else {}):
                    with self.assertRaises(FactoryBlocked):
                        f.agent(spec, cwd, "rework", 2 if mode == "round" else 1, modified)
        self.assertEqual(self.fx.runtime.calls, [])
        self.assertEqual(len(self.rows(f)), 7)

    def test_missing_or_corrupt_completed_rework_evidence_prevents_reuse(self):
        for mode in ("missing", "corrupt"):
            with self.subTest(mode=mode):
                if mode == "corrupt":
                    self.fx.doCleanups()
                    self.fx.setUp()
                f = self.interrupt(True, "after-checkpoint")
                row = next(r for r in self.rows(f) if r["stage"] == "rework")
                path = Path(row["evidence"])
                if mode == "missing":
                    path.unlink()
                else:
                    path.chmod(0o600)
                    path.write_text("corrupt synthetic rework evidence")
                self.fx.reopen()
                report = self.fx.factory.run("feature")
                self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
                self.assertEqual(self.fx.runtime.calls, [])

    def test_running_or_unknown_rework_is_not_replayed(self):
        for status in ("RUNNING", "UNKNOWN"):
            with self.subTest(status=status):
                if status == "UNKNOWN":
                    self.fx.doCleanups()
                    self.fx.setUp()
                f, runtime = self.fx.factory, self.fx.runtime
                agent = runtime.agent
                def uncertain(role, *args):
                    result = agent(role, *args)
                    if role == "rework":
                        if status == "RUNNING":
                            raise KeyboardInterrupt("lost rework response")
                        result["status"] = "UNKNOWN"
                    return result
                with patch.object(runtime, "agent", side_effect=uncertain):
                    if status == "RUNNING":
                        with self.assertRaises(KeyboardInterrupt):
                            f.run("feature")
                    else:
                        self.assertEqual(f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")
                row = next(r for r in self.rows(f) if r["stage"] == "rework")
                self.assertEqual(row["status"], status)
                self.fx.reopen()
                report = self.fx.factory.run("feature")
                self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN", report)
                self.assertEqual(self.fx.runtime.calls, [])
                self.assertEqual(next(r for r in self.rows(self.fx.factory)
                                      if r["stage"] == "rework"), row)
