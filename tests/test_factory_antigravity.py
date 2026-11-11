from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, git, READY
from harness.factory_fixture import fixture_config, AcceptanceRuntime
from harness.factory_runtime import LocalRuntime
from harness.factory_antigravity import identity, proxy_facts


class AntigravityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cli = self.root / "agy-offline"
        shutil.copyfile(Path(__file__).parent / "fixtures/antigravity_cli.py", self.cli)
        self.cli.chmod(0o700)
        self.mode = self.cli.with_suffix(".mode")
        self.mode.write_text("normal")
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "score.py").write_text("def score():\n    return 1\n")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "base")
        self.runtime = LocalRuntime()
        self.config = fixture_config()
        self.config["simulation"] = False
        self.config["profiles"]["second_reviewer"] = {"provider": "antigravity", "backend": "antigravity-cli",
            "model": "gemini-4-argon-medium", "effort": "medium", "cli_path": str(self.cli)}
        self.original_identity = self.runtime.profile_identity
        def profile_identity(profile):
            return identity(profile) if profile["provider"] == "antigravity" else {"offline": True}
        with patch.object(self.runtime, "profile_identity", side_effect=profile_identity):
            self.f = Factory(self.root / "state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.f.submit({"version": 2, "mission_id": "feature", "repository": str(self.repo), "objective": "Static offline review"})
        self.spec, self.cwd = self.f.prepare("feature")
        (self.cwd / "score.py").write_text("def score():\n    return 2\n")
        self.target = self.f.checkpoint(self.spec, self.cwd)

    def review(self):
        with patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
            return self.f.review(self.spec, self.cwd, self.target, "second_reviewer")

    def test_real_adapter_success_cache_version_and_private_evidence(self):
        result = self.review()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["provider"], "antigravity")
        self.assertNotIn("canonical_receipt", result)
        execution = result["canonical_execution"]
        stop = json.loads(Path(execution["review_lifecycle"]["path"]).read_text())
        self.assertEqual(stop["stop"]["proof"], "ECHILD")
        self.assertEqual(stop["exit_code"], 0)
        self.assertEqual(self.review(), result)
        self.assertEqual(len(self.cli.with_suffix(".calls").read_text().splitlines()), 1)
        packet = json.loads((Path(execution["workspace"]) / "review-input.json").read_text())
        self.assertNotIn("feedback", packet)
        self.assertNotIn("plan", packet)
        op = self.f.db.execute("SELECT * FROM operations").fetchone()
        self.f.verify_evidence(op)
        for item in json.loads(op["result"])["raw_evidence"]:
            self.assertEqual(Path(item["path"]).stat().st_mode & 0o077, 0)
        Path(execution["stdout_path"]).write_text("tamper")
        with self.assertRaises((ValueError, FactoryBlocked)):
            self.f.verify_evidence(op)

    def test_invalid_results_never_recover_retry_or_become_code_failure(self):
        for mode in ("error", "version", "incomplete", "invalid", "truncated", "repeated", "mutate"):
            with self.subTest(mode=mode):
                # Separate mission operations, each with exactly one logical start.
                name = "feature-" + mode
                self.f.submit({**self.spec, "mission_id": name})
                self.spec, self.cwd = self.f.prepare(name)
                (self.cwd / "score.py").write_text("def score():\n    return 3\n")
                self.target = self.f.checkpoint(self.spec, self.cwd)
                self.mode.write_text(mode)
                with self.assertRaises(FactoryBlocked): self.review()
                with self.assertRaises(FactoryBlocked): self.review()
                ops = self.f.db.execute("SELECT * FROM operations WHERE mission=?", (name,)).fetchall()
                self.assertEqual(len(ops), 1)
                self.assertEqual(ops[0]["status"], "UNKNOWN")
                paths = json.loads(ops[0]["result"])["raw_evidence"]
                diagnostic = next(Path(p["path"]) for p in paths if p["path"].endswith(".agy-diagnostics.json"))
                data = json.loads(diagnostic.read_text())
                if mode == "error":
                    self.assertEqual(data["status"], "ERROR")
                    self.assertEqual(data["visible_retry_events"][0]["wrapped_code"], 500)
                    self.assertEqual(data["visible_retry_events"][0]["http_status"], "UNKNOWN")
        self.assertEqual(len(self.cli.with_suffix(".calls").read_text().splitlines()), 7)

    def test_timeout_and_cancel_stop_descendants_and_classify(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                name = "cancel" if cancel else "timeout"
                self.f.submit({**self.spec, "mission_id": name})
                self.spec, self.cwd = self.f.prepare(name)
                (self.cwd / "score.py").write_text("def score():\n    return 3\n")
                self.target = self.f.checkpoint(self.spec, self.cwd)
                self.mode.write_text("sleep")
                original = self.runtime._supervised_review_step
                def step(*args, **kwargs):
                    return original(*args[:-1], .3 if not cancel else 5, **kwargs)
                if cancel:
                    def request_cancel():
                        time.sleep(.2)
                        self.runtime.container_cancel.set()
                    thread = threading.Thread(target=request_cancel)
                    thread.start()
                with patch.object(self.runtime, "_supervised_review_step", side_effect=step):
                    with self.assertRaises(FactoryBlocked): self.review()
                if cancel: thread.join()
                op = self.f.db.execute("SELECT * FROM operations WHERE mission=?", (name,)).fetchone()
                raw = Path(op["evidence"]).with_suffix(".review.stop.json")
                stop = json.loads(raw.read_text())
                self.assertEqual(stop["outcome"], "cancelled" if cancel else "timeout")
                self.assertEqual(stop["stop"]["proof"], "ECHILD")
                self.assertIsNone(self.runtime._review_owner)
                diagnostic = json.loads(raw.with_name(raw.name.replace(".review.stop.json", ".agy-diagnostics.json")).read_text())
                self.assertEqual(diagnostic["exit_class"], "CANCELLED" if cancel else "CONTROLLER_TIMEOUT")

    def test_complete_fail_enters_existing_rework_chain_with_all_priorities(self):
        fixture = AcceptanceRuntime()
        # Only developer/main review/gates are fixtures; second review executes
        # the actual LocalRuntime adapter and real subreaper with a mock binary.
        with patch.object(self.runtime, "agent", side_effect=fixture.agent), \
             patch.object(self.runtime, "gate", side_effect=fixture.gate), \
             patch("harness.factory_preflight.inspect_prepaid", return_value={"status": "PASS", "findings": []}):
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        events = [json.loads(row[0]) for row in self.f.db.execute("SELECT payload FROM events WHERE kind='rework'")]
        second = next(f for f in events[0]["feedback"] if f["department"] == "second_reviewer")
        self.assertEqual([f["priority"] for f in second["findings"]], [0, 1, 2, 3])
        rework = next(c for c in fixture.calls if c["role"] == "rework")
        self.assertIn("feedback", rework["payload"])

    def test_proxy_credentials_redacted(self):
        facts = json.dumps(proxy_facts({"HTTPS_PROXY": "http://user:secret@private.example:1234", "NO_PROXY": "localhost,.example.com"}))
        self.assertNotIn("secret", facts)
        self.assertNotIn("private.example", facts)
