from __future__ import annotations

import tempfile
import unittest
import json
import hashlib
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from harness.adapters import (
    FootballPredictionAdapter, GateResult, ReviewFailureClassification, SimulatedAdapter,
)
from harness.cli import approval_head, build, load_spec, main as cli_main, reconcile_supplied_spec
from harness.codex import AppServerCodex, FixtureCodex, Turn
from harness.domain import InvalidTransition, MissionSpec, State
from harness.isolation import Worktree, WorktreeManager, compose_namespace, docker_env
from harness.journal import Journal
from harness.policy import Decision, decide, permitted
from harness.process import JobResult, ProcessSupervisor, proc_identity, proc_start_ticks
from harness.supervisor import Supervisor


class FakeCodex:
    def __init__(self, messages=None):
        self.thread = None
        self.turns = []
        self.messages = iter(messages or ["任务尚未完成。", "已完成。"])

    def start_or_resume(self, thread_id, cwd):
        self.thread = thread_id or "thread-1"
        return self.thread

    def turn(self, thread_id, prompt, cwd):
        value = next(self.messages, "已完成。")
        self.turns.append((thread_id, prompt, value))
        return Turn(thread_id, f"turn-{len(self.turns)}", value)


class HarnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.journal = Journal(root / "harness.sqlite")
        self.adapter = SimulatedAdapter()
        self.codex = FakeCodex()
        self.supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, root / "logs"), self.codex, self.adapter)
        self.spec = MissionSpec("safe-demo", "/safe/repo", "harmless fixture", adapter="simulation", merge_policy="auto")
        self.worktree = root / "safe-worktree"
        self.worktree.mkdir()
        self.supervisor.create(self.spec, str(self.worktree), "b" * 40, "harness/safe-demo")

    def tearDown(self):
        self.tmp.cleanup()

    def advance_to_test(self):
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)

    def drain(self):
        for _ in range(30):
            state = self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
            if state == State.PASS:
                return state
            for child in list(self.supervisor.process._children.values()):
                child.wait()
            self.supervisor.collect_jobs(self.spec.mission_id)
        self.fail("did not finish")

    def _review_fixture(self, reviewer="codex", head="b" * 40):
        adapter = FootballPredictionAdapter()
        worktree = Path(self.tmp.name) / "review-target"
        worktree.mkdir(exist_ok=True)
        evidence = adapter.review_evidence_dir(worktree, "mission", reviewer, head)
        for directory in reversed((evidence.parents[2], evidence.parents[1],
                                   evidence.parents[0], evidence)):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        receipt = evidence / "receipt.json"
        receipt.write_text("{}")
        stdout = Path(self.tmp.name) / "review.stdout"
        stdout.write_text(json.dumps({"review_receipt": str(receipt), "status": "PASS"}))
        return adapter, worktree, evidence, receipt, stdout

    def _deepseek_review_fixture(self):
        adapter, worktree, evidence_dir, receipt, stdout = self._review_fixture("deepseek")
        (worktree / "scope.json").write_text("{}")
        receipt.write_text(json.dumps({
            "receipt_version": "independent-review-receipt/v1",
            "base_sha": "a" * 40, "head_sha": "b" * 40, "mission_id": "mission",
            "diff_sha256": "c" * 64, "review_result": "PASS", "findings": [],
            "integrity": {"sha256": "d" * 64},
        }))
        return adapter, worktree, evidence_dir, receipt, stdout

    def _trusted_codex_policy_fixture(self, root: Path, codex_home: Path,
                                      codex_binary: str = "/usr/bin/python3") -> Path:
        trusted = root / "trusted-codex-policy"
        scripts = trusted / "scripts" / "devops"
        scripts.mkdir(parents=True, exist_ok=True)
        (scripts / "codex_reviewer_isolation.py").write_text(
            "from pathlib import Path\n"
            f"CANONICAL_HOME = Path({str(codex_home)!r})\n"
            "def canonical_reviewer_environment(source=None):\n"
            "    return {'CODEX_HOME': str(CANONICAL_HOME)}\n"
            f"def canonical_codex_binary(): return Path({codex_binary!r})\n",
            encoding="utf-8",
        )
        (scripts / "codex_review_contract.py").write_text(
            "REVIEW_MODEL_PINNED = 'gpt-5.6-sol'\n"
            "REVIEW_REASONING_EFFORT_PINNED = 'high'\n",
            encoding="utf-8",
        )
        return trusted

    @staticmethod
    def _write_private_review_log(path: Path, content: bytes | str) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        path.chmod(0o600)

    def _receiptless_codex_attempt(self, *, error: str, events: list[dict] | None,
                                   attempt_id: str = "a" * 32, stderr: str = ""):
        adapter, worktree, evidence, _, stdout = self._review_fixture()
        self._write_private_review_log(stdout, json.dumps({"status": "FAIL", "error": error}) + "\n")
        event_path = evidence / f"codex-review-output-{'b' * 12}-{attempt_id}.jsonl"
        if events is not None:
            self._write_private_review_log(
                event_path,
                "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            )
        process_stderr = Path(self.tmp.name) / f"{attempt_id}.stderr"
        self._write_private_review_log(process_stderr, stderr)
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_repo_from_origin", return_value="owner/project"), \
                patch.object(adapter, "_canonical_codex_reviewer_policy", return_value={
                    "codex_home": "/private/canonical-codex-reviewer",
                    "codex_binary": "/usr/lib/chatgpt/resources/codex",
                    "model": "gpt-5.6-sol", "reasoning_effort": "high",
                }):
            result = adapter.review_result(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence), attempt_id=attempt_id,
                terminal_status="EXITED", exit_code=1, stderr_path=str(process_stderr),
            )
        return result, event_path

    def _prepare_agent_preflight(self, adapter, worktree):
        with patch.object(adapter, "discover_pr", return_value=GateResult(
                "PASS", "fixture PR", data={"number": 2, "repo": "owner/repo",
                                            "head": "a" * 40, "base": "main",
                                            "base_sha": "c" * 40},
        )), patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "fixture PR body", data={"repo": "owner/repo",
                    "head": "a" * 40, "base": "main", "base_sha": "c" * 40,
                    "state": "OPEN", "body": "review context\n"},
        )):
            return adapter.prepare_gate(
                "agent-preflight", worktree=str(worktree), base="c" * 40,
                head="a" * 40, mission_id="safe-demo",
                scope_file=str(worktree / "scope.json"),
            )

    def _target_git_repo(self):
        adapter = FootballPredictionAdapter()
        repo = Path(self.tmp.name) / "target-policy-repo"
        repo.mkdir(exist_ok=True)
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Harness Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "harness-test@example.invalid"], cwd=repo, check=True)
        for relative in adapter.REVIEW_CONTRACT_PATHS:
            path = repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            content = "all:\n\t@true\n" if relative == "Makefile" else "# fixture\n"
            path.write_text(content)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "base policy"], cwd=repo, check=True)
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        return repo, base

    def test_review_context_uses_committed_scope_without_rewriting_candidate_worktree(self):
        repo = Path(self.tmp.name) / "review-context-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "harness@example.invalid"], check=True)
        scope = repo / "docs" / "agentic" / "mission.json"
        scope.parent.mkdir(parents=True)
        scope.write_text('{"forbidden_actions":["live"]}\n', encoding="utf-8")
        (repo / "source.py").write_text("candidate\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "exact review context"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        committed_scope = scope.read_bytes()
        scope.write_text('{"forbidden_actions":[]}\n', encoding="utf-8")

        adapter = FootballPredictionAdapter()
        context = adapter.review_context_worktree(str(repo), "mission", head)

        self.assertEqual(context.parent, repo.parent)
        self.assertEqual(context.joinpath("docs/agentic/mission.json").read_bytes(), committed_scope)
        self.assertEqual(scope.read_text(encoding="utf-8"), '{"forbidden_actions":[]}\n')
        self.assertEqual(adapter.review_scope_file(
            context, head, "docs/agentic/mission.json",
        ).read_bytes(), committed_scope)
        self.assertEqual(subprocess.check_output(
            ["git", "-C", str(context), "rev-parse", "HEAD"], text=True,
        ).strip(), head)
        self.assertTrue(subprocess.check_output(
            ["git", "-C", str(context), "worktree", "list", "--porcelain"], text=True,
        ).find(f"worktree {context}\nHEAD {head}\ndetached") >= 0)

    def test_review_scope_rejects_changes_to_committed_review_context(self):
        repo = Path(self.tmp.name) / "tampered-review-context-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "harness@example.invalid"], check=True)
        (repo / "scope.json").write_text("{}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "scope.json"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "scope"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        adapter = FootballPredictionAdapter()
        context = adapter.review_context_worktree(str(repo), "mission", head)
        (context / "scope.json").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "differs from the committed HEAD blob"):
            adapter.review_scope_file(context, head, "scope.json")

    def test_supervisor_launches_independent_review_from_exact_head_context(self):
        repo = Path(self.tmp.name) / "review-launch-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "harness@example.invalid"], check=True)
        (repo / "scope.json").write_text('{"forbidden_actions":["live"]}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "scope.json"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
        base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        (repo / "source.py").write_text("candidate\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "reviewed head"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

        spec = MissionSpec(
            "review-launch", str(repo), "test exact review context",
            required_gates=(), reviews=("codex",), mission_scope_file="scope.json",
        )
        journal = Journal(Path(self.tmp.name) / "review-launch.sqlite")
        journal.create(spec, worktree=str(repo), base_sha=base,
                       branch="harness/review-launch", origin_repo="fixture/repo")
        journal.update(spec.mission_id, current_head=head, current_state=State.REVIEW)
        process = ProcessSupervisor(journal, Path(self.tmp.name) / "review-launch-logs")
        adapter = FootballPredictionAdapter()
        supervisor = Supervisor(journal, process, self.codex, adapter)

        reviewer_environment = {"PATH": "/trusted/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}
        with patch.object(adapter, "review_argv", return_value=["canonical-review"]) as review_argv, \
                patch.object(adapter, "review_environment", return_value=reviewer_environment) as review_env, \
                patch.object(process, "start", return_value="review-job") as start:
            self.assertEqual(supervisor.step(spec.mission_id, spec), State.REVIEW)

        context = adapter.review_context_worktree(str(repo), spec.mission_id, head)
        self.assertEqual(start.call_args.args[2], ["canonical-review"])
        self.assertEqual(start.call_args.args[3], str(context))
        self.assertEqual(start.call_args.args[5], head)
        self.assertEqual(start.call_args.args[4], reviewer_environment)
        self.assertFalse(start.call_args.kwargs["inherit_environment"])
        review_env.assert_called_once_with("codex", worktree=str(context), base=base)
        self.assertEqual(review_argv.call_args.kwargs["worktree"], str(context))
        self.assertEqual(review_argv.call_args.kwargs["scope_file"], str(context / "scope.json"))
        self.assertRegex(review_argv.call_args.kwargs["attempt_id"], r"^[0-9a-f]{32}$")
        self.assertEqual((context / "scope.json").read_text(encoding="utf-8"), '{"forbidden_actions":["live"]}\n')

    def test_background_verify_continues_same_mission_without_duplicate(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        rows = self.journal.db.execute("SELECT job_id FROM jobs").fetchall()
        self.assertEqual(len(rows), 1)
        # Natural language says incomplete; supervisor polls its registered job instead of ending/restarting it.
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs").fetchone()[0], 1)
        self.assertEqual(self.drain(), State.PASS)
        self.assertEqual(self.codex.thread, "thread-1")

    def test_cli_style_supervision_waits_for_owned_gate_and_finishes(self):
        self.advance_to_test()
        self.assertEqual(self.supervisor.run_until_terminal(self.spec.mission_id, self.spec), State.PASS)
        self.assertFalse(self.journal.status(self.spec.mission_id).background_jobs)

    def test_pending_review_stays_pending_without_repair_turn(self):
        self.adapter.reviews = ["PENDING"]
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.REVIEW)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.REVIEW)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["pending_gate"], "review:codex")
        self.assertEqual(self.codex.turns, [])

    def test_async_review_findings_are_durable_input_to_repair_turn(self):
        head = "a" * 40
        findings = [{"severity": "P1", "title": "repair this", "evidence": "exact source evidence"}]
        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        scope_file = self.worktree / "scope.json"
        scope_file.write_text("{}")
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(spec.__dict__), current_head=head,
            current_state=State.REVIEW, pending_gate="review:codex",
        )
        stdout_path = Path(self.tmp.name) / "review.stdout"
        receipt_path = Path(self.tmp.name) / "review-receipt.json"
        receipt_path.write_text('{"review_result":"FAIL"}')
        stdout_path.write_text(json.dumps({"review_receipt": str(receipt_path)})); self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("review-job", self.spec.mission_id, "review:codex", "[]", head, "LOST",
             str(stdout_path), "", "2026-01-01T00:00:00+00:00"),
        )
        self.journal.db.commit()
        with patch.object(
                self.supervisor.process,
                "poll",
                side_effect=[[JobResult("review-job", "LOST", None, head)], []],
        ), \
                patch("harness.supervisor.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                patch.object(self.supervisor.adapter, "review_result", return_value=GateResult(
                    "FAIL", "canonical receipt reports findings", "/private/review.json",
                    {"findings": findings},
                )) as review_result:
            self.supervisor.reconcile(self.spec.mission_id)
            # A second controller/reconcile pass consumes no duplicate result
            # after the atomic review-job publication.
            self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(review_result.call_count, 1)
        self.assertEqual(
            self.journal.db.execute("SELECT state FROM jobs WHERE job_id=?", ("review-job",)).fetchone()[0],
            "CONSUMED",
        )
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.IMPLEMENT)
        resumed = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "resumed-review-logs"),
            self.codex, self.adapter,
        )
        self.assertEqual(resumed.step(self.spec.mission_id, spec), State.TEST)
        prompt = self.codex.turns[-1][1]
        self.assertIn("P1", prompt)
        self.assertIn("repair this", prompt)
        self.assertIn("exact source evidence", prompt)
        self.assertEqual(resumed._async_review_repair_context(self.spec.mission_id, "b" * 40), "")

    def test_dead_review_with_invalid_receipt_blocks_without_automatic_retry(self):
        head = "a" * 40
        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        (self.worktree / "scope.json").write_text("{}")
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(spec.__dict__), current_head=head,
            current_state=State.REVIEW, pending_gate="review:codex",
        )
        stdout_path = Path(self.tmp.name) / "incomplete-review.stdout"
        stdout_path.write_text("{}")
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("incomplete-review-job", self.spec.mission_id, "review:codex", "[]", head,
             "LOST", str(stdout_path), "", "2026-01-01T00:00:00+00:00"),
        )
        self.journal.db.commit()
        with patch.object(self.supervisor.process, "poll", return_value=[
                JobResult("incomplete-review-job", "LOST", None, head),
        ]), patch.object(self.supervisor.adapter, "review_result", return_value=GateResult(
                "BLOCKED_EXTERNAL", "receipt did not validate")):
            self.supervisor.reconcile(self.spec.mission_id)
        mission = self.journal.mission(self.spec.mission_id)
        self.assertEqual(mission["current_state"], State.BLOCKED_EXTERNAL)
        self.assertEqual(self.journal.db.execute(
            "SELECT state FROM jobs WHERE job_id='incomplete-review-job'").fetchone()[0],
            "CONSUMED")
        self.assertEqual(self.journal.db.execute(
            "SELECT count(*) FROM events WHERE mission_id=? AND kind='review_retry_required'",
            (self.spec.mission_id,)).fetchone()[0], 0)
        with patch.object(self.supervisor.process, "start") as duplicate_start:
            self.assertEqual(self.supervisor.step(self.spec.mission_id, spec), State.BLOCKED_EXTERNAL)
        duplicate_start.assert_not_called()

    def test_typed_review_failure_uses_two_bounded_retries_with_backoff(self):
        head = "a" * 40
        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        (self.worktree / "scope.json").write_text("{}")
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(spec.__dict__), current_head=head,
            current_state=State.REVIEW, pending_gate="review:codex",
        )

        def add_job(job_id):
            stderr = Path(self.tmp.name) / f"{job_id}.err"
            stderr.write_text("request timeout while reconnecting\n")
            self.journal.db.execute(
                "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,"
                "stdout_path,stderr_path,started_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (job_id, self.spec.mission_id, "review:codex", "[]", head,
                 "LOST", "", str(stderr), "2026-01-01T00:00:00+00:00"),
            )
            self.journal.db.commit()

        add_job("transport-review-1")
        with patch.object(self.supervisor.process, "poll", return_value=[
                JobResult("transport-review-1", "LOST", None, head),
        ]), patch.object(self.supervisor.adapter, "review_result", return_value=GateResult(
                "BLOCKED_EXTERNAL", "review capacity failure",
                failure_classification=ReviewFailureClassification.TRANSIENT_CAPACITY)):
            self.supervisor.reconcile(self.spec.mission_id)
        mission = self.journal.mission(self.spec.mission_id)
        self.assertEqual(mission["current_state"], State.REVIEW)
        self.assertIsNone(mission["pending_gate"])
        self.assertGreaterEqual(float(mission["review_retry_after"]), time.time() + 29)
        self.assertEqual(self.journal.db.execute(
            "SELECT count(*) FROM events WHERE mission_id=? AND kind='review_retry_required'",
            (self.spec.mission_id,),
        ).fetchone()[0], 1)

        # The persisted deadline prevents a hot-loop restart.
        with patch.object(self.supervisor.process, "start") as duplicate_start:
            self.assertEqual(self.supervisor.step(self.spec.mission_id, spec), State.REVIEW)
        duplicate_start.assert_not_called()
        with patch.object(self.supervisor.process, "start") as duplicate_start:
            self.assertEqual(
                self.supervisor.run_until_wait(self.spec.mission_id, spec, limit=2),
                State.REVIEW,
            )
        duplicate_start.assert_not_called()
        with patch("harness.supervisor.time.sleep") as wait:
            self.assertEqual(
                self.supervisor.run_until_terminal(self.spec.mission_id, spec,
                                                   limit=1, poll_interval=0.01),
                State.REVIEW,
            )
        wait.assert_called_once()

        # Consume retry two after its deadline, then prove the third failure
        # becomes terminal instead of creating a fourth invocation.
        self.journal.update(self.spec.mission_id, pending_gate="review:codex",
                            review_retry_after=time.time() - 1)
        add_job("transport-review-2")
        with patch.object(self.supervisor.process, "poll", return_value=[
                JobResult("transport-review-2", "LOST", None, head),
        ]), patch.object(self.supervisor.adapter, "review_result", return_value=GateResult(
                "BLOCKED_EXTERNAL", "review transport failed",
                failure_classification=ReviewFailureClassification.TRANSIENT_TRANSPORT)):
            self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_state"], State.REVIEW)
        self.assertGreaterEqual(float(self.journal.mission(self.spec.mission_id)["review_retry_after"]),
                                time.time() + 89)

        self.journal.update(self.spec.mission_id, pending_gate="review:codex",
                            review_retry_after=time.time() - 1)
        add_job("transport-review-3")
        with patch.object(self.supervisor.process, "poll", return_value=[
                JobResult("transport-review-3", "LOST", None, head),
        ]), patch.object(self.supervisor.adapter, "review_result", return_value=GateResult(
                "BLOCKED_EXTERNAL", "review transport failed",
                failure_classification=ReviewFailureClassification.TRANSIENT_CAPACITY)):
            self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_state"], State.BLOCKED_EXTERNAL)
        self.assertEqual(self.journal.db.execute(
            "SELECT count(*) FROM events WHERE mission_id=? AND kind='review_retry_required'",
            (self.spec.mission_id,),
        ).fetchone()[0], 2)

    def test_review_text_and_untyped_payload_cannot_trigger_transport_retry(self):
        terminal = JobResult("review-job", "EXITED", 1, "a" * 40)
        malformed = GateResult(
            "BLOCKED_EXTERNAL", "malformed response: request timeout while reconnecting",
            data={"retryable": True, "classification": "transport"},
        )
        self.assertFalse(Supervisor._review_retryable_failure(terminal, malformed))
        self.assertFalse(Supervisor._review_retryable_failure(
            JobResult("review-job", "RUNNING", None, "a" * 40),
            GateResult("BLOCKED_EXTERNAL",
                       failure_classification=ReviewFailureClassification.TRANSIENT_TRANSPORT),
        ))
        self.assertFalse(Supervisor._review_retryable_failure(
            terminal, GateResult("FAIL",
                                 failure_classification=ReviewFailureClassification.TRANSIENT_TRANSPORT),
        ))
        self.assertTrue(Supervisor._review_retryable_failure(
            terminal, GateResult(
                "BLOCKED_EXTERNAL", "trusted adapter classified timeout",
                failure_classification=ReviewFailureClassification.TRANSIENT_TRANSPORT,
            ),
        ))
        self.assertTrue(Supervisor._review_retryable_failure(
            terminal, GateResult(
                "BLOCKED_EXTERNAL", "trusted adapter classified capacity",
                failure_classification=ReviewFailureClassification.TRANSIENT_CAPACITY,
            ),
        ))

    def test_stale_terminal_review_job_is_consumed_once_after_head_change(self):
        old_head, current_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id, current_head=current_head, current_state=State.TEST,
            pending_gate=None,
        )
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,"
            "stdout_path,stderr_path,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("stale-review-job", self.spec.mission_id, "review:codex", "[]", old_head,
             "EXITED", "", "", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00"),
        )
        self.journal.db.commit()
        with patch.object(self.adapter, "exact_head", return_value=current_head):
            self.supervisor.reconcile(self.spec.mission_id)
            self.assertEqual(self.supervisor.process.poll(self.spec.mission_id), [])
            self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.db.execute(
            "SELECT state FROM jobs WHERE job_id='stale-review-job'",
        ).fetchone()
        self.assertEqual(row["state"], "CONSUMED")
        self.assertEqual(self.journal.db.execute(
            "SELECT count(*) FROM events WHERE mission_id=? AND kind='review_result_stale'",
            (self.spec.mission_id,),
        ).fetchone()[0], 1)

    def test_terminal_review_job_is_consumed_when_same_head_gate_is_no_longer_pending(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.TEST,
            pending_gate=None,
        )
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,"
            "stdout_path,stderr_path,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("superseded-review-job", self.spec.mission_id, "review:codex", "[]", head,
             "EXITED", "", "", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:01+00:00"),
        )
        self.journal.db.commit()
        with patch.object(self.adapter, "exact_head", return_value=head), \
                patch.object(self.adapter, "review_result", create=True) as review_result:
            self.supervisor.reconcile(self.spec.mission_id)
            self.assertEqual(self.supervisor.process.poll(self.spec.mission_id), [])
            self.supervisor.reconcile(self.spec.mission_id)
        review_result.assert_not_called()
        row = self.journal.db.execute(
            "SELECT state FROM jobs WHERE job_id='superseded-review-job'",
        ).fetchone()
        self.assertEqual(row["state"], "CONSUMED")
        self.assertEqual(self.journal.db.execute(
            "SELECT count(*) FROM events WHERE mission_id=? AND kind='review_result_stale'",
            (self.spec.mission_id,),
        ).fetchone()[0], 1)

    def test_pre_merge_ci_pending_is_waitable_and_does_not_merge(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=7, pr_repo="fixture/repo", pr_base_sha="b" * 40,
        )
        with patch.object(self.adapter, "ci", return_value=GateResult("PENDING", "required check queued")):
            state = self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(state, State.MERGE)
        self.assertEqual(row["pending_gate"], "pre-merge-ci")
        self.assertEqual(row["ci_state"], "PENDING")
        self.assertEqual(self.adapter.merged_heads, set())

    def test_recovered_merge_claim_resumes_polling_pre_merge_ci(self):
        head = "a" * 40
        old_pid = 99999999
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=7, pr_repo="fixture/repo", merge_claim_head=head,
            pr_base_sha="b" * 40, merge_claim_pr_number=7, merge_claim_pr_repo="fixture/repo",
            merge_claim_pr_base_sha="b" * 40,
            merge_claim_pid=old_pid, merge_claim_start_ticks="dead-owner",
            merge_invocation_started=0,
        )
        real_identity = self.journal._proc_identity

        def owner_identity(pid):
            if pid == old_pid:
                return "ABSENT", None
            return real_identity(pid)

        with patch.object(self.adapter, "ci", side_effect=[
                GateResult("PENDING", "required check queued"),
                GateResult("PASS", "required check passed"),
        ]) as ci, patch.object(self.journal, "_proc_identity", side_effect=owner_identity):
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
            row = self.journal.mission(self.spec.mission_id)
            self.assertEqual(row["merge_claim_head"], head)
            self.assertEqual(row["pending_gate"], "pre-merge-ci")
            # The same live lease polls again instead of treating itself as a
            # foreign ACTIVE owner and leaving this mission permanently stuck.
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(ci.call_count, 2)
        self.assertEqual(self.adapter.merged_heads, {head})
        self.assertEqual(self.adapter.merge_index, 1)

    def test_terminal_runner_rejects_nonpositive_or_nonfinite_poll_interval(self):
        for value in (0, -0.1, float("nan"), float("inf"), -float("inf"), True, "1"):
            with self.subTest(poll_interval=value), self.assertRaises(ValueError):
                self.supervisor.run_until_terminal(
                    self.spec.mission_id, self.spec, poll_interval=value,
                )

    def test_terminal_runner_polls_exact_head_ci_until_it_finishes(self):
        spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(spec.__dict__),
            current_head="a" * 40, current_state=State.CI,
        )
        with patch.object(self.adapter, "ci", side_effect=[
                GateResult("PENDING", "check queued"), GateResult("PASS", "checks pass"),
                GateResult("PASS", "pre-merge recheck pass")]) as check, \
                patch("harness.supervisor.time.sleep") as sleep:
            state = self.supervisor.run_until_terminal(self.spec.mission_id, spec, poll_interval=0.01)
        self.assertEqual(state, State.WAITING_APPROVAL)
        self.assertEqual(check.call_count, 3)
        sleep.assert_called_once_with(0.01)

    def test_terminal_runner_polls_production_gate_until_it_finishes(self):
        head, merge_sha = "a" * 40, "c" * 40

        class PendingProductionAdapter:
            def __init__(self):
                self.calls = 0

            def exact_head(self, worktree):
                return head

            def post_merge(self, *args):
                self.calls += 1
                if self.calls == 1:
                    return GateResult("PENDING", "Production Gate queued", data={"ci_status": "queued"})
                return GateResult("PASS", "Production Gate passed", data={
                    "ci_head_sha": merge_sha,
                    "main_sha": "d" * 40, "tree_sha": "e" * 40,
                })

        adapter = PendingProductionAdapter()
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "pending-production-logs"),
            self.codex, adapter,
        )
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.POST_MERGE,
            pr_number=7, pr_repo="fixture/repo", pr_base_sha="b" * 40, merge_sha=merge_sha,
        )
        with patch("harness.supervisor.time.sleep") as sleep:
            state = supervisor.run_until_terminal(self.spec.mission_id, self.spec, poll_interval=0.01)
        self.assertEqual(state, State.PASS)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["pending_gate"])
        self.assertEqual(adapter.calls, 2)
        sleep.assert_called_once_with(0.01)

    def test_supervisor_rejects_production_pass_not_bound_to_merge_sha(self):
        head, merge_sha = "a" * 40, "c" * 40

        class WrongSourceProductionAdapter(FootballPredictionAdapter):
            def exact_head(self, worktree):
                return head

            def post_merge(self, *args):
                return GateResult("PASS", "wrong source", data={
                    "ci_head_sha": "b" * 40, "main_sha": "d" * 40, "tree_sha": "e" * 40,
                })

        adapter = WrongSourceProductionAdapter()
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "wrong-production-source"),
            self.codex, adapter,
        )
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.POST_MERGE,
            pr_number=7, pr_repo="fixture/repo", merge_sha=merge_sha,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_codex_turn_claim_serializes_controllers_and_unknown_outcome_fails_closed(self):
        self.supervisor.step(self.spec.mission_id, self.spec)  # CREATED -> PREPARING
        self.supervisor.step(self.spec.mission_id, self.spec)  # PREPARING -> IMPLEMENT
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start), "CLAIMED")
        second = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "second-turn-logs"),
                            self.codex, self.adapter)
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.IMPLEMENT)
        self.assertEqual(self.codex.turns, [])
        self.journal.update(self.spec.mission_id, codex_turn_pid=99999999, codex_turn_start_ticks="gone")
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_completed_codex_turn_is_consumed_after_restart_without_replay(self):
        """A crash after turn completion cannot launch a duplicate writable turn."""
        self.supervisor.step(self.spec.mission_id, self.spec)  # CREATED -> PREPARING
        self.supervisor.step(self.spec.mission_id, self.spec)  # PREPARING -> IMPLEMENT
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(self.spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.complete_codex_turn(self.spec.mission_id, "turn-1", owner_pid, owner_start)

        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "turn-restart-logs"),
            self.codex,
            self.adapter,
        )
        self.assertEqual(replacement.step(self.spec.mission_id, self.spec), State.TEST)
        self.assertEqual(self.codex.turns, [])
        self.assertEqual(self.journal.mission(self.spec.mission_id)["codex_turn_state"], "CONSUMED")

    def test_completed_codex_turn_stale_marker_is_discarded_before_fresh_turn(self):
        """A durable completion for A cannot authorize B or permanently block B."""
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(self.spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.complete_codex_turn(self.spec.mission_id, "turn-1", owner_pid, owner_start)

        new_head = "b" * 40
        self.journal.reconcile_head(self.spec.mission_id, new_head)
        self.adapter.heads = [new_head]
        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "stale-turn-logs"),
            self.codex,
            self.adapter,
        )
        self.assertEqual(replacement.step(self.spec.mission_id, self.spec), State.IMPLEMENT)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["codex_turn_state"], "DISCARDED")
        self.assertEqual(row["codex_turn_source_head"], "a" * 40)
        self.assertEqual(row["current_head"], new_head)
        self.assertEqual(self.codex.turns, [])
        self.assertEqual(replacement.step(self.spec.mission_id, self.spec), State.TEST)
        self.assertEqual(len(self.codex.turns), 1)

    def test_corrupt_stale_codex_turn_remains_fail_closed(self):
        self.journal.update(
            self.spec.mission_id,
            current_head="a" * 40,
            current_state=State.IMPLEMENT,
            codex_turn_state="STALE",
            codex_turn_id=None,
            codex_turn_source_state=State.IMPLEMENT,
            codex_turn_source_head="b" * 40,
        )
        self.assertEqual(
            self.supervisor.step(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.codex.turns, [])

    def test_running_codex_turn_cannot_complete_after_source_head_changes(self):
        """Completion persistence is a CAS against the claimed source identity."""
        self.supervisor.step(self.spec.mission_id, self.spec)
        self.supervisor.step(self.spec.mission_id, self.spec)
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(self.spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.reconcile_head(self.spec.mission_id, "b" * 40)
        with self.assertRaisesRegex(RuntimeError, "completion persistence"):
            self.journal.complete_codex_turn(
                self.spec.mission_id, "turn-1", owner_pid, owner_start,
            )
        self.assertEqual(
            self.journal.claim_codex_turn(self.spec.mission_id, owner_pid, owner_start),
            "UNKNOWN",
        )

    def test_completed_production_turn_rechecks_dirty_checkpoint_after_restart(self):
        """Durable completion cannot bypass a post-reconcile worktree mutation."""
        repo = Path(self.tmp.name) / "completed-dirty-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

        class DirtyAfterReconcileAdapter(FootballPredictionAdapter):
            def exact_head(self, worktree):
                Path(worktree, "uncheckpointed.txt").write_text("late model edit\n")
                return head

        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        journal = Journal(Path(self.tmp.name) / "completed-dirty.sqlite")
        journal.create(spec, worktree=str(repo), base_sha="b" * 40,
                       branch="harness/completed-dirty", origin_repo="fixture/repo")
        journal.update(spec.mission_id, current_head=head, current_state=State.IMPLEMENT)
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(journal.claim_codex_turn(spec.mission_id, owner_pid, owner_start), "CLAIMED")
        journal.record_codex_thread(spec.mission_id, "thread-1", owner_pid, owner_start)
        journal.complete_codex_turn(spec.mission_id, "turn-1", owner_pid, owner_start)

        replacement = Supervisor(
            journal,
            ProcessSupervisor(journal, Path(self.tmp.name) / "completed-dirty-logs"),
            self.codex,
            DirtyAfterReconcileAdapter(),
        )
        self.assertEqual(replacement.step(spec.mission_id, spec), State.BLOCKED_EXTERNAL)
        self.assertEqual(self.codex.turns, [])
        self.assertEqual(journal.mission(spec.mission_id)["codex_turn_state"], "COMPLETED")

    def test_completed_production_turn_blocks_when_checkpoint_inspection_fails(self):
        """An unavailable Git checkpoint inspection is not treated as clean."""
        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        self.journal.db.execute(
            "UPDATE missions SET spec_json=?,current_head=?,current_state=? WHERE mission_id=?",
            (json.dumps(spec.__dict__), "a" * 40, State.IMPLEMENT, spec.mission_id),
        )
        self.journal.db.commit()
        owner_pid, owner_start = self.supervisor._merge_owner()
        self.assertEqual(
            self.journal.claim_codex_turn(spec.mission_id, owner_pid, owner_start),
            "CLAIMED",
        )
        self.journal.record_codex_thread(spec.mission_id, "thread-1", owner_pid, owner_start)
        self.journal.complete_codex_turn(spec.mission_id, "turn-1", owner_pid, owner_start)
        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "checkpoint-error-logs"),
            self.codex,
            FootballPredictionAdapter(),
        )
        with patch("harness.supervisor.subprocess.run", side_effect=OSError("git unavailable")):
            self.assertFalse(replacement._agent_turn(spec.mission_id, "resume", ()))
        self.assertEqual(self.journal.status(spec.mission_id).state, State.BLOCKED_EXTERNAL)
        self.assertEqual(self.codex.turns, [])

    def test_checkpoint_failure_cannot_block_a_concurrently_advanced_source(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id, current_head=old_head, current_state=State.IMPLEMENT,
        )
        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "checkpoint-race-logs"),
            self.codex,
            FootballPredictionAdapter(),
        )

        def advance_then_fail(*args, **kwargs):
            self.journal.update(
                self.spec.mission_id, current_head=new_head, current_state=State.REVIEW,
            )
            raise OSError("git unavailable after concurrent progress")

        with patch("harness.supervisor.subprocess.run", side_effect=advance_then_fail), \
                self.assertRaisesRegex(InvalidTransition, "stale transition"):
            replacement._codex_checkpoint_ready(
                self.spec.mission_id, str(self.worktree),
                expected_state=State.IMPLEMENT, expected_head=old_head,
            )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]), (State.REVIEW, new_head))

    def test_unknown_or_stale_codex_claim_cannot_clobber_concurrent_progress(self):
        old_head, new_head = "a" * 40, "b" * 40
        for claim_result in ("UNKNOWN", "STALE"):
            with self.subTest(claim_result=claim_result):
                self.journal.update(
                    self.spec.mission_id,
                    current_head=old_head,
                    current_state=State.IMPLEMENT,
                    terminal_state=None,
                )

                def advance_then_return(*args):
                    self.journal.update(
                        self.spec.mission_id,
                        current_head=new_head,
                        current_state=State.REVIEW,
                    )
                    return claim_result

                with patch.object(
                        self.journal, "claim_codex_turn", side_effect=advance_then_return), \
                        self.assertRaisesRegex(InvalidTransition, "stale"):
                    self.supervisor._agent_turn(self.spec.mission_id, "work", ())
                row = self.journal.mission(self.spec.mission_id)
                self.assertEqual(
                    (row["current_state"], row["current_head"]),
                    (State.REVIEW, new_head),
                )

    def test_codex_exception_cannot_block_a_concurrently_advanced_source(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id, current_head=old_head, current_state=State.IMPLEMENT,
        )

        class RacingCodex(FakeCodex):
            def turn(inner_self, thread_id, prompt, cwd):
                self.journal.update(
                    self.spec.mission_id,
                    current_head=new_head,
                    current_state=State.REVIEW,
                )
                raise RuntimeError("provider failed after concurrent progress")

        replacement = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "codex-race-logs"),
            RacingCodex(),
            self.adapter,
        )
        with self.assertRaisesRegex(InvalidTransition, "stale transition"):
            replacement._agent_turn(self.spec.mission_id, "work", ())
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]), (State.REVIEW, new_head))

    def test_noop_journal_paths_leave_sqlite_transaction_clean(self):
        """Lease-loss and zero-row invalidation paths must not poison the connection."""
        self.journal.invalidate_reviews(self.spec.mission_id, "a" * 40)
        with self.assertRaisesRegex(RuntimeError, "thread persistence"):
            self.journal.record_codex_thread(self.spec.mission_id, "thread", 99999999, "gone")
        with self.assertRaisesRegex(RuntimeError, "completion persistence"):
            self.journal.complete_codex_turn(self.spec.mission_id, "turn", 99999999, "gone")
        self.journal.fail_codex_turn(self.spec.mission_id, "stale owner", 99999999, "gone")
        self.journal.transition(self.spec.mission_id, State.PREPARING, "transaction paths recovered")

    def test_atomic_mission_creation_persists_isolation_metadata(self):
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["worktree"], str(self.worktree))
        self.assertEqual(row["base_sha"], "b" * 40)
        self.assertEqual(row["branch"], "harness/safe-demo")

    def test_codex_policy_boundary_disables_network_and_limits_writes(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = ("live_provider_request", "quota_consumption")
        adapter._policy_cwd = "/tmp/mission-worktree"
        adapter._permissions_profile = "cmh_delegated_test"
        params = adapter._policy_params("/tmp/mission-worktree")
        self.assertEqual(params["approvalPolicy"], "never")
        self.assertEqual(params["permissions"], "cmh_delegated_test")

    def test_codex_policy_baseline_is_not_optional(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._configured_forbidden_actions = adapter._effective_policy(())
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/tmp/mission-worktree"
        adapter._permissions_profile = "cmh_delegated_test"
        params = adapter._policy_params("/tmp/mission-worktree")
        self.assertEqual(params["approvalPolicy"], "never")
        self.assertEqual(params["permissions"], "cmh_delegated_test")

    def test_codex_policy_never_falls_back_to_caller_cwd(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = None
        with self.assertRaisesRegex(RuntimeError, "not bound"):
            adapter._policy_params("/caller-controlled")
        adapter._policy_cwd = "/mission-worktree"
        with self.assertRaisesRegex(RuntimeError, "differs"):
            adapter._policy_params("/caller-controlled")

    def test_thread_start_and_resume_use_bound_sandbox_and_exclude_auth_home(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/mission-worktree"
        adapter._permissions_profile = "cmh_delegated_test"
        expected_policy = {
            "cwd": "/mission-worktree",
            "model": "gpt-5.6-sol",
            "approvalPolicy": "never",
            "permissions": "cmh_delegated_test",
            "developerInstructions": adapter._authority_instructions("/mission-worktree"),
            "config": {
                "shell_environment_policy": {
                    "filters": {"CODEX_HOME": "exclude"},
                    "ignore_default_excludes": False,
                },
            },
        }
        with patch.object(
                adapter, "_request", return_value={
                    "thread": {"id": "thread-1"},
                    "activePermissionProfile": {"id": "cmh_delegated_test"},
                }) as request:
            self.assertEqual(adapter.start_or_resume(None, "/mission-worktree"), "thread-1")
            request.assert_called_once_with("thread/start", expected_policy)
        with patch.object(
                adapter, "_request", return_value={
                    "thread": {"id": "thread-1"},
                    "activePermissionProfile": {"id": "cmh_delegated_test"},
                }) as request:
            self.assertEqual(adapter.start_or_resume("thread-1", "/mission-worktree"), "thread-1")
            request.assert_called_once_with(
                "thread/resume", {"threadId": "thread-1", **expected_policy},
            )

    def test_thread_start_rejects_implicit_permission_profile_fallback(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/mission-worktree"
        adapter._permissions_profile = "cmh_delegated_expected"
        with patch.object(adapter, "_request", return_value={
                "thread": {"id": "thread-1"},
                "activePermissionProfile": {"id": ":workspace"},
        }), self.assertRaisesRegex(RuntimeError, "did not activate"):
            adapter.start_or_resume(None, "/mission-worktree")

    @unittest.skipUnless(
        shutil.which("codex") or Path("/usr/lib/chatgpt/resources/codex").is_file(),
        "Codex App Server is not installed",
    )
    def test_app_server_activates_auth_read_denial_before_any_turn(self):
        executable = shutil.which("codex") or "/usr/lib/chatgpt/resources/codex"
        with tempfile.TemporaryDirectory(prefix="cmh-app-server-profile-") as temp:
            root = Path(temp)
            codex_home = root / "codex.home"
            codex_home.mkdir(mode=0o700)
            worktree = root / "worktree"
            worktree.mkdir()
            subprocess.run(["git", "init", "-q", str(worktree)], check=True)
            with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}, clear=True), \
                 patch("harness.codex.require_builder_qualification"):
                adapter = AppServerCodex(executable=executable, worktree=str(worktree))
                try:
                    thread_id = adapter.start_or_resume(None, str(worktree))
                finally:
                    adapter.close()
        self.assertTrue(thread_id)

    def test_turn_start_keeps_the_bound_filesystem_permission_profile(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/mission-worktree"
        adapter._permissions_profile = "cmh_delegated_test"
        adapter.proc = type("Process", (), {"stdin": StringIO()})()
        with patch.object(adapter, "_request", return_value={"turn": {"id": "turn-1"}}) as request, \
                patch.object(adapter, "_turn_completed", return_value={
                    "items": [{"type": "agentMessage", "text": "done"}],
                }):
            turn = adapter.turn("thread-1", "prompt", "/mission-worktree")
        self.assertEqual(turn.text, "done")
        params = request.call_args.args[1]
        self.assertEqual(params["permissions"], "cmh_delegated_test")
        self.assertEqual(params["cwd"], "/mission-worktree")
        self.assertNotIn("runtimeWorkspaceRoots", params)
        self.assertNotIn("sandboxPolicy", params)

    @unittest.skipUnless(
        shutil.which("codex") or Path("/usr/lib/chatgpt/resources/codex").is_file(),
        "Codex CLI is not installed",
    )
    def test_codex_profile_denies_known_and_proc_recovered_auth_paths(self):
        executable = shutil.which("codex") or "/usr/lib/chatgpt/resources/codex"
        root = Path(self.tmp.name)
        codex_home = root / "codex.home"
        codex_home.mkdir(mode=0o700)
        marker = codex_home / "auth-fixture.txt"
        marker.write_text("fixture-only-credential-marker", encoding="utf-8")
        workspace = root / "sandbox-workspace"
        workspace.mkdir()
        profile = "cmh_delegated_adversarial"
        script = """import os,sys
expected=sys.argv[2]
paths=[sys.argv[1]]
open(os.path.join(sys.argv[3],'write-check.txt'),'w').write('workspace-write-ok')
parent=os.getppid()
home=''
for _ in range(24):
    try:
        raw=open(f'/proc/{parent}/environ','rb').read()
        env=dict(item.split(b'=',1) for item in raw.split(b'\\0') if b'=' in item)
        found=env.get(b'CODEX_HOME',b'').decode()
        if found:
            home=found
            break
        stat=open(f'/proc/{parent}/stat','r').read()
        fields=stat[stat.rfind(')')+2:].split()
        parent=int(fields[1])
        if parent <= 1:
            break
    except (OSError,ValueError,IndexError):
        break
if home == expected:
    paths.append(home+'/auth-fixture.txt')
for path in dict.fromkeys(paths):
    try:
        with open(path,'r') as stream:
            print('READ:'+stream.read())
        sys.exit(3)
    except OSError:
        pass
print('BLOCKED:'+('PROC' if home == expected else 'DIRECT_ONLY'))"""
        command = [
            executable, *AppServerCodex._permissions_profile_overrides(str(codex_home), profile),
            "-C", str(workspace), "sandbox", "--permission-profile", profile,
            "--", sys.executable, "-I", "-c", script, str(marker), str(codex_home),
            str(workspace),
        ]
        env = {
            "PATH": os.defpath, "HOME": "/nonexistent", "LANG": "C.UTF-8",
            "CODEX_HOME": str(codex_home),
        }
        completed = subprocess.run(command, env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(completed.stdout.strip(), {"BLOCKED:PROC", "BLOCKED:DIRECT_ONLY"})
        self.assertNotIn("fixture-only-credential-marker", completed.stdout + completed.stderr)
        self.assertEqual((workspace / "write-check.txt").read_text(), "workspace-write-ok")

    def test_codex_policy_is_constructor_bound_to_canonical_git_worktree(self):
        first = Path(self.tmp.name) / "first-policy-repo"
        second = Path(self.tmp.name) / "second-policy-repo"
        for repo in (first, second):
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
        process = type("Process", (), {
            "stdin": StringIO(), "stdout": StringIO(), "stderr": None,
            "poll": lambda self: 0,
        })()
        codex_home = Path(self.tmp.name) / "codex-home"
        codex_home.mkdir(mode=0o700)
        self.assertEqual(AppServerCodex._canonical_worktree(str(first)), str(first))
        with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}), \
                patch("harness.codex.require_builder_qualification"), \
                patch("harness.codex.subprocess.Popen", return_value=process) as launch, \
                patch.object(AppServerCodex, "_canonical_worktree", return_value=str(first)), \
                patch.object(AppServerCodex, "_request", return_value={}) as request:
            adapter = AppServerCodex(executable="/usr/bin/true", worktree=str(first))
        request.assert_called_once_with("initialize", {
            "clientInfo": {"name": "codex-mission-harness", "version": "0.1"},
            "capabilities": {"experimentalApi": True},
        })
        self.assertEqual(launch.call_args.args[0][1:5], [
            "-c", 'model="gpt-5.6-sol"', "-c", 'model_reasoning_effort="high"',
        ])
        launch_argv = launch.call_args.args[0]
        self.assertIn('-c', launch_argv)
        self.assertIn('default_permissions=":workspace"', launch_argv)
        self.assertIn(f'permissions.{adapter._permissions_profile}.extends=":workspace"', launch_argv)
        self.assertIn(
            f'permissions.{adapter._permissions_profile}.filesystem={{"{codex_home}" = "deny"}}',
            launch_argv,
        )
        self.assertIn(
            f"permissions.{adapter._permissions_profile}.network.enabled=false", launch_argv,
        )
        self.assertFalse((codex_home / "config.toml").exists())
        adapter.set_policy((), str(first))
        self.assertEqual(adapter._policy_cwd, str(first))
        with self.assertRaisesRegex(RuntimeError, "immutable"):
            adapter.set_policy((), str(second))
        with self.assertRaisesRegex(RuntimeError, "absolute canonical"):
            adapter.set_policy((), "relative/repo")
        adapter.close()

        unbound = AppServerCodex.__new__(AppServerCodex)
        unbound._configured_forbidden_actions = unbound._effective_policy(())
        with self.assertRaisesRegex(RuntimeError, "not constructor-bound"):
            unbound.set_policy((), str(first))

    def test_app_server_uses_explicit_environment_allowlist(self):
        first = Path(self.tmp.name) / "app-server-env-repo"
        subprocess.run(["git", "init", "-q", str(first)], check=True)
        codex_home = Path(self.tmp.name) / "codex-home"
        codex_home.mkdir(mode=0o700)
        attacker_bin = Path(self.tmp.name) / "attacker-bin"
        attacker_bin.mkdir(mode=0o700)
        hostile = {
            "PATH": str(attacker_bin),
            "HOME": str(Path.home()),
            "CODEX_HOME": str(codex_home),
            "OPENAI_API_KEY": "ambient-api-key-must-not-pass",
            "GH_TOKEN": "ambient-gh-token-must-not-pass",
            "SSH_AUTH_SOCK": "/tmp/ambient-agent.sock",
            "HTTPS_PROXY": "http://proxy.example.invalid:8080",
        }
        process = type("Process", (), {
            "stdin": StringIO(), "stdout": StringIO(), "stderr": None,
            "poll": lambda self: 0,
        })()
        with patch.dict(os.environ, hostile, clear=True), \
                patch("harness.codex.require_builder_qualification"), \
                patch("harness.codex.subprocess.Popen", return_value=process) as launch, \
                patch.object(AppServerCodex, "_canonical_worktree", return_value=str(first)), \
                patch.object(AppServerCodex, "_request", return_value={}):
            adapter = AppServerCodex(executable="/usr/bin/true", worktree=str(first))
        child_env = launch.call_args.kwargs["env"]
        self.assertEqual(child_env["CODEX_HOME"], str(codex_home))
        self.assertEqual(child_env["HOME"], "/nonexistent")
        self.assertEqual(child_env["HTTPS_PROXY"], hostile["HTTPS_PROXY"])
        for name in ("OPENAI_API_KEY", "GH_TOKEN", "SSH_AUTH_SOCK"):
            self.assertNotIn(name, child_env)
        self.assertNotIn(str(attacker_bin), child_env["PATH"])
        adapter.close()

    def test_codex_home_rejects_group_writable_directory_chain(self):
        codex_home = Path(self.tmp.name) / "group-writable-codex-home"
        codex_home.mkdir(mode=0o700)
        codex_home.chmod(0o770)
        with patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
            with self.assertRaisesRegex(RuntimeError, "owner-controlled"):
                AppServerCodex._codex_home()
        codex_home.chmod(0o700)
        parent = Path(self.tmp.name) / "group-writable-codex-parent"
        parent.mkdir(mode=0o770)
        parent.chmod(0o770)
        nested = parent / "home"
        nested.mkdir(mode=0o700)
        with patch.dict(os.environ, {"CODEX_HOME": str(nested)}):
            with self.assertRaisesRegex(RuntimeError, "owner-controlled"):
                AppServerCodex._codex_home()
        parent.chmod(0o700)

    def test_app_server_rejects_launcher_from_bound_worktree(self):
        repo = Path(self.tmp.name) / "launcher-repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        launcher = repo / "codex"
        launcher.write_text("#!/bin/sh\nexit 0\n")
        launcher.chmod(0o755)
        codex_home = Path(self.tmp.name) / "launcher-codex-home"
        codex_home.mkdir(mode=0o700)
        with patch("harness.codex.require_builder_qualification"), patch.dict(os.environ, {
                "PATH": f"{repo}:/usr/bin:/bin", "CODEX_HOME": str(codex_home),
        }, clear=True), self.assertRaisesRegex(
                RuntimeError, "inside the mission worktree"):
            AppServerCodex(worktree=str(repo))

    def test_app_server_executes_the_same_relative_launcher_it_validated(self):
        with tempfile.TemporaryDirectory(prefix="cmh-relative-launcher-", dir=Path.home()) as temp:
            root = Path(temp)
            controller = root / "controller"
            worktree = root / "worktree"
            trusted_launcher = controller / "bin" / "codex"
            candidate_launcher = worktree / "bin" / "codex"
            trusted_launcher.parent.mkdir(parents=True)
            worktree.mkdir()
            subprocess.run(["git", "init", "-q", str(worktree)], check=True)
            for launcher in (trusted_launcher, candidate_launcher):
                launcher.parent.mkdir(parents=True, exist_ok=True)
                launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                launcher.chmod(0o755)
            codex_home = root / "codex-home"
            codex_home.mkdir(mode=0o700)
            process = type("Process", (), {
                "stdin": StringIO(), "stdout": StringIO(), "stderr": None,
                "poll": lambda self: 0,
            })()
            previous_cwd = Path.cwd()
            os.chdir(controller)
            try:
                with patch("harness.codex.require_builder_qualification"), patch.dict(os.environ, {
                        "PATH": "/usr/bin:/bin", "CODEX_HOME": str(codex_home),
                        }, clear=True), \
                        patch("harness.codex.subprocess.Popen", return_value=process) as launch, \
                        patch.object(AppServerCodex, "_canonical_worktree", return_value=str(worktree)), \
                        patch.object(AppServerCodex, "_request", return_value={}):
                    adapter = AppServerCodex(executable="bin/codex", worktree=str(worktree))
            finally:
                os.chdir(previous_cwd)

            self.assertEqual(launch.call_args.args[0][0], str(trusted_launcher.resolve()))
            self.assertNotEqual(launch.call_args.args[0][0], str(candidate_launcher.resolve()))
            adapter.close()

    def test_codex_thread_receives_explicit_sensitive_action_boundary(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(("merge",))
        adapter._policy_cwd = "/mission-worktree"
        instructions = adapter._thread_policy_params(
            "/mission-worktree",
        )["developerInstructions"]
        self.assertIn("only source editing", instructions)
        for action in adapter._forbidden_actions:
            self.assertIn(action, instructions)
        self.assertIn("approval requests are always denied", instructions)

    def test_app_server_explicitly_rejects_sensitive_approval_requests(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = type("Process", (), {"stdin": StringIO()})()
        request = {
            "id": 41,
            "method": "item/commandExecution/requestApproval",
            "params": {"command": "git merge origin/main"},
        }
        self.assertTrue(adapter._reject_server_request(request))
        response = json.loads(adapter.proc.stdin.getvalue())
        self.assertEqual(response["id"], 41)
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("denied", response["error"]["message"])

    def test_production_build_injects_immutable_mission_codex_policy(self):
        denied = ("live_provider_request", "quota_consumption")
        fake = FakeCodex()
        with patch("harness.cli.AppServerCodex") as constructor, \
             self.assertRaisesRegex(ValueError, "builder qualification"):
            build(Path(self.tmp.name), "footballprediction", forbidden_actions=denied)
        constructor.assert_not_called()
        with patch("harness.cli.validate_builder_qualification"), \
             patch("harness.cli.AppServerCodex", return_value=fake) as constructor:
            supervisor = build(Path(self.tmp.name), "footballprediction",
                               forbidden_actions=denied)
        constructor.assert_called_once_with(forbidden_actions=denied,
                                            builder_qualification=None,
                                            builder_auth_key_file=None)
        self.assertIs(supervisor.codex, fake)

        with patch("harness.cli.validate_builder_qualification"), \
             patch("harness.cli.AppServerCodex", return_value=fake) as constructor:
            build(Path(self.tmp.name), "footballprediction", forbidden_actions=denied,
                  worktree="/validated/worktree")
        constructor.assert_called_once_with(
            forbidden_actions=denied, worktree="/validated/worktree",
            builder_qualification=None, builder_auth_key_file=None,
        )

        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._configured_forbidden_actions = denied
        adapter._forbidden_actions = denied
        adapter._policy_cwd = None
        with self.assertRaisesRegex(RuntimeError, "configured mission deny-list"):
            adapter.set_policy(("merge",), "/tmp/mission-worktree")

        unconfigured = AppServerCodex.__new__(AppServerCodex)
        with self.assertRaisesRegex(RuntimeError, "configured mission deny-list"):
            unconfigured.set_policy((), "/tmp/caller-worktree")

    def test_football_adapter_rejects_dirty_worktree_before_head_evidence(self):
        repo = Path(self.tmp.name) / "git-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        adapter = FootballPredictionAdapter()
        self.assertEqual(len(adapter.exact_head(str(repo))), 40)
        (repo / "tracked.txt").write_text("dirty\n")
        with self.assertRaisesRegex(RuntimeError, "clean committed worktree"):
            adapter.exact_head(str(repo))

    def test_git_fsmonitor_cannot_execute_during_exact_head_or_review_materialization(self):
        repo = Path(self.tmp.name) / "fsmonitor-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        marker = Path(self.tmp.name) / "fsmonitor-ran"
        hook = Path(self.tmp.name) / "fsmonitor.sh"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o700)
        subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True)
        adapter = FootballPredictionAdapter()
        head = adapter.exact_head(str(repo))
        with self.assertRaisesRegex(RuntimeError, "executable local Git configuration"):
            adapter.review_context_worktree(str(repo), "mission", head)
        self.assertFalse(marker.exists())

    def test_docker_namespace_is_unique_and_non_destructive(self):
        self.assertNotEqual(compose_namespace("same mission"), compose_namespace("same/mission"))
        self.assertTrue(docker_env("m1")["COMPOSE_PROJECT_NAME"].startswith("cmh-"))
        self.assertTrue(compose_namespace("任务-1").isascii())

    def test_mission_id_cannot_escape_worktree_root(self):
        with self.assertRaisesRegex(ValueError, "safe worktree identifier"):
            WorktreeManager().ensure("/safe/repo", "../../escape", Path(self.tmp.name) / "trees")

    def test_worktree_porcelain_parser_ignores_space_less_metadata(self):
        self.assertEqual(WorktreeManager._record_values([
            "worktree /tmp/mission path", "HEAD " + "a" * 40, "detached", "bare"
        ]), {"worktree": "/tmp/mission path", "HEAD": "a" * 40})

    def test_existing_mission_path_rejects_detached_and_foreign_worktrees(self):
        repo = Path(self.tmp.name) / "repo"
        (repo / ".git").mkdir(parents=True)
        root = Path(self.tmp.name) / "trees"
        expected = str((root / "safe-demo").resolve())

        def fake_run(*argv, cwd=None):
            if argv[-1] == "origin/main":
                return "b" * 40
            if argv[-2:] == ("list", "--porcelain"):
                return fake_run.listing
            raise AssertionError(argv)

        manager = WorktreeManager()
        for metadata in ("detached", "branch refs/heads/harness/another-mission"):
            with self.subTest(metadata=metadata):
                fake_run.listing = f"worktree {expected}\nHEAD {'a' * 40}\n{metadata}"
                with patch("harness.isolation.run", side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError, "detached or belongs to another branch"):
                        manager.ensure(str(repo), "safe-demo", root)

        fake_run.listing = f"worktree {expected}\nHEAD {'a' * 40}\nbranch refs/heads/harness/safe-demo"
        with patch("harness.isolation.run", side_effect=fake_run):
            tree = manager.ensure(str(repo), "safe-demo", root)
        self.assertEqual(tree.branch, "harness/safe-demo")

    def test_head_change_invalidates_both_reviews(self):
        self.advance_to_test()
        self.drain()  # first run establishes receipts for A
        self.assertEqual(self.journal.valid_reviews(self.spec.mission_id, "a" * 40), {"codex", "deepseek"})
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.valid_reviews(self.spec.mission_id, "b" * 40), set())
        invalid = self.journal.db.execute("SELECT count(*) FROM receipts WHERE invalidated=1").fetchone()[0]
        self.assertEqual(invalid, 2)

    def test_latest_exact_head_reviewer_verdict_supersedes_older_pass(self):
        head, other_head = "a" * 40, "b" * 40
        self.journal.record_receipt(self.spec.mission_id, "codex", head, "PASS")
        self.journal.record_receipt(self.spec.mission_id, "deepseek", head, "PASS")
        self.journal.record_receipt(self.spec.mission_id, "codex", other_head, "PASS")
        self.assertEqual(
            self.journal.valid_reviews(self.spec.mission_id, head),
            {"codex", "deepseek"},
        )

        self.journal.record_receipt(self.spec.mission_id, "codex", head, "FAIL")
        self.assertEqual(
            self.journal.valid_reviews(self.spec.mission_id, head),
            {"deepseek"},
        )
        self.assertEqual(
            self.journal.valid_reviews(self.spec.mission_id, other_head),
            {"codex"},
        )

        self.journal.record_receipt(self.spec.mission_id, "codex", head, "PASS")
        self.assertEqual(
            self.journal.valid_reviews(self.spec.mission_id, head),
            {"codex", "deepseek"},
        )

    def test_head_change_after_gates_rewinds_to_fresh_exact_head_validation(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        for child in self.supervisor.process._children.values(): child.wait()
        self.supervisor.collect_jobs(self.spec.mission_id)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.supervisor.step(self.spec.mission_id, self.spec)  # TEST -> REVIEW
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "b" * 40))

    def test_head_change_invalidates_owner_approval_and_requires_new_grant(self):
        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.WAITING_APPROVAL,
                            approval_state="PENDING", pending_gate="owner-merge", pr_number=1,
                            pr_repo="fixture/repo", pr_base_sha="b" * 40)
        self.journal.approve(
            self.spec.mission_id, "merge", "head A only", observed_head="a" * 40,
        )
        self.assertTrue(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "b" * 40))

    def test_existing_mission_spec_is_durable_authority_for_cli_and_supervisor(self):
        persisted, exists = reconcile_supplied_spec(self.journal, self.spec)
        self.assertTrue(exists)
        self.assertEqual(persisted, self.spec)
        for changed in (
            replace(self.spec, adapter="footballprediction"),
            replace(self.spec, required_gates=("other-gate",)),
            replace(self.spec, merge_policy="owner_approval"),
            replace(self.spec, forbidden_actions=("merge",)),
        ):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, "persisted mission contract"):
                    reconcile_supplied_spec(self.journal, changed)
                with self.assertRaisesRegex(RuntimeError, "persisted mission contract"):
                    self.supervisor.step(self.spec.mission_id, changed)

    def test_corrupt_persisted_spec_fails_closed(self):
        self.journal.db.execute("UPDATE missions SET spec_json='{}' WHERE mission_id=?", (self.spec.mission_id,))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "persisted mission spec is invalid"):
            self.journal.spec(self.spec.mission_id)

    def test_approval_is_bound_to_known_action_policy_head_and_pending_state(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.WAITING_APPROVAL,
                            approval_state="PENDING", pending_gate="owner-merge", pr_number=1,
                            pr_repo="fixture/repo", pr_base_sha="b" * 40)
        with self.assertRaisesRegex(ValueError, "unknown or non-sensitive"):
            self.journal.approve(self.spec.mission_id, "typo", observed_head="a" * 40)
        with self.assertRaisesRegex(ValueError, "does not require approval"):
            self.journal.approve(self.spec.mission_id, "merge", observed_head="a" * 40)

        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "observed canonical HEAD differs"):
            self.journal.approve(self.spec.mission_id, "merge", observed_head="b" * 40)
        self.journal.approve(self.spec.mission_id, "merge", observed_head="a" * 40)
        self.assertTrue(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        approval = self.journal.db.execute(
            "SELECT pr_base_sha FROM approvals WHERE mission_id=? AND action='merge'",
            (self.spec.mission_id,),
        ).fetchone()
        self.assertEqual(approval[0], "b" * 40)
        self.journal.update(self.spec.mission_id, pr_base_sha="c" * 40)
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        self.journal.update(self.spec.mission_id, pr_base_sha="b" * 40)
        self.journal.update(self.spec.mission_id, pr_number=2)
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        self.journal.update(self.spec.mission_id, pr_number=1, pr_repo="other/repo")
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))

        denied_spec = replace(owner_spec, forbidden_actions=("merge",))
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(denied_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        self.assertFalse(self.journal.approved(self.spec.mission_id, "merge", "a" * 40))
        with self.assertRaisesRegex(PermissionError, "mission forbids action"):
            self.journal.approve(self.spec.mission_id, "merge", observed_head="a" * 40)

    def test_approval_cannot_be_pregranted_or_bound_to_missing_head(self):
        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=? WHERE mission_id=?",
                                (json.dumps(owner_spec.__dict__), self.spec.mission_id))
        self.journal.db.commit()
        with self.assertRaisesRegex(RuntimeError, "explicitly observed"):
            self.journal.approve(self.spec.mission_id, "merge")
        with self.assertRaisesRegex(RuntimeError, "canonical HEAD reconciliation"):
            self.journal.approve(
                self.spec.mission_id, "merge", observed_head="a" * 40,
            )
        self.journal.update(self.spec.mission_id, current_head="a" * 40)
        with self.assertRaisesRegex(RuntimeError, "not waiting for approval"):
            self.journal.approve(
                self.spec.mission_id, "merge", observed_head="a" * 40,
            )

    def test_approval_rejections_are_atomic_and_do_not_persist_a_decision(self):
        head = "a" * 40
        owner_spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.update(
            self.spec.mission_id,
            spec_json=json.dumps(owner_spec.__dict__),
            current_head=head,
            current_state=State.WAITING_APPROVAL,
            approval_state="PENDING",
            pending_gate="owner-merge",
            pr_number=1,
            pr_repo="fixture/repo",
            pr_base_sha="b" * 40,
        )
        with self.assertRaisesRegex(RuntimeError, "explicitly observed"):
            self.journal.approve(self.spec.mission_id, "merge")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            self.journal.approve(
                self.spec.mission_id, "merge", observed_head="b" * 40,
            )
        self.assertEqual(
            self.journal.db.execute(
                "SELECT count(*) FROM approvals WHERE mission_id=?",
                (self.spec.mission_id,),
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.journal.mission(self.spec.mission_id)["approval_state"],
            "PENDING",
        )

        self.journal.approve(
            self.spec.mission_id, "merge", observed_head=head,
        )
        approval = self.journal.db.execute(
            "SELECT head_sha,pr_repo FROM approvals WHERE mission_id=?",
            (self.spec.mission_id,),
        ).fetchone()
        self.assertEqual(approval["head_sha"], head)
        self.assertEqual(approval["pr_repo"], "fixture/repo")
        self.assertEqual(
            self.journal.mission(self.spec.mission_id)["approval_state"],
            "APPROVED",
        )

    def test_cli_approve_unknown_mission_exits_cleanly(self):
        argv = ["harness", "--root", self.tmp.name, "approve", "missing",
                "--action", "merge"]
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit) as error:
            cli_main()
        self.assertEqual(error.exception.code, 2)

    def test_policy_rejects_unknown_actions_and_non_boolean_approval(self):
        self.assertEqual(decide("merge_pr"), Decision.DENY)
        self.assertEqual(decide("MERGE"), Decision.DENY)
        self.assertFalse(permitted("merge_pr", (), approved=True))
        self.assertFalse(permitted("merge", (), approved="APPROVED"))
        self.assertTrue(permitted("merge", (), approved=True))
        self.assertTrue(permitted("source_edit", (), approved=False))
        self.assertTrue(permitted("review:codex", (), approved=False))
        self.assertFalse(permitted("review:codex", ("review:codex",), approved=False))

    def test_review_branch_enforces_review_and_repair_policy(self):
        review_forbidden = replace(self.spec, forbidden_actions=("review:codex",))
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(review_forbidden.__dict__),
            current_head="a" * 40, current_state=State.REVIEW,
        )
        self.assertEqual(
            self.supervisor.step(self.spec.mission_id, review_forbidden),
            State.BLOCKED_POLICY,
        )
        self.assertEqual(self.adapter.review_index, 0)

        repair_forbidden = replace(self.spec, forbidden_actions=("source_edit",))
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(repair_forbidden.__dict__),
            current_head="a" * 40, current_state=State.REVIEW,
            pending_gate=None,
        )
        self.adapter.reviews = ["FAIL"]
        self.assertEqual(
            self.supervisor.step(self.spec.mission_id, repair_forbidden),
            State.BLOCKED_POLICY,
        )
        self.assertEqual(self.codex.turns, [])

    def test_pass_is_reopened_when_canonical_head_changes(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.PASS, terminal_state=State.PASS, merge_claim_head="a" * 40)
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

    def test_head_reconciliation_clears_stale_terminal_marker_from_nonpass_state(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW, terminal_state=State.PASS)
        self.adapter.heads = ["b" * 40]
        self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.TEST)
        self.assertIsNone(row["terminal_state"])

    def test_pending_review_marker_is_cleared_when_reviewer_resolves(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW,
                            pending_gate="review:codex", ci_state="PENDING")
        self.adapter.reviews = ["PASS"]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.REVIEW)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["pending_gate"])
        self.assertIsNone(row["ci_state"])

    def test_pending_ci_marker_is_cleared_when_ci_resolves(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.CI,
                            pending_gate="github-ci", ci_state="PENDING")
        self.adapter.ci_results = ["PASS"]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["pending_gate"])
        self.assertIsNone(row["ci_state"])

    def test_simulation_approval_uses_synthetic_head_not_git(self):
        spec = replace(self.spec, merge_policy="owner_approval")
        self.journal.db.execute("UPDATE missions SET spec_json=?,current_head=?,current_state=?,approval_state=?,pending_gate=? WHERE mission_id=?",
                                (json.dumps(spec.__dict__), "a" * 40, State.WAITING_APPROVAL,
                                 "PENDING", "owner-merge", spec.mission_id))
        self.journal.db.commit()
        with patch("harness.cli.git_run", side_effect=AssertionError("simulation must not query Git")):
            self.assertEqual(approval_head(self.journal, spec, self.journal.mission(spec.mission_id)), "a" * 40)

    def test_production_codex_dirty_checkpoint_fails_closed_before_test(self):
        repo = Path(self.tmp.name) / "dirty-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("clean\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)

        class DirtyCodex(FakeCodex):
            def turn(self, thread_id, prompt, cwd):
                Path(cwd, "uncheckpointed.txt").write_text("model edit\n")
                return super().turn(thread_id, prompt, cwd)

        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        journal = Journal(Path(self.tmp.name) / "dirty.sqlite")
        supervisor = Supervisor(journal, ProcessSupervisor(journal, Path(self.tmp.name) / "dirty-logs"),
                                DirtyCodex(), FootballPredictionAdapter())
        with patch.object(supervisor.adapter, "_repo_from_origin", return_value="fixture/repo"):
            supervisor.create(spec, str(repo), "b" * 40, "harness/dirty")
        supervisor.step(spec.mission_id, spec)
        supervisor.step(spec.mission_id, spec)
        self.assertEqual(supervisor.step(spec.mission_id, spec), State.BLOCKED_EXTERNAL)
        self.assertNotEqual(journal.status(spec.mission_id).state, State.TEST)

    def test_codex_checkpoint_rejects_executable_git_config_before_status(self):
        class GuardedAdapter(FootballPredictionAdapter):
            def _assert_safe_local_git_config(self, worktree, env):
                raise RuntimeError("repository has executable local Git configuration")

        adapter = GuardedAdapter()
        supervisor = Supervisor(self.journal, self.supervisor.process, self.codex, adapter)
        with patch.object(adapter, "_call") as status:
            self.assertFalse(supervisor._codex_checkpoint_ready(
                self.spec.mission_id, str(self.worktree),
                expected_state=State.CREATED, expected_head=None))
        status.assert_not_called()
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.BLOCKED_EXTERNAL)

    def test_review_p1_and_ci_fail_are_repaired_not_blocked(self):
        self.adapter.reviews = ["FAIL", "PASS", "PASS"]
        self.adapter.ci_results = ["FAIL", "PASS"]
        self.advance_to_test()
        self.assertEqual(self.drain(), State.PASS)
        events = [row[0] for row in self.journal.db.execute("SELECT kind FROM events").fetchall()]
        self.assertGreaterEqual(events.count("codex_turn"), 3)

    def test_ci_failure_repair_honors_source_edit_deny_list(self):
        spec = replace(self.spec, forbidden_actions=("source_edit",))
        self.journal.update(
            spec.mission_id,
            spec_json=json.dumps(spec.__dict__),
            current_head="a" * 40,
            current_state=State.CI,
        )
        self.adapter.ci_results = ["FAIL"]
        self.assertEqual(self.supervisor.step(spec.mission_id, spec), State.BLOCKED_POLICY)
        self.assertEqual(self.codex.turns, [])

    def test_restart_resume_reconciles_not_restart_zero(self):
        self.advance_to_test()
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        old_process = self.supervisor.process
        child = next(iter(old_process._children.values()))
        child.wait()  # deterministic controlled interruption point: command ended before supervisor restart
        replacement = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "logs"), self.codex, self.adapter)
        # The replacement observes the persisted RUNNING row and the reaped PID,
        # marks that unjournaled outcome LOST, and resumes the same mission at TEST.
        replacement.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.TEST)
        self.assertEqual(row["current_head"], "a" * 40)
        self.assertEqual(row["codex_thread_id"], "thread-1")
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM events WHERE kind='mission_created'").fetchone()[0], 1)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE state='CONSUMED'").fetchone()[0], 1)
        replacement.collect_jobs(self.spec.mission_id)
        self.supervisor = replacement
        self.assertEqual(self.drain(), State.PASS)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)

    def test_terminal_gate_poll_replays_after_crash_before_publication(self):
        self.advance_to_test()
        self.supervisor.step(self.spec.mission_id, self.spec)
        child = next(iter(self.supervisor.process._children.values()))
        child.wait()
        observed = self.supervisor.process.poll(self.spec.mission_id)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].state, "EXITED")
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        replacement = Supervisor(self.journal, ProcessSupervisor(
            self.journal, Path(self.tmp.name) / "replay-gate-logs"), self.codex, self.adapter)
        replacement.reconcile(self.spec.mission_id)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.assertEqual(self.journal.db.execute(
            "SELECT state FROM jobs WHERE job_id=?", (observed[0].job_id,)).fetchone()[0], "CONSUMED")

    def test_agent_prose_is_not_terminal_and_invalid_transition_fails_closed(self):
        self.advance_to_test()
        self.assertFalse(self.journal.status(self.spec.mission_id).terminal)
        with self.assertRaises(InvalidTransition):
            self.journal.transition(self.spec.mission_id, State.PASS, "agent prose")

    def test_transition_is_exact_state_and_head_compare_and_swap(self):
        self.journal.update(self.spec.mission_id, current_state=State.REVIEW,
                            current_head="a" * 40)
        other = Journal(Path(self.tmp.name) / "harness.sqlite")
        other.reconcile_head(self.spec.mission_id, "b" * 40)
        with self.assertRaisesRegex(InvalidTransition, "expected state|expected HEAD"):
            self.journal.transition(
                self.spec.mission_id, State.CI, "stale review decision",
                expected_state=State.REVIEW, expected_head="a" * 40,
            )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]),
                         (State.TEST, "b" * 40))

    def test_run_until_wait_stably_returns_blocked_external(self):
        self.adapter.reviews = ["BLOCKED_EXTERNAL"]
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.REVIEW)
        self.assertEqual(
            self.supervisor.run_until_wait(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        # Re-entry is terminal and must not consume another reviewer result or
        # fall through the progress loop.
        review_index = self.adapter.review_index
        self.assertEqual(
            self.supervisor.run_until_wait(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.adapter.review_index, review_index)

    def test_policy_block_is_a_stable_terminal_wait_state(self):
        spec = replace(self.spec, forbidden_actions=("source_edit",))
        self.journal.db.execute("UPDATE missions SET spec_json=?,current_state=? WHERE mission_id=?",
                                (json.dumps(spec.__dict__), State.IMPLEMENT, spec.mission_id))
        self.journal.db.commit()
        self.assertEqual(self.supervisor.run_until_wait(spec.mission_id, spec), State.BLOCKED_POLICY)
        self.assertEqual(self.supervisor.run_until_terminal(spec.mission_id, spec), State.BLOCKED_POLICY)

    def test_app_server_turn_requires_completed_notification(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = type("Process", (), {"stdout": StringIO(
            '{"method":"turn/started","params":{}}\n'
            '{"method":"turn/completed","params":{"threadId":"t","turn":'
            '{"id":"x","status":"completed","items":[{"type":"agentMessage","text":"done"}]}}}\n'
        )})()
        turn = adapter._turn_completed("t", "x")
        self.assertEqual(turn["status"], "completed")

    def test_app_server_eof_fails_closed(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter.proc = type("Process", (), {"stdin": StringIO(), "stdout": StringIO()})()
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            adapter._request("ping", {})

    def test_app_server_rejects_unsolicited_server_request(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter.proc = type("Process", (), {
            "stdin": StringIO(),
            "stdout": StringIO(
                '{"id":99,"method":"item/commandExecution/requestApproval","params":{}}\n'
                '{"id":1,"result":{"ok":true}}\n'
            ),
        })()
        self.assertEqual(adapter._request("ping", {}), {"ok": True})
        self.assertIn("request denied by mission harness policy", adapter.proc.stdin.getvalue())

    def test_app_server_buffers_early_turn_completion_while_waiting_for_response(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter._pending_messages = []
        adapter.proc = type("Process", (), {
            "stdin": StringIO(),
            "stdout": StringIO(
                '{"method":"turn/completed","params":{"threadId":"t","turn":'
                '{"id":"x","status":"completed","items":[]}}}\n'
                '{"id":1,"result":{"turn":{"id":"x"}}}\n'
            ),
        })()
        self.assertEqual(adapter._request("turn/start", {}), {"turn": {"id": "x"}})
        self.assertEqual(adapter._turn_completed("t", "x")["status"], "completed")

    def test_app_server_pipe_read_has_a_response_deadline(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter._pending_messages = []
        adapter._reader_queue = queue.Queue()
        adapter._reader_thread = object()
        adapter._response_timeout = 0.01
        adapter.proc = type("Process", (), {
            "stdin": StringIO(), "stdout": StringIO(),
        })()
        with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
            adapter._request("ping", {})

    def test_app_server_reader_consumes_text_wrapper_buffer_without_fd_readiness(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.seq = 0
        adapter._pending_messages = []
        adapter.proc = type("Process", (), {
            "stdin": StringIO(),
            "stdout": StringIO('{"id":1,"result":{"ok":true}}\n'),
        })()
        self.assertEqual(adapter._request("ping", {}), {"ok": True})

    def test_empty_completed_turn_does_not_fabricate_agent_text(self):
        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter._forbidden_actions = adapter._effective_policy(())
        adapter._policy_cwd = "/mission-worktree"
        with patch.object(adapter, "_request", return_value={"turn": {"id": "turn-1"}}), \
                patch.object(adapter, "_turn_completed", return_value={
                    "id": "turn-1", "status": "completed", "items": [],
                }):
            turn = adapter.turn("thread-1", "work", "/mission-worktree")
        self.assertEqual(turn.text, "")

    def test_app_server_close_terminates_and_reaps_once(self):
        class FakeProcess:
            def __init__(self):
                self.stdin, self.stdout = StringIO(), StringIO()
                self.stderr = None
                self.terminated = 0
                self.waited = 0

            def poll(self):
                return None

            def terminate(self):
                self.terminated += 1

            def wait(self, timeout):
                self.waited += 1
                return 0

        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = FakeProcess()
        adapter.close()
        adapter.close()
        self.assertEqual((adapter.proc.terminated, adapter.proc.waited), (1, 1))
        self.assertTrue(adapter.proc.stdin.closed)
        self.assertTrue(adapter.proc.stdout.closed)

    def test_app_server_close_never_masks_a_second_wait_timeout(self):
        class StuckProcess:
            stdin, stdout, stderr = StringIO(), StringIO(), None

            def poll(self):
                return None

            def terminate(self):
                pass

            def kill(self):
                pass

            def wait(self, timeout):
                raise subprocess.TimeoutExpired("codex", timeout)

        adapter = AppServerCodex.__new__(AppServerCodex)
        adapter.proc = StuckProcess()
        adapter.close()

    def test_gate_pass_is_bound_to_exact_head(self):
        self.journal.update(
            self.spec.mission_id, current_state=State.TEST,
            current_head="a" * 40, pending_gate="verify-pr",
        )
        self.journal.complete_gate(self.spec.mission_id, "verify-pr", "a" * 40)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "b" * 40))

    def test_complete_gate_serializes_concurrent_gate_writers(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id, current_state=State.TEST,
            current_head=head, pending_gate="gate-a",
        )
        database = Path(self.tmp.name) / "harness.sqlite"
        first_has_lock = threading.Event()
        second_attempted_lock = threading.Event()
        outcomes = {}
        original_loads = json.loads

        def pause_first_writer(payload, *args, **kwargs):
            if threading.current_thread().name == "gate-writer-a":
                first_has_lock.set()
                if not second_attempted_lock.wait(timeout=2):
                    raise AssertionError("second gate writer never attempted its writer lock")
            return original_loads(payload, *args, **kwargs)

        def first_writer():
            journal = Journal(database)
            try:
                journal.complete_gate(self.spec.mission_id, "gate-a", head)
                outcomes["first"] = "PASS"
            except Exception as exc:
                outcomes["first"] = exc
            finally:
                journal.db.close()

        def second_writer():
            journal = Journal(database)
            journal.db.set_trace_callback(
                lambda sql: second_attempted_lock.set()
                if sql == "BEGIN IMMEDIATE" else None
            )
            try:
                if not first_has_lock.wait(timeout=2):
                    raise AssertionError("first gate writer never acquired its writer lock")
                journal.complete_gate(self.spec.mission_id, "gate-b", head)
                outcomes["second"] = "PASS"
            except Exception as exc:
                outcomes["second"] = exc
            finally:
                journal.db.close()

        with patch("harness.journal.json.loads", side_effect=pause_first_writer):
            second = threading.Thread(target=second_writer, name="gate-writer-b")
            first = threading.Thread(target=first_writer, name="gate-writer-a")
            second.start()
            first.start()
            first.join(timeout=3)
            second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(outcomes["first"], "PASS")
        self.assertIsInstance(outcomes["second"], InvalidTransition)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(json.loads(row["completed_gates_json"]), {"gate-a": head})
        self.assertIsNone(row["pending_gate"])

    def test_process_reservation_prevents_duplicate_launch(self):
        process = self.supervisor.process
        first = process.start(self.spec.mission_id, "one-gate", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        second = process.start(self.spec.mission_id, "one-gate", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        self.assertEqual(first, second)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='one-gate'").fetchone()[0], 1)
        next(iter(process._children.values())).wait()
        process.poll(self.spec.mission_id)

    def test_process_can_launch_with_explicit_environment_without_ambient_inheritance(self):
        class CapturedStdin:
            def __init__(self):
                self.payload = b""
                self.closed = False

            def write(self, payload):
                self.payload += payload
                return len(payload)

            def close(self):
                self.closed = True

        class Child:
            pid = 34567

            def __init__(self):
                self.stdin = CapturedStdin()

        process = self.supervisor.process
        child = Child()
        explicit_environment = {"PATH": "/trusted/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"}
        with patch("harness.process.subprocess.Popen", return_value=child) as popen, \
                patch("harness.process.os.getpgid", return_value=child.pid), \
                patch("harness.process.proc_start_ticks", return_value="child-start"):
            process.start(
                self.spec.mission_id, "clean-review", ["/trusted/python", "review.py"],
                str(self.worktree), explicit_environment, "a" * 40,
                inherit_environment=False,
            )

        self.assertEqual(popen.call_args.kwargs["env"], {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/nonexistent", "LANG": "C.UTF-8",
        })
        self.assertEqual(json.loads(child.stdin.payload)["env"], explicit_environment)
        self.assertTrue(child.stdin.closed)

    def test_log_open_failure_retires_starting_reservation_and_allows_retry(self):
        process = self.supervisor.process
        real_open = os.open

        def fail_log_open(path, flags, mode=0o777, *, dir_fd=None):
            if str(path).endswith(".out"):
                raise PermissionError("logs denied")
            if dir_fd is None:
                return real_open(path, flags, mode)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with patch("harness.process.os.open", side_effect=fail_log_open):
            with self.assertRaisesRegex(PermissionError, "logs denied"):
                process.start(
                    self.spec.mission_id, "log-open-fails", ["/bin/sh", "-c", "exit 0"],
                    str(self.worktree), {}, "a" * 40,
                )
        failed = self.journal.db.execute(
            "SELECT job_id,state,ended_at FROM jobs WHERE mission_id=? AND name=?",
            (self.spec.mission_id, "log-open-fails"),
        ).fetchone()
        self.assertEqual(failed["state"], "FAILED_LAUNCH")
        self.assertIsNotNone(failed["ended_at"])
        self.assertEqual(
            self.journal.db.execute(
                "SELECT count(*) FROM jobs WHERE mission_id=? AND name=? "
                "AND state IN ('STARTING','RUNNING')",
                (self.spec.mission_id, "log-open-fails"),
            ).fetchone()[0],
            0,
        )
        self.assertIsNotNone(self.journal.db.execute(
            "SELECT 1 FROM events WHERE mission_id=? AND kind='process_launch_failed'",
            (self.spec.mission_id,),
        ).fetchone())
        retried = process.start(
            self.spec.mission_id, "log-open-fails", ["/bin/sh", "-c", "exit 0"],
            str(self.worktree), {}, "a" * 40,
        )
        self.assertNotEqual(retried, failed["job_id"])
        process._children[retried].wait()
        process.poll(self.spec.mission_id)

    def test_process_log_directory_and_files_are_owner_only(self):
        process = self.supervisor.process
        self.assertEqual(process.log_root.stat().st_mode & 0o777, 0o700)
        job_id = process.start(
            self.spec.mission_id, "private-logs", ["/bin/sh", "-c", "printf safe"],
            str(self.worktree), {}, "a" * 40,
        )
        process.wait_for_mission(self.spec.mission_id)
        process.poll(self.spec.mission_id)
        row = self.journal.db.execute(
            "SELECT stdout_path,stderr_path FROM jobs WHERE job_id=?", (job_id,),
        ).fetchone()
        self.assertIsNotNone(row)
        for key in ("stdout_path", "stderr_path"):
            path = Path(row[key])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_process_log_root_rejects_redirectable_ancestors(self):
        root = Path(self.tmp.name)
        safe = root / "safe-logs"
        safe.mkdir(mode=0o700)
        redirect = root / "redirect"
        redirect.symlink_to(safe, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "ancestor is unsafe"):
            ProcessSupervisor(self.journal, redirect / "logs")
        writable = root / "writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, "ancestor is unsafe"):
            ProcessSupervisor(self.journal, writable / "logs")

    def test_release_pipe_failure_reaps_child_and_retires_running_lease(self):
        class FailingStdin:
            def write(self, payload):
                raise BrokenPipeError("bootstrap exited before release")

            def close(self):
                pass

        class LiveChild:
            pid = 12345

            def __init__(self):
                self.stdin = FailingStdin()
                self.terminated = False
                self.waited = False

            def poll(self):
                return None if not self.terminated else -15

            def terminate(self):
                self.terminated = True

            def wait(self, timeout):
                self.waited = True
                return -15

        child = LiveChild()
        process = self.supervisor.process
        def kill_group(pgid, sig):
            if sig == 0:
                raise ProcessLookupError()
            child.terminated = True
        with patch("harness.process.subprocess.Popen", return_value=child), \
                patch("harness.process.os.getpgid", return_value=12345), \
                patch("harness.process.os.killpg", side_effect=kill_group), \
                patch("harness.process.proc_start_ticks", return_value="child-start"):
            with self.assertRaisesRegex(BrokenPipeError, "before release"):
                process.start(
                    self.spec.mission_id, "release-fails", ["/bin/false"],
                    str(self.worktree), {}, "a" * 40,
                )
        row = self.journal.db.execute(
            "SELECT job_id,state,ended_at FROM jobs WHERE mission_id=? AND name=?",
            (self.spec.mission_id, "release-fails"),
        ).fetchone()
        self.assertTrue(child.terminated)
        self.assertTrue(child.waited)
        self.assertNotIn(row["job_id"], process._children)
        self.assertEqual(row["state"], "LOST")
        self.assertIsNotNone(row["ended_at"])
        self.assertEqual(
            self.journal.db.execute(
                "SELECT count(*) FROM jobs WHERE mission_id=? AND name=? "
                "AND state IN ('STARTING','RUNNING')",
                (self.spec.mission_id, "release-fails"),
            ).fetchone()[0],
            0,
        )

    def test_restart_does_not_retry_while_owned_process_group_survives(self):
        job_id = "review-group-survives"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,pid,pgid,"
            "start_ticks,state,stdout_path,stderr_path,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "review:codex", "[]", "a" * 40,
             98765, 98765, "old-start", "RUNNING", "", "", "now"),
        )
        self.journal.db.commit()
        resumed = ProcessSupervisor(self.journal, Path(self.tmp.name) / "group-replay-logs")
        with patch("harness.process.proc_identity", return_value=("ABSENT", None)), \
                patch("harness.process.os.killpg", return_value=None):
            observed = resumed.poll(self.spec.mission_id)
        self.assertEqual([(result.job_id, result.state) for result in observed],
                         [(job_id, "RUNNING")])
        self.assertEqual(self.journal.db.execute(
            "SELECT state FROM jobs WHERE job_id=?", (job_id,)).fetchone()[0], "RUNNING")

    def test_terminal_poll_cas_cannot_overwrite_a_peer_terminal_result(self):
        job_id = "concurrent-terminal-poll"
        database = Path(self.tmp.name) / "harness.sqlite"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,pid,pgid,"
            "start_ticks,state,stdout_path,stderr_path,started_at,launcher_pid,"
            "launcher_start_ticks,lease_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40,
             34567, 34567, "child-start", "RUNNING", "", "", "now",
             45678, "launcher-start", "lease-a"),
        )
        self.journal.db.commit()
        peer = Journal(database)

        def peer_publishes_exit(pid):
            peer.db.execute(
                "UPDATE jobs SET state='EXITED',exit_code=0,ended_at='peer-ended' "
                "WHERE job_id=? AND state='RUNNING' AND lease_token=?",
                (job_id, "lease-a"),
            )
            peer.db.commit()
            return "ABSENT", None

        try:
            with patch("harness.process.proc_identity", side_effect=peer_publishes_exit):
                self.assertEqual(self.supervisor.process.poll(self.spec.mission_id), [])
        finally:
            peer.db.close()
        row = self.journal.db.execute(
            "SELECT state,exit_code,ended_at FROM jobs WHERE job_id=?", (job_id,),
        ).fetchone()
        self.assertEqual(tuple(row), ("EXITED", 0, "peer-ended"))
        self.assertIsNone(self.journal.db.execute(
            "SELECT 1 FROM events WHERE mission_id=? AND kind='process_lost' "
            "AND json_extract(payload_json, '$.job_id')=?",
            (self.spec.mission_id, job_id),
        ).fetchone())

    def test_prepublication_identity_failure_retires_starting_reservation(self):
        class UnreleasedChild:
            pid = 23456

            def __init__(self):
                self.stdin = StringIO()
                self.terminated = False
                self.waited = False

            def terminate(self):
                self.terminated = True

            def wait(self):
                self.waited = True
                return -15

        child = UnreleasedChild()
        process = self.supervisor.process
        with patch("harness.process.subprocess.Popen", return_value=child), \
                patch("harness.process.os.getpgid", side_effect=PermissionError("pgid denied")):
            with self.assertRaisesRegex(PermissionError, "pgid denied"):
                process.start(
                    self.spec.mission_id, "publish-fails", ["/bin/true"],
                    str(self.worktree), {}, "a" * 40,
                )
        row = self.journal.db.execute(
            "SELECT state,ended_at FROM jobs WHERE mission_id=? AND name=?",
            (self.spec.mission_id, "publish-fails"),
        ).fetchone()
        self.assertEqual(row["state"], "FAILED_LAUNCH")
        self.assertIsNotNone(row["ended_at"])
        self.assertTrue(child.terminated)
        self.assertTrue(child.waited)
        self.assertEqual(process._children, {})

        replacement = process.start(
            self.spec.mission_id, "publish-fails", ["/bin/sh", "-c", "exit 0"],
            str(self.worktree), {}, "a" * 40,
        )
        process._children[replacement].wait()
        process.poll(self.spec.mission_id)

    def test_restart_poll_records_zero_exit_from_reaped_child(self):
        job_id = "reaped-zero"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,pid,pgid,start_ticks,state,stdout_path,stderr_path,started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40, 123, 123, "old-ticks", "RUNNING", "", "", "now"),
        )
        self.journal.db.commit()
        replacement = ProcessSupervisor(self.journal, Path(self.tmp.name) / "reaped-logs")
        with patch("harness.process.proc_identity", return_value=("ABSENT", None)), patch(
                "harness.process.os.waitpid", return_value=(123, 0)):
            result = replacement.poll(self.spec.mission_id)
        self.assertEqual([(item.state, item.exit_code) for item in result], [("EXITED", 0)])
        self.assertEqual(tuple(self.journal.db.execute(
            "SELECT state,exit_code FROM jobs WHERE job_id=?", (job_id,)).fetchone()), ("EXITED", 0))

    def test_proc_identity_permission_error_fails_closed(self):
        with patch("harness.process.Path.read_text", side_effect=PermissionError):
            self.assertEqual(proc_identity(123), ("UNKNOWN", None))
            self.assertIsNone(proc_start_ticks(123))
        with patch("harness.journal.Path.read_text", side_effect=PermissionError):
            self.assertEqual(Journal._proc_identity(123), ("UNKNOWN", None))
            self.assertIsNone(Journal._proc_start_ticks(123))

    def test_stale_gate_failure_cannot_trigger_repair_for_new_head(self):
        self.adapter.heads = ["b" * 40]
        self.journal.update(self.spec.mission_id, current_head="b" * 40, current_state=State.TEST,
                            pending_gate="verify-pr")
        stale = JobResult("old-job", "EXITED", 17, "a" * 40)
        with patch.object(self.supervisor.process, "poll", return_value=[stale]):
            self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["pending_gate"], "verify-pr")
        event = self.journal.db.execute(
            "SELECT payload_json FROM events WHERE kind='gate_failure_stale' ORDER BY seq DESC LIMIT 1").fetchone()
        self.assertIsNotNone(event)
        payload = json.loads(event[0])
        self.assertEqual(payload["launch_head"], "a" * 40)
        self.assertEqual(payload["current_head"], "b" * 40)
        self.assertEqual(payload["exit_code"], 17)

    def test_stale_non_exit_process_result_cannot_fail_the_new_source(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.adapter.heads = [new_head]
        self.journal.update(
            self.spec.mission_id, current_head=new_head, current_state=State.TEST,
            pending_gate="verify-pr",
        )
        stale = JobResult("old-job", "FAILED_LAUNCH", None, old_head)
        with patch.object(self.supervisor.process, "poll", return_value=[stale]):
            self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]), (State.TEST, new_head))
        event = self.journal.db.execute(
            "SELECT payload_json FROM events WHERE kind='process_result_stale' "
            "ORDER BY seq DESC LIMIT 1",
        ).fetchone()
        self.assertIsNotNone(event)
        payload = json.loads(event[0])
        self.assertEqual(payload["launch_head"], old_head)
        self.assertEqual(payload["current_head"], new_head)

    def test_current_process_failure_transition_is_bound_to_guarded_snapshot(self):
        head, concurrent_head = "a" * 40, "b" * 40
        self.adapter.heads = [head]
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.TEST,
            pending_gate=None,
        )
        failed = JobResult("current-job", "FAILED_LAUNCH", None, head)
        transition = self.journal.transition

        def race_before_transition(*args, **kwargs):
            self.journal.update(
                self.spec.mission_id,
                current_head=concurrent_head,
                current_state=State.REVIEW,
            )
            return transition(*args, **kwargs)

        with patch.object(self.supervisor.process, "poll", return_value=[failed]), \
                patch.object(self.journal, "transition", side_effect=race_before_transition), \
                self.assertRaisesRegex(InvalidTransition, "stale transition"):
            self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(
            (row["current_state"], row["current_head"]),
            (State.REVIEW, concurrent_head),
        )

    def test_stale_starting_lease_is_recoverable_before_a_replacement_launch(self):
        """A crash before PID publication is marked lost before a replacement launch."""
        job_id = "reserved-only"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at,launcher_pid,launcher_start_ticks,lease_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40, "STARTING", "", "", "now", 99999999, "never", "lease"),
        )
        self.journal.db.commit()
        result = self.supervisor.process.poll(self.spec.mission_id)
        self.assertEqual([(item.job_id, item.state) for item in result], [(job_id, "LOST")])
        replacement = self.supervisor.process.start(self.spec.mission_id, "verify-pr", ["/bin/sh", "-c", "exit 0"], str(self.worktree), {}, "a" * 40)
        self.assertNotEqual(replacement, job_id)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)
        self.supervisor.process._children[replacement].wait()
        self.supervisor.process.poll(self.spec.mission_id)

    def test_starting_recovery_cas_rejects_a_changed_lease(self):
        job_id = "renewed-reservation"
        self.journal.db.execute(
            "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,"
            "stdout_path,stderr_path,started_at,launcher_pid,launcher_start_ticks,lease_token) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (job_id, self.spec.mission_id, "verify-pr", "[]", "a" * 40,
             "STARTING", "", "", "now", 99999999, "old-start", "old-lease"),
        )
        self.journal.db.commit()
        other = Journal(Path(self.tmp.name) / "harness.sqlite")

        def renew_before_recovery(pid):
            other.db.execute(
                "UPDATE jobs SET lease_token='new-lease' WHERE job_id=?", (job_id,),
            )
            other.db.commit()
            return "ABSENT", None

        with patch("harness.process.proc_identity", side_effect=renew_before_recovery):
            self.assertEqual(self.supervisor.process.poll(self.spec.mission_id), [])
        row = self.journal.db.execute(
            "SELECT state,lease_token FROM jobs WHERE job_id=?", (job_id,),
        ).fetchone()
        self.assertEqual(tuple(row), ("STARTING", "new-lease"))

    def test_restart_gate_crash_points_fail_closed_and_recover(self):
        self.advance_to_test()
        # completed-but-not-journaled after a controller restart becomes LOST, not PASS
        self.supervisor.run_until_wait(self.spec.mission_id, self.spec)
        child = next(iter(self.supervisor.process._children.values()))
        child.wait()
        restarted = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "restarted-logs"), self.codex, self.adapter)
        restarted.reconcile(self.spec.mission_id)
        self.assertFalse(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        self.assertEqual(self.journal.status(self.spec.mission_id).state, State.TEST)
        # Retry from canonical TEST truth, then simulate a crash after gate journal but before state transition.
        restarted.run_until_wait(self.spec.mission_id, self.spec)
        for child in list(restarted.process._children.values()):
            child.wait()
        restarted.collect_jobs(self.spec.mission_id)
        self.assertTrue(self.journal.gate_passed_at_head(self.spec.mission_id, "verify-pr", "a" * 40))
        replacement = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "again-logs"), self.codex, self.adapter)
        self.assertEqual(replacement.run_until_wait(self.spec.mission_id, self.spec), State.PASS)
        self.assertEqual(self.journal.db.execute("SELECT count(*) FROM jobs WHERE name='verify-pr'").fetchone()[0], 2)

    def test_owner_approval_is_persisted_and_resume_consumes_only_explicit_grant(self):
        spec = MissionSpec("approval-demo", "/safe/repo", "approval fixture", adapter="simulation", merge_policy="owner_approval")
        worktree = Path(self.tmp.name) / "approval-worktree"; worktree.mkdir()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "approval-logs"), self.codex, SimulatedAdapter())
        supervisor.create(spec, str(worktree), "b" * 40, "harness/approval-demo")
        for _ in range(20):
            state = supervisor.run_until_wait(spec.mission_id, spec)
            if state == State.WAITING_APPROVAL:
                break
            for child in list(supervisor.process._children.values()):
                child.wait()
            supervisor.collect_jobs(spec.mission_id)
        self.assertEqual(state, State.WAITING_APPROVAL)
        self.assertFalse(self.journal.approved(spec.mission_id, "merge", "a" * 40))
        resumed = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "approval-restart"), self.codex, supervisor.adapter)
        self.assertEqual(resumed.step(spec.mission_id, spec), State.WAITING_APPROVAL)
        self.journal.approve(
            spec.mission_id, "merge", "explicit owner command",
            observed_head="a" * 40,
        )
        for _ in range(10):
            state = resumed.run_until_wait(spec.mission_id, spec)
            if state == State.PASS:
                break
        self.assertEqual(state, State.PASS)

    def test_simulation_cli_build_selects_simulated_contract_adapter(self):
        supervisor = build(Path(self.tmp.name), "simulation", FakeCodex())
        self.assertIsInstance(supervisor.adapter, SimulatedAdapter)

    def test_cli_resolves_worktree_before_constructing_production_codex(self):
        mission = Path(self.tmp.name) / "production-mission.json"
        mission.write_text(json.dumps({
            "schema_version": 1,
            "mission_id": "constructor-bound",
            "repository": "/source/repository",
            "objective": "safe fixture",
            "mission_scope_file": "scope.json",
        }))
        tree = Worktree(
            "/source/repository", "b" * 40, "harness/constructor-bound",
            "/validated/mission-worktree",
        )
        events = []

        def ensure(*args):
            events.append("ensure")
            return tree

        def stop_after_build(*args, **kwargs):
            events.append("build")
            self.assertEqual(kwargs["worktree"], tree.path)
            raise RuntimeError("stop after constructor boundary assertion")

        argv = ["harness", "--root", self.tmp.name, "run", str(mission)]
        with patch.object(sys, "argv", argv), \
                patch("harness.cli.WorktreeManager.ensure", side_effect=ensure), \
                patch("harness.cli.build", side_effect=stop_after_build), \
                self.assertRaisesRegex(RuntimeError, "constructor boundary"):
            cli_main()
        self.assertEqual(events, ["ensure", "build"])

    def test_invalid_adapter_names_fail_closed_and_simulation_does_not_start_app_server(self):
        path = Path(self.tmp.name) / "bad.json"
        path.write_text(json.dumps({"schema_version": 1, "mission_id": "x", "repository": "/r", "objective": "x", "adapter": "sim"}))
        with self.assertRaises(ValueError):
            load_spec(path)
        path.write_text(json.dumps({"schema_version": True, "mission_id": "x", "repository": "/r", "objective": "x"}))
        with self.assertRaises(ValueError):
            load_spec(path)
        supervisor = build(Path(self.tmp.name), "simulation")
        self.assertIsInstance(supervisor.codex, FixtureCodex)
        self.assertNotIsInstance(supervisor.codex, AppServerCodex)

    def test_legacy_football_mission_scope_is_readable_but_new_scope_is_contained(self):
        base = {"schema_version": 1, "mission_id": "x", "repository": "/r",
                "objective": "x", "adapter": "footballprediction"}
        legacy = MissionSpec.from_mapping(base)
        self.assertIsNone(legacy.mission_scope_file)
        legacy_payload = {
            **base, "mission_id": self.spec.mission_id, "repository": self.spec.repository,
        }
        self.journal.update(self.spec.mission_id, spec_json=json.dumps(legacy_payload))
        self.assertIsNone(self.journal.spec(self.spec.mission_id).mission_scope_file)
        for scope in ("", "/tmp/scope.json", "../scope.json", "a/../../scope.json", "a\\scope.json"):
            payload = dict(base)
            payload["mission_scope_file"] = scope
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "safe relative path"):
                MissionSpec.from_mapping(payload)
        valid = MissionSpec.from_mapping({**base, "mission_scope_file": "docs/agentic/mission.json"})
        self.assertEqual(valid.mission_scope_file, "docs/agentic/mission.json")

    def test_forbidden_merge_is_denied_before_claim(self):
        spec = MissionSpec("deny-merge", "/safe/repo", "fixture", adapter="simulation", merge_policy="auto", forbidden_actions=("merge",))
        worktree = Path(self.tmp.name) / "deny-worktree"; worktree.mkdir()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "deny-logs"), self.codex, self.adapter)
        supervisor.create(spec, str(worktree), "b" * 40, "harness/deny-merge")
        self.journal.update(spec.mission_id, current_head="a" * 40, current_state=State.MERGE)
        self.assertEqual(supervisor.step(spec.mission_id, spec), State.BLOCKED_POLICY)
        self.assertIsNone(self.journal.mission(spec.mission_id)["merge_claim_head"])

    def test_first_merge_claim_executes_external_merge(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["merge_claim_head"])
        self.assertEqual(row["merge_sha"], "c" * 40)

    def test_merge_failure_is_external_not_policy_denial(self):
        class FailingMergeAdapter(SimulatedAdapter):
            def merge(self, worktree, head, pr_number=None):
                return GateResult("FAIL", "remote merge service rejected request")

        adapter = FailingMergeAdapter()
        supervisor = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-fail-logs"),
                                self.codex, adapter)
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_merge_exception_after_invocation_reconciles_without_retry(self):
        class RaisingMergeAdapter(SimulatedAdapter):
            def __init__(self):
                super().__init__()
                self.merge_calls = 0

            def merge(self, worktree, head, pr_number=None):
                self.merge_calls += 1
                self.merged_heads.add(head)
                raise RuntimeError("transport disconnected after request")

        adapter = RaisingMergeAdapter()
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-exception-logs"),
            self.codex,
            adapter,
        )
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=head,
            current_state=State.MERGE,
            merge_claim_head=None,
            merge_claim_pid=None,
            merge_claim_start_ticks=None,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(adapter.merged_heads, {head})
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_invocation_started"], 0)
        self.assertEqual(adapter.merge_calls, 1)

    def test_ambiguous_merge_remains_reconcilable_until_server_confirms_merge(self):
        class DelayedMerge(SimulatedAdapter):
            def __init__(self):
                super().__init__()
                self.calls = 0
                self.status_calls = 0

            def merge(self, worktree, head, pr_number=None):
                self.calls += 1
                raise RuntimeError("response unavailable after invocation")

            def merge_status(self, worktree, head, pr_number=None, pr_repo=None):
                self.status_calls += 1
                if self.status_calls == 1:
                    return GateResult("BLOCKED_EXTERNAL", "GitHub state temporarily unavailable")
                return GateResult("PASS", "merged", data={"merge_sha": "c" * 40})

        adapter = DelayedMerge()
        supervisor = Supervisor(self.journal, self.supervisor.process, self.codex, adapter)
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.MERGE)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(adapter.calls, 1)

    def test_merge_failure_after_invocation_is_not_retried(self):
        class AlwaysUnavailable(SimulatedAdapter):
            def __init__(self):
                super().__init__()
                self.merge_calls = 0

            def merge(self, worktree, head):
                self.merge_calls += 1
                raise RuntimeError("transport unavailable")

        adapter = AlwaysUnavailable()
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "bounded-merge-retry"),
            self.codex, adapter,
        )
        head = "a" * 40
        self.journal.update(self.spec.mission_id, current_head=head, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(adapter.merge_calls, 1)

    def test_invoked_merge_not_started_status_is_ambiguous_and_never_retried(self):
        class SimulatedCrash(BaseException):
            pass

        class CrashingMergeAdapter(SimulatedAdapter):
            def __init__(self):
                super().__init__()
                self.merge_calls = 0
                self.status_calls = 0

            def merge(self, worktree, head, pr_number=None, pr_repo=None):
                self.merge_calls += 1
                self.merged_heads.add(head)
                raise SimulatedCrash("process died after external request")

            def merge_status(self, worktree, head, pr_number=None, pr_repo=None):
                self.status_calls += 1
                return GateResult("NOT_STARTED", "stale canonical observation")

        adapter = CrashingMergeAdapter()
        first = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-crash-first"),
            self.codex, adapter,
        )
        head = "a" * 40
        old_pid, old_ticks = 424242, "old-merge-owner"
        owner_alive = {"value": True}
        real_identity = self.journal._proc_identity

        def proc_identity(pid):
            if pid == old_pid:
                return ("PRESENT", old_ticks) if owner_alive["value"] else ("ABSENT", None)
            return real_identity(pid)

        self.journal.update(self.spec.mission_id, current_head=head, current_state=State.MERGE,
                            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None)
        with patch.object(first, "_merge_owner", return_value=(old_pid, old_ticks)), \
                patch.object(self.journal, "_proc_identity", side_effect=proc_identity), \
                self.assertRaises(SimulatedCrash):
            first.step(self.spec.mission_id, self.spec)

        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.MERGE)
        self.assertEqual(row["merge_invocation_started"], 1)
        self.assertEqual(adapter.merge_calls, 1)

        owner_alive["value"] = False
        restarted = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "merge-crash-restart"),
            self.codex, adapter,
        )
        with patch.object(self.journal, "_proc_identity", side_effect=proc_identity):
            self.assertEqual(restarted.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(adapter.status_calls, 1)
        self.assertEqual(adapter.merge_calls, 1)

    def test_keyword_only_pr_adapter_arguments_are_dispatched(self):
        seen = {}

        class KeywordOnlyAdapter(SimulatedAdapter):
            def ci(self, worktree, head, *, pr_number=None, pr_repo=None):
                seen["ci"] = (pr_number, pr_repo)
                return GateResult("PASS", "keyword-only CI", data={
                    "pr_number": pr_number, "pr_repo": pr_repo, "pr_base_sha": "b" * 40,
                })

            def merge(self, worktree, head, *, pr_number=None, pr_repo=None):
                seen["merge"] = (pr_number, pr_repo)
                return GateResult("PASS", "keyword-only merge", data={
                    "pr": pr_number, "repo": pr_repo, "pr_base_sha": "b" * 40,
                    "merge_sha": "c" * 40,
                })

        adapter = KeywordOnlyAdapter()
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "keyword-only-pr-adapter"),
            self.codex, adapter,
        )
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(seen, {"ci": (1, "fixture/repo"), "merge": (1, "fixture/repo")})

    def test_merge_pass_must_explicitly_bind_durable_repository_identity(self):
        class MissingRepositoryAdapter(SimulatedAdapter):
            def ci(self, worktree, head, *, pr_number=None, pr_repo=None):
                return GateResult("PASS", "keyword-only CI", data={
                    "pr_number": pr_number, "pr_repo": pr_repo, "pr_base_sha": "b" * 40,
                })

            def merge(self, worktree, head, *, pr_number=None, pr_repo=None):
                return GateResult("PASS", "merge omitted repository", data={
                    "pr": pr_number, "pr_base_sha": "b" * 40, "merge_sha": "c" * 40,
                })

        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "missing-merge-repository"),
            self.codex, MissingRepositoryAdapter(),
        )
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)

    def test_legacy_two_argument_ci_adapter_is_dispatched_without_crash(self):
        class TwoArgumentCI(SimulatedAdapter):
            def ci(self, worktree, head):
                return GateResult("PASS", "legacy fixture")

        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "two-arg-ci"),
            self.codex, TwoArgumentCI(),
        )
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.CI)
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.MERGE)

    def test_ci_preserves_nonretryable_external_failure_evidence_without_pr_identity(self):
        head = "a" * 40
        failure_evidence = "GitHub CI query failed because the credential scope is unavailable"

        class CanonicalBlockedCI(FootballPredictionAdapter):
            def exact_head(self, worktree):
                return head

            def ci(self, worktree, reviewed_head, pr_number=None, pr_repo=None,
                   base_sha=None, pr_base_sha=None):
                return GateResult(
                    "BLOCKED_EXTERNAL", failure_evidence,
                    data={"retryable": False, "classification": "configuration"},
                )

        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "blocked-ci-evidence"),
            self.codex,
            CanonicalBlockedCI(),
        )
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.CI,
        )

        self.assertEqual(
            supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL,
        )
        event = self.journal.db.execute(
            "SELECT payload_json FROM events WHERE mission_id=? AND kind='state_transition' "
            "ORDER BY seq DESC LIMIT 1",
            (self.spec.mission_id,),
        ).fetchone()
        self.assertEqual(json.loads(event[0])["reason"], failure_evidence)

    def test_live_unknown_merge_claim_is_not_stolen(self):
        head = "a" * 40
        owner_pid, owner_ticks = self.supervisor._merge_owner()
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=1, pr_repo="fixture/repo", merge_claim_head=head,
            pr_base_sha="b" * 40, merge_claim_pr_number=1, merge_claim_pr_repo="fixture/repo",
            merge_claim_pr_base_sha="b" * 40,
            merge_claim_pid=owner_pid, merge_claim_start_ticks=owner_ticks,
            merge_invocation_started=1, pending_gate="merge-outcome-unknown",
        )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["pending_gate"], "merge-outcome-unknown")
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_pid"], owner_pid)

    def test_recovered_production_merge_persists_pr_and_merge_sha(self):
        head, merge_sha = "a" * 40, "c" * 40

        class RecoveredProductionAdapter(FootballPredictionAdapter):
            def exact_head(self, worktree): return head
            def merge_status(self, worktree, reviewed_head, pr_number=None, pr_repo=None,
                             pr_base_sha=None):
                return GateResult("PASS", "merged", data={"pr": pr_number, "repo": pr_repo,
                                                           "pr_base_sha": pr_base_sha,
                                                           "merge_sha": merge_sha})

        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "recovered-production"),
            self.codex, RecoveredProductionAdapter(),
        )
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=7, pr_repo="fixture/repo", pr_base_sha="b" * 40,
            merge_claim_head=head, merge_claim_pr_number=7, merge_claim_pr_repo="fixture/repo",
            merge_claim_pr_base_sha="b" * 40, merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner", merge_invocation_started=1,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["pr_number"], row["merge_sha"]), (7, merge_sha))

    def test_unknown_merge_decision_fails_closed_before_claim(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            pr_number=1, pr_repo="fixture/repo", pr_base_sha="b" * 40,
                            merge_claim_head=None,
                            merge_claim_pid=None, merge_claim_start_ticks=None)
        with patch("harness.supervisor.decide", return_value="UNRECOGNIZED"):
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_POLICY)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

    def test_head_drift_during_deliver_rewinds_and_merge_claim_recovers(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.DELIVER)
        self.adapter.heads = ["b" * 40]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.TEST)
        for child in list(self.supervisor.process._children.values()):
            child.wait()
        self.supervisor.collect_jobs(self.spec.mission_id)
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            pr_number=1, pr_repo="fixture/repo",
                            pr_base_sha="b" * 40,
                            merge_claim_head="a" * 40, merge_claim_pid=99999999,
                            merge_claim_pr_number=1, merge_claim_pr_repo="fixture/repo",
                            merge_claim_pr_base_sha="b" * 40,
                            merge_claim_start_ticks="dead-owner")
        self.adapter.heads = ["a" * 40]
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})

    def test_head_drift_during_post_merge_reopens_before_delivery(self):
        class DriftingPostMergeAdapter(SimulatedAdapter):
            def post_merge(self, gate, head):
                self.heads = ["b" * 40]
                return GateResult("PASS", "post-merge completed before drift")

        adapter = DriftingPostMergeAdapter(heads=["a" * 40])
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "post-merge-drift-logs"),
            self.codex,
            adapter,
        )
        spec = replace(self.spec, post_merge_gates=("production-gate",))
        self.journal.update(
            self.spec.mission_id,
            spec_json=json.dumps(spec.__dict__),
            current_head="a" * 40,
            current_state=State.POST_MERGE,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, spec), State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_head"], "b" * 40)

    def test_head_drift_at_final_delivery_check_reopens_before_pass(self):
        class SequenceHeadAdapter(SimulatedAdapter):
            def __init__(self):
                super().__init__(heads=["a" * 40])
                self.observations = iter(["a" * 40, "b" * 40])

            def exact_head(self, worktree):
                return next(self.observations, "b" * 40)

        adapter = SequenceHeadAdapter()
        supervisor = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "deliver-drift-logs"),
            self.codex,
            adapter,
        )
        self.journal.update(
            self.spec.mission_id,
            current_head="a" * 40,
            current_state=State.DELIVER,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.TEST)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["current_head"], "b" * 40)

    def test_live_merge_claim_cannot_be_stolen_by_second_controller(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            pr_number=1, pr_repo="fixture/repo", pr_base_sha="b" * 40,
                            merge_claim_head=None,
                            merge_claim_pid=None, merge_claim_start_ticks=None)
        owner_pid, owner_start_ticks = self.supervisor._merge_owner()
        self.assertTrue(self.journal.claim_merge(self.spec.mission_id, "a" * 40, owner_pid, owner_start_ticks))
        claim = self.journal.mission(self.spec.mission_id)
        self.assertEqual((claim["merge_claim_pr_number"], claim["merge_claim_pr_repo"]),
                         (1, "fixture/repo"))
        self.assertEqual(claim["merge_claim_pr_base_sha"], "b" * 40)
        second = Supervisor(self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "second-logs"),
                            self.codex, self.adapter)
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], "a" * 40)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_merge_invocation_rechecks_claim_lease_before_adapter_call(self):
        head = "a" * 40
        self.adapter.heads = [head]
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=7, pr_repo="fixture/repo", pr_base_sha="b" * 40,
            merge_claim_head=None, merge_claim_pid=None, merge_claim_start_ticks=None,
        )
        with patch.object(self.journal, "confirm_merge_retry_safe", return_value="NO_CLAIM") as confirm, \
                patch.object(self.adapter, "merge", wraps=self.adapter.merge) as merge:
            state = self.supervisor.step(self.spec.mission_id, self.spec)
        self.assertEqual(state, State.MERGE)
        confirm.assert_called_once_with(
            self.spec.mission_id, head, self.supervisor.process.launcher_pid,
            self.supervisor.process.launcher_start_ticks,
        )
        merge.assert_not_called()

    def test_invoked_merge_status_is_queried_after_dead_owner_and_not_started_blocks(self):
        """An invoked merge with NOT_STARTED remains ambiguous and is never repeated."""
        head = "a" * 40
        old_pid, old_start = 424242, "original-owner-start"
        owner_alive = {"value": True}
        external_calls: list[str] = []
        status_claim_owners: list[tuple[int, str]] = []
        journal = self.journal

        class RacingMergeAdapter(SimulatedAdapter):
            def merge_status(self, worktree, claimed_head, pr_number=None, pr_base_sha=None):
                row = journal.mission(self_spec.mission_id)
                status_claim_owners.append(
                    (row["merge_claim_pid"], row["merge_claim_start_ticks"]),
                )
                # This is the old failure window: if status is queried while
                # the original owner is alive, it can issue the merge after
                # NOT_STARTED was observed and then exit before reclaim.
                if owner_alive["value"]:
                    external_calls.append("original-owner")
                    owner_alive["value"] = False
                return GateResult("NOT_STARTED", "canonical merge not started")

            def merge(self, worktree, claimed_head, pr_number=None, pr_base_sha=None):
                external_calls.append("recovery-owner")
                return GateResult("PASS", "recovery merge")

        self_spec = self.spec
        adapter = RacingMergeAdapter(heads=[head])
        recovery = Supervisor(
            journal,
            ProcessSupervisor(journal, Path(self.tmp.name) / "merge-race-logs"),
            self.codex,
            adapter,
        )
        journal.update(
            self_spec.mission_id,
            current_head=head,
            current_state=State.MERGE,
            merge_claim_head=head,
            pr_number=1, pr_repo="fixture/repo",
            merge_claim_pr_number=1, merge_claim_pr_repo="fixture/repo",
            pr_base_sha="b" * 40, merge_claim_pr_base_sha="b" * 40,
            merge_claim_pid=old_pid,
            merge_claim_start_ticks=old_start,
            merge_invocation_started=1,
            pending_gate="merge-outcome-unknown",
        )
        real_proc_identity = journal._proc_identity

        def owner_identity(pid):
            if pid == old_pid:
                return (("PRESENT", old_start) if owner_alive["value"]
                        else ("ABSENT", None))
            return real_proc_identity(pid)

        with patch.object(journal, "_proc_identity", side_effect=owner_identity):
            # While the old owner is alive, recovery must not even query status.
            self.assertEqual(recovery.step(self_spec.mission_id, self_spec), State.MERGE)
            self.assertEqual(status_claim_owners, [])
            self.assertEqual(external_calls, [])

            # Once the old owner is definitely dead, its claim is transferred
            # before status is queried; NOT_STARTED is still ambiguous after
            # an invocation may have begun, so it must not be retried.
            owner_alive["value"] = False
            self.assertEqual(recovery.step(self_spec.mission_id, self_spec), State.MERGE)

        recovery_owner = recovery._merge_owner()
        self.assertEqual(status_claim_owners, [recovery_owner])
        self.assertEqual(external_calls, [])

    def test_head_drift_preserves_live_merge_claim_then_revalidates_after_safe_reclaim(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=old_head,
            current_state=State.MERGE,
            pr_number=1,
            pr_repo="fixture/repo",
            pr_base_sha="b" * 40,
            merge_claim_head=None,
            merge_claim_pid=None,
            merge_claim_start_ticks=None,
        )
        owner_pid, owner_start_ticks = self.supervisor._merge_owner()
        self.assertTrue(
            self.journal.claim_merge(
                self.spec.mission_id, old_head, owner_pid, owner_start_ticks,
            )
        )

        # A concurrent source update must not erase the live claim: its owner
        # may still be between the durable claim and the external merge call.
        self.adapter.heads = [new_head]
        self.supervisor.reconcile(self.spec.mission_id)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual((row["current_state"], row["current_head"]), (State.MERGE, new_head))
        self.assertEqual(row["merge_claim_head"], old_head)

        second = Supervisor(
            self.journal,
            ProcessSupervisor(self.journal, Path(self.tmp.name) / "drifted-claim-logs"),
            self.codex,
            self.adapter,
        )
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.MERGE)
        self.assertEqual(self.adapter.merged_heads, set())

        # Once canonical status says NOT_STARTED and the recorded owner is
        # definitely gone, reclaim atomically rewinds to TEST for the new HEAD;
        # it still cannot merge the new HEAD in the same supervisor turn.
        self.journal.update(
            self.spec.mission_id,
            merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner",
        )
        self.assertEqual(second.step(self.spec.mission_id, self.spec), State.TEST)
        row = self.journal.mission(self.spec.mission_id)
        self.assertIsNone(row["merge_claim_head"])
        self.assertEqual(row["current_head"], new_head)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_head_drift_reclaim_result_without_journal_rewind_fails_closed(self):
        """A return label alone cannot authorize the supervisor to skip validation."""
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=new_head,
            current_state=State.MERGE,
            merge_claim_head=old_head,
            merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner",
        )
        self.adapter.heads = [new_head]
        with patch.object(
                self.journal, "confirm_merge_retry_safe",
                return_value="REWOUND_HEAD_DRIFT"):
            self.assertEqual(
                self.supervisor.step(self.spec.mission_id, self.spec),
                State.BLOCKED_EXTERNAL,
            )
        self.assertEqual(self.adapter.merged_heads, set())
        self.assertEqual(
            self.journal.mission(self.spec.mission_id)["merge_claim_head"], old_head,
        )

    def test_completed_stale_head_merge_blocks_instead_of_merging_new_head(self):
        old_head, new_head = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=old_head,
            current_state=State.MERGE,
            merge_claim_head=old_head,
            pr_number=1, pr_repo="fixture/repo",
            merge_claim_pr_number=1, merge_claim_pr_repo="fixture/repo",
            pr_base_sha="b" * 40, merge_claim_pr_base_sha="b" * 40,
            merge_claim_pid=99999999,
            merge_claim_start_ticks="dead-owner",
            merge_invocation_started=1,
        )
        self.adapter.merged_heads.add(old_head)
        self.adapter.heads = [new_head]

        self.supervisor.reconcile(self.spec.mission_id)
        self.assertEqual(
            self.supervisor.step(self.spec.mission_id, self.spec),
            State.BLOCKED_EXTERNAL,
        )
        self.assertEqual(self.adapter.merged_heads, {old_head})
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["merge_claim_head"], old_head)
        self.assertEqual(row["current_head"], new_head)

    def test_dead_merge_claim_is_reclaimed_only_after_canonical_not_started(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            pr_number=1, pr_repo="fixture/repo",
                            pr_base_sha="b" * 40,
                            merge_claim_head="a" * 40, merge_claim_pr_number=1,
                            merge_claim_pr_repo="fixture/repo", merge_claim_pr_base_sha="b" * 40,
                            merge_claim_pid=99999999,
                            merge_claim_start_ticks="dead-owner")
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(self.adapter.merged_heads, {"a" * 40})
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["merge_claim_head"])

    def test_unknown_merge_claim_identity_fails_closed(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
                            merge_claim_head="a" * 40, merge_claim_pid=None, merge_claim_start_ticks=None)
        self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_simulated_merge_failure_does_not_claim_external_merge_completed(self):
        adapter = SimulatedAdapter(merge=["BLOCKED_EXTERNAL"])
        result = adapter.merge("/fixture", "a" * 40, 7, "fixture/repo")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(adapter.merged_heads, set())
        self.assertEqual(adapter.merge_status("/fixture", "a" * 40, 7, "fixture/repo").status,
                         "NOT_STARTED")

    def test_unverifiable_live_merge_owner_claim_cannot_be_reclaimed(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=head,
            current_state=State.MERGE,
            merge_claim_head=head,
            merge_claim_pid=12345,
            merge_claim_start_ticks="owner-start",
        )
        with patch.object(
                self.journal, "_proc_identity", return_value=("UNKNOWN", None)):
            self.assertEqual(
                self.supervisor.step(self.spec.mission_id, self.spec),
                State.BLOCKED_EXTERNAL,
            )
        self.assertEqual(self.journal.mission(self.spec.mission_id)["merge_claim_head"], head)
        self.assertEqual(self.adapter.merged_heads, set())

    def test_journal_reclaim_returns_unknown_without_mutating_unverifiable_claim(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id,
            current_head=head,
            current_state=State.MERGE,
            merge_claim_head=head,
            merge_claim_pid=12345,
            merge_claim_start_ticks="owner-start",
        )
        recovery_pid, recovery_start = self.supervisor._merge_owner()
        with patch.object(
                self.journal, "_proc_identity", return_value=("UNKNOWN", None)):
            self.assertEqual(
                self.journal.claim_merge_recovery(
                    self.spec.mission_id, head, recovery_pid, recovery_start,
                ),
                "UNKNOWN",
            )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["merge_claim_head"], head)
        self.assertEqual(row["merge_claim_pid"], 12345)

    def test_football_adapter_review_fails_closed_instead_of_crashing(self):
        result = FootballPredictionAdapter().review("codex", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_football_adapter_private_evidence_directory_is_owner_only(self):
        path = Path(self.tmp.name) / "evidence"
        path.mkdir(mode=0o755)
        private = FootballPredictionAdapter._private_dir(path)
        self.assertEqual(private.stat().st_mode & 0o777, 0o700)

    def test_preflight_private_evidence_is_owner_only(self):
        result = self._prepare_agent_preflight(FootballPredictionAdapter(), self.worktree)
        self.assertEqual(result.status, "PASS")
        body_path = Path(result.data["env"]["PR_BODY"])
        self.assertEqual(body_path.read_text(encoding="utf-8"), "review context\n")
        self.assertEqual(body_path.stat().st_mode & 0o777, 0o600)
        for directory in (body_path.parent, body_path.parent.parent, body_path.parent.parent.parent):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_preflight_rejects_pr_change_between_discovery_and_body_fetch(self):
        adapter = FootballPredictionAdapter()
        discovery = {"number": 2, "repo": "owner/repo", "head": "a" * 40,
                     "base": "main", "base_sha": "c" * 40}
        for changed in ({"head": "b" * 40}, {"base_sha": "d" * 40},
                        {"state": "CLOSED"}):
            current = {**discovery, "state": "OPEN", "body": "stale\n", **changed}
            with self.subTest(changed=changed), \
                    patch.object(adapter, "discover_pr", return_value=GateResult(
                        "PASS", data=discovery)), \
                    patch.object(adapter, "_pr_state", return_value=GateResult(
                        "PASS", data=current)):
                result = adapter.prepare_gate(
                    "agent-preflight", worktree=str(self.worktree), base="c" * 40,
                    head="a" * 40, mission_id="safe-demo", scope_file="scope.json",
                )
                self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_preflight_rejects_a_different_review_base(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "discover_pr", return_value=GateResult(
                "PASS", data={"number": 2, "repo": "owner/repo", "head": "a" * 40,
                              "base": "main", "base_sha": "c" * 40})), \
                patch.object(adapter, "_pr_state", return_value=GateResult(
                    "PASS", data={"repo": "owner/repo", "head": "a" * 40,
                                  "base": "main", "base_sha": "c" * 40,
                                  "state": "OPEN", "body": "review context\n"})):
            result = adapter.prepare_gate(
                "agent-preflight", worktree=str(self.worktree), base="b" * 40,
                head="a" * 40, mission_id="safe-demo", scope_file="scope.json")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_worktree_git_config_cannot_hide_executable_filter(self):
        repo = Path(self.tmp.name) / "worktree-config-fixture"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "extensions.worktreeConfig", "true"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "--worktree",
                        "filter.fixture.process", "/bin/false"], check=True)
        with self.assertRaisesRegex(RuntimeError, "executable local Git configuration"):
            FootballPredictionAdapter._assert_safe_local_git_config(
                str(repo), FootballPredictionAdapter._trusted_git_environment())

    def test_review_path_rejects_an_untrusted_git_binary(self):
        adapter = FootballPredictionAdapter()
        with patch.object(FootballPredictionAdapter, "_validate_executable", side_effect=RuntimeError(
                "trusted executable has unsafe ownership or permissions")):
            with self.assertRaisesRegex(RuntimeError, "unsafe ownership"):
                adapter._trusted_review_path(str(self.worktree))

    def test_legacy_pr_adapter_receives_the_pinned_base(self):
        received = []

        def legacy(worktree, head, pr_number=None, pr_repo=None, base_sha=None):
            received.append(base_sha)

        Supervisor._invoke_pr_adapter(legacy, "/fixture", "a" * 40, 2,
                                      "owner/repo", pr_base_sha="b" * 40)
        self.assertEqual(received, ["b" * 40])

    def test_preflight_rejects_symlinked_evidence_root_without_writing_through(self):
        root = Path(self.tmp.name)
        victim = root / "victim-evidence"
        victim.mkdir(mode=0o700)
        marker = victim / "marker.txt"
        marker.write_text("untouched\n", encoding="utf-8")
        evidence_root = self.worktree.parent / ".cmh-gate-evidence"
        evidence_root.symlink_to(victim, target_is_directory=True)

        result = self._prepare_agent_preflight(FootballPredictionAdapter(), self.worktree)

        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched\n")
        self.assertFalse((victim / "safe-demo").exists())

    def test_preflight_rejects_symlinked_head_directory_without_writing_through(self):
        root = Path(self.tmp.name)
        evidence_root = self.worktree.parent / ".cmh-gate-evidence"
        mission_dir = evidence_root / "safe-demo"
        mission_dir.mkdir(parents=True, mode=0o700)
        victim = root / "victim-head"
        victim.mkdir(mode=0o700)
        marker = victim / "marker.txt"
        marker.write_text("untouched\n", encoding="utf-8")
        (mission_dir / ("a" * 40)).symlink_to(victim, target_is_directory=True)

        result = self._prepare_agent_preflight(FootballPredictionAdapter(), self.worktree)

        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(marker.read_text(encoding="utf-8"), "untouched\n")
        self.assertFalse((victim / "pr-body.md").exists())

    def test_preflight_rejects_symlinked_body_file_without_truncating_target(self):
        root = Path(self.tmp.name)
        body_directory = (
            self.worktree.parent / ".cmh-gate-evidence" / "safe-demo" / ("a" * 40)
        )
        body_directory.mkdir(parents=True, mode=0o700)
        victim = root / "victim-body.md"
        victim.write_text("untouched review body\n", encoding="utf-8")
        (body_directory / "pr-body.md").symlink_to(victim)

        result = self._prepare_agent_preflight(FootballPredictionAdapter(), self.worktree)

        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(victim.read_text(encoding="utf-8"), "untouched review body\n")

    def test_preflight_rejects_hardlinked_body_without_chmod_or_truncation(self):
        root=Path(self.tmp.name)
        body_directory=self.worktree.parent/'.cmh-gate-evidence'/'safe-demo'/('a'*40)
        body_directory.mkdir(parents=True,mode=0o700)
        victim=root/'unrelated.txt';victim.write_text('untouched data\n');victim.chmod(0o640)
        os.link(victim,body_directory/'pr-body.md')
        result=self._prepare_agent_preflight(FootballPredictionAdapter(),self.worktree)
        self.assertEqual(result.status,'BLOCKED_EXTERNAL')
        self.assertEqual(victim.read_text(),'untouched data\n')
        self.assertEqual(victim.stat().st_mode & 0o777,0o640)

    def test_private_writer_rejects_hardlink_before_mutating_inode(self):
        root=Path(self.tmp.name)
        victim=root/'unrelated.txt';victim.write_text('untouched data\n');victim.chmod(0o640)
        alias=root/'linked-evidence';os.link(victim,alias)
        with self.assertRaisesRegex(RuntimeError,'single-link'):
            FootballPredictionAdapter._write_private_file(alias,'replacement')
        self.assertEqual(victim.read_text(),'untouched data\n')
        self.assertEqual(victim.stat().st_mode & 0o777,0o640)

    def test_pr_discovery_without_open_pr_is_retryable(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_run", side_effect=[
                "https://github.com/owner/project.git", "feature", "[]",
        ]):
            result = adapter.discover_pr("/worktree", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertTrue(result.data["retryable"])

    def test_retryable_pr_discovery_remains_pending_and_retries(self):
        head = "a" * 40
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
        )
        pending = GateResult("BLOCKED_EXTERNAL", "GitHub temporarily unavailable",
                             data={"retryable": True})
        found = GateResult("PASS", "fixture PR", data={
            "number": 9, "repo": "fixture/repo", "head": head,
            "base": "main", "state": "OPEN", "base_sha": "b" * 40,
        })
        with patch.object(self.adapter, "discover_pr", side_effect=[pending, found]) as discover:
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.MERGE)
            row = self.journal.mission(self.spec.mission_id)
            self.assertEqual(row["pending_gate"], "pr-discovery")
            self.assertIsNone(row["terminal_state"])
            self.assertEqual(self.supervisor.step(self.spec.mission_id, self.spec), State.POST_MERGE)
        self.assertEqual(discover.call_count, 2)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["pr_number"], 9)
        self.assertEqual(row["pr_base_sha"], "b" * 40)

    def test_football_review_preflight_requires_both_commits(self):
        adapter = FootballPredictionAdapter()
        missing = subprocess.CompletedProcess([], 1, "", "")
        present = subprocess.CompletedProcess([], 0, "", "")
        for probes in ((missing, present), (present, missing)):
            with self.subTest(missing="base" if probes[0] is missing else "head"), \
                    patch.object(adapter, "_call", side_effect=probes) as call:
                result = adapter.review_preflight("/fixture", "a" * 40, "b" * 40)
            self.assertEqual(result.status, "BLOCKED_EXTERNAL")
            self.assertIn("commit is unavailable", result.evidence)
            self.assertEqual(call.call_count, 1 if probes[0] is missing else 2)

    def test_football_review_preflight_accepts_available_commits(self):
        adapter = FootballPredictionAdapter()
        present = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(adapter, "_call", side_effect=[present, present]):
            result = adapter.review_preflight("/fixture", "a" * 40, "b" * 40)
        self.assertEqual(result.status, "PASS")
        self.assertIn("trusted base", result.evidence)

    def test_football_review_executes_policy_from_trusted_base_checkout(self):
        adapter, worktree, evidence, _, _ = self._review_fixture()
        trusted = Path(self.tmp.name) / "trusted-base"
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted):
            argv = adapter.review_argv(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                evidence_dir=str(evidence), attempt_id="a" * 32,
            )
        self.assertTrue(Path(argv[0]).is_absolute())
        self.assertEqual(argv[1:4], [
            "-I", "-B", str(trusted / "scripts/devops/codex_independent_review.py"),
        ])
        self.assertNotIn("/usr/bin/env", argv)
        self.assertEqual(argv[argv.index("--repo-root") + 1], str(worktree))
        self.assertEqual(argv[argv.index("--run-id") + 1], "a" * 32)
        self.assertIn("--json", argv)
        self.assertIn("run", argv)

    def test_trusted_python_interpreter_uses_system_path_when_running_python_is_untrusted(self):
        adapter = FootballPredictionAdapter()
        system_python = Path("/usr/bin/python3")
        if not system_python.exists():
            self.skipTest("system Python interpreter is unavailable")
        with patch("harness.adapters.sys.executable", "/tmp/untrusted/python3"), \
                patch("harness.adapters.shutil.which", return_value=str(system_python)):
            resolved = adapter._trusted_python_interpreter()
        self.assertEqual(resolved, str(system_python.resolve(strict=True)))

    def test_review_scope_git_uses_validated_system_path_without_worktree_entries(self):
        adapter = FootballPredictionAdapter()
        root = Path(self.tmp.name) / "scope-root"
        root.mkdir()
        (root / "scope.json").write_bytes(b"committed scope")
        head = "a" * 40
        with patch.object(adapter, "_trusted_system_path", return_value="/usr/bin:/bin"), \
                patch("harness.adapters.subprocess.check_output",
                      side_effect=[head + "\n", b"committed scope"]) as check_output:
            scope = adapter.review_scope_file(str(root), head, "scope.json")
        self.assertEqual(scope, root / "scope.json")
        self.assertEqual(len(check_output.call_args_list), 2)
        for call in check_output.call_args_list:
            path = call.kwargs["env"]["PATH"].split(os.pathsep)
            self.assertEqual(path, ["/usr/bin", "/bin"])
            self.assertNotIn("", path)
            self.assertNotIn(str(root), path)

    def test_review_environment_filters_ambient_execution_and_git_variables(self):
        adapter = FootballPredictionAdapter()
        worktree = Path(self.tmp.name) / "review-target"
        worktree.mkdir(exist_ok=True)
        codex_home = Path(self.tmp.name) / ".footballprediction" / "canonical-codex-reviewer"
        codex_home.mkdir(mode=0o700, parents=True)
        codex_home.chmod(0o700)
        auth_file = codex_home / "auth.json"
        auth_file.write_text("credential-content-must-never-leak", encoding="utf-8")
        auth_file.chmod(0o600)
        trusted = self._trusted_codex_policy_fixture(Path(self.tmp.name), codex_home)
        attacker_bin = Path(self.tmp.name) / "attacker-bin"
        attacker_bin.mkdir(mode=0o777)
        attacker_bin.chmod(0o777)
        hostile = {
            "PATH": os.pathsep.join((str(attacker_bin), "/usr/bin")),
            "CODEX_HOME": str(attacker_bin),
            "CODEX_API_KEY": "builder-codex-key",
            "OPENAI_API_KEY": "must-not-be-inherited",
            "OPENAI_BASE_URL": "https://builder-provider.invalid/v1",
            "OPENAI_MODEL": "builder-model",
            "CLIPROXY_BASE_URL": "https://builder-proxy.invalid/v1",
            "GIT_DIR": "/attacker/repo.git",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
            "PYTHONPATH": "/attacker/python",
            "PYTHONHOME": "/attacker/python-home",
            "CODEX_CLI_PATH": "/attacker/codex",
            "OPENAI_API_KEY": "must-not-be-inherited",
            "HTTPS_PROXY": "http://proxy.example.invalid:8080",
        }
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_trusted_python_interpreter",
                             return_value=str(Path("/usr/bin/python3").resolve(strict=True))), \
                patch.object(adapter, "_trusted_review_path", return_value="/usr/bin"), \
                patch.object(adapter, "_call", wraps=adapter._call) as policy_call, \
                patch.dict(os.environ, hostile, clear=True):
            environment = adapter.review_environment("codex", worktree=str(worktree), base="a" * 40)
            policy = adapter._canonical_codex_reviewer_policy(
                worktree=str(worktree), base="a" * 40,
            )

        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["CODEX_HOME"], str(codex_home))
        self.assertNotEqual(environment["CODEX_HOME"], hostile["CODEX_HOME"])
        self.assertEqual(environment["HTTPS_PROXY"], hostile["HTTPS_PROXY"])
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "PYTHONPATH",
                     "PYTHONHOME", "CODEX_CLI_PATH", "CODEX_API_KEY", "OPENAI_API_KEY",
                     "OPENAI_BASE_URL", "OPENAI_MODEL", "CLIPROXY_BASE_URL"):
            self.assertNotIn(name, environment)
        self.assertNotIn("credential-content-must-never-leak", repr(environment))
        self.assertNotIn("credential-content-must-never-leak", repr(policy_call.call_args))
        self.assertEqual(policy["codex_binary"], "/usr/bin/python3")
        self.assertTrue(Path(policy["codex_binary"]).is_absolute())
        self.assertEqual((policy["model"], policy["reasoning_effort"]), ("gpt-5.6-sol", "high"))
        with patch.object(adapter, "_trusted_review_path", return_value="/usr/bin"):
            deepseek_env = adapter.review_environment("deepseek", worktree=str(worktree))
        self.assertNotIn("CODEX_HOME", deepseek_env)
        with self.assertRaisesRegex(ValueError, "unsupported independent reviewer"):
            adapter.review_environment("other", worktree=str(worktree), base="a" * 40)

    def test_codex_review_environment_fails_closed_when_canonical_home_is_missing(self):
        adapter = FootballPredictionAdapter()
        worktree = Path(self.tmp.name) / "missing-home-review-target"
        worktree.mkdir()
        missing_home = Path(self.tmp.name) / "missing-canonical-reviewer-home"
        trusted = self._trusted_codex_policy_fixture(Path(self.tmp.name), missing_home)
        hostile = {"CODEX_HOME": str(Path(self.tmp.name) / "builder-home")}
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_trusted_python_interpreter",
                             return_value=str(Path("/usr/bin/python3").resolve(strict=True))), \
                patch.object(adapter, "_trusted_review_path", return_value="/usr/bin"), \
                patch.dict(os.environ, hostile, clear=True):
            with self.assertRaisesRegex(RuntimeError, "CODEX_HOME or auth metadata is unavailable"):
                adapter.review_environment("codex", worktree=str(worktree), base="a" * 40)

        invalid_home = Path(self.tmp.name) / "invalid-canonical-reviewer-home"
        invalid_home.mkdir(mode=0o755)
        invalid_home.chmod(0o755)
        auth = invalid_home / "auth.json"
        auth.write_text("fixture", encoding="utf-8")
        auth.chmod(0o600)
        trusted = self._trusted_codex_policy_fixture(Path(self.tmp.name), invalid_home)
        with patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_trusted_python_interpreter",
                             return_value=str(Path("/usr/bin/python3").resolve(strict=True))), \
                patch.object(adapter, "_trusted_review_path", return_value="/usr/bin"), \
                patch.dict(os.environ, hostile, clear=True):
            with self.assertRaisesRegex(RuntimeError, "CODEX_HOME must be owner-only"):
                adapter.review_environment("codex", worktree=str(worktree), base="a" * 40)

    def test_codex_home_must_not_overlap_reviewed_worktree(self):
        root = Path(self.tmp.name)

        def make_home(path: Path) -> Path:
            path.mkdir(mode=0o700, parents=True)
            path.chmod(0o700)
            auth = path / "auth.json"
            auth.write_text("fixture", encoding="utf-8")
            auth.chmod(0o600)
            return path

        worktree = root / "review-target"
        worktree.mkdir()
        nested_home = make_home(worktree / ".codex")
        with self.assertRaisesRegex(RuntimeError, "must remain outside"):
            FootballPredictionAdapter._validate_canonical_codex_home(
                str(nested_home), worktree=str(worktree),
            )

        containing_home = make_home(root / "codex-home")
        nested_worktree = containing_home / "review-target"
        nested_worktree.mkdir()
        with self.assertRaisesRegex(RuntimeError, "must remain outside"):
            FootballPredictionAdapter._validate_canonical_codex_home(
                str(containing_home), worktree=str(nested_worktree),
            )

    def test_authority_call_ignores_ambient_path_and_execution_overrides(self):
        adapter = FootballPredictionAdapter()
        attacker_bin = Path(self.tmp.name) / "attacker-bin"
        attacker_bin.mkdir()
        fake_gh = attacker_bin / "gh"
        fake_gh.write_text("#!/bin/sh\nprintf forged\n", encoding="utf-8")
        fake_gh.chmod(0o755)
        hostile = {
            "PATH": str(attacker_bin),
            "HOME": str(Path.home()),
            "GH_HOST": "api.attacker.invalid",
            "GH_REPO": "attacker/forged",
            "GH_TOKEN": "test-only-token",
            "GIT_DIR": "/attacker/repo.git",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
            "PYTHONPATH": "/attacker/python",
            "PYTHONHOME": "/attacker/python-home",
            "LD_PRELOAD": "/attacker/lib.so",
            "OPENAI_API_KEY": "must-not-be-inherited",
        }
        completed = subprocess.CompletedProcess([], 0, "trusted response", "")
        with patch.dict(os.environ, hostile, clear=True), \
                patch("harness.adapters.subprocess.run", return_value=completed) as run:
            result = adapter._call(
                ["gh", "api", "repos/owner/repo"], cwd=self.tmp.name,
                env={"PATH": str(attacker_bin), "GH_REPO": "owner/repo"},
            )

        self.assertEqual(result.returncode, 0)
        argv = run.call_args.args[0]
        child_env = run.call_args.kwargs["env"]
        self.assertEqual(argv[0], adapter._trusted_system_executable("gh"))
        self.assertNotEqual(argv[0], str(fake_gh))
        self.assertEqual(child_env["PATH"], adapter._trusted_system_path())
        self.assertEqual(child_env["GH_HOST"], "github.com")
        self.assertEqual(child_env["GH_REPO"], "owner/repo")
        # GitHub auth may flow to the verified gh binary; arbitrary execution
        # controls and unrelated API credentials must not.
        self.assertEqual(child_env["GH_TOKEN"], "test-only-token")
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                     "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "OPENAI_API_KEY"):
            self.assertNotIn(name, child_env)
        self.assertEqual(child_env["GIT_CONFIG_COUNT"], "0")

    def test_run_uses_trusted_absolute_executable_and_filtered_environment(self):
        adapter = FootballPredictionAdapter()
        attacker_bin = Path(self.tmp.name) / "attacker-bin"
        attacker_bin.mkdir()
        fake_git = attacker_bin / "git"
        fake_git.write_text("#!/bin/sh\nprintf forged\n", encoding="utf-8")
        fake_git.chmod(0o755)
        hostile = {
            "PATH": str(attacker_bin),
            "HOME": str(Path.home()),
            "GH_TOKEN": "test-only-token",
            "GIT_DIR": "/attacker/repo.git",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "PYTHONPATH": "/attacker/python",
        }
        with patch.dict(os.environ, hostile, clear=True), \
                patch("harness.adapters.subprocess.check_output", return_value="main\n") as check_output:
            result = adapter._run(["git", "branch", "--show-current"], cwd=self.tmp.name)

        self.assertEqual(result, "main\n")
        argv = check_output.call_args.args[0]
        child_env = check_output.call_args.kwargs["env"]
        self.assertEqual(argv[0], adapter._trusted_system_executable("git"))
        self.assertNotEqual(argv[0], str(fake_git))
        self.assertEqual(child_env["PATH"], adapter._trusted_system_path())
        self.assertEqual(child_env["GH_TOKEN"], "test-only-token")
        for name in ("GIT_DIR", "GIT_CONFIG_KEY_0", "PYTHONPATH"):
            self.assertNotIn(name, child_env)
        self.assertEqual(child_env["GIT_CONFIG_COUNT"], "0")

    def test_trusted_git_output_ignores_ambient_git_overrides(self):
        adapter = FootballPredictionAdapter()
        hostile = {
            "GIT_DIR": "/attacker/repo.git",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_REPLACE_REF_BASE": "refs/replace-attacker/",
        }
        expected = subprocess.CompletedProcess([], 0, "committed scope\n", "")
        with patch.dict(os.environ, hostile), patch.object(adapter, "_call", return_value=expected) as call:
            self.assertEqual(adapter._trusted_git_output(Path(self.tmp.name), "show", "HEAD:scope.json"),
                             "committed scope\n")
        self.assertIn("--no-replace-objects", call.call_args.args[0])
        self.assertFalse(call.call_args.kwargs["inherit_environment"])
        self.assertNotIn("GIT_DIR", call.call_args.kwargs["env"])
        self.assertNotIn("GIT_WORK_TREE", call.call_args.kwargs["env"])
        self.assertNotIn("GIT_CONFIG_KEY_0", call.call_args.kwargs["env"])
        self.assertEqual(call.call_args.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_codex_receipt_classifier_imports_policy_from_trusted_base(self):
        adapter, worktree, evidence_dir, receipt, stdout = self._review_fixture()
        trusted = Path(self.tmp.name) / "trusted-base"
        classified = subprocess.CompletedProcess(
            [], 0, json.dumps({"classification": {"classification": "VALID_CURRENT"},
                               "receipt": {"review_result": "PASS", "findings": []}}), "",
        )
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "review_environment", return_value={"PATH": "/usr/bin"}), \
                patch.object(adapter, "_call", return_value=classified) as call:
            result = adapter.review_result(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "PASS")
        self.assertEqual(call.call_args.kwargs["cwd"], str(trusted))

    def test_codex_review_verdict_comes_from_validated_receipt_not_stdout(self):
        adapter, worktree, evidence_dir, receipt, stdout = self._review_fixture()
        trusted = Path(self.tmp.name) / "trusted-base"
        cases = (
            ("PASS", "FAIL", "FAIL"),
            ("FAIL", "PASS", "PASS"),
        )
        for payload_status, receipt_verdict, expected in cases:
            with self.subTest(payload_status=payload_status, receipt_verdict=receipt_verdict):
                stdout.write_text(json.dumps({"review_receipt": str(receipt), "status": payload_status}))
                classified = subprocess.CompletedProcess(
                    [], 0, json.dumps({
                        "classification": {"classification": "VALID_CURRENT"},
                        "receipt": {"review_result": receipt_verdict, "findings": []},
                    }), "",
                )
                with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                        patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                        patch.object(adapter, "review_environment", return_value={"PATH": "/usr/bin"}), \
                        patch.object(adapter, "_call", return_value=classified):
                    result = adapter.review_result(
                        "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                        mission_id="mission", scope_file=str(worktree / "scope.json"),
                        stdout_path=str(stdout), evidence_dir=str(evidence_dir),
                    )
                self.assertEqual(result.status, expected)
                self.assertIsNone(result.failure_classification)

    def test_codex_classifier_without_receipt_verdict_fails_closed(self):
        adapter, worktree, evidence_dir, receipt, stdout = self._review_fixture()
        trusted = Path(self.tmp.name) / "trusted-base"
        classified = subprocess.CompletedProcess(
            [], 0, json.dumps({"classification": {"classification": "VALID_CURRENT"}}), "",
        )
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "review_environment", return_value={"PATH": "/usr/bin"}), \
                patch.object(adapter, "_call", return_value=classified):
            result = adapter.review_result(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_receiptless_codex_failures_get_typed_classification_and_private_evidence(self):
        cases = (
            ("capacity", "Selected model is at capacity; access_token=fixture-secret",
             ReviewFailureClassification.TRANSIENT_CAPACITY, True),
            ("timeout", "request timeout while waiting for response",
             ReviewFailureClassification.TRANSIENT_TRANSPORT, True),
            ("reset", "connection reset by peer",
             ReviewFailureClassification.TRANSIENT_TRANSPORT, True),
            ("auth", "token_revoked: HTTP 401",
             ReviewFailureClassification.AUTHENTICATION_FAILURE, False),
            ("unsupported", "unsupported model gpt-5.6-sol",
             ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED, False),
            ("reconnect", "reconnecting after WebSocket failure; no turn.completed",
             ReviewFailureClassification.TRANSIENT_TRANSPORT, True),
        )
        for attempt_number, (name, message, classification, retryable) in enumerate(cases, 1):
            with self.subTest(name=name):
                attempt_id = f"{attempt_number:032x}"
                result, event_path = self._receiptless_codex_attempt(
                    error=message,
                    events=[{"type": "turn.failed", "error": {"message": message}}],
                    attempt_id=attempt_id,
                )
                self.assertEqual(result.status, "BLOCKED_EXTERNAL")
                self.assertIsNone(result.artifact)
                self.assertEqual(result.failure_classification, classification)
                self.assertEqual(classification.retryable, retryable)
                evidence_path = Path(result.data["failure_evidence_path"])
                evidence_bytes = evidence_path.read_bytes()
                evidence = json.loads(evidence_bytes)
                self.assertEqual(
                    hashlib.sha256(evidence_bytes).hexdigest(),
                    result.data["failure_evidence_sha256"],
                )
                self.assertEqual(evidence["schema_version"], "cmh-review-attempt-failure/v1")
                self.assertEqual(evidence["repository"], "owner/project")
                self.assertEqual(evidence["mission_id"], "mission")
                self.assertEqual(evidence["base_sha"], "a" * 40)
                self.assertEqual(evidence["head_sha"], "b" * 40)
                self.assertEqual(evidence["model"], "gpt-5.6-sol")
                self.assertEqual(evidence["reasoning_effort"], "high")
                self.assertEqual(evidence["codex_home"], "/private/canonical-codex-reviewer")
                self.assertEqual(evidence["codex_binary"], "/usr/lib/chatgpt/resources/codex")
                self.assertEqual(evidence["stage"], "review")
                self.assertEqual(evidence["attempt_id"], attempt_id)
                self.assertEqual(evidence["terminal_status"], "EXITED")
                self.assertEqual(evidence["failure_classification"], classification.value)
                self.assertEqual(evidence["retryable"], retryable)
                self.assertEqual(evidence["event_log"]["path"], str(event_path))
                self.assertEqual(
                    evidence["event_log"]["sha256"],
                    hashlib.sha256(event_path.read_bytes()).hexdigest(),
                )
                self.assertNotIn("fixture-secret", evidence_bytes.decode("utf-8"))
                self.assertNotIn("access_token", evidence_bytes.decode("utf-8"))

    def test_codex_failure_evidence_classifies_flat_events_and_process_stderr(self):
        cases = (
            (
                "flat_capacity", "outer reviewer exited 1",
                [{"type": "error", "status": 429, "code": "overloaded_error",
                  "message": "Selected model is at capacity"}], "",
                ReviewFailureClassification.TRANSIENT_CAPACITY, True, 429,
                "overloaded_error",
                "provider returned HTTP 429; provider capacity is temporarily unavailable",
            ),
            (
                "flat_auth", "outer reviewer exited 1",
                [{"type": "error", "status": 401, "code": "token_revoked",
                  "message": "authorization failed"}], "",
                ReviewFailureClassification.AUTHENTICATION_FAILURE, False, 401,
                "token_revoked", "provider returned HTTP 401; provider rejected reviewer authentication",
            ),
            (
                "flat_model", "outer reviewer exited 1",
                [{"type": "turn.failed", "error": {
                    "code": "unsupported_model", "message": "model not supported",
                }}], "",
                ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED, False, None,
                "unsupported_model", "requested reviewer model is unavailable or unsupported",
            ),
            (
                "stderr_transport", "outer reviewer exited 1", [],
                "request timeout; ETIMEDOUT while connecting",
                ReviewFailureClassification.TRANSIENT_TRANSPORT, True, None,
                "etimedout", "reviewer provider transport was interrupted",
            ),
            (
                "local_cli", "outer reviewer exited 1", [],
                "error: unexpected argument --ask-for-approval",
                ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE, False, None,
                None, "review request or receipt contract was rejected",
            ),
            (
                "opaque", "outer reviewer exited 1", [], "opaque subprocess failure",
                ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE, False, None,
                None, "reviewer failure did not match a known safe diagnostic",
            ),
        )
        for attempt_number, (name, wrapper_error, events, stderr, classification,
                             retryable, http_status, provider_code, diagnostic) in enumerate(cases, 20):
            with self.subTest(name=name):
                result, _ = self._receiptless_codex_attempt(
                    error=wrapper_error, events=events,
                    attempt_id=f"{attempt_number:032x}", stderr=stderr,
                )
                self.assertEqual(result.status, "BLOCKED_EXTERNAL")
                self.assertIsNone(result.artifact)
                self.assertEqual(result.failure_classification, classification)
                self.assertEqual(result.data["retryable"], retryable)
                record = json.loads(Path(result.data["failure_evidence_path"]).read_text())
                self.assertEqual(record["failure_classification"], classification.value)
                self.assertEqual(record["retryable"], retryable)
                self.assertEqual(record["http_status"], http_status)
                self.assertEqual(record["provider_error_code"], provider_code)
                self.assertEqual(record["sanitized_diagnostic"], diagnostic)
                self.assertEqual(record["turn_completed"], False)
                self.assertEqual(record["exit_code"], 1)

    def test_codex_failure_evidence_never_echoes_secret_diagnostic(self):
        secret = "sk-fixture-secret-never-persist"
        result, _ = self._receiptless_codex_attempt(
            error=f"Selected model is at capacity; bearer {secret}",
            events=[{"type": "error", "message": f"capacity; access_token={secret}"}],
            attempt_id="f" * 32,
        )
        evidence_path = Path(result.data["failure_evidence_path"])
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
        self.assertEqual(result.failure_classification,
                         ReviewFailureClassification.TRANSIENT_CAPACITY)
        self.assertEqual(evidence["sanitized_diagnostic"],
                         "provider capacity is temporarily unavailable")
        self.assertNotIn(secret.encode(), evidence_bytes)
        self.assertNotIn(b"bearer", evidence_bytes.lower())
        self.assertNotIn(b"access_token", evidence_bytes.lower())

    def test_codex_nonzero_generic_schema_text_is_unknown_process_failure(self):
        secret = "sk-fixture-process-secret"
        result, _ = self._receiptless_codex_attempt(
            error=f"structured output schema validation failed; {secret}",
            events=[{"type": "error", "message": "invalid JSON"}],
            attempt_id="e" * 32,
        )
        self.assertEqual(result.failure_classification,
                         ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE)
        self.assertFalse(result.data["retryable"])
        raw = Path(result.data["failure_evidence_path"]).read_bytes()
        record = json.loads(raw)
        self.assertEqual(record["failure_phase"], "PROCESS_OR_PROVIDER")
        self.assertFalse(record["process_succeeded"])
        self.assertEqual(record["exit_code"], 1)
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(b"structured output schema", raw)

    def _deepseek_receiptless_wrapper_result(self, *, tamper_sidecar=False,
                                             mismatched_attempt=False):
        adapter, worktree, evidence_dir, _, stdout = self._review_fixture("deepseek")
        attempt_id = "e" * 32
        run_dir = evidence_dir / attempt_id
        run_dir.mkdir(mode=0o700)
        run_dir.chmod(0o700)
        failure_path = run_dir / f"review-attempt-failure-aggregate-{attempt_id}.json"
        failure = {
            "schema_version": "cmh-review-attempt-failure/v1",
            "repository": "ssh://github.com/owner/project.git",
            "mission_id": "mission",
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "diff_sha256": "c" * 64,
            "reviewer": "deepseek",
            "provider": "deepseek",
            "model": "deepseek-flash",
            "reasoning_effort": None,
            "attempt_id": attempt_id,
            "stage": "aggregate",
            "chunk_index": None,
            "terminal_status": "EXITED",
            "exit_code": 1,
            "turn_completed": None,
            "started_at": 10.0,
            "completed_at": 11.0,
            "failure_classification": "TRANSIENT_CAPACITY",
            "retryable": True,
            "reason_code": "provider_capacity",
            "http_status": 429,
            "provider_error_code": "rate_limit_error",
            "sanitized_diagnostic": "provider capacity is temporarily unavailable",
            "process_stdout_sha256": "d" * 64,
            "process_stderr_sha256": "f" * 64,
            "command_sha256": "1" * 64,
            "completed_chunk_artifacts": [],
            "receipt_written": False,
        }
        failure["integrity_sha256"] = hashlib.sha256(json.dumps(
            failure, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        raw = (json.dumps(failure, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self._write_private_review_log(failure_path, raw)
        expected_sha = hashlib.sha256(raw).hexdigest()
        if tamper_sidecar:
            failure_path.write_text("{}", encoding="utf-8")
            failure_path.chmod(0o600)
        self._write_private_review_log(stdout, json.dumps({
            "status": "BLOCKED_EXTERNAL",
            "error": "provider capacity is temporarily unavailable",
            "failure_classification": "TRANSIENT_CAPACITY",
            "retryable": True,
            "failure_evidence_path": str(failure_path),
            "failure_evidence_sha256": expected_sha,
        }) + "\n")
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_repo_from_origin", return_value="owner/project"):
            result = adapter.review_result(
                "deepseek", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
                attempt_id=("9" if mismatched_attempt else "e") * 32,
                terminal_status="EXITED", exit_code=1,
            )
        return result

    def test_deepseek_typed_failure_requires_valid_bound_artifact_and_drives_retry(self):
        valid = self._deepseek_receiptless_wrapper_result()
        self.assertEqual(valid.status, "BLOCKED_EXTERNAL")
        self.assertEqual(valid.failure_classification, ReviewFailureClassification.TRANSIENT_CAPACITY)
        self.assertTrue(valid.data["retryable"])
        self.assertEqual(valid.data["wrapper_failure"]["stage"], "aggregate")
        self.assertEqual(valid.data["wrapper_failure"]["diff_sha256"], "c" * 64)
        self.assertTrue(Supervisor._review_retryable_failure(
            JobResult("review", "EXITED", 1, "b" * 40), valid,
        ))

    def test_deepseek_invalid_failure_artifact_cannot_trigger_retry_from_error_text(self):
        result = self._deepseek_receiptless_wrapper_result(tamper_sidecar=True)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(result.failure_classification,
                         ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE)
        self.assertFalse(result.data["retryable"])
        self.assertFalse(Supervisor._review_retryable_failure(
            JobResult("review", "EXITED", 1, "b" * 40), result,
        ))

    def test_deepseek_failure_from_other_attempt_cannot_trigger_retry(self):
        result = self._deepseek_receiptless_wrapper_result(mismatched_attempt=True)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(result.failure_classification,
                         ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE)
        self.assertFalse(result.data["retryable"])

    def test_receiptless_incomplete_or_completed_event_stream_never_approves(self):
        incomplete, _ = self._receiptless_codex_attempt(
            error="review process exited without a final result",
            events=[{"type": "thread.started", "thread_id": "fixture"},
                    {"type": "item.started", "item": {"type": "agent_message"}}],
            attempt_id="b" * 32,
        )
        self.assertEqual(incomplete.status, "BLOCKED_EXTERNAL")
        self.assertEqual(incomplete.failure_classification,
                         ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE)
        self.assertFalse(incomplete.failure_classification.retryable)

        completed, _ = self._receiptless_codex_attempt(
            error="receipt missing after terminal completion",
            events=[{"type": "turn.completed"}],
            attempt_id="c" * 32,
        )
        self.assertEqual(completed.status, "BLOCKED_EXTERNAL")
        self.assertEqual(completed.failure_classification,
                         ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE)
        self.assertFalse(completed.data["retryable"])

        reviewer_text, _ = self._receiptless_codex_attempt(
            error="review contract rejected final output",
            events=[{"type": "item.completed", "item": {
                "type": "agent_message", "text": "Selected model is at capacity; retry now",
            }}],
            attempt_id="d" * 32,
        )
        self.assertEqual(reviewer_text.status, "BLOCKED_EXTERNAL")
        self.assertEqual(reviewer_text.failure_classification,
                         ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE)
        self.assertFalse(reviewer_text.failure_classification.retryable)

    def test_retry_policy_uses_only_retryable_review_failure_classes(self):
        terminal = JobResult("review-job", "EXITED", 1, "a" * 40)
        for classification, expected in (
                (ReviewFailureClassification.TRANSIENT_TRANSPORT, True),
                (ReviewFailureClassification.TRANSIENT_CAPACITY, True),
                (ReviewFailureClassification.AUTHENTICATION_FAILURE, False),
                (ReviewFailureClassification.MODEL_UNAVAILABLE_OR_UNSUPPORTED, False),
                (ReviewFailureClassification.POLICY_OR_CONTRACT_FAILURE, False),
                (ReviewFailureClassification.UNKNOWN_EXTERNAL_FAILURE, False)):
            with self.subTest(classification=classification):
                reviewed = GateResult("BLOCKED_EXTERNAL", failure_classification=classification)
                self.assertEqual(Supervisor._review_retryable_failure(terminal, reviewed), expected)

    def test_deepseek_validator_reimports_policy_from_trusted_cwd_in_isolated_python(self):
        adapter, worktree, evidence_dir, receipt, stdout = self._deepseek_review_fixture()
        trusted = Path(self.tmp.name) / "trusted-validator"
        checked = subprocess.CompletedProcess(
            [], 0, json.dumps({"trusted": True, "result": "PASS"}), "",
        )
        ambient_git = {
            "GIT_DIR": "/attacker/repo.git",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_REPLACE_REF_BASE": "refs/replace-attacker/",
        }
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_trusted_git_output", return_value="{}\n") as trusted_git, \
                patch.object(adapter, "_call", return_value=checked) as validator_call, \
                patch.dict(os.environ, ambient_git):
            result = adapter.review_result(
                "deepseek", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "PASS")
        trusted_git.assert_called_once()
        self.assertEqual(trusted_git.call_args.args[1:], ("show", f"{'b' * 40}:scope.json"))
        self.assertFalse(validator_call.call_args.kwargs["inherit_environment"])
        self.assertEqual(validator_call.call_args.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
        for name in ambient_git.keys() - {"GIT_CONFIG_COUNT"}:
            self.assertNotIn(name, validator_call.call_args.kwargs["env"])
        self.assertEqual(validator_call.call_args.kwargs["env"]["GIT_CONFIG_COUNT"], "0")

    def test_deepseek_validator_rejects_non_object_output_without_crashing(self):
        adapter, worktree, evidence_dir, _, stdout = self._deepseek_review_fixture()
        trusted = Path(self.tmp.name) / "trusted-validator"
        checked = subprocess.CompletedProcess([], 0, "[]", "")
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_call", return_value=checked), \
                patch.object(adapter, "_trusted_git_output", return_value="{}\n"):
            result = adapter.review_result(
                "deepseek", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_trusted_base_checkout_rejects_preexisting_unregistered_clone(self):
        adapter = FootballPredictionAdapter()
        repo, base = self._target_git_repo()
        preexisting = repo.parent / ".cmh-trusted-base" / base
        preexisting.parent.mkdir(mode=0o700, parents=True)
        subprocess.run(["git", "clone", "-q", str(repo), str(preexisting)], check=True)
        with self.assertRaisesRegex(RuntimeError, "registered detached worktree"):
            adapter._trusted_base_checkout(str(repo), base)

    def test_trusted_base_checkout_ignores_ambient_git_repository_and_config(self):
        adapter = FootballPredictionAdapter()
        repo, base = self._target_git_repo()
        attacker = Path(self.tmp.name) / "ambient-git-repository"
        attacker.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(attacker)], check=True)
        subprocess.run(["git", "-C", str(attacker), "config", "user.name", "Attacker"], check=True)
        subprocess.run(["git", "-C", str(attacker), "config", "user.email", "attacker@example.invalid"], check=True)
        (attacker / "untrusted.txt").write_text("ambient repository\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(attacker), "add", "untrusted.txt"], check=True)
        subprocess.run(["git", "-C", str(attacker), "commit", "-qm", "attacker repository"], check=True)
        hostile_environment = {
            "GIT_DIR": str(attacker / ".git"),
            "GIT_WORK_TREE": str(attacker),
            "GIT_INDEX_FILE": str(attacker / ".git" / "attacker-index"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.bare",
            "GIT_CONFIG_VALUE_0": "true",
        }
        with patch.dict(os.environ, hostile_environment):
            trusted = adapter._trusted_base_checkout(str(repo), base)
        self.assertEqual(subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(trusted), "rev-parse", "HEAD"],
            text=True,
        ).strip(), base)
        self.assertEqual((trusted / "Makefile").read_text(encoding="utf-8"), "all:\n\t@true\n")

    def test_trusted_base_checkout_detects_hidden_policy_file_edit(self):
        adapter = FootballPredictionAdapter()
        repo, base = self._target_git_repo()
        trusted = adapter._trusted_base_checkout(str(repo), base)
        makefile = trusted / "Makefile"
        makefile.write_text("all:\n\t@echo untrusted\n")
        subprocess.run(["git", "update-index", "--assume-unchanged", "Makefile"], cwd=trusted, check=True)
        self.assertEqual(subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=trusted, text=True,
        ), "")
        with self.assertRaisesRegex(RuntimeError, "content differs from the commit"):
            adapter._trusted_base_checkout(str(repo), base)

    def test_trusted_base_verifies_scripts_beyond_explicit_contract_paths(self):
        adapter = FootballPredictionAdapter()
        repo, _ = self._target_git_repo()
        extra = repo / "scripts/devops/pr_ready_check.py"
        extra.write_text("# committed extra script\n")
        subprocess.run(["git", "add", str(extra.relative_to(repo))], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "extra trusted script"], cwd=repo, check=True)
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        trusted = adapter._trusted_base_checkout(str(repo), base)
        self.assertEqual((trusted / extra.relative_to(repo)).read_bytes(), extra.read_bytes())
        (trusted / extra.relative_to(repo)).write_text("# changed\n")
        subprocess.run(["git", "update-index", "--assume-unchanged",
                        str(extra.relative_to(repo))], cwd=trusted, check=True)
        with self.assertRaisesRegex(RuntimeError, "content differs from the commit"):
            adapter._trusted_base_checkout(str(repo), base)

    def test_untrusted_stdout_cannot_redirect_receipt_validation_code(self):
        adapter, worktree, evidence_dir, _, stdout = self._review_fixture()
        external_receipt = Path(self.tmp.name) / "outside-receipt.json"
        external_receipt.write_text("{}")
        stdout.write_text(json.dumps({"review_receipt": str(external_receipt), "status": "PASS"}))
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout") as trusted, \
                patch.object(adapter, "_read_private_review_log",
                             wraps=adapter._read_private_review_log) as read_private:
            result = adapter.review_result(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        trusted.assert_not_called()
        self.assertNotIn(external_receipt,
                         [call.args[0] for call in read_private.call_args_list])

    def test_review_evidence_symlink_is_rejected_before_receipt_use(self):
        adapter, worktree, evidence_dir, _, stdout = self._review_fixture()
        evidence_root = evidence_dir.parents[2]
        moved_root = evidence_root.with_name(".cmh-review-evidence-real")
        evidence_root.rename(moved_root)
        evidence_root.symlink_to(moved_root, target_is_directory=True)
        with patch.object(adapter, "review_preflight", return_value=GateResult("PASS")), \
                patch.object(adapter, "_trusted_base_checkout") as trusted:
            result = adapter.review_result(
                "codex", worktree=str(worktree), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(worktree / "scope.json"),
                stdout_path=str(stdout), evidence_dir=str(evidence_dir),
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        trusted.assert_not_called()

    def test_evidence_paths_reject_traversing_mission_ids(self):
        adapter = FootballPredictionAdapter()
        with self.assertRaisesRegex(ValueError, "safe evidence path"):
            adapter.review_evidence_dir("/tmp/worktree", "../escape", "codex", "a" * 40)

    def test_pr_discovery_uses_worktree_origin_not_ambient_gh_repo(self):
        adapter = FootballPredictionAdapter()
        branch = "feature/exact-head"
        pull = {
            "number": 42,
            "head": {"sha": "a" * 40, "ref": branch},
            "base": {"ref": "main", "sha": "b" * 40},
        }
        with patch.object(adapter, "_run", side_effect=[
                "https://credential@github.com/owner/project.git", branch, json.dumps([pull])]) as run, \
                patch.dict(os.environ, {"GH_REPO": "attacker/other-repository"}):
            result = adapter.discover_pr("/worktree", "a" * 40)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.data, {
            "number": 42, "repo": "owner/project", "head": "a" * 40,
            "base": "main", "state": "OPEN", "base_sha": "b" * 40,
        })
        discovery_argv = run.call_args_list[-1].args[0]
        self.assertEqual(
            discovery_argv[2],
            "repos/owner/project/pulls?state=open&head=owner%3Afeature%2Fexact-head",
        )
        self.assertNotIn("credential", result.evidence)

    def test_pr_discovery_rejects_non_github_origin(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_run", return_value="https://example.invalid/owner/project.git") as run:
            result = adapter.discover_pr("/worktree", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(run.call_count, 1)

    def test_pr_discovery_malformed_nested_fields_fail_closed(self):
        adapter = FootballPredictionAdapter()
        malformed = [{
            "number": 42, "head": "not-an-object", "base": {"ref": "main"},
        }]
        with patch.object(adapter, "_run", side_effect=[
                "https://github.com/owner/project.git", "feature", json.dumps(malformed),
        ]):
            result = adapter.discover_pr("/worktree", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_supervisor_rejects_untrusted_pr_discovery_identity_without_casting(self):
        class MalformedPRAdapter(SimulatedAdapter):
            def discover_pr(self, worktree, head):
                return GateResult("PASS", "untrusted", data={
                    "number": "7", "repo": "fixture/repo",
                })

        adapter = MalformedPRAdapter()
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "invalid-pr-logs"),
            self.codex, adapter,
        )
        self.journal.update(
            self.spec.mission_id, current_head="a" * 40, current_state=State.MERGE,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, self.spec), State.BLOCKED_EXTERNAL)
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["pr_number"])

    def test_post_merge_parses_canonical_json_before_human_footer(self):
        adapter = FootballPredictionAdapter()
        merge_sha = "a" * 40
        report = {
            "ci_head_sha": merge_sha, "ci_status": "completed", "ci_conclusion": "success",
            "verdict": "PASS", "failures": [],
        }
        completed = subprocess.CompletedProcess(
            [], 0, json.dumps(report, indent=2) + "\n\nPost-merge completion evidence passed.\n", "",
        )
        with patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_assert_safe_local_git_config"), \
                patch.object(adapter, "_repo_from_origin", return_value="owner/project"), \
                patch.object(adapter, "_call", side_effect=[completed, subprocess.CompletedProcess([], 0, "", "")]), \
                patch.object(adapter, "_run", side_effect=["", "d" * 40, "e" * 40]):
            result = adapter.post_merge("/worktree", merge_sha, 7, "owner/project", "feature", "b" * 40)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.data["main_sha"], "d" * 40)
        self.assertEqual(result.data["tree_sha"], "e" * 40)

    def test_post_merge_derives_tree_and_reachability_from_one_captured_main_sha(self):
        adapter = FootballPredictionAdapter()
        merge_sha = "a" * 40
        main_sha = "d" * 40
        report = {"ci_head_sha": merge_sha, "ci_status": "completed",
                  "ci_conclusion": "success", "verdict": "PASS", "failures": []}
        completed = subprocess.CompletedProcess([], 0, json.dumps(report), "")
        with patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_assert_safe_local_git_config"), \
                patch.object(adapter, "_repo_from_origin", return_value="owner/project"), \
                patch.object(adapter, "_call", side_effect=[completed, subprocess.CompletedProcess([], 0, "", "")]) as call, \
                patch.object(adapter, "_run", side_effect=["", main_sha, "e" * 40]) as run:
            result = adapter.post_merge("/worktree", merge_sha, 7, "owner/project", "feature", "b" * 40)
        self.assertEqual(result.status, "PASS")
        self.assertEqual(run.call_args_list[1].args[0], ["git", "rev-parse", "origin/main"])
        self.assertEqual(run.call_args_list[2].args[0], ["git", "rev-parse", f"{main_sha}^{{tree}}"])
        self.assertEqual(call.call_args_list[1].args[0],
                         ["git", "merge-base", "--is-ancestor", merge_sha, main_sha])

    def test_post_merge_bootstraps_trusted_project_imports_in_isolated_python(self):
        adapter = FootballPredictionAdapter()
        merge_sha = "a" * 40
        report = {
            "ci_head_sha": merge_sha, "ci_status": "completed", "ci_conclusion": "success",
            "verdict": "PASS", "failures": [],
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(report), "")
        with patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_assert_safe_local_git_config"), \
                patch.object(adapter, "_repo_from_origin", return_value="owner/project"), \
                patch.object(adapter, "_trusted_python_interpreter", return_value="/trusted/python"), \
                patch.object(adapter, "_call", side_effect=[completed, subprocess.CompletedProcess([], 0, "", "")]) as call, \
                patch.object(adapter, "_run", side_effect=["", "d" * 40, "e" * 40]):
            result = adapter.post_merge("/worktree", merge_sha, 7, "owner/project", "feature", "b" * 40)
        self.assertEqual(result.status, "PASS")
        argv = call.call_args_list[0].args[0]
        self.assertEqual(argv[:4], ["/trusted/python", "-I", "-B", "-c"])
        self.assertIn("Path(sys.argv[1]) / 'scripts/devops'", argv[4])
        self.assertIn("import pr_post_merge_check as m", argv[4])
        self.assertEqual(argv[5:], [
            "/trusted", "--pr", "7", "--merge-commit", merge_sha,
            "--branch", "feature", "--json",
        ])

    def test_post_merge_queued_ci_is_pending_even_when_canonical_command_exits_one(self):
        adapter = FootballPredictionAdapter()
        merge_sha = "a" * 40
        report = {
            "ci_head_sha": merge_sha, "ci_status": "queued", "ci_conclusion": "",
            "verdict": "FAIL", "failures": ["Production Gate CI is queued"],
        }
        queued = subprocess.CompletedProcess(
            [], 1, json.dumps(report, indent=2) + "\n\nPost-merge completion evidence FAILED.\n",
            "Post-merge completion evidence FAILED.\n",
        )
        with patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_call", return_value=queued), \
                patch.object(adapter, "_run") as run:
            result = adapter.post_merge("/worktree", merge_sha, 7, "owner/project", "feature", "b" * 40)
        self.assertEqual(result.status, "PENDING")
        run.assert_not_called()

    def test_post_merge_terminal_failure_is_not_mislabeled_as_infrastructure_error(self):
        adapter = FootballPredictionAdapter()
        report = {
            "ci_head_sha": "a" * 40, "ci_status": "completed", "ci_conclusion": "failure",
            "verdict": "FAIL", "failures": ["Production Gate CI failed"],
        }
        failed = subprocess.CompletedProcess([], 1, json.dumps(report) + "\n", "canonical failure")
        with patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_call", return_value=failed):
            result = adapter.post_merge("/worktree", "a" * 40, 7, "owner/project", "feature", "b" * 40)
        self.assertEqual(result.status, "FAIL")

    def test_merge_uses_durable_pr_identity_without_rediscovery(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        not_started = GateResult("NOT_STARTED", "safe", data={"pr_base_sha": base_sha})
        merged = GateResult("PASS", "merged", data={"pr": 17, "repo": "fixture/repo",
            "pr_base_sha": base_sha, "merge_sha": "c" * 40})
        completed = subprocess.CompletedProcess([], 0, "", "")
        protection = subprocess.CompletedProcess([], 0, json.dumps({
            "required_status_checks": {"strict": True, "contexts": ["verify"]},
            "enforce_admins": {"enabled": True},
        }), "")
        with patch.object(adapter, "discover_pr") as discover, \
                patch.object(adapter, "merge_status", side_effect=[not_started, merged]) as status, \
                patch.object(adapter, "_call", side_effect=[
                    protection, subprocess.CompletedProcess([], 0, "[]", ""), completed,
                ]) as call:
            result = adapter.merge("/candidate", "a" * 40, 17, "fixture/repo", base_sha)
        self.assertEqual(result.status, "PASS")
        discover.assert_not_called()
        self.assertEqual(status.call_args_list[0].args, ("/candidate", "a" * 40, 17, "fixture/repo"))
        self.assertEqual(status.call_args_list[0].kwargs["pr_base_sha"], base_sha)
        self.assertEqual(call.call_args_list[0].args[0], [
            "gh", "api", "repos/fixture/repo/branches/main/protection",
        ])
        self.assertEqual(call.call_args_list[1].args[0], [
            "gh", "api", "repos/fixture/repo/rules/branches/main",
        ])
        self.assertEqual(call.call_args_list[2].args[0][:6], [
            "gh", "pr", "merge", "17", "--repo", "fixture/repo",
        ])
        self.assertIn("--match-head-commit", call.call_args_list[2].args[0])

    def test_merge_fails_closed_without_server_enforced_base_freshness(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        not_started = GateResult("NOT_STARTED", "safe", data={"pr_base_sha": base_sha})
        unavailable = subprocess.CompletedProcess([], 1, "", "HTTP 403")
        with patch.object(adapter, "merge_status", return_value=not_started), \
                patch.object(adapter, "_call", return_value=unavailable) as call:
            result = adapter.merge("/candidate", "a" * 40, 17, "fixture/repo", base_sha)
        self.assertEqual(result.status, "BLOCKED_POLICY")
        self.assertIn("strict base freshness", result.evidence)
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0], [
            "gh", "api", "repos/fixture/repo/branches/main/protection",
        ])

    def test_merge_queue_rule_blocks_before_merge_invocation(self):
        adapter = FootballPredictionAdapter()
        protection = subprocess.CompletedProcess([], 0, json.dumps({
            "required_status_checks": {"strict": True, "contexts": ["verify"]},
            "enforce_admins": {"enabled": True},
        }), "")
        rules = subprocess.CompletedProcess([], 0, json.dumps([{"type": "merge_queue"}]), "")
        with patch.object(adapter, "merge_status", return_value=GateResult("NOT_STARTED", "safe")), \
                patch.object(adapter, "_call", side_effect=[protection, rules]) as call:
            result = adapter.merge("/candidate", "a" * 40, 17, "fixture/repo", "b" * 40)
        self.assertEqual(result.status, "BLOCKED_POLICY")
        self.assertIn("merge queue", result.evidence)
        self.assertEqual(call.call_count, 2)

    def test_merge_requires_strict_statuses_and_admin_enforcement(self):
        adapter = FootballPredictionAdapter()
        cases = (
            {"required_status_checks": {"strict": False, "contexts": ["verify"]},
             "enforce_admins": {"enabled": True}},
            {"required_status_checks": {"strict": True, "contexts": []},
             "enforce_admins": {"enabled": True}},
            {"required_status_checks": {"strict": True, "contexts": ["verify"]},
             "enforce_admins": {"enabled": False}},
        )
        for protection_data in cases:
            with self.subTest(protection_data=protection_data):
                # Exercise the public merge path so an invalid rule can never
                # reach the irreversible GitHub merge command.
                not_started = GateResult("NOT_STARTED", "safe")
                response = subprocess.CompletedProcess([], 0, json.dumps(protection_data), "")
                with patch.object(adapter, "merge_status", return_value=not_started), \
                        patch.object(adapter, "_call", return_value=response) as call:
                    result = adapter.merge(
                        "/candidate", "a" * 40, 17, "fixture/repo", "b" * 40,
                    )
                self.assertEqual(result.status, "BLOCKED_POLICY")
                self.assertEqual(call.call_count, 1)

    def test_ci_requires_whole_canonical_pr_ready_pass(self):
        adapter = FootballPredictionAdapter()
        report = {"verdict": "FAIL", "pr": {"head_sha": "a" * 40},
                  "findings": [{"name": "required-check:verify", "passed": True,
                                "message": "status=completed"}]}
        completed = subprocess.CompletedProcess([], 1, json.dumps(report), "policy failed")
        with patch.object(adapter, "discover_pr", return_value=GateResult(
                "PASS", "PR", data={"number": 7, "repo": "fixture/repo", "base_sha": "c" * 40})), \
                patch.object(adapter, "_pr_state", return_value=GateResult(
                    "PASS", "PR", data={"head": "a" * 40, "base": "main", "state": "OPEN",
                                         "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_call", return_value=completed):
            result = adapter.ci("/fixture", "a" * 40, base_sha="c" * 40)
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.data["pr_number"], 7)

    def test_ci_without_trusted_base_sha_fails_closed_without_running_candidate(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_call") as call:
            result = adapter.ci("/fixture", "a" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("trusted base SHA", result.evidence)
        call.assert_not_called()

    def test_ci_rejects_trusted_policy_base_that_differs_from_current_pr_base(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "discover_pr", return_value=GateResult(
                "PASS", "PR", data={"number": 7, "repo": "owner/project", "base_sha": "c" * 40})), \
                patch.object(adapter, "_pr_state", return_value=GateResult(
                    "PASS", "PR", data={"head": "a" * 40, "base": "main", "state": "OPEN",
                                         "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout") as trusted, \
                patch.object(adapter, "_call") as call:
            result = adapter.ci("/fixture", "a" * 40, base_sha="b" * 40)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("trusted policy base SHA", result.evidence)
        trusted.assert_not_called()
        call.assert_not_called()

    def test_merge_ready_delegates_to_canonical_target_gate(self):
        adapter = FootballPredictionAdapter()
        scope = Path(self.tmp.name) / "scope.json"
        scope.write_text("{}")
        local = subprocess.CompletedProcess([], 0, json.dumps({"verdict": "PASS"}), "")
        ready = subprocess.CompletedProcess([], 0, json.dumps({"merge_ready": "YES"}), "")
        with patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "PR", data={"body": "body", "head": "b" * 40,
                                     "base": "main", "state": "OPEN", "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout", return_value=Path(self.tmp.name) / "trusted"), \
                patch.object(adapter, "_call", side_effect=[local, ready]) as call:
            result = adapter.merge_ready(
                worktree=str(self.tmp.name), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(scope), pr_number=7,
                pr_repo="owner/project", pr_base_sha="c" * 40,
                receipts={"codex": "/r/c.json"}, ci_status="PASS",
            )
        self.assertEqual(result.status, "PASS")
        self.assertIn("agent-workflow", " ".join(call.call_args_list[1].args[0]))
        self.assertFalse(call.call_args_list[0].kwargs["inherit_environment"])
        self.assertNotIn("ANTHROPIC_API_KEY", call.call_args_list[0].kwargs["env"])
        command = call.call_args_list[1].args[0]
        self.assertIn("--protected-invariants", command)
        self.assertEqual(command[command.index("--protected-invariants") + 1], "PASS")
        self.assertEqual(command[command.index("--forbidden-side-effects") + 1], "NO")
        self.assertEqual(command[command.index("--required-pr-governance") + 1], "UNKNOWN")
        self.assertEqual(command[command.index("--pr") + 1], "7")
        self.assertEqual(command[command.index("--remote-ci-status") + 1], "PASS")

    def test_merge_ready_rejects_symlink_at_local_preflight_evidence(self):
        adapter = FootballPredictionAdapter()
        worktree = Path(self.tmp.name) / "candidate"
        worktree.mkdir()
        scope = worktree / "scope.json"
        scope.write_text("{}")
        head = "b" * 40
        evidence = worktree.parent / ".cmh-merge-evidence" / "mission" / head
        evidence.mkdir(parents=True, mode=0o700)
        target = Path(self.tmp.name) / "victim.json"
        target.write_text("preserve this file\n", encoding="utf-8")
        local_path = evidence / "local-preflight.json"
        local_path.symlink_to(target)
        local = subprocess.CompletedProcess([], 0, json.dumps({"verdict": "PASS"}), "")
        ready = subprocess.CompletedProcess([], 0, json.dumps({"merge_ready": "YES"}), "")
        with patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "PR", data={"body": "body", "head": head,
                                     "base": "main", "state": "OPEN", "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout", return_value=Path(self.tmp.name) / "trusted"), \
                patch.object(adapter, "_call", side_effect=[local, ready]) as call:
            result = adapter.merge_ready(
                worktree=str(worktree), base="a" * 40, head=head,
                mission_id="mission", scope_file=str(scope), pr_number=7,
                pr_repo="owner/project", pr_base_sha="c" * 40,
                receipts={"codex": "/receipt.json"}, ci_status="PASS",
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("cannot safely persist local merge evidence", result.evidence)
        self.assertTrue(local_path.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "preserve this file\n")
        self.assertEqual(call.call_count, 1)

    def test_merge_ready_rejects_base_sha_change_before_target_commands(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "PR", data={"body": "body", "head": "b" * 40,
                                     "base": "main", "state": "OPEN", "base_sha": "c" * 40})), \
                patch.object(adapter, "_call") as call:
            result = adapter.merge_ready(
                worktree="/candidate", base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file="/candidate/scope.json", pr_number=7,
                pr_repo="owner/project", pr_base_sha="b" * 40,
                receipts={"codex": "/receipt.json"}, ci_status="PASS",
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("base", result.evidence)
        call.assert_not_called()

    def test_merge_ready_parses_multiline_json_and_never_executes_candidate_makefile(self):
        adapter = FootballPredictionAdapter()
        candidate = Path(self.tmp.name) / "candidate"
        candidate.mkdir()
        scope = candidate / "scope.json"
        scope.write_text("{}")
        marker = candidate / "makefile-ran"
        (candidate / "Makefile").write_text(
            "agent-preflight:\n\t touch " + str(marker) + "\n", encoding="utf-8",
        )
        trusted = Path(self.tmp.name) / "trusted-base"
        local = subprocess.CompletedProcess(
            [], 0, json.dumps({"verdict": "PASS", "detail": {"ok": True}}, indent=2)
            + "\nHuman-readable footer\n", "",
        )
        ready = subprocess.CompletedProcess(
            [], 0, json.dumps({"merge_ready": "YES", "reason": "exact gates"}, indent=2)
            + "\nHuman-readable footer\n", "",
        )
        with patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "PR", data={"body": "body", "head": "b" * 40,
                                     "base": "main", "state": "OPEN", "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout", return_value=trusted), \
                patch.object(adapter, "_call", side_effect=[local, ready]) as call:
            result = adapter.merge_ready(
                worktree=str(candidate), base="a" * 40, head="b" * 40,
                mission_id="mission", scope_file=str(scope), pr_number=7,
                pr_repo="owner/project", pr_base_sha="c" * 40,
                receipts={"codex": "/receipt.json"}, ci_status="PASS",
            )
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.data["reason"], "exact gates")
        self.assertEqual(call.call_count, 2)
        self.assertEqual(call.call_args_list[0].args[0][0], sys.executable)
        self.assertEqual(call.call_args_list[0].kwargs["cwd"], str(trusted))
        self.assertNotIn("make", call.call_args_list[0].args[0])
        self.assertFalse(marker.exists())

    def test_owner_approval_precedes_target_merge_readiness_command(self):
        class RecordingAdapter(FootballPredictionAdapter):
            def __init__(self):
                self.merge_ready_calls = 0
                self.merge_calls = 0

            def exact_head(self, worktree):
                return "a" * 40

            def _repo_from_origin(self, worktree):
                return "fixture/repo"

            def ci(self, worktree, head, pr_number=None, pr_repo=None, base_sha=None):
                return GateResult("PASS", "exact CI", data={
                    "pr_number": pr_number, "pr_repo": pr_repo, "pr_base_sha": "b" * 40,
                })

            def merge_ready(self, **kwargs):
                self.merge_ready_calls += 1
                return GateResult("PASS", "ready")

            def merge(self, worktree, head, pr_number=None, pr_repo=None, pr_base_sha=None):
                self.merge_calls += 1
                return GateResult("PASS", "merged", data={"pr": pr_number,
                    "repo": pr_repo, "pr_base_sha": pr_base_sha, "merge_sha": "c" * 40})

        adapter = RecordingAdapter()
        spec = replace(self.spec, adapter="footballprediction",
                       mission_scope_file="scope.json", merge_policy="owner_approval")
        self.journal.update(
            self.spec.mission_id, spec_json=json.dumps(spec.__dict__), current_head="a" * 40,
            current_state=State.MERGE, pr_number=7, pr_repo="fixture/repo", pr_base_sha="b" * 40,
            origin_repo="fixture/repo",
        )
        supervisor = Supervisor(
            self.journal, ProcessSupervisor(self.journal, Path(self.tmp.name) / "approval-boundary"),
            self.codex, adapter,
        )
        self.assertEqual(supervisor.step(self.spec.mission_id, spec), State.WAITING_APPROVAL)
        self.assertEqual(adapter.merge_ready_calls, 0)
        self.assertEqual(adapter.merge_calls, 0)

    def test_pr_binding_rejects_repository_other_than_pinned_origin(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.CI, origin_repo="owner/original")
        self.assertFalse(self.journal.bind_pr_identity(
            self.spec.mission_id, "a" * 40, 7, "attacker/alternate", "b" * 40))
        self.assertIsNone(self.journal.mission(self.spec.mission_id)["pr_repo"])

    def test_changed_origin_blocks_production_before_ci(self):
        class RedirectedOrigin(FootballPredictionAdapter):
            def exact_head(self, worktree):
                return "a" * 40

            def _repo_from_origin(self, worktree):
                return "attacker/alternate"

            def discover_pr(self, worktree, head):
                raise AssertionError("redirected origin must not reach PR discovery")

        spec = replace(self.spec, adapter="footballprediction", mission_scope_file="scope.json")
        self.journal.update(self.spec.mission_id, spec_json=json.dumps(spec.__dict__),
                            current_head="a" * 40, current_state=State.CI,
                            origin_repo="owner/original")
        supervisor = Supervisor(self.journal, self.supervisor.process, self.codex,
                                RedirectedOrigin())
        self.assertEqual(supervisor.step(self.spec.mission_id, spec), State.BLOCKED_EXTERNAL)

    def test_controller_subprocesses_ignore_global_git_configuration(self):
        child = FootballPredictionAdapter._trusted_subprocess_environment()
        self.assertEqual(child["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_trusted_checkout_rejects_local_checkout_filter_before_materialization(self):
        repo = Path(self.tmp.name) / "filter-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
        (repo / "tracked.txt").write_text("safe\n")
        (repo / ".gitattributes").write_text("tracked.txt filter=evil\n")
        subprocess.run(["git", "-C", str(repo), "add", "tracked.txt", ".gitattributes"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        marker = Path(self.tmp.name) / "smudge-executed"
        subprocess.run(["git", "-C", str(repo), "config", "filter.evil.smudge",
                        f"sh -c 'touch {marker}; cat'"], check=True)
        with self.assertRaisesRegex(RuntimeError, "executable local Git configuration"):
            FootballPredictionAdapter()._trusted_base_checkout(str(repo), head)
        self.assertFalse(marker.exists(), "checkout ran an untrusted smudge filter")

    def test_production_mission_rejects_unexecutable_post_merge_gates(self):
        raw = dict(self.spec.__dict__, adapter="footballprediction",
                   post_merge_gates=["unsupported-production-gate"])
        with self.assertRaisesRegex(ValueError, "post_merge_gates are unsupported"):
            MissionSpec.from_mapping(raw)

    def test_ci_malformed_json_evidence_fails_closed(self):
        adapter = FootballPredictionAdapter()
        cases = (
            {"verdict": "PASS", "pr": [], "findings": []},
            {"verdict": "PASS", "pr": {"head_sha": "a" * 40}, "findings": [None]},
        )
        for report in cases:
            with self.subTest(report=report):
                with patch.object(adapter, "discover_pr", return_value=GateResult(
                        "PASS", "PR", data={"number": 7, "repo": "fixture/repo", "base_sha": "c" * 40})), \
                patch.object(adapter, "_pr_state", return_value=GateResult(
                    "PASS", "PR", data={"head": "a" * 40, "base": "main", "state": "OPEN",
                                         "base_sha": "c" * 40})), \
                patch.object(adapter, "_trusted_base_checkout", return_value=Path("/trusted")), \
                patch.object(adapter, "_call", return_value=subprocess.CompletedProcess(
                            [], 0, json.dumps(report), "")) as call:
                    result = adapter.ci("/fixture", "a" * 40, base_sha="c" * 40)
                self.assertEqual(result.status, "BLOCKED_EXTERNAL")
                call.assert_called()

    def test_ci_reuses_durable_pr_and_rejects_identity_change(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "discover_pr") as discover, patch.object(
                adapter, "_pr_state", return_value=GateResult(
                    "PASS", "PR", data={"head": "b" * 40, "base": "main", "state": "OPEN"})) as state:
            result = adapter.ci(
                "/fixture",
                "a" * 40,
                7,
                "fixture/repo",
                base_sha="b" * 40,
            )
        discover.assert_not_called()
        state.assert_called_once_with("/fixture", 7, "fixture/repo")
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_ci_rejects_pr_base_change_after_review_binding(self):
        adapter = FootballPredictionAdapter()
        with patch.object(adapter, "_pr_state", return_value=GateResult(
                "PASS", "PR", data={"head": "a" * 40, "base": "main", "state": "OPEN",
                                     "base_sha": "c" * 40})), \
                patch.object(adapter, "_call") as call:
            result = adapter.ci(
                "/fixture", "a" * 40, 7, "fixture/repo",
                base_sha="c" * 40, pr_base_sha="b" * 40,
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("base SHA changed", result.evidence)
        call.assert_not_called()

    def test_merge_recovery_open_pr_is_ambiguous_not_retry_safe(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        responses = iter([
            json.dumps({"number": 7, "state": "open", "merged": False, "head": {"sha": "a" * 40},
                        "base": {"ref": "main", "sha": base_sha}, "auto_merge": None}),
        ])
        with patch.object(adapter, "_run", side_effect=lambda *args, **kwargs: next(responses)):
            result = adapter.merge_status("/fixture", "a" * 40, 7, "fixture/repo", base_sha)
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("ambiguous", result.evidence)

    def test_open_pr_with_moved_base_is_not_safe_to_retry_merge(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        responses = iter([
            json.dumps({"number": 7, "state": "open", "merged": False,
                        "head": {"sha": "a" * 40},
                        "base": {"ref": "main", "sha": "c" * 40}, "auto_merge": None}),
        ])
        with patch.object(adapter, "_run", side_effect=lambda *args, **kwargs: next(responses)):
            result = adapter.merge_status(
                "/fixture", "a" * 40, 7, "fixture/repo", base_sha, allow_open_retry=True,
            )
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertIn("ambiguous", result.evidence)

    def test_merged_pr_recovery_requires_exact_approved_base_parent(self):
        adapter = FootballPredictionAdapter()
        merge_sha = "d" * 40
        pr = {"number": 7, "state": "closed", "merged": True,
              "head": {"sha": "a" * 40}, "base": {"ref": "main", "sha": "c" * 40},
              "merge_commit_sha": merge_sha}
        for first_parent, expected in (("b" * 40, "PASS"), ("e" * 40, "BLOCKED_EXTERNAL")):
            with self.subTest(first_parent=first_parent), patch.object(
                    adapter, "_run", side_effect=[json.dumps(pr), json.dumps({
                        "parents": [{"sha": first_parent}],
                    })]):
                result = adapter.merge_status(
                    "/fixture", "a" * 40, 7, "fixture/repo", "b" * 40,
                )
            self.assertEqual(result.status, expected)

    def test_merge_queue_or_auto_merge_is_never_retry_safe(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        for queue_fields in ({"auto_merge": {"enabled_by": {}}},
                             {"auto_merge": None, "merge_queue_entry": {"id": 91}}):
            responses = iter([
                json.dumps({"number": 7, "state": "open", "merged": False,
                            "head": {"sha": "a" * 40},
                            "base": {"ref": "main", "sha": base_sha},
                            **queue_fields}),
            ])
            with self.subTest(queue_fields=queue_fields), patch.object(
                    adapter, "_run", side_effect=lambda *args, **kwargs: next(responses)):
                result = adapter.merge_status(
                    "/fixture", "a" * 40, 7, "fixture/repo", base_sha, allow_open_retry=True,
                )
                self.assertEqual(result.status, "BLOCKED_EXTERNAL")

    def test_head_change_clears_durable_pr_identity(self):
        self.journal.update(self.spec.mission_id, current_head="a" * 40,
                            current_state=State.CI, pr_number=7, pr_repo="fixture/repo",
                            pr_base_sha="b" * 40)
        self.journal.reconcile_head(self.spec.mission_id, "b" * 40)
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.TEST)
        self.assertIsNone(row["pr_number"])
        self.assertIsNone(row["pr_repo"])

    def test_merge_completion_cannot_publish_a_different_pr_base_than_its_claim(self):
        head, base_sha = "a" * 40, "b" * 40
        self.journal.update(
            self.spec.mission_id, current_head=head, current_state=State.MERGE,
            pr_number=7, pr_repo="fixture/repo", pr_base_sha=base_sha,
            merge_claim_head=head, merge_claim_pr_number=7,
            merge_claim_pr_repo="fixture/repo", merge_claim_pr_base_sha=base_sha,
        )
        with self.assertRaisesRegex(InvalidTransition, "exact claim or PR identity"):
            self.journal.complete_merge(
                self.spec.mission_id, head, pr_number=7, pr_repo="fixture/repo",
                pr_base_sha="c" * 40, merge_sha="d" * 40, reason="mismatched base",
            )
        row = self.journal.mission(self.spec.mission_id)
        self.assertEqual(row["current_state"], State.MERGE)
        self.assertEqual(row["merge_claim_pr_base_sha"], base_sha)

    def test_open_exact_head_pr_proves_merge_not_started(self):
        adapter = FootballPredictionAdapter()
        base_sha = "b" * 40
        responses = iter([
            json.dumps({"number": 7, "state": "open", "merged": False, "head": {"sha": "a" * 40},
                        "base": {"ref": "main", "sha": base_sha}, "auto_merge": None}),
        ])
        with patch.object(adapter, "_run", side_effect=lambda *args, **kwargs: next(responses)):
            result = adapter.merge_status("/fixture", "a" * 40, 7, "fixture/repo", base_sha,
                                          allow_open_retry=True)
        self.assertEqual(result.status, "NOT_STARTED")
