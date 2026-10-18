"""Synthetic wire messages through the real parser; never model inference."""
from __future__ import annotations

import io
import json
import queue
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.factory_runtime import FactoryAppServer, RuntimeFailure, WORK_SCHEMA


def usage(count, thread="t", turn="u"):
    return {"method": "thread/tokenUsage/updated", "params": {
        "threadId": thread, "turnId": turn, "tokenUsage": {"total": {
            "inputTokens": count, "outputTokens": 0, "totalTokens": count}}}}


def final():
    return {"method": "item/completed", "params": {"threadId": "t", "turnId": "u",
        "item": {"id": "answer", "type": "agentMessage", "phase": "final_answer",
                 "text": '{"summary":"synthetic edit","known_risks":[]}'}}}


def completed(status="completed"):
    return {"method": "turn/completed", "params": {"threadId": "t",
        "turn": {"id": "u", "status": status, "items": []}}}


ACCEPTED = {"id": 1, "result": {"turn": {"id": "u", "status": "inProgress"}}}


class TurnCompletionTests(unittest.TestCase):
    def server(self, messages, limit=100):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        server = FactoryAppServer.__new__(FactoryAppServer)
        server.proc = SimpleNamespace(stdin=io.StringIO(), stdout=io.StringIO(
            "".join(json.dumps(message) + "\n" for message in messages)))
        server.seq = 0
        server._end_time = time.monotonic() + 30
        server.events, server.usage = [], None
        server._policy_cwd, server._permissions_profile = "/tmp/synthetic", "fixture"
        server._forbidden_actions = ("release",)
        server.MODEL, server.REASONING_EFFORT = "gpt-6.1-sol", "high"
        server.token_limit = limit
        server.runtime_identity = {"model": server.MODEL, "provider": "openai"}
        server.transcript, server._transcript_bytes = Path(temporary.name) / "wire.raw", 0
        self.enterContext(patch.object(server, "start_or_resume", return_value="t"))
        self.enterContext(patch.object(server, "close"))
        return server

    def execute(self, server):
        return server.execute("synthetic request", WORK_SCHEMA, return_thread=True)

    def test_success_requires_terminal_event_and_keeps_full_usage_and_model_request(self):
        server = self.server([ACCEPTED, usage(20), final(), usage(35), completed()])
        result = self.execute(server)
        self.assertEqual(result["turn_completion"]["status"], "completed")
        self.assertTrue(result["usage_complete"])
        self.assertEqual(result["usage"]["total"]["totalTokens"], 35)
        self.assertEqual(result["thread_id"], "t")
        request = json.loads(server.proc.stdin.getvalue())
        self.assertEqual(request["params"]["model"], "gpt-6.1-sol")
        self.assertEqual(request["params"]["effort"], "high")

    def test_last_usage_over_limit_still_collects_already_queued_completion(self):
        server = self.server([ACCEPTED, usage(90), final(), usage(101), completed()])
        result = self.execute(server)
        self.assertTrue(result["usage_complete"])
        self.assertEqual(result["usage"]["total"]["totalTokens"], 101)
        self.assertEqual(result["turn_completion"]["status"], "completed")
        requests = [json.loads(line) for line in server.proc.stdin.getvalue().splitlines()]
        self.assertEqual([r["method"] for r in requests], ["turn/start", "turn/interrupt"])
        self.assertEqual(requests[1]["params"], {"threadId": "t", "turnId": "u"})
        self.assertLessEqual(server._end_time - time.monotonic(), 5)
        self.assertIn('"method": "turn/completed"', server.transcript.read_text())

    def test_over_limit_before_acceptance_response_does_not_lose_completion(self):
        server = self.server([final(), usage(101), completed(),
                              {"id": 2, "result": {}}, ACCEPTED])
        self.assertTrue(self.execute(server)["usage_complete"])

    def test_budget_interrupt_ack_is_not_completion_or_final_usage(self):
        server = self.server([ACCEPTED, usage(101), {"id": 2, "result": {}},
                              completed("interrupted")])
        with self.assertRaises(RuntimeFailure) as stopped:
            self.execute(server)
        self.assertFalse(stopped.exception.usage_complete)
        self.assertFalse(server._usage_complete)
        self.assertEqual(stopped.exception.identity["turn_completion"]["status"], "interrupted")
        self.assertEqual(stopped.exception.usage["total"]["totalTokens"], 101)

    def test_acceptance_and_final_text_without_terminal_event_remain_uncertain(self):
        server = self.server([ACCEPTED, usage(20), final()])
        with self.assertRaisesRegex(RuntimeError, "exited before"):
            self.execute(server)
        self.assertFalse(server._usage_complete)

    def test_completion_without_usage_does_not_settle_reservation(self):
        server = self.server([ACCEPTED, final(), completed()])
        with self.assertRaisesRegex(RuntimeFailure, "usage telemetry missing"):
            self.execute(server)
        self.assertFalse(server._usage_complete)

    def test_failed_terminal_is_retained_but_never_success(self):
        server = self.server([ACCEPTED, usage(20), completed("failed")])
        with self.assertRaises(RuntimeFailure) as stopped:
            self.execute(server)
        self.assertEqual(stopped.exception.identity["turn_completion"]["status"], "failed")
        self.assertFalse(stopped.exception.usage_complete)

    def test_duplicate_snapshot_is_idempotent_and_does_not_add_tokens(self):
        server = self.server([ACCEPTED, usage(20), usage(20), final(), completed()])
        result = self.execute(server)
        self.assertEqual(result["usage"]["total"]["totalTokens"], 20)
        self.assertTrue(result["usage_complete"])

    def test_usage_regression_within_turn_is_not_complete_accounting(self):
        server = self.server([ACCEPTED, usage(20), usage(15), final(), completed()])
        with self.assertRaisesRegex(RuntimeFailure, "regressed"):
            self.execute(server)
        self.assertFalse(server._usage_complete)

    def test_foreign_thread_and_old_turn_usage_do_not_overwrite_active_usage(self):
        server = self.server([ACCEPTED, usage(999, thread="foreign"), usage(888, turn="old"),
                              usage(20), final(), completed()])
        self.assertEqual(self.execute(server)["usage"]["total"]["totalTokens"], 20)
        self.assertFalse(server._budget_exceeded)

    def test_budget_drain_timeout_retains_partial_usage(self):
        server = self.server([])
        server._active_thread_id, server._active_turn_id = "t", "u"
        server._turn_usage_baseline = None
        with patch("harness.codex.AppServerCodex._read_message", return_value=usage(101)):
            server._read_message()
        server._reader_thread, server._reader_queue = object(), queue.Queue()
        server._end_time = time.monotonic() + 0.01
        with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
            server._turn_completed("t", "u", require_success=False)
        self.assertEqual(server.usage["total"]["totalTokens"], 101)

    def test_selected_model_reroute_cannot_claim_exact_model_success(self):
        event = {"method": "model/rerouted", "params": {"threadId": "t", "turnId": "u",
                 "fromModel": "gpt-6.1-sol", "toModel": "gpt-6-luna"}}
        server = self.server([ACCEPTED, event, usage(20), final(), completed()])
        with self.assertRaisesRegex(RuntimeError, "rerouted"):
            self.execute(server)

    def test_thread_resume_must_report_requested_effort_and_model(self):
        for model, effort, message in [("gpt-6-luna", "high", "model"),
                                       ("gpt-6.1-sol", "low", "reasoning effort")]:
            with self.subTest(model=model, effort=effort):
                server = self.server([])
                server.profile = {"model": server.MODEL, "effort": server.REASONING_EFFORT}
                server.transport = {"type": "official"}
                server._native_identity, server._source_home = {}, "/tmp/synthetic-auth"
                server._transport_provider, server._proxy_relay = "official-fixture", None
                response = {"model": model, "reasoningEffort": effort,
                            "modelProvider": server._transport_provider}
                with patch("harness.codex.AppServerCodex._request", return_value=response):
                    with self.assertRaisesRegex(RuntimeError, message):
                        server._request("thread/resume", {})


if __name__ == "__main__":
    unittest.main()
