"""Offline reproductions of the 0.164 interleaved native-thread failure.

No model, real authentication, historical ledger or Provider transport is used.
Snapshots are not summed as billing, and cached input is already in input.
"""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from harness.factory_budget import tokens
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure


def usage(count, cached=0):
    return {"total": {"inputTokens": count, "outputTokens": 0,
                      "cachedInputTokens": cached, "totalTokens": count},
            "last": {"inputTokens": count, "outputTokens": 0, "totalTokens": count}}


def notification(count, thread="root", turn="review", cached=0):
    return {"method": "thread/tokenUsage/updated", "params": {
        "threadId": thread, "turnId": turn, "tokenUsage": usage(count, cached)}}


class UsageScopeTests(unittest.TestCase):
    def setUp(self):
        self.server = FactoryAppServer.__new__(FactoryAppServer)
        self.server.events, self.server.runtime_identity = [], {"model": "fixture"}
        self.server.token_limit = 800000
        self.server._bind_usage_thread("root")
        self.server._bind_usage_turn("review")

    def feed(self, event):
        with patch("harness.codex.AppServerCodex._read_message", return_value=event):
            return self.server._read_message()

    def test_child_usage_is_recorded_but_cannot_replace_or_settle_parent(self):
        self.feed(notification(12000))
        with self.assertRaisesRegex(RuntimeFailure, "unauthorized native thread") as stopped:
            self.feed(notification(583681, "child", "child-turn"))
        self.assertEqual(tokens(stopped.exception.usage), 12000)
        telemetry = stopped.exception.usage_telemetry
        self.assertEqual(tokens(telemetry["by_thread"]["child"]["child-turn"]["last_token_usage"]), 583681)
        self.assertEqual(telemetry["provider_total_usage"], "UNKNOWN")
        self.assertEqual(telemetry["cross_thread_aggregation"], "NOT_PERFORMED")
        self.assertFalse(stopped.exception.usage_complete)

    def test_child_before_parent_usage_leaves_parent_unknown(self):
        with self.assertRaises(RuntimeFailure) as stopped:
            self.feed(notification(151665, "child", "child-turn"))
        self.assertIsNone(stopped.exception.usage)

    def test_same_thread_other_turn_cannot_replace_review_usage(self):
        self.feed(notification(100))
        with self.assertRaisesRegex(RuntimeFailure, "another native turn"):
            self.feed(notification(999, turn="other-turn"))
        self.assertEqual(tokens(self.server.usage), 100)
        self.assertIn("other-turn", self.server.usage_telemetry()["by_thread"]["root"])

    def test_missing_attribution_is_unknown_and_preserved(self):
        event = notification(30)
        del event["params"]["threadId"]
        with self.assertRaisesRegex(RuntimeFailure, "no thread/turn attribution") as stopped:
            self.feed(event)
        self.assertIsNone(stopped.exception.usage)
        self.assertEqual(stopped.exception.usage_telemetry["scope_errors"][0]["tokenUsage"], usage(30))

    def test_duplicate_cumulative_snapshots_and_cached_input_are_not_added(self):
        for _ in range(2):
            self.feed(notification(100, cached=80))
        self.assertEqual(tokens(self.server.usage), 100)
        record = self.server.usage_telemetry()["by_thread"]["root"]["review"]
        self.assertEqual(record["notifications"], 2)
        self.assertEqual(tokens(record["last_token_usage"]), 100)

    def test_usage_before_turn_acceptance_is_deferred_until_exact_binding(self):
        self.server._usage_turn_id = None
        self.feed(notification(21))
        self.assertIsNone(self.server.usage)
        self.server._bind_usage_turn("review")
        self.assertEqual(tokens(self.server.usage), 21)

    def test_early_usage_for_a_different_turn_fails_at_acceptance(self):
        self.server._usage_turn_id = None
        self.feed(notification(21, turn="wrong"))
        with self.assertRaisesRegex(RuntimeFailure, "another native turn"):
            self.server._bind_usage_turn("review")
        self.assertIsNone(self.server.usage)

    def test_real_parent_overshoot_remains_partial_not_a_physical_cap(self):
        with self.assertRaisesRegex(RuntimeFailure, "exceeded run allowance") as stopped:
            self.feed(notification(881564, cached=788096))
        self.assertEqual(tokens(stopped.exception.usage), 881564)
        self.assertFalse(stopped.exception.usage_complete)
        self.assertEqual(stopped.exception.usage_telemetry["thread_id"], "root")
        self.assertEqual(stopped.exception.usage_telemetry["turn_id"], "review")

    def test_delegation_activity_stops_before_waiting_for_child_or_recovery(self):
        self.feed(notification(12000))
        event = {"method": "item/started", "params": {"threadId": "root", "turnId": "review",
                 "item": {"type": "subAgentActivity", "kind": "started", "agentThreadId": "child"}}}
        with self.assertRaisesRegex(RuntimeFailure, "delegation observed although disabled") as stopped:
            self.feed(event)
        self.assertEqual(tokens(stopped.exception.usage), 12000)
        self.assertEqual(stopped.exception.usage_telemetry["scope_errors"][0]["agentThreadId"], "child")

    def test_foreign_child_terminal_failure_cannot_be_ignored(self):
        with self.assertRaisesRegex(RuntimeFailure, "unauthorized native thread/turn"):
            self.feed({"method": "turn/completed", "params": {"threadId": "child",
                "turn": {"id": "child-turn", "status": "failed", "error": {"codexErrorInfo": "serverOverloaded"}}}})

    def test_accepted_turn_must_match_started_notification(self):
        with self.assertRaisesRegex(RuntimeFailure, "changed the observed turn identity"):
            self.server._bind_usage_turn("different")

    def test_runtime_failure_keeps_attribution_and_closes_native_process(self):
        self.feed(notification(41))
        server = SimpleNamespace(proc=object(), _proxy_relay=None, usage=self.server.usage,
            runtime_identity=self.server.runtime_identity, usage_telemetry=self.server.usage_telemetry,
            execute=Mock(side_effect=RuntimeError("fixture interrupted")), close=Mock())
        with patch("harness.factory_runtime.FactoryAppServer", return_value=server):
            runtime = LocalRuntime()
            with self.assertRaises(RuntimeFailure) as stopped:
                runtime.agent("review", {}, Path("/fixture"), {}, Path("/unused"), 3, [])
        self.assertEqual(stopped.exception.usage_telemetry["thread_id"], "root")
        self.assertEqual(tokens(stopped.exception.usage), 41)
        server.close.assert_called_once()
        self.assertIsNone(runtime.current_process)


if __name__ == "__main__":
    unittest.main()
