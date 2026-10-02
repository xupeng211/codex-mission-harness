import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.resource_gate import (ResourceGateDenied, canonical, digest,
                                   model_request, normalize_deepseek_usage, reserve,
                                   sign_authorization)
from harness.model_registry import ModelSpec


def private(path, data):
    path.write_bytes(canonical(data) + b"\n")
    path.chmod(0o600)


class ResourceGateTests(unittest.TestCase):
    REQUEST_256 = json.loads((Path(__file__).parent / "fixtures" / "request_256_usage.json").read_text())
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "gate.key"
        self.key.write_bytes(b"synthetic-offline-gate-key")
        self.key.chmod(0o600)
        self.ledger = self.root / "resource-ledger.json"
        self.history = [{"number": 1, "provider": "deepseek", "status": "FAILED",
                         "historical_token_usage": "UNKNOWN"}]
        private(self.ledger, {"counter_semantics": "original mission ledger",
                              "requests": list(self.history)})
        self.call_wall = self.root / "call-wall.json"
        self.started = time.time() - 10
        private(self.call_wall, {"mission_id": "mission-a", "original_started_epoch": self.started,
                                 "before": {"ledger_sha256": digest(self.ledger.read_bytes())},
                                 "after": {"max_logical_model_calls": 5,
                                           "max_wall_clock_seconds": 1000, "calls_used": 1}})
        self.approval = self.root / "token-cost-approval.json"
        lane = lambda model, unit: {
            "model": model, "unknown_policy": "DEBIT_FULL_RESERVATION_STOP_ON_OVERAGE",
            "token_limit": {"input": 30, "output": 30, "reasoning": 30, "cache": 30},
            "token_reservation": {"input": 10, "output": 10, "reasoning": 10, "cache": 10},
            "cost_unit": unit, "cost_limit_microunits": 30,
            "cost_reservation_microunits": 10}
        self.payload = {"version": "cmh-resource-budget/v1", "mission_id": "mission-a",
                        "authorization_id": "synthetic-offline-approval",
                        "approval_source": "SYNTHETIC_TEST_FIXTURE", "approved_at_epoch": time.time(),
                        "original_started_epoch": self.started, "baseline_calls": 1,
                        "ledger_path": str(self.ledger),
                        "baseline_ledger_sha256": digest(self.ledger.read_bytes()),
                        "baseline_requests_sha256": digest(canonical(self.history)),
                        "max_logical_model_calls": 5, "max_wall_clock_seconds": 1000,
                        "token_authorization": "APPROVED", "cost_authorization": "APPROVED",
                        "call_wall_authorization_path": str(self.call_wall),
                        "call_wall_authorization_sha256": digest(self.call_wall.read_bytes()),
                        "providers": {"openai": lane("gpt-5.6-sol", "CODEX_SUBSCRIPTION_UNITS"),
                                      "deepseek": lane("deepseek-flash", "USD")}}
        self.payload["providers"]["deepseek"]["price_microusd_per_million"] = {
            "input_cache_miss": 300000, "output": 1200000, "cache_hit": 6000}
        self.publish()
        self.freeze = self.root / "ledger-freeze.json"
        self.freeze_current_history()
        self.env = {"CMH_RESOURCE_AUTHORIZATION": str(self.approval),
                    "CMH_RESOURCE_AUTH_SHA256": digest(self.approval.read_bytes()),
                    "CMH_RESOURCE_GATE_KEY_FILE": str(self.key),
                    "CMH_RESOURCE_LEDGER": str(self.ledger),
                    "CMH_RESOURCE_MISSION_ID": "mission-a", "CMH_RESOURCE_RUN_ID": "run-a",
                    "CMH_RESOURCE_FREEZE": str(self.freeze),
                    "CMH_RESOURCE_FREEZE_SHA256": digest(self.freeze.read_bytes())}

    def publish(self):
        private(self.approval, sign_authorization(self.payload, self.key.read_bytes()))

    def freeze_current_history(self):
        rows = json.loads(self.ledger.read_bytes())["requests"]
        private(self.freeze, sign_authorization({
            "version": "cmh-ledger-freeze/v1", "mission_id": "mission-a",
            "ledger_path": str(self.ledger), "frozen_calls": len(rows),
            "frozen_requests_sha256": digest(canonical(rows))}, self.key.read_bytes()))

    def call(self, provider="openai", model=None, environment=None):
        return reserve(provider=provider, model=model or ("gpt-5.6-sol" if provider == "openai"
                                                   else "deepseek-flash"), prompt=b"fixture",
                       stage="chunk-000", environment=self.env if environment is None else environment)

    def rows(self):
        return json.loads(self.ledger.read_text())["requests"]

    def test_missing_token_or_cost_approval_fails_before_ledger_mutation(self):
        for field in ("token_authorization", "cost_authorization"):
            self.payload[field] = "PENDING"
            self.publish()
            self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
            with self.assertRaises(ResourceGateDenied):
                self.call()
            self.assertEqual(len(self.rows()), 1)
            self.payload[field] = "APPROVED"

    def test_missing_contract_blocks_actual_openai_subprocess(self):
        from harness.openai_invocation import invoke_openai
        with patch.dict(os.environ, {}, clear=True), \
             patch("harness.openai_invocation.subprocess.Popen") as launch:
            with self.assertRaises(ResourceGateDenied):
                invoke_openai("fixture", ModelSpec("openai", "gpt-5.6-sol", "high"), {})
            launch.assert_not_called()

    def test_missing_contract_blocks_actual_deepseek_subprocess(self):
        import deepseek_review
        with patch.dict(os.environ, {}, clear=True), \
             patch("deepseek_review.subprocess.Popen") as launch:
            with self.assertRaises(ResourceGateDenied):
                deepseek_review.invoke_reviewer(["/bin/false", "--model", "deepseek-flash"],
                                                "fixture", {}, 1)
            launch.assert_not_called()

    def test_missing_contract_blocks_qualification_provider_entry(self):
        from harness.model_qualification import _actual_provider_invoke
        with patch.dict(os.environ, {}, clear=True), \
             patch("harness.model_qualification._actual_provider_invoke_unmetered") as launch:
            with self.assertRaises(ResourceGateDenied):
                _actual_provider_invoke(ModelSpec("deepseek", "deepseek-flash"), "fixture",
                                        token="synthetic", timeout=1)
            launch.assert_not_called()

    def test_historical_unknown_and_failed_record_preserved(self):
        r = self.call()
        r.settle("FAILED")
        self.assertEqual(self.rows()[0], self.history[0])
        self.assertEqual(self.rows()[1]["status"], "FAILED")
        self.assertEqual(self.rows()[1]["usage_accounting"], "FULL_RESERVATION_RETAINED")

    def test_started_and_unknown_block_new_call(self):
        self.call()
        with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
            self.call()
        r = self.rows(); r[-1]["status"] = "UNKNOWN"
        private(self.ledger, {"counter_semantics": "original mission ledger", "requests": r})
        with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
            self.call()

    def test_provider_and_mission_isolation(self):
        r = self.call(); r.settle("RETURNED")
        d = self.call("deepseek"); d.settle("RETURNED")
        self.assertEqual([x["provider"] for x in self.rows()[1:]], ["openai", "deepseek"])
        with self.assertRaisesRegex(ResourceGateDenied, "mission"):
            self.call(environment=dict(self.env, CMH_RESOURCE_MISSION_ID="other"))
        with self.assertRaisesRegex(ResourceGateDenied, "provider/model"):
            self.call(model="other")

    def test_token_and_cost_limits_are_independent(self):
        self.payload["providers"]["openai"]["token_limit"]["input"] = 10
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        r = self.call(); r.settle("RETURNED")
        with self.assertRaisesRegex(ResourceGateDenied, "token budget"):
            self.call()
        self.payload["providers"]["openai"]["token_limit"]["input"] = 30
        self.payload["providers"]["openai"]["cost_limit_microunits"] = 10
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "cost budget"):
            self.call()

    def test_authorization_version_rotation_keeps_prior_debit(self):
        first_hash = self.env["CMH_RESOURCE_AUTH_SHA256"]
        r = self.call(); r.settle("RETURNED")
        self.payload["authorization_id"] = "later-approved-version"
        self.payload["providers"]["openai"]["token_limit"]["input"] = 10
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        self.assertNotEqual(first_hash, self.env["CMH_RESOURCE_AUTH_SHA256"])
        with self.assertRaisesRegex(ResourceGateDenied, "token budget"):
            self.call()
        self.assertEqual(self.rows()[1]["authorization_sha256"], first_hash)

    def test_over_reservation_blocks_following_call(self):
        r = self.call()
        r.observe({"tokens": {"input": 11, "output": 0, "reasoning": 0, "cache": 0}})
        r.settle("RETURNED")
        with self.assertRaisesRegex(ResourceGateDenied, "over-reservation"):
            self.call()

    def test_cli_usd_metadata_is_not_misrepresented_as_billed_cost(self):
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 0, "output": 0, "reasoning": 0, "cache": 0},
                   "cache_read_tokens": 0, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 9999999,
                   "cost_classification": "OBSERVED_UNBILLED"})
        r.settle("RETURNED")
        self.assertEqual(self.rows()[-1]["estimated_cost_microusd"], 0)
        self.assertEqual(self.rows()[-1]["usage_accounting"], "OVER_RESERVATION_BLOCK_FUTURE_CALLS")
        self.assertEqual(self.rows()[-1]["cost_overage_source"], "CLI_ESTIMATE_UNBILLED")

    def test_authorized_price_estimate_over_reservation_blocks_following_call(self):
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 0, "output": 10, "reasoning": 0, "cache": 0},
                   "cache_read_tokens": 0, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 0})
        r.settle("RETURNED")
        self.assertGreater(self.rows()[-1]["estimated_cost_microusd"], 10)
        with self.assertRaisesRegex(ResourceGateDenied, "over-reservation"):
            self.call("deepseek")

    def test_reasoning_and_cache_tokens_are_priced_once(self):
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 10, "output": 10, "reasoning": 8, "cache": 8},
                   "cache_read_tokens": 8, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 0})
        r.settle("RETURNED")
        self.assertEqual(self.rows()[-1]["estimated_cost_microusd"], 16)

    def test_request_256_cache_read_may_exceed_non_cached_input(self):
        self.payload["providers"]["deepseek"]["cost_reservation_microunits"] = 3_000_000
        self.payload["providers"]["deepseek"]["cost_limit_microunits"] = 9_000_000
        self.payload["providers"]["deepseek"]["token_reservation"] = {
            "input": 64_000, "output": 128_000, "reasoning": 128_000, "cache": 64_000}
        self.payload["providers"]["deepseek"]["token_limit"] = {
            "input": 192_000, "output": 384_000, "reasoning": 384_000, "cache": 192_000}
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        usage = self.REQUEST_256["usage"]
        r = self.call("deepseek")
        r.observe({"tokens": {"input": usage["input_tokens"], "output": usage["output_tokens"],
                              "reasoning": usage["output_tokens_details"]["thinking_tokens"],
                              "cache": usage["cache_read_input_tokens"]},
                   "cache_read_tokens": usage["cache_read_input_tokens"],
                   "cache_creation_tokens": usage["cache_creation_input_tokens"],
                   "cli_reported_cost_microunits": round(self.REQUEST_256["total_cost_usd"] * 1_000_000)})
        r.settle("RETURNED")
        self.assertEqual(self.rows()[-1]["usage_accounting"], "FULL_RESERVATION_RETAINED")
        self.assertEqual(self.rows()[-1]["estimated_cost_microusd"], 153633)

    def test_request_256_raw_fields_normalize_without_reasoning_duplication(self):
        raw = self.REQUEST_256["usage"]
        observed = normalize_deepseek_usage(
            raw, self.REQUEST_256["total_cost_usd"],
            self.REQUEST_256["modelUsage"]["deepseek-flash"])
        self.assertEqual(observed["tokens"], {
            "input": 9566, "output": 125504, "reasoning": 0, "cache": 26368})
        self.assertEqual(observed["cache_read_tokens"], 26368)
        self.assertEqual(observed["cache_creation_tokens"], 0)
        self.assertEqual(observed["cli_reported_cost_microunits"], 2553618)
        self.assertEqual(observed["raw_usage_fields"], raw)
        self.assertEqual(observed["usage_scope"], "CLI_SESSION_AGGREGATE")

    def test_request_256_cli_estimate_over_cost_reservation_stops_future_call(self):
        self.payload["providers"]["deepseek"]["token_reservation"] = {
            "input": 64_000, "output": 128_000, "reasoning": 128_000, "cache": 64_000}
        self.payload["providers"]["deepseek"]["token_limit"] = {
            "input": 192_000, "output": 384_000, "reasoning": 384_000, "cache": 192_000}
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        usage = self.REQUEST_256["usage"]
        r = self.call("deepseek")
        r.observe({"tokens": {"input": usage["input_tokens"], "output": usage["output_tokens"],
                              "reasoning": 0, "cache": usage["cache_read_input_tokens"]},
                   "cache_read_tokens": usage["cache_read_input_tokens"],
                   "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": round(self.REQUEST_256["total_cost_usd"] * 1_000_000)})
        r.settle("RETURNED")
        self.assertEqual(self.rows()[-1]["usage_accounting"], "OVER_RESERVATION_BLOCK_FUTURE_CALLS")
        self.assertEqual(self.rows()[-1]["cost_overage_source"], "CLI_ESTIMATE_UNBILLED")

    def test_inconsistent_cache_split_and_missing_usage_fail_closed(self):
        for observed in (
            {"tokens": {"input": 2, "output": 3, "reasoning": 0, "cache": 4},
             "cache_read_tokens": 3, "cache_creation_tokens": 0,
             "cli_reported_cost_microunits": 0},
            {"tokens": {"input": None, "output": 3, "reasoning": 0, "cache": 0},
             "cache_read_tokens": 0, "cache_creation_tokens": 0,
             "cli_reported_cost_microunits": 0},
            {"tokens": {"input": 2, "output": 3, "reasoning": 0, "cache": 0},
             "cache_read_tokens": 0, "cache_creation_tokens": 0},
            {"tokens": {"input": 2, "output": 3, "reasoning": 0, "cache": 0},
             "cache_read_tokens": 0, "cache_creation_tokens": 0,
             "cli_reported_cost_microunits": 0,
             "raw_model_usage": {"inputTokens": 9, "outputTokens": 3,
                                 "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0,
                                 "thinkingTokens": 0, "costUSD": 0}},
        ):
            with self.subTest(observed=observed):
                r = self.call("deepseek")
                r.observe(observed)
                r.settle("RETURNED")
                self.assertEqual(self.rows()[-1]["usage_accounting"],
                                 "USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS")
                with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
                    self.call("deepseek")
                # Keep the same fixture budget, but reset only synthetic rows.
                private(self.ledger, {"counter_semantics": "original mission ledger",
                                      "requests": list(self.history)})

    def test_unknown_request_retains_full_debit_and_blocks(self):
        r = self.call("openai")
        r.settle("UNKNOWN")
        self.assertEqual(self.rows()[-1]["cost_reservation_microunits"], 10)
        self.assertEqual(self.rows()[-1]["token_reservation"]["input"], 10)
        with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
            self.call("openai")

    def test_frozen_abnormal_history_cannot_be_removed_to_regain_capacity(self):
        r = self.call("openai")
        r.observe({"tokens": {"input": 11, "output": 0, "reasoning": 0, "cache": 0}})
        r.settle("RETURNED")
        self.freeze_current_history()
        self.env["CMH_RESOURCE_FREEZE_SHA256"] = digest(self.freeze.read_bytes())
        rows = self.rows()
        private(self.ledger, {"counter_semantics": "original mission ledger",
                              "requests": rows[:-1]})
        with self.assertRaisesRegex(ResourceGateDenied, "frozen request history"):
            self.call("openai")

    def test_legacy_settlement_cannot_hide_cli_cost_overage(self):
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 1, "output": 1, "reasoning": 0, "cache": 0},
                   "cache_read_tokens": 0, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 11})
        r.settle("RETURNED")
        rows = self.rows()
        rows[-1]["usage_accounting"] = "FULL_RESERVATION_RETAINED"  # old runtime defect
        private(self.ledger, {"counter_semantics": "original mission ledger", "requests": rows})
        with self.assertRaisesRegex(ResourceGateDenied, "historical cost estimate"):
            self.call("deepseek")

    def test_same_request_cannot_settle_twice(self):
        r = self.call("openai")
        r.settle("RETURNED")
        with self.assertRaisesRegex(ResourceGateDenied, "settlement identity/state mismatch"):
            r.settle("RETURNED")
        self.assertEqual(len(self.rows()), 2)

    def test_overage_blocks_real_deepseek_invoker_before_subprocess(self):
        import deepseek_review
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 1, "output": 10, "reasoning": 0, "cache": 0},
                   "cache_read_tokens": 0, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 11})
        r.settle("RETURNED")
        with patch.dict(os.environ, self.env, clear=True), \
             patch("deepseek_review._invoke_reviewer_unmetered") as launch:
            with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
                deepseek_review.invoke_reviewer(["/bin/false", "--model", "deepseek-flash"],
                                                "fixture", {}, 1)
            launch.assert_not_called()

    def test_tampered_approval_or_ordinary_limit_raise_fails(self):
        self.payload["max_logical_model_calls"] = 6
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "hard limits"):
            self.call()
        self.payload["max_logical_model_calls"] = 5
        self.publish()
        with self.assertRaisesRegex(ResourceGateDenied, "version/hash"):
            self.call()

    def test_baseline_mutation_fails_closed(self):
        d=json.loads(self.ledger.read_text());d["requests"][0]["status"]="RETURNED";private(self.ledger,d)
        with self.assertRaisesRegex(ResourceGateDenied, "historical"):
            self.call()

    def test_nested_invocation_is_one_logical_call(self):
        with model_request(provider="openai", model="gpt-5.6-sol", prompt=b"outer",
                           stage="qualification", environment=self.env) as outer:
            with model_request(provider="openai", model="gpt-5.6-sol", prompt=b"inner",
                               stage="codex", environment=self.env) as inner:
                self.assertIs(outer, inner)
            with self.assertRaisesRegex(ResourceGateDenied, "nested model"):
                with model_request(provider="deepseek", model="deepseek-flash", prompt=b"other",
                                   stage="not-the-same-call", environment=self.env):
                    pass
        self.assertEqual(len(self.rows()), 2)
        self.assertEqual(self.rows()[-1]["status"], "RETURNED")

    def test_exception_retains_failed_reservation(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            with model_request(provider="openai", model="gpt-5.6-sol", prompt=b"fixture",
                               stage="chunk", environment=self.env):
                raise RuntimeError("synthetic")
        self.assertEqual(self.rows()[-1]["status"], "FAILED")
        self.assertEqual(self.rows()[-1]["usage_accounting"], "FULL_RESERVATION_RETAINED")

    def test_durable_replay_does_not_repeat_committed_model_call(self):
        import deepseek_review as storage
        from harness.review_resume import ReviewRun
        repo = self.root / "repo"; repo.mkdir()
        evidence = self.root / "evidence"
        stages = [("chunk-000", "chunk")]
        executed = []
        def execute():
            executed.append(1)
            with model_request(provider="deepseek", model="deepseek-flash", prompt=b"source",
                               stage="chunk-000", environment=self.env):
                return b'{"findings":[]}'
        def open_run():
            return ReviewRun(evidence, repo, {"mission_id": "mission-a"}, stages,
                             storage, prefix="fixture-")
        first = open_run()
        first.stage("chunk-000", "chunk", b"source", execute, json.loads)
        first.close()
        resumed = open_run()
        resumed.stage("chunk-000", "chunk", b"source", execute, json.loads)
        resumed.close()
        self.assertEqual(len(executed), 1)
        self.assertEqual(len(self.rows()), 2)

    def test_call_and_wall_hard_stops(self):
        call_wall = json.loads(self.call_wall.read_text())
        call_wall["after"]["max_wall_clock_seconds"] = 1
        private(self.call_wall, call_wall)
        self.payload["max_wall_clock_seconds"] = 1
        self.payload["call_wall_authorization_sha256"] = digest(self.call_wall.read_bytes())
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "hard stop"):
            self.call()
        call_wall["after"]["max_wall_clock_seconds"] = 1000
        private(self.call_wall, call_wall)
        self.payload["max_wall_clock_seconds"] = 1000
        self.payload["call_wall_authorization_sha256"] = digest(self.call_wall.read_bytes())
        for lane in self.payload["providers"].values():
            lane["token_limit"] = {key: 50 for key in lane["token_limit"]}
            lane["cost_limit_microunits"] = 50
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        for _ in range(4):
            r = self.call(); r.settle("RETURNED")
        with self.assertRaisesRegex(ResourceGateDenied, "hard stop"):
            self.call()


if __name__ == "__main__":
    unittest.main()
