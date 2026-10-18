import hashlib
import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
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
        self.price_source = self.root / "synthetic-price-source.json"
        private(self.price_source, {"fixture": "synthetic-price-source"})
        self.route_evidence = self.root / "synthetic-route-evidence.json"
        private(self.route_evidence, {"fixture": "synthetic-billing-route"})
        self.payload["providers"]["deepseek"].update({
            "billing_route_verified": True,
            "price_source_path": str(self.price_source),
            "price_source_sha256": digest(self.price_source.read_bytes()),
            "billing_route_evidence_path": str(self.route_evidence),
            "billing_route_evidence_sha256": digest(self.route_evidence.read_bytes())})
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

    def test_unverified_billing_route_or_price_source_blocks_before_reservation(self):
        lane = self.payload["providers"]["deepseek"]
        lane["billing_route_verified"] = False
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "billing route"):
            self.call("deepseek")
        self.assertEqual(len(self.rows()), 1)
        lane["billing_route_verified"] = True
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        private(self.price_source, {"fixture": "tampered-price-source"})
        with self.assertRaisesRegex(ResourceGateDenied, "price_source hash changed"):
            self.call("deepseek")
        self.assertEqual(len(self.rows()), 1)

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

    def test_signed_official_basis_disposes_only_bound_cli_fallback_overage(self):
        r = self.call("deepseek")
        observed = {"tokens": {"input": 1, "output": 1, "reasoning": 0, "cache": 0},
                    "cache_read_tokens": 0, "cache_creation_tokens": 0,
                    "cli_reported_cost_microunits": 11,
                    "raw_model_usage": {"inputTokens": 1, "outputTokens": 1,
                                        "cacheReadInputTokens": 0, "cacheCreationInputTokens": 0,
                                        "thinkingTokens": 0, "costUSD": 0.000011,
                                        "costBasis": "unknown"}}
        r.observe(observed); r.settle("RETURNED")
        original = dict(self.rows()[-1])
        self.freeze_current_history()
        self.env["CMH_RESOURCE_FREEZE_SHA256"] = digest(self.freeze.read_bytes())
        export = self.root / "synthetic-official-export.csv"
        private(export, {"fixture": "account tariff and daily total"})
        raw_cli = self.root / "synthetic-cli-session.json"
        private(raw_cli, {"usage": {"input_tokens": 1, "output_tokens": 1,
                                    "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
                                    "output_tokens_details": {"thinking_tokens": 0}},
                          "modelUsage": {"deepseek-flash": observed["raw_model_usage"]},
                          "total_cost_usd": 0.000011})
        recovery = self.root / "synthetic-recovery.json"
        rows = self.rows()
        private(recovery, sign_authorization({
            "version": "cmh-deepseek-official-billing-recovery/v1",
            "mission_id": "mission-a", "frozen_calls": len(rows),
            "frozen_requests_sha256": digest(canonical(rows)),
            "source_daily_export_sha256": digest(export.read_bytes()),
            "model": "deepseek-flash", "account_key_name": "synthetic-harness",
            "price_source_sha256": digest(self.price_source.read_bytes()),
            "billing_route_evidence_sha256": digest(self.route_evidence.read_bytes()),
            "official_price_microusd_per_million": self.payload["providers"]["deepseek"]["price_microusd_per_million"],
            "resumption_approved": True, "approval_source": "synthetic explicit future approval",
            "dispositions": [{"number": 2, "request_id": original["request_id"],
                              "row_sha256": digest(canonical(original)),
                              "raw_cli_artifact_path": str(raw_cli),
                              "raw_cli_artifact_sha256": digest(raw_cli.read_bytes()),
                              "official_usd_snapshot_estimate_microusd": 2,
                              "original_estimated_cost_microusd": original["estimated_cost_microusd"],
                              "legacy_estimate_incorrect_or_missing": False,
                              "classification": "CLI_FALLBACK_ESTIMATE_NOT_BILLED",
                              "settlement_status": "ESTIMATED_ONLY",
                              "confirmed_billed_cost": "UNKNOWN",
                              "reservation_refund_microusd": 0,
                              "retain_original_overage": True}]}, self.key.read_bytes()))
        lane = self.payload["providers"]["deepseek"]
        lane.update({"cli_cost_policy": "VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK",
                     "billing_account_key_name": "synthetic-harness",
                     "official_billing_export_path": str(export),
                     "official_billing_export_sha256": digest(export.read_bytes()),
                     "billing_recovery_path": str(recovery),
                     "billing_recovery_sha256": digest(recovery.read_bytes())})
        self.payload["billing_recovery_approved"] = True
        self.payload["billing_recovery_approval_source"] = "synthetic explicit future approval"
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        second = self.call("deepseek")
        second.observe(observed); second.settle("RETURNED")
        self.assertEqual(self.rows()[1], original)
        self.assertEqual(self.rows()[2]["usage_accounting"], "FULL_RESERVATION_RETAINED")
        self.assertTrue(self.rows()[2]["cli_fallback_over_reservation_observed"])
        original_export = export.read_bytes()
        private(export, {"fixture": "changed daily export"})
        with self.assertRaisesRegex(ResourceGateDenied, "evidence hash changed"):
            self.call("openai")
        export.write_bytes(original_export)
        original_recovery = recovery.read_bytes()
        private(recovery, {"fixture": "changed disposition"})
        with self.assertRaisesRegex(ResourceGateDenied, "evidence hash changed"):
            self.call("openai")
        recovery.write_bytes(original_recovery)
        original_raw = raw_cli.read_bytes()
        private(raw_cli, {"fixture": "changed CLI usage"})
        with self.assertRaisesRegex(ResourceGateDenied, "raw CLI evidence hash changed"):
            self.call("openai")
        raw_cli.write_bytes(original_raw)
        lane["price_microusd_per_million"]["output"] += 1
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "identity mismatch"):
            self.call("openai")
        lane["price_microusd_per_million"]["output"] -= 1
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        third = self.call("openai")
        third.settle("FAILED")
        self.assertEqual(self.rows()[3]["cost_reservation_microunits"], 10)

    def test_recovery_policy_without_explicit_approval_cannot_clear_old_overage(self):
        r = self.call("deepseek")
        r.observe({"tokens": {"input": 1, "output": 1, "reasoning": 0, "cache": 0},
                   "cache_read_tokens": 0, "cache_creation_tokens": 0,
                   "cli_reported_cost_microunits": 11})
        r.settle("RETURNED")
        self.payload["providers"]["deepseek"]["cli_cost_policy"] = (
            "VERIFIED_OFFICIAL_PRICE_WITH_DISCLOSED_CLI_FALLBACK")
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaises(ResourceGateDenied):
            self.call("deepseek")
        self.assertEqual(len(self.rows()), 2)

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

    def test_earlier_original_started_at_is_conservative_wall_start(self):
        self.payload["original_started_at_utc"] = datetime.fromtimestamp(
            time.time() - 2000, timezone.utc).isoformat()
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "wall-clock hard stop"):
            self.call()
        self.assertEqual(len(self.rows()), 1)

    def test_signed_stage_contract_selects_exact_deepseek_reservations(self):
        lane = self.payload["providers"]["deepseek"]
        lane["stage_token_reservation"] = {
            "chunk_or_qualification": dict(lane["token_reservation"]),
            "group_or_cross_group": {"input": 10, "cache": 20, "output": 20, "reasoning": 10}}
        lane["token_limit"] = {key: 100 for key in lane["token_limit"]}
        lane["cost_limit_microunits"] = 100
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        for stage, expected_cache in (("qualification-case", 10), ("chunk-000.json", 10),
                                      ("group-000.json", 20), ("aggregate.json", 20)):
            r = reserve(provider="deepseek", model="deepseek-flash", prompt=b"fixture",
                        stage=stage, environment=self.env)
            self.assertEqual(self.rows()[-1]["token_reservation"]["cache"], expected_cache)
            r.observe({"tokens": {"input": 1, "cache": 0, "output": 1, "reasoning": 0},
                       "cache_read_tokens": 0, "cache_creation_tokens": 0,
                       "cli_reported_cost_microunits": 1})
            r.settle("RETURNED")
        before = len(self.rows())
        with self.assertRaisesRegex(ResourceGateDenied, "unrecognized DeepSeek review stage"):
            reserve(provider="deepseek", model="deepseek-flash", prompt=b"fixture",
                    stage="group-forged", environment=self.env)
        self.assertEqual(len(self.rows()), before)

    def test_independent_provider_call_cap(self):
        self.payload["providers"]["deepseek"]["max_new_calls"] = 1
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        first = self.call("deepseek")
        first.observe({"tokens": {"input": 1, "cache": 0, "output": 1, "reasoning": 0},
                       "cache_read_tokens": 0, "cache_creation_tokens": 0,
                       "cli_reported_cost_microunits": 1})
        first.settle("RETURNED")
        with self.assertRaisesRegex(ResourceGateDenied, "provider independent call budget"):
            self.call("deepseek")

    def test_signed_qualification_scope_enforces_provider_prompt_order_and_four_calls(self):
        parent = self.root / "parent-authorization.json"
        self.payload["providers"]["deepseek"]["token_limit"] = {
            key: 100 for key in ("input", "cache", "output", "reasoning")}
        self.payload["providers"]["deepseek"]["cost_limit_microunits"] = 50
        private(parent, sign_authorization(self.payload, self.key.read_bytes()))
        prompts = [f"case-{i}".encode() for i in range(4)]
        self.payload.update({
            "authorization_id": "bounded-qualification-only",
            "approval_source": "SYNTHETIC_ONE_ATTEMPT_APPROVAL",
            "previous_authorization_sha256": digest(parent.read_bytes()),
            "execution_scope_parent_path": str(parent),
            "execution_scope_parent_sha256": digest(parent.read_bytes()),
            "execution_scope": {
                "version": "cmh-one-qualification/v1", "provider": "deepseek",
                "model": "deepseek-flash", "stage": "qualification-case",
                "baseline_calls": 1,
                "baseline_requests_sha256": digest(canonical(self.history)),
                "max_new_calls": 4, "run_id": "run-a",
                "prompt_sha256_in_order": [digest(p) for p in prompts]}})
        self.publish()
        self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        before = self.ledger.read_bytes()
        for provider, model, prompt, stage in (("openai", "gpt-5.6-sol", prompts[0], "qualification-case"),
                                               ("deepseek", "deepseek-flash", prompts[1], "qualification-case"),
                                               ("deepseek", "deepseek-flash", prompts[0], "chunk-000")):
            with self.assertRaises(ResourceGateDenied):
                reserve(provider=provider, model=model, prompt=prompt,
                        stage=stage, environment=self.env)
        self.assertEqual(self.ledger.read_bytes(), before)
        for prompt in prompts:
            reservation = reserve(provider="deepseek", model="deepseek-flash",
                                  prompt=prompt, stage="qualification-case", environment=self.env)
            reservation.observe({"tokens": {"input": 1, "cache": 0, "output": 1, "reasoning": 0},
                                 "cache_read_tokens": 0, "cache_creation_tokens": 0,
                                 "cli_reported_cost_microunits": 1})
            reservation.settle("RETURNED")
        with self.assertRaises(ResourceGateDenied):
            reserve(provider="deepseek", model="deepseek-flash", prompt=prompts[0],
                    stage="qualification-case", environment=self.env)

    def test_request_286_exception_requires_exact_signed_row_and_does_not_cover_future_overage(self):
        old = self.rows()
        old.extend({"number": i, "provider": "deepseek", "status": "FAILED"}
                   for i in range(2, 286))
        row = {"number": 286, "provider": "deepseek", "model": "deepseek-flash",
               "stage": "group-000.json", "request_id": "original-286", "status": "RETURNED",
               "usage_accounting": "OVER_RESERVATION_BLOCK_FUTURE_CALLS",
               "token_reservation": {"input": 64000, "cache": 64000,
                                     "output": 128000, "reasoning": 128000},
               "reported_usage": {"tokens": {"input": 47636, "cache": 132096,
                                              "output": 130294, "reasoning": 0}}}
        old.append(row)
        private(self.ledger, {"requests": old})
        self.payload["baseline_ledger_sha256"] = digest(self.ledger.read_bytes())
        self.payload["request286_original_ledger_sha256"] = digest(self.ledger.read_bytes())
        self.payload["max_logical_model_calls"] = 300
        self.payload["providers"]["openai"]["max_new_calls"] = 5
        wall = json.loads(self.call_wall.read_text())
        wall["before"]["ledger_sha256"] = self.payload["baseline_ledger_sha256"]
        wall["after"].update(max_logical_model_calls=300)
        private(self.call_wall, wall)
        self.payload["call_wall_authorization_sha256"] = digest(self.call_wall.read_bytes())
        self.freeze_current_history()
        self.env["CMH_RESOURCE_FREEZE_SHA256"] = digest(self.freeze.read_bytes())
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
            self.call()
        disposition = self.root / "request-286-disposition.json"
        evidence = {"version": "cmh-request286-token-recovery/v1", "mission_id": "mission-a",
                    "authorization_id": self.payload["authorization_id"], "request_number": 286,
                    "request_id": "original-286", "first_286_rows_sha256": digest(canonical(old)),
                    "original_ledger_sha256": self.payload["baseline_ledger_sha256"],
                    "row_286_sha256": digest(canonical(row)), "refund": 0,
                    "retain_original_overage": True,
                    "source_binding_result": "FAILED_MODEL_OUTPUT_ERROR"}
        private(disposition, sign_authorization(evidence, self.key.read_bytes()))
        self.payload.update(token_recovery_path=str(disposition),
                            token_recovery_sha256=digest(disposition.read_bytes()))
        self.publish(); self.env["CMH_RESOURCE_AUTH_SHA256"] = digest(self.approval.read_bytes())
        next_call = self.call(); next_call.settle("RETURNED")
        self.assertEqual(self.rows()[285], row)
        later = self.rows(); later[-1]["usage_accounting"] = "OVER_RESERVATION_BLOCK_FUTURE_CALLS"
        private(self.ledger, {"requests": later})
        with self.assertRaisesRegex(ResourceGateDenied, "unreconciled"):
            self.call()


if __name__ == "__main__":
    unittest.main()
