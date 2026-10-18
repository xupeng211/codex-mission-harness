"""Synthetic model names/prices only; task routing never invokes a provider."""
import copy
import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, validate_config, git
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_routing import CATEGORIES, estimate, select, validate_pool
from harness.factory_runtime import LocalRuntime, RuntimeFailure
from harness.factory_cli import main as cli_main
from types import SimpleNamespace
import test_factory_candidate as candidate_tests


def pool():
    return {"version": 1, "models": [
        {"id": tier, "model": "fixture-"+tier, "route_id": "fixture-route", "tier": tier,
         "efforts": ["low", "medium", "high", "xhigh"], "categories": sorted(CATEGORIES),
         "available": True, "auto": True, "protocol": "codex_responses", "price": "UNKNOWN",
         "transport": {"type": "cli_proxy", "endpoint": "http://127.0.0.1:18317/v1",
                       "configured_provider": "cli_proxy_api", "policy_file": "/nonexistent/fixture-policy.json"}}
        for tier in ("economy", "balanced", "high")]}


def price():
    return {"currency": "USD", "input_per_million": "2", "output_per_million": "8",
            "cached_input_per_million": "0.5", "source": "offline-fixture-contract-v1",
            "as_of": "2026-10-18", "basis": "operator_verified"}


class SelectionTests(unittest.TestCase):
    def test_explicit_complexity_risk_and_incomplete_attributes(self):
        for attrs, tier in (({"category": "docs", "complexity": "low", "risk": "low"}, "economy"),
                            ({"category": "feature", "complexity": "normal", "risk": "normal"}, "balanced"),
                            ({"category": "bugfix", "complexity": "complex", "risk": "low"}, "high"),
                            ({"category": "docs", "complexity": "low", "risk": "high"}, "high"),
                            ({"category": "security", "complexity": "low", "risk": "low"}, "high"),
                            ({}, "high"), ({"complexity": "low"}, "high")):
            with self.subTest(attrs=attrs), patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                profile, decision = select(pool(), attrs)
                self.assertEqual(profile["model"], "fixture-"+tier)
                self.assertEqual(decision["selected_tier"], tier)
                self.assertEqual((profile, decision), select(pool(), attrs))
                if not attrs:
                    self.assertIn("conservative", decision["reason"])

    def test_manual_model_tier_and_effort_do_not_bypass_capability(self):
        attrs = {"category": "tests", "complexity": "low", "risk": "low"}
        p = pool()
        p["models"][1]["auto"] = False
        profile, decision = select(p, {**attrs, "model": "balanced", "effort": "xhigh"})
        self.assertEqual(profile["model"], "fixture-balanced")
        self.assertEqual(profile["effort"], "xhigh")
        self.assertEqual(decision["selection_mode"], "manual_model")
        self.assertEqual(select(pool(), {**attrs, "tier": "balanced"})[1]["selected_tier"], "balanced")
        for request in ({"model": "economy"}, {"model": "does-not-exist"}, {"tier": "economy"},
                        {"effort": "unsupported"}, {"category": "arbitrary"}, {"model": "high", "fallback": True}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                select(p, request)

    def test_disabled_incompatible_and_unavailable_models_rejected(self):
        for key, value in (("available", False), ("efforts", ["low"]), ("categories", ["docs"]), ("auto", False)):
            p = pool()
            p["models"][2][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "no available"):
                select(p, {"category": "feature", "complexity": "complex", "risk": "high"})

    def test_price_ranking_is_secondary_to_capability_and_reproducible(self):
        p = pool()
        expensive = copy.deepcopy(p["models"][0])
        expensive.update(id="z-expensive", price=price())
        cheap = copy.deepcopy(expensive)
        cheap.update(id="a-cheap", price={**price(), "input_per_million": "1"})
        p["models"] += [expensive, cheap]
        attrs = {"category": "docs", "complexity": "low", "risk": "low"}
        self.assertEqual(select(p, attrs)[1]["pool_model_id"], "a-cheap")
        p["models"].reverse()
        self.assertEqual(select(p, attrs)[1]["pool_model_id"], "a-cheap")
        self.assertEqual(select(p)[1]["pool_model_id"], "high")

    def test_closed_pool_schema_rejects_uncontrolled_routes_and_fake_price(self):
        for mutation in (lambda e: e.update(api_key="secret-sentinel"),
                         lambda e: e.update(protocol="chat_completions"),
                         lambda e: e.update(price={**price(), "basis": "proxy_claim"}),
                         lambda e: e.update(price={**price(), "input_per_million": "NaN"}),
                         lambda e: e.update(price={**price(), "as_of": "unknown"}),
                         lambda e: e.update(price={**price(), "source": "https://host/?key=secret"}),
                         lambda e: e["transport"].update(fallback="official"),
                         lambda e: e["transport"].update(endpoint="https://api.example.com/v1"),
                         lambda e: e.update(available="yes")):
            p = pool()
            mutation(p["models"][0])
            with self.assertRaises(ValueError):
                validate_pool(p)
        p = pool()
        p["models"][1]["transport"]["endpoint"] = "http://127.0.0.1:18318/v1"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            validate_pool(p)

    def test_estimate_requires_known_cache_usage_complete_usage_and_verified_price(self):
        usage = {"input_tokens": 100000, "output_tokens": 10000, "cached_input_tokens": 20000}
        result = estimate(price(), usage, True)
        self.assertEqual(result["amount"], "0.25")
        self.assertEqual(result["actual_bill"], "UNKNOWN")
        self.assertEqual(result["upstream_model_identity"], "NOT_PROVABLE")
        for p, u, complete in (("UNKNOWN", usage, True), (price(), usage, False),
                               (price(), {"input_tokens": 100, "output_tokens": 10}, True),
                               (price(), {**usage, "cached_input_tokens": 100001}, True)):
            self.assertEqual(estimate(p, u, complete), "UNKNOWN")

    def test_config_and_task_routing_remain_opt_in(self):
        original = fixture_config()
        self.assertNotIn("model_routing", validate_config(original))
        configured = {**original, "model_routing": pool()}
        self.assertEqual(validate_config(configured)["model_routing"], pool())

    def test_cli_routes_explicit_task_attributes_without_model_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {**fixture_config(), "simulation": False, "model_routing": pool()}
            path = root/"config.json"
            path.write_text(json.dumps(config))
            with patch("harness.factory_cli.Factory") as constructor, patch("sys.stdout", io.StringIO()):
                factory = constructor.return_value
                factory.run.return_value = {"DELIVERY_STATUS": "LOCAL_CANDIDATE_READY"}
                cli_main(["submit", "offline contract", "--repository", str(root), "--config", str(path), "--json",
                          "--task-category", "docs", "--task-complexity", "low", "--task-risk", "low",
                          "--pool-model", "balanced", "--model-tier", "balanced", "--model-effort", "medium"])
                spec = factory.submit.call_args.args[0]
                self.assertEqual(spec["model_routing"], {"category": "docs", "complexity": "low", "risk": "low",
                                 "model": "balanced", "tier": "balanced", "effort": "medium"})
                self.assertEqual(select(config["model_routing"], spec["model_routing"])[0]["model"], "fixture-balanced")

    def test_route_preview_and_disabled_example_make_no_network_calls(self):
        from harness.factory_routing import main as preview
        example = Path(__file__).resolve().parents[1]/"config/factory.routing.example.json"
        config = validate_config(json.loads(example.read_text()))
        with self.assertRaisesRegex(ValueError, "no available"):
            select(config["model_routing"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, mission_path = root/"config.json", root/"mission.json"
            config_path.write_text(json.dumps({**fixture_config(), "model_routing": pool()}))
            mission_path.write_text(json.dumps({"model_routing": {"category": "docs", "complexity": "low", "risk": "low"}}))
            output = io.StringIO()
            with patch("sys.argv", ["preview", "--config", str(config_path), "--mission", str(mission_path)]), patch("sys.stdout", output), patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                preview()
            result = json.loads(output.getvalue())
            self.assertEqual(result["selection"]["selected_tier"], "economy")
            self.assertEqual(result["model_inference_calls"], 0)
            self.assertEqual(result["REAL_PROXY_MODEL_DISPATCH_VERIFIED"], "NO")

    def test_reused_process_stderr_cannot_mutate_prior_operation_evidence(self):
        class FakeServer:
            def __init__(self, profile, cwd, transcript, *args, **kwargs):
                self.transcript = transcript
                self.proc = object()
                self._proxy_relay = None
                self.errors = transcript.with_suffix(".stderr").open("xb")
                self.turn = 0
            def execute(self, *args, **kwargs):
                self.turn += 1
                self.errors.write(("turn-"+str(self.turn)+"\n").encode())
                self.errors.flush()
                return {"thread_id": "same-thread"}
            def close(self):
                self.errors.close()
        with tempfile.TemporaryDirectory() as directory, patch("harness.factory_runtime.FactoryAppServer", FakeServer):
            root = Path(directory)
            runtime = LocalRuntime()
            profile = {"provider": "openai", "model": "fixture"}
            try:
                runtime.agent("implement", profile, root, {"_reuse_session": True, "_return_thread": True}, root/"first.raw", 5, [])
                before = (root/"first.stderr").read_bytes()
                runtime.agent("rework", profile, root, {"_reuse_session": True, "_return_thread": True, "_thread_id": "same-thread"}, root/"second.raw", 5, [])
                self.assertEqual((root/"first.stderr").read_bytes(), before)
                self.assertEqual(before, b"turn-1\n")
                self.assertEqual((root/"second.stderr").read_bytes(), b"turn-2\n")
            finally:
                runtime.close_session()

    def test_localruntime_rechecks_new_relay_before_sending_a_turn(self):
        profile, _ = select(pool())
        runtime = LocalRuntime()
        expected = {"runtime": {"image": "authorized"}}
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, "profile_identity", return_value={"route_identity": expected}), patch("harness.factory_runtime.FactoryAppServer") as constructor:
            server = constructor.return_value
            server._proxy_relay = SimpleNamespace(policy=SimpleNamespace(identity={"image": "changed"}))
            with self.assertRaisesRegex(RuntimeFailure, "before dispatch"):
                runtime.agent("implement", profile, Path(directory), {"_authorized_route": expected}, Path(directory)/"raw", 5, [])
            server.execute.assert_not_called()
            server.close.assert_called_once()

    def test_reported_route_mismatch_keeps_unknown_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/"source"
            source.mkdir()
            git(source, "init", "-q")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "--allow-empty", "-qm", "baseline")
            config = {**fixture_config(), "simulation": False, "model_routing": pool(),
                      "budget": {"max_agent_runs": 3, "max_run_tokens": 100, "max_total_tokens": 300}}
            runtime = SimpleNamespace(simulation=False, profile_identity=lambda p: {"configured": p, "route_identity": {"model": p["model"]}})
            factory = Factory(root/"state", config, runtime)
            try:
                mission = factory.submit({"version": 2, "mission_id": "mismatch", "repository": str(source), "objective": "offline result contract"})
                spec = json.loads(factory.row(mission)["spec"])
                _, identity = factory.developer_binding(spec)
                with patch("harness.factory_preflight.inspect_prepaid", return_value={"findings": []}), self.assertRaises(FactoryBlocked):
                    factory.operation(mission, "wrong-route", "implement", "developer", {"profile": identity}, {}, True,
                        lambda _: {"usage_complete": True, "usage": {"input_tokens": 7, "output_tokens": 2},
                                   "runtime_identity": {"route_identity": {"model": "other"}, "reported_model": "fixture-high"}})
                row = factory.db.execute("SELECT * FROM operations").fetchone()
                self.assertEqual(row["status"], "UNKNOWN")
                from harness.factory_budget import accounting
                usage = accounting([row], config["budget"])
                self.assertEqual(usage["observed_tokens"], 9)
                self.assertEqual(usage["unknown_token_reservation"], 100)
            finally:
                factory.close()

    def test_localruntime_rejects_changed_authorized_route_before_appserver(self):
        profile, _ = select(pool())
        runtime = LocalRuntime()
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, "profile_identity", return_value={"route_identity": {"changed": True}}), patch("harness.factory_runtime.FactoryAppServer") as server:
            with self.assertRaisesRegex(RuntimeFailure, "authorization"):
                runtime.agent("implement", profile, Path(directory), {"_authorized_route": {"original": True}}, Path(directory)/"raw", 5, [])
            server.assert_not_called()


class RoutingDeliveryTests(unittest.TestCase):
    authorize = candidate_tests.LocalCandidateTests.authorize
    approval = candidate_tests.LocalCandidateTests.approval
    run_candidate = candidate_tests.LocalCandidateTests.run_candidate

    def setUp(self):
        candidate_tests.LocalCandidateTests.setUp(self)
        self.f.close()
        self.config["model_routing"] = pool()
        self.f = Factory(self.root/"routed-state", self.config, self.runtime)
        self.spec["model_routing"] = {"category": "bugfix", "complexity": "low", "risk": "low"}
        # Keep the complete existing local resource/test/isolation authorization.
        self.spec["local_candidate_authorization"]["worktree"] = str(self.f.root/"candidates/feature")
        self.spec["local_candidate_authorization"]["executor_identity"] = self.f.developer_binding(self.spec)[1]

    def test_same_model_thread_and_budget_survive_trusted_qa_repair(self):
        self.runtime.failure = "repair"
        captured = []
        original = self.runtime.agent
        def agent(role, profile, *args):
            captured.append(copy.deepcopy(profile))
            return original(role, profile, *args)
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "LOCAL_CANDIDATE_READY", report)
        self.assertEqual(self.runtime.threads, [None, "fixture-thread"])
        self.assertEqual(self.runtime.operation_limits, [("implement", 60000), ("rework", 36000)])
        self.assertEqual([p["model"] for p in captured], ["fixture-economy", "fixture-economy"])
        self.assertEqual(captured[0], captured[1])
        routing = report["MODEL_ROUTING"]
        self.assertEqual(routing["selection"]["route_id"], "fixture-route")
        self.assertEqual(routing["repair_attempts"], 1)
        self.assertTrue(any(q["status"] == "FAIL" for q in routing["qa_results"]))
        self.assertTrue(all(op["estimated_cost"] == "UNKNOWN" for op in routing["operations"]))
        self.assertTrue(all(isinstance(op["elapsed_seconds"], float) for op in routing["operations"]))
        self.assertEqual(report["OBSERVED_TOKEN_USAGE"]["total"], 22000)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 0)
        self.assertEqual(report["LOCAL_CANDIDATE_EVIDENCE"]["executor_identity"]["model_selection"], routing["selection"])
        self.assertEqual(report["REMOTE_WRITE_STATUS"], "NOT_EXECUTED")
        self.assertEqual(self.runtime.final_calls, 0)
        # Completed delivery remains a durable stopping boundary on resume.
        calls = len(self.runtime.calls)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "LOCAL_CANDIDATE_READY")
        self.assertEqual(calls, len(self.runtime.calls))

    def test_one_factory_routes_two_tasks_without_model_state_leaking(self):
        first = self.run_candidate()
        self.spec["mission_id"] = "second-task"
        self.spec["model_routing"] = {"category": "feature", "complexity": "complex", "risk": "high"}
        authorization = self.spec["local_candidate_authorization"]
        authorization["mission_id"] = "second-task"
        authorization["worktree"] = str(self.f.root/"candidates/second-task")
        authorization["executor_identity"] = self.f.developer_binding(self.spec)[1]
        second = self.f.run(self.f.submit(self.spec))
        self.assertEqual(first["MODEL_ROUTING"]["selection"]["selected_tier"], "economy")
        self.assertEqual(second["MODEL_ROUTING"]["selection"]["selected_tier"], "high")
        self.assertEqual(second["DELIVERY_STATUS"], "LOCAL_CANDIDATE_READY", second)
        self.assertEqual(self.f.report("feature")["MODEL_ROUTING"]["selection"]["selected_tier"], "economy")

    def test_manual_model_and_new_authorization_bind_before_dispatch(self):
        self.spec["model_routing"]["model"] = "balanced"
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.f.submit(self.spec)
        self.assertEqual(self.runtime.calls, [])
        self.spec["local_candidate_authorization"]["executor_identity"] = self.f.developer_binding(self.spec)[1]
        self.assertEqual(self.run_candidate()["MODEL_ROUTING"]["selection"]["requested_model"], "fixture-balanced")

    def test_task_mutation_and_pool_mutation_cannot_upgrade_repair(self):
        self.f.submit(self.spec)
        changed = copy.deepcopy(self.spec)
        changed["model_routing"]["model"] = "high"
        with self.assertRaisesRegex(ValueError, "route changed"):
            self.f.developer_binding(changed)
        with self.assertRaises(ValueError):
            self.f.submit(changed)
        self.f.config["model_routing"]["models"][0]["model"] = "fixture-upgrade"
        with self.assertRaises(ValueError):
            self.f.run("feature")
        self.assertEqual(self.runtime.calls, [])

    def test_resume_recomputes_identity_and_rejects_changed_runtime(self):
        self.runtime.profile_identity = lambda p: {"configured": p, "route_identity": {"runtime": "original"}}
        self.f._routing_identities.clear()
        self.spec["local_candidate_authorization"]["executor_identity"] = self.f.developer_binding(self.spec)[1]
        self.f.submit(self.spec)
        self.f.close()
        self.runtime.profile_identity = lambda p: {"configured": p, "route_identity": {"runtime": "changed"}}
        self.f = Factory(self.root/"routed-state", self.config, self.runtime)
        with self.assertRaisesRegex(ValueError, "route changed"):
            self.f.developer_binding(self.spec)
        self.assertEqual(self.runtime.calls, [])

    def test_wire_token_deltas_cache_and_conditional_price_survive_repair(self):
        for entry in self.f.config["model_routing"]["models"]:
            entry["price"] = price()
        self.spec["local_candidate_authorization"]["executor_identity"] = self.f.developer_binding(self.spec)[1]
        self.runtime.failure = "repair"
        original = self.runtime.agent
        def agent(role, *args):
            result = original(role, *args)
            n = len(self.runtime.threads)
            result["usage"] = {"input_tokens": 10000*n, "output_tokens": 1000*n,
                               "cached_input_tokens": 2000*n, "total_tokens": 11000*n}
            return result
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "LOCAL_CANDIDATE_READY", report)
        self.assertEqual(report["OBSERVED_TOKEN_USAGE"]["total"], 22000)
        runs = report["MODEL_ROUTING"]["operations"]
        self.assertEqual([r["usage"]["cached_input_tokens"] for r in runs], [2000, 2000])
        self.assertEqual([r["estimated_cost"]["amount"] for r in runs], ["0.025", "0.025"])
        self.assertTrue(all(r["actual_bill"] == "UNKNOWN" for r in runs))

    def test_unknown_repair_retains_partial_usage_and_reservation_without_replay(self):
        self.runtime.failure = "repair"
        original = self.runtime.agent
        def agent(role, *args):
            if role == "rework":
                raise RuntimeFailure("lost terminal", {"total": {"inputTokens": 15000, "outputTokens": 0, "totalTokens": 15000}})
            return original(role, *args)
        with patch.object(self.runtime, "agent", side_effect=agent):
            report = self.run_candidate()
        self.assertEqual(report["DELIVERY_STATUS"], "UNKNOWN")
        self.assertEqual(report["BUDGET_USED"]["observed_tokens"], 15000)
        self.assertEqual(report["BUDGET_USED"]["unknown_token_reservation"], 36000)
        self.assertEqual(report["MODEL_ROUTING"]["operations"][-1]["estimated_cost"], "UNKNOWN")
        before = len(self.runtime.calls)
        self.f.run("feature")
        self.assertEqual(before, len(self.runtime.calls))

    def test_direct_dispatch_cannot_replace_authorized_identity(self):
        self.f.submit(self.spec)
        with self.assertRaises(FactoryBlocked):
            self.f.operation("feature", "forbidden", "implement", "developer", {"profile": {"model": "fixture-high"}}, {}, True,
                             lambda _: self.fail("unauthorized dispatch"))
        self.assertEqual(self.runtime.calls, [])


if __name__ == "__main__":
    unittest.main()
