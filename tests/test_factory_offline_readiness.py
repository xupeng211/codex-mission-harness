"""Factory -> Remote -> fixed original PR readiness; all services are offline.

Developer/review/container/final-gate fixtures are NOT real delivery evidence.
The original readiness evaluator, selected original-rule preflights and the
Harness state flow are real. GitHub/CI reads and writes use local doubles.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter, GateResult
from harness.factory import Factory, READY, git
import test_factory_controller_gates as fixtures
from test_factory_contract_binding import PROJECT_BASE, evidence, load_contract
from test_factory_preflight_roots import PreflightProbe
import test_factory_preflight_inspection as preflight_fixtures


class ReadinessRemote(fixtures.FakeRemote):
    def __init__(self, *args, canonical, events, mismatch=False):
        super().__init__(*args)
        self.canonical, self.events, self.mismatch = canonical, events, mismatch
        self.adapter = FootballPredictionAdapter()

    def api(self, endpoint, method="GET", data=None):
        self.events.append({"kind": "api-double", "method": method, "endpoint": endpoint,
                            "payload": copy.deepcopy(data)})
        return super().api(endpoint, method, data)

    def command(self, argv, **kwargs):
        self.events.append({"kind": "command-double", "argv": list(argv)})
        return super().command(argv, **kwargs)

    def ci(self, policy, spec, target, body, *, wait):
        canonical = self.canonical
        def state(*args):
            raw = self.raw
            return GateResult("PASS", data={"head": raw["head"]["sha"], "base": raw["base"]["ref"],
                "state": raw["state"].upper(), "base_sha": raw["base"]["sha"]})

        def readiness(argv, **kwargs):
            # Execute the pinned original evaluator with REAL local Git reads.
            # Only its four GitHub read functions are replaced by fixed data.
            raw = self.raw
            canonical.ROOT = Path(self.cwd)
            repo = canonical.RepoInfo(policy["repository"], "main")
            branch = raw["head"]["ref"] + ("-different" if self.mismatch else "")
            pr = canonical.PrInfo(raw["number"], "Offline PR", raw["state"].upper(), False,
                raw["base"]["ref"], raw["base"]["sha"], branch, raw["head"]["sha"],
                "MERGEABLE", raw["body"], bool(raw["body"].strip()))
            required = ("Environment / Proxy / Static / Unit Gate", "Docker Build Validation")
            runs = tuple(canonical.CheckRun(n, "completed", "success", target["head"]) for n in required)
            with patch.object(canonical, "fetch_repo", return_value=repo), \
                    patch.object(canonical, "fetch_pr", return_value=pr), \
                    patch.object(canonical, "fetch_required_checks", return_value=required), \
                    patch.object(canonical, "fetch_check_runs", return_value=runs):
                result = canonical.evaluate(raw["number"])
            document = canonical.format_json(result)
            self.events.append({"kind": "original-readiness", "baseline": PROJECT_BASE,
                                "invocation": argv, "result": json.loads(document)})
            return subprocess.CompletedProcess(argv, 0 if result.passed else 1, document, "")

        with patch.object(self.adapter, "_pr_state", side_effect=state), \
                patch.object(self.adapter, "_trusted_base_checkout", return_value=Path(self.canonical.__file__).parent), \
                patch.object(self.adapter, "_call", side_effect=readiness):
            return super().ci(policy, spec, target, body, wait=wait)


class OfflineChainRuntime(fixtures.LiveProtocolDouble):
    def __init__(self, canonical):
        super().__init__()
        self.canonical, self.events = canonical, []
        self.mismatch, self.lose_once = False, False
        self.script = None

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        self.events.append({"kind": role, "branch": git(cwd, "branch", "--show-current"),
                            "head": git(cwd, "rev-parse", "HEAD")})
        # Reuse the fixture's correct implementation, without its unrelated
        # deliberate floor-division bug and synthetic reviewer-driven rework.
        result = super().agent("rework" if role == "implement" else role, profile, cwd, payload,
                               transcript, timeout, denied_roots)
        if self.script is not None and role in {"implement", "rework"}:
            path, content = self.script
            (cwd / path).parent.mkdir(parents=True, exist_ok=True)
            (cwd / path).write_text(content)
        return result

    def project_remote(self, action, policy, spec, cwd, target, body, transcript, timeout, **kwargs):
        transcript.write_text("OFFLINE chain; no real publication, CI or providers\n")
        self.events.append({"kind": action, "target": target,
            "local_branch": git(cwd, "branch", "--show-current")})
        if self.remote is None:
            self.remote = ReadinessRemote(cwd, transcript, spec, target, body, canonical=self.canonical,
                                         events=self.events, mismatch=self.mismatch)
            self.remote.lose_create_response = self.lose_once
        self.remote.target = target
        try:
            if self.script is not None and action in {"publish", "verify"}:
                probe = PreflightProbe(spec, cwd, target, body)
                try:
                    probe.publication()
                    if action == "verify":
                        actual = probe.final()
                        # The real gate still says NO without real receipts.
                        # Only its two original local preflights are asserted;
                        # review/container/final approval remain state-flow doubles.
                        if (len(probe.events) != 3 or actual.data is None
                                or actual.data.get("local_required_checks") != "PASS"):
                            raise ValueError("original final local preflights rejected fixture")
                finally:
                    self.events.append({"kind": "original-preflights", "action": action,
                        "target": target, "body": body, "events": probe.events,
                        "remaining_final_authority": "OFFLINE synthetic review/CI/container fixtures"})
            if action == "publish":
                result = self.remote.publish(policy, spec, target, body, kwargs.get("previous_head"))
            elif action == "reconcile":
                result = self.remote.observe(policy, spec, target, body)
            else:
                result = self.remote.ci(policy, spec, target, body, wait=False)
        finally:
            self.remote.lose_create_response = False
        return {**result, "fixture": False, "OFFLINE_DOUBLE": True}


class OfflineReadinessChainTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.FactoryLiveProtocolTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.fx.root
        self.canonical = load_contract(self, "offline_chain_readiness", "pr_ready_check.py")
        self.runtime = OfflineChainRuntime(self.canonical)
        self.f = self.fx.f
        self.f.runtime = self.runtime

    def save(self, name, report):
        evidence(name, {"OFFLINE_ONLY": True, "baseline": PROJECT_BASE, "report": report,
            "events": self.runtime.events, "writes": self.runtime.remote.writes if self.runtime.remote else []})

    def test_preparation_implementation_publication_ci_original_readiness_reaches_ready(self):
        report = self.f.run("feature")
        self.save("offline-ready", report)
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        remote = self.runtime.remote
        self.assertEqual(remote.writes, ["push", "create"])
        self.assertEqual(report["CANDIDATE_BRANCH"], remote.branch)
        events = self.runtime.events
        kinds = [e["kind"] for e in events]
        self.assertLess(kinds.index("plan"), kinds.index("implement"))
        self.assertLess(kinds.index("implement"), kinds.index("publish"))
        self.assertLess(kinds.index("publish"), kinds.index("ci"))
        self.assertLess(kinds.index("ci"), kinds.index("original-readiness"))
        self.assertTrue(all(e["branch"] == remote.branch for e in events if e["kind"] in {"plan", "implement"}))
        readiness = [e["result"] for e in events if e["kind"] == "original-readiness"]
        self.assertTrue(readiness)
        self.assertTrue(all(r["verdict"] == "PASS" and r["local"]["branch"] == remote.branch
            and r["local"]["head_sha"] == report["TARGET_HEAD"] for r in readiness))
        self.assertFalse(report["MERGE_PERFORMED"])

    def test_original_readiness_still_rejects_branch_identity_mismatch(self):
        self.runtime.mismatch = True
        report = self.f.run("feature")
        self.save("offline-identity-rejected", report)
        self.assertNotEqual(report["DELIVERY_STATUS"], READY, report)
        results = [e["result"] for e in self.runtime.events if e["kind"] == "original-readiness"]
        self.assertTrue(results)
        for result in results:
            self.assertEqual(result["verdict"], "FAIL")
            self.assertEqual([f["name"] for f in result["findings"] if not f["passed"]], ["local-branch-matches-pr"])

    def test_lost_publication_response_resumes_exact_branch_without_writes_or_replacement(self):
        self.runtime.lose_once = True
        first = self.f.run("feature")
        self.assertEqual(first["DELIVERY_STATUS"], "UNKNOWN", first)
        original = dict(self.f.db.execute("SELECT * FROM operations WHERE stage='project_publish'").fetchone())
        branches = git(Path(first["CANDIDATE"]), "show-ref", "--heads")
        report = self.f.run("feature")
        self.save("offline-recovery", report)
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(self.runtime.remote.writes, ["push", "create"])
        self.assertEqual(git(Path(report["CANDIDATE"]), "show-ref", "--heads"), branches)
        self.assertEqual(dict(self.f.db.execute("SELECT * FROM operations WHERE id=?", (original["id"],)).fetchone()), original)

    def original_rule_script_chain(self, content):
        """Keep the existing chain doubles, but run all three real preflights."""
        preflight_fixtures.PublicationDataRootTests.setUpClass()
        self.addCleanup(preflight_fixtures.PublicationDataRootTests.doClassCleanups)
        original = preflight_fixtures.PublicationDataRootTests("test_new_script_lifecycle_header_is_read_from_candidate")
        original.setUp()
        self.addCleanup(original.doCleanups)
        fx = original.fx
        path = "scripts/ops/offline_chain_probe.py"
        fx.scope["authorized_paths"].extend(["tests/test_score.py", path])
        content_scope = json.dumps(fx.scope, indent=2) + "\n"
        self.f = Factory(fx.root / "original-preflight-offline-chain", {
            **fx.config, "project_container": fixtures.CONTAINER, "project_delivery": fixtures.DELIVERY,
            "project_review_limits": fixtures.LIMITS, "checks": [["make", "verify-targeted"]],
            "ci": [["make", "verify-pr"]]}, self.runtime)
        self.addCleanup(self.f.close)
        spec = {"version": 2, "mission_id": "feature", "repository": str(fx.repo),
            "base": fx.base, "objective": "Offline original-rule script lifecycle chain",
            "approved_mission_scope": {"approval_id": "offline-script-chain", "mission_id": "feature",
                "base": fx.base, "path": fx.path, "content": content_scope,
                "sha256": hashlib.sha256(content_scope.encode()).hexdigest(),
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
            "pr_body_template": preflight_fixtures.publication_body(fx,
                {"head": "{{candidate_head}}", "files": sorted(fx.scope["authorized_paths"])})}
        self.runtime.script = (path, content)
        self.f.submit(spec)

    def test_legal_script_original_three_preflights_reaches_fixture_ready(self):
        self.original_rule_script_chain("# Owner: offline chain fixture\nprint(1)\n")
        report = self.f.run("feature")
        self.save("offline-script-ready", report)
        self.assertEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(self.runtime.remote.writes, ["push", "create"])
        originals = [e for e in self.runtime.events if e["kind"] == "original-preflights"]
        self.assertTrue(any(e["action"] == "verify" and len(e["events"]) == 3 for e in originals))
        for call in originals:
            self.assertNotIn("## Script Lifecycle", call["body"])
            self.assertTrue(all(e["facts"]["result"]["verdict"] == "PASS" for e in call["events"]))
        self.assertFalse(report["MERGE_PERFORMED"])

    def test_illegal_script_original_publication_preflight_stops_fixture_chain(self):
        self.original_rule_script_chain("print(1)\n")
        report = self.f.run("feature")
        self.save("offline-script-rejected", report)
        self.assertNotEqual(report["DELIVERY_STATUS"], READY, report)
        self.assertEqual(self.runtime.remote.writes, [])
        calls = [e for e in self.runtime.events if e["kind"] == "original-preflights"]
        self.assertTrue(calls)
        self.assertTrue(all(e["facts"]["result"]["verdict"] == "FAIL" for c in calls for e in c["events"]))
        self.assertIn("Script lifecycle missing", json.dumps(calls))


if __name__ == "__main__":
    unittest.main()
