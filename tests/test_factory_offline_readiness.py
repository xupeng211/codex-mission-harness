"""Factory -> Remote -> fixed original PR readiness; all services are offline.

Developer/review/container/final-gate fixtures are NOT real delivery evidence.
Only the original readiness evaluator and the Harness state flow under test
are real. GitHub/CI reads and publication writes use explicit local doubles.
"""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from harness.adapters import FootballPredictionAdapter, GateResult
from harness.factory import READY, git
import test_factory_controller_gates as fixtures
from test_factory_contract_binding import PROJECT_BASE, evidence, load_contract


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

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        self.events.append({"kind": role, "branch": git(cwd, "branch", "--show-current"),
                            "head": git(cwd, "rev-parse", "HEAD")})
        # Reuse the fixture's correct implementation, without its unrelated
        # deliberate floor-division bug and synthetic reviewer-driven rework.
        return super().agent("rework" if role == "implement" else role, profile, cwd, payload,
                             transcript, timeout, denied_roots)

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


if __name__ == "__main__":
    unittest.main()
