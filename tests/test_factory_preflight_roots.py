"""Three original-rule preflights; GitHub facts only are offline doubles.

Missing model receipts intentionally keep the real final gate at NO. These
tests assert its repeated local preflight, never invent a review approval.
"""
import copy
import json
from pathlib import Path
from unittest.mock import Mock, patch
import unittest

from harness.adapters import FootballPredictionAdapter, GateResult
from harness.factory_project import FootballPredictionContract
from harness.factory_remote import run as remote_run
from test_factory_contract_binding import evidence
import test_factory_controller_gates as gates
import test_factory_preflight_inspection as fixtures


class PreflightProbe:
    """Observe real subprocess rules and substitute only remote PR facts."""

    def __init__(self, spec, cwd, target, body):
        self.spec, self.cwd, self.target, self.body = spec, cwd, target, body
        self.adapter = FootballPredictionAdapter()
        self.original_call = self.adapter._call
        self.events, self.repeat_invocation = [], None

    def call(self, argv, **kwargs):
        argv = list(argv)
        code_index = argv.index("-c") + 1
        code = argv[code_index]
        repeated = "raise SystemExit(m.main())" in code
        if repeated:
            self.repeat_invocation = (list(argv), dict(kwargs))
        terminal = "raise SystemExit(m.main())" if repeated else "raise SystemExit(p.main())"
        assert terminal in code, "only the two original preflight entrypoints are authorized"
        audit = self.cwd.parent / f"preflight-probe-{len(self.events)}.json"
        # Instrument return values/provenance; no rule function returns a stub.
        observe = f"""
import hashlib, json, os
from scripts.ops.helpers import governance_p1_checks as gov, disposable_canonical_db_proof_scan as proof
_original_preflight = p.run_preflight
def _observe_preflight(*args, **kwargs):
    result = _original_preflight(*args, **kwargs)
    modules = (p, g, h, gov, proof)
    facts = {{'result': result, 'cwd': os.getcwd(), 'governance_base': gov._resolve_diff_base(),
        'roots': [str(p.ROOT), str(g.ROOT), str(h.ROOT_HELPER), str(gov.ROOT), str(proof.ROOT)],
        'rules': [{{'path': x.__file__, 'sha256': hashlib.sha256(Path(x.__file__).read_bytes()).hexdigest()}} for x in modules]}}
    Path({str(audit)!r}).write_text(json.dumps(facts))
    return result
p.run_preflight = _observe_preflight
"""
        if repeated:
            observe += ("m._remote_pr_check = lambda *a, **k: "
                "(m.GateCheck('remote-required-ci','PASS','OFFLINE PR facts only'), {}, "
                + repr(self.body) + ")\n")
        argv[code_index] = code.replace(terminal, observe + terminal)
        result = self.original_call(argv, **kwargs)
        facts = json.loads(audit.read_text()) if audit.exists() else None
        self.events.append({"stage": "repeated-final" if repeated else "preflight",
            "argv": argv, "cwd": kwargs.get("cwd"), "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr, "facts": facts})
        return result

    def publication(self):
        with patch.object(self.adapter, "_call", side_effect=self.call):
            return FootballPredictionContract(self.adapter).validate_pr_body(
                self.spec, self.cwd, self.target, self.body)

    def final(self):
        facts = GateResult("PASS", data={"head": self.target["head"], "base": "main",
            "state": "OPEN", "base_sha": self.target["base"], "body": self.body})
        with patch.object(self.adapter, "_pr_state", return_value=facts), \
                patch.object(self.adapter, "_call", side_effect=self.call):
            return self.adapter.merge_ready(worktree=str(self.cwd), base=self.target["base"],
                head=self.target["head"], mission_id=self.spec["mission_id"],
                scope_file=str(self.cwd / self.target["mission_scope_file"]),
                pr_number=7, pr_repo="fixture/football", pr_base_sha=self.target["base"],
                receipts={"codex": str(self.cwd.parent / "OFFLINE-MISSING-RECEIPT.json")},
                ci_status="PASS", use_project_policy=True)

    def repeat_with_claimed_pass(self, previous):
        """A forged PASS artifact must not bypass the repeated real check."""
        argv, kwargs = copy.deepcopy(previous.repeat_invocation)
        argv[6] = str(self.cwd)
        claimed = copy.deepcopy(previous.events[0]["facts"]["result"])
        claimed.update(base_sha=self.target["base"], head_sha=self.target["head"],
                       current_head_sha=self.target["head"], changed_paths=self.target["files"])
        path = self.cwd.parent / "OFFLINE-CLAIMED-PASS.json"
        path.write_text(json.dumps(claimed))
        for flag, value in (("--repo-root", str(self.cwd)), ("--base-sha", self.target["base"]),
                ("--head-sha", self.target["head"]), ("--mission-scope-file", str(self.cwd / self.target["mission_scope_file"])),
                ("--local-preflight-json", str(path))):
            argv[argv.index(flag) + 1] = value
        result = self.call(argv, **kwargs)
        return self.adapter._json_document_prefix(result.stdout)


class ThreePreflightDataRootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.PublicationDataRootTests.setUpClass()
        cls.addClassCleanup(fixtures.PublicationDataRootTests.doClassCleanups)

    def setUp(self):
        self.fx = fixtures.PublicationDataRootTests("test_new_script_lifecycle_header_is_read_from_candidate")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.probes = []
        self.addCleanup(lambda: evidence(self.id(), {"OFFLINE_ONLY": True,
            "original_rules_baseline": "a65464d1e5de498a072ed9a8fdf69ce46bcc04c5",
            "probes": [{"target": p.target, "body": p.body, "events": p.events} for p in self.probes]}))

    def probe(self, spec, cwd, target):
        p = PreflightProbe(spec, cwd, target, fixtures.publication_body(self.fx.fx, target))
        self.assertNotIn("## Script Lifecycle", p.body)
        self.probes.append(p)
        return p

    def assert_bound(self, p, verdict):
        for event in p.events:
            facts = event["facts"]
            self.assertIsNotNone(facts, event)
            self.assertEqual(facts["result"]["verdict"], verdict, event)
            self.assertEqual(facts["cwd"], str(p.cwd))
            self.assertEqual(event["cwd"], str(p.cwd))
            self.assertEqual(facts["roots"], [str(p.cwd)] * 5)
            self.assertEqual(facts["governance_base"], p.target["base"])
            for field, expected in (("base_sha", p.target["base"]), ("head_sha", p.target["head"]),
                    ("current_head_sha", p.target["head"]), ("changed_paths", p.target["files"])):
                self.assertEqual(facts["result"][field], expected)
            for rule in facts["rules"]:
                path = Path(rule["path"])
                self.assertTrue(path.is_relative_to(self.fx.snapshot))
                self.assertEqual(rule["sha256"], self.fx.rules[path.relative_to(self.fx.snapshot).as_posix()])

    def assert_three_accept(self, p):
        self.assertTrue(p.publication().is_file())
        result = p.final()
        # Real final gate still refuses missing receipts; only local checks pass.
        self.assertEqual(result.status, "BLOCKED_EXTERNAL")
        self.assertEqual(len(p.events), 3, p.events)
        self.assertEqual(result.data["local_required_checks"], "PASS", result)
        self.assertEqual(result.data["merge_ready"], "NO")
        self.assert_bound(p, "PASS")

    def assert_three_reject(self, p, previous, message):
        remote = Mock(adapter=p.adapter)
        with patch.object(p.adapter, "_call", side_effect=p.call), \
                patch("harness.factory_remote.Remote", return_value=remote):
            with self.assertRaisesRegex(ValueError, message):
                remote_run("publish", gates.DELIVERY, p.spec, p.cwd, p.target, p.body,
                           self.fx.fx.root / "rejected-publication.raw", 5)
        remote.publish.assert_not_called()
        remote.command.assert_not_called()
        remote.api.assert_not_called()
        self.assertEqual(p.final().status, "BLOCKED_EXTERNAL")
        repeated = p.repeat_with_claimed_pass(previous)
        self.assertEqual(repeated["local_required_checks"], "FAIL", repeated)
        self.assertEqual(repeated["merge_ready"], "NO")
        self.assertEqual(len(p.events), 3)
        self.assert_bound(p, "FAIL")
        for event in p.events:
            self.assertIn(message, json.dumps(event["facts"]["result"]))
        self.assertEqual(self.fx.fx.starts, [], "no provider may run")

    def test_legal_new_script_passes_all_three_original_preflights(self):
        spec, cwd, target = self.fx.candidate("scripts/ops/root_probe.py", "# Owner: offline fixture\nprint(1)\n")
        self.assertFalse((self.fx.snapshot / "scripts/ops/root_probe.py").exists())
        self.assert_three_accept(self.probe(spec, cwd, target))

    def test_missing_lifecycle_rejected_by_all_three_without_publication_write(self):
        path = "scripts/ops/root_probe.py"
        spec, cwd, target = self.fx.candidate(path, "# Owner: offline fixture\nprint(1)\n")
        previous = self.probe(spec, cwd, target)
        self.assert_three_accept(previous)
        (cwd / path).write_text("print(1)\n")
        target = self.fx.fx.f.checkpoint(spec, cwd)
        self.assert_three_reject(self.probe(spec, cwd, target), previous, "Script lifecycle missing")

    def test_candidate_archive_violation_survives_later_same_file_commit(self):
        path = self.fx.existing
        content = (self.fx.snapshot / path).read_text()
        spec, cwd, target = self.fx.candidate(path, content + "\n# Legal candidate edit.\n")
        previous = self.probe(spec, cwd, target)
        self.assert_three_accept(previous)
        (cwd / path).write_text(content + "\nimport archive_vault_2026.probe\n")
        self.fx.fx.f.checkpoint(spec, cwd)
        with (cwd / path).open("a") as stream:
            stream.write("\n# Later harmless rework cannot hide the earlier import.\n")
        target = self.fx.fx.f.checkpoint(spec, cwd)
        self.assert_three_reject(self.probe(spec, cwd, target), previous, "Archive runtime import detected")
        self.assertEqual((self.fx.snapshot / path).read_text(), content)

    def test_disposable_marker_uses_candidate_revision_in_all_three(self):
        path = "tests/integration/canonical_inventory/disposable_postgres.test.js"
        spec, cwd, target = self.fx.candidate(path,
            '// M3_CANONICAL_DISPOSABLE_DB_WRITE_PROOF_V1\nconst sql = "DELETE FROM cmh_fixture";\n')
        previous = self.probe(spec, cwd, target)
        self.assert_three_accept(previous)
        (cwd / path).write_text('const sql = "DELETE FROM cmh_fixture";\n')
        target = self.fx.fx.f.checkpoint(spec, cwd)
        self.assert_three_reject(self.probe(spec, cwd, target), previous, "new dangerous keyword")


if __name__ == "__main__":
    unittest.main()
