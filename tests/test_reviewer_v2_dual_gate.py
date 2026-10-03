"""Deterministic contract tests; these do not qualify a real provider model."""
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
import reviewer_v2_gate as gate  # noqa: E402
import reviewer_v2_openai as review  # noqa: E402
from harness.model_registry import ModelSpec  # noqa: E402
from harness.openai_invocation import InvocationFailure, _matches_schema  # noqa: E402


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


class SummaryContractTests(unittest.TestCase):
    def test_group_and_synthesis_schema_reject_parser_invalid_summaries(self):
        for group in (False, True):
            schema = review._schema(group, synthesis=not group)
            for summary in ("x" * 31, "x" * 4001, " " * 32,
                            " " + "x" * 32, "x" * 32 + "\n"):
                value = {"findings": [], "summary": summary}
                if group:
                    value["decisions"] = []
                with self.subTest(group=group, summary_length=len(summary)):
                    self.assertFalse(_matches_schema(value, schema))
                    if summary in ("x" * 31, "x" * 4001, " " * 32):
                        parser = review._result if group else review._synthesis_result
                        with self.assertRaisesRegex(ValueError, "summary"):
                            if group:
                                parser(review._canon(value), group=True)
                            else:
                                parser(review._canon(value))
            for length in (32, 4000):
                value = {"findings": [], "summary": "x" * length}
                if group:
                    value["decisions"] = []
                with self.subTest(group=group, legal_length=length):
                    self.assertTrue(_matches_schema(value, schema))
                    if group:
                        self.assertEqual(review._result(review._canon(value), group=True), value)
                    else:
                        self.assertEqual(review._synthesis_result(review._canon(value)), value)

    def test_prompts_state_summary_length_contract(self):
        group_prompt = review._prompt("GROUP REVIEW", base="a" * 40, head="b" * 40,
                                      diff=b"+changed\n", ids=[])
        synthesis_prompt = review._synthesis_prompt([], "a" * 40, "b" * 40)
        for prompt in (group_prompt, synthesis_prompt):
            self.assertIn("32 to 4000", prompt)
            self.assertIn("no leading or trailing whitespace", prompt)


class OpenAIContractTests(unittest.TestCase):
    def test_disputed_originals_survive_all_cross_group_synthesis_levels(self):
        diff=b'a'*960100
        observed=[]
        def call(prompt,kind):
            if kind is False:
                return review._canon({'findings':[{'severity':'P1','title':'cross-group concern','evidence':'original evidence'}]})
            if kind is True:
                blockers=json.JSONDecoder().raw_decode(prompt.split('Blockers: ',1)[1])[0]
                source=prompt.split('EXACT DIFF TEXT (UTF-8):\n',1)[1].encode()
                decisions=[{'finding_id':b['finding_id'],'decision':'DISPUTED',
                    'rationale':'Local source appears to refute the original concern.',
                    'source_quote':'a'*12,'source_id':review._sha(source),
                    'quote_start':0,'quote_end':12} for b in blockers]
                return review._canon({'findings':[],'decisions':decisions,
                    'summary':'The bounded group has locally disputed the chunk concerns.'})
            summaries=json.loads(prompt.split('Group summaries: ',1)[1])
            audit=[a for item in summaries for a in item['disposition_audit']]
            observed.append(audit)
            all_groups=[g for item in summaries for g in item['source_groups']]
            findings=([{'severity':'P1','title':'reinstated cross-group concern','evidence':'Original disputed finding was reevaluated.'}]
                      if len(all_groups)==11 else [])
            return review._canon({'findings':findings,'summary':'Cross-group audit retains every original finding and decision.'})
        receipt,_=review._assemble(diff,'a'*40,'b'*40,call)
        self.assertEqual(len(observed[-1]),11)
        originals=[b for audit in observed[-1] for b in audit['original_blockers']]
        self.assertEqual(len(originals),31)
        self.assertEqual(len({b['finding_id'] for b in originals}),31)
        self.assertTrue(all(d['decision']=='DISPUTED' for a in observed[-1] for d in a['decisions']))
        self.assertEqual(receipt['review_result'],'FAIL')
        self.assertEqual(receipt['findings'][0]['title'],'reinstated cross-group concern')

    def test_schema_selection_uses_stage_not_labels_inside_reviewed_source(self):
        prompt = "CHUNK REVIEW source contains GROUP REVIEW and FINAL CROSS-GROUP REVIEW"
        with patch.object(review, "invoke_openai", return_value=SimpleNamespace(response='{"findings":[]}')) as invoke:
            for stage, required in (("chunk", {"findings"}),
                                    ("group", {"findings", "decisions", "summary"}),
                                    ("synthesis", {"findings", "summary"})):
                review.invoke_codex(prompt, ModelSpec("openai", "gpt-5.6-sol", "high"), stage=stage)
                self.assertEqual(set(invoke.call_args.args[2]["required"]), required)
        with self.assertRaises(ValueError):
            review.invoke_codex(prompt, ModelSpec("openai", "gpt-5.6-sol", "high"), stage="unknown")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "Test")
        git(self.root, "remote", "add", "origin", "git@github.com:example/harness.git")
        (self.root / "x.py").write_text("def f():\n    return 1\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "base")
        self.base = git(self.root, "rev-parse", "HEAD")
        git(self.root, "update-ref", "refs/remotes/origin/main", self.base)
        (self.root / "x.py").write_text("def f():\n    return 2\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-qm", "change")
        self.head = git(self.root, "rev-parse", "HEAD")
        self.spec = ModelSpec("openai", "gpt-5.6-sol", "high")
        self.diff = review.full.read_diff(self.root, self.base, self.head)


    def _signed(self, receipt):
        receipt.update(model=self.spec.model, reasoning_effort=self.spec.reasoning_effort,
                       mission_id="codex-mission-harness",
                       repository="ssh://github.com/example/harness.git",
                       registry_sha256=review._sha(review.load_registry().path.read_bytes()),
                       runner_sha256=review._sha(Path(review.__file__).read_bytes()),
                       invocation_sha256=review._sha(Path(review.invocation_module.__file__).read_bytes()),
                       schema_manifest_sha256=review._schema_manifest_sha())
        _, manifest = review.full.build_manifest(self.root, self.base, self.head, receipt['repository'])
        receipt['task_assignments'] = review.full.review_tasks(self.diff, manifest)
        receipt['full_manifest'] = manifest
        receipt['execution_identity'] = review.expected_execution(receipt, manifest, 'a' * 64, self.spec)
        receipt["auth_hmac_sha256"] = hmac.new(b"test-key", review._canon(receipt), hashlib.sha256).hexdigest()
        return receipt

    def test_no_blockers_bounded_source_and_exact_receipt(self):
        calls = []
        def call(prompt, group):
            calls.append((prompt, group))
            if group:
                return json.dumps({"findings": [], "decisions": [],
                                   "summary": "The changed return value has no blocking impact."}).encode()
            return b'{"findings":[]}'
        receipt, _ = review._assemble(self.diff, self.base, self.head, call)
        self._signed(receipt)
        self.assertEqual(receipt["review_result"], "PASS")
        self.assertEqual([group for _, group in calls], [False, True])
        self.assertIn(self.head, calls[0][0])
        review.validate(receipt, root=self.root, base=self.base, head=self.head,
                        spec=self.spec, auth_key="test-key")
        original_read = Path.read_bytes
        def changed_runner(path):
            return b"changed runner" if path == Path(review.__file__) else original_read(path)
        with patch.object(Path, "read_bytes", changed_runner):
            with self.assertRaises(ValueError):
                review.validate(receipt, root=self.root, base=self.base,
                                head=self.head, spec=self.spec, auth_key="test-key")
        changed_mission = dict(receipt, mission_id="another-mission")
        with self.assertRaises(ValueError):
            review.validate(changed_mission, root=self.root, base=self.base,
                            head=self.head, spec=self.spec, auth_key="test-key")
        changed_repository = dict(receipt, repository="ssh://github.com/other/repo.git")
        with self.assertRaises(ValueError):
            review.validate(changed_repository, root=self.root, base=self.base,
                            head=self.head, spec=self.spec, auth_key="test-key")
        with self.assertRaises(ValueError):
            review.validate(receipt, root=self.root, base=self.base, head="0" * 40,
                            spec=self.spec, auth_key="test-key")

    def test_failed_invocation_publishes_failure_only_for_exact_head(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        def fail(_prompt, _group):
            raise InvocationFailure("TURN_TIMEOUT_UNDIAGNOSED", "no terminal event",
                                    {"observed_event_types": ["turn.started"]})
        with patch.object(review, "validate_qualification_receipt", return_value={}), \
             patch.object(review, "preflight"), \
             patch.object(review, "invoke_codex", side_effect=lambda *_args, **_kwargs: fail(None, None)), \
             self.assertRaises(InvocationFailure) as caught:
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                       qualification_path="fixture-qualification")
        failure_path = Path(caught.exception.evidence["failure_record"])
        record = json.loads(failure_path.read_text())
        self.assertEqual(record["status"], "BLOCKED")
        self.assertEqual(record["head_sha"], self.head)
        self.assertEqual(record["diff_sha256"], hashlib.sha256(self.diff).hexdigest())
        self.assertEqual(record["failure_category"], "TURN_TIMEOUT_UNDIAGNOSED")
        self.assertEqual({item.name for item in failure_path.parent.iterdir()},
                         {"failure.json", "state.json"})

    def test_interrupt_after_first_chunk_records_failure_without_receipt(self):
        evidence = Path(self.temp.name) / "interrupted"
        evidence.mkdir(mode=0o700)
        calls = 0
        def invoke(_prompt, _spec, *, stage, timeout, transport_sink=None):
            nonlocal calls
            calls += 1
            if calls == 1:  # structured preflight
                return b'{"findings":[]}'
            if calls == 2:
                return b'{"findings":[]}'
            raise KeyboardInterrupt()
        with patch.object(review, "validate_qualification_receipt", return_value={}), \
             patch.object(review, "preflight"), \
             patch.object(review, "_plan", return_value=(
                 [{"index": i, "start": 0, "end": len(self.diff)} for i in range(3)],
                 [{"index": 0, "chunk_indexes": [0, 1, 2],
                   "start": 0, "end": len(self.diff)}])), \
             patch.object(review, "invoke_codex", side_effect=invoke), \
             self.assertRaises(KeyboardInterrupt):
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                       qualification_path="fixture-qualification")
        run_dir, = (item for item in evidence.iterdir() if item.is_dir())
        self.assertTrue((run_dir / "chunk-000.json").exists())
        self.assertFalse((run_dir / "chunk-001.json").exists())
        self.assertFalse((run_dir / "receipt.json").exists())
        failure = json.loads((run_dir / "failure.json").read_text())
        self.assertEqual(failure["failure_category"], "CANCELLED")
        self.assertEqual(failure["head_sha"], self.head)
        self.assertTrue(failure["resume_allowed"])
        self.assertEqual(failure["durable_completed_stages"], ["chunk-000"])
        self.assertEqual(failure["next_stage"], "chunk-001")

    def test_invalid_group_result_preserves_raw_stage_and_never_publishes_receipt(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        blocker = {"severity": "P1", "title": "Concrete issue", "evidence": "x.py:2"}
        raw_group = json.dumps({"findings": [], "decisions": [{
            "finding_id": "C000F000", "decision": "DISPUTED",
            "rationale": "This rationale claims the blocker does not apply.",
            "source_quote": "a quotation absent from the diff", "source_id": review._sha(self.diff),
            "quote_start": 0, "quote_end": 32}],
            "summary": "The group was reviewed but its dispute lacks source evidence."}).encode()
        calls = 0
        def invoke(_prompt, _spec, *, stage, timeout, transport_sink=None):
            nonlocal calls
            calls += 1
            if calls == 1:
                return b'{"findings":[]}'  # preflight
            return raw_group if stage == "group" else json.dumps({"findings": [blocker]}).encode()
        with patch.object(review, "validate_qualification_receipt", return_value={}), \
             patch.object(review, "preflight"), \
             patch.object(review, "invoke_codex", side_effect=invoke), \
             self.assertRaisesRegex(ValueError, "bound source reference"):
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                       qualification_path="fixture-qualification")
        run_dir, = (item for item in evidence.iterdir() if item.is_dir())
        self.assertFalse((run_dir / "group-000.json").exists())
        failure = json.loads((run_dir / "failure.json").read_text())
        self.assertEqual(failure["status"], "BLOCKED")
        self.assertEqual(failure["failure_category"], "REVIEW_RESULT_INVALID")
        self.assertNotIn("group-000.json", failure["artifact_sha256"])
        self.assertTrue(failure["resume_allowed"])
        self.assertEqual(failure["resume_policy_reason"], "bounded source binding retry")
        self.assertFalse((run_dir / "receipt.json").exists())
        requested = []
        def retry(_prompt, _spec, *, stage, timeout, transport_sink=None):
            requested.append(stage)
            if stage == "chunk" and len(requested) == 1:
                return b'{"findings":[]}'  # fresh structured preflight
            if stage == "chunk":
                raise AssertionError("committed Chunk must not be recalled")
            return json.dumps({"findings": [], "decisions": [{
                "finding_id": "C000F000", "decision": "UPHELD",
                "rationale": "The original finding remains valid in this exact source.",
                "source_quote": "", "source_id": "", "quote_start": 0, "quote_end": 0}],
                "summary": "The original blocker remains present after source review."}).encode()
        with patch.object(review, "validate_qualification_receipt", return_value={}), \
             patch.object(review, "preflight"), \
             patch.object(review, "invoke_codex", side_effect=retry):
            receipt = review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                                 qualification_path="fixture-qualification")
        self.assertEqual(requested, ["chunk", "group"])
        self.assertEqual(json.loads(receipt.read_text())["review_result"], "FAIL")
        self.assertTrue(json.loads((run_dir / "state.json").read_text())["receipt_written"])

    def test_preflight_provider_failure_publishes_no_approval_receipt(self):
        evidence = Path(self.temp.name) / "evidence"
        evidence.mkdir(mode=0o700)
        error = InvocationFailure("AUTHENTICATION_FAILURE", "provider rejected auth",
                                  {"failure_markers": {"http_401": True}})
        with patch.object(review, "validate_qualification_receipt", return_value={}), \
             patch.object(review, "preflight", side_effect=error) as preflight:
            with self.assertRaises(InvocationFailure) as caught:
                review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                           qualification_path="fixture-qualification")
        preflight.assert_called_once()
        path = Path(caught.exception.evidence["failure_record"])
        record = json.loads(path.read_text())
        self.assertEqual(record["failure_category"], "AUTHENTICATION_FAILURE")
        self.assertEqual(record["head_sha"], self.head)
        self.assertFalse(list(evidence.rglob("receipt.json")))

    def test_live_review_requires_matching_final_reviewer_qualification(self):
        evidence = Path(self.temp.name) / "evidence"
        with self.assertRaisesRegex(ValueError, "qualification receipt"):
            review.run(self.root, self.base, self.head, evidence, "test-key", self.spec)
        self.assertFalse(list(evidence.rglob("receipt.json")))
        self.assertEqual(len(list(evidence.rglob("failure.json"))), 1)
        with patch.object(review, "validate_qualification_receipt",
                          side_effect=ValueError("role mismatch")) as validate:
            with self.assertRaisesRegex(ValueError, "role mismatch"):
                review.run(self.root, self.base, self.head, evidence, "test-key", self.spec,
                           qualification_path="untrusted-receipt")
        self.assertEqual(validate.call_args.kwargs["role"], "final_reviewer")
        self.assertFalse(list(evidence.rglob("receipt.json")))

    def test_missing_unknown_and_duplicate_blocker_id_fail_closed(self):
        blocker = {"severity": "P1", "title": "Concrete issue", "evidence": "x.py:2"}
        for ids in ([], ["C000F001"], ["C000F000", "C000F000"]):
            with self.subTest(ids=ids):
                def call(prompt, group):
                    if not group:
                        return json.dumps({"findings": [blocker]}).encode()
                    decisions = [{"finding_id": identifier, "decision": "UPHELD",
                                  "rationale": "The changed source makes the issue persist.",
                                  "source_quote": "", "source_id": "",
                                  "quote_start": 0, "quote_end": 0} for identifier in ids]
                    return json.dumps({"findings": [], "decisions": decisions,
                                       "summary": "The source was reviewed with its original finding."}).encode()
                with self.assertRaises(ValueError):
                    review._assemble(self.diff, self.base, self.head, call)

    def test_upheld_blocker_forces_fail_and_dispute_needs_source_quote(self):
        blocker = {"severity": "P2", "title": "Concrete issue", "evidence": "x.py:2"}
        def call(prompt, group):
            if not group:
                return json.dumps({"findings": [blocker]}).encode()
            return json.dumps({"findings": [], "decisions": [{"finding_id": "C000F000",
                "decision": "UPHELD", "rationale": "The changed source makes the issue persist.",
                "source_quote": "", "source_id": "", "quote_start": 0, "quote_end": 0}],
                "summary": "The blocker remains in the reviewed source."}).encode()
        receipt, _ = review._assemble(self.diff, self.base, self.head, call)
        self.assertEqual(receipt["review_result"], "FAIL")
        self._signed(receipt)
        review.validate(receipt, root=self.root, base=self.base, head=self.head,
                        spec=self.spec, auth_key="test-key")
        receipt["groups"][0]["source_blockers"][0]["finding"]["severity"] = "P3"
        self._signed_after_change(receipt)
        with self.assertRaises(ValueError):
            review.validate(receipt, root=self.root, base=self.base, head=self.head,
                            spec=self.spec, auth_key="test-key")

    @staticmethod
    def _signed_after_change(receipt):
        receipt.pop("auth_hmac_sha256")
        receipt["auth_hmac_sha256"] = hmac.new(b"test-key", review._canon(receipt), hashlib.sha256).hexdigest()

    def _gate_bind(self, deepseek, openai):
        _, manifest = review.full.build_manifest(self.root, self.base, self.head, deepseek['repository'])
        validators = {}
        for provider, receipt in [('deepseek', deepseek), ('openai', openai)]:
            role = 'independent_reviewer' if provider == 'deepseek' else 'final_reviewer'
            configuration = {'provider': provider, 'model': receipt['model'],
                             'reasoning_effort': receipt.get('reasoning_effort')}
            qualified = {'role': role, 'mode': 'real_provider', 'identity': configuration}
            validators[provider] = lambda q=qualified: q
            receipt.update(task_assignments=review.full.review_tasks(self.diff, manifest), full_manifest=manifest, chunks=manifest['chunks'], groups=manifest['groups'],
                           registry_sha256='b' * 64, runner_sha256='c' * 64)
            receipt['execution_identity'] = review.full.execution_identity(manifest, receipt['mission_id'],
                review._sha(review._canon(qualified)), role=role, provider=provider,
                model=receipt['model'], configuration=configuration, registry_hash='b' * 64,
                runner_hash='c' * 64, invocation_hash='d' * 64, schema_hash='e' * 64)
        return validators

    def test_gate_requires_two_valid_independent_exact_lanes(self):
        diff_hash = hashlib.sha256(self.diff).hexdigest()
        deepseek = {"provider": "deepseek", "model": "deepseek-flash", "base_sha": self.base,
                    "head_sha": self.head, "diff_sha256": diff_hash, "review_result": "PASS", "findings": [],
                    "mission_id": "codex-mission-harness", "repository": "ssh://github.com/example/harness.git"}
        openai = {**deepseek, "provider": "openai", "model": "gpt-5.6-sol",
                  "reasoning_effort": "high"}
        qualifications = self._gate_bind(deepseek, openai)
        validate = lambda value: value
        proof = gate.validate_gate(qualification_validators=qualifications, root=self.root, base=self.base, head=self.head,
                    deepseek_receipt=deepseek, openai_receipt=openai,
                    deepseek_validator=validate, openai_validator=validate,
                    mission_id="codex-mission-harness", repository="ssh://github.com/example/harness.git")
        self.assertEqual(proof["status"], "PASS")
        openai["findings"] = [{"severity": "P1"}]
        with self.assertRaises(ValueError):
            gate.validate_gate(qualification_validators=qualifications, root=self.root, base=self.base, head=self.head,
                deepseek_receipt=deepseek, openai_receipt=openai,
                deepseek_validator=validate, openai_validator=validate,
                mission_id="codex-mission-harness", repository="ssh://github.com/example/harness.git")

    def test_gate_rechecks_checkout_after_lane_validation(self):
        diff_hash = hashlib.sha256(self.diff).hexdigest()
        identity = {"base_sha": self.base, "head_sha": self.head,
                    "diff_sha256": diff_hash, "review_result": "PASS", "findings": [],
                    "mission_id": "codex-mission-harness",
                    "repository": "ssh://github.com/example/harness.git"}
        deepseek = dict(identity, provider="deepseek", model="deepseek-flash")
        openai = dict(identity, provider="openai", model="gpt-5.6-sol",
                      reasoning_effort="high")
        qualifications = self._gate_bind(deepseek, openai)
        def mutate(value):
            (self.root / "x.py").write_text("uncommitted mutation\n")
            return value
        with self.assertRaisesRegex(ValueError, "changed during validation"):
            gate.validate_gate(qualification_validators=qualifications, root=self.root, base=self.base, head=self.head,
                deepseek_receipt=deepseek, openai_receipt=openai,
                deepseek_validator=lambda value: value, openai_validator=mutate,
                mission_id="codex-mission-harness", repository=identity["repository"])


if __name__ == "__main__":
    unittest.main()
