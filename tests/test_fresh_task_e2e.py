"""Existing two runners/validators/Consumer on exact PR2, fake models only.

The qualification adapter is explicitly synthetic and cannot issue a live
certificate. Actual gate slots, signed fixture accounting, raw usage binding,
review parsers, source binding and both receipt validators remain in use.
"""
import copy
import hmac
import hashlib
import json
import os
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from harness import formal_delivery_gate as gate, fresh_task as fresh, full_diff_manifest as full
from harness import openai_invocation as invocation, resource_gate as resources, model_qualification as qualification
from harness.model_registry import load_registry
from harness.premerge_plan import build_plan
from harness.resource_gate import canonical, digest
import test_fresh_task as fixtures
import reviewer_v2_openai as oa
import reviewer_v2_deepseek as ds
import reviewer_v2_gate as consumer
from direct_deepseek_fixture import envelope, USAGE


class FreshTaskEndToEndTests(unittest.TestCase):
    def test_20_21_22_complete_new_task_consumer_and_cross_identity_rejection(self):
        f = fixtures.FreshTaskTests(); f.setUp()
        self.addCleanup(f.doCleanups)
        auth = f.load()
        root = Path('/home/xupeng/codex-mission-harness.pr2-final-candidate')
        runtime_root = Path(gate.__file__).resolve().parents[2]
        repository = auth['fresh_task']['scope']['repository']
        models = {p: load_registry().role('final_reviewer' if p == 'openai' else 'independent_reviewer')
                  for p in ('openai', 'deepseek')}
        # Bind the actual current code/schema bytes in the isolated fixture.
        f.payload['runtime']['head'] = full.git(runtime_root, 'rev-parse', 'HEAD').decode().strip()
        f.payload['runtime']['files'] = {name: digest((runtime_root / name).read_bytes()) for name in gate.RUNTIME_FILES}
        f.payload['runtime']['registry_sha256'] = digest(load_registry().path.read_bytes())
        f.runtime = f.payload['runtime']
        scope, manifest = fresh.build_scope(runtime_root, f.runtime)
        f.payload['fresh_task'].update(scope=scope, request_plan=fresh.build_request_plan(scope, manifest))
        f.approve(); f.activate(); auth = f.load()
        qualified = {p: dict(role='final_reviewer' if p == 'openai' else 'independent_reviewer',
                            mode='real_provider', identity=s.identity(), delivery_binding=gate.qualification_binding(auth),
                            offline_test_only=True, live_certificate_eligible=False)
                     for p, s in models.items()}
        key = 'OFFLINE_ONLY_NEVER_PROVIDER_CREDENTIAL'
        events_seen = []

        def reserve(p, stage, prompt, raw):
            f.env['CMH_RESOURCE_RUN_ID'] = os.environ.get('CMH_RESOURCE_RUN_ID', 'fixture-qualification-' + p)
            r = f.reserve_stage(p, stage, prompt.encode())
            if p == 'openai':
                event_stream = b'\n'.join(canonical(v) for v in [
                    {'type': 'thread.started', 'thread_id': 'OFFLINE-thread-' + r.request_id},
                    {'type': 'turn.started'},
                    {'type': 'item.completed', 'item': {'type': 'agent_message', 'id': 'OFFLINE-message', 'text': raw.decode()}},
                    {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'cached_input_tokens': 2,
                        'output_tokens': 5, 'reasoning_output_tokens': 3}}]) + b'\n'
                active = resources._active_reservation.set(r)
                try:
                    ref = invocation._persist_transport(prompt.encode(), event_stream, b'', raw,
                                                        models[p], '0' * 64)
                finally: resources._active_reservation.reset(active)
                parsed = invocation.parse_events(event_stream)
                usage = dict(parsed['usage'], transport_binding=ref, thread_id=parsed['thread_id'],
                             turn_ordinal=parsed['turn_ordinal'], agent_message_id=parsed['agent_message_id'],
                             response_sha256=digest(raw))
            else: usage = ds.direct.normalize_usage(USAGE)
            r.observe(usage); r.settle('RETURNED')
            events_seen.append(dict(provider=p, stage=stage, request_id=r.request_id,
                                    prompt_sha256=digest(prompt.encode()), fixture_only=True))
            return raw

        def qualify(p):
            def call(spec, prompt):
                case = next(c for c in qualification.CASES if qualification.qualification_prompt(c) == prompt)
                decisions = []
                for i, finding in enumerate(qualification.expected_findings(case)):
                    disposition = case.expected['F' + str(i + 1)]
                    decisions.append(dict(finding_id=finding['finding_id'], decision=disposition,
                        rationale='OFFLINE fixture: exact qualification source supports this decision.',
                        source_quote='return a + b' if disposition == 'DISPUTED' else ''))
                raw = canonical(dict(findings=[], decisions=decisions,
                    summary='OFFLINE fixture: deterministic semantic qualification only.'))
                return reserve(p, 'qualification-case', prompt, raw).decode()
            result = qualification.evaluate_cases(models[p], call)
            self.assertEqual(len(result.cases_passed), 4)
            self.assertFalse(result.passed)  # never a real Qualification PASS
            with self.assertRaises(ValueError):
                qualification.qualification_receipt(result, auth_key=key,
                    role=qualified[p]['role'])
            return result

        def simulated_binding(binding, actual):
            self.assertEqual(binding, gate.qualification_binding(actual))
            self.assertEqual(actual['evidence_domain'], 'OFFLINE_TEST')

        def mock_oa(prompt, spec, *, stage, **kwargs):
            value = {'findings': []} if stage == 'chunk' else dict(findings=[], decisions=[],
                summary='OFFLINE ONLY: a fixture did not independently review this code.')
            return reserve('openai', os.environ['CMH_RESOURCE_STAGE'], prompt, canonical(value))

        def mock_ds(prompt, token, schema, **kwargs):
            stage = kwargs['stage']
            value = {'findings': []} if stage.startswith('chunk') else dict(findings=[], decisions=[],
                summary='OFFLINE ONLY: a fixture did not independently review this code.')
            return reserve('deepseek', stage, prompt, envelope(value, prompt, schema))

        def validate_o(value):
            return oa.validate(value, root=root, base=fresh.TARGET_BASE, head=fresh.TARGET_HEAD,
                spec=models['openai'], auth_key=key, receipt_path=opath, mission_id=auth['mission_id'])
        def validate_d(value):
            return ds.validate(value, fresh.TARGET_BASE, fresh.TARGET_HEAD, root, dpath,
                auth['mission_id'], repository, key)

        with patch.dict(os.environ, f.env), patch.object(gate, 'load_authorization', side_effect=f.load), \
             patch.object(gate, 'validate_qualification_binding', side_effect=simulated_binding), \
             patch.object(oa, 'preflight'), \
             patch.object(oa, 'validate_qualification_receipt', return_value=qualified['openai']), \
             patch.object(ds, 'validate_qualification_receipt', return_value=qualified['deepseek']), \
             patch.object(ds.legacy, 'read_token_file', return_value=key), \
             patch.object(oa, 'invoke_codex', side_effect=mock_oa), \
             patch.object(ds.direct, 'invoke', side_effect=mock_ds):
            qualify('openai')
            opath = oa.run(root, fresh.TARGET_BASE, fresh.TARGET_HEAD,
                          fresh.review_evidence_path(auth, 'openai'), key, models['openai'],
                          mission_id=auth['mission_id'], qualification_path='OFFLINE_QUALIFICATION_NOT_REAL')
            oreceipt = json.loads(opath.read_bytes()); validate_o(oreceipt)
            qualify('deepseek')
            args = SimpleNamespace(repo=str(root), base=fresh.TARGET_BASE, head=fresh.TARGET_HEAD,
                evidence=str(fresh.review_evidence_path(auth, 'deepseek')), token_file='OFFLINE_NO_KEY',
                mission_id=auth['mission_id'], timeout=900, qualification='OFFLINE_QUALIFICATION_NOT_REAL')
            dpath = Path(ds.run(args)['review_receipt'])
            dreceipt = json.loads(dpath.read_bytes()); validate_d(dreceipt)
            plan = build_plan(runtime_root, repository, fresh.TARGET_BASE, fresh.TARGET_HEAD,
                              full.git(runtime_root, 'rev-parse', 'HEAD').decode().strip())
            common = dict(root=root, base=fresh.TARGET_BASE, head=fresh.TARGET_HEAD, plan=plan,
                          scope='pr2', repository=repository, deepseek_receipt=dreceipt,
                          openai_receipt=oreceipt, deepseek_validator=validate_d, openai_validator=validate_o,
                          mission_id=auth['mission_id'],
                          qualification_validators={p: (lambda p=p: qualified[p]) for p in models})
            checked = consumer.validate_premerge_gate(**common)
            self.assertEqual(checked['status'], 'PASS')  # fixture Consumer logic only
            rejected = []
            for field, value in [('mission_id', fresh.PREFIX + '0' * 64),
                                  ('head_sha', '0' * 40), ('groups', []), ('review_result', 'FAIL')]:
                for p, receipt, validator in [('openai', oreceipt, validate_o), ('deepseek', dreceipt, validate_d)]:
                    changed = copy.deepcopy(receipt); changed[field] = value
                    changed.pop('auth_hmac_sha256', None)
                    changed['auth_hmac_sha256'] = hmac.new(key.encode(), canonical(changed), hashlib.sha256).hexdigest()
                    with self.subTest(provider=p, field=field), self.assertRaises(ValueError): validator(changed)
                    rejected.append(p + ':' + field)
            with self.assertRaises(ValueError): consumer.validate_premerge_gate(**dict(common, deepseek_receipt=None))
            before = len(events_seen)
            oa.run(root, fresh.TARGET_BASE, fresh.TARGET_HEAD, fresh.review_evidence_path(auth, 'openai'),
                   key, models['openai'], mission_id=auth['mission_id'], qualification_path='OFFLINE_QUALIFICATION_NOT_REAL')
            ds.run(args)
            self.assertEqual(len(events_seen), before)
        ledger = gate._verify_child(f.ledger, f.key.read_bytes(), f.load())
        self.assertEqual(len(ledger['requests']), 14)
        self.assertEqual([v['provider'] for v in ledger['requests']], ['openai'] * 7 + ['deepseek'] * 7)
        self.assertEqual(f.predecessor.read_bytes(), f.old_bytes)
        self.assertEqual(gate._read(gate._checkpoint_path(f.predecessor)), f.old_checkpoint)
        output = os.environ.get('CMH_OFFLINE_E2E_EVIDENCE_DIR')
        if output:
            dest = Path(output); dest.mkdir(parents=True, exist_ok=True)
            for p in models:
                shutil.copytree(fresh.review_evidence_path(auth, p), dest / ('OFFLINE_ONLY-' + p), dirs_exist_ok=True)
            shutil.copytree(f.ledger.parent / 'openai-invocations', dest / 'OFFLINE_ONLY-raw-openai', dirs_exist_ok=True)
            for name, path in [('OFFLINE_ONLY-ledger.json', f.ledger), ('OFFLINE_ONLY-checkpoint.json', gate._checkpoint_path(f.ledger)),
                               ('OFFLINE_ONLY-authorization.json', f.auth), ('OFFLINE_ONLY-user-approval.json', f.approval)]:
                shutil.copyfile(path, dest / name)
            (dest / 'offline-e2e-result.json').write_text(json.dumps(dict(status='PASS_OFFLINE_SIMULATION_ONLY',
                target_head=fresh.TARGET_HEAD, target_tree=fresh.TARGET_TREE, synthetic_mission=auth['mission_id'],
                consumed_simulated_slots=14, providers={'openai': 7, 'deepseek': 7},
                consumer_status='PASS_OFFLINE_FIXTURES_NOT_REAL_REVIEW', invalid_receipts_rejected=rejected,
                resume_additional_fixture_calls=0, real_model_calls=0, production_grants_created=0,
                real_qualification_certificates=0, qualification_adapter='explicit simulation; domain refusal separately tested',
                old_history_unchanged=True, transport_events=events_seen), indent=2))


if __name__ == '__main__': unittest.main()
