"""Offline security tests. No Provider traffic, keys or production accounting."""
import copy
import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from harness import diagnostic_probe as probe, formal_delivery_gate as gate
from harness import resource_gate as resources, artifact_lineage
from harness.model_registry import ModelSpec
from harness.openai_invocation import InvocationFailure, InvocationResult
from harness.resource_gate import ResourceGateDenied, canonical, digest
import test_formal_delivery_gate as fixture


class DiagnosticScopeTests(unittest.TestCase):
    setUp = fixture.FormalDeliveryGateTests.setUp
    write = fixture.FormalDeliveryGateTests.write
    publish = fixture.FormalDeliveryGateTests.publish
    load = fixture.FormalDeliveryGateTests.load

    def enable(self):
        self.runtime['models']['openai'] = copy.deepcopy(probe.MODEL)
        self.payload['runtime'] = self.runtime
        self.payload.update(qualification_launch_approved=False, full_review_launch_approved=False)
        self.payload['diagnostic_probe'] = {
            'version': probe.VERSION, 'mission': probe.MISSION, 'purpose': probe.PURPOSE,
            'model': copy.deepcopy(probe.MODEL), 'route': 'codex_subscription',
            'max_logical_invocations': 1, 'result_authority': probe.CLASSIFICATION,
            'harness_logical_retry': 0, 'runtime_head': self.runtime['head'],
            'token_ceiling': self.payload['providers']['openai']['token_reservation'],
            'cost_ceiling_microunits': 1000000, 'diagnostic_id': 'd'*64,
            'prompt_sha256': digest(b'fixture'), 'schema_sha256': digest(canonical({})),
            'prompt_bytes': 7}
        self.approval.write_bytes(canonical({'diagnostic_probe': self.payload['diagnostic_probe']}))
        self.payload['user_approval_sha256'] = digest(self.approval.read_bytes())
        self.env['CMH_RESOURCE_RUN_ID'] = 'd'*64
        self.publish()

    def reserve_probe(self, prompt=b'fixture', provider='openai', model='gpt-5.6-sol'):
        return gate._reserve_validated(self.load(), self.env, provider, model, prompt,
                                       probe.STAGE, self.now, offline=True)

    def settle(self, r, usage=None):
        with patch.object(gate, 'load_authorization', side_effect=self.load):
            if usage is not None: r.observe(usage)
            r.settle('RETURNED' if usage else 'FAILED')
        return json.loads(self.ledger.read_bytes())['requests'][-1]

    def test_explicit_approval_required(self):
        self.enable(); self.approval.write_text('{}')
        self.payload['user_approval_sha256']=digest(self.approval.read_bytes()); self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_scope_cannot_change_model_route_runtime_or_invocation_count(self):
        self.enable(); original=copy.deepcopy(self.payload['diagnostic_probe'])
        for key,value in [('model',dict(probe.MODEL,reasoning_effort='low')),('route','api'),
                          ('max_logical_invocations',2),('max_logical_invocations',True),
                          ('runtime_head','b'*40),('harness_logical_retry',1),
                          ('purpose','arbitrary request'),('result_authority','FORMAL'),
                          ('token_ceiling',dict.fromkeys(gate.CATEGORIES,1)),
                          ('cost_ceiling_microunits',1)]:
            with self.subTest(key=key,value=value):
                self.payload['diagnostic_probe']=dict(original,**{key:value})
                with self.assertRaises(ResourceGateDenied): probe.validate_scope(self.payload)

    def test_exact_prompt_and_run_id(self):
        self.enable()
        for prompt in [b'other',b'fixture\n']:
            with self.assertRaises(ResourceGateDenied): self.reserve_probe(prompt)
        self.env['CMH_RESOURCE_RUN_ID']='other'
        with self.assertRaises(ResourceGateDenied): self.reserve_probe()
        self.assertEqual(json.loads(self.ledger.read_bytes())['requests'],[])

    def test_wrong_provider_model_and_missing_scope(self):
        self.enable()
        for p,m in [('deepseek','deepseek-flash'),('openai','other')]:
            with self.assertRaises(ResourceGateDenied): self.reserve_probe(provider=p,model=m)
        del self.payload['diagnostic_probe']; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve_probe()

    def test_independent_identity_normal_reservation_and_second_call_rejected(self):
        self.enable(); r=self.reserve_probe(); row=self.settle(r)
        self.assertNotEqual(r.request_id,self.env['CMH_RESOURCE_RUN_ID'])
        self.assertEqual(row['stage'],probe.STAGE)
        self.assertEqual(row['result_authority'],probe.CLASSIFICATION)
        self.assertNotIn('target',row)
        self.assertEqual(row['token_reservation'],dict.fromkeys(gate.CATEGORIES,10))
        self.assertEqual(row['cost_reservation_microunits'],1000000)
        with self.assertRaises(ResourceGateDenied): self.reserve_probe()
        self.assertEqual(len(json.loads(self.ledger.read_bytes())['requests']),1)

    def test_verified_usage_normal_settlement(self):
        self.enable(); r=self.reserve_probe()
        usage={'tokens':dict.fromkeys(gate.CATEGORIES,1),'usage_scope':'CODEX_EXEC_TURN'}
        with patch('harness.openai_invocation.verify_openai_usage',return_value=True) as verify:
            row=self.settle(r,usage)
        verify.assert_called_once()
        self.assertEqual(row['reported_usage'],usage)
        self.assertEqual(row['usage_accounting'],'FULL_RESERVATION_RETAINED')

    def test_missing_usage_fail_closed(self):
        self.enable(); r=self.reserve_probe(); row=self.settle(r)
        self.assertEqual(row['reported_usage'],'UNKNOWN')
        self.assertEqual(row['usage_accounting'],'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        self.assertEqual(row['cost_reservation_microunits'],1000000)

    def test_unverifiable_usage_retains_full_reservation(self):
        self.enable(); r=self.reserve_probe()
        with patch('harness.openai_invocation.verify_openai_usage',side_effect=ValueError('untrusted')):
            row=self.settle(r,{'tokens':dict.fromkeys(gate.CATEGORIES,1),'usage_scope':'CODEX_EXEC_TURN'})
        self.assertEqual(row['usage_accounting'],'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        self.assertEqual(row['token_reservation'],dict.fromkeys(gate.CATEGORIES,10))

    def test_mission_call_token_cost_hard_limits_apply(self):
        self.enable()
        for field,value in [('max_new_calls',0),('token_limit',dict.fromkeys(gate.CATEGORIES,1)),
                            ('cost_limit_microunits',1)]:
            with self.subTest(field=field):
                if field=='max_new_calls':
                    self.payload[field]=value
                else: self.payload['providers']['openai'][field]=value
                self.publish()
                with self.assertRaises(ResourceGateDenied): self.reserve_probe()
                self.assertEqual(json.loads(self.ledger.read_bytes())['requests'],[])
                if field=='max_new_calls':self.payload[field]=10
                elif field=='token_limit':self.payload['providers']['openai'][field]=dict.fromkeys(gate.CATEGORIES,100)
                else:self.payload['providers']['openai'][field]=5000000

    def test_diagnostic_authority_rejects_all_formal_stages(self):
        self.enable()
        for stage in ['qualification-case','chunk-000','group-000','final','structured-preflight']:
            with self.subTest(stage=stage), self.assertRaises(ResourceGateDenied):
                gate._reserve_validated(self.load(),self.env,'openai','gpt-5.6-sol',b'fixture',stage,self.now,offline=True)

    def test_cannot_issue_qualification_binding_or_bind_formal_review(self):
        self.enable(); auth=self.load()
        with self.assertRaises(ResourceGateDenied):gate.qualification_binding(auth)
        with patch.object(gate,'load_authorization',return_value=auth):
            with self.assertRaises(ResourceGateDenied):
                gate.bind_review(gate.NEW_MISSION,self.root,'base','head','registry',ModelSpec(**probe.MODEL),{})

    def test_cannot_create_or_update_review_run(self):
        from harness.review_resume import ReviewRun
        self.enable(); storage=Mock()
        with patch.dict(os.environ,self.env),patch.object(gate,'load_authorization',side_effect=self.load):
            with self.assertRaises(ResourceGateDenied):ReviewRun(self.root,self.root,{},[],storage,prefix='review')
        storage.open_private_directory.assert_not_called()

    def test_origin_not_authoritative_for_qualification_receipt_or_adjudication(self):
        self.enable(); auth=self.load(); auth['_lineage_sha256']=[auth['_authorization_sha256']]
        with patch.dict(os.environ,self.env), patch.object(gate,'_verify_child',return_value={'requests':[]}):
            with self.assertRaisesRegex(ValueError,'DIAGNOSTIC_ONLY'):
                artifact_lineage.origin_authority(auth['_authorization_sha256'],auth)

    def test_scope_count_inherited_across_continuation(self):
        self.enable(); r=self.reserve_probe(); self.settle(r)
        rows=json.loads(self.ledger.read_bytes())['requests']
        later=dict(self.load(),_authorization_sha256='new-authority')
        with self.assertRaises(ResourceGateDenied):
            probe.validate_request(later,rows,'openai','gpt-5.6-sol',b'fixture','d'*64)

    def test_no_harness_retry_and_reconnect_capture(self):
        self.enable(); captured=[]
        def fake_invoke(prompt,spec,schema,**kwargs):
            kwargs['transport_sink'](prompt.encode(),b'{"type":"error","message":"Reconnecting... 1/5"}\n',b'')
            raise InvocationFailure('TRANSIENT_TRANSPORT','failed',{'terminal_observed':False})
        def reserve(**kw):return self.reserve_probe(kw['prompt'],kw['provider'],kw['model'])
        with patch.dict(os.environ,self.env),patch.object(gate,'load_authorization',side_effect=self.load), \
             patch.object(resources,'reserve',side_effect=reserve), \
             patch('harness.openai_invocation.invoke_openai',side_effect=fake_invoke) as invoke:
            with self.assertRaises(InvocationFailure):probe.run_once('fixture',{},transport_sink=lambda *x:captured.append(x))
        invoke.assert_called_once(); self.assertIn(b'Reconnecting',captured[0][1])
        self.assertEqual(json.loads(self.ledger.read_bytes())['requests'][0]['reported_usage'],'UNKNOWN')

    def test_cannot_borrow_existing_reservation(self):
        self.enable(); token=resources._active_reservation.set(Mock())
        try:
            with self.assertRaises(ResourceGateDenied):probe.run_once('fixture',{})
        finally:resources._active_reservation.reset(token)
        self.assertEqual(json.loads(self.ledger.read_bytes())['requests'],[])

    def test_schema_mismatch_does_not_reserve(self):
        self.enable()
        with patch.object(gate,'load_authorization',side_effect=self.load):
            with self.assertRaises(ResourceGateDenied):probe.run_once('fixture',{'changed':True})
        self.assertEqual(json.loads(self.ledger.read_bytes())['requests'],[])

    def test_only_noncanonical_result_returned(self):
        self.enable()
        def reserve(**kw):return self.reserve_probe(kw['prompt'],kw['provider'],kw['model'])
        with patch.dict(os.environ,self.env),patch.object(gate,'load_authorization',side_effect=self.load), \
             patch.object(resources,'reserve',side_effect=reserve), \
             patch('harness.openai_invocation.invoke_openai',return_value=InvocationResult('{}',{})) as invoke:
            result=probe.run_once('fixture',{})
        self.assertEqual(result['result_authority'],probe.CLASSIFICATION); invoke.assert_called_once()
        self.assertEqual(set(result),{'result_authority','request_id','response','evidence'})

    def test_relabel_history_detected_by_checkpoint(self):
        self.enable(); r=self.reserve_probe(); self.settle(r)
        raw=json.loads(self.ledger.read_bytes());raw['requests'][0]['stage']='group-000'
        self.ledger.write_bytes(canonical(raw))
        with self.assertRaises(ResourceGateDenied):gate._checked_child(self.ledger,self.key.read_bytes())

    def test_history_parent_334_and_limits_unchanged(self):
        self.enable(); before=self.parent.read_bytes(); limits=copy.deepcopy(self.payload['providers'])
        r=self.reserve_probe();self.settle(r)
        self.assertEqual(self.parent.read_bytes(),before)
        self.assertEqual(self.payload['providers'],limits)

    def test_prepared_prompt_schema_model_semantics_unchanged(self):
        # The diagnostic/governance files are deliberately not reviewer semantic inputs.
        self.assertNotIn('src/harness/diagnostic_probe.py',artifact_lineage.SEMANTIC_FILES)
        self.assertNotIn('src/harness/formal_delivery_gate.py',artifact_lineage.SEMANTIC_FILES)
        self.assertNotIn('src/harness/review_resume.py',artifact_lineage.SEMANTIC_FILES)
        self.assertEqual(probe.MODEL,ModelSpec('openai','gpt-5.6-sol','high').identity())
