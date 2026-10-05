"""Signed synthetic availability, fake Codex only; no real subscription access."""
import copy
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import test_formal_delivery_gate as fixtures
from harness import formal_delivery_gate as gate, resource_gate as resources
from harness import openai_invocation as invocation
from harness.resource_gate import SubscriptionPause, ResourceGateDenied, canonical, digest, sign_authorization


class AvailabilityTests(unittest.TestCase):
    write = fixtures.FormalDeliveryGateTests.write
    publish = fixtures.FormalDeliveryGateTests.publish
    load = fixtures.FormalDeliveryGateTests.load

    def setUp(self):
        fixtures.FormalDeliveryGateTests.setUp(self)
        self.policy = dict(version=gate.AVAILABILITY_VERSION, provider='openai', route='codex_subscription',
            model='gpt-5.6-sol', binary=str(invocation.CANONICAL_BINARY),
            codex_home=str(invocation.CANONICAL_HOME), max_snapshot_age_seconds=200)
        self.payload['openai_availability_policy'] = self.policy
        # No numeric provider quota claim, even an UNKNOWN balance is irrelevant.
        self.accounts['accounts']['openai'].pop('available_microunits')
        self.publish()
        self.refresh()

    def ledger_value(self): return gate._checked_child(self.ledger, self.key.read_bytes())

    def snapshot(self, **changes):
        old = self.ledger_value().get('openai_availability')
        value = dict(self.policy, evidence_domain='OFFLINE_TEST',
            account_id=self.payload['account_ids']['openai'],
            credential_identity=self.payload['credential_identities']['openai'],
            authorization_sha256=self.env['CMH_RESOURCE_AUTH_SHA256'], policy_sha256=digest(canonical(self.policy)),
            epoch=old['epoch']+1 if old else 1, previous_snapshot_sha256=old['sha256'] if old else None,
            baseline_checkpoint_sha256=digest(gate._checkpoint_path(self.ledger).read_bytes()),
            observed_epoch=990, expires_epoch=1090, source_path=str(self.official),
            source_sha256=digest(self.official.read_bytes()), subscription_active=True,
            membership_active=True, known_capacity_blocked=False)
        value.update(changes); return value

    def refresh(self, **changes):
        value=self.snapshot(**changes); path=self.root/('availability-%d.json'%value['epoch'])
        self.write(path, sign_authorization(value,self.key.read_bytes()))
        gate._refresh_availability_validated(self.load(),self.env,path,digest(path.read_bytes()),self.now,offline=True)

    def reserve(self, prompt=b'fixture', stage='qualification-case'):
        return gate._reserve_validated(self.load(),self.env,'openai','gpt-5.6-sol',prompt,stage,self.now,offline=True)

    def settle(self, r):
        r.observe({'tokens':{k:0 for k in gate.CATEGORIES}}); r.settle('RETURNED')

    def test_available_authorizes_current_call_without_n_call_claim(self):
        r=self.reserve(); self.assertFalse(r.execution_allowed)
        self.assertEqual(self.ledger_value()['requests'][0]['subscription_availability_epoch'],1)
        self.assertNotIn('authorized_calls', self.snapshot())

    def test_stale_and_missing_block_before_send(self):
        from harness.model_registry import ModelSpec
        self.now=1090
        with patch.object(resources,'reserve',side_effect=lambda **kw:self.reserve()), \
             patch.object(invocation,'_invoke_openai_unmetered') as send:
            with self.assertRaises(SubscriptionPause):
                invocation.invoke_openai('fixture',ModelSpec('openai','gpt-5.6-sol','high'),{})
            send.assert_not_called()
        self.assertEqual(self.ledger_value()['requests'],[])
        self.now=1000; ledger=self.ledger_value(); ledger.pop('openai_availability')
        gate._write_child(self.ledger,ledger,self.key.read_bytes())
        with self.assertRaises(SubscriptionPause): self.reserve()

    def test_wrong_identity_or_invalid_status_rejected(self):
        for change in ({'provider':'deepseek'}, {'route':'openai_api'}, {'model':'other'},
            {'codex_home':'/tmp/other'}, {'account_id':'other'}, {'credential_identity':'0'*64},
            {'subscription_active':'true'}, {'expires_epoch':5000}):
            with self.subTest(change=change), self.assertRaises(ResourceGateDenied): self.refresh(**change)
        for change in ({'subscription_active':False},{'membership_active':False},{'known_capacity_blocked':True}):
            with self.assertRaises(SubscriptionPause): self.refresh(**change)

    def test_historical_percentages_never_authorize(self):
        with self.assertRaises(SubscriptionPause):
            self.refresh(observed_epoch=1,expires_epoch=100,five_hour_remaining_percent=71,weekly_remaining_percent=80)
        value=self.snapshot(); value.pop('subscription_active'); value['five_hour_remaining_percent']=71
        p=self.root/'percent-only.json';self.write(p,sign_authorization(value,self.key.read_bytes()))
        with self.assertRaises(ResourceGateDenied):
            gate._availability_snapshot(self.load(),p,digest(p.read_bytes()),self.key.read_bytes(),self.now)

    def test_oa103_and_token_cost_clock_limits_remain(self):
        lane=self.payload['providers']['openai'];lane.update(max_new_calls=103,
            token_limit={k:10000 for k in gate.CATEGORIES},cost_limit_microunits=103000000)
        self.payload.update(max_new_calls=203,shared_max_calls=1000,
                            shared_cost_limits={'deepseek':100000000,'openai':1000000000})
        self.publish()
        ledger=self.ledger_value();ledger.pop('openai_availability');gate._write_child(self.ledger,ledger,self.key.read_bytes());self.refresh()
        for i in range(103):self.settle(self.reserve(stage='chunk-%d'%i))
        with self.assertRaises(ResourceGateDenied):self.reserve(stage='chunk-104')
        self.assertEqual(len(self.ledger_value()['requests']),103)
        self.now=self.payload['expires_epoch']
        with self.assertRaises(ResourceGateDenied):self.reserve()

    def test_available_cannot_override_tokens_cost_or_unknown(self):
        self.settle(self.reserve())
        original=copy.deepcopy(self.payload)
        for field,value in (('token_limit',{k:1 for k in gate.CATEGORIES}),('cost_limit_microunits',1000000)):
            self.payload['providers']['openai'][field]=value;self.publish()
            with self.assertRaises(ResourceGateDenied):self.reserve()
            self.payload=copy.deepcopy(original);self.publish()
        r=self.reserve();r.settle('FAILED')
        with self.assertRaises(ResourceGateDenied):self.refresh()

    def test_signed_source_policy_and_epoch_cannot_be_forged(self):
        entry=self.ledger_value()['openai_availability']
        with self.assertRaises(ResourceGateDenied):
            gate._refresh_availability_validated(self.load(),self.env,entry['path'],entry['sha256'],self.now,offline=True)
        value=self.snapshot();p=self.root/'unsigned.json';self.write(p,value)
        with self.assertRaises(ResourceGateDenied):
            gate._refresh_availability_validated(self.load(),self.env,p,digest(p.read_bytes()),self.now,offline=True)
        self.official.write_bytes(b'changed synthetic source')
        with self.assertRaises(ResourceGateDenied):self.reserve()

    def test_capacity_pause_attempts_remain_bounded(self):
        from harness.model_qualification import CASES,qualification_prompt
        prompt=qualification_prompt(CASES[0]).encode()
        row=dict(provider='openai',stage='qualification-case',authorization_sha256='test',run_id='run',
            status='FAILED',reported_usage={'tokens':{}},failure_class='SUBSCRIPTION_UNAVAILABLE',
            usage_accounting='FULL_RESERVATION_RETAINED',prompt_sha256=digest(prompt))
        gate._qualification_request([row],'openai',prompt,'run')
        with self.assertRaises(ResourceGateDenied):gate._qualification_request([row,row],'openai',prompt,'run')
        with self.assertRaises(ResourceGateDenied):gate._qualification_request([row],'openai',prompt,'another-run')

    def test_failure_classifier_is_narrow_and_ignores_review_text(self):
        for text in (b'quota exhausted',b'usage_limit_reached',b"You've hit your usage limit",
                     b'subscription unavailable',b'membership expired',b'insufficient_quota'):
            self.assertEqual(invocation._failure_category(text,b'',timed_out=False),'SUBSCRIPTION_UNAVAILABLE')
        self.assertEqual(invocation._failure_category(b'429 rate limit',b'',timed_out=False),'TRANSIENT_CAPACITY')
        self.assertEqual(invocation._event_error_bytes(b'{"type":"item.completed","item":{"text":"quota exhausted"}}'),b'')

    def test_explicit_provider_failure_pauses_once_and_freezes_unknown(self):
        from harness.model_registry import ModelSpec
        def fail(*args,**kwargs): raise invocation.InvocationFailure('SUBSCRIPTION_UNAVAILABLE','synthetic',{})
        with patch.object(resources,'reserve',side_effect=lambda **kw:self.reserve()), \
             patch.object(invocation,'_invoke_openai_unmetered',side_effect=fail) as send:
            with self.assertRaises(SubscriptionPause):
                invocation.invoke_openai('fixture',ModelSpec('openai','gpt-5.6-sol','high'),{})
            send.assert_called_once()
        before=self.ledger.read_bytes();row=self.ledger_value()['requests'][0]
        self.assertEqual(row['status'],'FAILED');self.assertEqual(row['reported_usage'],'UNKNOWN')
        self.assertEqual(row['failure_class'],'SUBSCRIPTION_UNAVAILABLE')
        with self.assertRaises(ResourceGateDenied):self.refresh()
        self.assertEqual(self.ledger.read_bytes(),before)

    def test_refresh_keeps_history_clock_and_qualification(self):
        self.settle(self.reserve());before=self.ledger_value();binding=gate.qualification_binding(self.load())
        self.refresh();after=self.ledger_value()
        self.assertEqual(before['requests'],after['requests'])
        self.assertEqual(before.get('started_epoch'),after.get('started_epoch'))
        self.assertEqual(binding,gate.qualification_binding(self.load()))
        auth=copy.deepcopy(self.load());auth['runtime']['models']['openai']['model']='other'
        self.assertNotEqual(binding,gate.qualification_binding(auth))

    def test_checkpoint_pause_preserves_completed_stages(self):
        from harness.review_resume import ReviewRun
        import deepseek_review as storage
        root=self.root/'repo';root.mkdir();identity={'provider':'openai','runtime':'synthetic'}
        run=ReviewRun(self.root/'reviews',root,identity,[('chunk-000','chunk'),('chunk-001','chunk')],storage,prefix='offline-')
        run.stage('chunk-000','chunk',b'one',lambda:b'{}',json.loads)
        run.failure(dict(status='PAUSED_SUBSCRIPTION_UNAVAILABLE',failure_category='PAUSED_SUBSCRIPTION_UNAVAILABLE'))
        oldpath=run.path;run.close()
        resumed=ReviewRun(self.root/'reviews',root,identity,[('chunk-000','chunk'),('chunk-001','chunk')],storage,prefix='offline-')
        try:
            self.assertEqual(resumed.path,oldpath);self.assertEqual(resumed.state['completed_order'],['chunk-000'])
            self.assertFalse(resumed.state['receipt_written'])
        finally:resumed.close()

    def test_qualification_two_pass_third_pause_then_refresh_resume(self):
        from harness.model_registry import ModelSpec
        from harness.model_qualification import QualificationEvidence,CASES,qualification_prompt,_evaluate_cases,expected_findings
        from harness.openai_invocation import InvocationResult
        spec=ModelSpec('openai','gpt-5.6-sol','high');self.runtime['models']['openai']=spec.identity();self.payload['runtime']=self.runtime;self.publish()
        ledger=self.ledger_value();ledger.pop('openai_availability');gate._write_child(self.ledger,ledger,self.key.read_bytes());self.refresh()
        evidence=QualificationEvidence(self.root/'qualification');calls=[];paused=[]
        def invoke(actual,prompt):
            case=next(c for c in CASES if qualification_prompt(c)==prompt);r=self.reserve(prompt.encode());evidence.capture_reservation(case.name,r.request_id)
            calls.append(case.name)
            if case.name==CASES[2].name and not paused:
                # Synthetic known usage: production UNKNOWN may never be cleared by refresh.
                paused.append(True);r.observe({'tokens':{k:0 for k in gate.CATEGORIES}});r.settle('FAILED');gate.record_subscription_block(r)
                raise SubscriptionPause('synthetic exhaustion',provider_attempted=True)
            self.settle(r)
            decisions=[dict(finding_id=f['finding_id'],decision=case.expected.get('F'+str(i+1),'UPHELD'),
                rationale='The exact source supports this semantic disposition.',
                source_quote='return a + b' if case.name=='source_based_dispute' else '') for i,f in enumerate(expected_findings(case))]
            return InvocationResult(json.dumps(dict(decisions=decisions,findings=[],summary='Exact synthetic source checked for the semantic case.')),
                                    {'resource_request_id':r.request_id})
        with patch.dict(os.environ,self.env,clear=True),patch.object(gate,'load_authorization',side_effect=lambda:self.load()):
            with self.assertRaises(SubscriptionPause):_evaluate_cases(spec,invoke,mode='real_provider',evidence=evidence)
            self.assertEqual(len(self.ledger_value()['qualification_progress']['openai/offline-run']['cases']),2)
            with self.assertRaises(SubscriptionPause):self.reserve()
            history=copy.deepcopy(self.ledger_value()['requests']);self.refresh()
            self.assertEqual(history,self.ledger_value()['requests'])
            evidence=QualificationEvidence(evidence.directory,resume=True)
            result=_evaluate_cases(spec,invoke,mode='real_provider',evidence=evidence)
            self.assertEqual(len(result.cases_passed),4);self.assertFalse(result.passed)
        self.assertEqual(calls.count('clean'),1);self.assertEqual(calls.count('single_blocker'),1)
        self.assertEqual(len(self.ledger_value()['requests']),5)


if __name__=='__main__':unittest.main()
