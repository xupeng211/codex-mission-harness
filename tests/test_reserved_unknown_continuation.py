"""Synthetic, signed five-call history. No real authority or provider execution."""
import copy
import json
import unittest
from unittest.mock import patch
from pathlib import Path
from harness import formal_delivery_gate as gate
from harness.resource_gate import canonical,digest,sign_authorization,ResourceGateDenied
import test_formal_delivery_gate as fixtures


class ContinuationTests(unittest.TestCase):
    write=fixtures.FormalDeliveryGateTests.write
    publish=fixtures.FormalDeliveryGateTests.publish

    def setUp(self):
        fixtures.FormalDeliveryGateTests.setUp(self)
        self.payload['max_new_calls']=203;self.payload['shared_max_calls']=537
        for p in ('deepseek','openai'):
            self.accounts['accounts'][p]['available_microunits']=200000000
            self.payload['shared_cost_limits'][p]=200000000
        for p,n in (('deepseek',100),('openai',103)):
            self.payload['providers'][p]['max_new_calls']=n
            self.payload['providers'][p]['token_limit']={k:10000 for k in gate.CATEGORIES}
            self.payload['providers'][p]['cost_limit_microunits']=n*self.payload['providers'][p]['cost_reservation_microunits']
        self.publish();self.prior=copy.deepcopy(self.payload);self.prior_path=self.root/'prior-auth.json'
        self.prior_path.write_bytes(self.auth.read_bytes());self.prior_path.chmod(0o600)
        self.prior_sha=digest(self.prior_path.read_bytes())
        child=gate._checked_child(self.ledger,self.key.read_bytes());rows=[]
        for i in range(1,6):
            p='deepseek' if i<=4 else 'openai';lane=self.prior['providers'][p]
            rows.append(dict(number=i,request_id='synthetic-%d'%i,mission_id=gate.NEW_MISSION,
                provider=p,model=lane['model'],authorization_sha256=self.prior_sha,
                status='RETURNED',stage='qualification-case',run_id='old-run',
                reported_usage='UNKNOWN' if i==5 else {'tokens':{k:1 for k in gate.CATEGORIES}},
                usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS' if i==5 else 'FULL_RESERVATION_RETAINED',
                token_reservation=lane['token_reservation'],cost_reservation_microunits=lane['cost_reservation_microunits'],
                cost_unit=lane['cost_unit'],started_epoch=960+i,finished_epoch=961+i,duration_seconds=1))
        child['requests']=rows;gate._write_child(self.ledger,child,self.key.read_bytes())
        self.predecessor_path=self.ledger;self.frozen_rows=copy.deepcopy(rows);self.parent_hash=digest(self.parent.read_bytes())
        c=dict(version=gate.CONTINUATION_VERSION,predecessor_ledger_path=str(self.ledger),
            predecessor_ledger_sha256=digest(self.ledger.read_bytes()),
            predecessor_checkpoint_sha256=digest(gate._checkpoint_path(self.ledger).read_bytes()),
            requests_sha256=digest(canonical(rows)),unknown_request_id=rows[4]['request_id'],unknown_row_sha256=digest(canonical(rows[4])),
            retain_unknown=True,refund=0,full_reservation_nonrefundable=True,
            consumed_calls={'deepseek':4,'openai':1,'global':5},remaining_call_limits={'deepseek':96,'openai':102,'global':198})
        self.ledger=self.root/'continuation.json';self.env['CMH_RESOURCE_LEDGER']=str(self.ledger)
        self.approval=self.root/'new-approval.txt'
        self.approval.write_text('OFFLINE ONLY new independent continuation approval');self.approval.chmod(0o600)
        self.payload['user_approval_path']=str(self.approval)
        self.payload.update(authorization_id='continuation-synthetic',approved_at_epoch=1000,
            user_approval_sha256=digest(self.approval.read_bytes()),ledger_path=str(self.ledger),continuation=c,
            previous_authorization_path=str(self.prior_path),previous_authorization_sha256=self.prior_sha,
            child_baseline_checkpoint_sha256=c['predecessor_checkpoint_sha256'])
        self.payload['runtime']=copy.deepcopy(self.runtime);self.payload['runtime']['head']='d'*40
        self.payload['targets']['PR4']['head']='d'*40
        self.runtime=self.payload['runtime'];self.publish(update_child=False)

    def load(self):return gate._load(self.env,self.anchor,self.runtime,self.now,offline=True)

    def activate(self):gate._activate_validated(self.load(),self.env,offline=True)

    def test_exact_history_copied_without_rewriting_predecessor(self):
        before=self.predecessor_path.read_bytes();self.activate();auth=self.load();child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        self.assertEqual(child['requests'],self.frozen_rows);self.assertEqual(self.predecessor_path.read_bytes(),before)
        self.assertEqual(child['requests'][4]['reported_usage'],'UNKNOWN')
        self.assertEqual(child['requests'][4]['usage_accounting'],'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        self.assertEqual(sum(r['cost_reservation_microunits'] for r in child['requests'] if r['provider']=='deepseek'),1600000)
        self.assertEqual(child['requests'][4]['cost_reservation_microunits'],1000000)

    def test_remaining_caps_derived_from_retained_calls(self):
        self.activate();rows=gate._verify_child(self.ledger,self.key.read_bytes(),self.load())['requests']
        self.assertEqual((100-sum(r['provider']=='deepseek' for r in rows),103-sum(r['provider']=='openai' for r in rows),203-len(rows)),(96,102,198))
        self.assertEqual([r['run_id'] for r in rows],['old-run']*5)

    def test_original_unknown_still_blocks_without_disposition(self):
        self.assertTrue(gate._unresolved({},self.frozen_rows[4]))
        auth=self.load();self.assertFalse(gate._unresolved(auth,self.frozen_rows[4]))
        changed=dict(self.frozen_rows[4],request_id='another');self.assertTrue(gate._unresolved(auth,changed))

    def test_wrong_predecessor_hash_or_checkpoint_fails(self):
        for field in ('predecessor_ledger_sha256','predecessor_checkpoint_sha256','requests_sha256','unknown_row_sha256'):
            original=self.payload['continuation'][field];self.payload['continuation'][field]='0'*64;self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload['continuation'][field]=original

    def test_no_zero_or_refund_or_raised_remaining_caps(self):
        for changes in ({'retain_unknown':False},{'refund':1},{'full_reservation_nonrefundable':False},
                        {'remaining_call_limits':{'deepseek':100,'openai':103,'global':203}}):
            original=copy.deepcopy(self.payload['continuation']);self.payload['continuation'].update(changes);self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload['continuation']=original

    def test_history_cannot_be_edited_truncated_or_zeroed_in_new_child(self):
        self.activate();auth=self.load();child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        for mutation in ('zero','refund','truncate','token'):
            changed=copy.deepcopy(child)
            if mutation=='zero':changed['requests'][4]['reported_usage']={'tokens':{k:0 for k in gate.CATEGORIES}}
            if mutation=='refund':changed['requests'][4]['cost_reservation_microunits']=0
            if mutation=='token':changed['requests'][4]['token_reservation']['output']=0
            if mutation=='truncate':changed['requests']=[]
            gate._write_child(self.ledger,changed,self.key.read_bytes())
            with self.assertRaises(ResourceGateDenied):gate._verify_child(self.ledger,self.key.read_bytes(),auth)

    def test_cannot_reset_limits_tokens_cost_attempts_or_clock(self):
        for changes in ({'started_epoch':999},{'expires_epoch':1200},{'max_wall_clock_seconds':200},
                        {'max_new_calls':204},{'shared_max_calls':538}):
            original=copy.deepcopy(self.payload);self.payload.update(changes);self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload=original
        for field in ('token_limit','cost_limit_microunits','max_new_calls'):
            original=copy.deepcopy(self.payload);lane=self.payload['providers']['openai']
            lane[field]={k:9999 for k in gate.CATEGORIES} if field=='token_limit' else lane[field]+1
            self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload=original

    def test_uncovered_or_inflight_predecessor_fails_even_when_resigned(self):
        raw=self.predecessor_path.read_bytes();cp=gate._checkpoint_path(self.predecessor_path);cpraw=cp.read_bytes()
        for change in ({'status':'STARTED'},{'cost_reservation_microunits':0},{'token_reservation':{k:0 for k in gate.CATEGORIES}}):
            child=gate._checked_child(self.predecessor_path,self.key.read_bytes());child['requests'][4].update(change)
            gate._write_child(self.predecessor_path,child,self.key.read_bytes())
            c=self.payload['continuation'];c['predecessor_ledger_sha256']=digest(self.predecessor_path.read_bytes());c['predecessor_checkpoint_sha256']=digest(cp.read_bytes());c['requests_sha256']=digest(canonical(child['requests']));c['unknown_row_sha256']=digest(canonical(child['requests'][4]));self.payload['child_baseline_checkpoint_sha256']=c['predecessor_checkpoint_sha256'];self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.predecessor_path.write_bytes(raw);cp.write_bytes(cpraw)

    def test_new_unknown_or_inflight_always_blocks(self):
        auth=self.load()
        for change in ({'number':6},{'status':'STARTED'},{'usage_accounting':'OVER_RESERVATION_BLOCK_FUTURE_CALLS'}):
            self.assertTrue(gate._unresolved(auth,dict(self.frozen_rows[4],**change)))

    def test_old334_unknown_and_reserve_immutable(self):
        self.activate();self.assertEqual(digest(self.parent.read_bytes()),self.parent_hash)
        rows=json.loads(self.parent.read_bytes())['requests'];self.assertEqual(rows[333]['reported_usage'],'UNKNOWN')
        self.assertEqual(rows[333]['status'],'FAILED');self.assertEqual(rows[333]['cost_reservation_microunits'],400000)

    def test_new_runtime_invalidates_previous_qualification(self):
        prior=dict(self.prior,_authorization_sha256=self.prior_sha);old=gate.qualification_binding(prior)
        with self.assertRaises(ResourceGateDenied):gate.validate_qualification_binding(old,self.load())

    def test_production_cannot_select_arbitrary_five_request_history(self):
        with self.assertRaises(ResourceGateDenied):gate._continuation_predecessor(self.payload,self.prior,self.key.read_bytes())

    def test_future_missing_usage_still_stops_after_one_reserved_call(self):
        self.activate();auth=self.load()
        r=gate._reserve_validated(auth,self.env,'openai','gpt-5.6-sol',b'new fixture','qualification-case',self.now,offline=True)
        r.settle('RETURNED')
        child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        self.assertEqual(child['requests'][:5],self.frozen_rows)
        self.assertEqual(child['requests'][5]['reported_usage'],'UNKNOWN')
        with self.assertRaises(ResourceGateDenied):
            gate._reserve_validated(auth,self.env,'openai','gpt-5.6-sol',b'next fixture','qualification-case',self.now,offline=True)

    def test_inherited_token_and_cost_reservations_consumed_before_send(self):
        self.activate()
        for kind in ('tokens','cost'):
            auth=self.load();lane=auth['providers']['openai']
            if kind=='tokens':lane['token_limit']={k:10 for k in gate.CATEGORIES}
            else:lane['cost_limit_microunits']=1000000
            with self.assertRaises(ResourceGateDenied):
                gate._reserve_validated(auth,self.env,'openai','gpt-5.6-sol',b'fixture','qualification-case',self.now,offline=True)
        self.assertEqual(gate._verify_child(self.ledger,self.key.read_bytes(),self.load())['requests'],self.frozen_rows)

    def test_funding_prefix_preserves_unknown_without_claiming_it_resolved(self):
        self.activate();auth=self.load();child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        child['funding']={'path':'synthetic','sha256':'synthetic','epoch':1}
        value={'epoch':1,'covered_requests':5,'covered_prefix_sha256':digest(canonical(child['requests']))}
        with patch.object(gate,'_snapshot',return_value=value):
            self.assertEqual(gate._current_funds(auth,child,self.key.read_bytes(),self.now),value)
        self.assertEqual(child['requests'][4]['reported_usage'],'UNKNOWN')
        child['requests'].append(dict(child['requests'][4],number=6,request_id='ordinary-unknown'))
        value.update(covered_requests=6,covered_prefix_sha256=digest(canonical(child['requests'])))
        with patch.object(gate,'_snapshot',return_value=value),self.assertRaises(ResourceGateDenied):
            gate._current_funds(auth,child,self.key.read_bytes(),self.now)
