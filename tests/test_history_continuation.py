"""Complete signed multi-generation history; never executes a provider."""
import copy
from unittest.mock import patch
from pathlib import Path
from harness import formal_delivery_gate as gate
from harness.resource_gate import canonical, digest, ResourceGateDenied
import unittest
import test_reserved_unknown_continuation as fixtures


class HistoryContinuationTests(unittest.TestCase):
    write=fixtures.ContinuationTests.write
    publish=fixtures.ContinuationTests.publish
    load=fixtures.ContinuationTests.load
    activate=fixtures.ContinuationTests.activate
    def setUp(self):
        fixtures.ContinuationTests.setUp(self)
        self.activate()
        auth=self.load();child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        for number in range(6,17):
            provider='deepseek' if number<=9 or number>=14 else 'openai'
            row=copy.deepcopy(self.frozen_rows[0 if provider=='deepseek' else 4])
            row.update(number=number,request_id='second-generation-%d'%number,
                       authorization_sha256=auth['_authorization_sha256'],run_id='second-run')
            if number==16:
                row.update(status='FAILED',reported_usage='UNKNOWN',usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
            else:
                row.update(reported_usage={'tokens':{k:1 for k in gate.CATEGORIES}},usage_accounting='FULL_RESERVATION_RETAINED')
            child['requests'].append(row)
        gate._write_child(self.ledger,child,self.key.read_bytes())
        self.second_path=self.ledger;self.second_prior=copy.deepcopy(self.payload)
        self.second_prior_sha=auth['_authorization_sha256']
        self.second_auth_path=self.root/'second-auth.json';self.second_auth_path.write_bytes(self.auth.read_bytes());self.second_auth_path.chmod(0o600)
        self.sixteen=copy.deepcopy(child['requests'])
        c=gate.build_history_continuation(self.second_prior,self.second_prior_sha,self.ledger,self.key.read_bytes())
        self.payload.update(authorization_id='third-generation',continuation=c,
            previous_authorization_path=str(self.second_auth_path),previous_authorization_sha256=self.second_prior_sha,
            child_baseline_checkpoint_sha256=c['predecessor_checkpoint_sha256'])
        self.ledger=self.root/'third-ledger.json';self.env['CMH_RESOURCE_LEDGER']=str(self.ledger);self.payload['ledger_path']=str(self.ledger)
        self.approval=self.root/'third-approval.txt';self.approval.write_text('OFFLINE explicit full history continuation');self.approval.chmod(0o600)
        self.payload.update(user_approval_path=str(self.approval),user_approval_sha256=digest(self.approval.read_bytes()))
        self.payload['runtime']['head']='e'*40;self.payload['targets']['PR4']['head']='e'*40;self.runtime=self.payload['runtime'];self.publish(update_child=False)

    def test_multigeneration_sixteen_calls_exact_history(self):
        self.activate();auth=self.load();rows=gate._verify_child(self.ledger,self.key.read_bytes(),auth)['requests']
        self.assertEqual(rows,self.sixteen)
        self.assertEqual(self.payload['continuation']['consumed_calls'],{'deepseek':11,'openai':5,'global':16})
        self.assertEqual(self.payload['continuation']['remaining_call_limits'],{'deepseek':89,'openai':98,'global':187})
        for i in [4,15]:self.assertFalse(gate._unresolved(auth,rows[i]));self.assertEqual(rows[i]['reported_usage'],'UNKNOWN')
        self.assertTrue(gate._unresolved(auth,dict(rows[15],number=17,request_id='new-unknown')))
        self.assertEqual(gate._history(rows),gate._history(self.sixteen))

    def test_all_history_rewrites_and_unknown_reservation_release_rejected(self):
        self.activate();auth=self.load();original=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        for field,value in [('reported_usage',{'tokens':{k:0 for k in gate.CATEGORIES}}),('cost_reservation_microunits',0),('token_reservation',{k:0 for k in gate.CATEGORIES}),('duration_seconds',0),('run_id','reset')]:
            child=copy.deepcopy(original);child['requests'][15][field]=value;gate._write_child(self.ledger,child,self.key.read_bytes())
            with self.assertRaises(ResourceGateDenied):gate._verify_child(self.ledger,self.key.read_bytes(),auth)

    def test_hash_unknown_manifest_and_remaining_caps_must_match(self):
        for field,value in [('predecessor_ledger_sha256','0'*64),('accounting_sha256','0'*64),('historical_unknowns',[]),('remaining_call_limits',{'deepseek':100,'openai':103,'global':203}),('full_reservation_nonrefundable',False),('refund',1)]:
            original=copy.deepcopy(self.payload);self.payload['continuation'][field]=value;self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload=original

    def test_wrong_direct_authority_and_skipped_predecessor_fail(self):
        for field,value in [('previous_authorization_sha256',self.prior_sha),('previous_authorization_path',str(self.prior_path))]:
            original=copy.deepcopy(self.payload);self.payload[field]=value;self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.payload=original

    def test_re_signed_inflight_unclassified_and_uncovered_unknown_fail(self):
        raw=self.second_path.read_bytes();cp=gate._checkpoint_path(self.second_path);cpraw=cp.read_bytes()
        for change in [{'status':'STARTED'},{'usage_accounting':'FULL_RESERVATION_RETAINED'},{'cost_reservation_microunits':0},{'token_reservation':{k:0 for k in gate.CATEGORIES}}]:
            child=gate._checked_child(self.second_path,self.key.read_bytes());child['requests'][15].update(change);gate._write_child(self.second_path,child,self.key.read_bytes())
            c=gate.build_history_continuation(self.second_prior,self.second_prior_sha,self.second_path,self.key.read_bytes());self.payload['continuation']=c;self.payload['child_baseline_checkpoint_sha256']=c['predecessor_checkpoint_sha256'];self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied):self.load()
            self.second_path.write_bytes(raw);cp.write_bytes(cpraw)

    def test_retained_deepseek_unknown_wallet_reserve_survives_refresh(self):
        self.activate();auth=self.load();child=gate._verify_child(self.ledger,self.key.read_bytes(),auth)
        child['requests'][15]['wallet_exposure_microcny']=30
        # Bind the immutable row with exposure, as a signed predecessor would.
        auth['continuation']['historical_unknowns'][1]['row_sha256']=digest(canonical(child['requests'][15]))
        auth['deepseek_funding_policy']={'currency':'CNY','unit_upper_bound_microcny':{'chunk_or_qualification':100},'safety_margin_microcny':10}
        value={'covered_requests':16,'available_microcny':130,'unsettled_liability_microcny':0,'other_allocations_microcny':0}
        with patch.object(gate,'_current_funds',return_value=value):
            from harness.resource_gate import FundingPause
            with self.assertRaises(FundingPause):gate._funding_check(auth,child,self.key.read_bytes(),'qualification-case',self.now)
