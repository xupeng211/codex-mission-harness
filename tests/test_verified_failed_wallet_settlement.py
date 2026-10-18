"""Offline signed native wallet coverage; no historical row rewrite/refund."""
import copy
import json
import unittest
from unittest.mock import patch

import test_deepseek_cny_capacity as native
from harness import formal_delivery_gate as gate, deepseek_direct as direct
from harness.resource_gate import FundingPause, ResourceGateDenied, canonical, digest, sign_authorization


class VerifiedFailedWalletTests(native.NativeCapacityTests):
    # Run the existing native gate regressions as well as this extension.
    def terminal(self, state='FAILED'):
        self.refresh(available_microcny=10*self.bound)
        reservation = self.reserve_ds()
        raw = dict(prompt_tokens=10, prompt_cache_hit_tokens=2, prompt_cache_miss_tokens=8,
                   completion_tokens=5, total_tokens=15,
                   completion_tokens_details={'reasoning_tokens': 3})
        reservation.observe(direct.normalize_usage(raw))
        with patch('harness.resource_gate.time.time', return_value=self.now+1):
            reservation.settle(state)
        return self.ledger_value()['requests'][-1]

    def cover(self, proofs=None, **changes):
        ledger = self.ledger_value(); rows=ledger['requests']
        expected=gate.verified_failed_wallet_settlements(self.load(), rows)
        path=self.root/'settlement-proof.json'
        self.write(path, {'verified_failed_wallet_settlements':expected if proofs is None else proofs})
        return self.refresh(covered_requests=len(rows), covered_prefix_sha256=digest(canonical(rows)),
            settlement_source_path=str(path), settlement_source_sha256=digest(path.read_bytes()), **changes)

    def test_verified_failed_coverage_releases_only_wallet_pending_exposure(self):
        row=self.terminal(); before=canonical(self.ledger_value()['requests'])
        proof=gate.verified_failed_wallet_settlements(self.load(), [row])[0]
        self.assertEqual(proof['actual_usage_cost_upper_microcny'], 60)  # reasoning is not charged twice
        self.refresh(available_microcny=self.bound)
        with self.assertRaises(FundingPause):
            gate._funding_check(self.load(), self.ledger_value(), self.key.read_bytes(),'chunk',self.now)
        self.cover(available_microcny=self.bound)
        gate._funding_check(self.load(), self.ledger_value(),self.key.read_bytes(),'chunk',self.now)
        self.assertEqual(canonical(self.ledger_value()['requests']),before)
        self.assertEqual(self.ledger_value()['requests'][0]['status'],'FAILED')
        self.assertEqual(self.ledger_value()['requests'][0]['cost_reservation_microunits'],row['cost_reservation_microunits'])

    def test_verified_failure_does_not_block_later_success_prefix(self):
        failed=self.terminal(); success=self.terminal('RETURNED')
        self.cover(available_microcny=self.bound)
        gate._funding_check(self.load(),self.ledger_value(),self.key.read_bytes(),'chunk',self.now)
        self.assertEqual(self.ledger_value()['requests'],[failed,success])

    def test_success_coverage_still_works(self):
        row=self.terminal('RETURNED');self.cover(available_microcny=self.bound)
        self.assertEqual(gate.verified_failed_wallet_settlements(self.load(),[row]),[])
        gate._funding_check(self.load(),self.ledger_value(),self.key.read_bytes(),'chunk',self.now)

    def test_unknown_possible_send_cannot_be_covered_or_cost_proved(self):
        reservation=self.reserve_ds()
        with patch('harness.resource_gate.time.time',return_value=self.now+1):reservation.settle('FAILED')
        ledger=self.ledger_value();before=canonical(ledger['requests'])
        with self.assertRaises(ResourceGateDenied):gate.verified_failed_wallet_settlements(self.load(),ledger['requests'])
        with self.assertRaises(ResourceGateDenied):self.cover()
        self.assertEqual(canonical(self.ledger_value()['requests']),before)
        self.assertEqual(ledger['requests'][0]['reported_usage'],'UNKNOWN')

    def test_usage_raw_mismatch_blocks_coverage(self):
        row=self.terminal();row['reported_usage']['tokens']['output']+=1
        with self.assertRaises(ResourceGateDenied):gate.verified_failed_wallet_settlements(self.load(),[row])

    def test_price_identity_mismatch_blocks_coverage(self):
        row=self.terminal();row['native_price_identity_sha256']='0'*64
        with self.assertRaises(ResourceGateDenied):gate.verified_failed_wallet_settlements(self.load(),[row])

    def test_usage_hash_price_and_cost_proof_mismatch_fail(self):
        row=self.terminal();proof=gate.verified_failed_wallet_settlements(self.load(),[row])
        for key,value in (('usage_sha256','0'*64),('row_sha256','0'*64),
                          ('native_price_identity_sha256','0'*64),('actual_usage_cost_upper_microcny',0)):
            bad=copy.deepcopy(proof);bad[0][key]=value
            with self.subTest(key=key),self.assertRaises(ResourceGateDenied):self.cover(bad)

    def test_missing_proof_and_inflight_cannot_settle(self):
        self.terminal()
        with self.assertRaises(ResourceGateDenied):self.cover([])
        ledger=self.ledger_value();row=copy.deepcopy(ledger['requests'][0]);row['status']='STARTED'
        # No terminal failure proof is created for STARTED; prefix validator blocks it.
        self.assertEqual(gate.verified_failed_wallet_settlements(self.load(),[row]),[])
        ledger['requests'][0]=row;self.rewrite(ledger)
        with self.assertRaises(ResourceGateDenied):self.cover()

    def test_tampered_ledger_checkpoint_is_rejected(self):
        self.terminal();value=json.loads(self.ledger.read_text());value['requests'][0]['reported_usage']['tokens']['input']=0
        self.write(self.ledger,value)
        with self.assertRaises(ResourceGateDenied):self.ledger_value()
