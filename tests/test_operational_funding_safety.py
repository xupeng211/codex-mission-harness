"""Synthetic signed policy and mocked Direct transport; never live accounts."""
import copy
import unittest
from unittest.mock import patch

import test_deepseek_cny_capacity as native
from harness import formal_delivery_gate as gate, deepseek_direct as direct, resource_gate as resources
from harness.resource_gate import ResourceGateDenied, FundingPause


class OperationalFundingTests(unittest.TestCase):
    write = native.NativeCapacityTests.write
    publish = native.NativeCapacityTests.publish
    load = native.NativeCapacityTests.load
    ledger_value = native.NativeCapacityTests.ledger_value
    refresh = native.NativeCapacityTests.refresh
    snapshot = native.NativeCapacityTests.snapshot
    reserve_ds = native.NativeCapacityTests.reserve_ds
    settle = native.NativeCapacityTests.settle

    def setUp(self):
        native.NativeCapacityTests.setUp(self)
        for name in ('provider_no_overdraft', 'no_overdraft_source_path', 'no_overdraft_source_sha256'):
            self.policy.pop(name)
        self.policy['no_overdraft_policy'] = gate.OPERATIONAL_NO_OVERDRAFT
        self.margin = (self.bound * 10 + 99) // 100
        self.policy['safety_margin_microcny'] = self.margin
        self.publish()
        self.refresh(available_microcny=self.bound + self.margin)

    def test_operational_contract_without_absolute_document_and_exact_margin(self):
        auth = self.load()
        self.assertEqual(self.margin, 263716)
        self.assertEqual(self.bound + self.margin, 2900868)
        self.assertNotIn('provider_no_overdraft', auth['deepseek_funding_policy'])
        self.assertNotIn('no_overdraft_source_path', auth['deepseek_funding_policy'])
        self.reserve_ds()
        self.assertEqual(len(self.ledger_value()['requests']), 1)

    def test_missing_or_wrong_margin_and_ambiguous_policy_fail(self):
        original = copy.deepcopy(self.policy)
        for change in ({'safety_margin_microcny': 263715}, {'safety_margin_microcny': 0},
                       {'safety_margin_microcny': 263716.0}, {'no_overdraft_policy': 'guess'},
                       {'provider_no_overdraft': True}):
            self.payload['deepseek_funding_policy'] = dict(original, **change)
            self.publish()
            with self.subTest(change=change), self.assertRaises(ResourceGateDenied):
                self.load()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_stale_balance_blocks_before_send(self):
        self.now = 1090
        with patch.object(direct, '_bounded_post') as send, self.assertRaises(FundingPause):
            self.reserve_ds()
        send.assert_not_called()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_insufficient_balance_blocks_before_send(self):
        self.refresh(available_microcny=self.bound + self.margin - 1)
        with patch.object(direct, '_bounded_post') as send, self.assertRaises(FundingPause) as caught:
            self.reserve_ds()
        self.assertEqual(caught.exception.details['required_microcny'], 2900868)
        send.assert_not_called()
        self.assertEqual(self.ledger_value()['requests'], [])

    def _failed_direct_attempt(self, code):
        before = self.parent.read_bytes()
        effect = None if code == 'HTTP_402' else direct.DirectFailure('TRANSPORT_FAILURE')
        with patch.object(resources, 'reserve', side_effect=lambda **kw: self.reserve_ds()), \
             patch.object(gate, 'require_active_transport'), \
             patch.object(gate, 'require_provider_credential'), \
             patch.object(gate, 'bounded_delivery_timeout', side_effect=lambda value: value), \
             patch.object(direct, '_bounded_post', return_value=(402, b''), side_effect=effect) as send:
            with self.assertRaises(direct.DirectFailure) as caught:
                with resources.model_request(provider='deepseek', model='deepseek-flash',
                    prompt=b'fixture', stage='qualification-case', environment=self.env):
                    direct.invoke('fixture', 'SYNTHETIC-KEY-NOT-REAL', {})
            self.assertEqual(caught.exception.code, code)
            self.assertFalse(caught.exception.retryable)
            send.assert_called_once()
            row = self.ledger_value()['requests'][0]
            self.assertEqual(row['status'], 'FAILED')
            self.assertEqual(row['reported_usage'], 'UNKNOWN')
            self.assertEqual(row['usage_accounting'], 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
            self.assertEqual(row['cost_reservation_microunits'], 400000)
            with self.assertRaises(ResourceGateDenied): self.reserve_ds()
            with self.assertRaises(ResourceGateDenied): self.refresh()
            send.assert_called_once()
        self.assertEqual(before, self.parent.read_bytes())

    def test_402_is_fail_closed_no_retry_and_unknown_retains_reservation(self):
        self._failed_direct_attempt('HTTP_402')

    def test_possibly_sent_transport_failure_blocks_next_send_and_refresh(self):
        self._failed_direct_attempt('TRANSPORT_FAILURE')

    def test_inflight_blocks_next_invocation(self):
        self.reserve_ds()
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()
        self.assertEqual(len(self.ledger_value()['requests']), 1)

    def test_rich_balance_cannot_bypass_mission_call_limit(self):
        self.refresh(available_microcny=10**15)
        before = self.parent.read_bytes()
        for _ in range(self.payload['providers']['deepseek']['max_new_calls']):
            self.settle(self.reserve_ds())
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()
        self.assertEqual(before, self.parent.read_bytes())

    def test_owner_and_liability_facts_never_default_to_true(self):
        original = copy.deepcopy(self.accounts)
        for flag in ('no_unbounded_prior_liability', 'all_prior_activity_included', 'exclusive_allocation'):
            for value in (None, False):
                self.accounts = copy.deepcopy(original)
                self.accounts[flag] = value
                self.publish()
                with self.assertRaises(ResourceGateDenied): self.load()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_snapshot_missing_liability_or_owner_facts_is_rejected(self):
        for changes in ({'exclusive_allocation': None}, {'no_unbounded_prior_liability': False},
                        {'unsettled_liability_microcny': None}, {'settlement_coverage_verified': False}):
            before = self.ledger.read_bytes()
            with self.assertRaises(ResourceGateDenied): self.refresh(**changes)
            self.assertEqual(before, self.ledger.read_bytes())

    def test_single_send_identity_and_no_top_up_policy_cannot_change(self):
        identity = direct.identity()
        self.assertEqual((identity['max_tokens'], identity['http_attempts'], identity['retry']),
                         (90000, 1, 0))
        original = copy.deepcopy(self.policy)
        for change in ({'manual_top_up_only': False},
                       {'direct_transport_identity': dict(identity, retry=1)},
                       {'direct_transport_identity': dict(identity, max_tokens=90001)}):
            self.payload['deepseek_funding_policy'] = dict(original, **change)
            self.publish()
            with self.assertRaises(ResourceGateDenied): self.load()


if __name__ == '__main__': unittest.main()
