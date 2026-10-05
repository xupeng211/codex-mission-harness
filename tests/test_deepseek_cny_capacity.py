"""Synthetic signed native-CNY snapshots; no wallet, keys or Provider access."""
import copy
import json
import unittest
from unittest.mock import patch

import test_formal_delivery_gate as fixture
import test_staged_funding as staged
from harness import formal_delivery_gate as gate, deepseek_direct as direct
from harness.resource_gate import FundingPause, ResourceGateDenied, canonical, digest


class NativeCapacityTests(unittest.TestCase):
    write = fixture.FormalDeliveryGateTests.write
    publish = fixture.FormalDeliveryGateTests.publish
    load = fixture.FormalDeliveryGateTests.load
    ledger_value = staged.StagedFundingTests.ledger_value
    refresh = staged.StagedFundingTests.refresh
    reserve_ds = staged.StagedFundingTests.reserve_ds
    settle = staged.StagedFundingTests.settle
    rewrite = staged.StagedFundingTests.rewrite

    def setUp(self):
        fixture.FormalDeliveryGateTests.setUp(self)
        # Synthetic rates, NOT current official pricing or a live authorization.
        self.policy = dict(version=gate.STAGED_POLICY, currency='CNY',
            execution_unit='ONE_PROVIDER_CALL', manual_top_up_only=True,
            provider_enforced_unit_bound=True, provider_no_overdraft=True,
            max_snapshot_age_seconds=200, safety_margin_microcny=0,
            native_price=dict(provider='deepseek', currency='CNY', model=direct.MODEL,
                input_cache_miss_microcny_per_million=2000000,
                output_microcny_per_million=8000000), direct_transport_identity=direct.identity())
        self.bound = gate._native_cny_bound(self.policy)
        self.policy['unit_upper_bound_microcny'] = dict(chunk_or_qualification=self.bound,
                                                      group_or_cross_group=self.bound)
        for name in ('pricing', 'enforced_bound', 'no_overdraft'):
            self.policy[name + '_source_path'] = str(self.official)
            self.policy[name + '_source_sha256'] = digest(self.official.read_bytes())
        self.payload['deepseek_funding_policy'] = self.policy
        self.accounts['accounts']['deepseek']['available_microunits'] = 1
        self.publish()
        self.refresh()

    def snapshot(self, **changes):
        value = staged.StagedFundingTests.snapshot(self)
        for name in ('available', 'unsettled_liability', 'other_allocations'):
            value[name + '_microcny'] = value.pop(name + '_microusd')
        value.update(provider='deepseek', unit='CNY', amount_semantics='CURRENT_AVAILABLE_NET_BALANCE',
                     available_microcny=self.bound)
        for key in ('conversion_source_path', 'conversion_source_sha256'):
            value.pop(key)
        value.update(changes)
        return value

    def test_native_bound_and_single_execution_unit_not_full_mission(self):
        self.assertEqual(self.bound, 2637152)
        from harness.model_qualification import CASES
        self.assertEqual(len(CASES), 4)
        self.assertEqual(4 * self.bound, 10548608)
        # Equality admits one unit, despite cash < four cases and 100 calls.
        row = self.ledger_value()
        reservation = self.reserve_ds()
        self.assertFalse(reservation.execution_allowed)
        record = self.ledger_value()['requests'][0]
        self.assertEqual(record['wallet_currency'], 'CNY')
        self.assertEqual(record['wallet_exposure_microcny'], self.bound)
        self.assertNotIn('wallet_exposure_microusd', record)
        self.assertEqual(record['cost_unit'], 'USD')
        self.assertEqual(record['cost_reservation_microunits'], 400000)
        self.assertEqual(row['requests'], [])

    def test_sufficient_and_exact_boundary(self):
        for amount in (self.bound, self.bound + 1):
            self.refresh(available_microcny=amount)
            funds = gate._funding_check(self.load(), self.ledger_value(), self.key.read_bytes(),
                                        'aggregate.json', self.now)
            self.assertEqual(funds['_unit_exposure'], self.bound)

    def test_insufficient_pauses_before_any_send_or_attempt(self):
        self.refresh(available_microcny=self.bound - 1)
        before = self.ledger_value()['requests']
        with patch.object(direct, '_bounded_post') as send, self.assertRaises(FundingPause) as caught:
            self.reserve_ds()
        send.assert_not_called()
        self.assertEqual(self.ledger_value()['requests'], before)
        self.assertEqual(caught.exception.details['currency'], 'CNY')
        self.assertEqual(caught.exception.details['shortfall_microcny'], 1)
        self.assertNotIn('required_microusd', caught.exception.details)

    def test_wrong_currency_provider_and_ambiguous_amount(self):
        for change in ({'unit': 'USD'}, {'unit': None}, {'provider': 'openai'},
                       {'available_microusd': 999999999}, {'conversion_source_sha256': '0' * 64},
                       {'amount_semantics': 'GROSS_BALANCE'}):
            with self.subTest(change=change), self.assertRaises(ResourceGateDenied):
                self.refresh(**change)

    def test_malformed_amounts(self):
        for amount in (-1, True, float('nan'), float('inf'), 1.5, '2.637152', None):
            with self.subTest(amount=amount), self.assertRaises(ResourceGateDenied):
                self.refresh(available_microcny=amount)

    def test_stale_missing_and_changed_official_evidence(self):
        self.now = 1090
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.now = 1000
        ledger = self.ledger_value(); ledger.pop('funding'); self.rewrite(ledger)
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.assertEqual(self.ledger_value()['requests'], [])
        self.official.write_bytes(b'changed pricing/capacity evidence')
        with self.assertRaises(ResourceGateDenied): self.refresh()

    def test_old_balance_never_automatically_authorizes(self):
        with self.assertRaises(FundingPause):
            self.refresh(available_microcny=27180000, observed_epoch=1, expires_epoch=100)
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_settled_history_not_deducted_twice(self):
        parent = self.parent.read_bytes()
        self.settle(self.reserve_ds()); rows = self.ledger_value()['requests']
        self.refresh(covered_requests=1, covered_prefix_sha256=digest(canonical(rows)))
        self.reserve_ds()  # Fresh net balance is exactly one bound, no historical deduction.
        self.assertEqual(self.parent.read_bytes(), parent)
        self.assertEqual(self.load()['_history']['deepseek']['cost'], 28800000)
        self.assertEqual(len(self.ledger_value()['requests']), 2)

    def test_topup_refresh_preserves_counters_clock_and_qualification(self):
        self.settle(self.reserve_ds())
        auth = self.load(); binding = gate.qualification_binding(auth)
        before = self.ledger_value()
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.refresh(available_microcny=2 * self.bound)
        after = self.ledger_value()
        self.assertEqual(before['requests'], after['requests'])
        for key in ('started_epoch', 'authorization_sha256', 'parent_ledger_sha256'):
            self.assertEqual(before.get(key), after.get(key))
        self.assertEqual(binding, gate.qualification_binding(self.load()))
        self.reserve_ds()
        self.assertEqual(len(self.ledger_value()['requests']), 2)

    def test_unknown_not_cleared_by_refresh(self):
        reservation = self.reserve_ds(); reservation.settle('FAILED')
        before = self.ledger.read_bytes()
        with self.assertRaises(ResourceGateDenied): self.refresh(available_microcny=999999999)
        self.assertEqual(self.ledger.read_bytes(), before)
        self.assertEqual(self.ledger_value()['requests'][0]['reported_usage'], 'UNKNOWN')

    def test_price_and_transport_identity_change_reject_old_snapshot(self):
        old = self.ledger_value()['funding']
        for field in ('native_price', 'direct_transport_identity'):
            auth = copy.deepcopy(self.load())
            auth['deepseek_funding_policy'][field]['model'] = 'changed-model'
            with self.assertRaises(ResourceGateDenied):
                gate._snapshot(auth, old['path'], old['sha256'], self.key.read_bytes(), self.now)
        policy = copy.deepcopy(self.policy)
        policy['native_price']['output_microcny_per_million'] += 1
        auth = copy.deepcopy(self.load()); auth['deepseek_funding_policy'] = policy
        with self.assertRaises(ResourceGateDenied):
            gate._snapshot(auth, old['path'], old['sha256'], self.key.read_bytes(), self.now)
        auth = copy.deepcopy(self.load()); auth['runtime']['models']['deepseek']['model'] = 'changed-model'
        self.assertNotEqual(gate.qualification_binding(auth), gate.qualification_binding(self.load()))

    def test_invalid_or_lower_bound_and_fx_policy_rejected(self):
        for change in ({'currency': 'EUR'}, {'unit_upper_bound_microcny': dict(
                chunk_or_qualification=self.bound - 1, group_or_cross_group=self.bound)},
                {'safety_margin_microusd': 0}):
            auth = copy.deepcopy(self.load()); auth['deepseek_funding_policy'].update(change)
            with self.assertRaises(ResourceGateDenied): gate._validate_funding_policy(auth)
        auth = copy.deepcopy(self.load())
        auth['deepseek_funding_policy']['native_price']['output_microcny_per_million'] = float('inf')
        with self.assertRaises(ResourceGateDenied): gate._validate_funding_policy(auth)

    def test_native_rounds_up_without_cache_discount_or_reasoning_addition(self):
        policy = copy.deepcopy(self.policy)
        policy['native_price'].update(input_cache_miss_microcny_per_million=1,
                                      output_microcny_per_million=2)
        self.assertEqual(gate._native_cny_bound(policy), 2)

    def test_rich_wallet_cannot_raise_calls_cost_tokens_or_wallclock(self):
        self.refresh(available_microcny=999999999999)
        self.settle(self.reserve_ds())
        original = copy.deepcopy(self.payload)
        for field, value in (('max_new_calls', 1), ('cost_limit_microunits', 400000),
                             ('token_limit', {k: 1 for k in gate.CATEGORIES})):
            self.payload['providers']['deepseek'][field] = value; self.publish()
            with self.subTest(field=field), self.assertRaises(ResourceGateDenied): self.reserve_ds()
            self.payload = copy.deepcopy(original); self.publish()
        self.now = self.payload['expires_epoch']
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_native_snapshot_replay_and_suffix_currency_fail_closed(self):
        entry = self.ledger_value()['funding']
        with self.assertRaises(ResourceGateDenied):
            gate._refresh_validated(self.load(), self.env, entry['path'], entry['sha256'], self.now, offline=True)
        self.settle(self.reserve_ds())
        ledger = self.ledger_value(); ledger['requests'][0].pop('wallet_exposure_microcny'); self.rewrite(ledger)
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_formal_transport_rejects_missing_or_legacy_usd_capacity(self):
        from types import SimpleNamespace
        from harness.resource_gate import _active_reservation
        import os
        active = SimpleNamespace(provider='deepseek', model=direct.MODEL, execution_allowed=True)
        token = _active_reservation.set(active)
        try:
            for policy in (None, {'currency': 'USD'}):
                auth = {'deepseek_funding_policy': policy}
                with patch.dict(os.environ, {'CMH_RESOURCE_MISSION_ID': gate.NEW_MISSION}), \
                     patch.object(gate, 'load_authorization', return_value=auth), \
                     self.assertRaises(ResourceGateDenied):
                    gate.require_active_transport('deepseek', direct.MODEL)
        finally:
            _active_reservation.reset(token)

    def test_public_adapter_cannot_send_when_native_capacity_insufficient(self):
        from harness import resource_gate as resources
        self.refresh(available_microcny=self.bound - 1)
        with patch.object(resources, 'reserve', side_effect=lambda **kw: self.reserve_ds(kw['stage'])), \
             patch.object(direct, '_bounded_post') as send:
            with self.assertRaises(FundingPause):
                direct.invoke('synthetic prompt', 'OFFLINE-FAKE-KEY', {'type': 'object'})
            send.assert_not_called()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_native_qualification_pause_resume_reuses_completed_case(self):
        from harness.model_registry import ModelSpec
        from harness.model_qualification import (QualificationEvidence, CASES, _evaluate_cases,
            qualification_prompt, expected_findings, _SCHEMA)
        from harness.openai_invocation import InvocationResult
        from direct_deepseek_fixture import envelope
        spec = ModelSpec('deepseek', direct.MODEL, None)
        self.runtime['models']['deepseek'] = spec.identity()
        self.payload['runtime'] = self.runtime; self.publish()
        ledger = self.ledger_value(); ledger.pop('funding'); self.rewrite(ledger); self.refresh()
        evidence = QualificationEvidence(self.root / 'native-qualification')
        calls = []
        def invoke(actual, prompt):
            case = next(c for c in CASES if qualification_prompt(c) == prompt)
            reservation = gate._reserve_validated(self.load(), self.env, actual.provider, actual.model,
                prompt.encode(), 'qualification-case', self.now, offline=True)
            evidence.capture_reservation(case.name, reservation.request_id)
            calls.append(case.name)
            self.settle(reservation)
            decisions = [{'finding_id': finding['finding_id'],
                'decision': case.expected.get('F' + str(i + 1), 'UPHELD'),
                'rationale': 'The exact source directly supports this semantic disposition.',
                'source_quote': 'return a + b' if case.name == 'source_based_dispute' else ''}
                for i, finding in enumerate(expected_findings(case))]
            return InvocationResult(envelope({'decisions': decisions, 'findings': [],
                'summary': 'Synthetic case checked against its exact source.'}, prompt, _SCHEMA).decode(),
                {'resource_request_id': reservation.request_id})
        import os
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(gate, 'load_authorization', side_effect=lambda: self.load()):
            with self.assertRaises(FundingPause):
                _evaluate_cases(spec, invoke, mode='real_provider', evidence=evidence)
            before = self.ledger_value()['requests']
            self.assertEqual(calls, ['clean'])
            self.refresh(available_microcny=4 * self.bound)
            self.assertEqual(self.ledger_value()['requests'], before)
            evidence = QualificationEvidence(evidence.directory, resume=True)
            result = _evaluate_cases(spec, invoke, mode='real_provider', evidence=evidence)
            self.assertEqual(len(result.cases_passed), 4)
            self.assertEqual(result.mode, "offline_delivery_fixture")
            self.assertFalse(result.passed)  # Synthetic authority cannot qualify production.
        self.assertEqual(calls, [case.name for case in CASES])
        self.assertEqual(len(self.ledger_value()['requests']), 4)


if __name__ == '__main__':
    unittest.main()
