"""Isolated signed fixtures only: no production key, account or transport."""
import copy
import json
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import test_formal_delivery_gate as fixture_module
from harness import formal_delivery_gate as gate
from harness.resource_gate import FundingPause, ResourceGateDenied, canonical, digest, sign_authorization


class StagedFundingTests(unittest.TestCase):
    write = fixture_module.FormalDeliveryGateTests.write
    publish = fixture_module.FormalDeliveryGateTests.publish
    load = fixture_module.FormalDeliveryGateTests.load

    def setUp(self):
        fixture_module.FormalDeliveryGateTests.setUp(self)
        self.policy = {'version': gate.STAGED_POLICY, 'execution_unit': 'ONE_PROVIDER_CALL',
                       'manual_top_up_only': True, 'provider_enforced_unit_bound': True,
                       'provider_no_overdraft': True, 'max_snapshot_age_seconds': 200,
                       'safety_margin_microusd': 10000,
                       'unit_upper_bound_microusd': {'chunk_or_qualification': 300000,
                                                   'group_or_cross_group': 350000}}
        for name in ('pricing', 'enforced_bound', 'no_overdraft'):
            self.policy[name + '_source_path'] = str(self.official)
            self.policy[name + '_source_sha256'] = digest(self.official.read_bytes())
        self.payload['deepseek_funding_policy'] = self.policy
        # Historical+future internal envelope deliberately larger than cash.
        self.accounts['accounts']['deepseek']['available_microunits'] = 310000
        self.publish()
        self.snapshot_path = self.root / 'funds.json'
        self.refresh()

    def snapshot(self, **changes):
        ledger = self.ledger_value()
        old = ledger.get('funding')
        value = {'version': gate.FUNDS_VERSION, 'evidence_domain': 'OFFLINE_TEST',
                 'authorization_sha256': self.env['CMH_RESOURCE_AUTH_SHA256'],
                 'parent_ledger_sha256': self.anchor.ledger_sha256,
                 'account_id': self.payload['account_ids']['deepseek'],
                 'credential_identity': self.payload['credential_identities']['deepseek'],
                 'route': 'deepseek-flash', 'unit': 'USD', 'policy_sha256': digest(canonical(self.policy)),
                 'no_unbounded_prior_liability': True, 'historical_settlement_in_net_balance': True,
                 'settlement_coverage_verified': True, 'exclusive_allocation': True, 'epoch': old['epoch'] + 1 if old else 1,
                 'previous_snapshot_sha256': old['sha256'] if old else None,
                 'baseline_checkpoint_sha256': digest(gate._checkpoint_path(self.ledger).read_bytes()),
                 'observed_epoch': 990, 'expires_epoch': 1090,
                 'available_microusd': 310000, 'unsettled_liability_microusd': 0,
                 'other_allocations_microusd': 0, 'covered_requests': 0,
                 'covered_prefix_sha256': digest(canonical([]))}
        for name in ('official', 'conversion', 'settlement'):
            value[name + '_source_path'] = str(self.official)
            value[name + '_source_sha256'] = digest(self.official.read_bytes())
        value.update(changes)
        return value

    def ledger_value(self):
        return gate._checked_child(self.ledger, self.key.read_bytes())

    def refresh(self, **changes):
        value = self.snapshot(**changes)
        path = self.root / ('funds-%s.json' % value['epoch'])
        self.write(path, sign_authorization(value, self.key.read_bytes()))
        gate._refresh_validated(self.load(), self.env, path, digest(path.read_bytes()), self.now, offline=True)
        return path

    def reserve_ds(self, stage='qualification-case'):
        return gate._reserve_validated(self.load(), self.env, 'deepseek', 'deepseek-flash',
                                       b'fixture', stage, self.now, offline=True)

    def settle(self, reservation):
        reservation.observe({'tokens': {k: 0 for k in gate.CATEGORIES}})
        with patch('harness.resource_gate.time.time', return_value=self.now + 1):
            reservation.settle('RETURNED')

    def rewrite(self, value):
        gate._write_child(self.ledger, value, self.key.read_bytes())

    def test_01_unit_fits_while_full_future_cash_does_not(self):
        before = self.parent.read_bytes()
        self.assertGreater(self.load()['providers']['deepseek']['cost_limit_microunits'], 310000)
        reservation = self.reserve_ds()
        self.assertFalse(reservation.execution_allowed)
        row = self.ledger_value()['requests'][0]
        self.assertEqual(row['wallet_exposure_microusd'], 300000)
        self.assertEqual(row['cost_reservation_microunits'], 400000)
        self.assertEqual(self.parent.read_bytes(), before)

    def test_02_insufficient_cash_pauses_without_transport_or_debit(self):
        self.refresh(available_microusd=309999)
        with patch('subprocess.Popen') as spawn, self.assertRaises(FundingPause) as caught:
            self.reserve_ds()
        spawn.assert_not_called()
        ledger = self.ledger_value()
        self.assertEqual(ledger['requests'], [])
        self.assertEqual(ledger['funding_pause']['stage'], 'qualification-case')
        self.assertEqual(caught.exception.details['shortfall_microusd'], 1)

    def test_03_missing_snapshot_rejects(self):
        ledger = self.ledger_value(); ledger.pop('funding'); self.rewrite(ledger)
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_04_expired_snapshot_pauses(self):
        self.now = 1090
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.assertEqual(self.ledger_value()['requests'], [])

    def test_05_wrong_account_rejects(self):
        with self.assertRaises(ResourceGateDenied): self.refresh(account_id='another-account')

    def test_06_unproven_physical_bound_rejects(self):
        self.policy['provider_enforced_unit_bound'] = False; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_07_post_snapshot_charges_are_retained(self):
        self.settle(self.reserve_ds())
        with self.assertRaises(FundingPause) as caught: self.reserve_ds()
        self.assertEqual(caught.exception.details['available_microusd'], 10000)
        self.assertEqual(len(self.ledger_value()['requests']), 1)

    def test_08_parent_history_replacement_rejects(self):
        self.parent.write_bytes(b'{}')
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_09_request334_zero_rejects(self):
        value = json.loads(self.parent.read_bytes()); value['requests'][-1]['reported_usage'] = 'ZERO'
        self.write(self.parent, value)
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_10_old_reserve_loss_rejects(self):
        self.payload['parent']['deepseek_reserved_microusd'] = 0; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_11_settled_prefix_not_debited_twice(self):
        self.settle(self.reserve_ds()); rows = self.ledger_value()['requests']
        self.refresh(covered_requests=1, covered_prefix_sha256=digest(canonical(rows)))
        self.reserve_ds()
        self.assertEqual(len(self.ledger_value()['requests']), 2)
        self.assertEqual(sum(r['cost_reservation_microunits'] for r in rows), 400000)
        self.assertEqual(self.load()['_history']['deepseek']['cost'], 28800000)

    def test_12_unsettled_and_unknown_liability_not_omitted(self):
        self.refresh(unsettled_liability_microusd=1)
        with self.assertRaises(FundingPause): self.reserve_ds()
        for change in ({'unsettled_liability_microusd': 'UNKNOWN'},
                       {'no_unbounded_prior_liability': False}, {'settlement_coverage_verified': False}):
            with self.subTest(change=change), self.assertRaises(ResourceGateDenied): self.refresh(**change)

    def test_13_concurrent_atomic_reservation_cannot_overspend(self):
        def attempt(_):
            try: self.reserve_ds(); return True
            except ResourceGateDenied: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(len(self.ledger_value()['requests']), 1)

    def test_14_mission_calls_and_cost_ceiling_still_stop(self):
        self.settle(self.reserve_ds())
        for field, value in (('max_new_calls', 1), ('cost_limit_microunits', 400000)):
            with self.subTest(field=field):
                saved = copy.deepcopy(self.payload)
                self.payload['providers']['deepseek'][field] = value; self.publish()
                with self.assertRaises(ResourceGateDenied): self.reserve_ds()
                self.payload = saved; self.publish()

    def test_15_each_token_ceiling_still_stops(self):
        self.settle(self.reserve_ds())
        for category in gate.CATEGORIES:
            with self.subTest(category=category):
                self.payload['providers']['deepseek']['token_limit'][category] = 10; self.publish()
                with self.assertRaises(ResourceGateDenied): self.reserve_ds()
                self.payload['providers']['deepseek']['token_limit'][category] = 100; self.publish()

    def test_16_clock_not_reset(self):
        self.payload['max_wall_clock_seconds'] = 50; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_17_pause_checkpoint_persists_highwater_and_identity(self):
        self.settle(self.reserve_ds())
        with self.assertRaises(FundingPause): self.reserve_ds('chunk-001.json')
        ledger = self.ledger_value(); pause = ledger['funding_pause']
        self.assertEqual(pause['request_high_water'], 1)
        self.assertEqual(pause['run_id'], 'offline-run')
        self.assertEqual(pause['authorization_sha256'], self.env['CMH_RESOURCE_AUTH_SHA256'])
        self.assertEqual(pause['stage'], 'chunk-001.json')

    def test_18_refresh_then_atomic_resume(self):
        self.settle(self.reserve_ds())
        with self.assertRaises(FundingPause): self.reserve_ds()
        self.refresh(available_microusd=610000)
        self.assertIn('funding_pause', self.ledger_value())
        self.reserve_ds()
        ledger = self.ledger_value()
        self.assertNotIn('funding_pause', ledger)
        self.assertEqual(ledger['requests'][-1]['funding_epoch'], 2)
        self.assertEqual(ledger['requests'][0]['funding_epoch'], 1)

    def test_19_topup_does_not_unfreeze_unknown(self):
        reservation = self.reserve_ds(); reservation.settle('FAILED')
        with self.assertRaises(ResourceGateDenied): self.refresh(available_microusd=99999999)
        self.assertEqual(self.ledger_value()['requests'][0]['reported_usage'], 'UNKNOWN')

    def test_20_refresh_keeps_counts_debits_clock_and_auth(self):
        self.settle(self.reserve_ds())
        before = copy.deepcopy(self.ledger_value()['requests']); auth = self.auth.read_bytes()
        for balance in (610000, 910000, 1210000): self.refresh(available_microusd=balance)
        self.assertEqual(self.ledger_value()['requests'], before)
        self.assertEqual(self.auth.read_bytes(), auth)
        self.assertEqual(self.load()['started_epoch'], 950)
        self.assertEqual(self.ledger_value()['funding']['epoch'], 4)

    def test_21_qualification_binding_stable_only_on_funds_refresh(self):
        before = gate.qualification_binding(self.load())
        self.refresh(available_microusd=999999)
        self.assertEqual(gate.qualification_binding(self.load()), before)

    def test_22_openai_preflight_durable_pause_reuse(self):
        from harness.review_resume import ReviewRun
        import deepseek_review as storage
        evidence = self.root / 'review'
        identity = {'provider': 'fixture', 'runtime': 'same'}
        stages = [('structured-preflight', 'preflight'), ('chunk-000', 'chunk')]
        calls = []
        def launch(): calls.append('preflight'); return b'{"findings":[]}'
        repo = self.root / 'repo'; repo.mkdir()
        run = ReviewRun(evidence, repo, identity, stages, storage, prefix='fixture-')
        run.stage('structured-preflight', 'preflight', b'fixed', launch, json.loads)
        for _ in range(3): run.failure({'failure_category': 'PAUSED_AWAITING_MANUAL_FUNDING'})
        original = run.path; run.close()
        resumed = ReviewRun(evidence, repo, identity, stages, storage, prefix='fixture-')
        try:
            self.assertEqual(resumed.path, original)
            resumed.stage('structured-preflight', 'preflight', b'fixed', launch, json.loads)
            self.assertEqual(calls, ['preflight'])
            self.assertEqual(resumed.state['failure_count'], 0)
            self.assertEqual(resumed.state['next_stage'], 'chunk-000')
        finally: resumed.close()

    def test_23_execution_identity_drift_still_rejects(self):
        for item in ('head', 'registry_sha256', 'models', 'files'):
            with self.subTest(item=item):
                saved = copy.deepcopy(self.runtime)
                self.runtime[item] = 'drift'
                with self.assertRaises(ResourceGateDenied): self.load()
                self.runtime = saved

    def test_24_cash_never_substitutes_execution_authority(self):
        self.refresh(available_microusd=999999999)
        self.payload['activation_approved'] = False; self.publish()
        with patch('subprocess.Popen') as spawn, self.assertRaises(ResourceGateDenied): self.reserve_ds()
        spawn.assert_not_called()

    def test_25_all_raw_transports_reject_synthetic_reservation(self):
        from harness import resource_gate
        from harness.openai_invocation import _invoke_openai_unmetered
        reservation = self.reserve_ds()
        token = resource_gate._active_reservation.set(reservation)
        try:
            with patch('subprocess.Popen') as spawn, self.assertRaises(ResourceGateDenied):
                gate.require_active_transport('deepseek', 'deepseek-flash')
            spawn.assert_not_called()
            with self.assertRaises(ResourceGateDenied): gate.require_active_transport('openai', 'gpt-5.6-sol')
        finally: resource_gate._active_reservation.reset(token)

    def test_26_funding_fixture_cannot_create_formal_qualification(self):
        with self.assertRaises(ResourceGateDenied): gate.load_authorization(self.env)
        self.assertFalse(any('receipt' in p.name for p in self.root.iterdir()))

    def test_27_replay_inflight_and_unknown_coverage_reject(self):
        old = self.ledger_value()['funding']
        with self.assertRaises(ResourceGateDenied):
            gate._refresh_validated(self.load(), self.env, old['path'], old['sha256'], self.now, offline=True)
        self.reserve_ds()
        with self.assertRaises(ResourceGateDenied): self.refresh(available_microusd=999999)

    def test_28_source_tamper_and_false_settlement_reject(self):
        with self.assertRaises(ResourceGateDenied): self.refresh(covered_requests=1)
        self.official.write_bytes(b'tampered')
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_29_other_allocations_and_margin_count(self):
        self.refresh(available_microusd=410000, other_allocations_microusd=100001)
        with self.assertRaises(FundingPause) as caught: self.reserve_ds()
        self.assertEqual(caught.exception.details['shortfall_microusd'], 1)

    def test_30_refresh_crash_cannot_refund_ledger(self):
        old_write = gate._write_atomic
        def crash(path, value):
            if path == self.ledger: raise OSError('OFFLINE crash')
            old_write(path, value)
        with patch.object(gate, '_write_atomic', side_effect=crash), self.assertRaises(OSError): self.refresh()
        with self.assertRaises(ResourceGateDenied): self.reserve_ds()

    def test_31_qualification_reuses_signed_success_then_only_next_case(self):
        from harness.model_registry import ModelSpec
        from harness.model_qualification import (QualificationEvidence, CASES, _evaluate_cases,
                                                  qualification_prompt)
        from harness.openai_invocation import InvocationResult
        spec = ModelSpec('deepseek', 'deepseek-flash', None)
        self.runtime['models']['deepseek'] = spec.identity()
        self.payload['runtime'] = self.runtime; self.publish()
        # Balance snapshot is bound to the new synthetic authorization hash.
        ledger = self.ledger_value(); ledger.pop('funding'); self.rewrite(ledger); self.refresh()
        evidence = QualificationEvidence(self.root / 'qualification')
        calls = []
        def invoke(actual, prompt):
            calls.append(prompt)
            case = next(c for c in CASES if qualification_prompt(c) == prompt)
            reservation = gate._reserve_validated(self.load(), self.env, actual.provider, actual.model,
                prompt.encode(), 'qualification-case', self.now, offline=True)
            evidence.capture_reservation(case.name, reservation.request_id)
            self.settle(reservation)
            if case.name == 'clean':
                return InvocationResult(json.dumps({'decisions': [], 'findings': [],
                    'summary': 'The clean source has no blockers after exact review.'}),
                    {'resource_request_id': reservation.request_id})
            raise AssertionError('second case must pause before fake transport')
        with patch.dict(os.environ, self.env, clear=True), patch.object(gate, 'load_authorization', side_effect=lambda: self.load()):
            with self.assertRaises(FundingPause): _evaluate_cases(spec, invoke, mode='real_provider', evidence=evidence)
            self.assertEqual(len(self.ledger_value()['qualification_progress']['deepseek/offline-run']['cases']), 1)
            self.refresh(available_microusd=300001)  # still insufficient; retain case 1
            resumed = QualificationEvidence(evidence.directory, resume=True)
            with self.assertRaises(FundingPause): _evaluate_cases(spec, invoke, mode='real_provider', evidence=resumed)
        self.assertEqual(calls.count(qualification_prompt(CASES[0])), 1)
        self.assertEqual(len(self.ledger_value()['requests']), 1)
        self.assertFalse(any('receipt' in p.name for p in evidence.directory.iterdir()))
        from harness.model_qualification import expected_findings, qualification_receipt
        def finish(actual, prompt):
            calls.append(prompt)
            case = next(c for c in CASES if qualification_prompt(c) == prompt)
            reservation = gate._reserve_validated(self.load(), self.env, actual.provider, actual.model,
                prompt.encode(), 'qualification-case', self.now, offline=True)
            resumed.capture_reservation(case.name, reservation.request_id)
            self.settle(reservation)
            decisions = [{'finding_id': finding['finding_id'],
                'decision': case.expected.get('F' + str(i + 1), 'UPHELD'),
                'rationale': 'The exact source directly supports this semantic disposition.',
                'source_quote': 'return a + b' if case.name == 'source_based_dispute' else ''}
                for i, finding in enumerate(expected_findings(case))]
            return InvocationResult(json.dumps({'decisions': decisions, 'findings': [],
                'summary': 'All supplied findings were checked against their exact source.'}),
                {'resource_request_id': reservation.request_id})
        self.refresh(available_microusd=1210000)
        with patch.dict(os.environ, self.env, clear=True), patch.object(gate, 'load_authorization', side_effect=lambda: self.load()):
            result = _evaluate_cases(spec, finish, mode='real_provider', evidence=resumed)
            self.assertEqual(len(result.cases_passed), 4)
            self.assertEqual(result.mode, 'offline_delivery_fixture')
            self.assertFalse(result.passed)
            with self.assertRaises(ValueError): qualification_receipt(result, auth_key='OFFLINE', role='independent_reviewer')
        self.assertEqual(len(self.ledger_value()['requests']), 4)
        self.assertEqual(calls.count(qualification_prompt(CASES[0])), 1)

    def test_32_post_start_expiry_is_not_a_resumable_funding_pause(self):
        from harness import resource_gate
        reservation = self.reserve_ds()
        token = resource_gate._active_reservation.set(reservation)
        try:
            auth = self.load()
            with patch.dict(os.environ, self.env, clear=True), self.assertRaises(ResourceGateDenied) as caught:
                gate._bounded_timeout(auth, 1090, 900)
            self.assertNotIsInstance(caught.exception, FundingPause)
        finally: resource_gate._active_reservation.reset(token)

    def test_33_qualification_artifact_tamper_and_missing_progress_reject(self):
        from harness.model_registry import ModelSpec
        from harness.model_qualification import QualificationEvidence
        spec = ModelSpec('deepseek', 'deepseek-flash', None)
        self.runtime['models']['deepseek'] = spec.identity(); self.payload['runtime'] = self.runtime
        self.publish(); ledger = self.ledger_value(); ledger.pop('funding'); self.rewrite(ledger); self.refresh()
        evidence = QualificationEvidence(self.root / 'qualification')
        self.settle(self.reserve_ds())
        with patch.dict(os.environ, self.env, clear=True), patch.object(gate, 'load_authorization', side_effect=lambda: self.load()):
            with self.assertRaises(ResourceGateDenied): evidence.delivery_progress(spec)

    def test_34_bound_breach_freezes_before_new_request(self):
        reservation = self.reserve_ds()
        ledger = self.ledger_value()
        ledger['requests'][0]['price_microusd_per_million'] = {
            'input_cache_miss': 310001000000, 'output': 0, 'cache_hit': 0}
        self.rewrite(ledger)
        reservation.observe({'tokens': {'input': 1, 'cache': 0, 'output': 0, 'reasoning': 0},
                             'cache_read_tokens': 0, 'cache_creation_tokens': 0,
                             'cli_reported_cost_microunits': 310001})
        reservation.settle('RETURNED')
        self.assertEqual(self.ledger_value()['requests'][0]['usage_accounting'],
                         'OVER_RESERVATION_BLOCK_FUTURE_CALLS')
        with self.assertRaises(ResourceGateDenied): self.refresh(available_microusd=999999)
