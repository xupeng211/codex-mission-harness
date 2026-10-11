"""Synthetic fresh approval/ledger lifecycle; zero Provider credentials or calls."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from harness import formal_delivery_gate as gate, fresh_task as fresh
from harness.resource_gate import ResourceGateDenied, canonical, digest, sign_authorization
import test_historical_diagnostic_continuation as history


class FreshTaskTests(unittest.TestCase):
    write = history.HistoricalDiagnosticContinuationTests.write
    publish = history.HistoricalDiagnosticContinuationTests.publish
    load = history.HistoricalDiagnosticContinuationTests.load
    activate = history.HistoricalDiagnosticContinuationTests.activate
    rebind = history.HistoricalDiagnosticContinuationTests.rebind

    def setUp(self):
        history.HistoricalDiagnosticContinuationTests.setUp(self)
        self.old_bytes = self.predecessor.read_bytes()
        self.old_checkpoint = gate._read(gate._checkpoint_path(self.predecessor))
        self.old_authority_path = Path(self.reader['previous_authorization_path'])
        self.old_authority_bytes = self.old_authority_path.read_bytes()
        self.now = 1200
        self.addCleanup(patch.stopall)
        patch.object(fresh, 'TASK_ROOT', self.root).start()
        prior = copy.deepcopy(self.payload)
        for field in ('continuation', 'previous_authorization_path', 'previous_authorization_sha256',
                      'child_baseline_checkpoint_sha256'):
            prior.pop(field, None)
        self.runtime = copy.deepcopy(prior['runtime'])
        self.runtime['models'] = {'deepseek': {'provider': 'deepseek', 'model': 'deepseek-flash', 'reasoning_effort': None},
                                 'openai': {'provider': 'openai', 'model': 'gpt-5.6-sol', 'reasoning_effort': 'high'}}
        scope, manifest = fresh.build_scope(Path(gate.__file__).resolve().parents[2], self.runtime)
        disposition = gate.build_history_continuation(self.prior, self.reader['previous_authorization_sha256'],
                                                      self.predecessor, self.key.read_bytes())
        request_plan = fresh.build_request_plan(scope, manifest)
        prior.update(scope=['PR2'], targets={'PR2': {'base': fresh.TARGET_BASE, 'head': fresh.TARGET_HEAD}},
                     runtime=self.runtime, started_epoch=1200, expires_epoch=1350, max_wall_clock_seconds=150,
                     approved_at_epoch=1199, max_new_calls=14, shared_max_calls=1000,
                     authorization_id='OFFLINE_FRESH_ONLY',
                     fresh_task=dict(version=fresh.VERSION, history_authorization_path=str(self.old_authority_path),
                         history=disposition, scope=scope, request_plan=request_plan,
                         overlapping_target_approved=True, budget_microcny=18730000))
        for p, lane in prior['providers'].items():
            lane.update(max_new_calls=7, cost_limit_microunits=7 * lane['cost_reservation_microunits'])
            lane['token_reservation'] = ({'input': 64000, 'cache': 64000, 'output': 128000, 'reasoning': 128000}
                                        if p == 'deepseek' else {'input': 400000, 'cache': 400000, 'output': 128000, 'reasoning': 128000})
            if p == 'deepseek':
                lane['stage_token_reservation'] = {'chunk_or_qualification': lane['token_reservation'],
                    'group_or_cross_group': {'input': 64000, 'cache': 192000, 'output': 192000, 'reasoning': 128000}}
            from harness.resource_gate import _stage_reservation
            lane['token_limit'] = {k: sum(_stage_reservation(lane, p, s['stage'])[k]
                for s in request_plan['providers'][p]) for k in gate.CATEGORIES}
            prior['shared_token_limits'][p] = dict.fromkeys(gate.CATEGORIES, 100000000)
            self.accounts['accounts'][p]['available_microunits'] = 1000000000
            prior['shared_cost_limits'][p] = 1000000000
        self.payload = prior
        self.accounts.update(observed_epoch=1199, expires_epoch=1350,
                             fresh_history_sha256=disposition['predecessor_ledger_sha256'])
        self.approval = self.root / 'fresh-user-approval.json'
        self.auth = self.root / 'fresh-auth.json'
        self.ledger = fresh.task_ledger_path(disposition)
        self.payload['ledger_path'] = str(self.ledger)
        self.env.update(CMH_RESOURCE_AUTHORIZATION=str(self.auth), CMH_RESOURCE_LEDGER=str(self.ledger))
        self.approve()

    def approve(self):
        self.write(self.account_path, sign_authorization(self.accounts, self.key.read_bytes()))
        self.payload['account_evidence_sha256'] = digest(self.account_path.read_bytes())
        successor = fresh.is_successor(self.payload)
        self.write(self.approval, dict(version=fresh.SUCCESSOR_APPROVAL_VERSION if successor else fresh.APPROVAL_VERSION, evidence_domain='OFFLINE_TEST',
                  explicit_paid_execution_approval=True, payload=fresh.approval_payload(self.payload)))
        sha = digest(self.approval.read_bytes())
        self.payload.update(user_approval_path=str(self.approval), user_approval_sha256=sha,
                            mission_id=(fresh.SUCCESSOR_PREFIX if successor else fresh.PREFIX) + sha,
                            execution_id=digest((b'cmh-successor-execution/v1/' if successor else b'cmh-fresh-execution/v1/') + sha.encode()))
        self.env['CMH_RESOURCE_MISSION_ID'] = self.payload['mission_id']
        self.write_auth()

    def write_auth(self):
        self.write(self.auth, sign_authorization(self.payload, self.key.read_bytes()))
        self.env['CMH_RESOURCE_AUTH_SHA256'] = digest(self.auth.read_bytes())

    def reserve_stage(self, provider, stage, prompt):
        auth = self.load()
        token = gate._review_context.set(dict(target='PR2', provider=provider,
                                             binding=gate.qualification_binding(auth)))
        try:
            return gate._reserve_validated(auth, self.env, provider, self.runtime['models'][provider]['model'],
                                           prompt, stage, self.now, offline=True)
        finally:
            gate._review_context.reset(token)

    def settle(self, reservation, *, known=True, status='RETURNED'):
        if known:
            reservation.observe({'tokens': dict.fromkeys(gate.CATEGORIES, 0)})
        reservation.settle(status)

    def complete_gpt(self):
        from harness.model_qualification import CASES, qualification_prompt
        for c in CASES:
            self.settle(self.reserve_stage('openai', 'qualification-case', qualification_prompt(c).encode()))
        for s in ['structured-preflight', 'chunk-000', 'group-000']:
            self.settle(self.reserve_stage('openai', s, b'offline-fixture'))

    def test_01_old_authority_expired_and_clock_unchanged(self):
        env = dict(self.env, CMH_RESOURCE_AUTHORIZATION=str(self.old_authority_path),
                   CMH_RESOURCE_AUTH_SHA256=digest(self.old_authority_bytes),
                   CMH_RESOURCE_MISSION_ID=gate.NEW_MISSION, CMH_RESOURCE_LEDGER=str(self.predecessor))
        with self.assertRaisesRegex(ResourceGateDenied, 'time or validity'):
            gate._load(env, self.anchor, self.prior['runtime'], self.now, offline=True)
        self.assertEqual(self.old_authority_path.read_bytes(), self.old_authority_bytes)

    def test_05_06_original_history_and_unknowns_unchanged(self):
        auth = self.load(); self.activate()
        self.assertEqual(len(auth['_fresh_history']['requests']), 120)
        self.assertEqual(len(auth['fresh_task']['history']['historical_unknowns']), 8)
        self.assertEqual(self.predecessor.read_bytes(), self.old_bytes)
        self.assertEqual(gate._read(gate._checkpoint_path(self.predecessor)), self.old_checkpoint)
        self.assertEqual(gate._verify_child(self.ledger, self.key.read_bytes(), auth)['requests'], [])
        self.assertEqual(auth['_history']['global_calls'], 454)

    def test_08_missing_or_unapproved_user_evidence_rejected(self):
        for mode in ('missing', 'unapproved', 'changed'):
            self.approve()
            if mode == 'missing': self.approval.unlink()
            else:
                obj = json.loads(self.approval.read_bytes())
                if mode == 'unapproved': obj['explicit_paid_execution_approval'] = False
                else: obj['payload']['max_new_calls'] = 15
                self.write(self.approval, obj)
                self.payload['user_approval_sha256'] = digest(self.approval.read_bytes()); self.write_auth()
            with self.subTest(mode=mode), self.assertRaises(ResourceGateDenied): self.load()

    def test_09_new_independent_candidate_accepted(self):
        auth = self.load(); self.activate()
        self.assertNotEqual(auth['mission_id'], gate.NEW_MISSION)
        self.assertEqual(gate._verify_child(self.ledger, self.key.read_bytes(), auth)['mission_id'], auth['mission_id'])
        self.assertEqual(auth['max_new_calls'], 14)
        from harness.model_qualification import CASES, qualification_prompt
        self.assertFalse(self.reserve_stage('openai', 'qualification-case',
                         qualification_prompt(CASES[0]).encode()).execution_allowed)

    def test_10_11_exact_target_scope_plan_rejected_on_drift(self):
        original = copy.deepcopy(self.payload)
        for field in ('head', 'tree', 'scope', 'manifest', 'plan'):
            self.payload = copy.deepcopy(original)
            if field == 'head': self.payload['targets']['PR2']['head'] = '0' * 40
            elif field == 'tree': self.payload['fresh_task']['scope']['tree'] = '0' * 40
            elif field == 'scope': self.payload['fresh_task']['scope']['diff_sha256'] = '0' * 64
            elif field == 'manifest': self.payload['fresh_task']['scope']['manifest_sha256'] = '0' * 64
            else: self.payload['fresh_task']['request_plan']['maximum_calls']['openai'] = 8
            self.approve()
            with self.subTest(field=field), self.assertRaises(ResourceGateDenied): self.load()

    def test_12_model_provider_runtime_identity(self):
        original = copy.deepcopy(self.payload)
        for field in ('model', 'provider', 'effort', 'runtime'):
            self.payload = copy.deepcopy(original)
            if field == 'model': self.payload['runtime']['models']['openai']['model'] = 'gpt-6-astra'
            elif field == 'provider': self.payload['runtime']['models']['openai']['provider'] = 'deepseek'
            elif field == 'effort': self.payload['runtime']['models']['openai']['reasoning_effort'] = 'low'
            else: self.payload['runtime']['registry_sha256'] = '0' * 64
            self.approve()
            with self.subTest(field=field), self.assertRaises(ResourceGateDenied): self.load()

    def test_13_budget_validity_and_overlap_limits(self):
        original = copy.deepcopy(self.payload)
        for change in ('calls', 'tokens', 'cost', 'expiry', 'wall', 'overlap', 'native_budget'):
            self.payload = copy.deepcopy(original)
            if change == 'calls': self.payload['providers']['openai']['max_new_calls'] = 8
            elif change == 'tokens': self.payload['providers']['openai']['token_limit']['output'] += 1
            elif change == 'cost': self.payload['providers']['openai']['cost_limit_microunits'] += 1
            elif change == 'expiry': self.payload['expires_epoch'] = 1351
            elif change == 'wall': self.payload['max_wall_clock_seconds'] = 151
            elif change == 'overlap': self.payload['fresh_task']['overlapping_target_approved'] = False
            else: self.payload['fresh_task']['budget_microcny'] = 0
            self.approve()
            with self.subTest(change=change), self.assertRaises(ResourceGateDenied): self.load()

    def test_14_slots_are_ordered_bounded_and_no_old_replay(self):
        from harness.model_qualification import CASES, qualification_prompt
        self.activate()
        with self.assertRaises(ResourceGateDenied): self.reserve_stage('openai', 'group-000', b'old-request')
        self.complete_gpt()
        with self.assertRaises(ResourceGateDenied):
            self.reserve_stage('openai', 'qualification-case', qualification_prompt(CASES[0]).encode())
        self.assertEqual(len(gate._checked_child(self.ledger, self.key.read_bytes())['requests']), 7)

    def test_15_23_same_approval_or_new_name_cannot_fork_or_reset(self):
        self.activate(); before = self.ledger.read_bytes()
        with self.assertRaises(ResourceGateDenied): self.activate()
        self.payload['authorization_id'] = 'SECOND_OFFLINE_APPROVAL'; self.approve()
        with self.assertRaises(ResourceGateDenied): self.activate()
        self.assertEqual(self.ledger.read_bytes(), before)
        self.payload['ledger_path'] = str(self.root / 'empty-reset.json'); self.approve()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_16_expiry_checked_at_reservation(self):
        auth = self.load(); self.activate()
        with self.assertRaises(ResourceGateDenied):
            gate._reserve_validated(auth, self.env, 'openai', 'gpt-5.6-sol', b'fixture',
                                    'qualification-case', 1350, offline=True)

    def test_17_new_unknown_or_fail_blocks_all_progress(self):
        from harness.model_qualification import CASES, qualification_prompt
        self.activate()
        r = self.reserve_stage('openai', 'qualification-case', qualification_prompt(CASES[0]).encode())
        self.settle(r, known=False, status='FAILED')
        self.assertEqual(gate._checked_child(self.ledger, self.key.read_bytes())['requests'][0]['reported_usage'], 'UNKNOWN')
        with self.assertRaises(ResourceGateDenied):
            self.reserve_stage('openai', 'qualification-case', qualification_prompt(CASES[0]).encode())

    def test_18_diagnostic_and_history_rewrite_rejected(self):
        original = copy.deepcopy(self.payload)
        for mutation in ('diagnostic', 'history_hash', 'unknown', 'refund'):
            self.payload = copy.deepcopy(original)
            if mutation == 'diagnostic': self.payload['diagnostic_probe'] = {'model': 'gpt-6-astra'}
            elif mutation == 'history_hash': self.payload['fresh_task']['history']['predecessor_ledger_sha256'] = '0' * 64
            elif mutation == 'unknown': self.payload['fresh_task']['history']['historical_unknowns'] = []
            else: self.payload['fresh_task']['history']['refund'] = 1
            self.approve()
            with self.subTest(mutation=mutation), self.assertRaises(ResourceGateDenied): self.load()
        self.assertEqual(self.predecessor.read_bytes(), self.old_bytes)

    def test_19_old_qualification_never_inherited(self):
        auth = self.load()
        simulated_formal = dict(auth, evidence_domain='FORMAL')
        with self.assertRaisesRegex(ResourceGateDenied, 'cannot inherit old qualification'):
            gate.validate_qualification_binding(gate.qualification_binding(dict(auth, mission_id=gate.NEW_MISSION)), simulated_formal)
        gate.validate_qualification_binding(gate.qualification_binding(auth), simulated_formal)
        with self.assertRaisesRegex(ResourceGateDenied, 'synthetic qualification'):
            gate.validate_qualification_binding(gate.qualification_binding(auth), auth)

    def test_24_unsigned_offline_never_enters_formal_sender(self):
        self.activate()
        with self.assertRaises(ResourceGateDenied): gate.load_authorization(self.env)
        self.payload['mission_id'] = gate.NEW_MISSION; self.write_auth()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_transport_requires_exact_prompt_and_durable_single_send(self):
        from harness.model_qualification import CASES, qualification_prompt
        self.activate(); prompt = qualification_prompt(CASES[0]).encode()
        r = self.reserve_stage('openai', 'qualification-case', prompt)
        auth = self.load()
        with patch.object(gate, 'load_authorization', return_value=auth):
            with self.assertRaises(ResourceGateDenied): fresh.claim_transport(auth, r, b'wrong prompt')
            fresh.claim_transport(auth, r, prompt)
            with self.assertRaises(ResourceGateDenied): fresh.claim_transport(auth, r, prompt)

    def test_21_authority_cannot_be_borrowed_by_another_fresh_mission(self):
        from harness.artifact_lineage import authority_matches
        from harness.reviewer_v2_contract import contract_authorization_identity
        self.activate(); auth = self.load()
        with patch.object(gate, 'load_authorization', return_value=auth), patch.dict('os.environ', self.env):
            self.assertTrue(authority_matches(auth['_authorization_sha256'], auth['mission_id']))
            other = fresh.PREFIX + '0' * 64
            with self.assertRaises(ValueError): authority_matches(auth['_authorization_sha256'], other)
            with self.assertRaises(ValueError): contract_authorization_identity(other)

    def test_qualification_cli_uses_the_new_deterministic_diagnostics_namespace(self):
        auth = self.load()
        for provider in ("openai", "deepseek"):
            output = fresh.review_evidence_path(auth, provider).parent / ("qualification-" + provider + ".json")
            self.assertEqual(output.with_name(output.stem + "-diagnostics"),
                             fresh.qualification_evidence_path(auth, provider))

    def test_native_unknown_exposure_and_independent_cny_budget(self):
        auth = self.load(); hist = copy.deepcopy(auth['_fresh_history'])
        for r in hist['requests']:
            if r['provider'] == 'deepseek' and r.get('reported_usage') == 'UNKNOWN': r['wallet_exposure_microcny'] = 2637152
        auth = dict(auth, _fresh_history=hist, deepseek_funding_policy={'safety_margin_microcny': 263716})
        source = self.root / 'settlement.json'
        sha = auth['fresh_task']['history']['predecessor_ledger_sha256']
        self.write(source, dict(fresh_history_sha256=sha))
        snapshot = dict(fresh_history_sha256=sha, settlement_source_path=str(source))
        retained = sum(r.get('wallet_exposure_microcny', 0) for r in hist['requests'])
        self.assertEqual(fresh.native_funding_check(auth, {'requests': []}, snapshot, 2637152, 10000000), 10000000 - retained)
        auth['fresh_task']['budget_microcny'] = 2637152
        with self.assertRaises(ResourceGateDenied): fresh.native_funding_check(auth, {'requests': []}, snapshot, 2637152, 10000000)


if __name__ == '__main__': unittest.main()
