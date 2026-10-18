"""Synthetic evidence exercises the gate, never a provider or formal receipt."""
import copy
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from harness import formal_delivery_gate as gate
from harness.resource_gate import ResourceGateDenied, canonical, digest, sign_authorization


class FormalDeliveryGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = 1000
        self.key = self.root / 'key'
        self.key.write_bytes(b'OFFLINE-SYNTHETIC-NOT-A-PRODUCTION-KEY')
        self.key.chmod(0o600)
        rows = [{'number': i, 'provider': 'openai', 'status': 'RETURNED'}
                for i in range(1, 247)]
        for i in range(247, 335):
            provider = 'deepseek' if i <= 318 else 'openai'
            rows.append({'number': i, 'provider': provider, 'status': 'RETURNED',
                         'token_reservation': {k: 10 for k in gate.CATEGORIES},
                         'cost_reservation_microunits': 400000 if provider == 'deepseek' else 1000000})
        # Exactly 72 DS calls in the approved historical period, including #334.
        rows[317]['provider'] = 'openai'; rows[317]['cost_reservation_microunits'] = 1000000
        rows[-1].update(provider='deepseek', mission_id=gate.OLD_MISSION,
                        status='FAILED', reported_usage='UNKNOWN',
                        cost_reservation_microunits=400000,
                        usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        self.parent = self.root / 'parent.json'; self.write(self.parent, {'requests': rows})
        self.parent_auth = self.root / 'parent-auth.json'
        self.write(self.parent_auth, sign_authorization({'version': 'cmh-resource-budget/v1',
                   'mission_id': gate.OLD_MISSION, 'baseline_calls': 246,
                   'ledger_path': str(self.parent),
                   'original_started_epoch': 1}, self.key.read_bytes()))
        self.anchor = gate.TrustAnchor(digest(self.parent.read_bytes()),
                                      digest(self.parent_auth.read_bytes()), digest(canonical(rows[-1])))
        self.runtime = {'head': 'a' * 40, 'files': {'contract': 'b' * 64},
                        'registry_sha256': 'c' * 64,
                        'models': {'deepseek': {'provider': 'deepseek', 'model': 'deepseek-flash'},
                                   'openai': {'provider': 'openai', 'model': 'gpt-5.6-sol'}}}
        self.official = self.root / 'official.txt'
        self.official.write_text('SYNTHETIC OFFLINE authoritative capacity fixture')
        self.official.chmod(0o600)
        self.approval = self.root / 'user-approval.txt'
        self.approval.write_text('OFFLINE SYNTHETIC approval, not user authority'); self.approval.chmod(0o600)
        self.account_path = self.root / 'account.json'
        self.accounts = {'version': gate.ACCOUNT_VERSION, 'evidence_domain': 'OFFLINE_TEST',
                         'observed_epoch': 900, 'expires_epoch': 1100,
                         'parent_ledger_sha256': self.anchor.ledger_sha256,
                         'policy': gate.CAPACITY_POLICY, 'no_unbounded_prior_liability': True,
                         'all_prior_activity_included': True, 'exclusive_allocation': True,
                         'official_source_path': str(self.official),
                         'official_source_sha256': digest(self.official.read_bytes()),
                         'accounts': {p: {'account_id': p + '-dedicated',
                             'available_microunits': 100000000, 'other_reserved_microunits': 1000000,
                             'other_calls': 0, 'other_tokens': {k: 0 for k in gate.CATEGORIES},
                             'credential_identity': gate.credential_identity(p, b'OFFLINE-ONLY', self.key.read_bytes()),
                             'unit': 'USD' if p == 'deepseek' else 'CODEX_SUBSCRIPTION_UNITS'}
                                      for p in ('deepseek', 'openai')}}
        lane = lambda p: {'model': self.runtime['models'][p]['model'],
                         'max_new_calls': 5, 'token_limit': {k: 100 for k in gate.CATEGORIES},
                         'token_reservation': {k: 10 for k in gate.CATEGORIES},
                         'unknown_policy': 'DEBIT_FULL_RESERVATION_STOP_ON_OVERAGE',
                         'cost_unit': 'USD' if p == 'deepseek' else 'CODEX_SUBSCRIPTION_UNITS',
                         'cost_reservation_microunits': 400000 if p == 'deepseek' else 1000000,
                         'cost_limit_microunits': 2000000 if p == 'deepseek' else 5000000}
        self.ledger = self.root / 'child.json'
        self.payload = {'version': gate.AUTH_VERSION, 'evidence_domain': 'OFFLINE_TEST',
                        'authorization_id': 'synthetic-only', 'approval_source': 'EXPLICIT_USER_APPROVAL',
                        'approved_at_epoch': 900, 'user_approval_path': str(self.approval),
                        'user_approval_sha256': digest(self.approval.read_bytes()),
                        'mission_id': gate.NEW_MISSION, 'scope': ['PR2', 'PR4'],
                        'activation_approved': True, 'source_binding_version': gate.SOURCE_VERSION,
                        'source_binding_approved': True, 'old_mission_frozen': True,
                        'historical_actual_usage': 'UNKNOWN', 'chunk_migration_allowed': False,
                        'token_accounting_basis': 'PROSPECTIVE_PLUS_KNOWN_HISTORICAL_RESERVATIONS',
                        'parent': {'mission_id': gate.OLD_MISSION, 'ledger_path': str(self.parent),
                                   'ledger_sha256': self.anchor.ledger_sha256,
                                   'authorization_path': str(self.parent_auth),
                                   'authorization_sha256': self.anchor.authorization_sha256,
                                   'request_334_sha256': self.anchor.request_sha256,
                                   'acceptance': 'INCOMPLETE',
                                   'original_started_at': '2026-10-01T16:53:04Z',
                                   'deepseek_reserved_microusd': 28800000},
                        'runtime': self.runtime, 'targets': {'PR2': {'base': '1' * 40, 'head': '2' * 40},
                                                           'PR4': {'base': '2' * 40, 'head': 'a' * 40}},
                        'ledger_path': str(self.ledger), 'started_epoch': 950,
                        'expires_epoch': 1100, 'max_wall_clock_seconds': 150,
                        'max_new_calls': 10, 'shared_max_calls': 344,
                        'shared_token_limits': {p: {k: 100000 for k in gate.CATEGORIES}
                                                for p in ('deepseek', 'openai')},
                        'shared_cost_limits': {'deepseek': 100000000, 'openai': 100000000},
                        'account_evidence_path': str(self.account_path),
                        'account_ids': {p: p + '-dedicated' for p in ('deepseek', 'openai')},
                        'credential_identities': {p: gate.credential_identity(p, b'OFFLINE-ONLY', self.key.read_bytes())
                                                  for p in ('deepseek', 'openai')},
                        'providers': {p: lane(p) for p in ('deepseek', 'openai')}}
        self.auth = self.root / 'auth.json'
        self.env = {'CMH_RESOURCE_AUTHORIZATION': str(self.auth),
                    'CMH_RESOURCE_GATE_KEY_FILE': str(self.key),
                    'CMH_RESOURCE_MISSION_ID': gate.NEW_MISSION,
                    'CMH_RESOURCE_LEDGER': str(self.ledger), 'CMH_RESOURCE_RUN_ID': 'offline-run'}
        self.publish()
        self.write(self.ledger, sign_authorization({'version': gate.LEDGER_VERSION, 'evidence_domain': 'OFFLINE_TEST',
                   'mission_id': gate.NEW_MISSION, 'parent_ledger_sha256': self.anchor.ledger_sha256,
                   'authorization_sha256': self.env['CMH_RESOURCE_AUTH_SHA256'], 'requests': []}, self.key.read_bytes()))
        gate._write_child(self.ledger, json.loads(self.ledger.read_bytes()), self.key.read_bytes())

    def write(self, path, value):
        path.write_bytes(canonical(value) + b'\n'); path.chmod(0o600)

    def publish(self, update_child=True):
        self.write(self.account_path, sign_authorization(self.accounts, self.key.read_bytes()))
        self.payload['account_evidence_sha256'] = digest(self.account_path.read_bytes())
        self.write(self.auth, sign_authorization(self.payload, self.key.read_bytes()))
        self.env['CMH_RESOURCE_AUTH_SHA256'] = digest(self.auth.read_bytes())
        if update_child and self.ledger.exists():
            ledger = json.loads(self.ledger.read_bytes())
            ledger['authorization_sha256'] = self.env['CMH_RESOURCE_AUTH_SHA256']
            gate._write_child(self.ledger, ledger, self.key.read_bytes())

    def load(self):
        return gate._load(self.env, self.anchor, self.runtime, self.now, offline=True)

    def reserve(self):
        value = self.load()
        return gate._reserve_validated(value, self.env, 'openai', 'gpt-5.6-sol', b'fixture',
                                       'qualification-case', self.now, offline=True)

    def test_direct_unknown_attempt_retains_reservation_and_blocks_new_run(self):
        from harness import deepseek_direct as direct
        from harness import resource_gate as resources
        from direct_deepseek_fixture import KEY
        def reserve(**kwargs):
            return gate._reserve_validated(self.load(), self.env, 'deepseek', direct.MODEL,
                                          kwargs['prompt'], kwargs['stage'], self.now, offline=True)
        with patch.object(resources, 'reserve', side_effect=reserve), \
             patch.object(gate, 'require_active_transport'), patch.object(gate, 'require_provider_credential'), \
             patch.object(gate, 'bounded_delivery_timeout', side_effect=lambda n: n), \
             patch.object(direct, '_bounded_post', side_effect=direct.DirectFailure('REQUEST_TIMEOUT')) as send:
            with self.assertRaises(direct.DirectFailure):
                direct.invoke('prompt', KEY, {'type': 'object'}, stage='chunk-000.json')
            send.assert_called_once()
            row = json.loads(self.ledger.read_bytes())['requests'][0]
            self.assertEqual(row['reported_usage'], 'UNKNOWN')
            self.assertEqual(row['cost_reservation_microunits'], 400000)
            self.env['CMH_RESOURCE_RUN_ID'] = 'another-run'
            with self.assertRaises(ResourceGateDenied):
                direct.invoke('prompt', KEY, {'type': 'object'}, stage='chunk-000.json')
            self.assertEqual(send.call_count, 1)

    def test_direct_100_call_gate_is_atomic_and_shared_across_run_ids(self):
        from harness import deepseek_direct as direct, resource_gate as resources
        from direct_deepseek_fixture import KEY, response
        lane = self.payload['providers']['deepseek']
        lane.update(max_new_calls=100, token_limit={k: 1000 for k in gate.CATEGORIES},
                    cost_limit_microunits=40000000,
                    price_microusd_per_million={'input_cache_miss': 300000, 'cache_hit': 3000, 'output': 1200000})
        self.payload.update(max_new_calls=105, shared_max_calls=439)
        self.publish()
        def reserve(**kwargs):
            return gate._reserve_validated(self.load(), self.env, 'deepseek', direct.MODEL,
                                          kwargs['prompt'], kwargs['stage'], self.now, offline=True)
        with patch.object(resources, 'reserve', side_effect=reserve), \
             patch.object(gate, 'require_active_transport'), patch.object(gate, 'require_provider_credential'), \
             patch.object(gate, 'bounded_delivery_timeout', side_effect=lambda n: n), \
             patch.object(direct, '_bounded_post', return_value=(200, direct.canonical(response({'findings': []})))) as send:
            for number in range(100):
                self.env['CMH_RESOURCE_RUN_ID'] = 'offline-run-' + str(number)
                direct.invoke('prompt', KEY, {'type': 'object'}, stage='chunk-%03d.json' % number)
            self.assertEqual(send.call_count, 100)
            row = json.loads(self.ledger.read_bytes())['requests'][0]
            self.assertEqual(row['reported_usage']['tokens']['output'], 5)
            self.assertEqual(row['estimated_cost_microusd'], 9)
            with self.assertRaises(ResourceGateDenied):
                direct.invoke('prompt', KEY, {'type': 'object'}, stage='chunk-100.json')
            self.assertEqual(send.call_count, 100)
            self.assertEqual(len(json.loads(self.ledger.read_bytes())['requests']), 100)

    def test_01_missing_parent(self):
        self.parent.unlink()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_02_parent_hash(self):
        self.parent.write_bytes(self.parent.read_bytes() + b' ')
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_03_parent_signature(self):
        value = json.loads(self.parent_auth.read_bytes()); value['authorization_hmac_sha256'] = '0' * 64
        self.write(self.parent_auth, value)
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_04_334_cannot_be_verified(self):
        value = json.loads(self.parent.read_bytes()); value['requests'][-1]['reported_usage'] = {'input': 0}
        self.write(self.parent, value)
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_05_reservation_preserved(self):
        self.payload['parent']['deepseek_reserved_microusd'] = 0; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_06_missing_parent_binding(self):
        self.payload.pop('parent'); self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_07_unlinked_empty_ledger(self):
        self.write(self.ledger, {'requests': []})
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_08_unsigned_authorization(self):
        self.write(self.auth, self.payload); self.env['CMH_RESOURCE_AUTH_SHA256'] = digest(self.auth.read_bytes())
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_09_synthetic_signature_cannot_enter_formal_loader(self):
        with self.assertRaises(ResourceGateDenied): gate.load_authorization(self.env)

    def test_10_head_drift(self):
        self.payload['runtime']['head'] = 'f' * 40; self.publish()
        with self.assertRaises(ResourceGateDenied): gate._load(self.env, self.anchor,
            dict(self.runtime, head='a' * 40), self.now, offline=True)

    def test_11_runtime_registry_drift(self):
        for field in ('files', 'registry_sha256'):
            runtime = copy.deepcopy(self.runtime); runtime[field] = 'changed'
            with self.assertRaises(ResourceGateDenied): gate._load(self.env, self.anchor,
                runtime, self.now, offline=True)

    def test_12_old_qualification_binding(self):
        with self.assertRaises(ResourceGateDenied): gate.validate_qualification_binding({}, self.load())

    def test_13_unknown_capacity(self):
        self.accounts['accounts']['openai']['available_microunits'] = 'UNKNOWN'; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_14_expired_account(self):
        self.accounts['expires_epoch'] = 999; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_15_wrong_account(self):
        self.accounts['accounts']['openai']['account_id'] = 'other'; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_16_insufficient_capacity(self):
        self.accounts['accounts']['openai']['available_microunits'] = 100; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_17_uncovered_prior_liability(self):
        for field in ('no_unbounded_prior_liability', 'all_prior_activity_included', 'exclusive_allocation'):
            self.accounts[field] = False; self.publish()
            with self.assertRaises(ResourceGateDenied): self.load()
            self.accounts[field] = True

    def test_18_call_cap(self):
        self.payload['providers']['openai']['max_new_calls'] = 0; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_19_each_token_cap(self):
        for field in gate.CATEGORIES:
            self.payload['providers']['openai']['token_limit'][field] = 1; self.publish()
            with self.assertRaises(ResourceGateDenied): self.reserve()
            self.payload['providers']['openai']['token_limit'][field] = 100

    def test_20_cost_and_time_cap(self):
        self.payload['providers']['openai']['cost_limit_microunits'] = 1; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()
        self.payload['providers']['openai']['cost_limit_microunits'] = 5000000
        self.payload['max_wall_clock_seconds'] = 1; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_21_concurrent_reservation_no_overallocation(self):
        self.payload['providers']['openai']['max_new_calls'] = 1; self.publish()
        barrier = threading.Barrier(2)
        def attempt():
            barrier.wait()
            try: self.reserve(); return True
            except ResourceGateDenied: return False
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: attempt(), range(2))), [False, True])

    def test_22_unknown_usage_blocks_next_call(self):
        reservation = self.reserve(); reservation.settle('FAILED')
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_23_unactivated_runner_cannot_call_transport(self):
        from harness.openai_invocation import invoke_openai
        from harness.model_registry import ModelSpec
        with patch.dict('os.environ', self.env, clear=True), patch(
                'harness.openai_invocation._invoke_openai_unmetered') as transport:
            with self.assertRaises(ResourceGateDenied):
                invoke_openai('fixture', ModelSpec('openai', 'gpt-5.6-sol', 'high'), {})
            transport.assert_not_called()

    def test_24_offline_artifact_is_not_formal_receipt(self):
        value = self.load()
        self.assertEqual(value['evidence_domain'], 'OFFLINE_TEST')
        with self.assertRaises(ResourceGateDenied): gate._load(self.env, self.anchor,
            self.runtime, self.now, offline=False)

    def test_25_valid_structure_positive_and_preserved_parent(self):
        old = self.parent.read_bytes(); value = self.load()
        self.assertEqual(value['_history']['deepseek']['cost'], 28800000)
        self.assertEqual(value['_history']['global_calls'], 334)
        self.reserve()
        self.assertEqual(old, self.parent.read_bytes())
        self.assertEqual(len(json.loads(self.ledger.read_bytes())['requests']), 1)

    def test_26_formal_domain_does_not_make_synthetic_key_trusted(self):
        self.payload['evidence_domain'] = 'FORMAL'; self.accounts['evidence_domain'] = 'FORMAL'
        self.publish()
        with self.assertRaises(ResourceGateDenied):
            gate._load(self.env, gate.PRODUCTION_ANCHOR, self.runtime, self.now)

    def test_27_bad_parent_hmac_even_with_matching_artifact_hash(self):
        value = json.loads(self.parent_auth.read_bytes()); value['authorization_hmac_sha256'] = '0' * 64
        self.write(self.parent_auth, value)
        expected_hash = digest(self.parent_auth.read_bytes())
        self.payload['parent']['authorization_sha256'] = expected_hash; self.publish()
        anchor = gate.TrustAnchor(self.anchor.ledger_sha256, expected_hash, self.anchor.request_sha256)
        with self.assertRaises(ResourceGateDenied):
            gate._load(self.env, anchor, self.runtime, self.now, offline=True)

    def test_28_checkpoint_prevents_empty_ledger_rollback(self):
        empty = self.ledger.read_bytes(); self.reserve(); self.ledger.write_bytes(empty)
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_29_missing_checkpoint_blocks_resume(self):
        gate._checkpoint_path(self.ledger).unlink()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_30_persistence_failure_keeps_gate_closed(self):
        original = gate._write_atomic
        def fail_ledger(path, value):
            if path == self.ledger: raise OSError('synthetic fsync/write failure')
            return original(path, value)
        with patch.object(gate, '_write_atomic', side_effect=fail_ledger):
            with self.assertRaises(OSError): self.reserve()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_31_other_tasks_occupy_shared_capacity(self):
        self.accounts['accounts']['openai']['other_reserved_microunits'] = 100000000; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_32_shared_token_and_global_caps_count_parent(self):
        self.payload['shared_max_calls'] = 334; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()
        self.payload['shared_max_calls'] = 344
        self.payload['shared_token_limits']['openai']['input'] = 1; self.publish()
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_33_each_raw_transport_rejects_unactivated_mission(self):
        from harness.openai_invocation import _invoke_openai_unmetered
        from harness.model_qualification import _actual_provider_invoke_unmetered
        from harness.model_registry import ModelSpec
        import deepseek_review
        calls = [lambda: _invoke_openai_unmetered('fixture', ModelSpec('openai', 'gpt-5.6-sol', 'high'), {}),
                 lambda: _actual_provider_invoke_unmetered(ModelSpec('deepseek', 'deepseek-flash'),
                         'fixture', token='SYNTHETIC_ONLY', timeout=1),
                 lambda: deepseek_review._invoke_reviewer_unmetered(
                         ['synthetic-launcher', '--model', 'deepseek-flash'], 'fixture', {}, 1)]
        with patch.dict('os.environ', self.env, clear=True), patch('subprocess.Popen') as spawn:
            for call in calls:
                with self.assertRaises(ResourceGateDenied): call()
            spawn.assert_not_called()

    def test_34_activation_and_source_approval_required(self):
        for field in ('activation_approved', 'source_binding_approved', 'old_mission_frozen'):
            self.payload[field] = False; self.publish()
            with self.assertRaises(ResourceGateDenied): self.load()
            self.payload[field] = True

    def test_35_draft_cannot_be_source_binding_authorization(self):
        from harness.reviewer_v2_contract import contract_authorization_identity
        with patch.dict('os.environ', self.env, clear=True):
            with self.assertRaises(ResourceGateDenied): contract_authorization_identity(gate.NEW_MISSION)

    def test_36_new_mission_cannot_start_builder(self):
        from harness.codex import AppServerCodex
        with patch.dict('os.environ', self.env, clear=True), patch('subprocess.Popen') as spawn:
            with self.assertRaises(ValueError): AppServerCodex(worktree=str(self.root))
            spawn.assert_not_called()

    def test_37_qualification_requests_are_exact_ordered_and_bounded(self):
        from harness.model_qualification import CASES, qualification_prompt
        first = qualification_prompt(CASES[0]).encode()
        gate._qualification_request([], 'openai', first, 'run-a')
        with self.assertRaises(ResourceGateDenied):
            gate._qualification_request([], 'openai', b'arbitrary probe', 'run-a')
        rows = [{'provider': 'openai', 'stage': 'qualification-case', 'run_id': 'run-a'}]
        with self.assertRaises(ResourceGateDenied):
            gate._qualification_request(rows, 'openai', first, 'run-b')
        with self.assertRaises(ResourceGateDenied):
            gate._qualification_request(rows * 4, 'openai', first, 'run-a')

    def test_38_official_evidence_tampering_and_missing_source(self):
        self.official.write_text('changed synthetic source')
        with self.assertRaises(ResourceGateDenied): self.load()
        self.official.unlink()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_39_signed_child_tampering_rejected(self):
        value = json.loads(self.ledger.read_bytes()); value['mission_id'] = 'new-id-bypass'
        self.write(self.ledger, value)
        with self.assertRaises(ResourceGateDenied): self.reserve()

    def test_40_copy_parent_to_another_home_does_not_rebind_authorization(self):
        copied = self.root / 'copied-parent.json'; copied.write_bytes(self.parent.read_bytes()); copied.chmod(0o600)
        self.payload['parent']['ledger_path'] = str(copied); self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_41_changing_mission_id_does_not_create_authority(self):
        self.payload['mission_id'] = 'another-id'; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_42_offline_active_reservation_cannot_enter_transport(self):
        from harness.resource_gate import _active_reservation
        reservation = self.reserve(); token = _active_reservation.set(reservation)
        try:
            with patch.dict('os.environ', {}, clear=True):
                with self.assertRaises(ResourceGateDenied):
                    gate.require_active_transport('openai', 'gpt-5.6-sol')
        finally:
            _active_reservation.reset(token)

    def test_43_user_approval_provenance_required(self):
        self.approval.write_text('changed approval')
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_44_account_credential_binding_cannot_change(self):
        self.accounts['accounts']['openai']['credential_identity'] = '0' * 64; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_45_future_envelope_must_fit_capacity_before_first_call(self):
        self.payload['providers']['openai']['cost_limit_microunits'] = 200000000; self.publish()
        with self.assertRaises(ResourceGateDenied): self.load()

    def prepare_revision(self, index):
        previous = self.root / f'previous-{index}.json'
        previous.write_bytes(self.auth.read_bytes()); previous.chmod(0o600)
        approval = self.root / f'approval-{index}.txt'
        approval.write_text(f'OFFLINE SYNTHETIC independent identity approval {index}'); approval.chmod(0o600)
        self.payload.update(authorization_id=f'synthetic-revision-{index}', approved_at_epoch=self.now,
                            user_approval_path=str(approval), user_approval_sha256=digest(approval.read_bytes()),
                            previous_authorization_path=str(previous),
                            previous_authorization_sha256=digest(previous.read_bytes()),
                            child_baseline_checkpoint_sha256=digest(gate._checkpoint_path(self.ledger).read_bytes()))
        self.publish(update_child=False)

    def test_46_signed_identity_revision_preserves_counters_and_parent(self):
        old = self.parent.read_bytes(); reservation = self.reserve()
        reservation.observe({'tokens': {k: 0 for k in gate.CATEGORIES}}); reservation.settle('RETURNED')
        before = json.loads(self.ledger.read_bytes())['requests']
        self.prepare_revision(1)
        value = self.load(); gate._activate_validated(value, self.env, offline=True)
        after = json.loads(self.ledger.read_bytes())['requests']
        self.assertEqual(before, after)
        self.assertEqual(old, self.parent.read_bytes())
        self.assertEqual(len(value['_lineage_sha256']), 2)
        self.reserve()
        self.assertEqual(len(json.loads(self.ledger.read_bytes())['requests']), 2)

    def test_47_identity_revision_cannot_raise_budget_or_reset_clock(self):
        self.prepare_revision(1)
        for name in ('max_new_calls', 'started_epoch'):
            old = self.payload[name]; self.payload[name] += 1; self.publish(update_child=False)
            with self.assertRaises(ResourceGateDenied): self.load()
            self.payload[name] = old

    def test_48_identity_revision_cannot_clear_unknown(self):
        self.reserve().settle('FAILED'); self.prepare_revision(1)
        with self.assertRaises(ResourceGateDenied):
            gate._activate_validated(self.load(), self.env, offline=True)

    def test_49_identity_revision_cannot_replace_missing_history(self):
        self.prepare_revision(1); self.ledger.unlink()
        with self.assertRaises(ResourceGateDenied):
            gate._activate_validated(self.load(), self.env, offline=True)

    def test_50_identity_revision_is_bounded_and_needs_fresh_approval(self):
        for i in (1, 2):
            self.prepare_revision(i); gate._activate_validated(self.load(), self.env, offline=True)
        self.prepare_revision(3)
        with self.assertRaises(ResourceGateDenied): self.load()

    def test_51_subprocess_timeout_cannot_outlive_authority_or_account_proof(self):
        value = self.load()
        self.assertEqual(gate._bounded_timeout(value, 1000, 900), 100)
        value['_account']['expires_epoch'] = 1007
        self.assertEqual(gate._bounded_timeout(value, 1000, 900), 7)
        with self.assertRaises(ResourceGateDenied): gate._bounded_timeout(value, 1007, 900)

    def test_52_removing_mission_environment_cannot_bypass_raw_transports(self):
        from harness.openai_invocation import _invoke_openai_unmetered
        from harness.model_qualification import _actual_provider_invoke_unmetered
        from harness.model_registry import ModelSpec
        import deepseek_review
        with patch.dict('os.environ', {}, clear=True), patch('subprocess.Popen') as spawn:
            for call in (
                    lambda: _invoke_openai_unmetered('fixture', ModelSpec('openai', 'gpt-5.6-sol', 'high'), {}),
                    lambda: _actual_provider_invoke_unmetered(ModelSpec('deepseek', 'deepseek-flash'),
                             'fixture', token='SYNTHETIC_ONLY', timeout=1),
                    lambda: deepseek_review._invoke_reviewer_unmetered(
                             ['synthetic', '--model', 'deepseek-flash'], 'fixture', {}, 1)):
                with self.assertRaises(ResourceGateDenied): call()
            spawn.assert_not_called()


if __name__ == '__main__': unittest.main()
