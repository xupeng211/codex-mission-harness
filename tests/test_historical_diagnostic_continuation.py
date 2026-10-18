"""Closed diagnostic history is accounting, never fresh reviewer authority."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import diagnostic_probe as diagnostic, formal_delivery_gate as gate
from harness.resource_gate import ResourceGateDenied, canonical, digest, sign_authorization
import test_history_continuation as fixtures

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_openai as reviewer
from harness.model_registry import ModelSpec


class HistoricalDiagnosticContinuationTests(unittest.TestCase):
    write = fixtures.HistoryContinuationTests.write
    publish = fixtures.HistoryContinuationTests.publish
    load = fixtures.HistoryContinuationTests.load
    activate = fixtures.HistoryContinuationTests.activate

    def setUp(self):
        fixtures.HistoryContinuationTests.setUp(self)
        child = gate._checked_child(self.second_path, self.key.read_bytes())
        for number in range(17, 119):
            provider = 'deepseek' if number <= 82 else 'openai'
            row = copy.deepcopy(self.frozen_rows[0 if provider == 'deepseek' else 4])
            row.update(number=number, request_id=f'formal-{number}',
                       authorization_sha256=self.second_prior_sha,
                       reported_usage={'tokens': dict.fromkeys(gate.CATEGORIES, 1)},
                       usage_accounting='FULL_RESERVATION_RETAINED')
            if number in (97, 114, 115, 116, 117):
                row.update(status='FAILED', reported_usage='UNKNOWN',
                           usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
            child['requests'].append(row)
        gate._write_child(self.second_path, child, self.key.read_bytes())
        prior, prior_sha, prior_path, ledger_path = (
            self.second_prior, self.second_prior_sha, self.second_auth_path, self.second_path)
        self.pins = {}
        self.origins = []
        for number, model in ((119, 'gpt-6-astra'), (120, 'gpt-5.6-sol')):
            authority = copy.deepcopy(prior)
            authority['runtime']['models']['openai'] = dict(diagnostic.MODEL)
            lane = authority['providers']['openai']
            scope = dict(version=diagnostic.VERSION, mission=diagnostic.MISSION,
                         purpose=diagnostic.PURPOSE,
                         model=dict(diagnostic.MODEL, model=model),
                         route='codex_subscription', max_logical_invocations=1,
                         result_authority=diagnostic.CLASSIFICATION, harness_logical_retry=0,
                         runtime_head=authority['runtime']['head'],
                         token_ceiling=lane['token_reservation'],
                         cost_ceiling_microunits=lane['cost_reservation_microunits'],
                         diagnostic_id=digest(str(number).encode()),
                         prompt_sha256=digest(f'prompt-{number}'.encode()),
                         schema_sha256=digest(f'schema-{number}'.encode()),
                         prompt_bytes=12137 if number == 119 else 105015)
            successor = self.root / f'history-{number}.json'
            authority.update(diagnostic_probe=scope, qualification_launch_approved=False,
                             full_review_launch_approved=False,
                             previous_authorization_path=str(prior_path),
                             previous_authorization_sha256=prior_sha,
                             ledger_path=str(successor))
            authority_path = self.root / f'diagnostic-origin-{number}.json'
            self.write(authority_path, sign_authorization(authority, self.key.read_bytes()))
            origin_sha = digest(authority_path.read_bytes())
            row = dict(number=number, request_id=f'diagnostic-{number}',
                       mission_id=gate.NEW_MISSION, provider='openai', model=model,
                       authorization_sha256=origin_sha, status='FAILED',
                       stage=diagnostic.STAGE, run_id=scope['diagnostic_id'],
                       model_configuration=scope['model'], diagnostic_id=scope['diagnostic_id'],
                       prompt_sha256=scope['prompt_sha256'], schema_sha256=scope['schema_sha256'],
                       route=scope['route'], harness_logical_retry=0,
                       execution_classification='DIAGNOSTIC_PROBE',
                       result_authority=diagnostic.CLASSIFICATION,
                       token_reservation=lane['token_reservation'],
                       cost_reservation_microunits=lane['cost_reservation_microunits'],
                       cost_unit=lane['cost_unit'], started_epoch=960, finished_epoch=961,
                       reported_usage='UNKNOWN' if number == 120 else {'tokens': dict.fromkeys(gate.CATEGORIES, 0)},
                       usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS' if number == 120 else 'FULL_RESERVATION_RETAINED')
            child = copy.deepcopy(child)
            child['requests'].append(row)
            child['authorization_sha256'] = origin_sha
            gate._write_child(successor, child, self.key.read_bytes())
            self.pins[origin_sha] = digest(canonical(row))
            self.origins.append((authority_path, origin_sha, copy.deepcopy(authority)))
            prior, prior_sha, prior_path, ledger_path = authority, origin_sha, authority_path, successor
        self.prior = prior
        self.predecessor = ledger_path
        self.rows = copy.deepcopy(child['requests'])
        self.reader = copy.deepcopy(self.payload)
        self.reader.update(ledger_path=str(self.root / 'unactivated-successor.json'),
                           previous_authorization_path=str(prior_path),
                           previous_authorization_sha256=prior_sha)
        self.rebind()
        self.pin_patch = patch.object(gate, 'HISTORICAL_DIAGNOSTIC_ROWS', self.pins)
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)

    def rebind(self):
        c = gate.build_history_continuation(self.prior,
            self.reader['previous_authorization_sha256'], self.predecessor, self.key.read_bytes())
        self.reader.update(continuation=c, child_baseline_checkpoint_sha256=c['predecessor_checkpoint_sha256'])

    def validate(self):
        return gate._history_continuation_predecessor(self.reader, self.prior,
                                                    self.key.read_bytes(), offline=True)

    def test_A_B_G_complete_120_rows_eight_unknowns_and_formal_records(self):
        before = self.predecessor.read_bytes()
        rows = self.validate()['requests']
        self.assertEqual(rows, self.rows)
        self.assertEqual(self.predecessor.read_bytes(), before)
        self.assertEqual(len(rows), 120)
        self.assertEqual([r['number'] for r in rows if r['reported_usage'] == 'UNKNOWN'],
                         [5, 16, 97, 114, 115, 116, 117, 120])
        self.assertEqual(gate._history(rows)['openai']['calls'], 43)
        self.assertEqual(gate._history(rows)['deepseek']['calls'], 77)
        self.assertEqual(self.reader['continuation']['consumed_calls']['global'], 120)
        self.assertEqual(self.reader['continuation']['remaining_call_limits']['global'], 83)
        self.assertEqual(rows[0]['model'], 'deepseek-flash')

    def test_C_F_diagnostics_cannot_authorize_review_or_become_PASS(self):
        for _, sha, authority in self.origins:
            with self.assertRaises(ResourceGateDenied):
                gate.require_review_authority(authority)
            with self.assertRaises(ResourceGateDenied):
                gate.qualification_binding(dict(authority, _authorization_sha256=sha))
        for field, value in [('status', 'RETURNED'), ('reported_usage', {'tokens': dict.fromkeys(gate.CATEGORIES, 0)}),
                             ('result_authority', 'FORMAL'), ('execution_classification', 'REVIEW')]:
            child = gate._checked_child(self.predecessor, self.key.read_bytes())
            original = copy.deepcopy(child)
            child['requests'][-1][field] = value
            gate._write_child(self.predecessor, child, self.key.read_bytes())
            self.rebind()
            with self.assertRaises(ResourceGateDenied):
                self.validate()
            gate._write_child(self.predecessor, original, self.key.read_bytes())
        self.rebind()

    def test_D_invalid_origin_signature_or_hash_is_rejected(self):
        path, _, _ = self.origins[0]
        raw = path.read_bytes()
        value = json.loads(raw)
        value['diagnostic_probe']['model']['model'] = 'gpt-5.6-sol'
        path.write_bytes(canonical(value))
        with self.assertRaises(ResourceGateDenied):
            self.validate()
        path.write_bytes(raw)

    def test_D_no_unpinned_model_or_scope_exception(self):
        with patch.object(gate, 'HISTORICAL_DIAGNOSTIC_ROWS', {}):
            with self.assertRaises(ResourceGateDenied):
                self.validate()
        for field, value in [('authorization_sha256', '0' * 64), ('prompt_sha256', '0' * 64),
                             ('schema_sha256', '0' * 64), ('run_id', 'replay'),
                             ('model', 'gpt-6.1-sol'), ('cost_reservation_microunits', 0)]:
            row = dict(self.rows[-2], **{field: value})
            self.assertFalse(gate._historical_diagnostic(row, self.origins[0][2], self.origins[0][1]))

    def test_E_consumed_diagnostic_cannot_be_sent_again(self):
        for _, _, authority in self.origins:
            with self.assertRaises(ResourceGateDenied):
                diagnostic.validate_scope(authority)
        auth = copy.deepcopy(self.reader)
        auth.update(_authorization_sha256='f' * 64, _lineage_sha256=[r['authorization_sha256'] for r in self.rows],
                    _predecessor_child=self.validate(), max_new_calls=120)
        ledger = dict(gate._checked_child(self.predecessor, self.key.read_bytes()), authorization_sha256='f' * 64)
        path = Path(auth['ledger_path'])
        gate._write_child(path, ledger, self.key.read_bytes())
        env = dict(self.env, CMH_RESOURCE_RUN_ID='fresh-fixture')
        with self.assertRaises(ResourceGateDenied):
            gate._reserve_validated(auth, env, 'openai', 'gpt-5.6-sol', b'fixture',
                                    'qualification-case', self.now, offline=True)
        self.assertEqual(gate._checked_child(path, self.key.read_bytes())['requests'], self.rows)

    def test_H_history_is_not_a_complete_reviewer_receipt(self):
        root = Path(__file__).resolve().parents[1]
        spec = ModelSpec('openai', 'gpt-5.6-sol', 'high')
        for incomplete in (self.validate(), self.rows[-2], self.rows[-1]):
            with self.assertRaises(ValueError):
                reviewer.validate(incomplete, root=root, base='a' * 40,
                                  head='b' * 40, spec=spec, auth_key='OFFLINE_TEST_ONLY')

    def test_I_J_prefix_and_UNKNOWN_cannot_be_released_or_reclaimed(self):
        auth = dict(self.reader, _predecessor_child=self.validate())
        for row in self.rows:
            if row['reported_usage'] == 'UNKNOWN':
                self.assertFalse(gate._unresolved(auth, row))  # Retained, never resolved/refunded.
                self.assertTrue(gate._unresolved(auth, dict(row, request_id='new-request')))
                self.assertTrue(gate._unresolved(auth, dict(row, status='STARTED')))
        raw = self.predecessor.read_bytes()
        cp = gate._checkpoint_path(self.predecessor)
        cpraw = cp.read_bytes()
        for mutation in ('truncate', 'duplicate', 'reorder', 'zero_reservation'):
            child = gate._checked_child(self.predecessor, self.key.read_bytes())
            if mutation == 'truncate': child['requests'].pop()
            if mutation == 'duplicate': child['requests'][-1]['request_id'] = child['requests'][0]['request_id']
            if mutation == 'reorder': child['requests'][-2:] = reversed(child['requests'][-2:])
            if mutation == 'zero_reservation': child['requests'][-1]['token_reservation'] = dict.fromkeys(gate.CATEGORIES, 0)
            gate._write_child(self.predecessor, child, self.key.read_bytes())
            self.rebind()
            with self.assertRaises(ResourceGateDenied): self.validate()
            self.predecessor.write_bytes(raw)
            cp.write_bytes(cpraw)
        self.rebind()


if __name__ == '__main__':
    unittest.main()
