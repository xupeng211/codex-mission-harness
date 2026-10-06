"""Official-shaped JSONL through production invocation and signed settlement.
All Codex processes are mocked; no network or model requests.
"""
import copy
import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import test_openai_availability as fixtures
from harness import openai_invocation as invoke, formal_delivery_gate as gate, resource_gate as resources
from harness.model_registry import ModelSpec
from harness.model_qualification import _actual_provider_invoke, _SCHEMA

USAGE = dict(input_tokens=1000, cached_input_tokens=700, output_tokens=200, reasoning_output_tokens=150)
RESPONSE = json.dumps(dict(decisions=[], findings=[], summary='The supplied source has been checked and no defects were found.'))


def stream(usage=USAGE):
    terminal = dict(type='turn.completed')
    if usage is not None: terminal['usage'] = usage
    return b'\n'.join(json.dumps(e).encode() for e in (
        dict(type='thread.started', thread_id='0199a213-81c0-7800-8aa1-bbab2a035a53'),
        dict(type='turn.started'),
        dict(type='item.completed', item=dict(id='item_0', type='agent_message', text=RESPONSE)),
        terminal)) + b'\n'


class OpenAIUsageTests(unittest.TestCase):
    write = fixtures.AvailabilityTests.write
    publish = fixtures.AvailabilityTests.publish
    load = fixtures.AvailabilityTests.load
    refresh = fixtures.AvailabilityTests.refresh
    snapshot = fixtures.AvailabilityTests.snapshot
    ledger_value = fixtures.AvailabilityTests.ledger_value
    reserve = fixtures.AvailabilityTests.reserve

    def setUp(self):
        fixtures.AvailabilityTests.setUp(self)
        self.spec = ModelSpec('openai', 'gpt-5.6-sol', 'high')
        self.runtime['models']['openai'] = self.spec.identity()
        self.payload['runtime'] = self.runtime
        self.payload['providers']['openai']['token_limit'] = {k: 10000 for k in gate.CATEGORIES}
        self.payload['providers']['openai']['token_reservation'] = {k: 2000 for k in gate.CATEGORIES}
        self.payload['shared_token_limits']['openai'] = {k: 20000 for k in gate.CATEGORIES}
        self.publish()
        # Reinitialize only this synthetic fixture, never production history.
        self.ledger.unlink(); gate._checkpoint_path(self.ledger).unlink()
        gate._activate_validated(self.load(), self.env, offline=True)
        self.refresh()

    def call(self, usage=USAGE, mutate=None):
        process = Mock(pid=1234, returncode=0)
        process.communicate.return_value = (stream(usage), b'')
        def start(command, **kwargs):
            Path(command[command.index('--output-last-message') + 1]).write_text(RESPONSE)
            return process
        def reserve(**kwargs):
            r = self.reserve(kwargs['prompt']); r.execution_allowed = True
            return r
        original = invoke.verify_openai_usage
        def verify(usage, row, auth, key):
            if mutate is not None: mutate(usage)
            return original(usage, row, auth, key)
        with patch.dict(os.environ, self.env, clear=True), \
             patch.object(gate, 'load_authorization', side_effect=lambda *a: self.load()), \
             patch.object(gate, 'require_active_transport'), \
             patch.object(gate, 'require_provider_credential'), \
             patch.object(gate, 'require_invocation_spec'), \
             patch.object(gate, 'bounded_delivery_timeout', side_effect=lambda n:n), \
             patch.object(invoke, 'canonical_environment', return_value={}), \
             patch.object(invoke.subprocess, 'Popen', side_effect=start), \
             patch.object(resources, 'reserve', side_effect=reserve), \
             patch.object(invoke, 'verify_openai_usage', side_effect=verify):
            return _actual_provider_invoke(self.spec, 'fixture', token=None, timeout=1)

    def test_jsonl_to_qualification_invocation_to_signed_settlement(self):
        result = self.call()
        row = self.ledger_value()['requests'][0]
        self.assertEqual(row['status'], 'RETURNED')
        self.assertEqual(row['usage_accounting'], 'FULL_RESERVATION_RETAINED')
        self.assertEqual(row['reported_usage']['tokens'], dict(input=300, cache=700, output=200, reasoning=150))
        self.assertEqual(row['reported_usage']['usage_scope'], 'CODEX_EXEC_TURN')
        self.assertEqual(result.evidence['resource_request_id'], row['request_id'])
        self.assertNotIn('cache_creation_tokens', row['reported_usage'])
        # Reasoning remains a subset of completion, not an extra output charge.
        self.assertEqual(row['reported_usage']['tokens']['output'], 200)
        self.assertEqual(row['cost_reservation_microunits'], 1000000)

    def test_capture_survives_ephemeral_cleanup_and_rehashes(self):
        result = self.call(); row = self.ledger_value()['requests'][0]
        usage = result.evidence['usage']; ref = usage['transport_binding']
        binding = gate._signed(ref['path'], ref['sha256'], self.key.read_bytes())
        self.assertEqual(binding['request_id'], row['request_id'])
        self.assertTrue(Path(binding['files']['stdout.jsonl']['path']).is_file())
        self.assertTrue(invoke.verify_openai_usage(usage, row, self.load(), self.key.read_bytes()))

    def test_missing_or_malformed_usage_remains_unknown_and_blocks(self):
        for bad in (None, {}, dict(USAGE, reasoning_output_tokens=None),
                    dict(USAGE, input_tokens=True), dict(USAGE, cached_input_tokens=1001),
                    dict(USAGE, reasoning_output_tokens=201)):
            self.assertIsNone(invoke.parse_events(stream(bad))['usage'])
        self.call(None)
        row = self.ledger_value()['requests'][0]
        self.assertEqual(row['reported_usage'], 'UNKNOWN')
        self.assertEqual(row['usage_accounting'], 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        with self.assertRaises(resources.ResourceGateDenied): self.reserve()

    def test_malformed_usage_settles_unknown(self):
        self.call(dict(USAGE, reasoning_output_tokens=None))
        row = self.ledger_value()['requests'][0]
        self.assertEqual(row['reported_usage'], 'UNKNOWN')
        self.assertEqual(row['usage_accounting'], 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')

    def test_duplicate_terminal_fields_are_rejected(self):
        raw = stream().replace(b'"input_tokens": 1000', b'"input_tokens": 1000, "input_tokens": 1')
        with self.assertRaises(ValueError): invoke.parse_events(raw)

    def test_raw_request_runtime_model_or_turn_mismatch_blocks(self):
        result = self.call(); row = self.ledger_value()['requests'][0]
        for field, wrong in (('request_id', 'wrong'), ('model', 'other'), ('prompt_sha256', '0'*64)):
            changed = dict(row, **{field:wrong})
            with self.assertRaises(ValueError):
                invoke.verify_openai_usage(result.evidence['usage'], changed, self.load(), self.key.read_bytes())
        auth = self.load();auth['runtime'] = dict(auth['runtime'], head='f'*40)
        with self.assertRaises(ValueError):
            invoke.verify_openai_usage(result.evidence['usage'], row, auth, self.key.read_bytes())
        for field in ('thread_id','agent_message_id','response_sha256'):
            usage = dict(result.evidence['usage'], **{field:'wrong'})
            with self.assertRaises(ValueError):
                invoke.verify_openai_usage(usage, row, self.load(), self.key.read_bytes())

    def test_modified_transport_blocks_settlement_without_refund(self):
        def tamper(usage):
            binding=gate._signed(usage['transport_binding']['path'],None,self.key.read_bytes())
            Path(binding['files']['stdout.jsonl']['path']).write_bytes(stream(dict(USAGE,input_tokens=1001)))
        self.call(mutate=tamper)
        row=self.ledger_value()['requests'][0]
        self.assertEqual(row['usage_accounting'],'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')
        self.assertEqual(row['cost_reservation_microunits'],1000000)

    def test_unknown_history_cannot_be_refreshed_or_identity_updated(self):
        self.call(None);before=copy.deepcopy(self.ledger_value()['requests'])
        with self.assertRaises(resources.ResourceGateDenied): self.refresh()
        self.assertEqual(before,self.ledger_value()['requests'])
        auth=self.load();auth['_previous']=dict(auth);auth['child_baseline_checkpoint_sha256']=resources.digest(gate._checkpoint_path(self.ledger).read_bytes())
        with self.assertRaises(resources.ResourceGateDenied):gate._activate_validated(auth,self.env,offline=True)
        self.assertEqual(before,self.ledger_value()['requests'])

    def test_consumed_history_keeps_five_calls_and_caps(self):
        ledger=self.ledger_value();ledger['requests']=[dict(number=i+1,request_id=str(i),provider='deepseek' if i<4 else 'openai',model='deepseek-flash' if i<4 else 'gpt-5.6-sol',mission_id=gate.NEW_MISSION,authorization_sha256=self.env['CMH_RESOURCE_AUTH_SHA256'],status='RETURNED',reported_usage='UNKNOWN' if i==4 else {'tokens':{}},usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS' if i==4 else 'FULL_RESERVATION_RETAINED',token_reservation={k:1 for k in gate.CATEGORIES},cost_reservation_microunits=400000 if i<4 else 1000000) for i in range(5)]
        gate._write_child(self.ledger,ledger,self.key.read_bytes());before=copy.deepcopy(ledger['requests'])
        with self.assertRaises(resources.ResourceGateDenied):self.reserve()
        rows=self.ledger_value()['requests'];self.assertEqual(rows,before)
        self.assertEqual((100-sum(r['provider']=='deepseek' for r in rows),103-sum(r['provider']=='openai' for r in rows),203-len(rows)),(96,102,198))

    def test_new_runtime_invalidates_old_qualification_binding(self):
        auth=self.load();binding=gate.qualification_binding(auth)
        auth['runtime']=dict(auth['runtime'],head='f'*40)
        with self.assertRaises(resources.ResourceGateDenied):gate.validate_qualification_binding(binding,auth)
