"""Bounded Direct adapter security regressions. All responses are synthetic."""
import copy
import io
import json
import multiprocessing
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

from harness import deepseek_direct as direct, model_qualification as qualification
from harness import formal_delivery_gate as gate
from harness.resource_gate import ResourceGateDenied, _active_reservation, normalize_direct_deepseek_usage
from harness.model_registry import load_registry
from harness.review_resume import ReviewRun
from direct_deepseek_fixture import KEY, USAGE, response, envelope, reserved_transport

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_deepseek as reviewer
import deepseek_review as storage

SCHEMA = reviewer.CHUNK_SCHEMA


class DirectTransportTests(unittest.TestCase):
    def test_success_exact_request_and_identity(self):
        with reserved_transport() as (active, send):
            raw = direct.invoke('fixture prompt', KEY, SCHEMA)
            bound = direct.validate_envelope(raw, schema=SCHEMA, prompt='fixture prompt')
            send.assert_called_once()
            payload, key, timeout = send.call_args.args
            request = json.loads(payload)
            self.assertEqual(key, KEY)
            self.assertEqual(request['model'], 'deepseek-flash')
            self.assertEqual(request['max_tokens'], 90000)
            self.assertFalse(request['stream'])
            self.assertEqual(request['response_format'], {'type': 'json_object'})
            self.assertNotIn(KEY, raw.decode())
            self.assertEqual(bound['direct_completion']['finish_reason'], 'stop')
            self.assertEqual(active.observed['tokens'], dict(input=8, cache=2, output=5, reasoning=3))
            with self.assertRaises(direct.DirectFailure):
                direct.invoke('another prompt', KEY, SCHEMA)
            self.assertEqual(send.call_count, 1)

    def test_one_http_post_no_redirect_or_retry(self):
        for status in (200, 301, 302, 307, 308, 401, 402, 429, 500, 503):
            with self.subTest(status=status):
                conn = Mock(); conn.sock = None
                result = Mock(status=status); result.read.side_effect = [b'{}', b'']
                conn.getresponse.return_value = result
                with patch.object(direct.http.client, 'HTTPSConnection', return_value=conn):
                    actual, body = direct._post_once(b'{}', KEY, 5)
                self.assertEqual(actual, status)
                conn.request.assert_called_once()
                self.assertEqual(conn.request.call_args.args[:2], ('POST', '/chat/completions'))
                conn.close.assert_called_once()
                if status != 200:
                    result.read.assert_not_called()
                    self.assertEqual(body, b'')

    def test_network_failure_never_second_send(self):
        for error in (TimeoutError(KEY), OSError(KEY)):
            conn = Mock(); conn.request.side_effect = error
            with patch.object(direct.http.client, 'HTTPSConnection', return_value=conn):
                with self.assertRaises(type(error)):
                    direct._post_once(b'{}', KEY, 5)
            conn.request.assert_called_once()
            conn.close.assert_called_once()

    def test_worker_sanitizes_exception_and_reaps(self):
        before = {p.pid for p in multiprocessing.active_children()}
        with patch.object(direct, '_post_once', side_effect=OSError(KEY)):
            with self.assertRaises(direct.DirectFailure) as caught:
                direct._bounded_post(b'{}', KEY, 1)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_closed_parent_pipe_cannot_print_secret_traceback(self):
        pipe = Mock(); pipe.send.side_effect = BrokenPipeError(KEY)
        pipe.close.side_effect = OSError(KEY)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(direct, '_post_once', side_effect=OSError(KEY)), \
             redirect_stdout(out), redirect_stderr(err):
            direct._worker(pipe, b'{}', KEY, 1)
        self.assertEqual(out.getvalue() + err.getvalue(), '')
        self.assertEqual(pipe.send.call_count, 1)

    def test_deadline_kills_background_worker(self):
        before = {p.pid for p in multiprocessing.active_children()}
        with patch.object(direct, '_post_once', side_effect=lambda *_: time.sleep(5)):
            start = time.monotonic()
            with self.assertRaises(direct.DirectFailure):
                direct._bounded_post(b'{}', KEY, .05)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_redirect_http_errors_and_timeouts_terminal_single_attempt(self):
        for status in (301, 302, 307, 308, 401, 402, 429, 500, 503):
            with self.subTest(status=status), reserved_transport(status=status) as (active, send):
                with self.assertRaises(direct.DirectFailure) as caught:
                    direct.invoke('prompt', KEY, SCHEMA)
                self.assertFalse(caught.exception.retryable)
                send.assert_called_once()
                self.assertIsNone(active.observed)  # no invented zero usage
        for error in (direct.DirectFailure('REQUEST_TIMEOUT'), OSError(KEY)):
            with reserved_transport(error=error) as (active, send):
                with self.assertRaises(direct.DirectFailure) as caught:
                    direct.invoke('prompt', KEY, SCHEMA)
                send.assert_called_once()
                self.assertIsNone(active.observed)
                self.assertNotIn(KEY, str(caught.exception))

    def test_length_with_valid_schema_json_is_failure(self):
        with reserved_transport(response({'findings': []}, finish='length')) as (active, send):
            with self.assertRaises(direct.DirectFailure) as caught:
                direct.invoke('prompt', KEY, SCHEMA)
            self.assertEqual(caught.exception.code, 'INCOMPLETE_COMPLETION')
            self.assertIsNotNone(active.observed)  # real usage remains charged
            send.assert_called_once()

    def test_missing_unknown_incomplete_statuses_fail_closed(self):
        for finish in (None, '', 'unknown', 'max_tokens', 'incomplete', 'content_filter', 'tool_calls'):
            value = response({'findings': []}, finish=finish)
            if finish is None:
                del value['choices'][0]['finish_reason']
            with self.subTest(finish=finish), reserved_transport(value) as (_, send):
                with self.assertRaises(direct.DirectFailure):
                    direct.invoke('prompt', KEY, SCHEMA)
                send.assert_called_once()

    def test_empty_malformed_incomplete_schema_and_reasoning_starvation(self):
        cases = [('', 'stop'), ('{', 'stop'), ('{}', 'stop'),
                 ('{"findings":"wrong"}', 'stop'), ('{"findings":[', 'length'), ('', 'length')]
        for content, finish in cases:
            value = response({}, finish=finish)
            value['choices'][0]['message']['content'] = content
            with self.subTest(content=content, finish=finish), reserved_transport(value) as (_, send):
                with self.assertRaises(direct.DirectFailure):
                    direct.invoke('prompt', KEY, SCHEMA)
                send.assert_called_once()

    def test_bad_usage_and_invocation_identity(self):
        for mutation in ('missing', 'bool', 'partition', 'reasoning', 'total', 'cap', 'model', 'choices', 'tools'):
            value = copy.deepcopy(response({'findings': []}))
            if mutation == 'missing': value.pop('usage')
            elif mutation == 'bool': value['usage']['prompt_tokens'] = True
            elif mutation == 'partition': value['usage']['prompt_cache_hit_tokens'] = 11
            elif mutation == 'reasoning': value['usage']['completion_tokens_details']['reasoning_tokens'] = 6
            elif mutation == 'total': value['usage']['total_tokens'] = direct.MAX_CONTEXT + 1
            elif mutation == 'cap': value['usage'].update(completion_tokens=90001, total_tokens=90011)
            elif mutation == 'model': value['model'] = 'another-model'
            elif mutation == 'choices': value['choices'] *= 2
            elif mutation == 'tools': value['choices'][0]['message']['tool_calls'] = [{}]
            with self.subTest(mutation=mutation), reserved_transport(value) as (_, send):
                with self.assertRaises(direct.DirectFailure):
                    direct.invoke('prompt', KEY, SCHEMA)
                send.assert_called_once()

    def test_invalid_cap_and_request_fail_before_send(self):
        for cap in (0, -1, True, 90001, 128000, '90000'):
            with self.subTest(cap=cap), reserved_transport() as (_, send):
                with self.assertRaises(direct.DirectFailure):
                    direct.invoke('prompt', KEY, SCHEMA, max_tokens=cap)
                send.assert_not_called()
        for key in (None, '', 'bad\nkey', '中文'):
            with reserved_transport() as (_, send):
                with self.assertRaises(direct.DirectFailure):
                    direct.invoke('prompt', key, SCHEMA)
                send.assert_not_called()

    def test_secret_echo_plain_and_json_escaped_never_published(self):
        for escaped in (False, True):
            value = response({'findings': []})
            value['usage']['unexpected'] = KEY
            body = direct.canonical(value)
            if escaped:
                body = body.replace(KEY.encode(), ''.join('\\u%04x' % ord(c) for c in KEY).encode())
            with reserved_transport() as (active, send):
                send.return_value = (200, body)
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    with self.assertRaises(direct.DirectFailure) as caught:
                        direct.invoke('prompt', KEY, SCHEMA)
                self.assertIsNone(active.observed)
                self.assertNotIn(KEY, out.getvalue() + err.getvalue() + str(caught.exception))

    def test_usage_partition_reasoning_not_double_charged(self):
        usage = normalize_direct_deepseek_usage(USAGE)
        self.assertEqual(usage['tokens']['output'], 5)
        self.assertEqual(usage['tokens']['reasoning'], 3)
        self.assertEqual(usage['tokens']['input'] + usage['tokens']['cache'], 10)
        self.assertNotIn('raw_model_usage', usage)
        self.assertEqual(usage['provider_max_tokens'], 90000)

    def test_unreserved_or_synthetic_transport_is_denied(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(direct, '_bounded_post') as send:
            with self.assertRaises(ResourceGateDenied):
                direct.invoke('prompt', KEY, SCHEMA)
            send.assert_not_called()
        from types import SimpleNamespace
        token = _active_reservation.set(SimpleNamespace(execution_allowed=False))
        try:
            with patch.object(direct, '_bounded_post') as send:
                with self.assertRaises(ResourceGateDenied):
                    direct.invoke('prompt', KEY, SCHEMA)
                send.assert_not_called()
        finally:
            _active_reservation.reset(token)

    def test_legacy_formal_cli_cannot_send(self):
        for mission in (gate.NEW_MISSION, gate.OLD_MISSION):
            with patch.dict('os.environ', {'CMH_RESOURCE_MISSION_ID': mission}), patch.object(storage.subprocess, 'Popen') as send:
                with self.assertRaises(ResourceGateDenied):
                    storage._invoke_reviewer_unmetered(['claude', '--model', direct.MODEL], 'prompt', {}, 1)
                send.assert_not_called()


class DirectEvidenceTests(unittest.TestCase):
    def test_persisted_status_runtime_and_request_revalidated(self):
        raw = envelope({'findings': []}, 'prompt', SCHEMA)
        direct.validate_envelope(raw, schema=SCHEMA, prompt='prompt')
        for field, replacement in (('finish_reason', 'length'), ('model', 'wrong'),
                ('provider_id', ''), ('request_sha256', '0' * 64),
                ('schema_sha256', '0' * 64), ('prompt_sha256', '0' * 64), ('transport', {})):
            value = json.loads(raw); value['direct_completion'][field] = replacement
            with self.subTest(field=field), self.assertRaises(direct.DirectFailure):
                direct.validate_envelope(direct.canonical(value), schema=SCHEMA, prompt='prompt')

    def test_formal_missing_evidence_cannot_parse(self):
        with patch.dict('os.environ', {'CMH_RESOURCE_MISSION_ID': gate.NEW_MISSION}):
            with self.assertRaises(reviewer.ReviewStageFailure):
                reviewer._parse_stage('{"findings":[]}', reviewer.parse_chunk, {'stage': 'chunk'})

    def test_cap_artifact_never_commits_or_publishes_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir()
            run = ReviewRun(Path(tmp) / 'evidence', root, {'transport': direct.identity()},
                            [('chunk-000', 'chunk')], storage, prefix='offline-')
            try:
                raw = envelope({'findings': []}, 'prompt', SCHEMA, finish='length')
                with self.assertRaises(reviewer.ReviewStageFailure):
                    run.stage('chunk-000', 'chunk', b'prompt', lambda: raw,
                              lambda data: reviewer._parse_stage(data.decode(), reviewer.parse_chunk, {'stage': 'chunk'}))
                self.assertFalse(run.state['completed'])
                self.assertFalse(run.state['final_completed'])
                with self.assertRaises(ValueError):
                    run.receipt('receipt.json', b'{"review_result":"PASS"}', lambda: None)
                self.assertFalse((run.path / 'receipt.json').exists())
                self.assertTrue(run.state['diagnostic_artifacts'])
                run_id = run.state['review_run_id']
            finally:
                run.close()
            resumed = ReviewRun(Path(tmp) / 'evidence', root, {'transport': direct.identity()},
                                [('chunk-000', 'chunk')], storage, prefix='offline-')
            try:
                self.assertEqual(resumed.state['review_run_id'], run_id)
                self.assertFalse(resumed.state['completed'])
            finally:
                resumed.close()

    def test_qualification_four_cases_same_adapter_and_cap_failure(self):
        spec = load_registry().role('independent_reviewer')
        calls = []
        def invoke(_spec, prompt):
            case = next(c for c in qualification.CASES if qualification.qualification_prompt(c) == prompt)
            decisions = []
            for label, decision in case.expected.items():
                finding = qualification.expected_findings(case)[int(label[1:])-1]
                decisions.append({'finding_id': finding['finding_id'], 'decision': decision,
                    'rationale': 'The exact source establishes this semantic decision.',
                    'source_quote': case.source.splitlines()[1] if decision == 'DISPUTED' else '',
})
            output = {'findings': [], 'decisions': decisions, 'summary': 'Offline semantic case checked against the exact source.'}
            with reserved_transport(response(output)) as (_, send):
                result = qualification._actual_provider_invoke_unmetered(spec, prompt, token=KEY, timeout=1)
                calls.append(json.loads(send.call_args.args[0]))
                return result
        result = qualification._evaluate_cases(spec, invoke, mode='real_provider')
        self.assertTrue(result.passed)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(c['max_tokens'] == 90000 and c['model'] == direct.MODEL for c in calls))
        def cap(_spec, prompt):
            with reserved_transport(response({'findings': [], 'decisions': [],
                    'summary': 'Completely valid synthetic qualification response.'}, finish='length')) as (_, send):
                try:
                    return qualification._actual_provider_invoke_unmetered(spec, prompt, token=KEY, timeout=1)
                finally:
                    send.assert_called_once()
        result = qualification._evaluate_cases(spec, cap, mode='real_provider')
        self.assertFalse(result.passed)
        self.assertEqual(result.cases_failed, ('clean',))
        with self.assertRaises(ValueError):
            qualification.qualification_receipt(result, auth_key='OFFLINE-SIGNER', role='independent_reviewer')

    def test_committed_checkpoint_revalidates_completion_before_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'; root.mkdir()
            identity = {'transport': direct.identity()}
            run = ReviewRun(Path(tmp) / 'evidence', root, identity,
                            [('chunk-000', 'chunk')], storage, prefix='offline-')
            validate = lambda data: reviewer._parse_stage(data.decode(), reviewer.parse_chunk,
                                                         {'stage': 'chunk'}, prompt='prompt')
            good = envelope({'findings': []}, 'prompt', SCHEMA)
            run.stage('chunk-000', 'chunk', b'prompt', lambda: good, validate)
            # Simulate a recomputed artifact/checkpoint hash: status validation
            # must still reject, independently of the durable hash check.
            bad = envelope({'findings': []}, 'prompt', SCHEMA, finish='length')
            run.state['completed']['chunk-000'].update(artifact_sha256=direct.digest(bad), output_hash=direct.digest(bad))
            (run.path / 'chunk-000.json').write_bytes(bad)
            from harness.review_resume import _atomic_state
            _atomic_state(run.fd, run.state)
            run.close()
            resumed = ReviewRun(Path(tmp) / 'evidence', root, identity,
                                [('chunk-000', 'chunk')], storage, prefix='offline-')
            try:
                with patch.object(direct, 'invoke') as send:
                    with self.assertRaises(reviewer.ReviewStageFailure):
                        resumed.stage('chunk-000', 'chunk', b'prompt', send, validate)
                    send.assert_not_called()
            finally:
                resumed.close()

    def test_source_binding_failure_is_not_an_automatic_retry(self):
        finding = {'severity': 'P1', 'title': 'Synthetic issue', 'evidence': 'Exact source'}
        expected = reviewer.bind_findings([finding], 'C', 0)
        output = {'findings': [], 'decisions': [{
            'finding_id': expected[0]['finding_id'], 'decision': 'DISPUTED',
            'rationale': 'The source reference must match the exact group identity.',
            'source_quote': 'uniquely matching source text', 'source_id': '0' * 64}],
            'summary': 'A synthetic response with invalid source binding.'}
        raw = envelope(output, 'prompt', reviewer.SYNTHESIS_SCHEMA)
        state = {'stage': 'group', 'stage_id': 'group-000.json'}
        with self.assertRaises(reviewer.ReviewStageFailure):
            reviewer._parse_stage(raw.decode(), lambda value: reviewer.parse_synthesis(
                value, expected, source=b'uniquely matching source text', structured_evidence=True),
                state, prompt='prompt')
        self.assertFalse(state['resume_allowed'])
        self.assertEqual(state['source_binding_diagnostic']['error_subclass'], 'SOURCE_ID_MISMATCH')

    def test_old_mission_cannot_be_migrated_by_direct_transport(self):
        with patch.dict('os.environ', {'CMH_RESOURCE_MISSION_ID': gate.OLD_MISSION}), \
             patch('harness.resource_gate.reserve') as reserve:
            with self.assertRaises(ResourceGateDenied):
                direct.invoke('prompt', KEY, SCHEMA)
            reserve.assert_not_called()

    def test_runtime_includes_direct_adapter(self):
        self.assertIn('src/harness/deepseek_direct.py', gate.RUNTIME_FILES)
        result = qualification.QualificationResult(load_registry().role('independent_reviewer').identity(),
                     'real_provider', tuple(c.name for c in qualification.CASES), (), ('0' * 64,) * 4)
        receipt = qualification.qualification_receipt(result, auth_key='OFFLINE-SIGNER', role='independent_reviewer')
        self.assertEqual(receipt['invocation_sha256'], direct.identity()['adapter_sha256'])


if __name__ == '__main__':
    unittest.main()
