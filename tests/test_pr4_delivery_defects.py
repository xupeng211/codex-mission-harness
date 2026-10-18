"""Bounded PR4 regressions: synthetic keys/ledgers and mocked provider transport only."""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import deepseek_review as storage
import reviewer_v2_deepseek as deepseek
import reviewer_v2_openai as openai
import reviewer_v2_gate as cli
import test_verified_failed_wallet_settlement as wallet_fixture
from direct_deepseek_fixture import envelope
from harness import artifact_lineage as lineage, formal_delivery_gate as gate
from harness import openai_invocation as invocation, resource_gate as resources
from harness.model_registry import ModelSpec
from harness.review_resume import ReviewRun
from harness.resource_gate import canonical, digest, sign_authorization, ResourceGateDenied


def signed_openai_usage(root, key, auth, row, response):
    """Real signed raw transport proof; production verify_openai_usage is never mocked."""
    directory = root / row['request_id']
    directory.mkdir(mode=0o700)
    raw_usage = dict(input_tokens=5, cached_input_tokens=2, output_tokens=3,
                     reasoning_output_tokens=1)
    stdout = b'\n'.join(canonical(e) for e in [
        dict(type='thread.started', thread_id='offline-thread-' + row['request_id']),
        dict(type='turn.started'),
        dict(type='item.completed', item=dict(id='offline-message', type='agent_message',
                                             text=response.decode())),
        dict(type='turn.completed', usage=raw_usage)]) + b'\n'
    files = {}
    for name, raw in [('stdout.jsonl', stdout), ('stderr', b''), ('response.json', response)]:
        path = directory / name
        path.write_bytes(raw); path.chmod(0o600)
        files[name] = dict(path=str(path), sha256=digest(raw))
    binding = dict(request_id=row['request_id'], authorization_sha256=row['authorization_sha256'],
                   runtime_sha256=digest(canonical(auth['runtime'])),
                   model=auth['runtime']['models']['openai'], prompt_sha256=row['prompt_sha256'],
                   command_sha256='f' * 64, files=files)
    path = directory / 'binding.json'
    path.write_bytes(canonical(sign_authorization(binding, key))); path.chmod(0o600)
    usage = dict(invocation.normalize_openai_usage(raw_usage),
                 transport_binding=dict(path=str(path), sha256=digest(path.read_bytes())),
                 thread_id='offline-thread-' + row['request_id'], turn_ordinal=1,
                 agent_message_id='offline-message', response_sha256=digest(response))
    return usage, stdout


class AcceptedRequestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        self.key = self.root / 'key'; self.key.write_bytes(b'OFFLINE-PR4'); self.key.chmod(0o600)
        self.spec = ModelSpec('openai', 'gpt-5.6-sol', 'high')
        self.auth_sha = 'a' * 64
        self.auth = dict(_authorization_sha256=self.auth_sha,
                         runtime=dict(models=dict(openai=self.spec.identity())))
        self.rows = []; self.ledger = self.root / 'ledger.json'; self.persist()
        self.identity = dict(provider='openai', source_binding_contract_authorization_sha256=self.auth_sha)
        self.env = dict(CMH_RESOURCE_MISSION_ID=gate.NEW_MISSION,
                        CMH_RESOURCE_LEDGER=str(self.ledger), CMH_RESOURCE_GATE_KEY_FILE=str(self.key))
        self.mocks = [patch.dict(os.environ, self.env, clear=True),
                      patch.object(gate, 'load_authorization', return_value=self.auth),
                      patch.object(gate, 'require_review_authority'),
                      patch.object(lineage, 'origin_authority', side_effect=lambda *a: (self.auth, {'requests': self.rows}))]
        for mock in self.mocks: mock.start(); self.addCleanup(mock.stop)
        self.source = b'+value = 2\n'
        self.blockers = [dict(finding_id='C000F000', severity='P2', title='offline blocker', evidence='value')]
        self.prompt = openai._prompt('GROUP REVIEW', base='1' * 40, head='2' * 40,
                                     diff=self.source, ids=self.blockers).encode()
        decision = dict(finding_id='C000F000', decision='UPHELD', source_quote='', source_id='',
                        rationale='The exact source retains the original concrete blocker.')
        self.good = canonical(dict(findings=[], decisions=[decision],
                                   summary='The original blocker remains in this exact source.'))
        self.bad = canonical(dict(findings=[], decisions=[dict(decision, decision='DISPUTED',
                                   source_quote='absent quote', source_id=digest(self.source))],
                                  summary='This dispute cannot be supported by the supplied source.'))

    def persist(self):
        gate._write_child(self.ledger, {'requests': self.rows}, self.key.read_bytes())

    def open(self):
        return ReviewRun(self.root / 'evidence', self.repo, self.identity,
                         [('group-000', 'group')], storage, prefix='openai-v2-')

    def validate(self, raw):
        result = openai._result(raw, group=True)
        openai._decide(self.blockers, result, self.source)
        return result

    def execute(self, run, response):
        row = dict(request_id='request-' + str(len(self.rows) + 1), number=len(self.rows) + 1,
                   run_id=run.state['review_run_id'], stage='group-000', provider='openai',
                   model=self.spec.model, authorization_sha256=self.auth_sha,
                   prompt_sha256=digest(self.prompt), status='STARTED',
                   token_reservation={k: 10 for k in gate.CATEGORIES}, cost_reservation_microunits=1000000)
        self.rows.append(row); self.persist()
        usage, stdout = signed_openai_usage(self.root, self.key.read_bytes(), self.auth, row, response)
        def transport(_prompt, _spec, _schema, **kwargs):
            token = resources._active_reservation.set(SimpleNamespace(
                request_id=row['request_id'], authorization_sha256=self.auth_sha))
            try: kwargs['transport_sink'](self.prompt, stdout, b'')
            finally: resources._active_reservation.reset(token)
            row.update(status='RETURNED', reported_usage=usage, usage_accounting='FULL_RESERVATION_RETAINED')
            self.persist()
            return invocation.InvocationResult(response.decode(), {'usage': usage})
        with patch.object(openai, 'invoke_openai', side_effect=transport):
            return openai.invoke_codex(self.prompt.decode(), self.spec, stage='group',
                transport_sink=lambda p, out, err: run.capture_transport('group-000', p, out, err))

    def complete(self, retry=False):
        run = self.open()
        if retry:
            with self.assertRaisesRegex(ValueError, 'bound source reference'):
                run.stage('group-000', 'group', self.prompt, lambda: self.execute(run, self.bad), self.validate)
            run.failure(dict(failure_category='REVIEW_RESULT_INVALID', resume_allowed=True,
                             resume_policy_reason='bounded source binding retry'))
            path = run.path; run.close(); run = self.open(); self.assertEqual(run.path, path)
        run.stage('group-000', 'group', self.prompt, lambda: self.execute(run, self.good), self.validate)
        return run

    def history(self, run):
        lineage.review_history(run.state, lambda name: storage.read_private_artifact(run.fd, name))

    def test_single_call(self):
        run = self.complete(); self.addCleanup(run.close)
        self.history(run)

    def test_source_binding_retry_receipt_and_resume(self):
        run = self.complete(retry=True)
        before = canonical(self.rows)
        self.history(run)  # Old code rejects the two genuinely RETURNED calls here.
        accepted = run.state['completed']['group-000']['accepted_request']
        self.assertEqual(accepted['request_id'], self.rows[1]['request_id'])
        self.assertEqual(accepted['response_sha256'], digest(self.good))
        failed, = run.path.glob('group-000-failed-raw-*.json')
        self.assertEqual(json.loads(failed.read_bytes())['resource_request']['request_id'], self.rows[0]['request_id'])
        self.assertEqual(len(list(run.path.glob('group-000-transport-*.json'))), 2)
        path = run.path; run.close(); resumed = self.open(); self.addCleanup(resumed.close)
        self.assertEqual(resumed.path, path); self.history(resumed)
        resumed.stage('group-000', 'group', self.prompt,
                      lambda: self.fail('resume must not invoke a provider'), self.validate)
        receipt = resumed.receipt('receipt.json', b'{"result":"FAIL"}', lambda: self.history(resumed))
        self.assertTrue(receipt.exists()); self.assertEqual(before, canonical(self.rows))

    def test_bound_request_cannot_be_replaced_by_latest_returned(self):
        run = self.complete(); self.addCleanup(run.close)
        # A later call with identical response must not replace the actual accepted request.
        self.execute(run, self.good)
        self.history(run)
        self.assertEqual(run.state['completed']['group-000']['accepted_request']['request_id'], 'request-1')

    def test_wrong_binding_and_cross_identity_fail_closed(self):
        run = self.complete(); self.addCleanup(run.close)
        record = run.state['completed']['group-000']
        for key in ('request_id', 'response_sha256', 'authorization_sha256', 'run_id', 'stage', 'provider', 'prompt_sha256'):
            with self.subTest(binding=key):
                original = copy.deepcopy(record['accepted_request'])
                record['accepted_request'][key] = 'wrong'
                with self.assertRaises(ValueError): self.history(run)
                record['accepted_request'] = copy.deepcopy(original)
                record['accepted_request'][key] = None
                with self.assertRaises(ValueError): self.history(run)
                record['accepted_request'] = original
        for key, wrong in [('run_id', 'other-run'), ('stage', 'chunk-000'), ('provider', 'deepseek'),
                           ('authorization_sha256', 'b' * 64), ('prompt_sha256', 'other-prompt'),
                           ('status', 'UNKNOWN'), ('reported_usage', 'UNKNOWN'),
                           ('usage_accounting', 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')]:
            old = self.rows[0][key]; self.rows[0][key] = wrong
            with self.subTest(row=key), self.assertRaises(ValueError): self.history(run)
            self.rows[0][key] = old
        usage = self.rows[0]['reported_usage']; old = usage['tokens']['output']; usage['tokens']['output'] += 1
        with self.assertRaises(ValueError): self.history(run)
        usage['tokens']['output'] = old
        self.rows.append(copy.deepcopy(self.rows[0]))
        with self.assertRaises(ValueError): self.history(run)

    def test_response_tamper_and_missing_binding_fail_closed(self):
        run = self.complete(); self.addCleanup(run.close)
        record = run.state['completed']['group-000']; accepted = record.pop('accepted_request')
        with self.assertRaises(ValueError): self.history(run)
        record['accepted_request'] = accepted
        path = run.path / record['artifact_path']; path.write_bytes(self.bad)
        # Even if local artifact hashes are recomputed, signed response evidence must still reject it.
        record.update(artifact_sha256=digest(self.bad), output_hash=digest(self.bad))
        with self.assertRaises(ValueError): self.history(run)

    def test_legacy_single_call_still_requires_unique_signed_evidence(self):
        run = self.complete(); self.addCleanup(run.close)
        run.state.pop('accepted_request_binding_version')
        run.state['completed']['group-000'].pop('accepted_request')
        self.history(run)
        self.execute(run, self.good)
        with self.assertRaises(ValueError): self.history(run)

    def test_resume_rejects_persisted_wrong_request_binding(self):
        run = self.complete(); path = run.path; run.close()
        state = json.loads((path / 'state.json').read_bytes())
        state['completed']['group-000']['accepted_request']['request_id'] = 'wrong-request'
        (path / 'state.json').write_bytes(canonical(state))
        with self.assertRaises(ValueError): self.open()

    def test_missing_or_ambiguous_transport_cannot_commit(self):
        run = self.open(); self.addCleanup(run.close)
        with self.assertRaises(ValueError):
            run.stage('group-000', 'group', self.prompt, lambda: self.good, self.validate)
        def duplicate_transport():
            raw = self.execute(run, self.good)
            run.capture_transport('group-000', self.prompt, b'extra', b'')
            return raw
        with self.assertRaises(ValueError):
            run.stage('group-000', 'group', self.prompt, duplicate_transport, self.validate)
        self.assertEqual(run.state['completed'], {})
        self.assertFalse((run.path / 'receipt.json').exists())

    def test_runner_publishes_real_receipt_after_bounded_source_binding_retry(self):
        def git(*args): return subprocess.check_output(['git', '-C', str(self.repo), *args]).decode().strip()
        git('init', '-q'); git('config', 'user.email', 'offline@example.invalid'); git('config', 'user.name', 'Offline')
        git('remote', 'add', 'origin', 'git@github.com:example/harness.git')
        (self.repo / 'source.py').write_text('value = 1\n'); git('add', '.'); git('commit', '-qm', 'base')
        base = git('rev-parse', 'HEAD')
        (self.repo / 'source.py').write_text('value = 2\n'); git('add', '.'); git('commit', '-qm', 'head')
        head = git('rev-parse', 'HEAD'); calls = []; group_calls = []
        def transport(prompt, spec, schema, **kwargs):
            stage = os.environ['CMH_RESOURCE_STAGE']; calls.append(stage)
            if stage == 'group-000':
                response = self.bad if not group_calls else self.good; group_calls.append(stage)
            elif stage == 'chunk-000':
                response = canonical(dict(findings=[dict(severity='P2', title='offline blocker', evidence='source.py')]))
            else: response = b'{"findings":[]}'
            row = dict(request_id='runner-request-' + str(len(self.rows) + 1),
                       run_id=os.environ['CMH_RESOURCE_RUN_ID'], stage=stage, provider='openai',
                       model=spec.model, authorization_sha256=self.auth_sha,
                       prompt_sha256=digest(prompt.encode()), status='STARTED',
                       token_reservation={k: 10 for k in gate.CATEGORIES}, cost_reservation_microunits=1000000)
            self.rows.append(row); self.persist()
            usage, stdout = signed_openai_usage(self.root, self.key.read_bytes(), self.auth, row, response)
            token = resources._active_reservation.set(SimpleNamespace(
                request_id=row['request_id'], authorization_sha256=self.auth_sha))
            try: kwargs['transport_sink'](prompt.encode(), stdout, b'')
            finally: resources._active_reservation.reset(token)
            row.update(status='RETURNED', reported_usage=usage, usage_accounting='FULL_RESERVATION_RETAINED')
            self.persist()
            return invocation.InvocationResult(response.decode(), {'usage': usage})
        evidence = self.root / 'runner-evidence'
        with patch.object(openai, 'invoke_openai', side_effect=transport), \
             patch.object(openai, 'preflight'), \
             patch.object(openai, 'validate_qualification_receipt', return_value={}), \
             patch.object(gate, 'bind_review', return_value=None), \
             patch.object(openai, 'contract_authorization_identity', return_value=self.auth_sha), \
             patch.object(lineage, 'authority_matches', return_value=True), \
             patch.object(lineage, 'artifact_code_hash', side_effect=lambda path, _: digest(path.read_bytes())):
            with self.assertRaisesRegex(ValueError, 'bound source reference'):
                openai.run(self.repo, base, head, evidence, 'OFFLINE-RECEIPT-KEY', self.spec,
                           mission_id=gate.NEW_MISSION, qualification_path='offline-fixture')
            self.assertFalse(list(evidence.rglob('receipt.json')))
            receipt_path = openai.run(self.repo, base, head, evidence, 'OFFLINE-RECEIPT-KEY', self.spec,
                                     mission_id=gate.NEW_MISSION, qualification_path='offline-fixture')
            receipt = json.loads(receipt_path.read_bytes())
            openai.validate(receipt, root=self.repo, base=base, head=head, spec=self.spec,
                            auth_key='OFFLINE-RECEIPT-KEY', receipt_path=receipt_path, mission_id=gate.NEW_MISSION)
        self.assertEqual(calls, ['structured-preflight', 'chunk-000', 'group-000', 'group-000'])
        self.assertTrue(all(row['status'] == 'RETURNED' for row in self.rows))
        self.assertEqual(receipt['review_result'], 'FAIL')  # The UPHELD blocker still blocks approval.
        state = json.loads((receipt_path.parent / 'state.json').read_bytes())
        self.assertEqual(state['completed']['group-000']['accepted_request']['request_id'], self.rows[-1]['request_id'])
        self.assertEqual(len(list(receipt_path.parent.glob('group-000-failed-raw-*.json'))), 1)


class MixedWalletTests(unittest.TestCase):
    setUp = wallet_fixture.VerifiedFailedWalletTests.setUp
    write = wallet_fixture.VerifiedFailedWalletTests.write
    publish = wallet_fixture.VerifiedFailedWalletTests.publish
    load = wallet_fixture.VerifiedFailedWalletTests.load
    ledger_value = wallet_fixture.VerifiedFailedWalletTests.ledger_value
    refresh = wallet_fixture.VerifiedFailedWalletTests.refresh
    reserve_ds = wallet_fixture.VerifiedFailedWalletTests.reserve_ds
    snapshot = wallet_fixture.VerifiedFailedWalletTests.snapshot
    terminal = wallet_fixture.VerifiedFailedWalletTests.terminal
    cover = wallet_fixture.VerifiedFailedWalletTests.cover
    rewrite = wallet_fixture.VerifiedFailedWalletTests.rewrite

    def openai_failed(self):
        reservation = gate._reserve_validated(self.load(), self.env, 'openai', 'gpt-5.6-sol',
                                              b'fixture', 'qualification-case', self.now, offline=True)
        row = self.ledger_value()['requests'][-1]
        usage, _ = signed_openai_usage(self.root, self.key.read_bytes(), self.load(), row, b'{"findings":[]}')
        reservation.observe(usage)
        with patch.object(gate, 'load_authorization', side_effect=lambda: self.load()), \
             patch('harness.resource_gate.time.time', return_value=self.now + 1):
            reservation.settle('FAILED')
        row = self.ledger_value()['requests'][-1]
        self.assertEqual(row['usage_accounting'], 'FULL_RESERVATION_RETAINED')
        return row

    def test_openai_failed_and_deepseek_failed_share_wallet_prefix(self):
        openai_row = self.openai_failed(); deepseek_row = self.terminal()
        before = canonical(self.ledger_value()['requests']); parent = self.parent.read_bytes()
        proofs = gate.verified_failed_wallet_settlements(self.load(), self.ledger_value()['requests'])
        self.assertEqual([p['request_id'] for p in proofs], [deepseek_row['request_id']])
        self.cover(available_microcny=self.bound)
        gate._funding_check(self.load(), self.ledger_value(), self.key.read_bytes(), 'chunk', self.now)
        self.assertEqual(before, canonical(self.ledger_value()['requests']))
        self.assertEqual(parent, self.parent.read_bytes())
        self.assertEqual(self.ledger_value()['requests'][0], openai_row)

    def test_openai_failed_only_needs_its_own_usage_proof(self):
        self.openai_failed(); rows = self.ledger_value()['requests']
        self.assertEqual(gate.verified_failed_wallet_settlements(self.load(), rows), [])
        self.refresh(covered_requests=len(rows), covered_prefix_sha256=digest(canonical(rows)))

    def test_mixed_unknown_started_overage_and_unverified_block(self):
        self.openai_failed(); self.terminal(); original = self.ledger_value()
        for index in (0, 1):
            for changes in [dict(status='UNKNOWN'), dict(status='STARTED'),
                            dict(reported_usage='UNKNOWN', usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS'),
                            dict(usage_accounting='OVER_RESERVATION_BLOCK_FUTURE_CALLS'),
                            dict(usage_accounting='USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS')]:
                ledger = copy.deepcopy(original); ledger['requests'][index].update(changes); self.rewrite(ledger)
                with self.subTest(provider=index, changes=changes), self.assertRaises(ResourceGateDenied): self.cover()
        self.rewrite(original)

    def test_openai_signed_usage_identity_reservation_and_tamper_block(self):
        self.openai_failed(); self.terminal(); original = self.ledger_value()
        for key, wrong in [('provider', 'unknown-provider'), ('model', 'wrong'), ('authorization_sha256', '0' * 64),
                           ('mission_id', 'other'), ('cost_reservation_microunits', 0), ('cost_unit', 'USD'),
                           ('token_reservation', {k: 1 for k in gate.CATEGORIES})]:
            ledger = copy.deepcopy(original); ledger['requests'][0][key] = wrong; self.rewrite(ledger)
            with self.subTest(key=key), self.assertRaises(ResourceGateDenied): self.cover()
        for key in ('response_sha256', 'thread_id'):
            ledger = copy.deepcopy(original); ledger['requests'][0]['reported_usage'][key] = 'wrong'; self.rewrite(ledger)
            with self.subTest(usage=key), self.assertRaises(ResourceGateDenied): self.cover()
        self.rewrite(original)
        ref = original['requests'][0]['reported_usage']['transport_binding']
        binding = gate._signed(ref['path'], ref['sha256'], self.key.read_bytes())
        Path(binding['files']['response.json']['path']).write_bytes(b'{"findings":[{}]}')
        with self.assertRaises(ResourceGateDenied): self.cover()

    def test_mixed_deepseek_invalid_tariff_and_cost_proof_block(self):
        self.openai_failed(); self.terminal(); original = self.ledger_value()
        bad = copy.deepcopy(original); bad['requests'][1]['native_price_identity_sha256'] = '0' * 64
        self.rewrite(bad)
        with self.assertRaises(ResourceGateDenied): self.cover()
        self.rewrite(original)
        proofs = gate.verified_failed_wallet_settlements(self.load(), original['requests'])
        for key in ('row_sha256', 'usage_sha256', 'native_price_identity_sha256', 'actual_usage_cost_upper_microcny'):
            bad = copy.deepcopy(proofs); bad[0][key] = 0 if key.endswith('microcny') else '0' * 64
            with self.subTest(proof=key), self.assertRaises(ResourceGateDenied): self.cover(bad)


class SeparateSigningCLItests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        def git(*args): return subprocess.check_output(['git', '-C', str(self.repo), *args]).decode().strip()
        git('init', '-q'); git('config', 'user.email', 'offline@example.invalid'); git('config', 'user.name', 'Offline')
        git('remote', 'add', 'origin', 'git@github.com:example/harness.git')
        (self.repo / 'source.py').write_text('value = 1\n'); git('add', '.'); git('commit', '-qm', 'base')
        self.base = git('rev-parse', 'HEAD')
        (self.repo / 'source.py').write_text('value = 2\n'); git('add', '.'); git('commit', '-qm', 'head')
        self.head = git('rev-parse', 'HEAD')
        self.token = self.root / 'token'; self.key = self.root / 'auth-key'; self.oa = self.root / 'oa-key'
        for path, value in [(self.token, 'OFFLINE-TOKEN-T'), (self.key, 'OFFLINE-SIGNING-K'), (self.oa, 'OFFLINE-OPENAI')]:
            path.write_text(value); path.chmod(0o600)

    def exercise(self, separate=True, wrong_signature=False):
        args = SimpleNamespace(repo=str(self.repo), base=self.base, head=self.head,
                               evidence=str(self.root / 'evidence'), token_file=str(self.token),
                               auth_key_file=str(self.key) if separate else None,
                               mission_id='offline-pr4', timeout=1, qualification='offline-fixture')
        def transport(prompt, token, schema, **kwargs):
            self.assertEqual(token, self.token.read_text())
            value = dict(findings=[]) if 'Scope=chunk' in prompt else dict(findings=[], decisions=[],
                      summary='The exact source change preserves all relevant behavior.')
            return envelope(value, prompt, schema)
        with patch.object(deepseek, 'validate_qualification_receipt', return_value={}), \
             patch.object(deepseek.direct, 'invoke', side_effect=transport):
            result = deepseek.run(args)
        receipt_path = Path(result['review_receipt'])
        if wrong_signature:
            receipt = json.loads(receipt_path.read_bytes()); receipt['auth_hmac_sha256'] = '0' * 64
            receipt_path.write_bytes(canonical(receipt))
        openai_path = self.root / 'openai.json'; openai_path.write_text('{}'); openai_path.chmod(0o600)
        argv = ['reviewer_v2_gate.py', '--repo', str(self.repo), '--base', self.base, '--head', self.head,
                '--deepseek-receipt', str(receipt_path), '--openai-receipt', str(openai_path),
                '--deepseek-token-file', str(self.token), '--openai-auth-key-file', str(self.oa),
                '--deepseek-qualification', 'offline-ds', '--openai-qualification', 'offline-oa',
                '--mission-id', 'offline-pr4']
        if separate: argv += ['--deepseek-auth-key-file', str(self.key)]
        def gate_boundary(**kwargs):
            kwargs['qualification_validators']['deepseek']()
            try:
                kwargs['deepseek_validator'](kwargs['deepseek_receipt'])  # Real Receipt Validator.
            except ValueError as exc:
                self.validation_error = str(exc)
                raise
            return dict(status='PASS')
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), \
             patch('harness.model_qualification.validate_qualification_receipt', return_value={}) as qualification, \
             patch.object(cli, 'validate_gate', side_effect=gate_boundary), redirect_stdout(output):
            code = cli.main()
        self.assertEqual(qualification.call_args_list[0].kwargs['auth_key'],
                         self.key.read_text() if separate else self.token.read_text())
        return code, json.loads(output.getvalue())

    def test_cli_separate_signing_key_is_used_for_real_receipt_validator(self):
        code, output = self.exercise()
        self.assertEqual(code, 0, getattr(self, 'validation_error', None))
        self.assertEqual(output['status'], 'PASS')

    def test_cli_rejects_wrong_signature(self):
        code, output = self.exercise(wrong_signature=True)
        self.assertEqual(code, 1); self.assertEqual(output['status'], 'BLOCKED_EXTERNAL')
        self.assertEqual(self.validation_error, 'receipt authentication mismatch')

    def test_cli_legacy_same_token_and_signing_key(self):
        code, output = self.exercise(separate=False)
        self.assertEqual(code, 0); self.assertEqual(output['status'], 'PASS')
