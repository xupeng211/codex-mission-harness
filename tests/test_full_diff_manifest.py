"""Full-scope regression fixtures. All model responses are explicitly mocked."""
import copy
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from harness import full_diff_manifest as full
from harness.review_resume import ReviewRun

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_openai as openai
import reviewer_v2_deepseek as deepseek
import reviewer_v2_gate as gate


class FullDiffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Offline Fixture')
        self.git('remote', 'add', 'origin', 'git@github.com:example/harness.git')
        (self.root / 'source.txt').write_text('before\n')
        self.base = self.commit('base')
        self.git('update-ref', 'refs/remotes/origin/main', self.base)
        (self.root / 'source.txt').write_text('after\n')
        self.head = self.commit('head')
        self.repository = 'ssh://github.com/example/harness.git'
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args]).decode().strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def large(self, size=888000):
        (self.root / 'large.txt').write_text(('0123456789abcdef' * 60 + '\n') * (size // 961))
        self.head = self.commit('large single file and hunk')
        return self.manifest()

    def manifest(self):
        return full.build_manifest(self.root, self.base, self.head, self.repository)

    @staticmethod
    def rehash(m):
        m.pop('manifest_sha256', None)
        m['manifest_sha256'] = full.sha256(full.canonical(m))
        return m

    def test_small_diff(self):
        d, m = self.manifest()
        self.assertLess(len(d), 256000)
        self.assertEqual(full.validate_coverage(d, m)['coverage_percentage'], 100)

    def test_above_256kb_without_changing_legacy_limit(self):
        d, m = self.large(300000)
        self.assertGreater(len(d), 256000)
        self.assertEqual(openai.secure.MAX_V2_DIFF_BYTES, 256000)
        self.assertGreater(m['chunk_count'], 8)
        self.assertEqual(full.validate_manifest(self.root, m, self.repository, self.base, self.head)['validator_result'], 'PASS')

    def test_888kb_deterministic_manifest_and_chunks(self):
        d, m = self.large()
        d2, m2 = self.manifest()
        self.assertGreater(len(d), 880000)
        self.assertEqual((d, m), (d2, m2))
        self.assertGreater(len(m['groups']), 3)
        self.assertEqual(b''.join(d[c['start']:c['end']] for c in m['chunks']), d)

    def test_single_file_oversize_is_subdivided(self):
        d, m = self.large(300000)
        record = next(r for r in m['changes'] if r['path'] == 'large.txt')
        self.assertGreater(len(record['chunk_ids']), 8)
        self.assertTrue(all(c['end'] - c['start'] <= full.CHUNK_BYTES for c in m['chunks']))

    def test_single_hunk_oversize_location_context(self):
        d, m = self.large(300000)
        record = next(r for r in m['changes'] if r['path'] == 'large.txt')
        self.assertEqual(len(record['hunks']), 1)
        c = m['chunks'][3]
        self.assertIn('large.txt'.encode().hex(), full.chunk_context(m, c['start'], c['end']))
        self.assertIn(record['hunks'][0]['sha256'], full.chunk_context(m, c['start'], c['end']))

    def test_add_delete_rename_mode_unicode_paths(self):
        (self.root / 'rename old.txt').write_text('unchanged rename content\n' * 20)
        (self.root / 'delete.txt').write_text('deleted\n')
        (self.root / 'mode.sh').write_text('echo fixture\n')
        self.base = self.commit('file types base')
        self.git('mv', 'rename old.txt', '重命名\nnew.txt')
        (self.root / 'delete.txt').unlink()
        (self.root / 'added.txt').write_text('added\n')
        (self.root / 'mode.sh').chmod(0o755)
        self.head = self.commit('types')
        d, m = self.manifest()
        self.assertEqual({r['change_type'][0] for r in m['changes']}, {'A', 'D', 'R', 'M'})
        rename = next(r for r in m['changes'] if r['change_type'][0] == 'R')
        self.assertEqual(rename['old_path_hex'], b'rename old.txt'.hex())
        self.assertEqual(rename['path_hex'], '重命名\nnew.txt'.encode().hex())
        mode = next(r for r in m['changes'] if r['path'] == 'mode.sh')
        self.assertEqual((mode['old_mode'], mode['new_mode']), ('100644', '100755'))
        self.assertTrue(full.validate_coverage(d, m)['review_ready'])

    def test_binary_explicitly_blocks_text_review(self):
        (self.root / 'binary.bin').write_bytes(b'\0\xff' * 100)
        self.head = self.commit('binary')
        d, m = self.manifest()
        self.assertEqual(full.validate_coverage(d, m)['UNSUPPORTED_CHANGE_COUNT'], 1)
        with self.assertRaisesRegex(ValueError, 'specialized'):
            full.validate_manifest(self.root, m, self.repository, self.base, self.head, review_ready=True)

    def test_gitlink_is_never_silently_ignored(self):
        self.git('update-index', '--add', '--cacheinfo', f'160000,{self.base},module')
        self.git('commit', '-qm', 'gitlink')
        self.head = self.git('rev-parse', 'HEAD')
        d, m = self.manifest()
        self.assertEqual(next(r for r in m['changes'] if r['path'] == 'module')['source_kind'], 'gitlink')
        self.assertFalse(full.validate_coverage(d, m)['review_ready'])

    def test_non_utf8_blocks_and_symlink_is_explicit(self):
        (self.root / 'invalid.txt').write_bytes(b'value=\xff\n')
        (self.root / 'link').symlink_to('source.txt')
        self.head = self.commit('non utf8 and symlink')
        d, m = self.manifest()
        self.assertEqual(next(r for r in m['changes'] if r['path'] == 'link')['new_mode'], '120000')
        self.assertFalse(full.validate_coverage(d, m)['review_ready'])

    def test_chunk_boundaries_and_resource_limits(self):
        for size in (1, 31999, 32000, 32001, 96000, 96001, full.MAX_FULL_BYTES):
            with self.subTest(size=size):
                d = b'x' * size
                chunks, groups = full.plan(d)
                self.assertEqual(chunks[0]['start'], 0)
                self.assertEqual(chunks[-1]['end'], size)
                self.assertTrue(all(g['end'] - g['start'] <= full.GROUP_BYTES for g in groups))
        with self.assertRaises(ValueError):
            full.plan(b'x' * (full.MAX_FULL_BYTES + 1))

    def test_chunk_hash_mutation(self):
        d, m = self.manifest(); chunks = copy.deepcopy(m['chunks']); chunks[0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError): full.validate_coverage(d, m, chunks)

    def test_manifest_hash_mutation(self):
        d, m = self.manifest(); m['manifest_sha256'] = '0' * 64
        with self.assertRaises(ValueError): full.validate_coverage(d, m)

    def test_missing_chunk(self):
        d, m = self.large(300000)
        with self.assertRaises(ValueError): full.validate_coverage(d, m, m['chunks'][1:])

    def test_duplicate_chunk(self):
        d, m = self.manifest()
        with self.assertRaises(ValueError): full.validate_coverage(d, m, m['chunks'] * 2)

    def test_missing_canonical_range(self):
        d, m = self.manifest(); m['changes'][0]['start'] += 1; self.rehash(m)
        with self.assertRaises(ValueError): full.validate_coverage(d, m)

    def test_overlapping_canonical_range(self):
        d, m = self.large(300000); m['changes'][1]['start'] = m['changes'][0]['start']; self.rehash(m)
        with self.assertRaises(ValueError): full.validate_coverage(d, m)

    def test_truncated_diff(self):
        d, m = self.manifest()
        with self.assertRaises(ValueError): full.validate_coverage(d[:-1], m)

    def test_uncovered_file_and_hunk_metadata_mutation(self):
        d, m = self.manifest(); m['changes'][0]['hunks'][0]['sha256'] = '0' * 64; self.rehash(m)
        with self.assertRaises(ValueError): full.validate_manifest(self.root, m, self.repository, self.base, self.head)
        d, m = self.manifest(); m['changes'] = []; self.rehash(m)
        with self.assertRaises(ValueError): full.validate_coverage(d, m)

    def test_task_identity_mutations(self):
        d, m = self.manifest(); tasks = full.review_tasks(d, m)
        for key in tasks[0]:
            with self.subTest(key=key):
                altered = copy.deepcopy(tasks); altered[0][key] = 'wrong'
                with self.assertRaises(ValueError): full.validate_tasks(d, m, altered)

    def test_wrong_base_head_diff_and_manifest(self):
        d, m = self.manifest()
        for field, value in [('base_sha', self.head), ('head_sha', self.base),
                             ('full_diff_sha256', 'a' * 64), ('repository', 'other')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(m); changed[field] = value; self.rehash(changed)
                with self.assertRaises(ValueError): full.validate_manifest(self.root, changed, self.repository, self.base, self.head)

    def test_execution_identity_mismatches(self):
        d, m = self.manifest()
        expected = full.execution_identity(m, 'fixture', 'a' * 64, role='final_reviewer', provider='openai',
            model='model', configuration={'model': 'model'}, registry_hash='b' * 64, runner_hash='c' * 64,
            invocation_hash='d' * 64, schema_hash='e' * 64)
        for key in expected:
            with self.subTest(field=key):
                changed = dict(expected); changed[key] = 'wrong'
                with self.assertRaises(ValueError): full.validate_execution(changed, expected)

    def test_resume_full_scope_invalidation(self):
        d, m = self.manifest()
        identity = {'full_manifest_sha256': m['manifest_sha256'], 'base_sha': self.base,
                    'head_sha': self.head, 'diff_hash': full.sha256(d), 'chunking_policy': full.CHUNKING,
                    'chunk_manifest_identity': full.sha256(full.canonical(m['chunks'])),
                    'review_execution_identity': 'b' * 64}
        stages = [('chunk-000', 'chunk'), ('group-000', 'group'), ('final', 'final')]
        for key in identity:
            with self.subTest(key=key):
                evidence = Path(self.tmp.name) / ('resume-' + key)
                run = ReviewRun(evidence, self.root, identity, stages, openai.secure, prefix='fixture-')
                old = run.path; run.stage('chunk-000', 'chunk', b'input', lambda: b'{}', json.loads); run.close()
                changed = dict(identity); changed[key] = 'changed'
                run = ReviewRun(evidence, self.root, changed, stages, openai.secure, prefix='fixture-')
                self.assertNotEqual(old, run.path)
                self.assertEqual(run.state['completed_order'], [])
                self.assertTrue(json.loads((old / 'state.json').read_text())['invalidated'])
                run.close()

    def test_resume_same_identity_and_incomplete_receipt_rejected(self):
        evidence = Path(self.tmp.name) / 'resume'
        stages = [('chunk-000', 'chunk'), ('chunk-001', 'chunk'), ('group-000', 'group'), ('final', 'final')]
        run = ReviewRun(evidence, self.root, {'manifest': 'same'}, stages, openai.secure, prefix='fixture-')
        run.stage('chunk-000', 'chunk', b'input', lambda: b'{}', json.loads); old = run.path; run.close()
        run = ReviewRun(evidence, self.root, {'manifest': 'same'}, stages, openai.secure, prefix='fixture-')
        self.assertEqual(old, run.path)
        run.stage('chunk-000', 'chunk', b'input', lambda: self.fail('reexecuted committed chunk'), json.loads)
        with self.assertRaises(ValueError): run.receipt('receipt.json', b'{}', lambda: None)
        self.assertFalse((run.path / 'receipt.json').exists()); run.close()

    def test_candidate_model_cannot_resume_baseline_chunks(self):
        evidence = Path(self.tmp.name) / 'model-migration-resume'
        stages = [('chunk-000', 'chunk'), ('group-000', 'group')]
        baseline = {'model': 'gpt-5.6-sol', 'model_configuration': {
            'model': 'gpt-5.6-sol', 'reasoning_effort': 'high'},
            'review_execution_identity': 'a' * 64}
        old = ReviewRun(evidence, self.root, baseline, stages, openai.secure,
                        prefix='fixture-')
        old.stage('chunk-000', 'chunk', b'input', lambda: b'{}', json.loads)
        old_path = old.path
        old.close()
        candidate = {'model': 'gpt-6.1-sol', 'model_configuration': {
            'model': 'gpt-6.1-sol', 'reasoning_effort': 'high'},
            'review_execution_identity': 'b' * 64}
        new = ReviewRun(evidence, self.root, candidate, stages, openai.secure,
                        prefix='fixture-')
        self.assertNotEqual(new.path, old_path)
        self.assertEqual(new.state['completed_chunk_ids'], [])
        self.assertTrue(json.loads((old_path / 'state.json').read_text())['invalidated'])
        new.close()

    def test_group_count_tree_plan(self):
        self.assertEqual(full.synthesis_stage_names(10), [('synthesis-000', 'cross-group'),
                         ('synthesis-001', 'cross-group'), ('synthesis-002', 'cross-group')])
        self.assertEqual(len(full.synthesis_stage_names(43)), 7)

    def test_aggregation_limit_never_drops_findings(self):
        with self.assertRaisesRegex(ValueError, 'cannot be discarded'):
            full.bounded_prompt('x' * (full.MAX_PROMPT_BYTES + 1))
        with self.assertRaises(ValueError): deepseek._bounded('x' * 400001)

    def mock_reviews(self):
        qualified = {}
        for role in ('independent_reviewer', 'final_reviewer'):
            spec = openai.load_registry().role(role)
            qualified[spec.provider] = {'role': role, 'mode': 'real_provider', 'identity': spec.identity(),
                                        'offline_test_only': True}
        def oa(prompt, spec, *, stage, timeout):
            return full.canonical({'findings': []} if stage == 'chunk' else
                {'findings': [], 'summary': 'Offline mock reviewed the supplied source completely.',
                 **({'decisions': []} if stage == 'group' else {})})
        def ds(command, prompt, env, timeout):
            result = {'findings': []} if 'Scope=chunk' in prompt else {
                'findings': [], 'decisions': [], 'summary': 'Offline mock reviewed the supplied source completely.'}
            return subprocess.CompletedProcess(command, 0, full.canonical({'structured_output': result}), b'')
        key = 'offline-fixture-key'
        evidence = Path(self.tmp.name) / 'reviews'
        with (patch.object(openai, 'invoke_codex', side_effect=oa), patch.object(openai, 'preflight'),
              patch.object(openai, 'validate_qualification_receipt', return_value=qualified['openai']),
              patch.object(deepseek, 'validate_qualification_receipt', return_value=qualified['deepseek']),
              patch.object(deepseek.legacy, 'resolve_claude_launcher', return_value=('/bin/true', '/usr/bin:/bin')),
              patch.object(deepseek.legacy, 'read_token_file', return_value=key),
              patch.object(deepseek.legacy, 'invoke_reviewer', side_effect=ds)):
            op = openai.run(self.root, self.base, self.head, evidence / 'openai', key,
                openai.load_registry().role('final_reviewer'), qualification_path='offline-fixture')
            response = deepseek.run(SimpleNamespace(repo=str(self.root), base=self.base, head=self.head,
                evidence=str(evidence / 'deepseek'), token_file='offline', qualification='offline-fixture',
                mission_id='codex-mission-harness', timeout=1))
        dp = Path(response['review_receipt'])
        self.receipts = {'deepseek': json.loads(dp.read_bytes()), 'openai': json.loads(op.read_bytes())}
        self.paths = {'deepseek': dp, 'openai': op}
        self.qualified = qualified
        self.key = key
        return self.run_gate()

    def run_gate(self, qualifications=None):
        return gate.validate_gate(root=self.root, base=self.base, head=self.head,
            mission_id='codex-mission-harness', repository=self.repository,
            deepseek_receipt=self.receipts['deepseek'], openai_receipt=self.receipts['openai'],
            deepseek_validator=lambda r: deepseek.validate(r, self.base, self.head, self.root,
                self.paths['deepseek'], 'codex-mission-harness', self.repository, self.key),
            openai_validator=lambda r: openai.validate(r, root=self.root, base=self.base, head=self.head,
                spec=openai.load_registry().role('final_reviewer'), auth_key=self.key,
                receipt_path=self.paths['openai']),
            qualification_validators={p: lambda p=p: (qualifications or self.qualified)[p]
                                      for p in ('deepseek', 'openai')})

    def test_large_offline_end_to_end_both_lanes_and_gate(self):
        d, m = self.large()
        proof = self.mock_reviews()
        self.assertEqual(proof['status'], 'PASS')
        self.assertEqual(proof['manifest_sha256'], m['manifest_sha256'])
        self.assertEqual(len(self.receipts['openai']['synthesis']), 3)
        for r in self.receipts.values():
            self.assertEqual(r['full_manifest'], m)
            self.assertEqual(len(r['chunks']), 28)
            self.assertEqual(len(r['groups']), 10)
            self.assertEqual(full.validate_coverage(d, m, r['chunks'])['COVERAGE_COMPLETE'], 'YES')
            state = json.loads((self.paths[r['provider']].parent / 'state.json').read_bytes())
            self.assertTrue(state['final_completed']); self.assertTrue(state['receipt_written'])
            self.assertEqual(len(state['completed_chunk_ids']), 28)
            self.assertEqual(len(state['completed_group_ids']), 10)

    def test_gate_qualification_identity_mismatch(self):
        self.mock_reviews(); changed = copy.deepcopy(self.qualified)
        changed['openai']['identity']['model'] = 'another-model'
        with self.assertRaisesRegex(ValueError, 'identity chain'): self.run_gate(changed)

    def test_gate_role_provider_qualification_mismatch(self):
        self.mock_reviews()
        for key, value in [('role', 'builder'), ('mode', 'deterministic_fixture')]:
            changed = copy.deepcopy(self.qualified); changed['deepseek'][key] = value
            with self.assertRaises(ValueError): self.run_gate(changed)

    def test_stale_receipt_rejected_after_head_change(self):
        self.mock_reviews(); (self.root / 'new.txt').write_text('new version\n'); self.head = self.commit('new head')
        with self.assertRaises(ValueError): self.run_gate()

    def test_signed_mutations_cannot_bypass_exact_scope(self):
        self.mock_reviews(); original = copy.deepcopy(self.receipts['openai'])
        for field in ('base_sha', 'head_sha', 'diff_sha256', 'runner_sha256', 'model', 'provider'):
            with self.subTest(field=field):
                changed = copy.deepcopy(original); changed[field] = 'wrong'
                changed.pop('auth_hmac_sha256')
                changed['auth_hmac_sha256'] = hmac.new(self.key.encode(), full.canonical(changed), hashlib.sha256).hexdigest()
                self.receipts['openai'] = changed
                with self.assertRaises(ValueError): self.run_gate()
        self.receipts['openai'] = original

    def test_incomplete_review_cannot_pass_gate(self):
        self.mock_reviews()
        for field in ('chunks', 'groups', 'full_manifest', 'execution_identity', 'task_assignments'):
            original = copy.deepcopy(self.receipts['openai'])
            self.receipts['openai'].pop(field)
            self.receipts['openai'].pop('auth_hmac_sha256')
            self.receipts['openai']['auth_hmac_sha256'] = hmac.new(self.key.encode(),
                full.canonical(self.receipts['openai']), hashlib.sha256).hexdigest()
            with self.assertRaises((ValueError, KeyError)): self.run_gate()
            self.receipts['openai'] = original

    def test_cross_group_finding_ledger_and_dispositions(self):
        d, m = self.large()
        finding = {'severity': 'P2', 'title': 'Fixture blocker', 'evidence': 'Original exact fixture evidence'}
        def call(prompt, group):
            if not group: return full.canonical({'findings': [finding]})
            if group == 'synthesis':
                self.assertIn('Original exact fixture evidence', prompt)
                self.assertIn('finding_id', prompt)
                return full.canonical({'findings': [], 'summary': 'All original blockers remain in the immutable ledger.'})
            # Extract group IDs, uphold all exact original blockers.
            text = prompt.split('Blockers: ', 1)[1].split('. \nEXACT DIFF', 1)[0]
            blockers = json.loads(text)
            decisions = [{'finding_id': b['finding_id'], 'decision': 'UPHELD',
                'rationale': 'The original blocker persists in this fixture.', 'source_quote': '',
                'source_id': '', 'quote_start': 0, 'quote_end': 0} for b in blockers]
            return full.canonical({'findings': [], 'decisions': decisions,
                                  'summary': 'The group retains all original blocking findings.'})
        r, _ = openai._assemble(d, self.base, self.head, call)
        self.assertEqual(r['review_result'], 'FAIL')
        self.assertEqual(len(r['findings']), len(m['chunks']))
        self.assertEqual(len({f['finding_id'] for item in openai.synthesis_level(r['groups'], r['chunks'])
                              for f in item['source_findings']}), len(m['chunks']))

    def test_missing_duplicate_disposition_fails_closed(self):
        finding = {'severity': 'P1', 'title': 'Fixture', 'evidence': 'fixture source'}
        expected = deepseek.bind_findings([finding], 'C', 0)
        decision = {'finding_id': 'C000F000', 'decision': 'UPHELD',
                    'rationale': 'The original source confirms this fixture blocker.',
                    'source_quote': '', 'source_id': '', 'quote_start': 0, 'quote_end': 0}
        for decisions in ([], [decision, decision]):
            raw = full.canonical({'findings': [], 'decisions': decisions,
                                  'summary': 'The fixture verifies complete exact once dispositions.'}).decode()
            with self.assertRaises(ValueError):
                deepseek.parse_synthesis(raw, expected, source=None, structured_evidence=True)

    def test_signed_missing_and_duplicate_completed_tasks_rejected(self):
        self.mock_reviews()
        original = copy.deepcopy(self.receipts['openai'])
        for field in ('chunks', 'groups'):
            for duplicate in (False, True):
                with self.subTest(field=field, duplicate=duplicate):
                    changed = copy.deepcopy(original)
                    changed[field] = changed[field] * 2 if duplicate else []
                    changed.pop('auth_hmac_sha256')
                    changed['auth_hmac_sha256'] = hmac.new(self.key.encode(), full.canonical(changed), hashlib.sha256).hexdigest()
                    self.receipts['openai'] = changed
                    with self.assertRaisesRegex(ValueError, 'coverage mismatch'):
                        self.run_gate()
        self.receipts['openai'] = original

    def test_signed_missing_cross_group_cannot_pass(self):
        self.large(); self.mock_reviews()
        altered = self.receipts['openai']; altered['synthesis'].pop()
        altered.pop('auth_hmac_sha256')
        altered['auth_hmac_sha256'] = hmac.new(self.key.encode(), full.canonical(altered), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, 'incomplete cross-group'):
            self.run_gate()

    def test_signed_old_manifest_scope_cannot_pass(self):
        old_diff, old_manifest = self.manifest()
        self.large(); self.mock_reviews()
        altered = self.receipts['openai']; altered['full_manifest'] = old_manifest
        altered.pop('auth_hmac_sha256')
        altered['auth_hmac_sha256'] = hmac.new(self.key.encode(), full.canonical(altered), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, 'actual Git scope'):
            self.run_gate()

    def test_final_gate_rejects_incremental_base(self):
        self.mock_reviews()
        # Even valid receipt validators cannot turn a branch-internal base into full scope.
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with self.assertRaisesRegex(ValueError, 'complete current target main'):
            self.run_gate()

    def test_durable_resume_multilevel_synthesis_and_unique_receipt(self):
        self.large()
        evidence = Path(self.tmp.name) / 'resume-real-runner'
        spec = openai.load_registry().role('final_reviewer')
        counts = {}
        interrupted = False
        def invoke(prompt, model, *, stage, timeout):
            nonlocal interrupted
            identity = full.sha256(prompt.encode())
            if stage == 'synthesis' and not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            counts[identity] = counts.get(identity, 0) + 1
            return full.canonical({'findings': []} if stage == 'chunk' else
                {'findings': [], 'summary': 'This offline fixture reviews all required source completely.',
                 **({'decisions': []} if stage == 'group' else {})})
        with (patch.object(openai, 'invoke_codex', side_effect=invoke), patch.object(openai, 'preflight'),
              patch.object(openai, 'validate_qualification_receipt', return_value={'offline_fixture': True})):
            with self.assertRaises(KeyboardInterrupt):
                openai.run(self.root, self.base, self.head, evidence, 'fixture-key', spec,
                           qualification_path='offline-fixture')
            run_dir, = [p for p in evidence.iterdir() if p.is_dir()]
            state = json.loads((run_dir / 'state.json').read_bytes())
            self.assertEqual(len(state['completed_chunk_ids']), 28)
            self.assertEqual(len(state['completed_group_ids']), 10)
            self.assertFalse(state['receipt_written'])
            receipt = openai.run(self.root, self.base, self.head, evidence, 'fixture-key', spec,
                                 qualification_path='offline-fixture')
            self.assertEqual(receipt.parent, run_dir)
            state = json.loads((run_dir / 'state.json').read_bytes())
            self.assertEqual(state['completed_order'][-3:], ['synthesis-000', 'synthesis-001', 'synthesis-002'])
            self.assertEqual(len(list(evidence.rglob('receipt.json'))), 1)
            committed_counts = dict(counts)
            again = openai.run(self.root, self.base, self.head, evidence, 'fixture-key', spec,
                               qualification_path='offline-fixture')
            self.assertEqual(receipt, again)
            # Only the explicit structured preflight runs again; reviewed chunks/groups stay committed.
            repeated = [k for k in counts if counts[k] > committed_counts.get(k, 0)]
            self.assertEqual(len(repeated), 1)
            self.assertTrue(all(v == 1 for k, v in counts.items() if k not in repeated))

    def test_qualification_contract_auth_cases_and_runner_binding(self):
        from harness.model_qualification import (QualificationResult, CASES, qualification_receipt,
                                                  validate_qualification_receipt)
        spec = openai.load_registry().role('final_reviewer')
        # Synthetic response identities belong exclusively to this disposable offline fixture.
        result = QualificationResult(spec.identity(), 'real_provider', tuple(c.name for c in CASES),
                                     (), tuple('a' * 64 for c in CASES))
        receipt = qualification_receipt(result, auth_key='fixture-key', role='final_reviewer')
        path = Path(self.tmp.name) / 'qualification-fixture.json'
        path.write_bytes(full.canonical(receipt)); path.chmod(0o600)
        validate_qualification_receipt(path, spec, auth_key='fixture-key', role='final_reviewer')
        self.assertNotIn('fixture-key', path.read_text())
        for field in ('review_runner_sha256', 'authentication_identity', 'case_manifest_sha256',
                      'full_scope_contract_sha256'):
            with self.subTest(field=field):
                altered = copy.deepcopy(receipt); altered[field] = '0' * 64
                unsigned = dict(altered); unsigned.pop('integrity_sha256')
                # Keep HMAC valid to test semantic field verification independently of signing.
                altered['integrity_sha256'] = hmac.new(b'fixture-key', json.dumps(unsigned,
                    sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
                path.write_bytes(full.canonical(altered))
                with self.assertRaises(ValueError):
                    validate_qualification_receipt(path, spec, auth_key='fixture-key', role='final_reviewer')

    def test_footballprediction_isolation(self):
        d, m = self.large()
        seen = []
        original = full.git
        def record(root, *args, **kwargs):
            seen.append(Path(root).resolve())
            return original(root, *args, **kwargs)
        with patch.object(full, 'git', side_effect=record):
            full.validate_manifest(self.root, m, self.repository, self.base, self.head)
        self.assertEqual(set(seen), {self.root.resolve()})
        self.assertNotIn('FootballPrediction', str(self.root))


if __name__ == '__main__':
    unittest.main()
