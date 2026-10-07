"""High-value multidimensional admission, cancellation and onboarding regressions."""
from __future__ import annotations

import copy
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, validate_config
from harness.factory_budget import accounting
from harness.factory_cli import main
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_http import NoRedirect, request
from harness.factory import git


class DeliveryLimitsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'project'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        (self.repo / 'score.py').write_text('def add(a,b):\n    return a+b\n')
        (self.repo / 'tests').mkdir()
        (self.repo / 'tests/test_score.py').write_text('import unittest\n')
        git(self.repo, 'add', '.')
        git(self.repo, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-qm', 'base')
        self.config = fixture_config()
        self.config['budget'] = {'max_agent_runs': 16, 'max_run_tokens': 100, 'max_total_tokens': 200, 'max_wall_seconds': 3600}
        self.f = Factory(self.root / 'state', self.config, AcceptanceRuntime())
        self.addCleanup(self.f.close)
        self.f.submit({'version': 2, 'mission_id': 'feature', 'repository': str(self.repo), 'objective': 'Add average'})

    def paid(self, key, usage):
        return self.f.operation('feature', key, 'plan', 'developer', {}, {}, True,
                                lambda transcript: {'output': {}, 'usage': usage})

    def test_unknown_tokens_keep_reservation_and_admission_blocks_third_run(self):
        self.paid('a', None)
        self.paid('b', None)
        with self.assertRaises(FactoryBlocked) as blocked:
            self.paid('c', {'input_tokens': 0, 'output_tokens': 0})
        self.assertEqual(blocked.exception.status, 'BLOCKED_BUDGET')
        data = self.f.report('feature')['BUDGET_USED']
        self.assertEqual(data['unknown_token_reservation'], 200)
        self.assertEqual(data['observed_tokens'], 0)
        self.assertEqual(data['unknown_usage_runs'], 2)
        # Proven result reuse does not allocate or refund another reservation.
        self.paid('a', {'input_tokens': 0, 'output_tokens': 0})
        self.assertEqual(self.f.report('feature')['BUDGET_USED'], data)

    def test_observed_usage_admits_new_run_without_inventing_dollars(self):
        for key in ('a', 'b', 'c'):
            self.paid(key, {'input_tokens': 10, 'output_tokens': 10})
        data = self.f.report('feature')['BUDGET_USED']
        self.assertEqual(data['observed_tokens'], 60)
        self.assertEqual(data['unknown_token_reservation'], 0)
        self.assertEqual(data['money'], 'FIXTURE_NO_PROVIDER_COST')

    def test_one_run_exceeding_reservation_is_retained_and_cannot_deliver(self):
        with self.assertRaisesRegex(FactoryBlocked, 'run token allowance exceeded'):
            self.paid('a', {'input_tokens': 101, 'output_tokens': 0})
        self.assertEqual(self.f.report('feature')['BUDGET_USED']['observed_tokens'], 101)

    def test_wall_time_survives_restart_and_blocks_unpaid_gate_too(self):
        with patch('harness.factory.time.time', return_value=time.time() + 3601):
            with self.assertRaisesRegex(FactoryBlocked, 'wall-clock exhausted'):
                self.f.operation('feature', 'gate', 'checks', 'local', {}, {}, False, lambda t: {'status': 'PASS'})
        self.assertEqual(self.f.report('feature')['BUDGET_USED']['agent_runs'], 0)

    def test_cancel_prevents_dispatch_and_resume_without_refund(self):
        self.paid('a', None)
        self.f.cancel('feature')
        self.assertEqual(self.f.run('feature')['DELIVERY_STATUS'], 'CANCELLED')
        self.assertEqual(self.f.run('feature')['BUDGET_USED']['unknown_token_reservation'], 100)
        with self.assertRaises(FactoryBlocked):
            self.paid('new', None)

    def test_invalid_token_authority_is_rejected(self):
        for budget in ({'max_agent_runs': 10, 'max_total_tokens': 100},
                       {'max_agent_runs': 10, 'max_run_tokens': 101, 'max_total_tokens': 100},
                       {'max_agent_runs': 10, 'max_wall_seconds': True}):
            config = copy.deepcopy(self.config)
            config['budget'] = budget
            with self.assertRaises(ValueError):
                validate_config(config)

    def test_setup_and_latest_status_delivery_cancel_paths(self):
        # Onboarding never sends model traffic, and never changes an old config.
        token = self.root / 'token'
        token.write_text('fake-key-not-for-inference')
        token.chmod(0o600)
        config = self.root / 'private/config.json'
        with patch('harness.factory_setup.shutil.which', return_value='/usr/bin/true'), patch('sys.stdout', io.StringIO()) as output:
            main(['setup', '--repository', str(self.repo), '--deepseek-token-file', str(token), '--config', str(config), '--json'])
        self.assertEqual(json.loads(output.getvalue())['MODEL_INFERENCE_CALLS'], 0)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
        before = config.read_bytes()
        with patch('harness.factory_setup.shutil.which', return_value='/usr/bin/true'), patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
            main(['setup', '--repository', str(self.repo), '--deepseek-token-file', str(token), '--config', str(config), '--json'])
        self.assertEqual(config.read_bytes(), before)
        # Exercise the command parser and latest-task selection with durable
        # real SQLite state; only provider inference is substituted here.
        live_config = fixture_config()
        live_config['simulation'] = False
        live_config['repository'] = str(self.repo)
        config.write_text(json.dumps(live_config))
        class Runtime(AcceptanceRuntime):
            simulation = False
        state = self.root / 'cli-state'
        with patch('harness.factory.LocalRuntime', Runtime):
            for command in (['submit', 'Add average', '--mission-id', 'cli-feature'], ['status'], ['delivery'], ['resume'], ['cancel'], ['resume']):
                with patch('sys.stdout', io.StringIO()) as output, patch('sys.stderr', io.StringIO()):
                    main(command + ['--state-dir', str(state), '--config', str(config), '--json'])
                result = json.loads(output.getvalue())
                self.assertEqual(result['MISSION'], 'cli-feature')
            self.assertEqual(result['DELIVERY_STATUS'], 'CANCELLED')

    def test_deepseek_redirect_is_never_treated_as_provider_identity(self):
        with self.assertRaisesRegex(RuntimeError, 'redirect rejected'):
            NoRedirect().redirect_request(None, None, None, None, None, None)

    def test_completed_malformed_deepseek_keeps_usage_for_charged_validation(self):
        token = self.root / 'token'
        token.write_text('fake-key')
        token.chmod(0o600)
        body = {'id': 'fake-response', 'model': 'deepseek-flash', 'usage': {'prompt_tokens': 2, 'completion_tokens': 1},
                'choices': [{'finish_reason': 'stop', 'message': {'content': 'not JSON'}}]}
        from unittest.mock import Mock
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps(body).encode())
        with patch('urllib.request.build_opener', return_value=opener):
            result = request({'model': 'deepseek-flash', 'token_file': str(token)}, {}, self.root / 'raw', 1)
        self.assertEqual(result['usage'], body['usage'])
        self.assertEqual(result['output'], 'not JSON')
        self.assertEqual(result['runtime_identity']['model'], 'deepseek-flash')

    def hosted_factory(self, outcome):
        workflow = self.repo / '.github/workflows/ci.yml'
        workflow.parent.mkdir(parents=True)
        workflow.write_text('name: CI\non: [push]\n')
        git(self.repo, 'add', '.')
        git(self.repo, '-c', 'user.name=Test', '-c', 'user.email=test@localhost', 'commit', '-qm', 'workflow')
        config = fixture_config()
        config['hosted_ci'] = {'repository': 'fixture/project', 'workflows': ['ci.yml']}
        runtime = AcceptanceRuntime()
        def hosted(policy, cwd, target, branch, transcript, timeout):
            result = {'status': 'PASS', 'target': target, 'repository': policy['repository'], 'branch': branch,
                      'MERGE_PERFORMED': False, 'runs': {'ci.yml': [{'databaseId': 1, 'headSha': target['head'],
                          'event': 'push', 'status': 'completed', 'conclusion': 'success',
                          'url': 'https://github.com/fixture/project/actions/runs/1'}]},
                      'jobs': {'1': [{'status': 'completed', 'conclusion': 'success'}]}}
            outcome(result)
            transcript.write_text(json.dumps(result))
            return result
        runtime.hosted_ci = hosted
        factory = Factory(self.root / 'hosted-state', config, runtime)
        self.addCleanup(factory.close)
        factory.submit({'version': 2, 'mission_id': 'hosted', 'repository': str(self.repo), 'objective': 'Add average'})
        return factory

    def test_hosted_matrix_success_is_bound_to_exact_target_and_separate_from_local_ci(self):
        factory = self.hosted_factory(lambda result: None)
        report = factory.run('hosted')
        self.assertEqual(report['DELIVERY_STATUS'], 'READY_FOR_USER_ACCEPTANCE')
        self.assertEqual(report['LOCAL_CI'], 'PASS')
        self.assertEqual(report['HOSTED_CI'], 'PASS')
        rows = factory.db.execute("SELECT result FROM operations WHERE stage='hosted_ci'").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(json.loads(rows[-1][0])['target']['head'], report['TARGET_HEAD'])

    def test_missing_or_stale_hosted_success_can_never_enter_delivery(self):
        def mutate(result):
            result['runs']['ci.yml'][0]['headSha'] = '0' * 40
        factory = self.hosted_factory(mutate)
        self.assertEqual(factory.run('hosted')['DELIVERY_STATUS'], 'UNKNOWN')
        self.assertEqual(factory.report('hosted')['HOSTED_CI'], 'UNKNOWN')

    def test_skipped_hosted_job_cannot_hide_behind_workflow_success(self):
        def mutate(result):
            result['jobs']['1'][0]['conclusion'] = 'skipped'
        factory = self.hosted_factory(mutate)
        self.assertEqual(factory.run('hosted')['DELIVERY_STATUS'], 'UNKNOWN')

    def test_verified_hosted_failure_receipt_triggers_bounded_rework(self):
        failed = [False]
        def mutate(result):
            if not failed[0]:
                failed[0] = True
                result['status'] = 'FAIL'
                result['runs']['ci.yml'][0]['conclusion'] = 'failure'
                result['jobs']['1'][0]['conclusion'] = 'failure'
        factory = self.hosted_factory(mutate)
        self.assertEqual(factory.run('hosted')['DELIVERY_STATUS'], 'READY_FOR_USER_ACCEPTANCE')
        feedback = json.loads(factory.db.execute("SELECT payload FROM events WHERE kind='rework' LIMIT 1").fetchone()[0])
        self.assertEqual(feedback['feedback'][0]['result']['department'], 'hosted_ci')

    def test_hosted_workflow_cannot_be_weakened_to_obtain_pass(self):
        factory = self.hosted_factory(lambda result: None)
        spec, cwd = factory.prepare('hosted')
        (cwd / '.github/workflows/ci.yml').write_text('name: fake success\n')
        with self.assertRaises(FactoryBlocked) as error:
            factory.checkpoint(spec, cwd)
        self.assertEqual(error.exception.status, 'BLOCKED_SCOPE')

    def test_inconsistent_provider_usage_is_unknown_instead_of_undercounted(self):
        from harness.factory import observed_usage
        self.assertIsNone(observed_usage({'total': {'inputTokens': 1000, 'outputTokens': 5, 'totalTokens': 1}}))
        self.assertIsNone(observed_usage({'prompt_tokens': 5, 'completion_tokens': 5, 'total_tokens': 1}))
