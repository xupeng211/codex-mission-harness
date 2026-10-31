"""Offline regressions at the main/Controller integration and CI boundaries."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from footballprediction_contract import ContractUnavailable
from harness.factory import FactoryBlocked, validate_config
from harness.factory_fixture import fixture_config
from harness.factory_runtime import FactoryAppServer, LocalRuntime, RuntimeFailure
import test_factory_phase2 as phase2
import test_factory_preparation_cleanup as preparation
import test_factory_remote_cleanup as remote
import test_factory_validation_cleanup as validation
from test_factory_controller_gates import CONTAINER

ROOT = Path(__file__).resolve().parents[1]
SUPERVISORS = [(preparation, preparation.PreparationGroupCleanupTests, 'full_gate_original_rules'),
               (remote, remote.RemoteGroupCleanupTests, 'actual_route'),
               (validation, validation.ValidationGroupCleanupTests, 'normal')]


class ContractPrerequisiteTests(unittest.TestCase):
    def test_make_verify_missing_contract_blocks_before_compile_or_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, FOOTBALLPREDICTION_CONTRACT_REPO=str(Path(tmp) / 'missing'))
            result = subprocess.run(['make', 'verify'], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('BLOCKED_CONTRACT_SOURCE', result.stderr)
        self.assertNotIn('compileall', result.stdout)
        self.assertNotIn('unittest discover', result.stdout)

    def test_an_unrelated_complete_git_checkout_cannot_substitute(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(path)], check=True)
            (path / 'Makefile').write_text('verify:\n\tfalse\n')
            subprocess.run(['git', '-C', str(path), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(path), '-c', 'user.name=Fixture',
                            '-c', 'user.email=f@localhost', 'commit', '-qm', 'unrelated'], check=True)
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'tests/footballprediction_contract.py')],
                cwd=ROOT, env=dict(os.environ, FOOTBALLPREDICTION_CONTRACT_REPO=tmp),
                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertIn('exact contract HEAD/tree mismatch', result.stderr)

    def test_missing_contract_is_typed_by_each_real_supervisor_and_still_an_error(self):
        for module, _, mode in SUPERVISORS:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as tmp:
                env = dict(os.environ, FOOTBALLPREDICTION_CONTRACT_REPO=str(Path(tmp) / 'missing'))
                result = subprocess.run([sys.executable, '-B', module.__file__, '--case', mode, tmp],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=18)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                report = json.loads(result.stdout)
                self.assertEqual(report['prerequisite_error']['code'], 'BLOCKED_CONTRACT_SOURCE')
                self.assertNotIn('driver_error', report)
                self.assertEqual(report['remaining'], [])
                from footballprediction_contract import raise_prerequisite
                with self.assertRaises(ContractUnavailable):
                    raise_prerequisite(report)

    def test_parent_does_not_reclassify_driver_error_exit_or_timeout_as_missing_source(self):
        for module, cls, mode in SUPERVISORS:
            case = cls()
            with self.subTest(module=module.__name__, fault='driver'):
                result = subprocess.CompletedProcess([], 0, json.dumps({'driver_error': 'AssertionError(real failure)'}), '')
                with patch.object(module.subprocess, 'run', return_value=result), self.assertRaisesRegex(AssertionError, 'driver_error'):
                    case.case(mode)
            with self.subTest(module=module.__name__, fault='exit'):
                result = subprocess.CompletedProcess([], 7, '', 'real child failure')
                with patch.object(module.subprocess, 'run', return_value=result), self.assertRaises(AssertionError):
                    case.case(mode)
            with self.subTest(module=module.__name__, fault='timeout'):
                with patch.object(module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('child', 1)), self.assertRaises(subprocess.TimeoutExpired):
                    case.case(mode)


class IntegratedUsageTests(unittest.TestCase):
    def test_same_thread_repair_resets_attribution_but_retains_cumulative_budget_baseline(self):
        server = FactoryAppServer.__new__(FactoryAppServer)
        server._policy_cwd, server._permissions_profile, server._forbidden_actions = '/tmp/fixture', 'fixture', ('merge',)
        server.MODEL, server.REASONING_EFFORT = None, None
        server.runtime_identity, server.events, server.usage = {}, [], None
        server.token_limit, server._reuse_session = 30, True
        server._end_time, server.seq = time.monotonic() + 30, 0
        server.proc = SimpleNamespace(stdin=io.StringIO())
        turn = {'id': 'first', 'count': 20}
        def complete(*args, **kwargs):
            usage = {'total': {'inputTokens': turn['count'], 'outputTokens': 0, 'totalTokens': turn['count']}}
            events = [dict(method='thread/tokenUsage/updated', params=dict(threadId='root', turnId=turn['id'], tokenUsage=usage)),
                      dict(method='item/completed', params=dict(threadId='root', turnId=turn['id'], item=dict(id='answer', type='agentMessage', text='{"ok":true}')))]
            for event in events:
                server.events.append(event)
                server._observe_execution_event(event)
            return {'status': 'completed', 'items': []}
        with patch.object(server, 'start_or_resume', return_value='root'), \
             patch.object(server, '_request', side_effect=lambda *args: {'turn': {'id': turn['id']}}), \
             patch.object(server, '_turn_completed', side_effect=complete):
            first = server.execute('first', {}, return_thread=True)
            turn.update(id='repair', count=45)
            second = server.execute('repair', {}, thread_id=first['thread_id'], return_thread=True)
        self.assertEqual(second['usage']['total']['totalTokens'], 45)
        self.assertEqual(set(second['usage_telemetry']['by_thread']['root']), {'repair'})
        self.assertFalse(server._budget_exceeded)
        with self.assertRaisesRegex(RuntimeFailure, 'another native turn'):
            server._observe_execution_event(dict(method='thread/tokenUsage/updated', params=dict(
                threadId='root', turnId='first', tokenUsage={'total': {'totalTokens': 999}})))
        self.assertEqual(server.usage['total']['totalTokens'], 45)

    def test_closing_local_session_cannot_clear_an_unconfirmed_controller_client(self):
        runtime = LocalRuntime()
        token = runtime.begin_execution('owned')
        client = runtime._preparation_client = object()
        process = runtime.current_process = object()
        runtime.close_session()
        self.assertIs(runtime.current_process, process)
        self.assertIs(runtime._preparation_client, client)
        self.assertFalse(runtime.end_execution(token))
        runtime._preparation_client = runtime.current_process = None
        self.assertTrue(runtime.end_execution(token))
        next_token = runtime.begin_execution('next')
        self.assertFalse(runtime.cancel(token))
        self.assertFalse(runtime._validation_cancelled)
        self.assertTrue(runtime.end_execution(next_token))


class IntegratedPolicyTests(unittest.TestCase):
    def test_existing_validation_engines_cannot_consume_each_others_policy(self):
        config = fixture_config()
        config.update(project_contract='footballprediction', trusted_validation=phase2.VALIDATION,
                      checks=[['make', 'verify-strict']], ci=[['make', 'verify-pr']], project_container=CONTAINER)
        with self.assertRaisesRegex(ValueError, 'cannot be mixed'):
            validate_config(config)

    def test_main_strict_publication_cannot_accept_configuration_or_fixture_as_live_execution(self):
        fx = phase2.Phase2Tests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        spec, cwd, target = fx.candidate()
        fx.f.config['simulation'] = False  # negative consumption probe only; never dispatch
        with self.assertRaisesRegex(FactoryBlocked, 'successful trusted strict execution is missing'):
            fx.f.require_project_validation(spec, cwd, target)
        fx.f.config['simulation'] = True
        fx.gates(spec, cwd, target, 'checks')  # explicit Docker double, fixture=True
        fx.f.config['simulation'] = False
        with self.assertRaisesRegex(FactoryBlocked, 'fixture provenance mismatch'):
            fx.f.require_project_validation(spec, cwd, target)


if __name__ == '__main__':
    unittest.main()
