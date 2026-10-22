"""Offline progress-policy acceptance. All generation is fixture-only."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, digest, git, policy_identity, validate_config
from harness.factory_fixture import AcceptanceRuntime, fixture_config
from harness.factory_candidate import BILLING, LOCAL_READY
from harness.factory_runtime import RuntimeFailure, FactoryAppServer, LocalRuntime
from harness import factory_progress as progress


class Runtime(AcceptanceRuntime):
    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        result.update(usage={"total": {"inputTokens": 150001 * len(self.calls), "outputTokens": 1, "totalTokens": 150001 * len(self.calls)+1}},
                      thread_id="offline-thread")
        return result


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'source'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        (self.repo/'score.py').write_text('def add(a,b):\n    return a+b\n')
        (self.repo/'tests').mkdir()
        (self.repo/'tests/test_score.py').write_text('import unittest\n')
        git(self.repo, 'add', '.')
        git(self.repo, '-c', 'user.name=Fixture', '-c', 'user.email=f@localhost', 'commit', '-qm', 'base')
        self.config = fixture_config()
        self.config.update(budget={}, execution_policy={"mode": "progress_driven", "idle_timeout_seconds": 30})
        self.config.pop('max_rounds')
        self.runtime = Runtime()
        self.f = Factory(self.root/'state', self.config, self.runtime)
        self.addCleanup(lambda: self.f.close())
        self.spec = {'version': 2, 'mission_id': 'feature', 'repository': str(self.repo),
                     'base': git(self.repo, 'rev-parse', 'HEAD'), 'objective': 'Add fractional average',
                     'acceptance': ['average([1,2]) == 1.5'], 'scope': ['score.py', 'tests/test_score.py']}
        self.authorize()

    def authorize(self):
        self.spec['progress_authorization'] = {
            'approval_id': 'OFFLINE-ONLY', **{k:self.spec[k] for k in ('mission_id','repository','base','objective','acceptance')},
            'allowed_paths': self.spec['scope'], 'worktree': str(self.f.root/'candidates/feature'),
            'policy_sha256': digest(policy_identity(self.f.config)), 'lane_identities': self.f.profile_identities,
            'financial': {'developer':'prepaid_only','reviewer':'prepaid_only','second_reviewer':'not_authorized'},
            'expires_at':'2099-01-01T00:00:00+00:00'}
        if self.spec.get('delivery_mode') == 'local_candidate':
            self.spec['local_candidate_authorization'] = {
                'approval_id':'OFFLINE-LOCAL', **{k:self.spec[k] for k in ('mission_id','repository','base','acceptance')},
                'allowed_paths':self.spec['scope'], 'worktree':str(self.f.root/'candidates/feature'),
                'executor_identity':self.f.profile_identities['developer'],
                **{k:self.f.config[k] for k in ('checks','ci','budget','timeout_seconds','simulation','execution_policy')},
                'billing':BILLING,'remote_write':'FORBIDDEN','formal_review':'NOT_AUTHORIZED',
                'executor_permissions':'ISOLATED_CANDIDATE_ONLY_NO_NETWORK','expires_at':'2099-01-01T00:00:00+00:00'}

    def test_complex_work_above_old_limits_keeps_tests_dual_review_and_rework(self):
        self.f.submit(self.spec)
        report = self.f.run('feature')
        self.assertEqual(report['DELIVERY_STATUS'], 'READY_FOR_USER_ACCEPTANCE', report)
        self.assertGreater(report['BUDGET_USED']['observed_tokens'], 100000)
        self.assertEqual(report['BUDGET_USED']['token_limit'], 'PROGRESS_DRIVEN')
        self.assertEqual(report['TEST_RESULT'], 'PASS')
        self.assertEqual(report['CI_RESULT'], 'PASS')
        self.assertIn('rework', [c['role'] for c in self.runtime.calls])
        self.assertEqual({r['provider'] for r in report['REVIEW_RESULT']}, {'openai','deepseek'})
        before = len(self.runtime.calls)
        self.f.run('feature')
        self.assertEqual(len(self.runtime.calls), before)  # repeated starts reuse evidence

    def test_more_than_historical_run_count_and_task_age_do_not_stop_admission(self):
        self.f.submit(self.spec)
        for n in range(101):
            with patch('harness.factory.time.time', return_value=time.time()+100000):
                self.f.operation('feature', str(n), 'implement', 'developer', {}, {'task':n}, True,
                    lambda t: {'usage':{'input_tokens':100001,'output_tokens':0}, 'output':{}})
        self.assertEqual(self.f.report('feature')['BUDGET_USED']['agent_runs'], 101)
        self.assertEqual(self.f.report('feature')['BUDGET_USED']['observed_tokens'], 10100101)

    def test_local_candidate_above_first_turn_and_repair_ceiling(self):
        self.spec['delivery_mode'] = 'local_candidate'
        self.authorize()
        self.f.submit(self.spec)
        report = self.f.run('feature')
        # Fixture tests initially miss the bug; independent tests remain the
        # local contract. Local success never acquires formal dual-review PASS.
        self.assertEqual(report['DELIVERY_STATUS'], LOCAL_READY, report)
        self.assertGreater(report['BUDGET_USED']['observed_tokens'], 100000)
        self.assertEqual(report['FORMAL_REVIEW'], 'NOT_EXECUTED')
        self.assertFalse(report['READY_FOR_MERGE'])

    def test_multiple_necessary_repairs_are_allowed_and_checked(self):
        self.spec['delivery_mode'] = 'local_candidate'
        self.authorize()
        original = self.runtime.agent
        def agent(role, profile, cwd, *args):
            result = original(role, profile, cwd, *args)
            count = len([c for c in self.runtime.calls if c['role'] in {'implement','rework'}])
            path = cwd/'tests/test_score.py'
            path.write_text(path.read_text()+ '\n    def test_fractional(self):\n        self.assertEqual(average([1,2]), 1.5)\n')
            if count < 3:
                source = cwd/'score.py'
                source.write_text(source.read_text().replace(' / ', ' // ')+f'\n# diagnostic attempt {count}\n')
            return result
        with patch.object(self.runtime, 'agent', side_effect=agent):
            self.f.submit(self.spec)
            report = self.f.run('feature')
        self.assertEqual(report['DELIVERY_STATUS'], LOCAL_READY, report)
        self.assertEqual(len([c for c in self.runtime.calls if c['role']=='rework']), 2)
        self.assertEqual(report['BUDGET_USED']['observed_tokens'], 450004)

    def test_unknown_keeps_partial_usage_and_blocks_new_or_same_dispatch_after_restart(self):
        self.f.submit(self.spec)
        def lost(t):
            raise RuntimeFailure('lost connection', {'input_tokens':150001,'output_tokens':0})
        with self.assertRaises(FactoryBlocked):
            self.f.operation('feature','lost','implement','developer',{}, {},True,lost)
        before = self.f.report('feature')['BUDGET_USED']
        self.assertEqual(before['partial_usage_runs'],1)
        self.assertEqual(before['observed_tokens'],150001)
        self.assertEqual(before['unknown_token_reservation'],'UNBOUNDED_UNKNOWN')
        self.assertEqual(before['committed_tokens'],'UNKNOWN')
        self.f.close()
        self.f = Factory(self.root/'state',self.config,self.runtime)
        for key in ('lost','new'):
            with self.assertRaisesRegex(FactoryBlocked, 'uncertain|unresolved'):
                self.f.operation('feature',key,'implement','developer',{}, {},True,lambda t:self.fail('replay'))
        self.assertEqual(self.f.report('feature')['BUDGET_USED'],before)

    def test_exact_task_policy_model_identity_and_expiry_are_required(self):
        original = copy.deepcopy(self.spec)
        for field, value in [('objective','Build a new platform'),('lane_identities',{}),
                             ('policy_sha256','bad'),('expires_at','2000-01-01T00:00:00+00:00')]:
            self.spec = copy.deepcopy(original)
            self.spec['progress_authorization'][field] = value
            with self.assertRaises(ValueError):
                self.f.submit(self.spec)
        self.spec = original
        self.spec.pop('progress_authorization')
        with self.assertRaises(ValueError):
            self.f.submit(self.spec)
        self.assertFalse(self.runtime.calls)

    def test_no_extra_paid_api_reviewer_or_remote_authority(self):
        self.f.submit(self.spec)
        self.f.close()
        live_config = copy.deepcopy(self.config)
        live_config['simulation'] = False
        for lane in ('developer','reviewer'):
            live_config['profiles'][lane]['codex_home'] = str(self.root/'absent-offline-auth')
        class LiveFixture(Runtime):
            simulation = False
        self.f = Factory(self.root/'live-fixture-state',live_config,LiveFixture())
        self.authorize()
        self.f.submit(self.spec)
        for lane in ('developer','reviewer','second_reviewer'):
            with self.assertRaises(FactoryBlocked) as stopped:
                progress.check_dispatch(self.f,'feature','review' if lane!='developer' else 'implement',lane,True)
            self.assertEqual(stopped.exception.status,'BLOCKED_FINANCIAL')
        for stage in ('push','merge','deploy','release','hosted_ci','project_pr_ci'):
            with self.assertRaises(FactoryBlocked):
                progress.check_dispatch(self.f,'feature',stage,'local',False)
        self.assertFalse(self.runtime.calls)
        self.spec['progress_authorization']['financial']['second_reviewer']='prepaid_only'
        with self.assertRaises(ValueError):
            progress.authorize(self.f,self.spec,self.f.root/'candidates/feature')

    def test_unchanged_rework_diagnoses_then_stops_but_new_evidence_can_continue(self):
        self.f.submit(self.spec)
        target = {'tree':'same'}
        for i in range(2):
            progress.check_rework(self.f,'feature',target,[{'status':'FAIL','error':'same','evidence_key':str(i)}])
        with self.assertRaisesRegex(FactoryBlocked,'same candidate'):
            progress.check_rework(self.f,'feature',target,[{'status':'FAIL','error':'same'}])
        progress.check_rework(self.f,'feature',{'tree':'new'},[{'status':'FAIL','error':'same'}])
        progress.check_rework(self.f,'feature',target,[{'status':'FAIL','error':'different'}])

    def test_incompatible_canonical_timeouts_fail_explicitly_before_dispatch(self):
        # Local validation now supports progress; canonical review remains an
        # independent, deliberately unsupported interface in this mode.
        progress.validate({**self.config,'trusted_validation':{}})
        self.f.submit(self.spec)
        self.f.project=True
        try:
            with self.assertRaisesRegex(FactoryBlocked,'fixed timeout interface'):
                progress.check_dispatch(self.f,'feature','review','reviewer',True)
        finally:
            self.f.project=False
        self.assertFalse(self.runtime.calls)

    def test_missing_usage_is_unknown_and_cannot_be_restarted(self):
        self.f.submit(self.spec)
        with self.assertRaises(FactoryBlocked):
            self.f.operation('feature','missing','implement','developer',{}, {},True,
                             lambda t:{'output':{}})
        with self.assertRaisesRegex(FactoryBlocked,'unresolved'):
            self.f.operation('feature','next','implement','developer',{}, {},True,
                             lambda t:self.fail('unsettled usage must not dispatch'))
        self.assertEqual(self.f.report('feature')['BUDGET_USED']['unknown_usage_runs'],1)

    def test_legacy_policy_cannot_be_silently_upgraded(self):
        raw=fixture_config()
        old=validate_config(raw)
        self.assertNotIn('execution_policy',old)
        self.assertEqual(old['budget'],{'max_agent_runs':12})
        for field,value in [('budget',{'max_agent_runs':12}),('max_rounds',3),('hosted_ci',{})]:
            bad=copy.deepcopy(self.config)
            bad[field]=value
            with self.assertRaises(ValueError):
                validate_config(bad)


class WireGuardTests(unittest.TestCase):
    setUp = ProgressTests.setUp
    authorize = ProgressTests.authorize
    def guard(self):
        self.events=[]
        return progress.ProgressGuard(self.repo,self.spec['scope'],self.events.append)

    def event(self, command='cat score.py', code=0, output='unchanged', reading=True):
        return {'method':'item/completed','params':{'item':{'type':'commandExecution','command':command,
            'exitCode':code,'aggregatedOutput':output,'commandActions':[{'type':'read'}] if reading else []}}}

    def test_necessary_reads_with_new_context_or_source_are_permitted(self):
        guard=self.guard()
        for i in range(30):
            if i % 5 == 0:
                guard.observe({'method':'item/completed','params':{'item':{'type':'agentMessage','text':f'Check acceptance case {i}'}}})
            guard.observe(self.event())
        (self.repo/'score.py').write_text('changed source\n')
        for _ in range(6):
            guard.observe(self.event(output='changed source'))

    def test_endless_unchanged_reads_and_same_failed_action_stop_with_evidence(self):
        for event, limit in ((self.event(),12),(self.event('python tests.py',1,'same traceback',False),3)):
            guard=self.guard()
            for _ in range(limit-1):
                guard.observe(event)
            with self.assertRaisesRegex(RuntimeError,'repeated unchanged'):
                guard.observe(event)
            self.assertTrue(self.events)

    def test_changed_failure_evidence_permits_debugging(self):
        guard=self.guard()
        for n in range(12):
            guard.observe(self.event('python tests.py',1,f'new traceback {n}',False))

    def test_same_error_can_be_rechecked_after_new_successful_diagnostics(self):
        guard=self.guard()
        for case in range(10):
            guard.observe(self.event('python failing_test.py',1,'same error',False))
            guard.observe(self.event('rg relevant_source',0,f'new diagnostic observation {case}',True))
        # Repeating old diagnostics without new data cannot keep a loop alive.
        guard.observe(self.event('python failing_test.py',1,'same error',False))
        guard.observe(self.event('rg relevant_source',0,'new diagnostic observation 0',True))
        guard.observe(self.event('python failing_test.py',1,'same error',False))
        with self.assertRaises(RuntimeError):
            guard.observe(self.event('python failing_test.py',1,'same error',False))

    def test_out_of_scope_infrastructure_and_reroute_stop(self):
        guard=self.guard()
        (self.repo/'new-platform').mkdir()
        (self.repo/'new-platform/server.py').write_text('outside scope')
        with self.assertRaisesRegex(RuntimeError,'scope'):
            guard.observe(self.event())
        with self.assertRaisesRegex(RuntimeError,'reroute'):
            guard.observe({'method':'model/rerouted','params':{'toModel':'other'}})


class IdleWatchdogTests(unittest.TestCase):
    def test_active_tool_can_outlive_old_wall_deadline_then_silence_kills_group(self):
        with tempfile.TemporaryDirectory() as temp:
            heartbeat=Path(temp)/'activity'
            heartbeat.touch()
            command=[sys.executable, str(Path(progress.__file__)), '1', str(os.getpid()), str(heartbeat),
                     sys.executable,'-c','import time; time.sleep(60)']
            proc=subprocess.Popen(command,start_new_session=True)
            try:
                for _ in range(9):
                    heartbeat.touch()
                    time.sleep(.2)
                self.assertIsNone(proc.poll())  # older than one-second timeout
                self.assertNotEqual(proc.wait(timeout=5),0)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid,9)
                    proc.wait()

    def test_verified_idle_session_does_not_expire_while_controller_runs_qa(self):
        with tempfile.TemporaryDirectory() as temp:
            heartbeat=Path(temp)/'activity'
            heartbeat.write_text('idle_between_verified_turns')
            proc=subprocess.Popen([sys.executable,str(Path(progress.__file__)),'1',str(os.getpid()),str(heartbeat),
                                   sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True)
            try:
                time.sleep(1.4)
                self.assertIsNone(proc.poll())
                heartbeat.write_text('active')
                self.assertNotEqual(proc.wait(timeout=5),0)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid,9)
                    proc.wait()

    def test_controller_loss_stops_even_with_fresh_heartbeat(self):
        with tempfile.TemporaryDirectory() as temp:
            heartbeat=Path(temp)/'activity'
            heartbeat.touch()
            proc=subprocess.Popen([sys.executable,str(Path(progress.__file__)),'60','999999999',str(heartbeat),
                                   sys.executable,'-c','import time; time.sleep(60)'],start_new_session=True)
            self.assertNotEqual(proc.wait(timeout=5),0)


class RestartTests(unittest.TestCase):
    setUp = ProgressTests.setUp
    authorize = ProgressTests.authorize
    def test_same_task_restarted_without_new_evidence_stops(self):
        self.f.submit(self.spec)
        for key in ('first','diagnostic'):
            self.f.operation('feature',key,'implement','developer',{}, {'task':'same'},True,
                lambda t: {'usage':{'input_tokens':1,'output_tokens':1}})
        with self.assertRaisesRegex(FactoryBlocked,'restarted without new evidence'):
            self.f.operation('feature','third','implement','developer',{}, {'task':'same'},True,
                lambda t: self.fail('must not dispatch'))


import shutil
import test_factory_proxy as proxy_tests
import test_factory_local_protocol as native_tests


class ProgressProxyTests(unittest.TestCase):
    setUp = proxy_tests.ProxyContracts.setUp
    write = staticmethod(proxy_tests.ProxyContracts.write)
    post = proxy_tests.ProxyContracts.post

    def test_progress_relay_ignores_old_count_tokens_and_run_age_but_keeps_wire_evidence(self):
        from harness.factory_proxy import ProxyRelay
        relay=ProxyRelay(self.profile,self.root/'progress.raw',1,progress_driven=True)
        self.addCleanup(relay.close)
        relay.deadline=time.monotonic()-10000
        for _ in range(130):
            self.assertTrue(self.post(relay))
        relay.collect_telemetry()
        self.assertEqual(len(self.requests),130)
        receipt=relay.receipt()
        self.assertEqual(receipt['physical_attempt_count'],130)
        self.assertTrue(receipt['usage_complete'])
        self.assertEqual(relay.usage()['total_tokens'],1690)
        self.assertEqual(receipt['money'],'UNKNOWN')

    def test_not_dispatched_evidence_keeps_rejection_separate_from_physical_receipts(self):
        from harness.factory_proxy import ProxyRelay
        relay=ProxyRelay(self.profile,self.root/'rejected.raw',5,progress_driven=True)
        self.addCleanup(relay.close)
        self.post(relay,model='unauthorized-model')
        self.assertFalse(self.requests)
        self.assertEqual(relay.records,[])
        event=json.loads(relay.evidence.read_text())
        self.assertEqual(event['event'],'REQUEST_NOT_DISPATCHED')
        self.assertEqual(event['reason_code'],'LOCAL_POLICY_REJECTED')
        self.assertEqual(len(event['request_sha256']),64)
        self.assertEqual(relay.receipt()['physical_attempt_count'],'UNKNOWN')

    def test_management_failure_retains_unknown_without_replay_or_undefined_evidence(self):
        from harness.factory_proxy import ProxyRelay
        relay=ProxyRelay(self.profile,self.root/'management-failed.raw',5,progress_driven=True)
        self.addCleanup(relay.close)
        self.post(relay)
        with patch.object(relay.policy,'management',side_effect=OSError('offline')):
            with self.assertRaisesRegex(ValueError,'telemetry unproven'):
                relay.collect_telemetry()
        self.assertFalse(relay.receipt()['usage_complete'])
        self.post(relay)
        self.assertEqual(len(self.requests),1)

    def test_progress_relay_unknown_and_model_switch_still_latch_closed(self):
        from harness.factory_proxy import ProxyRelay
        for mode in ('model_mismatch','http_error','partial'):
            self.mode=mode
            relay=ProxyRelay(self.profile,self.root/(mode+'.raw'),5,progress_driven=True)
            try:
                before=len(self.requests)
                self.post(relay)
                self.post(relay)
                self.assertEqual(len(self.requests),before+1)
                self.assertEqual(relay.receipt()['physical_attempt_count'],'UNKNOWN')
                self.assertFalse(relay.receipt()['usage_complete'])
            finally:
                relay.close()


@unittest.skipUnless(shutil.which('codex') and shutil.which('bwrap'),'native offline protocol required')
class ProgressNativeTests(unittest.TestCase):
    setUp = native_tests.NativeProtocolTests.setUp
    exec = native_tests.NativeProtocolTests.exec

    def test_native_inherited_rollout_budget_disabled_and_sandbox_kept_without_inference(self):
        (self.auth/'config.toml').write_text('[features.rollout_budget]\nenabled=true\nlimit_tokens=80000\n')
        profile={'provider':'openai','model':'offline-protocol-no-inference','codex_home':str(self.auth)}
        server=FactoryAppServer(profile,self.cwd,self.root/'progress-native.raw',30,
                               [self.root/'state',self.source],False,progress_scope=['score.py'])
        self.addCleanup(server.close)
        server.start_or_resume(None,str(self.cwd))
        effective=server._request('config/read',{'includeLayers':False})['config']
        self.assertFalse(effective['features']['rollout_budget']['enabled'])
        self.assertFalse(server._thread_policy_params(str(self.cwd))['config']['features']['rollout_budget']['enabled'])
        self.assertIsNone(server.token_limit)
        self.assertEqual(self.exec(server,"import json,socket; r='DENIED'\ntry:\n s=socket.socket(); s.connect(('1.1.1.1',443)); r='CONNECTED'\nexcept OSError: pass\nprint(json.dumps(r))"),'DENIED')
        self.assertFalse(any(e.get('method')=='turn/started' for e in server.events))

    def test_runtime_plan_has_no_32000_token_or_120_second_cutoff(self):
        from unittest.mock import Mock
        server=Mock(_proxy_relay=None)
        server.execute.return_value={'output':{},'usage':{'input_tokens':200001,'output_tokens':1}}
        runtime=LocalRuntime()
        runtime.resource_policy={'execution_policy':{'mode':'progress_driven','idle_timeout_seconds':900}}
        with patch('harness.factory_runtime.FactoryAppServer',return_value=server) as constructor:
            result=runtime.agent('plan',{'provider':'openai'},self.cwd,{},self.root/'plan.raw',900,[])
        self.assertEqual(constructor.call_args.args[3],900)
        self.assertIsNone(constructor.call_args.args[7])
        self.assertEqual(constructor.call_args.kwargs['progress_scope'],[])
        self.assertNotIn('planning_resource_guard',json.loads(server.execute.call_args.args[0]))
        self.assertEqual(result['usage']['input_tokens'],200001)


    def test_active_business_gate_outlives_wall_timeout_and_silent_gate_is_unknown(self):
        runtime=LocalRuntime()
        runtime.resource_policy={'execution_policy':{'mode':'progress_driven','idle_timeout_seconds':1}}
        target=self.factory.target(self.spec,self.cwd)
        result=runtime.gate(['python3','-u','-c','import time; [(print(n,flush=True),time.sleep(.2)) for n in range(9)]'],
                            self.cwd,target,self.root/'active-gate.raw',1)
        self.assertEqual(result['status'],'PASS')
        with self.assertRaisesRegex(RuntimeFailure,'silence'):
            runtime.gate(['python3','-c','import time; time.sleep(60)'],
                          self.cwd,target,self.root/'silent-gate.raw',1)
        self.assertEqual(json.loads((self.root/'silent-gate.watchdog.json').read_text())['reason'],'NO_EFFECTIVE_EVENTS')


    def test_repair_failure_copies_watchdog_evidence_to_current_operation(self):
        profile={'provider':'openai','model':'offline-protocol-no-inference','codex_home':str(self.auth)}
        server=FactoryAppServer(profile,self.cwd,self.root/'first.raw',30,
                               [self.root/'state',self.source],False,progress_scope=['score.py'])
        self.addCleanup(server.close)
        marker=server._heartbeat.with_suffix('.watchdog.json')
        marker.write_text('{"event":"WATCHDOG_STOP","reason":"NO_EFFECTIVE_EVENTS"}')
        runtime=LocalRuntime()
        runtime.resource_policy={'execution_policy':{'mode':'progress_driven','idle_timeout_seconds':30}}
        runtime._single_server=server
        runtime._single_binding=(json.dumps(profile,sort_keys=True),str(self.cwd.resolve()),tuple(map(str,[self.root/'state',self.source])))
        with patch.object(server,'execute',side_effect=RuntimeFailure('synthetic lost repair')):
            with self.assertRaisesRegex(RuntimeFailure,'lost repair'):
                runtime.agent('rework',profile,self.cwd,{'_reuse_session':True,'_thread_id':'offline-thread',
                    '_progress_scope':['score.py']},self.root/'repair.raw',30,[self.root/'state',self.source])
        self.assertEqual((self.root/'repair.watchdog.json').read_bytes(),marker.read_bytes())


import test_factory_turn_completion as completion_tests


class WireIntegrationTests(unittest.TestCase):
    setUp = ProgressTests.setUp
    authorize = ProgressTests.authorize

    def server(self, messages):
        server=completion_tests.TurnCompletionTests.server(self,messages,limit=None)
        server.progress_mode=True
        server._response_timeout=30
        server._heartbeat=self.root/'wire.activity'
        server._heartbeat.touch()
        server._progress_guard=progress.ProgressGuard(self.repo,self.spec['scope'],server._progress_event)
        return server

    def test_real_wire_parser_keeps_large_usage_without_interrupt(self):
        server=self.server([completion_tests.ACCEPTED,completion_tests.usage(300001),
                            completion_tests.final(),completion_tests.completed()])
        result=completion_tests.TurnCompletionTests.execute(self,server)
        self.assertEqual(result['usage']['total']['totalTokens'],300001)
        self.assertNotIn('turn/interrupt',server.proc.stdin.getvalue())

    def test_real_wire_parser_stops_repeated_failure_and_retains_diagnosis(self):
        failure=WireGuardTests.event(self,'python failing_test.py',1,'same error',False)
        server=self.server([failure,failure,failure])
        server._read_message()
        server._read_message()
        with self.assertRaisesRegex(RuntimeFailure,'repeated unchanged'):
            server._read_message()
        raw=server.transcript.read_text()
        self.assertIn('REPEATED_UNCHANGED_EVIDENCE',raw)
        self.assertIn('SAFE_STOP',raw)
