"""真实主验证进程和原项目规则；仅替换外部 Docker I/O，不调用服务。

独立 watchdog/finally 核对精确身份；subreaper 只为测试最终回收孤儿。
"""
from contextlib import ExitStack
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness.factory_runtime import LocalRuntime
from test_factory_container_lifecycle import DockerDouble
from test_factory_controller_gates import CONTAINER
from test_factory_preparation_cleanup import CHILD, identity
from test_factory_project_integration import PROJECT_BASE
import test_factory_project_integration as original_rules


def same(expected):
    actual = identity(expected['pid']) if expected else None
    return actual if actual and all(actual[k] == expected[k] for k in
                                    ('pid', 'starttime', 'pgid', 'sid', 'uid')) else None


CLIENT = r'''
import os,signal,subprocess,sys,time
from pathlib import Path
mode,path,child=sys.argv[1:]
signal.signal(signal.SIGTERM,signal.SIG_IGN)
if mode != 'normal':
 subprocess.Popen([sys.executable,'-I','-B','-c',child,path],
  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 until=time.monotonic()+2
 while not Path(path).exists() and time.monotonic()<until: time.sleep(.005)
 if not Path(path).exists(): raise RuntimeError('validation descendant not ready')
print('validation stdout',flush=True)
print('validation stderr',file=sys.stderr,flush=True)
if mode == 'wait': time.sleep(20)
sys.exit(7 if mode == 'error' else 124 if mode == 'exit124' else 0)
'''


def run_case(mode, root):
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    def alarm(*_):
        raise TimeoutError('independent 20-second validation watchdog')
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(20)
    runtime = LocalRuntime()
    real_popen, real_killpg = subprocess.Popen, os.killpg
    report = {'case': mode, 'source_phases': [], 'signals': [], 'watcher_errors': []}
    leaders, validation, finished = [], [], []
    fx = watcher = None
    fixture_started = False
    phase = 'product'
    child_path = root / 'descendant.json'
    unrelated = real_popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(30)'],
                           start_new_session=True, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    unrelated_identity = identity(unrelated.pid)
    report['unrelated_initial'] = unrelated_identity
    real_finish, real_end = runtime._finish_owned_client, runtime.end_execution
    import harness.factory_container as container
    real_consume, real_source, real_write = container.consume_output, container.source_check, container.RedactedOutput.write

    def launch(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        leaders.append((proc, identity(proc.pid)))
        return proc

    def main_client(proc):
        return bool(validation) and validation[0][0] is proc

    def group_signal(pgid, sig):
        anchor = next((same(v) for _, v in leaders if v['pid'] == pgid), None)
        assert anchor and anchor['ppid'] == os.getpid() and anchor['uid'] == os.getuid()
        assert anchor['pgid'] == anchor['sid'] == pgid
        report['signals'].append({'phase': phase, 'pgid': pgid, 'signal': sig, 'anchor': anchor})
        if phase == 'product' and validation and pgid == validation[0][0].pid:
            if mode in {'signal_failure', 'cancel_signal_failure', 'log_and_signal_failure'}:
                raise PermissionError('injected main validation signal failure')
            if mode == 'signal_no_effect':
                return
        return real_killpg(pgid, sig)

    def consume(proc, *args, **kwargs):
        value = real_consume(proc, *args, **kwargs)
        if main_client(proc):
            report['leader_after_output'] = identity(proc.pid)
            if mode == 'lost_anchor':
                report['foreign_reap'] = os.waitpid(proc.pid, 0)
            elif mode == 'identity_mismatch':
                runtime._preparation_client['identity']['starttime'] = 'damaged-starttime'
        return value

    def finish(client, deadline):
        value = real_finish(client, deadline)
        if main_client(client['process']):
            finished.append(client)
            report['validation_cleanup'] = value
            report['descendant_at_product_shutdown'] = same(json.loads(child_path.read_text())) if child_path.exists() else None
            if mode == 'late_cancel':
                report['late_cancel_accepted'] = runtime.cancel(runtime.container_cancel)
        return value

    def end(execution):
        child = json.loads(child_path.read_text()) if child_path.exists() else None
        report['descendant_at_identity_release_attempt'] = same(child)
        value = real_end(execution)
        report['end_execution_result'] = value
        return value

    def source(*args, **kwargs):
        report['source_phases'].append(args[2])
        return real_source(*args, **kwargs)

    def write(output, data):
        if mode in {'log_failure', 'log_and_signal_failure'} and main_client(runtime.current_process):
            raise OSError(28, 'original validation diagnostic ENOSPC')
        return real_write(output, data)

    def cancel_when_ready():
        try:
            until = time.monotonic() + 6
            while not child_path.exists() and time.monotonic() < until:
                time.sleep(.005)
            assert child_path.exists(), 'validation did not become ready'
            report['stale_cancel_accepted'] = runtime.cancel(threading.Event())
            report['cancel_accepted'] = runtime.cancel(runtime.container_cancel)
        except BaseException as error:
            report['watcher_errors'].append(repr(error))

    try:
        original_rules.CanonicalRuntimeIntegrationTests.setUpClass()
        fixture_started = True
        fx = original_rules.CanonicalRuntimeIntegrationTests('test_pr_body_uses_original_trusted_preflight')
        fx.setUp()
        fx.spec, fx.cwd, fx.target = fx.candidate()
        report['contract_rule_commit'] = PROJECT_BASE
        double = DockerDouble(fx, runtime)
        double.real_popen = launch
        dispatch = double.dispatch
        def docker_io(argv, **kwargs):
            if argv[1:3] == ['image', 'inspect']:
                double.calls.append(('image', argv))
                proc = launch([sys.executable, '-I', '-B', '-c', 'import sys;print(sys.argv[1])', argv[-1]], **kwargs)
                double.clients.append(proc)
                return proc
            if argv[1] != 'run':
                return dispatch(argv, **kwargs)
            double.calls.append(('run', argv))
            name = argv[argv.index('--name') + 1]
            double.resources[name] = dict(x.split('=', 1) for i, x in enumerate(argv) if i and argv[i-1] == '--label')
            client_mode = ('normal' if mode == 'normal' else 'error' if mode == 'error_exit' else
                           'exit124' if mode == 'exit124' else
                           'wait' if mode in {'cancel', 'timeout', 'cancel_signal_failure'} else 'return')
            proc = launch([sys.executable, '-I', '-B', '-c', CLIENT, client_mode, str(child_path), CHILD], **kwargs)
            double.clients.append(proc)
            validation.append(leaders[-1])
            return proc
        double.dispatch = docker_io
        with ExitStack() as hooks:
            # Real source_check, image check, Git binding and original policy.
            for name, method in [('Popen', double.popen), ('run', double.command), ('check_output', double.output)]:
                hooks.enter_context(patch('harness.factory_container.subprocess.' + name, side_effect=method))
            hooks.enter_context(patch('os.killpg', side_effect=group_signal))
            hooks.enter_context(patch.object(container, 'consume_output', side_effect=consume))
            hooks.enter_context(patch.object(container, 'source_check', side_effect=source))
            hooks.enter_context(patch.object(container.RedactedOutput, 'write', write))
            hooks.enter_context(patch.object(runtime, '_finish_owned_client', side_effect=finish))
            hooks.enter_context(patch.object(runtime, 'end_execution', side_effect=end))
            if mode in {'cancel', 'cancel_signal_failure'}:
                watcher = threading.Thread(target=cancel_when_ready)
                watcher.start()
            started = time.monotonic()
            report['gate_timeout'] = 3 if mode in {'timeout', 'signal_no_effect'} else 7
            try:
                report['value'] = runtime.container_gate(CONTAINER, fx.spec, fx.cwd, fx.target,
                    ['make', 'verify-targeted'], fx.root / 'validation.raw', report['gate_timeout'])
            except BaseException as error:
                report['error'] = {'type': type(error).__name__, 'message': str(error)}
            report['elapsed'] = time.monotonic() - started
            if watcher:
                watcher.join(2)
            report['output'] = (fx.root / 'validation.raw').read_text()
            child = json.loads(child_path.read_text()) if child_path.exists() else None
            report.update(descendant_initial=child, descendant_before_finally=same(child),
                leader_initial=validation[0][1] if validation else None,
                leader_before_finally=same(validation[0][1]) if validation else None,
                unrelated_before_finally=same(unrelated_identity),
                active_before_finally=runtime._active_execution is not None,
                current_before_finally=runtime.current_process.pid if runtime.current_process else None,
                docker_resources_before_finally=dict(double.resources), provider_starts=fx.starts)
            if report['active_before_finally']:
                try:
                    runtime.begin_execution('must-not-overlap')
                except Exception as error:
                    report['redispatch_error'] = type(error).__name__
                try:
                    runtime.container_gate(CONTAINER, fx.spec, fx.cwd, fx.target,
                        ['make', 'verify-targeted'], fx.root / 'forbidden-overlap.raw', 1)
                except Exception as error:
                    report['overlap_gate_error'] = type(error).__name__
                report['overlap_gate_started'] = (fx.root / 'forbidden-overlap.raw').exists()
            if mode == 'old_callbacks':
                old_client = finished[-1]
                old_token = old_client['execution']
                new_token = runtime.begin_execution('next-validation')
                ready, release = root / 'next.ready', root / 'next.release'
                def stale_callbacks():
                    try:
                        until = time.monotonic() + 2
                        while not ready.exists() and time.monotonic() < until: time.sleep(.005)
                        assert ready.exists()
                        report['old_cancel_accepted'] = runtime.cancel(old_token)
                        count = len(report['signals'])
                        report['old_cleanup'] = real_finish(old_client, time.monotonic() + .1)
                        report['old_cleanup_signals'] = report['signals'][count:]
                        report['new_identity_retained'] = runtime._active_execution is new_token
                        report['new_cancelled'] = new_token.is_set()
                    except BaseException as error:
                        report['watcher_errors'].append(repr(error))
                    finally:
                        release.write_text('release')
                watcher = threading.Thread(target=stale_callbacks); watcher.start()
                code = ('from pathlib import Path;import sys,time;Path(sys.argv[1]).write_text("ready");'
                        '\nwhile not Path(sys.argv[2]).exists(): time.sleep(.005)\n')
                try:
                    value = container.captured_client(runtime,
                        [sys.executable, '-I', '-B', '-c', code, str(ready), str(release)],
                        root, new_token, time.monotonic() + 3)
                    report['next_exit_code'] = value.returncode
                finally:
                    watcher.join(2)
                    report['next_end_execution'] = real_end(new_token)
    except BaseException as error:
        report['driver_error'] = repr(error)
    finally:
        signal.alarm(0)
        phase = 'test-finally'
        if watcher: watcher.join(2)
        child = json.loads(child_path.read_text()) if child_path.exists() else None
        evidence = os.environ.get('CMH_VALIDATION_CLEANUP_EVIDENCE')
        if evidence:
            dest = Path(evidence); dest.mkdir(parents=True, mode=0o700, exist_ok=True)
            (dest / (mode + '.before-test-finally.json')).write_text(json.dumps(report, indent=2) + '\n')
        known = {v['pid']: v for v in [unrelated_identity] + [v for _, v in leaders] + ([child] if child else [])}
        groups = {(v['pgid'], v['sid']) for _, v in leaders}
        for raw in Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split():
            orphan = identity(int(raw))
            if orphan and orphan['pid'] not in known and (orphan['pgid'], orphan['sid']) in groups:
                known[orphan['pid']] = orphan
        report['test_fallback_kills'], report['test_reaps'] = [], []
        for expected in known.values():
            actual = same(expected)
            if actual and actual['state'] not in {'Z', 'X'}:
                # After signalling the leader, orphan reparenting is async.
                # The recorded child may still have its original owned parent.
                assert actual['uid'] == os.getuid() and actual['ppid'] in {os.getpid(), expected['ppid']}
                report['test_fallback_kills'].append(actual)
                os.kill(actual['pid'], signal.SIGKILL)
        for proc, _ in leaders + [(unrelated, unrelated_identity)]:
            proc.wait(timeout=1)
            for stream in (proc.stdout, proc.stderr):
                if stream is not None: stream.close()
        for expected in known.values():
            if expected['pid'] in {unrelated.pid, *[p.pid for p, _ in leaders]}: continue
            until = time.monotonic() + 1
            while same(expected):
                pid, status = os.waitpid(expected['pid'], os.WNOHANG)
                if pid:
                    report['test_reaps'].append({'pid': pid, 'status': status}); break
                if time.monotonic() >= until: raise TimeoutError('exact validation orphan reap deadline')
                time.sleep(.005)
        if fx: fx.doCleanups()
        if fixture_started: original_rules.CanonicalRuntimeIntegrationTests.doClassCleanups()
        report['remaining'] = [same(v) for v in known.values() if same(v)]
        print(json.dumps(report))


class ValidationGroupCleanupTests(unittest.TestCase):
    def case(self, mode):
        with tempfile.TemporaryDirectory(prefix='cmh-validation-case-') as tmp:
            value = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--case', mode, tmp],
                                   capture_output=True, text=True, timeout=26)
        evidence = os.environ.get('CMH_VALIDATION_CLEANUP_EVIDENCE')
        if evidence:
            dest = Path(evidence); dest.mkdir(parents=True, mode=0o700, exist_ok=True)
            (dest / (mode + '.stdout.raw')).write_text(value.stdout)
            (dest / (mode + '.stderr.raw')).write_text(value.stderr)
        self.assertEqual(value.returncode, 0, value.stderr + value.stdout)
        result = json.loads(value.stdout)
        self.assertNotIn('driver_error', result, result)
        self.assertNotIn('error', result, result)
        self.assertFalse(result['watcher_errors'], result)
        self.assertFalse(result['remaining'], result)
        self.assertIsNotNone(result['leader_initial'], result)
        self.assertTrue(result['unrelated_before_finally'], result)
        self.assertFalse(result['provider_starts'], result)
        self.assertFalse(result['docker_resources_before_finally'], result)
        self.assertEqual(result['contract_rule_commit'], PROJECT_BASE)
        return result

    def stopped(self, result):
        for key in ('descendant_before_finally', 'descendant_at_identity_release_attempt'):
            child = result[key]
            self.assertTrue(child is None or child['state'] in {'Z', 'X'}, result)
        self.assertFalse(result['active_before_finally'], result)
        self.assertIsNone(result['current_before_finally'], result)
        self.assertTrue(result['end_execution_result'], result)
        self.assertTrue(result['value']['cleanup_confirmed'], result)
        self.assertFalse([v for v in result['test_fallback_kills']
                          if v['pid'] != result['unrelated_initial']['pid']], result)

    def unconfirmed(self, result):
        self.assertNotEqual(result['value']['status'], 'PASS', result)
        self.assertFalse(result['value']['cleanup_confirmed'], result)
        self.assertTrue(result['active_before_finally'], result)
        self.assertIsNotNone(result['current_before_finally'], result)
        self.assertFalse(result['end_execution_result'], result)
        self.assertEqual(result['redispatch_error'], 'RuntimeError', result)
        self.assertEqual(result['overlap_gate_error'], 'RuntimeFailure', result)
        self.assertFalse(result['overlap_gate_started'], result)

    def test_original_rules_gate_stops_stdio_closed_descendant_before_release(self):
        result = self.case('success'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'PASS', result)
        self.assertEqual(result['value']['exit_code'], 0)
        self.assertEqual(result['source_phases'], ['candidate', 'snapshot', 'final'])
        self.assertEqual(result['leader_after_output']['state'], 'Z', result)
        self.assertTrue(result['validation_cleanup']['confirmed'], result)
        self.assertTrue(result['test_reaps'], result)
        self.assertIn('validation stdout\n', result['output'])
        self.assertIn('validation stderr\n', result['output'])

    def test_normal_success_without_descendant_needs_no_group_signal(self):
        result = self.case('normal'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'PASS', result)
        self.assertFalse(result['signals'], result)
        self.assertLess(result['elapsed'], 5)

    def test_failure_exit_is_preserved_after_group_shutdown(self):
        result = self.case('error_exit'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'FAIL', result)
        self.assertEqual(result['value']['exit_code'], 7)

    def test_exit124_is_timeout_after_group_shutdown(self):
        result = self.case('exit124'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'TIMEOUT', result)
        self.assertEqual(result['value']['exit_code'], 124)

    def test_cancel_preserves_identity_anchor_and_stops_group(self):
        result = self.case('cancel'); self.stopped(result)
        self.assertFalse(result['stale_cancel_accepted'], result)
        self.assertTrue(result['cancel_accepted'], result)
        self.assertEqual(result['value']['status'], 'CANCELLED', result)
        self.assertEqual(result['value']['exit_code'], -signal.SIGKILL)

    def test_total_timeout_stops_group_within_original_budget(self):
        result = self.case('timeout'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'TIMEOUT', result)
        self.assertLess(result['elapsed'], result['gate_timeout'] + .5)

    def test_signal_failure_never_certifies_or_releases_group(self):
        result = self.case('signal_failure'); self.unconfirmed(result)
        self.assertEqual(result['value']['exit_code'], 0, result)
        self.assertTrue(result['test_fallback_kills'], result)

    def test_unobserved_signal_effect_gets_no_new_cleanup_budget(self):
        result = self.case('signal_no_effect'); self.unconfirmed(result)
        self.assertLess(result['elapsed'], result['gate_timeout'] + .5)

    def test_damaged_identity_refuses_group_signal_and_release(self):
        result = self.case('identity_mismatch'); self.unconfirmed(result)
        self.assertFalse(result['signals'], result)

    def test_foreign_reaped_leader_cannot_authorize_stale_pgid_signal(self):
        result = self.case('lost_anchor'); self.unconfirmed(result)
        self.assertFalse(result['signals'], result)

    def test_cleanup_failure_does_not_replace_cancellation(self):
        result = self.case('cancel_signal_failure'); self.unconfirmed(result)
        self.assertEqual(result['value']['status'], 'CANCELLED', result)

    def test_diagnostic_failure_still_stops_group(self):
        result = self.case('log_failure'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'BLOCKED_ENVIRONMENT', result)
        self.assertEqual(result['value']['error_type'], 'OSError', result)

    def test_cleanup_failure_does_not_replace_original_diagnostic_error(self):
        result = self.case('log_and_signal_failure'); self.unconfirmed(result)
        self.assertEqual(result['value']['error_type'], 'OSError', result)

    def test_old_validation_callbacks_cannot_affect_next_owned_client(self):
        result = self.case('old_callbacks'); self.stopped(result)
        self.assertFalse(result['old_cancel_accepted'], result)
        self.assertFalse(result['old_cleanup']['confirmed'], result)
        self.assertFalse(result['old_cleanup_signals'], result)
        self.assertTrue(result['new_identity_retained'], result)
        self.assertFalse(result['new_cancelled'], result)
        self.assertEqual(result['next_exit_code'], 0)
        self.assertTrue(result['next_end_execution'], result)

    def test_cancel_after_group_shutdown_cannot_return_pass(self):
        result = self.case('late_cancel'); self.stopped(result)
        self.assertTrue(result['late_cancel_accepted'], result)
        self.assertEqual(result['value']['status'], 'CANCELLED', result)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--case':
        run_case(sys.argv[2], Path(sys.argv[3]))
    else:
        unittest.main()
