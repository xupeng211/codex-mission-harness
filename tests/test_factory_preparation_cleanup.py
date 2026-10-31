"""真实本地准备进程；外部 Docker 替身，独立 watchdog/finally 与精确身份回收。

子进程中的 subreaper 只帮助测试回收孤儿；产品必须在 finally 前停止后代。
"""
import ctypes
import io
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
from footballprediction_contract import ContractUnavailable, raise_prerequisite
from unittest.mock import patch

from harness.factory_container import captured_client, prepare_client
from harness.factory_runtime import LocalRuntime


def identity(pid):
    try:
        root = Path('/proc') / str(pid)
        fields = (root / 'stat').read_text().rsplit(') ', 1)[1].split()
        return dict(pid=pid, state=fields[0], ppid=int(fields[1]), pgid=int(fields[2]),
                    sid=int(fields[3]), starttime=fields[19], uid=root.stat().st_uid)
    except (FileNotFoundError, ProcessLookupError):
        return None


def same(expected):
    actual = identity(expected['pid'])
    return actual if actual and actual['starttime'] == expected['starttime'] else None


CHILD = r'''
import json,os,signal,sys,time
from pathlib import Path
signal.signal(signal.SIGTERM,signal.SIG_IGN)
p=Path('/proc')/str(os.getpid()); f=(p/'stat').read_text().rsplit(') ',1)[1].split()
Path(sys.argv[1]).write_text(json.dumps(dict(pid=os.getpid(),state=f[0],ppid=int(f[1]),
 pgid=int(f[2]),sid=int(f[3]),starttime=f[19],uid=p.stat().st_uid)))
time.sleep(20)
'''

CLIENT = r'''
import signal,subprocess,sys,time
from pathlib import Path
mode,path,child=sys.argv[1:]
if mode != 'normal':
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 subprocess.Popen([sys.executable,'-I','-B','-c',child,path],
  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 end=time.monotonic()+2
 while not Path(path).exists() and time.monotonic()<end: time.sleep(0.005)
 if not Path(path).exists(): raise RuntimeError('synthetic child not ready')
print('preparation stdout',flush=True)
print('preparation stderr',file=sys.stderr,flush=True)
if mode == 'wait': time.sleep(20)
sys.exit(7 if mode == 'error' else 0)
'''


def run_case(mode, root):
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    def alarm(*_):
        raise TimeoutError('independent 12-second preparation watchdog')
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(12)
    runtime = LocalRuntime()
    real_popen, real_killpg = subprocess.Popen, os.killpg
    leaders, signals, finished, watcher_errors = [], [], [], []
    report = {'case': mode}
    fx = double = watcher = original_rule_fixture = None
    token = None
    phase = 'product'
    child_path = root / 'descendant.json'
    unrelated = real_popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(20)'],
                           start_new_session=True)
    unrelated_identity = identity(unrelated.pid)
    report['unrelated_initial'] = unrelated_identity
    original_consume = __import__('harness.factory_container', fromlist=['consume_output']).consume_output
    real_finish = getattr(runtime, '_finish_owned_client', None)

    def launch(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        leaders.append((proc, identity(proc.pid)))
        return proc

    def group_signal(pgid, sig):
        anchor = next((v for _, v in leaders if v['pid'] == pgid and same(v)), None)
        # Even a deliberately broken product must never signal an unrelated group.
        assert anchor and same(anchor)['ppid'] == os.getpid(), (pgid, anchor)
        assert same(anchor)['pgid'] == same(anchor)['sid'] == pgid
        signals.append({'phase': phase, 'pgid': pgid, 'signal': sig, 'anchor': same(anchor)})
        if phase == 'product' and mode in {'signal_failure', 'log_and_signal_failure', 'gate_signal_failure'}:
            raise PermissionError('injected preparation signal failure')
        if phase == 'product' and mode == 'signal_no_effect':
            return
        return real_killpg(pgid, sig)

    def finish(client, deadline):
        finished.append(client)
        value = real_finish(client, deadline)
        if mode == 'late_cancel':
            report['late_cancel_accepted'] = runtime.cancel(token)
        return value

    def consume(*args, **kwargs):
        value = original_consume(*args, **kwargs)
        if mode == 'lost_anchor':
            proc = args[0]
            report['foreign_reap'] = os.waitpid(proc.pid, 0)
        if mode == 'identity_mismatch':
            # Inject damaged ownership metadata, never forge an unrelated process.
            runtime._preparation_client['identity']['starttime'] = 'invalid-starttime'
        return value

    def cancel_when_ready():
        try:
            until = time.monotonic() + 2
            while not child_path.exists() and time.monotonic() < until:
                time.sleep(0.005)
            if not child_path.exists():
                raise AssertionError('preparation never became ready')
            report['cancel_accepted'] = runtime.cancel(token)
        except BaseException as error:
            watcher_errors.append(repr(error))

    class BrokenLog(io.BytesIO):
        def write(self, data):
            raise OSError(28, 'original diagnostic ENOSPC')
        def flush(self):
            raise OSError(5, 'secondary diagnostic EIO')

    try:
        from contextlib import ExitStack
        if mode == 'full_gate_original_rules':
            from test_factory_project_integration import CanonicalRuntimeIntegrationTests, PROJECT_BASE
            original_rule_fixture = CanonicalRuntimeIntegrationTests
            original_rule_fixture.setUpClass()
            fx = original_rule_fixture('test_pr_body_uses_original_trusted_preflight')
            fx.setUp()
            fx.spec, fx.cwd, fx.target = fx.candidate()
            report['contract_rule_commit'] = PROJECT_BASE
        with ExitStack() as stack:
            stack.enter_context(patch('harness.factory_container.subprocess.Popen', side_effect=launch))
            stack.enter_context(patch('os.killpg', side_effect=group_signal))
            stack.enter_context(patch('harness.factory_container.consume_output', side_effect=consume))
            if real_finish:
                stack.enter_context(patch.object(runtime, '_finish_owned_client', side_effect=finish))
            if mode == 'finish_diagnostic_failure':
                stack.enter_context(patch('harness.factory_container.RedactedOutput.finish',
                                          side_effect=OSError(28, 'synthetic-private-password')))
            started = time.monotonic()
            try:
                if mode.startswith('gate_') or mode.startswith('full_gate'):
                    from test_factory_container_lifecycle import DockerDouble
                    from test_factory_controller_gates import ControllerGatesTests, CONTAINER
                    if fx is None:
                        fx = ControllerGatesTests(); fx.setUp()
                    double = DockerDouble(fx, runtime)
                    dispatch = double.dispatch
                    child_path = fx.root / 'descendant.json'
                    def docker_io(argv, **kwargs):
                        if mode == 'full_gate_original_rules' and argv[1:3] == ['image', 'inspect']:
                            double.calls.append(('image', argv))
                            proc = launch([sys.executable, '-I', '-B', '-c', 'import sys; print(sys.argv[1])',
                                           argv[-1]], **kwargs)
                            double.clients.append(proc)
                            return proc
                        if argv[1] != 'cp':
                            return dispatch(argv, **kwargs)
                        double.calls.append(('cp', argv))
                        proc = launch([sys.executable, '-I', '-B', '-c', CLIENT,
                                       'return', str(child_path), CHILD], **kwargs)
                        double.clients.append(proc)
                        return proc
                    double.dispatch = docker_io
                    with ExitStack() as docker_hooks:
                        if mode == 'full_gate_original_rules':
                            # Only external Docker I/O is substituted here.
                            # Original source_check, image checking, trusted
                            # BASE rules, Git and binding execute unchanged.
                            for name, method in [('Popen', double.popen), ('run', double.command),
                                                 ('check_output', double.output)]:
                                docker_hooks.enter_context(patch('harness.factory_container.subprocess.' + name,
                                                                  side_effect=method))
                            import harness.factory_container as container
                            source_check = container.source_check
                            report['source_phases'] = []
                            def source_probe(runtime, request, stage, *args):
                                report['source_phases'].append(stage)
                                return source_check(runtime, request, stage, *args)
                            docker_hooks.enter_context(patch.object(container, 'source_check', side_effect=source_probe))
                        else:
                            docker_hooks.enter_context(double.hooks())
                        report['value'] = runtime.container_gate(CONTAINER, fx.spec, fx.cwd, fx.target,
                            ['make', 'verify-targeted'], fx.root / 'preparation.raw', 7 if original_rule_fixture else 4)
                    report['docker_resources_before_finally'] = dict(double.resources)
                    report['docker_calls'] = [v for v, _ in double.calls]
                    if original_rule_fixture:
                        report['provider_starts'] = fx.starts
                else:
                    token = runtime.begin_execution('preparation-case')
                    if mode == 'cancel':
                        watcher = threading.Thread(target=cancel_when_ready)
                        watcher.start()
                    client_mode = ('normal' if mode in {'normal', 'old_callbacks'} else
                                   'error' if mode == 'error_exit' else
                                   'wait' if mode in {'cancel', 'timeout'} else 'return')
                    argv = [sys.executable, '-I', '-B', '-c', CLIENT, client_mode, str(child_path), CHILD]
                    until = time.monotonic() + (0.6 if mode in {'timeout', 'signal_no_effect'} else 3)
                    if mode in {'log_failure', 'log_and_signal_failure'}:
                        output, error = BrokenLog(), io.BytesIO()
                        report['exit_code'] = prepare_client(runtime, argv, root, output, token, until,
                                                             stderr_log=error)
                    else:
                        value = captured_client(runtime, argv, root, token, until)
                        report.update(exit_code=value.returncode, stdout=value.stdout.decode(), stderr=value.stderr.decode())
            except BaseException as error:
                report['error'] = {'type': type(error).__name__, 'message': str(error),
                    'notes': getattr(error, '__notes__', []), 'cleanup': getattr(error, 'preparation_cleanup', None),
                    'stdout': getattr(error, 'stdout', b'').decode(), 'stderr': getattr(error, 'stderr', b'').decode()}
            report['elapsed'] = time.monotonic() - started
            if watcher:
                watcher.join(2)
            child = json.loads(child_path.read_text()) if child_path.exists() else None
            report.update(descendant_initial=child, descendant_before_finally=same(child) if child else None,
                leaders_initial=[v for _, v in leaders], leaders_before_finally=[same(v) for _, v in leaders],
                unrelated_before_finally=same(unrelated_identity))
            if token is not None:
                report['end_execution_result'] = runtime.end_execution(token)
            report.update(active_before_finally=runtime._active_execution is not None,
                current_before_finally=runtime.current_process.pid if runtime.current_process else None,
                preparation_cleanups=getattr(runtime, '_preparation_cleanups', []))
            if report['active_before_finally']:
                try:
                    runtime.begin_execution('must-not-steal')
                except Exception as error:
                    report['redispatch_error'] = type(error).__name__
            if mode == 'old_callbacks':
                old_client = finished[-1]
                new_token = runtime.begin_execution('next-preparation')
                ready, release = root / 'next.ready', root / 'next.release'
                def stale_callback():
                    try:
                        until = time.monotonic() + 2
                        while not ready.exists() and time.monotonic() < until:
                            time.sleep(0.005)
                        assert ready.exists()
                        report['old_cancel_accepted'] = runtime.cancel(token)
                        count = len(signals)
                        report['old_cleanup'] = real_finish(old_client, time.monotonic() + 0.1)
                        report['stale_cleanup_signals'] = signals[count:]
                        report['new_identity_retained'] = runtime._active_execution is new_token
                        report['new_cancelled'] = new_token.is_set()
                    except BaseException as error:
                        watcher_errors.append(repr(error))
                    finally:
                        release.write_text('release')
                watcher = threading.Thread(target=stale_callback); watcher.start()
                code = ('from pathlib import Path; import sys,time; '
                        'Path(sys.argv[1]).write_text("ready"); '
                        '\nwhile not Path(sys.argv[2]).exists(): time.sleep(0.005)\nprint("next stdout")')
                try:
                    value = captured_client(runtime, [sys.executable, '-I', '-B', '-c', code, str(ready), str(release)],
                                            root, new_token, time.monotonic() + 3)
                    report['next_exit_code'] = value.returncode
                finally:
                    watcher.join(2)
                    report['next_end_execution'] = runtime.end_execution(new_token)
    except ContractUnavailable as error:
        report['prerequisite_error'] = {'code': 'BLOCKED_CONTRACT_SOURCE', 'message': str(error)}
    except BaseException as error:
        report['driver_error'] = repr(error)
    finally:
        signal.alarm(0)
        phase = 'test-finally'
        if watcher:
            watcher.join(2)
        child = json.loads(child_path.read_text()) if child_path.exists() else None
        known = {v['pid']: v for v in [unrelated_identity] + [v for _, v in leaders] + ([child] if child else [])}
        # Recover only our own direct orphans in a group/session recorded at launch.
        groups = {(v['pgid'], v['sid']) for _, v in leaders}
        for raw in Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split():
            orphan = identity(int(raw))
            if orphan and orphan['pid'] not in known and (orphan['pgid'], orphan['sid']) in groups:
                known[orphan['pid']] = orphan
        report['test_fallback_kills'], report['test_reaps'] = [], []
        for expected in known.values():
            current = same(expected)
            if current and current['state'] not in {'Z', 'X'}:
                assert current['uid'] == os.getuid()
                assert (current['pgid'], current['sid']) == (expected['pgid'], expected['sid'])
                report['test_fallback_kills'].append(current)
                os.kill(current['pid'], signal.SIGKILL)
        # The product must already have stopped its group; the test subreaper
        # performs only final orphan reap in successful cases.
        for proc, _ in leaders:
            proc.wait(timeout=1)
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
        unrelated.wait(timeout=1)
        for expected in known.values():
            if expected['pid'] in {unrelated.pid, *[p.pid for p, _ in leaders]}:
                continue
            until = time.monotonic() + 1
            while True:
                try:
                    pid, status = os.waitpid(expected['pid'], os.WNOHANG)
                    if pid:
                        report['test_reaps'].append({'pid': pid, 'status': status}); break
                    if time.monotonic() >= until:
                        raise AssertionError('owned child not reapable after precise cleanup')
                    time.sleep(0.005)
                except ChildProcessError:
                    assert same(expected) is None
                    break
        if double:
            double.close()
        if fx:
            fx.doCleanups()
        if original_rule_fixture:
            original_rule_fixture.doClassCleanups()
        report.update(remaining=[same(v) for v in known.values() if same(v)], signals=signals,
                      watcher_errors=watcher_errors)
        print(json.dumps(report))


class PreparationGroupCleanupTests(unittest.TestCase):
    def case(self, mode):
        with tempfile.TemporaryDirectory(prefix='cmh-preparation-case-') as tmp:
            value = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--case', mode, tmp],
                                   capture_output=True, text=True, timeout=18)
        evidence = os.environ.get('CMH_PREPARATION_CLEANUP_EVIDENCE')
        if evidence:
            dest = Path(evidence); dest.mkdir(parents=True, mode=0o700, exist_ok=True)
            (dest / (mode + '.stdout.raw')).write_text(value.stdout)
            (dest / (mode + '.stderr.raw')).write_text(value.stderr)
        self.assertEqual(value.returncode, 0, value.stderr + value.stdout)
        result = json.loads(value.stdout)
        raise_prerequisite(result)
        self.assertNotIn('driver_error', result, result)
        self.assertFalse(result['watcher_errors'], result)
        self.assertFalse(result['remaining'], result)
        self.assertTrue(result['unrelated_before_finally'], result)
        return result

    def stopped(self, result):
        child = result['descendant_before_finally']
        self.assertTrue(child is None or child['state'] in {'Z', 'X'}, result)
        self.assertFalse(result['active_before_finally'], result)
        self.assertIsNone(result['current_before_finally'], result)
        self.assertFalse([v for v in result['test_fallback_kills']
                          if v['pid'] != result['unrelated_initial']['pid']], result)

    def test_successful_leader_stops_stdio_closed_descendant_before_release(self):
        result = self.case('success_descendant'); self.stopped(result)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['stdout'], 'preparation stdout\n')
        self.assertEqual(result['stderr'], 'preparation stderr\n')
        self.assertTrue(result['signals'])
        self.assertTrue(all(v['anchor']['state'] == 'Z' for v in result['signals']))

    def test_full_container_gate_stops_copy_descendant_before_pass(self):
        result = self.case('full_gate'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'PASS', result)
        self.assertTrue(result['value']['cleanup_confirmed'])
        self.assertEqual(result['docker_resources_before_finally'], {})
        self.assertIn('run', result['docker_calls'])

    def test_original_source_rules_and_queries_only_replace_external_docker_io(self):
        result = self.case('full_gate_original_rules'); self.stopped(result)
        self.assertEqual(result['value']['status'], 'PASS', result)
        self.assertEqual(result['source_phases'], ['candidate', 'snapshot', 'final'])
        self.assertEqual(result['contract_rule_commit'], 'a65464d1e5de498a072ed9a8fdf69ce46bcc04c5')
        self.assertTrue(result['value']['source_unchanged'])
        self.assertTrue(result['value']['preparation_cleanup_confirmed'])
        self.assertFalse(result['provider_starts'])

    def test_normal_client_preserves_separate_output_without_group_signal(self):
        result = self.case('normal'); self.stopped(result)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['stdout'], 'preparation stdout\n')
        self.assertEqual(result['stderr'], 'preparation stderr\n')
        self.assertFalse(result['signals'])

    def test_error_exit_preserves_code_and_output_after_stopping_descendant(self):
        result = self.case('error_exit'); self.stopped(result)
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual(result['stdout'], 'preparation stdout\n')
        self.assertEqual(result['stderr'], 'preparation stderr\n')

    def test_cancellation_stops_even_sigterm_ignoring_group(self):
        result = self.case('cancel'); self.stopped(result)
        self.assertTrue(result['cancel_accepted'])
        self.assertEqual(result['error']['type'], 'ExecutionStopped')
        self.assertEqual(result['error']['message'], 'CANCELLED')
        self.assertLess(result['elapsed'], 1.5)

    def test_timeout_uses_original_remaining_budget_and_force_stops_group(self):
        result = self.case('timeout'); self.stopped(result)
        self.assertEqual(result['error']['type'], 'ExecutionStopped')
        self.assertEqual(result['error']['message'], 'TIMEOUT')
        self.assertLess(result['elapsed'], 0.9)

    def unconfirmed(self, result):
        self.assertTrue(result['active_before_finally'], result)
        self.assertIsNotNone(result['current_before_finally'], result)
        self.assertEqual(result['redispatch_error'], 'RuntimeError')
        self.assertNotIn('exit_code', result)
        self.assertFalse(result['error']['cleanup']['confirmed'], result)

    def test_foreign_reaped_anchor_cannot_authorize_a_group_signal(self):
        result = self.case('lost_anchor'); self.unconfirmed(result)
        self.assertFalse(result['signals'], result)

    def test_damaged_identity_refuses_signal_and_release(self):
        result = self.case('identity_mismatch'); self.unconfirmed(result)
        self.assertFalse(result['signals'], result)

    def test_signal_failure_cannot_be_confirmed_or_return_success(self):
        result = self.case('signal_failure'); self.unconfirmed(result)
        self.assertTrue(result['test_fallback_kills'], result)
        self.assertEqual(result['error']['cleanup']['exit_code'], 0)
        self.assertEqual(result['error']['stdout'], 'preparation stdout\n')
        self.assertEqual(result['error']['stderr'], 'preparation stderr\n')

    def test_unconfirmed_group_does_not_get_a_fresh_timeout_budget(self):
        result = self.case('signal_no_effect'); self.unconfirmed(result)
        self.assertLess(result['elapsed'], 0.9)

    def test_full_gate_cannot_claim_cleanup_or_pass_on_signal_failure(self):
        result = self.case('gate_signal_failure')
        self.assertNotEqual(result['value']['status'], 'PASS', result)
        self.assertFalse(result['value']['cleanup_confirmed'], result)
        self.assertFalse(result['value']['preparation_cleanup_confirmed'], result)
        self.assertTrue(result['active_before_finally'])
        self.assertNotIn('run', result['docker_calls'])

    def test_diagnostic_failure_does_not_skip_cleanup_or_mask_original(self):
        result = self.case('log_failure'); self.stopped(result)
        self.assertEqual(result['error']['type'], 'OSError')
        self.assertIn('original diagnostic ENOSPC', result['error']['message'])
        self.assertTrue(result['error']['cleanup']['confirmed'])
        self.assertFalse(result['error']['cleanup']['diagnostics_complete'])
        self.assertIn('diagnostic OSError errno=5', result['error']['cleanup']['errors'])

    def test_cleanup_failure_keeps_original_diagnostic_error(self):
        result = self.case('log_and_signal_failure'); self.unconfirmed(result)
        self.assertEqual(result['error']['type'], 'OSError')
        self.assertIn('original diagnostic ENOSPC', result['error']['message'])

    def test_final_diagnostic_failure_preserves_command_outcome_but_blocks_success(self):
        result = self.case('finish_diagnostic_failure'); self.stopped(result)
        self.assertEqual(result['error']['type'], 'RuntimeFailure')
        self.assertTrue(result['error']['cleanup']['confirmed'])
        self.assertFalse(result['error']['cleanup']['diagnostics_complete'])
        self.assertEqual(result['error']['cleanup']['exit_code'], 0)
        self.assertEqual(result['error']['stdout'], 'preparation stdout\n')
        self.assertEqual(result['error']['stderr'], 'preparation stderr\n')
        self.assertNotIn('synthetic-private-password', json.dumps(result['error']['cleanup']))

    def test_stale_cancel_and_cleanup_cannot_steal_the_next_preparation(self):
        result = self.case('old_callbacks'); self.stopped(result)
        self.assertFalse(result['old_cancel_accepted'])
        self.assertFalse(result['old_cleanup']['confirmed'])
        self.assertFalse(result['stale_cleanup_signals'])
        self.assertTrue(result['new_identity_retained'])
        self.assertFalse(result['new_cancelled'])
        self.assertEqual(result['next_exit_code'], 0)
        self.assertTrue(result['next_end_execution'])

    def test_late_current_cancel_after_shutdown_cannot_return_success(self):
        result = self.case('late_cancel'); self.stopped(result)
        self.assertTrue(result['late_cancel_accepted'])
        self.assertEqual(result['error']['message'], 'CANCELLED')
        self.assertNotIn('exit_code', result)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--case':
        run_case(sys.argv[2], Path(sys.argv[3]))
    else:
        unittest.main()
