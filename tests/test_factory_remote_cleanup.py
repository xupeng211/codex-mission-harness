"""Bounded Linux process regressions; real supervision, local external-I/O doubles.

Each case runs in its own watchdog/subreaper process. The subreaper is a test
reaping aid, not a product feature. Assertions use the snapshot BEFORE finally.
"""
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


def identity(pid):
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
        return {"pid": pid, "state": f[0], "ppid": int(f[1]), "pgid": int(f[2]),
                "sid": int(f[3]), "starttime": f[19]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def same(expected):
    current = identity(expected["pid"])
    return current if current and current["starttime"] == expected["starttime"] else None


CLIENT = r'''
import json,os,subprocess,sys,time
from pathlib import Path
p=subprocess.Popen([sys.executable,'-I','-B','-c','import time; time.sleep(20)'],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
f=Path('/proc/'+str(p.pid)+'/stat').read_text().rsplit(') ',1)[1].split()
Path(sys.argv[1]).write_text(json.dumps({'pid':p.pid,'state':f[0],'ppid':int(f[1]),
    'pgid':int(f[2]),'sid':int(f[3]),'starttime':f[19]}))
if sys.argv[2] != 'return': time.sleep(20)
print('local response only')
'''

WORKER = r'''
import json,signal,sys,time
from pathlib import Path
from types import SimpleNamespace
from harness.factory_remote import Remote
v=json.load(sys.stdin)
mode=sys.argv[1]
if mode == 'normal':
 print(json.dumps({'status':'PASS','local_control_only':True})); sys.exit(0)
if mode in {'cancel','cutoff','cleanup_failure'}: signal.signal(signal.SIGTERM,signal.SIG_IGN)
r=Remote(v['cwd'],v['transcript'],v['timeout'],deadline=v['deadline'],
    adapter=SimpleNamespace(_trusted_subprocess_environment=lambda **kw:{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}))
if mode == 'lost_anchor':
 r.command([sys.executable,'-I','-B','-c',sys.argv[2],str(Path(v['cwd'])/'descendant.json'),'return'])
 Path(v['cwd'],'worker.ready').write_text('ready')
 time.sleep(0.15)
 sys.exit(7)
if mode in {'cancel','cutoff','cleanup_failure'}:
 import subprocess
 p=subprocess.Popen([sys.executable,'-I','-B','-c',sys.argv[2],str(Path(v['cwd'])/'descendant.json'),'return'])
 p.wait()
 Path(v['cwd'],'worker.ready').write_text('ready')
 time.sleep(20)
else:
 r.command([sys.executable,'-I','-B','-c',sys.argv[2],str(Path(v['cwd'])/'descendant.json'),
    'return' if mode == 'normal_descendant' else 'timeout'])
 print(json.dumps({'status':'PASS','local_control_only':True}))
'''

ROUTE_WORKER = r'''
import json,sys
from pathlib import Path
from unittest.mock import patch
from harness.adapters import FootballPredictionAdapter
import harness.factory_remote as remote
original=remote.Remote.command
def local_io(self,argv,**kw):
 with Path(sys.argv[4]).open('a') as stream: stream.write(json.dumps({'original_argv':argv})+'\n')
 if argv==['/usr/bin/git','--no-replace-objects','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','symbolic-ref','--quiet','--short','HEAD']:
  return original(self,argv,**kw)
 if argv[:2]==['/usr/bin/gh','api']:
  assert argv[argv.index('--method')+1]=='GET', 'no real or synthetic mutation allowed'
  return original(self,[sys.executable,'-I','-B',sys.argv[2],sys.argv[3],'timeout'],**kw)
 raise AssertionError('Unapproved external I/O: '+repr(argv))
with patch.object(FootballPredictionAdapter,'_trusted_base_checkout',return_value=Path(sys.argv[1])),patch.object(remote.Remote,'command',local_io):
 print(json.dumps(remote.run(**json.load(sys.stdin))))
'''


def run_case(mode, root):
    # Limit this aid to this disposable test runner, not the suite/product.
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    def alarm(*_):
        raise TimeoutError("independent 12-second process-case watchdog")
    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(12)
    runtime = LocalRuntime()
    original_popen, original_killpg = subprocess.Popen, os.killpg
    workers, signals, waits, errors = [], [], [], []
    phase = "product"
    result = {"case": mode}
    fx = None
    watcher = None
    client = root / 'client.py'
    client.write_text(CLIENT)
    unrelated = original_popen([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(20)'],
        start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    unrelated_identity = identity(unrelated.pid)
    spec, cwd, target, body, policy = {'mission_id': 'local-cleanup'}, root, {'head': 'a'*40, 'base': 'b'*40}, '', {}
    transcript = root / 'remote.raw'
    token = runtime.begin_execution(spec['mission_id'])
    old_token = None
    timeout = 2
    finished_workers = []
    real_finish = runtime._finish_remote_worker
    def finish(worker, deadline):
        finished_workers.append(worker)
        return real_finish(worker, deadline)
    try:
        if mode == 'actual_route':
            from test_factory_project_integration import CanonicalRuntimeIntegrationTests
            from test_factory_preflight_inspection import publication_body
            from test_factory_controller_gates import DELIVERY
            fx = CanonicalRuntimeIntegrationTests('test_pr_body_uses_original_trusted_preflight')
            fx.setUpClass()
            fx.setUp()
            spec, cwd, target = fx.candidate()
            body, policy = publication_body(fx, target), DELIVERY
            runtime.end_execution(token)
            token = runtime.begin_execution(spec['mission_id'])
            timeout = 5
            result['binding'] = {'rules_commit': 'a65464d1e5de498a072ed9a8fdf69ce46bcc04c5',
                'target': target, 'real': ['verify_target', 'validate_pr_body', 'reconcile/observe', 'Remote.command'],
                'doubles': ['fixed original rule checkout resolver', 'gh GET I/O only; local git is real']}

        def launch(argv, **kw):
            assert argv == [sys.executable, '-m', 'harness.factory_remote']
            script = ([sys.executable, '-B', '-c', ROUTE_WORKER, str(fx.snapshot), str(client),
                str(root/'descendant.json'), str(root/'route.jsonl')] if mode == 'actual_route' else
                [sys.executable, '-B', '-c', WORKER,
                    'normal_descendant' if mode == 'cleanup_failure_normal' else
                    'normal' if mode == 'cancel_after_shutdown' else
                    'command_timeout' if mode == 'diagnostic_failure' else mode, CLIENT])
            proc = original_popen(script, **kw)
            workers.append((proc, identity(proc.pid)))
            return proc

        def group_signal(pgid, sig):
            witness = [identity(pgid)]
            child_path = root / 'descendant.json'
            if child_path.exists(): witness.append(same(json.loads(child_path.read_text())))
            witness = [w for w in witness if w is not None and w['pgid'] == pgid]
            assert any(expected['pid'] == pgid for _, expected in workers) and witness, 'unowned group refused by test'
            signals.append({'phase': phase, 'pgid': pgid, 'signal': int(sig), 'witness': witness})
            if mode in {'cleanup_failure', 'cleanup_failure_normal'} and phase == 'product':
                raise OSError('injected group signal failure')
            return original_killpg(pgid, sig)

        def watch():
            try:
                until = time.monotonic()+3
                while not (root/'worker.ready').exists() and time.monotonic()<until: time.sleep(0.002)
                if not (root/'worker.ready').exists(): raise AssertionError('worker readiness missing')
                if mode == 'cancel':
                    result['cancelled'] = runtime.cancel(token)
                else:
                    # Simulate a foreign reaper consuming our child; no later
                    # signal may rely on the now-unpinned PID/PGID.
                    proc, expected = workers[-1]
                    assert same(expected)
                    pid, status = os.waitpid(proc.pid, 0)
                    result['foreign_reap'] = {'pid': pid, 'status': status}
            except BaseException as error:
                errors.append(repr(error))

        started = time.monotonic()
        from harness.adapters import FootballPredictionAdapter
        real_write = FootballPredictionAdapter._write_private_file
        real_fsync = os.fsync
        def fsync(fd):
            if mode == 'diagnostic_failure' and os.readlink(f'/proc/self/fd/{fd}').endswith('.cleanup.json'):
                raise OSError(28, 'injected cleanup evidence ENOSPC')
            return real_fsync(fd)
        def write(path, *args, **kwargs):
            value = real_write(path, *args, **kwargs)
            if mode == 'cancel_after_shutdown':
                result['late_current_cancel_accepted'] = runtime.cancel(token)
            return value
        with patch('harness.factory_runtime.subprocess.Popen', side_effect=launch), \
                patch('os.killpg', side_effect=group_signal), \
                patch.object(runtime, '_finish_remote_worker', side_effect=finish), \
                patch.object(FootballPredictionAdapter, '_write_private_file', side_effect=write), \
                patch('os.fsync', side_effect=fsync), \
                patch('harness.adapters.FootballPredictionAdapter._trusted_subprocess_environment',
                      return_value={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(Path.home())}):
            if mode in {'cancel', 'lost_anchor'}:
                watcher = threading.Thread(target=watch)
                watcher.start()
            try:
                result['value'] = runtime.project_remote('reconcile' if fx else 'ci', policy, spec, cwd,
                    target, body, transcript, timeout)
            except BaseException as error:
                result['error'] = {'type': type(error).__name__, 'message': str(error),
                    'notes': getattr(error, '__notes__', []), 'remote_cleanup': getattr(error, 'remote_cleanup', None)}
            if watcher: watcher.join(2)
            result['elapsed'] = time.monotonic()-started
            # This is the product result, captured before any test kill/reap.
            child = json.loads((root/'descendant.json').read_text()) if (root/'descendant.json').exists() else None
            result['descendant_initial'] = child
            result['descendant_before_finally'] = same(child) if child else None
            result['worker_before_finally'] = [same(expected) for _, expected in workers]
            runtime.end_execution(token)  # Outer Factory.run must not release unresolved ownership.
            result['active_before_finally'] = runtime._active_execution is token
            result['current_before_finally'] = runtime.current_process.pid if runtime.current_process else None
            if result['active_before_finally']:
                try:
                    runtime.project_remote('ci',policy,spec,cwd,target,body,root/'blocked.raw',1)
                except Exception as error:
                    result['redispatch_error'] = type(error).__name__
                result['workers_after_redispatch'] = len(workers)
            result['unrelated_before_finally'] = same(unrelated_identity)
            if mode == 'normal':
                old_token = token
                new_token = runtime.begin_execution('next')
                try:
                    result['old_cancel_accepted'] = runtime.cancel(old_token)
                    result['new_cancelled_by_old'] = new_token.is_set()
                    result['old_cleanup'] = real_finish(finished_workers[0], time.monotonic()+0.1)
                    result['new_identity_after_old_cleanup'] = runtime._active_execution is new_token
                finally:
                    runtime.end_execution(new_token)
    except BaseException as error:
        result['driver_error'] = repr(error)
    finally:
        signal.alarm(0)
        if watcher: watcher.join(2)
        phase = 'test-finally'
        child_path = root/'descendant.json'
        child = json.loads(child_path.read_text()) if child_path.exists() else None
        # A watchdog may interrupt the client just before its identity file
        # write. In this isolated subreaper, recover only our direct orphans
        # in an already recorded task group/session, then pin their starttime.
        known = {v['pid']:v for v in [unrelated_identity]+[v for _,v in workers]+([child] if child else [])}
        groups = {(v['pgid'],v['sid']) for _,v in workers}
        for value in Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split():
            orphan = identity(int(value))
            if orphan and orphan['pid'] not in known and (orphan['pgid'],orphan['sid']) in groups:
                known[orphan['pid']] = orphan
                result.setdefault('test_discovered_orphans', []).append(orphan)
        # PID + starttime + original group/session, never names or broad kill.
        for expected in known.values():
            current = same(expected)
            if current and current['state'] not in {'Z', 'X'}:
                assert current['pgid'] == expected['pgid'] and current['sid'] == expected['sid']
                result.setdefault('test_fallback_kills', []).append(current)
                os.kill(current['pid'], signal.SIGKILL)
        for proc, _ in workers:
            proc.wait(timeout=1)
            for stream in (proc.stdin, proc.stdout):
                if stream: stream.close()
        unrelated.wait(timeout=1)
        for child in [v for pid,v in known.items() if pid not in {unrelated.pid,*[p.pid for p,_ in workers]}]:
            until = time.monotonic()+1
            while True:
                try:
                    pid, status = os.waitpid(child['pid'], os.WNOHANG)
                    if pid:
                        waits.append({'pid': pid, 'status': status, 'test_reaped_only': True}); break
                    if time.monotonic() >= until: raise AssertionError('descendant not reapable after precise cleanup')
                    time.sleep(0.005)
                except ChildProcessError:
                    assert same(child) is None; break
        result.update(signals=signals, test_waits=waits, watcher_errors=errors,
            remaining=[same(v) for v in known.values() if same(v)])
        result['artifacts'] = {p.name: p.read_text() for p in root.iterdir()
            if p.is_file() and p.name not in {'client.py','descendant.json','worker.ready'}}
        if fx:
            fx.doCleanups(); fx.doClassCleanups()
        print(json.dumps(result))


class RemoteGroupCleanupTests(unittest.TestCase):
    def case(self, mode):
        with tempfile.TemporaryDirectory(prefix='cmh-remote-group-case-') as tmp:
            p = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--case', mode, tmp],
                capture_output=True, text=True, timeout=16)
        dest = os.environ.get('CMH_REMOTE_CLEANUP_EVIDENCE')
        if dest:
            out = Path(dest); out.mkdir(mode=0o700, parents=True, exist_ok=True)
            (out/(mode+'.stdout.raw')).write_text(p.stdout)
            (out/(mode+'.stderr.raw')).write_text(p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        r = json.loads(p.stdout)
        self.assertNotIn('driver_error', r, r)
        self.assertFalse(r['watcher_errors'], r)
        self.assertFalse(r['remaining'], r)
        self.assertTrue(r['unrelated_before_finally'], r)
        return r

    def stopped(self, r):
        child = r['descendant_before_finally']
        self.assertTrue(child is None or child['state'] in {'Z','X'}, r)
        self.assertFalse(r['active_before_finally'], r)
        self.assertIsNone(r['current_before_finally'], r)
        self.assertFalse([p for p in r.get('test_fallback_kills', [])
                          if p['pid'] != r['unrelated_before_finally']['pid']], r)

    def test_exited_worker_client_timeout_stops_live_same_group_descendant(self):
        r = self.case('command_timeout'); self.stopped(r)
        self.assertEqual(r['error']['type'], 'RuntimeFailure')
        self.assertIn('UNKNOWN', r['error']['message'])
        self.assertLess(r['elapsed'], 2.2)

    def test_real_admission_reconcile_observe_command_route(self):
        r = self.case('actual_route'); self.stopped(r)
        self.assertEqual(r['error']['type'], 'RuntimeFailure')
        route = [json.loads(v)['original_argv'] for v in r['artifacts']['route.jsonl'].splitlines()]
        self.assertEqual(route[0][-4:], ['symbolic-ref', '--quiet', '--short', 'HEAD'])
        self.assertEqual(route[1][:2], ['/usr/bin/gh', 'api'])
        self.assertEqual(r['binding']['rules_commit'], 'a65464d1e5de498a072ed9a8fdf69ce46bcc04c5')

    def test_normal_exit_preserves_result_and_unrelated_process(self):
        r = self.case('normal'); self.stopped(r)
        self.assertEqual(r['value']['status'], 'PASS')
        self.assertFalse(r['signals'])
        self.assertFalse(r['old_cancel_accepted'])
        self.assertFalse(r['new_cancelled_by_old'])
        self.assertFalse(r['old_cleanup']['confirmed'])
        self.assertTrue(r['new_identity_after_old_cleanup'])

    def test_normal_exit_with_descendant_stops_group_before_release(self):
        r = self.case('normal_descendant'); self.stopped(r)
        self.assertEqual(r['value']['status'], 'PASS')

    def test_cancel_and_parent_cutoff_force_reap_without_fake_result(self):
        for mode, error in [('cancel','ExecutionStopped'),('cutoff','TimeoutExpired')]:
            with self.subTest(mode=mode):
                r = self.case(mode); self.stopped(r)
                self.assertEqual(r['error']['type'], error)
                self.assertNotIn('value', r)
                self.assertLess(r['elapsed'], 2.2)

    def test_cleanup_failure_keeps_original_error_and_execution_identity(self):
        r = self.case('cleanup_failure')
        self.assertEqual(r['error']['type'], 'TimeoutExpired')
        self.assertTrue(r['active_before_finally'], r)
        self.assertIsNotNone(r['current_before_finally'], r)
        self.assertFalse(r['error']['remote_cleanup']['confirmed'])
        self.assertEqual(r['redispatch_error'], 'RuntimeFailure')
        self.assertEqual(r['workers_after_redispatch'], 1)
        self.assertTrue(r.get('test_fallback_kills'), r)
        self.assertLess(r['elapsed'], 2.2)

    def test_lost_unreaped_leader_refuses_group_signal_and_release(self):
        r = self.case('lost_anchor')
        self.assertIn('error', r)
        self.assertFalse(r['signals'], r)
        self.assertTrue(r['active_before_finally'], r)
        self.assertFalse(r['error']['remote_cleanup']['confirmed'])

    def test_cleanup_failure_cannot_return_a_normal_observation(self):
        r = self.case('cleanup_failure_normal')
        self.assertEqual(r['error']['type'], 'RuntimeFailure')
        self.assertNotIn('value', r)
        self.assertTrue(r['active_before_finally'])
        self.assertFalse(r['error']['remote_cleanup']['confirmed'])

    def test_diagnostic_failure_does_not_block_cleanup_or_mask_original(self):
        r = self.case('diagnostic_failure'); self.stopped(r)
        self.assertEqual(r['error']['type'], 'RuntimeFailure')
        self.assertEqual(r['error']['message'], 'project PR/CI worker failed; outcome retained as UNKNOWN, no replay')
        cleanup = r['error']['remote_cleanup']
        self.assertTrue(cleanup['confirmed'])
        self.assertFalse(cleanup['evidence_written'])
        self.assertTrue(any('ENOSPC' in e for e in cleanup['errors']))

    def test_current_cancellation_during_cleanup_cannot_return_success(self):
        r = self.case('cancel_after_shutdown'); self.stopped(r)
        self.assertTrue(r['late_current_cancel_accepted'])
        self.assertEqual(r['error']['type'], 'ExecutionStopped')
        self.assertNotIn('value', r)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--case':
        run_case(sys.argv[2], Path(sys.argv[3]))
    else:
        unittest.main()
