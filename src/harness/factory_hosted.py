"""Bounded GitHub publication/check polling, not a workflow engine or merger."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .sandbox import SAFE_PATH


def run(policy, cwd, target, branch, transcript, timeout):
    deadline = time.monotonic() + timeout
    env = {"PATH": SAFE_PATH, "HOME": str(Path.home()), "LANG": "C.UTF-8", "GH_PROMPT_DISABLED": "1",
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1"}
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
        if key in os.environ:
            env[key] = os.environ[key]
    def command(argv, polling=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("hosted CI deadline exhausted; no PASS was inferred")
        completed = subprocess.run(argv, cwd=cwd, env=env, timeout=min(60, remaining), capture_output=True, text=True)
        with Path(transcript).open('a') as stream:
            stream.write(json.dumps({"argv": argv, "exit_code": completed.returncode,
                                     "stdout": completed.stdout[-32000:], "stderr": completed.stderr[-8000:]}) + '\n')
        if completed.returncode and polling:
            return None
        if completed.returncode:
            raise RuntimeError(f"GitHub command failed: {completed.stderr[-2000:]}")
        return completed.stdout
    repository = policy['repository']
    protocol = command(['/usr/bin/gh', 'config', 'get', 'git_protocol', '--host', 'github.com']).strip()
    destination = f'git@github.com:{repository}.git' if protocol == 'ssh' else f'https://github.com/{repository}.git'
    env['GIT_SSH_COMMAND'] = '/usr/bin/ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15'
    # No force, no main update, no merge. Candidate Git config and hooks cannot
    # select authentication or an alternate destination.
    command(['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
             '-c', 'credential.helper=', '-c', 'credential.helper=!/usr/bin/gh auth git-credential',
             'push', '--', destination, f'{target["head"]}:refs/heads/{branch}'])
    receipts = {}
    while time.monotonic() < deadline:
        for workflow in policy['workflows']:
            raw = command(['/usr/bin/gh', 'run', 'list', '--repo', repository, '--workflow', workflow,
                           '--branch', branch, '--commit', target['head'], '--event', 'push', '--limit', '100',
                           '--json', 'databaseId,headSha,status,conclusion,url,workflowName,event'], polling=True)
            if raw is None:
                continue
            runs = json.loads(raw)
            matching = [r for r in runs if r['headSha'] == target['head'] and r['event'] == 'push']
            if matching:
                receipts[workflow] = matching
        if set(receipts) == set(policy['workflows']) and all(r['status'] == 'completed' for runs in receipts.values() for r in runs):
            result = {'status': 'PASS' if all(r['conclusion'] == 'success' for runs in receipts.values() for r in runs) else 'FAIL',
                      'target': target, 'repository': repository, 'branch': branch, 'runs': receipts,
                      'MERGE_PERFORMED': False}
            # Record real job/matrix outcomes, not just a workflow headline.
            result['jobs'] = {str(r['databaseId']): json.loads(command(['/usr/bin/gh', 'run', 'view', str(r['databaseId']),
                               '--repo', repository, '--json', 'jobs']))['jobs'] for runs in receipts.values() for r in runs}
            if any(job['conclusion'] != 'success' for jobs in result['jobs'].values() for job in jobs) or not all(result['jobs'].values()):
                result['status'] = 'FAIL'
            return result
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise TimeoutError("hosted checks missing or unfinished; UNKNOWN is not PASS")


def main():
    args = json.load(sys.stdin)
    print(json.dumps(run(**args)))


if __name__ == '__main__':
    main()
