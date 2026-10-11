"""Bounded PR2 tasks, using the existing delivery signature and ledger.

No approvals are issued here. Each of the two fixed edges has one successor path;
changing an approval, mission, signature or working directory cannot fork it.
"""
from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from .resource_gate import canonical, digest, ResourceGateDenied

VERSION = 'cmh-fresh-pr2-task/v1'
APPROVAL_VERSION = 'cmh-fresh-pr2-user-approval/v1'
PREFIX = 'HARNESS_PR2_FRESH_'
SUCCESSOR_VERSION = 'cmh-fixed-failed-pr2-successor/v1'
SUCCESSOR_APPROVAL_VERSION = 'cmh-fixed-failed-pr2-successor-approval/v1'
SUCCESSOR_PREFIX = 'HARNESS_PR2_SUCCESSOR_'
SUCCESSOR_RISKS = ['PARENT_UNKNOWN_RETAINED_NOT_SETTLED',
                   'GPT_QUOTA_UNKNOWN_NO_ADDITIONAL_PURCHASE',
                   'PROVIDER_PHYSICAL_COST_HARD_BOUND_UNPROVEN']
FAILED_MISSION = PREFIX + 'feb176100bf42820f7fcf39705961ad1e80cd468082679e5c7927400b49724fb'
FAILED_LEDGER_SHA = '304ac852dae5b71692c51f2b884f638a02ebfa2b81469441c3a275db7fa1807d'
FAILED_CHECKPOINT_SHA = 'fa104d0ba8e5b11e4208dcdb503b26083fa81d031dfae4df38a677380d7dc819'
FAILED_AUTH_SHA = '74c064dc9f70c92807110d36b71f8b1ebda3b524cb42117f9d06a7eb03a0cb77'
FAILED_ROW_SHA = 'e10b1a373fa02d18d98cb6e921b98e567e9298ae3a06b28a35d71037f0f878aa'
FAILED_EVIDENCE = {
    'gpt-real-failure-diagnosis.json': 'f5c80f92a670b951c203a3bfd07dc903ac81f59adcb523de1c86e15e36abf096',
    'gpt-original-transport/stdout.jsonl': '0ab9599d4c02b9aca723be96dbe59ff8a3b075c15e9f724b94040632f24d4b21',
    'gpt-original-transport/stderr': 'b18c9ea979e17bae93c1c1db737db608dc3769b29708d2cf400881a004443178',
    'gpt-original-transport/response.json': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'gpt-original-transport/binding.json': 'dcaba68b09ec5ed009666220e60ad8d272987113784bdad5d78554f8d009a479',
}
TASK_ROOT = Path('/home/xupeng/codex-mission-harness-evidence/autonomous-premerge-20261002')
HISTORY_LEDGER_SHA = '9bdc7e61d1cdba8a33a3a87c3f1304e1830c0a5f9d259d205266355871f6983f'
HISTORY_CHECKPOINT_SHA = 'd1497e738fceb4e6abcd8e0d5340ee2252c761116a16913881b3b7fa2d49879d'
HISTORY_AUTH_SHA = '90c041c4483ab39b51487cf0211eda8394609962554963d294368f7ea76aeb43'
TARGET_BASE = '3d30b6600fffe30d52b1d28f7bf91cd4afcf7eb1'
TARGET_HEAD = '07034521e08276e8cca1a9ecc5d12e082a7b51f6'
TARGET_TREE = '3fc17cb9584614b682c9565520f43bb9680e97e8'
DERIVED_FIELDS = {'mission_id', 'execution_id', 'ledger_path', 'user_approval_path',
                  'user_approval_sha256', 'authorization_hmac_sha256'}


def is_fresh_mission(mission):
    return isinstance(mission, str) and re.fullmatch(
        '(' + PREFIX + '|' + SUCCESSOR_PREFIX + ')[0-9a-f]{64}', mission) is not None


def is_successor(auth):
    return auth.get('fresh_task', {}).get('version') == SUCCESSOR_VERSION


def approval_payload(auth):
    """Exact approved envelope; only deterministic identity/path fields excluded."""
    return {k: v for k, v in auth.items() if k not in DERIVED_FIELDS}


def task_ledger_path(history):
    sha = history['predecessor_ledger_sha256']
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ResourceGateDenied('fresh predecessor hash malformed')
    return TASK_ROOT / ('fresh-pr2-task-' + sha + '.json')


def authorization_ledger_path(auth):
    if is_successor(auth):
        sha = auth['fresh_task']['successor']['ledger_sha256']
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
            _deny('successor parent hash malformed')
        return TASK_ROOT / ('successor-pr2-task-' + sha + '.json')
    return task_ledger_path(auth['fresh_task']['history'])


def build_scope(root, runtime, base=TARGET_BASE, head=TARGET_HEAD):
    from . import full_diff_manifest as full
    repository = full.git(root, 'remote', 'get-url', 'origin').decode().strip()
    from urllib.parse import urlparse
    # Same canonical repository identity as the existing review runner.
    if repository.startswith('git@github.com:'):
        repository = 'ssh://github.com/' + repository.split(':', 1)[1]
    elif urlparse(repository).scheme == 'https':
        repository = repository
    diff, manifest = full.build_manifest(root, base, head, repository)
    full.validate_manifest(root, manifest, repository, base, head, review_ready=True)
    tasks = full.review_tasks(diff, manifest)
    full.validate_tasks(diff, manifest, tasks)
    return dict(repository=repository, base=base, head=head,
                tree=full.git(root, 'rev-parse', head + '^{tree}').decode().strip(),
                diff_sha256=full.sha256(diff), manifest_sha256=manifest['manifest_sha256'],
                tasks=tasks, runtime_head=runtime['head'], prospective=False), manifest


def build_request_plan(scope, manifest):
    """Canonical seven-slot-per-provider PR2 plan; no formatting retries."""
    from .model_qualification import CASES, qualification_prompt
    from . import full_diff_manifest as full
    from .deepseek_direct import identity
    if manifest['chunk_count'] != 1 or not 0 < manifest['full_diff_bytes'] <= full.CHUNK_BYTES:
        raise ResourceGateDenied('fresh PR2 contract is exactly one chunk and one group')
    qualifications = [dict(slot='qualification:' + case.name, stage='qualification-case',
                           prompt_sha256=digest(qualification_prompt(case).encode())) for case in CASES]
    stages = {'deepseek': ['chunk-000.json', 'group-000.json', 'aggregate.json'],
              'openai': ['structured-preflight', 'chunk-000', 'group-000']}
    return dict(version=VERSION, scope_sha256=digest(canonical(scope)),
                manifest_sha256=scope['manifest_sha256'],
                providers={p: copy.deepcopy(qualifications) + [dict(slot=s, stage=s) for s in names]
                           for p, names in stages.items()},
                maximum_calls={'deepseek': 7, 'openai': 7, 'global': 14},
                direct_transport=identity(), automatic_retries=0,
                unknown_policy='RETAIN_FULL_RESERVATION_STOP_NO_RETRY',
                execution_order='openai_then_independent_deepseek',
                GPT_physical_HTTP='UNKNOWN')


def _deny(message):
    raise ResourceGateDenied(message)


def validate(auth, env, key, runtime, now, *, offline=False):
    """Additional bounded semantics, before shared legacy/account checks."""
    from . import formal_delivery_gate as gate
    f = auth['fresh_task']
    successor = is_successor(auth)
    if (set(f) != {'version', 'history_authorization_path', 'history', 'scope',
                   'request_plan', 'overlapping_target_approved', 'budget_microcny'} |
                   ({'successor'} if successor else set())
            or f['version'] not in {VERSION, SUCCESSOR_VERSION} or f['overlapping_target_approved'] is not True
            or any(k in auth for k in ('continuation', 'previous_authorization_path',
                'previous_authorization_sha256', 'child_baseline_checkpoint_sha256', 'diagnostic_probe'))):
        _deny('fresh task cannot renew, migrate or diagnose an old task')
    allowed = {'version', 'evidence_domain', 'authorization_id', 'approval_source', 'approved_at_epoch',
        'activation_approved', 'source_binding_version', 'source_binding_approved', 'old_mission_frozen',
        'historical_actual_usage', 'token_accounting_basis', 'chunk_migration_allowed', 'parent', 'runtime',
        'targets', 'scope', 'started_epoch', 'expires_epoch', 'max_wall_clock_seconds', 'max_new_calls',
        'shared_max_calls', 'shared_token_limits', 'shared_cost_limits', 'account_evidence_path',
        'account_evidence_sha256', 'account_ids', 'credential_identities', 'providers', 'fresh_task',
        'deepseek_funding_policy', 'openai_availability_policy'} | DERIVED_FIELDS
    if set(auth) - allowed:
        _deny('unknown fresh authorization field')
    approval = json.loads(gate._read(auth['user_approval_path']))
    if (set(approval) != {'version', 'evidence_domain', 'explicit_paid_execution_approval', 'payload'}
            or approval['version'] != (SUCCESSOR_APPROVAL_VERSION if successor else APPROVAL_VERSION)
            or approval['evidence_domain'] != auth['evidence_domain']
            or approval['explicit_paid_execution_approval'] is not True
            or approval['payload'] != approval_payload(auth)):
        _deny('fresh task needs exact new explicit execution approval')
    approval_sha = digest(gate._read(auth['user_approval_path']))
    prefix = SUCCESSOR_PREFIX if successor else PREFIX
    execution_domain = b'cmh-successor-execution/v1/' if successor else b'cmh-fresh-execution/v1/'
    if (approval_sha != auth['user_approval_sha256']
            or auth['mission_id'] != prefix + approval_sha
            or env['CMH_RESOURCE_MISSION_ID'] != auth['mission_id']
            or auth['execution_id'] != digest(execution_domain + approval_sha.encode())):
        _deny('fresh task identity must derive from its exact new approval')
    c = f['history']
    if not offline and (c['predecessor_ledger_sha256'] != HISTORY_LEDGER_SHA or
            c['predecessor_checkpoint_sha256'] != HISTORY_CHECKPOINT_SHA or
            c['predecessor_authorization_sha256'] != HISTORY_AUTH_SHA):
        _deny('fresh PR2 transition requires the frozen latest complete history')
    prior = gate._signed(f['history_authorization_path'], c['predecessor_authorization_sha256'], key)
    if (prior['mission_id'] != gate.NEW_MISSION or
            now < min(prior['expires_epoch'], prior['started_epoch'] + prior['max_wall_clock_seconds'])
            or auth['started_epoch'] < max(auth['approved_at_epoch'], prior['expires_epoch'])
            or not 0 < auth['max_wall_clock_seconds'] <= prior['max_wall_clock_seconds']
            or not auth['started_epoch'] < auth['expires_epoch'] <=
                auth['started_epoch'] + auth['max_wall_clock_seconds']):
        _deny('fresh validity cannot alter or overlap an active predecessor clock')
    reader = dict(prior, ledger_path=str(gate.continuation_ledger_path(c)), continuation=c,
                  previous_authorization_sha256=c['predecessor_authorization_sha256'],
                  child_baseline_checkpoint_sha256=c['predecessor_checkpoint_sha256'])
    history = gate._history_continuation_predecessor(reader, prior, key, offline=offline)
    if len(history['requests']) != 120 or len(c['historical_unknowns']) != 8:
        _deny('fresh transition must retain the complete 120-row/eight-UNKNOWN history')
    if (auth['ledger_path'] != str(authorization_ledger_path(auth)) or
            env['CMH_RESOURCE_LEDGER'] != auth['ledger_path'] or
            Path(auth['ledger_path']) == Path(c['predecessor_ledger_path'])):
        _deny('bounded task requires its unique immutable ledger namespace')
    root = Path(gate.__file__).resolve().parents[2]
    scope, manifest = build_scope(root, runtime)
    plan = build_request_plan(scope, manifest)
    if (auth['scope'] != ['PR2'] or auth['targets'] != {'PR2': {'base': TARGET_BASE, 'head': TARGET_HEAD}}
            or scope['tree'] != TARGET_TREE or f['scope'] != scope or f['request_plan'] != plan):
        _deny('fresh PR2 exact HEAD/tree/scope/manifest/request plan changed')
    if not offline:
        from .full_diff_manifest import git
        if git(root, 'rev-parse', 'origin/main').decode().strip() != TARGET_BASE:
            _deny('fresh task base is no longer current main')
    if (runtime['models'] != {'deepseek': {'provider': 'deepseek', 'model': 'deepseek-flash',
                                        'reasoning_effort': None},
                              'openai': {'provider': 'openai', 'model': 'gpt-5.6-sol',
                                         'reasoning_effort': 'high'}}
            or auth['max_new_calls'] != 14
            or any(auth['providers'][p]['max_new_calls'] != 7 for p in ('deepseek', 'openai'))
            or not gate._integer(f['budget_microcny'], 1)):
        _deny('fresh task models/call caps/native budget invalid')
    for p, lane in auth['providers'].items():
        from .resource_gate import _stage_reservation
        tokens = {k: sum(_stage_reservation(lane, p, s['stage'])[k]
                         for s in plan['providers'][p]) for k in gate.CATEGORIES}
        if (lane['cost_limit_microunits'] != 7 * lane['cost_reservation_microunits']
                or lane['token_limit'] != tokens):
            _deny('fresh budget is exactly the seven-slot plan, no transferred capacity')
    if not offline and (not auth.get('deepseek_funding_policy') or
            gate._funding_currency(auth) != 'CNY' or not auth.get('openai_availability_policy')):
        _deny('fresh execution retains native funds and subscription freshness contracts')
    if auth.get('deepseek_funding_policy'):
        policy = auth['deepseek_funding_policy']
        if f['budget_microcny'] < 7 * gate._native_cny_bound(policy) + policy['safety_margin_microcny']:
            _deny('fresh native budget cannot cover its complete plan and margin')
    if successor:
        if not offline and (auth['deepseek_funding_policy'].get('no_overdraft_policy') != gate.OPERATIONAL_NO_OVERDRAFT
                or auth['deepseek_funding_policy']['max_snapshot_age_seconds'] > 300
                or auth['openai_availability_policy']['max_snapshot_age_seconds'] > 300):
            _deny('successor retains operational financial safety and fresh 300-second snapshots')
        failed = validate_failed_parent(auth, env, key, now, offline=offline)
        # Accounting only: never import the failed row into the new request slots.
        history = dict(history, requests=history['requests'] + failed['requests'])
    return history


def validate_failed_parent(auth, env, key, now, *, offline=False):
    """One pinned authentication failure, not a general UNKNOWN recovery API."""
    from . import formal_delivery_gate as gate
    s = auth['fresh_task']['successor']
    if (set(s) != {'mission_id', 'authorization_path', 'authorization_sha256', 'ledger_path',
                  'ledger_sha256', 'checkpoint_sha256', 'unknown_row_sha256', 'failure_evidence',
                  'retain_unknown', 'refund', 'abandon_failed_execution_approved', 'accepted_risks',
                  'read_only_get_limits'}
            or s['retain_unknown'] is not True or s['refund'] != 0
            or s['abandon_failed_execution_approved'] is not True
            or s['accepted_risks'] != SUCCESSOR_RISKS):
        _deny('successor requires exact nonrefundable failed-parent disposition')
    gets = s['read_only_get_limits']
    if (set(gets) != {'logical', 'physical', 'automatic_retries'}
            or not gate._integer(gets['logical']) or not gate._integer(gets['physical'])
            or not 0 <= gets['logical'] <= 9 or not gets['logical'] <= gets['physical'] <= min(10, gets['logical'] + 1)
            or gets['automatic_retries'] != 0):
        _deny('successor needs separately approved bounded read-only GET permission')
    if not offline and (s['mission_id'] != FAILED_MISSION or s['ledger_sha256'] != FAILED_LEDGER_SHA
            or s['checkpoint_sha256'] != FAILED_CHECKPOINT_SHA or s['authorization_sha256'] != FAILED_AUTH_SHA
            or s['unknown_row_sha256'] != FAILED_ROW_SHA
            or {n: v['sha256'] for n, v in s['failure_evidence'].items()} != FAILED_EVIDENCE):
        _deny('successor is restricted to the fixed real GPT authentication failure')
    parent = gate._signed(s['authorization_path'], s['authorization_sha256'], key)
    if (parent.get('fresh_task', {}).get('version') != VERSION
            or 'successor' in parent['fresh_task'] or parent['mission_id'] != s['mission_id']
            or parent['parent'] != auth['parent'] or parent['evidence_domain'] != auth['evidence_domain']
            or parent['fresh_task']['history'] != auth['fresh_task']['history']
            or parent['ledger_path'] != s['ledger_path'] or parent['mission_id'] == auth['mission_id']
            or parent['execution_id'] == auth['execution_id']):
        _deny('successor parent cannot be substituted, nested or reused as execution identity')
    parent_env = dict(env, CMH_RESOURCE_MISSION_ID=parent['mission_id'], CMH_RESOURCE_LEDGER=parent['ledger_path'])
    validate(parent, parent_env, key, parent['runtime'], now, offline=offline)
    path = Path(s['ledger_path'])
    if (digest(gate._read(path)) != s['ledger_sha256'] or
            digest(gate._read(gate._checkpoint_path(path))) != s['checkpoint_sha256']):
        _deny('failed parent ledger/checkpoint changed')
    failed = gate._verify_child(path, key, dict(parent,
        _authorization_sha256=s['authorization_sha256'], _lineage_sha256=[s['authorization_sha256']]))
    rows = failed['requests']
    if (len(rows) != 1 or digest(canonical(rows[0])) != s['unknown_row_sha256']
            or rows[0].get('provider') != 'openai' or rows[0].get('status') != 'FAILED'
            or rows[0].get('reported_usage') != 'UNKNOWN'
            or rows[0].get('usage_accounting') != 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS'
            or rows[0].get('request_slot') != 'qualification:clean'
            or rows[0].get('transport_claimed') is not True
            or auth['approved_at_epoch'] < rows[0]['finished_epoch']):
        _deny('successor cannot erase, refund or generalize the pinned failed UNKNOWN')
    if set(s['failure_evidence']) != set(FAILED_EVIDENCE):
        _deny('successor requires the complete original authentication-failure evidence')
    for ref in s['failure_evidence'].values():
        if set(ref) != {'path', 'sha256'} or digest(gate._read(ref['path'])) != ref['sha256']:
            _deny('original failed execution evidence changed')
    return failed


def activation_claim_path(auth):
    return authorization_ledger_path(auth).with_suffix('.activation.json')


def activation_identity(auth):
    return dict(version=SUCCESSOR_VERSION, mission_id=auth['mission_id'], execution_id=auth['execution_id'],
                authorization_sha256=auth['_authorization_sha256'], ledger_path=auth['ledger_path'],
                failed_parent_ledger_sha256=auth['fresh_task']['successor']['ledger_sha256'])


def claim_activation(auth, key):
    """Called under the existing ledger lock; persisted before journal/ledger writes.

    Partial creation remains a permanent fail-closed claim, never reinitializable.
    """
    path = activation_claim_path(auth)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        _deny('fixed failed parent already has its one successor activation claim')
    try:
        with os.fdopen(fd, 'wb') as stream:
            from .resource_gate import sign_authorization
            stream.write(canonical(sign_authorization(activation_identity(auth), key)) + b'\n')
            stream.flush(); os.fsync(stream.fileno())
    finally:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)


def verify_activation(auth, key):
    from . import formal_delivery_gate as gate
    if gate._signed(activation_claim_path(auth), None, key) != activation_identity(auth):
        _deny('successor lost its immutable exclusive activation claim')


def reserve_slot(auth, rows, provider, stage, prompt, context):
    from .formal_delivery_gate import qualification_binding
    slots = auth['fresh_task']['request_plan']['providers'][provider]
    used = [r for r in rows if r['provider'] == provider]
    if any(r.get('status') != 'RETURNED' or r.get('usage_accounting') != 'FULL_RESERVATION_RETAINED' for r in rows):
        _deny('fresh task failure, UNKNOWN or in-flight state cannot advance')
    if provider == 'deepseek' and len([r for r in rows if r['provider'] == 'openai']) != 7:
        _deny('fresh plan completes GPT first; no early DeepSeek expense')
    if len(used) >= len(slots):
        _deny('fresh task request slots exhausted')
    slot = slots[len(used)]
    if slot['stage'] != stage or ('prompt_sha256' in slot and slot['prompt_sha256'] != digest(prompt)):
        _deny('fresh task cannot replay, reorder or substitute a request slot')
    if stage != 'qualification-case' and (not context or context['provider'] != provider
            or context['target'] != 'PR2' or context['binding'] !=
            qualification_binding(auth)):
        _deny('fresh review requires its own qualified exact source context')
    return slot['slot']


def verify_ledger(auth, ledger):
    binding = dict(execution_id=auth['execution_id'],
                   fresh_history_sha256=auth['fresh_task']['history']['predecessor_ledger_sha256'],
                   request_plan_sha256=digest(canonical(auth['fresh_task']['request_plan'])))
    if any(ledger.get(k) != v for k, v in binding.items()):
        _deny('fresh ledger lost its independent execution/history/plan identity')
    for p in ('deepseek', 'openai'):
        slots = auth['fresh_task']['request_plan']['providers'][p]
        selected = [r for r in ledger['requests'] if r['provider'] == p]
        if len(selected) > len(slots):
            _deny('fresh ledger exceeded its slots')
        for r, s in zip(selected, slots):
            expected = digest(canonical(dict(mission_id=auth['mission_id'], provider=p, slot=s['slot'])))
            from .resource_gate import _stage_reservation
            if (r.get('status') not in {'STARTED', 'RETURNED', 'FAILED'}
                    or type(r.get('transport_claimed')) is not bool
                    or r.get('token_reservation') != _stage_reservation(auth['providers'][p], p, s['stage'])
                    or r.get('cost_reservation_microunits') != auth['providers'][p]['cost_reservation_microunits']
                    or r.get('cost_unit') != auth['providers'][p]['cost_unit']
                    or r.get('request_id') != expected or r.get('request_slot') != s['slot']
                    or r.get('execution_id') != auth['execution_id'] or r.get('stage') != s['stage']
                    or r.get('model') != auth['runtime']['models'][p]['model']
                    or r.get('request_plan_sha256') != binding['request_plan_sha256']):
                _deny('fresh ledger cannot claim an old or altered request slot')
    return binding


def claim_transport(auth, active, prompt):
    """Durable one-send claim, before crossing either real Provider boundary."""
    from . import formal_delivery_gate as gate
    if not isinstance(prompt, bytes):
        _deny('fresh transport requires the exact reserved prompt bytes')
    path = Path(auth['ledger_path']); key = gate._read(active.ledger_key_path)
    with gate._locked(path.with_name(path.name + '.lock')):
        current = gate.load_authorization()
        if current['_authorization_sha256'] != auth['_authorization_sha256']:
            _deny('fresh authority changed before transport claim')
        ledger = gate._verify_child(path, key, current)
        row = next((r for r in ledger['requests'] if r['request_id'] == active.request_id), None)
        if (not row or row['status'] != 'STARTED' or row.get('transport_claimed') is not False
                or row['prompt_sha256'] != digest(prompt)
                or (row['provider'], row['model']) != (active.provider, active.model)):
            _deny('fresh transport prompt/state/one-send claim mismatch')
        row['transport_claimed'] = True
        gate._write_child(path, ledger, key)


def native_funding_check(auth, ledger, snapshot, upper, free):
    """Keep old native UNKNOWN exposure and the new approved CNY hard ceiling."""
    from . import formal_delivery_gate as gate
    history_sha = auth['fresh_task']['history']['predecessor_ledger_sha256']
    if snapshot.get('fresh_history_sha256') != history_sha:
        _deny('fresh wallet snapshot must bind all retained historical exposure')
    source = json.loads(gate._read(snapshot['settlement_source_path']))
    if source.get('fresh_history_sha256') != history_sha:
        _deny('fresh settlement evidence omits historical liabilities')
    if is_successor(auth):
        require_parent_capacity_binding(auth, snapshot)
        require_parent_capacity_binding(auth, source)
    unknowns = [r for r in auth['_fresh_history']['requests'] if r['provider'] == 'deepseek'
                and r.get('reported_usage') == 'UNKNOWN']
    if any(not gate._integer(r.get('wallet_exposure_microcny'), 1) for r in unknowns):
        _deny('historical native UNKNOWN exposure cannot be silently zeroed or converted')
    retained = sum(r['wallet_exposure_microcny'] for r in unknowns)
    cost = sum(r.get('wallet_exposure_microcny', 0) for r in ledger['requests']
               if r['provider'] == 'deepseek') + upper
    margin = auth['deepseek_funding_policy']['safety_margin_microcny']
    if cost + margin > auth['fresh_task']['budget_microcny']:
        _deny('fresh approved native CNY ceiling exhausted')
    return free - retained


def require_parent_capacity_binding(auth, capacity):
    if is_successor(auth) and capacity.get('successor_parent_ledger_sha256') != auth['fresh_task']['successor']['ledger_sha256']:
        _deny('successor capacity must include the failed parent full UNKNOWN reservation')


def review_evidence_path(auth, provider):
    if provider not in {'openai', 'deepseek'}:
        _deny('unknown fresh evidence provider')
    prefix = 'successor-pr2-evidence-' if is_successor(auth) else 'fresh-pr2-evidence-'
    return TASK_ROOT / (prefix + auth['user_approval_sha256']) / provider


def qualification_evidence_path(auth, provider):
    return review_evidence_path(auth, provider).parent / ('qualification-' + provider + '-diagnostics')
