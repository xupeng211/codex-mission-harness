"""One explicit fresh PR2 task, using the existing delivery signature and ledger.

No approvals are issued here. One immutable predecessor has one successor path;
changing an approval, mission, signature or working directory cannot fork it.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from .resource_gate import canonical, digest, ResourceGateDenied

VERSION = 'cmh-fresh-pr2-task/v1'
APPROVAL_VERSION = 'cmh-fresh-pr2-user-approval/v1'
PREFIX = 'HARNESS_PR2_FRESH_'
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
    return isinstance(mission, str) and re.fullmatch(PREFIX + '[0-9a-f]{64}', mission) is not None


def approval_payload(auth):
    """Exact approved envelope; only deterministic identity/path fields excluded."""
    return {k: v for k, v in auth.items() if k not in DERIVED_FIELDS}


def task_ledger_path(history):
    sha = history['predecessor_ledger_sha256']
    if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
        raise ResourceGateDenied('fresh predecessor hash malformed')
    return TASK_ROOT / ('fresh-pr2-task-' + sha + '.json')


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
    if (set(f) != {'version', 'history_authorization_path', 'history', 'scope',
                   'request_plan', 'overlapping_target_approved', 'budget_microcny'}
            or f['version'] != VERSION or f['overlapping_target_approved'] is not True
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
            or approval['version'] != APPROVAL_VERSION
            or approval['evidence_domain'] != auth['evidence_domain']
            or approval['explicit_paid_execution_approval'] is not True
            or approval['payload'] != approval_payload(auth)):
        _deny('fresh task needs exact new explicit execution approval')
    approval_sha = digest(gate._read(auth['user_approval_path']))
    if (approval_sha != auth['user_approval_sha256']
            or auth['mission_id'] != PREFIX + approval_sha
            or env['CMH_RESOURCE_MISSION_ID'] != auth['mission_id']
            or auth['execution_id'] != digest(b'cmh-fresh-execution/v1/' + approval_sha.encode())):
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
    if (auth['ledger_path'] != str(task_ledger_path(c)) or
            env['CMH_RESOURCE_LEDGER'] != auth['ledger_path'] or
            Path(auth['ledger_path']) == Path(c['predecessor_ledger_path'])):
        _deny('one frozen history has exactly one fresh successor namespace')
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
    return history


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


def review_evidence_path(auth, provider):
    if provider not in {'openai', 'deepseek'}:
        _deny('unknown fresh evidence provider')
    return TASK_ROOT / ('fresh-pr2-evidence-' + auth['user_approval_sha256']) / provider


def qualification_evidence_path(auth, provider):
    return review_evidence_path(auth, provider).parent / ('qualification-' + provider + '-diagnostics')
