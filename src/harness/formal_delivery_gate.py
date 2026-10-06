"""One scoped delivery continuation; no authority is issued by this module.

Production trust is bootstrapped from the immutable old authorization's HMAC,
not an environment-selected test key. Old UNKNOWN usage is retained. A new
call also needs separately approved, authoritative net account capacity.
"""
from __future__ import annotations

import hmac
import copy
import json
import os
import re
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .resource_gate import (ResourceGateDenied, FundingPause, Reservation, _locked, _private,
                            _write_atomic, canonical, digest, sign_authorization)

OLD_MISSION = 'HARNESS_AUTONOMOUS_PRE_MERGE_DELIVERY'
NEW_MISSION = 'HARNESS_CURRENT_VERSION_DELIVERY'
AUTH_VERSION = 'cmh-current-delivery-authorization/v1'
ACCOUNT_VERSION = 'cmh-shared-capacity-attestation/v1'
LEDGER_VERSION = 'cmh-current-delivery-ledger/v1'
SOURCE_VERSION = 'exact-unique-utf8-quote/v1'
CAPACITY_POLICY = 'AUTHORITATIVE_NET_CAPACITY_NO_UNBOUNDED_PRIOR_LIABILITY'
STAGED_POLICY = 'FIXED_BUDGET_STAGED_NET_WALLET/v1'
OPERATIONAL_NO_OVERDRAFT = 'OPERATIONAL_PRE_SEND_SAFETY/v1'
FUNDS_VERSION = 'cmh-staged-wallet-snapshot/v1'
CATEGORIES = ('input', 'cache', 'output', 'reasoning')
EVIDENCE_ROOT = Path('/home/xupeng/codex-mission-harness-evidence/autonomous-premerge-20261002')
DELIVERY_LEDGER = EVIDENCE_ROOT / 'current-version-delivery-ledger.json'
CONTINUATION_LEDGER = EVIDENCE_ROOT / 'current-version-delivery-ledger.continuation.json'
CONTINUATION_VERSION = 'cmh-request5-reserved-unknown-continuation/v1'
REQUEST5_LEDGER_SHA256 = 'bef620a429653dea8d895e2417114db69a04859dba90d28f90af34f4eb13f138'
REQUEST5_ROW_SHA256 = '57bf46b218deee3d9c795534f7909e7a40f1fc275f2f458a1456ca01d3c6c901'
HISTORICAL_AUTHORIZATION = (EVIDENCE_ROOT / 'formal-60h-review/authorized-closure-20261003/'
                            'final-dual-review-delivery-20261003/hard-delivery-resource-authorization.json')
RUNTIME_FILES = ('src/harness/deepseek_direct.py', 'src/harness/formal_delivery_gate.py', 'src/harness/resource_gate.py',
                 'src/harness/reviewer_v2_contract.py', 'src/harness/model_qualification.py',
                 'src/harness/model_registry.py', 'src/harness/openai_invocation.py',
                 'src/harness/full_diff_manifest.py', 'src/harness/review_resume.py',
                 'src/harness/codex.py',
                 'scripts/reviewer_v2_deepseek.py', 'scripts/reviewer_v2_openai.py',
                 'scripts/deepseek_review.py', 'scripts/model_qualification.py')
_review_context = ContextVar('cmh_formal_delivery_review', default=None)


@dataclass(frozen=True)
class TrustAnchor:
    ledger_sha256: str
    authorization_sha256: str
    request_sha256: str


PRODUCTION_ANCHOR = TrustAnchor(
    '200d702fa712629e35fb8746500e708e5382e1313b2737f8d2d25c4970160c9d',
    'c6caca54292b61f96d91b7a714cfee60006630d72fe490c5bfc464e8b1c5aa25',
    'aa865dcbea7392e6fe937d1566443ebc5acb4dc4d222ed4dc551fce9b9c3d153')


def _deny(message):
    raise ResourceGateDenied(message)


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _read(path):
    try:
        path = Path(path)
        if path.resolve() != path:
            _deny('delivery artifact path must be canonical, private and non-symlinked')
        return _private(path)
    except (OSError, TypeError) as exc:
        raise ResourceGateDenied('delivery evidence artifact is missing or inaccessible') from exc


def _signed(path, expected_hash, key):
    raw = _read(path)
    if expected_hash is not None and digest(raw) != expected_hash:
        _deny('delivery signed artifact hash mismatch')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise ResourceGateDenied('delivery signed artifact is malformed') from exc
    if not isinstance(value, dict):
        _deny('delivery signed artifact must be an object')
    signature = value.pop('authorization_hmac_sha256', None)
    expected = sign_authorization(value, key)['authorization_hmac_sha256']
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        _deny('delivery artifact signature invalid')
    return value


def runtime_snapshot():
    from .full_diff_manifest import git
    from .model_registry import load_registry
    root = Path(__file__).resolve().parents[2]
    if git(root, 'status', '--porcelain').strip():
        _deny('formal delivery runtime worktree is dirty')
    registry = load_registry()
    return {'head': git(root, 'rev-parse', 'HEAD').decode().strip(),
            'files': {name: digest((root / name).read_bytes()) for name in RUNTIME_FILES},
            'registry_sha256': digest(registry.path.read_bytes()),
            'models': {p: registry.role(role).identity() for p, role in
                       (('deepseek', 'independent_reviewer'), ('openai', 'final_reviewer'))}}


def _history(rows):
    result = {'global_calls': len(rows)}
    for provider in ('deepseek', 'openai'):
        selected = [r for r in rows if r.get('provider') == provider]
        result[provider] = {
            'calls': len(selected),
            'unmetered_calls': sum(not isinstance(r.get('token_reservation'), dict) for r in selected),
            'tokens': {k: sum(r.get('token_reservation', {}).get(k, 0) for r in selected)
                       for k in CATEGORIES},
            'cost': sum(r.get('cost_reservation_microunits', 0) for r in selected)}
    return result


def _load(env, anchor, runtime, now, *, offline=False):
    """Pure validation seam for offline fixtures; production never injects trust."""
    try:
        key = _read(env['CMH_RESOURCE_GATE_KEY_FILE'])
        auth_hash = env['CMH_RESOURCE_AUTH_SHA256']
        auth = _signed(env['CMH_RESOURCE_AUTHORIZATION'], auth_hash, key)
        domain = 'OFFLINE_TEST' if offline else 'FORMAL'
        if (auth.get('version') != AUTH_VERSION or auth.get('evidence_domain') != domain
                or auth.get('approval_source') != 'EXPLICIT_USER_APPROVAL'
                or not isinstance(auth.get('authorization_id'), str)
                or not auth['authorization_id'] or auth.get('activation_approved') is not True
                or auth.get('mission_id') != NEW_MISSION
                or env['CMH_RESOURCE_MISSION_ID'] != NEW_MISSION
                or auth.get('scope') != ['PR2', 'PR4']
                or auth.get('source_binding_version') != SOURCE_VERSION
                or auth.get('source_binding_approved') is not True
                or auth.get('old_mission_frozen') is not True
                or auth.get('historical_actual_usage') != 'UNKNOWN'
                or auth.get('token_accounting_basis') != 'PROSPECTIVE_PLUS_KNOWN_HISTORICAL_RESERVATIONS'
                or auth.get('chunk_migration_allowed') is not False):
            _deny('independent formal delivery activation approval is required')
        if (not _integer(auth['approved_at_epoch']) or auth['approved_at_epoch'] > now or
                digest(_read(auth['user_approval_path'])) != auth['user_approval_sha256']):
            _deny('independent user approval provenance is missing or changed')
        parent = auth['parent']
        if (parent['mission_id'] != OLD_MISSION or parent['ledger_sha256'] != anchor.ledger_sha256
                or parent['authorization_sha256'] != anchor.authorization_sha256
                or parent['request_334_sha256'] != anchor.request_sha256
                or parent['deepseek_reserved_microusd'] != 28800000
                or parent.get('acceptance') != 'INCOMPLETE'
                or parent.get('original_started_at') != '2026-10-01T16:53:04Z'):
            _deny('immutable signed parent anchor mismatch')
        # The fixed old authorization signature authenticates the signing key.
        # A synthetic key cannot authenticate these pinned bytes in production.
        legacy = _signed(parent['authorization_path'], anchor.authorization_sha256, key)
        if (legacy.get('mission_id') != OLD_MISSION or legacy.get('baseline_calls') != 246
                or legacy.get('version') != 'cmh-resource-budget/v1'
                or legacy.get('ledger_path') != parent['ledger_path']):
            _deny('parent authorization identity mismatch')
        raw = _read(parent['ledger_path'])
        if digest(raw) != anchor.ledger_sha256:
            _deny('parent ledger hash mismatch')
        rows = json.loads(raw)['requests']
        if (len(rows) != 334 or any(r.get('number') != n for n, r in enumerate(rows, 1))
                or digest(canonical(rows[-1])) != anchor.request_sha256
                or rows[-1].get('mission_id') != OLD_MISSION
                or rows[-1].get('status') != 'FAILED'
                or rows[-1].get('reported_usage') != 'UNKNOWN'
                or rows[-1].get('usage_accounting') != 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS'
                or rows[-1].get('cost_reservation_microunits') != 400000):
            _deny('request 334 FAILED/UNKNOWN history must remain intact')
        history = _history(rows)
        if history['deepseek']['cost'] != 28800000:
            _deny('historical DeepSeek full reservation was lost')
        if auth['runtime'] != runtime:
            _deny('delivery Git, runtime, registry or model identity changed')
        if (runtime['models']['deepseek']['model'] != 'deepseek-flash'
                or runtime['models']['openai']['model'] != 'gpt-5.6-sol'):
            _deny('formal review model changed')
        if not offline and runtime['models']['openai'].get('reasoning_effort') != 'high':
            _deny('formal OpenAI reasoning contract must remain high')
        targets = auth['targets']
        if (set(targets) != {'PR2', 'PR4'}
                or targets['PR4']['head'] != runtime['head']
                or any(set(item) != {'base', 'head'} or any(not isinstance(v, str) or
                       not re.fullmatch('[0-9a-f]{40}', v) for v in item.values())
                       for item in targets.values())):
            _deny('delivery target dependency mismatch')
        if not offline:
            from .full_diff_manifest import git
            root = Path(__file__).resolve().parents[2]
            git(root, 'merge-base', '--is-ancestor', targets['PR2']['head'], targets['PR4']['base'])
            for item in targets.values():
                git(root, 'merge-base', '--is-ancestor', item['base'], item['head'])
        ledger = Path(auth['ledger_path'])
        if (str(ledger) != env['CMH_RESOURCE_LEDGER'] or ledger.resolve() != ledger
                or ledger == Path(parent['ledger_path']) or not offline and
                    ledger != (CONTINUATION_LEDGER if auth.get('continuation') else DELIVERY_LEDGER)):
            _deny('delivery must use its fixed shared continuation ledger')
        for name in ('started_epoch', 'expires_epoch', 'max_wall_clock_seconds'):
            if not _integer(auth[name]):
                _deny('delivery time contract invalid')
        if not auth['started_epoch'] <= now < min(auth['expires_epoch'],
                                                 auth['started_epoch'] + auth['max_wall_clock_seconds']):
            _deny('delivery time or validity hard stop reached')
        for name in ('max_new_calls', 'shared_max_calls'):
            if not _integer(auth[name], 1):
                _deny('delivery logical call limit invalid')
        if auth.get('openai_availability_policy') is not None:
            _validate_availability_policy(auth)
        if auth.get('deepseek_funding_policy') is not None:
            _validate_funding_policy(auth)
        account = _signed(auth['account_evidence_path'], auth['account_evidence_sha256'], key)
        if (account.get('version') != ACCOUNT_VERSION or account.get('evidence_domain') != domain
                or account.get('parent_ledger_sha256') != anchor.ledger_sha256
                or account.get('policy') != CAPACITY_POLICY
                or any(account.get(name) is not True for name in
                       ('no_unbounded_prior_liability', 'all_prior_activity_included', 'exclusive_allocation'))
                or not _integer(account['observed_epoch']) or not _integer(account['expires_epoch'])
                or not account['observed_epoch'] <= now < account['expires_epoch']):
            _deny('authoritative net shared capacity proof is missing or expired')
        if digest(_read(account['official_source_path'])) != account['official_source_sha256']:
            _deny('official shared capacity evidence changed')
        for provider in ('deepseek', 'openai'):
            item = account['accounts'][provider]
            lane = auth['providers'][provider]
            unit = 'USD' if provider == 'deepseek' else 'CODEX_SUBSCRIPTION_UNITS'
            if (item['account_id'] != auth['account_ids'][provider] or item['unit'] != unit
                    or item['credential_identity'] != auth['credential_identities'][provider]
                    or not isinstance(item['credential_identity'], str)
                    or not re.fullmatch('[0-9a-f]{64}', item['credential_identity'])
                    or lane['model'] != runtime['models'][provider]['model']
                    or lane['cost_unit'] != unit
                    or lane['unknown_policy'] != 'DEBIT_FULL_RESERVATION_STOP_ON_OVERAGE'
                    or not (provider == 'openai' and auth.get('openai_availability_policy')) and
                       not _integer(item.get('available_microunits'))
                    or not _integer(item['other_reserved_microunits'])
                    or not _integer(item['other_calls'])
                    or set(item['other_tokens']) != set(CATEGORIES)
                    or any(not _integer(v) for v in item['other_tokens'].values())
                    or not _integer(lane['max_new_calls'])
                    or not _integer(lane['cost_limit_microunits'], 1)
                    or not _integer(lane['cost_reservation_microunits'], 1)
                    or any(set(lane[name]) != set(CATEGORIES) or
                           any(not _integer(v, 1) for v in lane[name].values())
                           for name in ('token_limit', 'token_reservation'))
                    or set(auth['shared_token_limits'][provider]) != set(CATEGORIES)
                    or any(not _integer(v, 1) for v in auth['shared_token_limits'][provider].values())
                    or not _integer(auth['shared_cost_limits'][provider], 1)):
                _deny('account, provider or bounded resource identity invalid')
            if not offline:
                expected_tokens = ({'input': 64000, 'cache': 64000, 'output': 128000, 'reasoning': 128000}
                                   if provider == 'deepseek' else
                                   {'input': 400000, 'cache': 400000, 'output': 128000, 'reasoning': 128000})
                if (lane['token_reservation'] != expected_tokens or
                        lane['cost_reservation_microunits'] != (400000 if provider == 'deepseek' else 1000000)):
                    _deny('existing per-call reservation contract cannot be lowered')
                if provider == 'deepseek' and lane.get('stage_token_reservation') != {
                        'chunk_or_qualification': expected_tokens,
                        'group_or_cross_group': {'input': 64000, 'cache': 192000,
                                                'output': 192000, 'reasoning': 128000}}:
                    _deny('DeepSeek Group/Cross-group reservation contract must be preserved')
            exposure = history[provider]['cost'] + item['other_reserved_microunits'] + lane['cost_limit_microunits']
            wallet_limit = (auth['shared_cost_limits'][provider] if (provider == 'deepseek' and
                            auth.get('deepseek_funding_policy') or provider == 'openai' and
                            auth.get('openai_availability_policy')) else item['available_microunits'])
            if exposure > min(wallet_limit, auth['shared_cost_limits'][provider]):
                _deny('shared account evidence cannot cover the complete approved future envelope')
            if any(history[provider]['tokens'][k] + item['other_tokens'][k] + lane['token_limit'][k] >
                   auth['shared_token_limits'][provider][k] for k in CATEGORIES):
                _deny('shared token envelope omits historical or other-task reservations')
        if history['global_calls'] + auth['max_new_calls'] + sum(
                a['other_calls'] for a in account['accounts'].values()) > auth['shared_max_calls']:
            _deny('shared call envelope cannot cover the complete approved future budget')
        if not offline:
            from .full_diff_manifest import read_diff, plan, synthesis_stage_names
            minima = {'deepseek': 4, 'openai': 4}
            ds_chunks, ds_groups = 4, 0
            for target in targets.values():
                chunks, groups = plan(read_diff(root, target['base'], target['head']))
                ds_chunks += len(chunks); ds_groups += len(groups) + 1
                minima['deepseek'] += len(chunks) + len(groups) + 1
                minima['openai'] += len(chunks) + len(groups) + len(synthesis_stage_names(len(groups))) + 1
            token_minima = {
                'deepseek': {'input': minima['deepseek'] * 64000,
                             'cache': ds_chunks * 64000 + ds_groups * 192000,
                             'output': ds_chunks * 128000 + ds_groups * 192000,
                             'reasoning': minima['deepseek'] * 128000},
                'openai': {k: minima['openai'] * (400000 if k in ('input', 'cache') else 128000)
                           for k in CATEGORIES}}
            if auth['max_new_calls'] < sum(minima.values()) or any(
                    auth['providers'][p]['max_new_calls'] < minima[p] or
                    auth['providers'][p]['cost_limit_microunits'] < minima[p] *
                    auth['providers'][p]['cost_reservation_microunits'] or
                    any(auth['providers'][p]['token_limit'][k] < token_minima[p][k] for k in CATEGORIES)
                    for p in minima):
                _deny('authorization cannot cover qualification and both complete minimum reviews')
        lineage = [auth_hash]
        current = auth
        revision_fields = {'authorization_id', 'approved_at_epoch', 'user_approval_path',
                           'user_approval_sha256', 'runtime', 'targets', 'account_evidence_path',
                           'account_evidence_sha256', 'credential_identities',
                           'previous_authorization_path', 'previous_authorization_sha256',
                           'child_baseline_checkpoint_sha256'}
        previous = None
        predecessor_child = None
        while any(name in current for name in ('previous_authorization_path',
                                               'previous_authorization_sha256',
                                               'child_baseline_checkpoint_sha256')):
            if len(lineage) >= 3:
                _deny('at most two separately signed identity updates; further work needs human decision')
            previous_hash = current['previous_authorization_sha256']
            if previous_hash in lineage:
                _deny('authorization lineage cycle')
            prior = _signed(current['previous_authorization_path'], previous_hash, key)
            if (current['user_approval_sha256'] == prior['user_approval_sha256'] or
                    current['approved_at_epoch'] < prior['approved_at_epoch']):
                _deny('each exact identity update requires a fresh independent user approval record')
            permitted_revision_fields = revision_fields
            if current.get('continuation'):
                if predecessor_child is not None or prior.get('continuation'):
                    _deny('request5 continuation is one exact separately approved transition')
                predecessor_child = _continuation_predecessor(current, prior, key, offline=offline)
                permitted_revision_fields = revision_fields | {'continuation', 'ledger_path'}
            if any(current.get(k) != prior.get(k) for k in set(current) | set(prior)
                   if k not in permitted_revision_fields):
                _deny('identity update cannot reset counters, start time, history or increase budgets')
            if not isinstance(current['child_baseline_checkpoint_sha256'], str) or not re.fullmatch(
                    '[0-9a-f]{64}', current['child_baseline_checkpoint_sha256']):
                _deny('identity update must acknowledge the exact durable child checkpoint')
            if previous is None:
                previous = dict(prior, _authorization_sha256=previous_hash)
            lineage.append(previous_hash); current = prior
        if auth.get('continuation') and predecessor_child is None:
            _deny('continuation requires an explicit signed predecessor authority')
        return dict(auth, _authorization_sha256=auth_hash, _history=history, _account=account,
                    _lineage_sha256=lineage, _previous=previous, _predecessor_child=predecessor_child)
    except ResourceGateDenied:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ResourceGateDenied('formal delivery evidence missing or malformed') from exc


def _continuation_predecessor(auth, prior, key, *, offline=False):
    """One narrowly approved historical disposition; never resolves usage."""
    c = auth['continuation']
    path = Path(c['predecessor_ledger_path'])
    if (c.get('version') != CONTINUATION_VERSION or prior.get('continuation')
            or c.get('retain_unknown') is not True or c.get('refund') != 0
            or c.get('full_reservation_nonrefundable') is not True
            or path != Path(prior['ledger_path']) or Path(auth['ledger_path']) == path
            or c.get('consumed_calls') != {'deepseek': 4, 'openai': 1, 'global': 5}
            or c.get('remaining_call_limits') != {'deepseek': 96, 'openai': 102, 'global': 198}
            or auth['max_new_calls'] != 203
            or any(auth['providers'][p]['max_new_calls'] != n for p, n in (('deepseek',100),('openai',103)))
            or c.get('predecessor_checkpoint_sha256') != auth['child_baseline_checkpoint_sha256']):
        _deny('request5 continuation disposition or inherited limits invalid')
    if not offline and (path != DELIVERY_LEDGER or Path(auth['ledger_path']) != CONTINUATION_LEDGER
            or c.get('predecessor_ledger_sha256') != REQUEST5_LEDGER_SHA256
            or c.get('unknown_row_sha256') != REQUEST5_ROW_SHA256):
        _deny('continuation is restricted to the approved frozen request5 history')
    if (digest(_read(path)) != c['predecessor_ledger_sha256']
            or digest(_read(_checkpoint_path(path))) != c['predecessor_checkpoint_sha256']):
        _deny('continuation predecessor ledger/checkpoint changed')
    child = _checked_child(path, key)
    rows = child['requests']
    if (len(rows) != 5 or child.get('version') != LEDGER_VERSION
            or len({r.get('request_id') for r in rows}) != 5 or child.get('mission_id') != NEW_MISSION
            or child.get('evidence_domain') != auth['evidence_domain']
            or child.get('parent_ledger_sha256') != auth['parent']['ledger_sha256']
            or child.get('authorization_sha256') != auth['previous_authorization_sha256']
            or digest(canonical(rows)) != c['requests_sha256']):
        _deny('continuation predecessor authorization or complete prefix mismatch')
    for i, row in enumerate(rows, 1):
        p = 'deepseek' if i <= 4 else 'openai'
        lane = prior['providers'][p]
        if (row.get('number') != i or row.get('provider') != p or row.get('model') != lane['model']
                or row.get('status') != 'RETURNED' or row.get('mission_id') != NEW_MISSION
                or row.get('authorization_sha256') != auth['previous_authorization_sha256']
                or row.get('token_reservation') != lane['token_reservation']
                or row.get('cost_reservation_microunits') != lane['cost_reservation_microunits']
                or row.get('cost_unit') != lane['cost_unit']
                or (i <= 4 and row.get('usage_accounting') != 'FULL_RESERVATION_RETAINED')):
            _deny('continuation cannot inherit in-flight, refunded or incomplete reservations')
    row = rows[-1]
    if (row.get('reported_usage') != 'UNKNOWN'
            or row.get('usage_accounting') != 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS'
            or row.get('request_id') != c.get('unknown_request_id')
            or digest(canonical(row)) != c['unknown_row_sha256']):
        _deny('historical UNKNOWN must remain exactly unchanged')
    return child


def _retained_request5(auth, row):
    c = auth.get('continuation')
    return bool(c and auth.get('_predecessor_child') and row.get('number') == 5
                and digest(canonical(row)) == c['unknown_row_sha256'])


def _unresolved(auth, row):
    return (row.get('status') in {'STARTED', 'UNKNOWN'} or row.get('usage_accounting') in
            {'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS', 'OVER_RESERVATION_BLOCK_FUTURE_CALLS'}) and not _retained_request5(auth, row)


def load_authorization(environment=None):
    env = os.environ if environment is None else environment
    # Reject a test-domain artifact before examining the runtime or any transport.
    try:
        value = json.loads(_read(env['CMH_RESOURCE_AUTHORIZATION']))
        if value.get('evidence_domain') != 'FORMAL':
            _deny('offline evidence cannot activate a formal mission')
    except (OSError, ValueError, KeyError) as exc:
        raise ResourceGateDenied('formal delivery authorization is required') from exc
    return _load(env, PRODUCTION_ANCHOR, runtime_snapshot(), time.time())


def authenticate_legacy_signer(key_path):
    _signed(HISTORICAL_AUTHORIZATION, PRODUCTION_ANCHOR.authorization_sha256, _read(key_path))


AVAILABILITY_VERSION = 'cmh-openai-subscription-availability/v1'


def _validate_availability_policy(auth):
    from .openai_invocation import CANONICAL_BINARY, CANONICAL_HOME
    p = auth['openai_availability_policy']
    if (p.get('version') != AVAILABILITY_VERSION or p.get('provider') != 'openai' or
            p.get('route') != 'codex_subscription' or p.get('model') != 'gpt-5.6-sol' or
            p.get('binary') != str(CANONICAL_BINARY) or p.get('codex_home') != str(CANONICAL_HOME) or
            not _integer(p.get('max_snapshot_age_seconds'), 1)):
        _deny('subscription availability policy identity invalid')


def _availability_snapshot(auth, path, sha, key, now):
    from .resource_gate import SubscriptionPause
    value = _signed(path, sha, key)
    p = auth.get('openai_availability_policy')
    if not p:
        _deny('subscription availability policy required')
    _validate_availability_policy(auth)
    identities = dict(version=AVAILABILITY_VERSION, evidence_domain=auth['evidence_domain'],
        provider='openai', route=p['route'], model=p['model'], binary=p['binary'],
        codex_home=p['codex_home'], account_id=auth['account_ids']['openai'],
        credential_identity=auth['credential_identities']['openai'],
        authorization_sha256=auth['_authorization_sha256'], policy_sha256=digest(canonical(p)))
    if (any(value.get(k) != v for k, v in identities.items()) or
            not _integer(value.get('epoch'), 1) or
            not _integer(value.get('observed_epoch')) or not _integer(value.get('expires_epoch')) or
            not value['observed_epoch'] < value['expires_epoch'] <= value['observed_epoch'] + p['max_snapshot_age_seconds'] or
            any(type(value.get(k)) is not bool for k in
                ('subscription_active', 'membership_active', 'known_capacity_blocked'))):
        _deny('subscription availability evidence identity or validity malformed')
    if digest(_read(value['source_path'])) != value['source_sha256']:
        _deny('subscription availability source changed')
    if (not value['observed_epoch'] <= now < value['expires_epoch'] or
            not value['subscription_active'] or not value['membership_active'] or value['known_capacity_blocked']):
        raise SubscriptionPause('current subscription availability is stale or blocked; refresh trusted evidence')
    return value


def _current_availability(auth, ledger, key, now):
    from .resource_gate import SubscriptionPause
    entry = ledger.get('openai_availability')
    if not entry or ledger.get('openai_subscription_block'):
        raise SubscriptionPause('fresh subscription availability evidence required before send')
    value = _availability_snapshot(auth, entry['path'], entry['sha256'], key, now)
    if value['epoch'] != entry['epoch']:
        _deny('subscription availability epoch mismatch')
    return value


def _refresh_availability_validated(auth, env, path, sha, now, *, offline=False):
    if auth['evidence_domain'] != ('OFFLINE_TEST' if offline else 'FORMAL'):
        _deny('synthetic availability cannot authorize production')
    ledger_path = Path(auth['ledger_path']); key = _read(env['CMH_RESOURCE_GATE_KEY_FILE'])
    with _locked(ledger_path.with_name(ledger_path.name + '.lock')):
        if not offline:
            auth = load_authorization(env); now = time.time()
        ledger = _verify_child(ledger_path, key, auth)
        if any(_unresolved(auth, r) for r in ledger['requests']):
            _deny('availability refresh cannot reconcile UNKNOWN, in-flight or overage accounting')
        value = _availability_snapshot(auth, path, sha, key, now)
        old = ledger.get('openai_availability')
        if (value.get('previous_snapshot_sha256') != (old['sha256'] if old else None) or
                value['epoch'] != (old['epoch'] + 1 if old else 1) or
                value.get('baseline_checkpoint_sha256') != digest(_read(_checkpoint_path(ledger_path))) or
                old and value['observed_epoch'] < old['observed_epoch']):
            _deny('availability refresh checkpoint, epoch or history mismatch')
        ledger['openai_availability'] = dict(path=str(path), sha256=sha, epoch=value['epoch'],
                                           observed_epoch=value['observed_epoch'])
        ledger.pop('openai_subscription_block', None)
        _write_child(ledger_path, ledger, key)


def refresh_subscription_availability(path, sha):
    _refresh_availability_validated(load_authorization(), os.environ, path, sha, time.time())


def record_subscription_block(reservation):
    # Failure consumes its existing reservation, even when usage is UNKNOWN.
    if reservation.ledger_key_path is None:
        return
    path = reservation.ledger; key = _read(reservation.ledger_key_path)
    with _locked(path.with_name(path.name + '.lock')):
        ledger = _checked_child(path, key)
        row = next(r for r in ledger['requests'] if r['request_id'] == reservation.request_id)
        if row['status'] != 'FAILED' or row['provider'] != 'openai':
            _deny('subscription failure must bind a settled failed OpenAI attempt')
        row['failure_class'] = 'SUBSCRIPTION_UNAVAILABLE'
        ledger['openai_subscription_block'] = dict(request_id=row['request_id'], status='PAUSED_SUBSCRIPTION_UNAVAILABLE')
        _write_child(path, ledger, key)


def _capacity_paused_request(row):
    return (row.get('provider') == 'openai' and row.get('status') == 'FAILED' and
            row.get('failure_class') == 'SUBSCRIPTION_UNAVAILABLE' and
            row.get('reported_usage') != 'UNKNOWN' and
            row.get('usage_accounting') == 'FULL_RESERVATION_RETAINED')


def _funding_currency(auth):
    currency = auth['deepseek_funding_policy'].get('currency', 'USD')
    if currency not in {'USD', 'CNY'}:
        _deny('unsupported provider capacity currency; no FX conversion')
    return currency


def _funding_suffix(auth):
    return 'microcny' if _funding_currency(auth) == 'CNY' else 'microusd'


def _native_cny_bound(policy):
    """Signed native prices, frozen Direct policy, integer upward rounding.

    Rates are micro-CNY per million tokens, never converted from USD. The
    signing authority must attest rates against the hash-bound pricing source.
    """
    from .deepseek_direct import identity, MAX_CONTEXT, MAX_TOKENS
    price = policy.get('native_price')
    if (not isinstance(price, dict) or set(price) != {
            'provider', 'currency', 'model', 'input_cache_miss_microcny_per_million',
            'output_microcny_per_million'} or price['provider'] != 'deepseek' or
            price['currency'] != 'CNY' or price['model'] != 'deepseek-flash' or
            policy.get('direct_transport_identity') != identity()):
        _deny('native CNY pricing or frozen Direct transport identity invalid')
    a, b = price['input_cache_miss_microcny_per_million'], price['output_microcny_per_million']
    if not _integer(a, 1) or not _integer(b, 1):
        _deny('native prices must be positive integer micro-CNY per million tokens')
    # Max over the two endpoints G=0 and G=MAX_TOKENS; reasoning is in G.
    numerator = a * MAX_CONTEXT + max(0, b - a) * MAX_TOKENS
    return (numerator + 999999) // 1000000


def _validate_funding_policy(auth):
    policy = auth['deepseek_funding_policy']
    suffix = _funding_suffix(auth)
    native = suffix == 'microcny'
    limits = policy.get('unit_upper_bound_' + suffix, {})
    if (policy.get('version') != STAGED_POLICY or policy.get('execution_unit') != 'ONE_PROVIDER_CALL'
            or policy.get('manual_top_up_only') is not True
            or policy.get('provider_enforced_unit_bound') is not True
            or not _integer(policy.get('max_snapshot_age_seconds'), 1)
            or not _integer(policy.get('safety_margin_' + suffix))
            or set(limits) != {'chunk_or_qualification', 'group_or_cross_group'}
            or any(not _integer(v, 1) for v in limits.values())):
        _deny('staged funding requires proven currency-specific provider bounds')
    if native:
        if ('unit_upper_bound_microusd' in policy or 'safety_margin_microusd' in policy or
                any(v != _native_cny_bound(policy) for v in limits.values())):
            _deny('CNY exposure must equal the native physical bound, separate from USD debit')
    elif any(v > auth['providers']['deepseek']['cost_reservation_microunits'] for v in limits.values()):
        _deny('legacy USD bound exceeds mission debit')
    operational = policy.get('no_overdraft_policy') == OPERATIONAL_NO_OVERDRAFT
    if operational:
        from .deepseek_direct import identity
        transport = identity()
        if (not native or transport['max_tokens'] != 90000 or
                transport['http_attempts'] != 1 or transport['retry'] != 0 or
                transport['redirect_replay'] != 0 or
                policy['safety_margin_microcny'] != (_native_cny_bound(policy) * 10 + 99) // 100 or
                any(name in policy for name in ('provider_no_overdraft',
                    'no_overdraft_source_path', 'no_overdraft_source_sha256'))):
            _deny('operational safety requires frozen single-send transport and approved ten-percent margin')
    elif policy.get('no_overdraft_policy') is not None or policy.get('provider_no_overdraft') is not True:
        _deny('funding policy must select a supported no-overdraft contract')
    for name in (('pricing', 'enforced_bound') if operational else
                 ('pricing', 'enforced_bound', 'no_overdraft')):
        if digest(_read(policy[name + '_source_path'])) != policy[name + '_source_sha256']:
            _deny('official unit financial safety rules missing or changed')


def _snapshot(auth, path, sha, key, now):
    try:
        value = _signed(path, sha, key)
        policy = auth['deepseek_funding_policy']
        currency, suffix = _funding_currency(auth), _funding_suffix(auth)
        if currency == 'CNY' and (value.get('provider') != 'deepseek' or
                value.get('amount_semantics') != 'CURRENT_AVAILABLE_NET_BALANCE' or
                any(k in value for k in ('available_microusd', 'unsettled_liability_microusd',
                                        'other_allocations_microusd', 'conversion_source_path',
                                        'conversion_source_sha256'))):
            _deny('native wallet provider, amount semantics or currency ambiguity invalid')
        if (value.get('version') != FUNDS_VERSION or value.get('evidence_domain') != auth['evidence_domain']
                or value.get('authorization_sha256') != auth['_authorization_sha256']
                or value.get('parent_ledger_sha256') != auth['parent']['ledger_sha256']
                or value.get('account_id') != auth['account_ids']['deepseek']
                or value.get('credential_identity') != auth['credential_identities']['deepseek']
                or value.get('route') != 'deepseek-flash' or value.get('unit') != currency
                or value.get('policy_sha256') != digest(canonical(policy))
                or value.get('no_unbounded_prior_liability') is not True
                or value.get('historical_settlement_in_net_balance') is not True
                or value.get('settlement_coverage_verified') is not True
                or value.get('exclusive_allocation') is not True
                or not _integer(value.get('epoch'), 1)
                or not _integer(value.get('observed_epoch')) or not _integer(value.get('expires_epoch'))
                or value['expires_epoch'] > value['observed_epoch'] + policy['max_snapshot_age_seconds']
                or value['expires_epoch'] <= value['observed_epoch']
                or any(not _integer(value.get(k)) for k in
                       ('available_' + suffix, 'unsettled_liability_' + suffix,
                        'other_allocations_' + suffix, 'covered_requests'))):
            _deny('wallet account, settlement, liability or conversion evidence invalid')
        for name in (('official', 'settlement') if currency == 'CNY' else
                     ('official', 'conversion', 'settlement')):
            if digest(_read(value[name + '_source_path'])) != value[name + '_source_sha256']:
                _deny('wallet official, currency or settlement source changed')
        if not value['observed_epoch'] <= now < value['expires_epoch']:
            raise FundingPause('余额证据未生效或已过期；请提供新的可信快照', currency=currency)
        return value
    except (OSError, KeyError, ValueError, TypeError) as exc:
        raise ResourceGateDenied('wallet snapshot malformed or incomplete') from exc


def _current_funds(auth, ledger, key, now):
    entry = ledger.get('funding')
    if not entry:
        raise FundingPause('缺少可信余额快照；未预留、未发起请求', currency=_funding_currency(auth))
    value = _snapshot(auth, entry['path'], entry['sha256'], key, now)
    rows = ledger['requests']
    n = value['covered_requests']
    if (entry['epoch'] != value['epoch'] or n > len(rows)
            or value['covered_prefix_sha256'] != digest(canonical(rows[:n]))
            or any((r.get('status') != 'RETURNED' or r.get('usage_accounting') != 'FULL_RESERVATION_RETAINED')
                   and not _retained_request5(auth, r) for r in rows[:n])):
        _deny('wallet settlement coverage differs from authenticated request prefix')
    return value


def _funding_check(auth, ledger, key, stage, now):
    value = _current_funds(auth, ledger, key, now)
    currency, suffix = _funding_currency(auth), _funding_suffix(auth)
    name = ('group_or_cross_group' if stage.startswith('group') or
            stage.startswith('aggregate') else 'chunk_or_qualification')
    upper = auth['deepseek_funding_policy']['unit_upper_bound_' + suffix][name]
    # The snapshot is already a net balance. Never subtract settled history.
    # Retain full exposure only for calls not yet reflected in that snapshot.
    pending = [r for r in ledger['requests'][value['covered_requests']:] if r['provider'] == 'deepseek']
    if any(not _integer(r.get('wallet_exposure_' + suffix), 1) for r in pending):
        _deny('pending wallet exposure currency missing or incompatible')
    free = (value['available_' + suffix] - value['unsettled_liability_' + suffix] -
            value['other_allocations_' + suffix] - sum(r['wallet_exposure_' + suffix] for r in pending))
    required = upper + auth['deepseek_funding_policy']['safety_margin_' + suffix]
    if free < required:
        raise FundingPause('余额不足；请手动补款并刷新可信证据', required=required,
                           available=free, currency=currency)
    return dict(value, _unit_exposure=upper)


def _refresh_validated(auth, env, snapshot_path, snapshot_sha256, now, *, offline=False):
    """Adopt separately signed capacity, never sign/replace execution authority."""
    if auth['evidence_domain'] != ('OFFLINE_TEST' if offline else 'FORMAL'):
        _deny('offline funds cannot activate formal execution')
    path = Path(auth['ledger_path']); key = _read(env['CMH_RESOURCE_GATE_KEY_FILE'])
    with _locked(path.with_name(path.name + '.lock')):
        if not offline:
            auth = load_authorization(env); now = time.time()
        if not auth.get('deepseek_funding_policy'):
            _deny('signed mission does not permit staged wallet refresh')
        ledger = _verify_child(path, key, auth)
        if any(_unresolved(auth, r) for r in ledger['requests']):
            _deny('funding refresh cannot clear in-flight, unknown or overage requests')
        value = _snapshot(auth, snapshot_path, snapshot_sha256, key, now)
        old = ledger.get('funding')
        if (value.get('previous_snapshot_sha256') != (old['sha256'] if old else None)
                or value['epoch'] != (old['epoch'] + 1 if old else 1)
                or value.get('baseline_checkpoint_sha256') != digest(_read(_checkpoint_path(path)))
                or old and value['observed_epoch'] < old['observed_epoch']
                or old and value['covered_requests'] < old['covered_requests']):
            _deny('funding epoch replay, rollback or checkpoint drift')
        candidate = dict(ledger, funding={'path': str(snapshot_path), 'sha256': snapshot_sha256,
            'epoch': value['epoch'], 'observed_epoch': value['observed_epoch'],
            'covered_requests': value['covered_requests']})
        _current_funds(auth, candidate, key, now)
        # Pause stays until a complete, atomic resource reservation succeeds.
        _write_child(path, candidate, key)


def refresh_wallet_snapshot(snapshot_path, snapshot_sha256):
    """Future account-owner-signed evidence only; no credentials or top-up."""
    _refresh_validated(load_authorization(), os.environ, snapshot_path, snapshot_sha256, time.time())


def qualification_binding(auth):
    return {'mission_id': NEW_MISSION, 'authorization_sha256': auth['_authorization_sha256'],
            'parent_ledger_sha256': auth['parent']['ledger_sha256'],
            'runtime_sha256': digest(canonical(auth['runtime']))}


def validate_qualification_binding(binding, auth):
    if binding != qualification_binding(auth) or auth['evidence_domain'] != 'FORMAL':
        _deny('old or synthetic qualification cannot authorize formal delivery')


def require_invocation_spec(spec):
    if os.environ.get('CMH_RESOURCE_MISSION_ID') == NEW_MISSION:
        auth = load_authorization()
        if spec.identity() != auth['runtime']['models'].get(spec.provider):
            _deny('provider invocation differs from the signed model and reasoning contract')


def credential_identity(provider, credential_bytes, key):
    import hashlib
    return hmac.new(key, b'cmh-delivery-account-route/v1/' + provider.encode() + b'/' + credential_bytes,
                    hashlib.sha256).hexdigest()


def require_provider_credential(provider, credential_bytes):
    if os.environ.get('CMH_RESOURCE_MISSION_ID') == NEW_MISSION:
        auth = load_authorization()
        key = _read(os.environ['CMH_RESOURCE_GATE_KEY_FILE'])
        if (not credential_bytes or credential_identity(provider, credential_bytes, key) !=
                auth['credential_identities'][provider]):
            _deny('actual provider credential/home differs from the authenticated account capacity route')


def _bounded_timeout(auth, now, requested):
    if type(requested) is not int or requested < 1:
        _deny('delivery child timeout must be a positive bounded integer')
    remaining = min(auth['expires_epoch'], auth['started_epoch'] + auth['max_wall_clock_seconds'],
                    auth['_account']['expires_epoch']) - now
    from .resource_gate import _active_reservation
    active = _active_reservation.get()
    if auth.get('deepseek_funding_policy') and active is not None and active.provider == 'deepseek':
        ledger = _verify_child(Path(auth['ledger_path']), _read(active.ledger_key_path), auth)
        try:
            funds = _current_funds(auth, ledger, _read(active.ledger_key_path), now)
        except FundingPause as exc:
            raise ResourceGateDenied('funding validity lost after STARTED; retain unknown freeze') from exc
        remaining = min(remaining, funds['expires_epoch'] - now)
    result = min(requested, 900, int(remaining))
    if result < 1:
        _deny('not enough valid time remains to launch a provider subprocess')
    return result


def bounded_delivery_timeout(requested):
    if os.environ.get('CMH_RESOURCE_MISSION_ID') == NEW_MISSION:
        return _bounded_timeout(load_authorization(), time.time(), requested)
    return requested


def require_active_transport(provider, model):
    """The lower-level CLI helpers cannot bypass activation or atomic reservation."""
    from .resource_gate import _active_reservation
    active = _active_reservation.get()
    if active is None or active.execution_allowed is not True:
        _deny('synthetic reservations cannot enter provider transport')
    if (active.provider, active.model) != (provider, model):
        _deny('raw provider transport differs from its active resource reservation')
    if os.environ.get('CMH_RESOURCE_MISSION_ID') == NEW_MISSION:
        auth = load_authorization()
        if provider == 'deepseek' and (not auth.get('deepseek_funding_policy') or
                                     _funding_currency(auth) != 'CNY'):
            _deny('Direct transport requires native CNY staged capacity')
        if (active is None or active.ledger_key_path is None or
                (active.provider, active.model) != (provider, model) or
                active.authorization_sha256 != auth['_authorization_sha256']):
            _deny('raw provider transport requires an active formal delivery reservation')
        ledger = _checked_child(active.ledger, _read(active.ledger_key_path))
        if provider == 'openai':
            _current_availability(auth, ledger, _read(active.ledger_key_path), time.time())
        if provider == 'deepseek' and auth.get('deepseek_funding_policy'):
            try:
                snapshot = _current_funds(auth, ledger, _read(active.ledger_key_path), time.time())
            except FundingPause as exc:
                raise ResourceGateDenied('funding validity lost after STARTED; retain unknown freeze') from exc
            row = next((r for r in ledger['requests'] if r.get('request_id') == active.request_id), {})
            if (row.get('funding_epoch') != snapshot['epoch'] or
                    row.get('funding_snapshot_sha256') != ledger['funding']['sha256']):
                _deny('transport funding epoch differs from its atomic reservation')
        if not any(row.get('request_id') == active.request_id and row.get('status') == 'STARTED'
                   and row.get('evidence_domain') == 'FORMAL' for row in ledger['requests']):
            _deny('raw provider transport reservation identity or state invalid')
    else:
        from .resource_gate import _authorization
        try:
            env = os.environ
            if env['CMH_RESOURCE_MISSION_ID'] != OLD_MISSION:
                _deny('raw transport cannot select an unapproved legacy mission')
            authenticate_legacy_signer(env['CMH_RESOURCE_GATE_KEY_FILE'])
            auth = _authorization(Path(env['CMH_RESOURCE_AUTHORIZATION']),
                                  Path(env['CMH_RESOURCE_GATE_KEY_FILE']), env['CMH_RESOURCE_AUTH_SHA256'])
            if (auth['mission_id'] != OLD_MISSION or auth['ledger_path'] != str(active.ledger)
                    or active.authorization_sha256 != env['CMH_RESOURCE_AUTH_SHA256']):
                _deny('raw legacy transport authorization identity mismatch')
            rows = json.loads(_read(active.ledger))['requests']
            if any(row.get('usage_accounting') == 'USAGE_UNVERIFIED_BLOCK_FUTURE_CALLS'
                   or row.get('status') == 'UNKNOWN' for row in rows):
                _deny('raw legacy transport cannot bypass unresolved historical usage')
            if not any(row.get('request_id') == active.request_id and row.get('status') == 'STARTED'
                       for row in rows):
                _deny('raw legacy transport lacks a durable active reservation')
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ResourceGateDenied('raw legacy transport needs authenticated resource context') from exc


def bind_review(mission_id, root, base, head, registry_hash, spec, qualification):
    if mission_id != NEW_MISSION and os.environ.get('CMH_RESOURCE_MISSION_ID') != NEW_MISSION:
        return None
    auth = load_authorization()
    validate_qualification_binding(qualification.get('delivery_binding'), auth)
    from .full_diff_manifest import git, read_diff, plan, synthesis_stage_names
    target = next((name for name, item in auth['targets'].items()
                   if item == {'base': base, 'head': head}), None)
    if (mission_id != NEW_MISSION or target is None
            or git(root, 'rev-parse', 'HEAD').decode().strip() != head
            or git(root, 'status', '--porcelain').strip()
            or registry_hash != auth['runtime']['registry_sha256']
            or spec.identity() != auth['runtime']['models'][spec.provider]):
        _deny('review arguments differ from the signed delivery identity')
    chunks, groups = plan(read_diff(root, base, head))
    stages = [f'chunk-{i:03d}' for i in range(len(chunks))] + [f'group-{i:03d}' for i in range(len(groups))]
    if spec.provider == 'deepseek':
        stages = [name + '.json' for name in stages] + ['aggregate.json']
    else:
        stages += ['structured-preflight'] + [name for name, _ in synthesis_stage_names(len(groups))]
    return _review_context.set({'target': target, 'base': base, 'head': head, 'stages': stages,
                               'binding': qualification_binding(auth), 'provider': spec.provider})


def reset_review(token):
    if token is not None:
        _review_context.reset(token)


def _checkpoint_path(path):
    return path.with_name(path.name + '.checkpoint.json')


def _checked_child(path, key):
    raw = _read(path)
    checkpoint = _signed(_checkpoint_path(path), None, key)
    if (checkpoint.get('ledger_path') != str(path) or checkpoint.get('ledger_sha256') != digest(raw)):
        _deny('delivery durable checkpoint differs from ledger; recovery must fail closed')
    ledger = _signed(path, None, key)
    if checkpoint.get('requests') != len(ledger.get('requests', [])):
        _deny('delivery checkpoint high-water count mismatch')
    return ledger


def _write_child(path, ledger, key):
    sealed = sign_authorization(ledger, key)
    raw_hash = digest(canonical(sealed) + b'\n')
    checkpoint = {'ledger_path': str(path), 'ledger_sha256': raw_hash,
                  'requests': len(ledger['requests'])}
    # Journal intent first. A crash between writes causes a mismatch and blocks
    # all launches; it never silently refunds a reservation.
    _write_atomic(_checkpoint_path(path), sign_authorization(checkpoint, key))
    _write_atomic(path, sealed)


def _verify_child(path, key, auth):
    ledger = _checked_child(path, key)
    if (ledger.get('version') != LEDGER_VERSION
            or ledger.get('evidence_domain') != auth['evidence_domain']
            or ledger.get('mission_id') != NEW_MISSION
            or ledger.get('parent_ledger_sha256') != auth['parent']['ledger_sha256']
            or ledger.get('authorization_sha256') != auth['_authorization_sha256']):
        _deny('empty or unlinked ledger cannot restart delivery accounting')
    rows = ledger['requests']
    if auth.get('continuation') and (not auth.get('_predecessor_child') or
            rows[:5] != auth['_predecessor_child']['requests']):
        _deny('continuation cannot modify, truncate or refund inherited history')
    if (not isinstance(rows, list) or any(row.get('number') != i or
            row.get('mission_id') != NEW_MISSION or
            row.get('authorization_sha256') not in auth['_lineage_sha256']
            for i, row in enumerate(rows, 1)) or
            len({r.get('request_id') for r in rows}) != len(rows)):
        _deny('delivery ledger continuity or identity invalid')
    return ledger


def _qualification_request(rows, provider, prompt, run_id, authorization_hash=None):
    from .model_qualification import CASES, qualification_prompt
    previous = [r for r in rows if r['provider'] == provider and r['stage'] == 'qualification-case'
                and (authorization_hash is None or r['authorization_sha256'] == authorization_hash)]
    if any(r['run_id'] != run_id for r in previous):
        _deny('qualification attempts cannot change run identity after capacity pause')
    capacity_failures = [r for r in previous if _capacity_paused_request(r)]
    if provider == 'openai':
        if (len(capacity_failures) >= 2 or
                sum(r.get('prompt_sha256') == digest(prompt) for r in previous) >= 2):
            _deny('bounded Qualification capacity-pause attempt limit reached')
        previous = [r for r in previous if not _capacity_paused_request(r)]
    if (len(previous) >= len(CASES) or
            any(r['run_id'] != run_id for r in previous) or
            prompt != qualification_prompt(CASES[len(previous)]).encode()):
        _deny('qualification is exactly one ordered four-case run; no arbitrary probe or retry')


def _reserve_validated(auth, env, provider, model, prompt, stage, now, *, offline=False):
    from .resource_gate import _stage_reservation, _limits
    if auth['evidence_domain'] != ('OFFLINE_TEST' if offline else 'FORMAL'):
        _deny('synthetic resource context cannot launch a provider')
    if not env.get('CMH_RESOURCE_RUN_ID'):
        _deny('delivery run identity required')
    lane = auth['providers'][provider]
    if not offline:
        _limits(auth, provider, model)  # Preserve existing price/route and token safety rules.
    if lane['model'] != model:
        _deny('delivery model identity mismatch')
    reservation = _stage_reservation(lane, provider, stage)
    path = Path(auth['ledger_path']); key = _read(env['CMH_RESOURCE_GATE_KEY_FILE'])
    with _locked(path.with_name(path.name + '.lock')):
        if not offline:
            auth = load_authorization(env)  # Recheck time/evidence/identity under the reservation lock.
            lane = auth['providers'][provider]
            reservation = _stage_reservation(lane, provider, stage)
            if stage != 'qualification-case':
                context = _review_context.get()
                if not context or context['binding'] != qualification_binding(auth):
                    _deny('review context expired or changed before atomic reservation')
            now = time.time()
        ledger = _verify_child(path, key, auth)
        rows = ledger['requests']; prior = [r for r in rows if r['provider'] == provider]
        context = None
        if not offline:
            if stage == 'qualification-case':
                _qualification_request(rows, provider, prompt, env['CMH_RESOURCE_RUN_ID'],
                                       auth['_authorization_sha256'])
            else:
                context = _review_context.get()
                if stage not in context['stages']:
                    _deny('review stage is outside the exact signed full-diff manifest')
                attempts = {}
                for row in prior:
                    if row.get('target') is not None:
                        item = (row['authorization_sha256'], row['target'], row['stage'])
                        attempts[item] = attempts.get(item, 0) + 1
                item = (auth['_authorization_sha256'], context['target'], stage)
                if (attempts.get(item, 0) >= 2 or attempts.get(item, 0) and
                        sum(max(0, count - 1) for count in attempts.values()) >= 2):
                    _deny('same-stage or provider total bounded retry limit reached')
        if any(_unresolved(auth, r) for r in rows):
            _deny('new mission has an unreconciled or in-flight request')
        if (len(rows) >= auth['max_new_calls'] or len(prior) >= lane['max_new_calls']
                or auth['_history']['global_calls'] + len(rows) + 1 +
                sum(a['other_calls'] for a in auth['_account']['accounts'].values()) > auth['shared_max_calls']):
            _deny('independent or shared logical call limit exhausted')
        for category in CATEGORIES:
            used = sum(r['token_reservation'][category] for r in prior)
            if (used + reservation[category] > lane['token_limit'][category] or
                    auth['_history'][provider]['tokens'][category] + used + reservation[category] +
                    auth['_account']['accounts'][provider]['other_tokens'][category] >
                    auth['shared_token_limits'][provider][category]):
                _deny('independent or shared token reservation ceiling exhausted')
        cost = sum(r['cost_reservation_microunits'] for r in prior) + lane['cost_reservation_microunits']
        account = auth['_account']['accounts'][provider]
        exposure = auth['_history'][provider]['cost'] + cost + account['other_reserved_microunits']
        staged = provider == 'deepseek' and auth.get('deepseek_funding_policy')
        if not offline and provider == 'deepseek' and (not staged or _funding_currency(auth) != 'CNY'):
            _deny('Direct DeepSeek requires native CNY staged capacity before reservation')
        if (cost > lane['cost_limit_microunits'] or exposure > auth['shared_cost_limits'][provider]
                or not staged and not (provider == 'openai' and auth.get('openai_availability_policy'))
                and exposure > account['available_microunits']):
            _deny('independent or shared account capacity exhausted')
        availability = None
        if provider == 'openai' and (not offline or auth.get('openai_availability_policy')):
            availability = _current_availability(auth, ledger, key, now)
        funds = None
        if staged:
            try:
                funds = _funding_check(auth, ledger, key, stage, now)
            except FundingPause as exc:
                ledger['funding_pause'] = dict(exc.details, provider=provider, stage=stage,
                    run_id=env['CMH_RESOURCE_RUN_ID'], observed_epoch=now,
                    request_high_water=len(rows), authorization_sha256=auth['_authorization_sha256'])
                _write_child(path, ledger, key)
                raise
        request_id = uuid.uuid4().hex
        row = {'number': len(rows) + 1, 'request_id': request_id, 'mission_id': NEW_MISSION,
               'authorization_sha256': auth['_authorization_sha256'], 'provider': provider,
               'model': model, 'run_id': env['CMH_RESOURCE_RUN_ID'], 'stage': stage,
               'started_epoch': now, 'status': 'STARTED', 'formal_delivery_gate': True,
               'evidence_domain': auth['evidence_domain'], 'prompt_sha256': digest(prompt),
               'parent_ledger_sha256': auth['parent']['ledger_sha256'],
               'account_evidence_sha256': auth['account_evidence_sha256'],
               'token_reservation': reservation, 'cost_unit': lane['cost_unit'],
               'cost_reservation_microunits': lane['cost_reservation_microunits'],
               'usage_accounting': 'FULL_RESERVATION_RETAINED'}
        if availability is not None:
            row.update(subscription_availability_epoch=availability['epoch'],
                       subscription_availability_sha256=ledger['openai_availability']['sha256'])
        if funds is not None:
            row.update(funding_epoch=funds['epoch'], funding_snapshot_sha256=ledger['funding']['sha256'],
                       **{'wallet_exposure_' + _funding_suffix(auth): funds['_unit_exposure']})
            if _funding_currency(auth) == 'CNY':
                row.update(wallet_currency='CNY', wallet_semantic_type='PROVIDER_CAPACITY',
                           native_price_identity_sha256=digest(canonical(auth['deepseek_funding_policy'])))
            ledger.pop('funding_pause', None)
        if provider == 'deepseek':
            row['price_microusd_per_million'] = lane.get('price_microusd_per_million')
            row['cost_basis_policy'] = lane.get('cli_cost_policy')
        if context is not None:
            row['target'] = context['target']
            row['review_binding'] = context['binding']
        rows.append(row)
        _write_child(path, ledger, key)
    return Reservation(path, request_id, auth['_authorization_sha256'], provider, model,
                       ledger_key_path=Path(env['CMH_RESOURCE_GATE_KEY_FILE']), execution_allowed=not offline)


def reserve_delivery(*, provider, model, prompt, stage, environment=None):
    env = os.environ if environment is None else environment
    auth = load_authorization(env)
    if stage != 'qualification-case':
        context = _review_context.get()
        if (not context or context['binding'] != qualification_binding(auth)
                or context['provider'] != provider):
            _deny('formal review needs a current qualified and signed target context')
    return _reserve_validated(auth, env, provider, model, prompt, stage, time.time())


def _activate_validated(auth, env, *, offline=False):
    if auth['evidence_domain'] != ('OFFLINE_TEST' if offline else 'FORMAL'):
        _deny('synthetic activation cannot become effective formal authority')
    path = Path(auth['ledger_path']); key = _read(env['CMH_RESOURCE_GATE_KEY_FILE'])
    with _locked(path.with_name(path.name + '.lock')):
        if not offline:
            auth = load_authorization(env)
        if path.exists() or _checkpoint_path(path).exists():
            previous = auth['_previous']
            if previous is None or digest(_read(_checkpoint_path(path))) != auth['child_baseline_checkpoint_sha256']:
                _deny('existing delivery history needs a signed exact-checkpoint identity update')
            previous['_lineage_sha256'] = auth['_lineage_sha256'][1:]
            ledger = _verify_child(path, key, previous)
            if any(_unresolved(auth, r) for r in ledger['requests']):
                _deny('identity update cannot clear an unreconciled child request')
            ledger['authorization_sha256'] = auth['_authorization_sha256']
            _write_child(path, ledger, key)
            return
        if auth.get('continuation'):
            if auth['_previous'] is None or auth.get('_predecessor_child') is None:
                _deny('continuation requires authenticated predecessor history')
            ledger = copy.deepcopy(auth['_predecessor_child'])
            ledger['authorization_sha256'] = auth['_authorization_sha256']
            ledger['predecessor_capacity'] = {k: ledger.pop(k) for k in
                ('funding', 'openai_availability') if k in ledger}
            _write_child(path, ledger, key)
            return
        if auth['_previous'] is not None:
            _deny('identity update cannot replace missing child history with an empty ledger')
        ledger = {'version': LEDGER_VERSION, 'evidence_domain': 'FORMAL', 'mission_id': NEW_MISSION,
                  'parent_ledger_sha256': auth['parent']['ledger_sha256'],
                  'authorization_sha256': auth['_authorization_sha256'], 'requests': []}
        ledger['evidence_domain'] = auth['evidence_domain']
        _write_child(path, ledger, key)


def initialize_ledger():
    """Future signed activation/update only. This never signs an execution approval."""
    _activate_validated(load_authorization(), os.environ)
