"""Reviewer V2 semantic identity and immutable ancestor evidence, never send authority.

Only qualification/receipt provenance validators and execution bookkeeping are
outside the semantic digest. Current validators still check every reused result.
All prompts, schemas, parsers, source binding, fixtures, transports and manifests
are included. Origin Git blobs are authenticated by the signed runtime manifest.
"""
from __future__ import annotations
import ast
import base64
import json
import os
from pathlib import Path
from .resource_gate import canonical, digest

SEMANTIC_FILES = {
    'src/harness/reviewer_v2_contract.py': (),
    'src/harness/model_qualification.py': ('validate_qualification_receipt',),
    'src/harness/model_registry.py': (), 'src/harness/deepseek_direct.py': (),
    'src/harness/openai_invocation.py': (), 'src/harness/full_diff_manifest.py': (),
    'src/harness/codex.py': (), 'scripts/deepseek_review.py': (),
    'scripts/model_qualification.py': (),
    'scripts/reviewer_v2_deepseek.py': ('validate',),
    'scripts/reviewer_v2_openai.py': ('validate',),
}


def semantic_code(raw, excluded=()):
    tree = ast.parse(raw)
    tree.body = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 or n.name not in excluded]
    return digest(ast.dump(tree, include_attributes=False).encode())


def semantic_runtime(runtime, root=None):
    from .full_diff_manifest import git
    root = Path(root) if root else Path(__file__).resolve().parents[2]
    hashes = {}
    for name, excluded in SEMANTIC_FILES.items():
        raw = git(root, 'show', runtime['head'] + ':' + name)
        if digest(raw) != runtime['files'].get(name):
            raise ValueError('semantic origin code differs from signed runtime')
        hashes[name] = semantic_code(raw, excluded)
    return {'version': 'cmh-review-semantic-runtime/v1', 'files': hashes,
            'models': runtime['models'], 'registry_sha256': runtime['registry_sha256']}


def origin_authority(origin_sha, auth=None):
    from . import formal_delivery_gate as gate
    auth = auth or gate.load_authorization()
    key = gate._read(os.environ['CMH_RESOURCE_GATE_KEY_FILE'])
    ledger = gate._verify_child(Path(auth['ledger_path']), key, auth)
    if origin_sha not in auth['_lineage_sha256']:
        raise ValueError('artifact authority is not in verified predecessor lineage')
    origin, sha = auth, auth['_authorization_sha256']
    visited = set()
    while sha != origin_sha:
        if sha in visited or not origin.get('previous_authorization_sha256'):
            raise ValueError('artifact lineage skipped or cyclic')
        visited.add(sha)
        continuation = origin.get('continuation', {})
        sha = origin['previous_authorization_sha256']
        successor = origin
        origin = gate._signed(origin['previous_authorization_path'], sha, key)
        prior_path = Path(origin['ledger_path'])
        prior = gate._checked_child(prior_path, key)
        if (continuation.get('predecessor_authorization_sha256') != sha
                or continuation.get('predecessor_ledger_path') != str(prior_path)
                or continuation.get('predecessor_ledger_sha256') != digest(gate._read(prior_path))
                or continuation.get('predecessor_checkpoint_sha256') != digest(gate._read(gate._checkpoint_path(prior_path)))
                or continuation.get('requests_sha256') != digest(canonical(prior['requests']))
                or Path(successor['ledger_path']) != gate.continuation_ledger_path(continuation)):
            raise ValueError('artifact lineage hash, predecessor or fork mismatch')
        if ledger['requests'][:len(prior['requests'])] != prior['requests']:
            raise ValueError('artifact accounting ancestor changed')
    if (origin['mission_id'] != auth['mission_id']
            or origin['targets']['PR2'] != auth['targets']['PR2']
            or origin['credential_identities'] != auth['credential_identities']
            or origin['account_ids'] != auth['account_ids']
            or semantic_runtime(origin['runtime']) != semantic_runtime(auth['runtime'])):
        raise ValueError('artifact semantic runtime, target or account changed')
    return origin, ledger


def authority_matches(origin_sha, mission_id):
    from . import formal_delivery_gate as gate
    if mission_id != gate.NEW_MISSION:
        from .reviewer_v2_contract import contract_authorization_identity
        return origin_sha == contract_authorization_identity(mission_id)
    origin_authority(origin_sha)
    return True


def artifact_code_hash(path, origin_sha):
    """Original code provenance is retained, only after semantic comparison."""
    from .formal_delivery_gate import NEW_MISSION
    if os.environ.get('CMH_RESOURCE_MISSION_ID') != NEW_MISSION:
        return digest(Path(path).read_bytes())
    origin, _ = origin_authority(origin_sha)
    root = Path(__file__).resolve().parents[2]
    name = str(Path(path).resolve().relative_to(root))
    if name not in SEMANTIC_FILES:
        return digest(Path(path).read_bytes())
    return origin['runtime']['files'][name]


def qualification_history(receipt, auth):
    from .model_qualification import CASES, qualification_prompt
    origin_sha = receipt['delivery_binding']['authorization_sha256']
    _, ledger = origin_authority(origin_sha, auth)
    rows = [r for r in ledger['requests'] if r.get('authorization_sha256') == origin_sha
            and r['provider'] == receipt['identity']['provider'] and r['stage'] == 'qualification-case'
            and r['status'] == 'RETURNED']
    if len(rows) != len(CASES):
        raise ValueError('qualification corresponding requests missing')
    for case, row in zip(CASES, rows):
        if (row['prompt_sha256'] != digest(qualification_prompt(case).encode())
                or not isinstance(row.get('reported_usage'), dict)
                or row.get('usage_accounting') != 'FULL_RESERVATION_RETAINED'):
            raise ValueError('qualification request/prompt/accounting changed')


def reusable_review_identity(previous, current):
    """Only provenance hashes may differ; every semantic input is still exact."""
    origin_sha = previous['source_binding_contract_authorization_sha256']
    origin_authority(origin_sha)
    for key in ('runner_hash', 'invocation_hash', 'manifest_implementation_sha256'):
        filename = {'runner_hash': 'scripts/reviewer_v2_' + previous['provider'] + '.py',
                    'invocation_hash': 'src/harness/' + ('deepseek_direct.py' if previous['provider'] == 'deepseek' else 'openai_invocation.py'),
                    'manifest_implementation_sha256': 'src/harness/full_diff_manifest.py'}[key]
        path = Path(__file__).resolve().parents[2] / filename
        if previous[key] != artifact_code_hash(path, origin_sha) or current[key] != digest(path.read_bytes()):
            raise ValueError('review code provenance mismatch')
    ignored = {'runner_hash', 'source_binding_contract_authorization_sha256', 'review_execution_identity'}
    if {k:v for k,v in previous.items() if k not in ignored} != {k:v for k,v in current.items() if k not in ignored}:
        raise ValueError('review prompt/schema/model/source/qualification identity changed')
    unsigned = {k:v for k,v in previous.items() if k != 'review_execution_identity'}
    if previous['review_execution_identity'] != digest(canonical(unsigned)):
        raise ValueError('review identity digest changed')
    return True


def review_history(state, read_artifact):
    """Authenticate each completed output against its immutable original invocation."""
    from . import formal_delivery_gate as gate
    from .openai_invocation import verify_openai_usage
    auth = gate.load_authorization(); key = gate._read(os.environ['CMH_RESOURCE_GATE_KEY_FILE'])
    _, ledger = origin_authority(state['identity']['source_binding_contract_authorization_sha256'], auth)
    for name, record in state['completed'].items():
        raw = read_artifact(record['artifact_path'])
        if digest(raw) != record['artifact_sha256'] or digest(raw) != record['output_hash']:
            raise ValueError('reused artifact hash changed')
        stage = name + '.json' if state['identity']['provider'] == 'deepseek' else name
        rows = [r for r in ledger['requests'] if r.get('run_id') == state['review_run_id']
                and r['stage'] == stage and r['status'] == 'RETURNED'
                and r['prompt_sha256'] == record['input_hash']]
        if len(rows) != 1 or not isinstance(rows[0].get('reported_usage'), dict):
            raise ValueError('reused artifact corresponding verified request missing or ambiguous')
        row = rows[0]
        origin, _ = origin_authority(row['authorization_sha256'], auth)
        if row['usage_accounting'] != 'FULL_RESERVATION_RETAINED':
            raise ValueError('reused artifact accounting reduced')
        if row['provider'] == 'openai':
            verify_openai_usage(row['reported_usage'], row, dict(origin, _authorization_sha256=row['authorization_sha256']), key)
            if row['reported_usage']['response_sha256'] != digest(raw):
                raise ValueError('reused OpenAI response differs from signed transport')
        else:
            value = json.loads(raw)['direct_completion']
            if value['usage'] != row['reported_usage']['raw_usage_fields'] or value['prompt_sha256'] != row['prompt_sha256']:
                raise ValueError('reused DeepSeek usage/prompt differs from accounting')
            transports = [json.loads(read_artifact(d['path'])) for d in state['diagnostic_artifacts']
                          if d['path'].startswith(name + '-transport-')]
            transports = [t for t in transports if (t.get('resource_request') or {}).get('request_id') == row['request_id']]
            if len(transports) != 1 or base64.b64decode(transports[0]['stdout_base64']) != raw:
                verify_legacy_direct_binding(row, raw, origin, key)


def verify_legacy_direct_binding(row, artifact, origin, key):
    """Null legacy checkpoint metadata requires independent signed HTTP evidence.

    The optional private signed index only locates original immutable bindings;
    it cannot substitute their original request/auth/runtime/prompt/usage hashes.
    """
    from . import formal_delivery_gate as gate, deepseek_direct as direct
    index = gate._signed(os.environ.get('CMH_ARTIFACT_RAW_BINDINGS'),
                         os.environ.get('CMH_ARTIFACT_RAW_BINDINGS_SHA256'), key)
    origin_authority(index['authorization_sha256'])
    if index.get('version') != 'cmh-legacy-direct-binding-index/v1':
        raise ValueError('legacy transport index version mismatch')
    ref = index['bindings'].get(row['request_id'])
    if not isinstance(ref, dict) or ref['artifact_sha256'] != digest(artifact):
        raise ValueError('reused Direct artifact has no bound original HTTP proof')
    proof = gate._signed(ref['path'], ref['sha256'], key)
    envelope = direct.loads(artifact); completion = envelope['direct_completion']
    raw = gate._read(proof['raw_response_path'])
    response = direct.loads(raw)
    if (proof['request_id'] != row['request_id']
            or proof['authorization_sha256'] != row['authorization_sha256']
            or proof['runtime_sha256'] != digest(canonical(origin['runtime']))
            or proof['prompt_sha256'] != row['prompt_sha256']
            or proof['model'] != row['model'] or proof['route'] != 'DIRECT_DEEPSEEK_API'
            or proof['transport_retry'] != 0 or proof['http_status'] != 200
            or digest(raw) != proof['raw_response_sha256']
            or proof['provider_id'] != response['id'] or response['id'] != completion['provider_id']
            or proof['schema_sha256'] != completion['schema_sha256']
            or digest(canonical(proof['schema'])) != completion['schema_sha256']
            or response['usage'] != completion['usage']
            or direct.loads(response['choices'][0]['message']['content']) != envelope['structured_output']):
        raise ValueError('legacy Direct HTTP identity/response/usage mismatch')
    direct.validate_envelope(artifact, schema=proof['schema'])
