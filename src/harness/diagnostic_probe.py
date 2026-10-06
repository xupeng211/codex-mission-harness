"""One explicitly signed support experiment, never reviewer authority.

Execution/governance only: use the unchanged canonical transport and schema.
The caller cannot choose another provider, model, route, input, or retry. Scope
counting includes inherited ledger rows, so continuation never resets it.
"""
from __future__ import annotations

from .resource_gate import ResourceGateDenied, canonical, digest

STAGE = 'diagnostic-shadow-output-usage'
VERSION = 'cmh-single-shadow-diagnostic/v1'
PURPOSE = 'OPENAI_SUPPORT_SMALLER_GROUP_OUTPUT_USAGE'
MISSION = 'ADD_MINIMAL_DIAGNOSTIC_SCOPE_AND_RUN_SINGLE_OPENAI_SHADOW_PROBE'
CLASSIFICATION = 'NON_CANONICAL_DIAGNOSTIC_ONLY'
MODEL = {'provider': 'openai', 'model': 'gpt-5.6-sol', 'reasoning_effort': 'high'}


def validate_scope(auth):
    import re
    scope = auth.get('diagnostic_probe')
    lane = auth['providers']['openai']
    expected = {'version': VERSION, 'mission': MISSION, 'purpose': PURPOSE,
                'model': MODEL, 'route': 'codex_subscription', 'max_logical_invocations': 1,
                'result_authority': CLASSIFICATION, 'harness_logical_retry': 0,
                'runtime_head': auth['runtime']['head'],
                'token_ceiling': lane['token_reservation'],
                'cost_ceiling_microunits': lane['cost_reservation_microunits']}
    extra = {'diagnostic_id', 'prompt_sha256', 'schema_sha256', 'prompt_bytes'}
    if (not isinstance(scope, dict) or set(scope) != set(expected) | extra
            or any(scope.get(k) != v or type(scope.get(k)) is not type(v)
                   for k, v in expected.items())
            or auth['runtime']['models']['openai'] != MODEL
            or any(not isinstance(scope[k], str) or not re.fullmatch('[0-9a-f]{64}', scope[k])
                   for k in ('diagnostic_id', 'prompt_sha256', 'schema_sha256'))
            or type(scope['prompt_bytes']) is not int or not 1 <= scope['prompt_bytes'] <= 16384
            or auth.get('qualification_launch_approved') is not False
            or auth.get('full_review_launch_approved') is not False):
        raise ResourceGateDenied('explicit bounded non-canonical diagnostic scope invalid')
    return scope


def validate_request(auth, rows, provider, model, prompt, run_id):
    scope = validate_scope(auth)
    if (provider != 'openai' or model != MODEL['model']
            or digest(prompt) != scope['prompt_sha256'] or len(prompt) != scope['prompt_bytes']
            or run_id != scope['diagnostic_id']):
        raise ResourceGateDenied('diagnostic request differs from exact signed experiment')
    if any(r.get('diagnostic_id') == scope['diagnostic_id'] for r in rows):
        raise ResourceGateDenied('single diagnostic logical invocation already reserved; no retry')
    return scope


def run_once(prompt: str, schema: dict, *, timeout: int = 900, transport_sink=None):
    """Exactly one canonical invocation; exceptions propagate without retry.

    No ReviewRun, Qualification, finding/parser, receipt or adjudication API is
    called. The returned data has explicit non-canonical authority. Canonical
    accounting still validates raw usage independently and retains UNKNOWN.
    """
    from . import formal_delivery_gate as gate
    from .model_registry import ModelSpec
    from .openai_invocation import invoke_openai
    from .resource_gate import model_request, _active_reservation
    if _active_reservation.get() is not None:
        raise ResourceGateDenied('diagnostic cannot borrow or nest an existing reservation')
    auth = gate.load_authorization()
    scope = validate_scope(auth)
    if digest(canonical(schema)) != scope['schema_sha256']:
        raise ResourceGateDenied('diagnostic schema differs from signed experiment')
    # Reservation revalidates the exact prompt and one-call cap under the ledger
    # lock. Do not set environment stage or impersonate a formal review context.
    with model_request(provider='openai', model=MODEL['model'], prompt=prompt.encode(),
                       stage=STAGE) as reservation:
        result = invoke_openai(prompt, ModelSpec(**MODEL), schema, timeout=timeout,
                               transport_sink=transport_sink)
        return {'result_authority': CLASSIFICATION, 'request_id': reservation.request_id,
                'response': result.response, 'evidence': result.evidence}
