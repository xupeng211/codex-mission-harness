"""Offline transport fixtures; no credentials or production authorization."""
import copy
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
from unittest.mock import patch
from harness import deepseek_direct as direct
from harness.resource_gate import _active_reservation

KEY = 'OFFLINE-SYNTHETIC-KEY-ONLY'
USAGE = dict(prompt_tokens=10, prompt_cache_hit_tokens=2, prompt_cache_miss_tokens=8,
             completion_tokens=5, total_tokens=15, completion_tokens_details={'reasoning_tokens': 3})


def response(output, *, finish='stop', usage=None):
    return {'id': 'offline-response', 'model': direct.MODEL,
            'choices': [{'index': 0, 'finish_reason': finish, 'message': {
                'role': 'assistant', 'content': direct.canonical(output).decode()}}],
            'usage': copy.deepcopy(USAGE if usage is None else usage)}


def envelope(output, prompt, schema, *, finish='stop'):
    return direct.canonical({'structured_output': output, 'direct_completion': {
        'transport': direct.identity(), 'finish_reason': finish, 'model': direct.MODEL,
        'provider_id': 'OFFLINE-ONLY', 'usage': USAGE,
        'request_sha256': direct.digest(direct.canonical(direct.request_payload(prompt, schema))),
        'prompt_sha256': direct.digest(prompt.encode()),
        'schema_sha256': direct.digest(direct.canonical(schema))}})


@contextmanager
def reserved_transport(value=None, *, status=200, error=None):
    active = SimpleNamespace(provider='deepseek', model=direct.MODEL, execution_allowed=True,
                             observed=None)
    active.observe = lambda usage: setattr(active, 'observed', usage)
    token = _active_reservation.set(active)
    try:
        with ExitStack() as stack:
            stack.enter_context(patch('harness.formal_delivery_gate.require_active_transport'))
            stack.enter_context(patch('harness.formal_delivery_gate.require_provider_credential'))
            stack.enter_context(patch('harness.formal_delivery_gate.bounded_delivery_timeout', side_effect=lambda n: n))
            transport = stack.enter_context(patch.object(direct, '_bounded_post',
                side_effect=error, return_value=(status, direct.canonical(value or response({'findings': []})))))
            yield active, transport
    finally:
        _active_reservation.reset(token)
