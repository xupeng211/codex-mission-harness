"""Single-attempt DeepSeek transport. No agent, redirects, retry or repair.

A short-lived worker bounds DNS/connect/read as well as the complete request.
Only the parent publishes sanitized, identity-bound completion evidence.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import multiprocessing
import os
from pathlib import Path
import ssl
import threading
import time

ENDPOINT = 'https://api.deepseek.com/chat/completions'
MODEL = 'deepseek-flash'
MAX_TOKENS = 90000
MAX_CONTEXT = 1048576
MAX_BODY_BYTES = 8_000_000
MAX_PROMPT_BYTES = 192000
VERSION = 'cmh-direct-deepseek/v1'
_SEND_LOCK = threading.Lock()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def loads(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise DirectFailure('DUPLICATE_JSON_FIELD')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(DirectFailure('INVALID_JSON')))


def _contains_secret(value, key):
    if isinstance(value, str):
        return key in value
    if isinstance(value, dict):
        return any(_contains_secret(k, key) or _contains_secret(v, key) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_secret(v, key) for v in value)
    return False


def request_payload(prompt, schema):
    return {'model': MODEL, 'max_tokens': MAX_TOKENS, 'stream': False,
            'thinking': {'type': 'enabled'}, 'reasoning_effort': 'high',
            'response_format': {'type': 'json_object'},
            'messages': [{'role': 'system', 'content': 'Return only JSON matching this schema: ' +
                          canonical(schema).decode()}, {'role': 'user', 'content': prompt}]}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def identity():
    return {'version': VERSION, 'provider_route': 'DIRECT_DEEPSEEK_API',
            'endpoint': ENDPOINT, 'model': MODEL,
            'max_tokens': MAX_TOKENS, 'http_attempts': 1, 'retry': 0,
            'redirect_replay': 0, 'stream': False, 'thinking': 'enabled',
            'reasoning_effort': 'high', 'adapter_sha256': digest(Path(__file__).read_bytes())}


class DirectFailure(RuntimeError):
    """Safe fixed diagnostic codes, never response bodies or exception text."""
    def __init__(self, code):
        self.code = code
        self.retryable = False
        super().__init__('Direct DeepSeek failed: ' + code)


def _post_once(payload, key, timeout):
    # http.client sends once and neither follows redirects nor retries requests.
    conn = http.client.HTTPSConnection('api.deepseek.com', timeout=min(30, timeout),
                                      context=ssl.create_default_context())
    conn.set_debuglevel(0)
    deadline = time.monotonic() + timeout
    try:
        conn.request('POST', '/chat/completions', body=payload,
                     headers={'Authorization': 'Bearer ' + key,
                              'Content-Type': 'application/json'})
        if conn.sock is not None:
            conn.sock.settimeout(max(.001, deadline - time.monotonic()))
        response = conn.getresponse()
        # Do not follow Location, and do not read/store authentication diagnostics.
        if response.status != 200:
            return response.status, b''
        parts, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            chunk = response.read(min(65536, MAX_BODY_BYTES + 1 - size))
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                raise DirectFailure('BODY_LIMIT')
            if not chunk:
                return response.status, b''.join(parts)
            parts.append(chunk)
    finally:
        conn.close()


def _worker(pipe, payload, key, timeout):
    # No exception may escape multiprocessing's bootstrap traceback: even a
    # broken parent pipe must not expose a credential-bearing network error.
    try:
        try:
            status, body = _post_once(payload, key, timeout)
            outcome = ('response', status, body)
        except BaseException:
            outcome = ('failure', 0, b'')
        try:
            pipe.send(outcome)
        except BaseException:
            pass
    finally:
        try:
            pipe.close()
        except BaseException:
            pass


def _bounded_post(payload, key, timeout):
    context = multiprocessing.get_context('fork')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(send, payload, key, timeout))
    try:
        process.start()
        send.close()
        if not receive.poll(timeout):
            raise DirectFailure('REQUEST_TIMEOUT')
        kind, status, body = receive.recv()
        if kind != 'response':
            raise DirectFailure('TRANSPORT_FAILURE')
        return status, body
    except DirectFailure:
        raise
    except Exception:
        raise DirectFailure('TRANSPORT_FAILURE') from None
    finally:
        receive.close(); send.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join()
            process.close()


def normalize_usage(raw):
    names = ('prompt_tokens', 'completion_tokens', 'total_tokens',
             'prompt_cache_hit_tokens', 'prompt_cache_miss_tokens')
    if not isinstance(raw, dict) or any(type(raw.get(k)) is not int or raw[k] < 0 for k in names):
        raise DirectFailure('INVALID_USAGE')
    details = raw.get('completion_tokens_details')
    reasoning = details.get('reasoning_tokens') if isinstance(details, dict) else None
    if (type(reasoning) is not int or reasoning < 0 or
            reasoning > raw['completion_tokens'] or
            raw['prompt_tokens'] != raw['prompt_cache_hit_tokens'] + raw['prompt_cache_miss_tokens'] or
            raw['total_tokens'] != raw['prompt_tokens'] + raw['completion_tokens'] or
            raw['total_tokens'] > MAX_CONTEXT or raw['completion_tokens'] > MAX_TOKENS):
        raise DirectFailure('INVALID_USAGE')
    # Direct prompt tokens partition into cache hit and ordinary/cache-miss input.
    # There is no separately charged cache-creation category on this route.
    return {'tokens': {'input': raw['prompt_cache_miss_tokens'],
                       'cache': raw['prompt_cache_hit_tokens'],
                       'output': raw['completion_tokens'], 'reasoning': reasoning},
            'cache_read_tokens': raw['prompt_cache_hit_tokens'], 'cache_creation_tokens': 0,
            'usage_scope': 'DIRECT_DEEPSEEK_API', 'raw_usage_fields': raw,
            'cost_classification': 'OBSERVED_UNBILLED',
            'provider_route': 'DIRECT_DEEPSEEK_API', 'provider_max_tokens': MAX_TOKENS,
            'transport_identity': identity()}


def _schema_check(value, schema):
    types = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool}
    kind = schema.get('type')
    if kind is not None and (kind not in types or type(value) is not types[kind]):
        raise DirectFailure('INVALID_SCHEMA')
    if 'enum' in schema and value not in schema['enum']:
        raise DirectFailure('INVALID_SCHEMA')
    if isinstance(value, dict):
        props = schema.get('properties', {})
        if (any(k not in value for k in schema.get('required', [])) or
                schema.get('additionalProperties') is False and any(k not in props for k in value)):
            raise DirectFailure('INVALID_SCHEMA')
        for k, child in value.items():
            if k in props:
                _schema_check(child, props[k])
    elif isinstance(value, list):
        for child in value:
            _schema_check(child, schema.get('items', {}))
    elif isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', len(value)):
            raise DirectFailure('INVALID_SCHEMA')


def validate_envelope(raw, *, schema=None, prompt=None):
    try:
        envelope = loads(raw)
        if (not isinstance(envelope, dict) or
                set(envelope) != {'structured_output', 'direct_completion'}):
            raise DirectFailure('INVALID_EVIDENCE')
        meta = envelope['direct_completion']
        if (not isinstance(meta, dict) or set(meta) != {
                'transport', 'finish_reason', 'model', 'request_sha256', 'prompt_sha256',
                'schema_sha256', 'provider_id', 'usage'} or
                meta['transport'] != identity() or meta['finish_reason'] != 'stop' or
                meta['model'] != MODEL or not isinstance(meta['provider_id'], str) or
                not meta['provider_id'] or any(not isinstance(meta[k], str) or len(meta[k]) != 64
                    or any(c not in '0123456789abcdef' for c in meta[k])
                    for k in ('request_sha256', 'prompt_sha256', 'schema_sha256'))):
            raise DirectFailure('INVALID_COMPLETION_EVIDENCE')
        normalize_usage(meta['usage'])
        if schema is not None:
            if meta['schema_sha256'] != digest(canonical(schema)):
                raise DirectFailure('SCHEMA_IDENTITY')
            _schema_check(envelope['structured_output'], schema)
        if prompt is not None and (schema is None or
                meta['prompt_sha256'] != digest(prompt.encode()) or
                meta['request_sha256'] != digest(canonical(request_payload(prompt, schema)))):
            raise DirectFailure('REQUEST_IDENTITY')
        if not isinstance(envelope['structured_output'], dict):
            raise DirectFailure('INVALID_SCHEMA')
        return envelope
    except DirectFailure:
        raise
    except Exception:
        raise DirectFailure('INVALID_EVIDENCE') from None


def _invoke_reserved(prompt, key, schema, timeout, max_tokens):
    from .formal_delivery_gate import require_active_transport, require_provider_credential, bounded_delivery_timeout
    from .resource_gate import _active_reservation
    if (type(max_tokens) is not int or max_tokens != MAX_TOKENS or
            not isinstance(key, str) or not key or '\r' in key or '\n' in key or
            not isinstance(prompt, str) or not isinstance(schema, dict) or
            type(timeout) is not int or timeout < 1 or timeout > 900):
        raise DirectFailure('INVALID_REQUEST')
    try:
        key.encode('ascii')
        if (len(prompt.encode()) > MAX_PROMPT_BYTES or
                key in prompt or _contains_secret(schema, key)):
            raise DirectFailure('INVALID_REQUEST')
        encoded = canonical(request_payload(prompt, schema))
    except (UnicodeError, TypeError, ValueError):
        raise DirectFailure('INVALID_REQUEST') from None
    require_active_transport('deepseek', MODEL)
    require_provider_credential('deepseek', key.encode())
    timeout = bounded_delivery_timeout(timeout)
    active = _active_reservation.get()
    with _SEND_LOCK:
        if active is None or getattr(active, 'direct_send_claimed', False):
            raise DirectFailure('RESERVATION_ALREADY_SENT_OR_MISSING')
        active.direct_send_claimed = True  # Atomic claim: never resend this reservation.
    try:
        status, body = _bounded_post(encoded, key, timeout)
        if key.encode() in body:
            raise DirectFailure('CREDENTIAL_ECHO')
        if status != 200:
            raise DirectFailure('HTTP_' + str(status) if type(status) is int else 'HTTP_FAILURE')
        result = loads(body)
        if _contains_secret(result, key):
            raise DirectFailure('CREDENTIAL_ECHO')
        # Obtain usage even on cap hit; never refund a physical attempt.
        usage = normalize_usage(result.get('usage'))
        active.observe(usage)
        choices = result.get('choices')
        if not isinstance(choices, list) or len(choices) != 1:
            raise DirectFailure('INVALID_COMPLETION')
        choice = choices[0]
        if choice.get('finish_reason') != 'stop':
            raise DirectFailure('INCOMPLETE_COMPLETION')
        message = choice.get('message')
        if (choice.get('index') != 0 or not isinstance(message, dict) or
                message.get('role') != 'assistant' or message.get('tool_calls') or
                result.get('model') != MODEL):
            raise DirectFailure('INVALID_COMPLETION')
        content = message.get('content')
        if not isinstance(content, str) or not content.strip():
            raise DirectFailure('EMPTY_CONTENT')
        structured = loads(content)
        if _contains_secret(structured, key):
            raise DirectFailure('CREDENTIAL_ECHO')
        _schema_check(structured, schema)
        envelope = {'structured_output': structured, 'direct_completion': {
            'transport': identity(), 'finish_reason': choice['finish_reason'],
            'model': result['model'], 'provider_id': result.get('id'),
            'prompt_sha256': digest(prompt.encode()), 'schema_sha256': digest(canonical(schema)),
            'request_sha256': digest(encoded), 'usage': result['usage']}}
        rendered = canonical(envelope)
        validate_envelope(rendered, schema=schema, prompt=prompt)
        return rendered
    except DirectFailure:
        raise
    except Exception:
        raise DirectFailure('INVALID_RESPONSE') from None


def invoke(prompt, key, schema, *, timeout=120, stage='qualification-case', max_tokens=MAX_TOKENS):
    from .resource_gate import _active_reservation, model_request, ResourceGateDenied
    from .formal_delivery_gate import OLD_MISSION
    if os.environ.get('CMH_RESOURCE_MISSION_ID') == OLD_MISSION:
        raise ResourceGateDenied('historical mission is frozen; Direct migration cannot resume it')
    if _active_reservation.get() is not None:
        return _invoke_reserved(prompt, key, schema, timeout, max_tokens)
    with model_request(provider='deepseek', model=MODEL, prompt=prompt.encode(), stage=stage):
        return _invoke_reserved(prompt, key, schema, timeout, max_tokens)
