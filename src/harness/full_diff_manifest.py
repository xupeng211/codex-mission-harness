"""Canonical full-scope source allocation and execution identity (no providers).

The legacy 256KB API is unchanged. This protocol admits at most 128 bounded
32KB inputs, and 64 groups. Unsupported source kinds block live execution.
"""
from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import time
from pathlib import Path
from .reviewer_v2_contract import canonical, sha256

VERSION = 'cmh-full-diff/v1'
POLICY = 'git-myers-u3-renames50-full-index-binary/v1'
CHUNKING = 'contiguous-bytes-32000/v1'
CHUNK_BYTES = 32000
GROUP_BYTES = 96000
MAX_CHUNKS = 128
MAX_GROUPS = 64
MAX_FULL_BYTES = CHUNK_BYTES * MAX_CHUNKS
MAX_PROMPT_BYTES = 192000
ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
       'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_ATTR_NOSYSTEM': '1'}
OPTIONS = ['-O/dev/null', '--no-ext-diff', '--no-textconv', '--no-color', '--full-index',
           '--find-renames=50%', '--diff-algorithm=myers', '--no-indent-heuristic',
           '--submodule=short', '--src-prefix=a/', '--dst-prefix=b/', '--unified=3', '--ignore-submodules=none']


def git(root, *args, limit=MAX_FULL_BYTES):
    command = ['git', '--no-replace-objects', '-C', str(root), '-c', 'core.quotePath=true',
               '-c', 'diff.renames=true', '-c', 'diff.renameLimit=32767',
               '-c', 'diff.suppressBlankEmpty=false', *args]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=ENV, start_new_session=True)
    blocks, size = [], 0
    deadline = time.monotonic() + 30
    try:
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('canonical Git command timed out')
            if not select.select([process.stdout], [], [], 0.1)[0]:
                continue
            block = os.read(process.stdout.fileno(), min(65536, limit + 1 - size))
            if not block:
                break
            blocks.append(block)
            size += len(block)
            if size > limit:
                raise ValueError('full scope resource limit exceeded; no truncation permitted')
        if process.wait(timeout=max(0.1, deadline - time.monotonic())):
            raise ValueError('canonical Git command failed')
        return b''.join(blocks)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()


def read_diff(root, base, head):
    for value in (base, head):
        if not re.fullmatch('[0-9a-f]{40}', value):
            raise ValueError('canonical full commit SHAs required')
        if git(root, 'cat-file', '-t', value).strip() != b'commit':
            raise ValueError('review identity must identify commits')
    return git(root, 'diff', *OPTIONS, '--binary', base, head, '--')


def plan(diff):
    if not diff or len(diff) > MAX_FULL_BYTES:
        raise ValueError('empty or oversized full scope')
    chunks = [{'index': i, 'start': start, 'end': min(start + CHUNK_BYTES, len(diff)),
               'sha256': sha256(diff[start:start + CHUNK_BYTES])}
              for i, start in enumerate(range(0, len(diff), CHUNK_BYTES))]
    groups = []
    for offset in range(0, len(chunks), 3):
        selected = chunks[offset:offset + 3]
        start, end = selected[0]['start'], selected[-1]['end']
        groups.append({'index': len(groups), 'start': start, 'end': end,
                       'chunk_indexes': [c['index'] for c in selected],
                       'sha256': sha256(diff[start:end])})
    if len(chunks) > MAX_CHUNKS or len(groups) > MAX_GROUPS:
        raise ValueError('full scope stage budget exceeded')
    return chunks, groups


def _records(root, base, head, diff, chunks):
    raw = git(root, 'diff', *OPTIONS, '--raw', '-z', '--no-abbrev', base, head, '--')
    fields = raw.split(b'\0')
    records, cursor = [], 0
    starts = [m.start() for m in re.finditer(rb'^diff --git ', diff, re.M)]
    if not starts or starts[0] != 0:
        raise ValueError('unrecognized canonical patch framing')
    while cursor < len(fields) and fields[cursor]:
        header = fields[cursor].decode('ascii').split()
        cursor += 1
        old_mode, new_mode, old_oid, new_oid, status = header
        path = fields[cursor]; cursor += 1
        old_path = None
        if status[0] in 'RC':
            old_path = path
            path = fields[cursor]; cursor += 1
        index = len(records)
        if index >= len(starts):
            raise ValueError('raw changes and canonical patch disagree')
        start, end = starts[index], starts[index + 1] if index + 1 < len(starts) else len(diff)
        source = diff[start:end]
        kind = ('gitlink' if '160000' in (old_mode[1:], new_mode) else
                'binary' if b'GIT binary patch\n' in source or re.search(rb'^Binary files ', source, re.M) else
                'non-utf8' if not _utf8(source) else 'text')
        # Git raw prefixes the first mode with a colon.
        old_mode = old_mode.lstrip(':')
        if '160000' in (old_mode, new_mode):
            kind = 'gitlink'
        hunks = []
        hstarts = [m.start() for m in re.finditer(rb'^@@ ', source, re.M)]
        for number, hs in enumerate(hstarts):
            he = hstarts[number + 1] if number + 1 < len(hstarts) else len(source)
            hunks.append({'start': start + hs, 'end': start + he,
                          'sha256': sha256(source[hs:he])})
        records.append({'path_hex': path.hex(), 'path': path.decode('utf-8', 'backslashreplace'),
                        'old_path_hex': old_path.hex() if old_path is not None else None,
                        'old_path': old_path.decode('utf-8', 'backslashreplace') if old_path is not None else None,
                        'change_type': status, 'old_mode': old_mode, 'new_mode': new_mode,
                        'old_oid': old_oid, 'new_oid': new_oid, 'start': start, 'end': end,
                        'sha256': sha256(source), 'hunks': hunks, 'source_kind': kind,
                        'review_strategy': 'exact-text' if kind == 'text' else 'BLOCKED: specialized source review required',
                        'chunk_ids': [f'C{c["index"]:03d}' for c in chunks
                                      if c['start'] < end and c['end'] > start]})
    if len(records) != len(starts):
        raise ValueError('uncovered file or unsupported patch framing')
    return records


def _utf8(source):
    try:
        source.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def build_manifest(root, base, head, repository):
    diff = read_diff(root, base, head)
    chunks, groups = plan(diff)
    records = _records(root, base, head, diff, chunks)
    manifest = {'version': VERSION, 'repository': repository, 'base_sha': base, 'head_sha': head,
                'merge_base': git(root, 'merge-base', base, head).decode().strip(),
                'diff_policy': POLICY, 'chunking_policy': CHUNKING,
                'full_diff_sha256': sha256(diff), 'full_diff_bytes': len(diff),
                'changed_file_count': len(records), 'changes': records,
                'chunk_count': len(chunks), 'chunks': chunks, 'groups': groups,
                'resource_limits': {'chunk_bytes': CHUNK_BYTES, 'group_bytes': GROUP_BYTES,
                                    'max_chunks': MAX_CHUNKS, 'max_groups': MAX_GROUPS}}
    manifest['manifest_sha256'] = sha256(canonical(manifest))
    return diff, manifest


def validate_coverage(diff, manifest, actual_chunks=None):
    unsigned = dict(manifest)
    observed = unsigned.pop('manifest_sha256', None)
    if (manifest.get('version') != VERSION or manifest.get('diff_policy') != POLICY
            or manifest.get('chunking_policy') != CHUNKING):
        raise ValueError('unsupported manifest or allocation policy')
    if sha256(canonical(unsigned)) != observed:
        raise ValueError('manifest hash mismatch')
    if len(diff) != manifest['full_diff_bytes'] or sha256(diff) != manifest['full_diff_sha256']:
        raise ValueError('truncated or mutated canonical source')
    chunks, groups = plan(diff)
    if manifest['chunks'] != chunks or manifest['groups'] != groups or manifest['chunk_count'] != len(chunks):
        raise ValueError('canonical allocation mismatch')
    actual = actual_chunks if actual_chunks is not None else chunks
    if len(actual) != len(chunks) or any({k: a.get(k) for k in c} != c for a, c in zip(actual, chunks)):
        raise ValueError('missing, duplicate, overlapping or mutated chunk')
    cursor = 0
    for record in manifest['changes']:
        start, end = record['start'], record['end']
        if start != cursor or not start < end <= len(diff) or sha256(diff[start:end]) != record['sha256']:
            raise ValueError('uncovered or overlapping change record')
        if record['chunk_ids'] != [f'C{c["index"]:03d}' for c in chunks if c['start'] < end and c['end'] > start]:
            raise ValueError('uncovered file allocation')
        cursor = end
    if cursor != len(diff) or len(manifest['changes']) != manifest['changed_file_count']:
        raise ValueError('uncovered file')
    unsupported = sum(r['source_kind'] != 'text' for r in manifest['changes'])
    return {'manifest_sha256': observed, 'diff_sha256': sha256(diff), 'coverage_percentage': 100,
            'COVERAGE_COMPLETE': 'YES', 'UNCOVERED_RANGES': 0, 'DUPLICATE_CANONICAL_COVERAGE': 0,
            'UNSUPPORTED_CHANGE_COUNT': unsupported, 'validator_result': 'PASS',
            'review_ready': unsupported == 0, 'required_chunks': len(chunks), 'required_groups': len(groups)}


def validate_manifest(root, manifest, repository, base, head, review_ready=False):
    diff, expected = build_manifest(root, base, head, repository)
    if manifest != expected:
        raise ValueError('manifest differs from actual Git scope')
    proof = validate_coverage(diff, manifest)
    if review_ready and not proof['review_ready']:
        raise ValueError('unsupported source requires specialized review; live review blocked')
    return proof


def execution_identity(manifest, mission_id, qualification_hash, *, role, provider, model,
                       configuration, registry_hash, runner_hash, invocation_hash, schema_hash):
    identity = {'version': 'cmh-full-review-execution/v1', 'repository': manifest['repository'],
                'mission_id': mission_id, 'base_sha': manifest['base_sha'], 'head_sha': manifest['head_sha'],
                'diff_sha256': manifest['full_diff_sha256'], 'manifest_sha256': manifest['manifest_sha256'],
                'chunking_policy': CHUNKING, 'manifest_implementation_sha256': sha256(Path(__file__).read_bytes()),
                'qualification_receipt_identity': qualification_hash,
                'role': role, 'provider': provider, 'model': model, 'model_configuration': configuration,
                'registry_sha256': registry_hash, 'runner_sha256': runner_hash,
                'invocation_sha256': invocation_hash, 'schema_manifest_sha256': schema_hash}
    identity['execution_sha256'] = sha256(canonical(identity))
    return identity


def validate_execution(identity, expected):
    if identity != expected:
        raise ValueError('qualification/full-review execution identity mismatch')


def synthesis_stage_names(group_count):
    names, count = [], group_count
    while count > 1:
        count = (count + 7) // 8
        for _ in range(count):
            names.append((f'synthesis-{len(names):03d}', 'cross-group'))
    return names


def bounded_prompt(prompt):
    if len(prompt.encode()) > MAX_PROMPT_BYTES:
        raise ValueError('aggregation input budget exceeded; findings cannot be discarded')
    return prompt


def review_tasks(diff, manifest):
    """Bind unique source allocation to a manifest, independently of results."""
    return [{'chunk_id': f'C{c["index"]:03d}', 'canonical_range': [c['start'], c['end']],
             'input_sha256': sha256(diff[c['start']:c['end']]),
             'original_diff_sha256': manifest['full_diff_sha256'],
             'manifest_sha256': manifest['manifest_sha256']}
            for c in manifest['chunks']]


def validate_tasks(diff, manifest, tasks):
    validate_coverage(diff, manifest)
    if tasks != review_tasks(diff, manifest):
        raise ValueError('chunk task ID/source/input/manifest identity mismatch')


def chunk_context(manifest, start, end):
    """Repeated location metadata is separate from canonical source coverage."""
    return canonical([{'path_hex': r['path_hex'], 'old_path_hex': r['old_path_hex'],
                       'change_type': r['change_type'], 'old_oid': r['old_oid'], 'new_oid': r['new_oid'],
                       'old_mode': r['old_mode'], 'new_mode': r['new_mode'],
                       'file_range': [r['start'], r['end']],
                       'hunks': [h for h in r['hunks'] if h['start'] < end and h['end'] > start]}
                      for r in manifest['changes'] if r['start'] < end and r['end'] > start]).decode()
