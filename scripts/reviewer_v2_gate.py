#!/usr/bin/env python3
"""Deterministic, fail-closed gate for this repository's two review lanes.

Each lane's own validator must verify its durable artifacts and authentication
before this module will consider a verdict. The gate never treats a model's
word PASS as an authorization on its own.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import deepseek_review as secure
from harness import full_diff_manifest as full
from pathlib import Path
from typing import Callable


def _diff(root: Path, base: str, head: str) -> bytes:
    return full.read_diff(root, base, head)


def _source_stable(root: Path, base: str, head: str, diff_hash: str) -> bool:
    def git(*args: str) -> bytes:
        return subprocess.check_output(
            ["git", "--no-replace-objects", "-C", str(root), *args],
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8",
                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                 "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1"})
    return (git("rev-parse", "HEAD").decode().strip() == head
            and not git("status", "--porcelain")
            and hashlib.sha256(_diff(root, base, head)).hexdigest() == diff_hash)


def _validate_scope_evidence(
    *, root: Path, base: str, head: str, deepseek_receipt: dict,
    openai_receipt: dict, deepseek_validator: Callable[[dict], dict],
    openai_validator: Callable[[dict], dict], mission_id: str, repository: str,
    qualification_validators: dict[str, Callable[[], dict]], target_main: str,
) -> dict:
    """Return an evidence digest only when both independently validated lanes pass.

    Validator closures must be bound to the expected private artifacts, model
    registry, auth key, repository identity and exact Git range. They must
    raise on any inconsistency. No bypassing a validator is supported.
    """
    if not all(re.fullmatch(r"[0-9a-f]{40}", value or "") for value in (base, head)):
        raise ValueError("full exact Git SHAs are required")
    root = Path(root).resolve(strict=True)
    if full.git(root, 'rev-parse', 'refs/remotes/origin/main').decode().strip() != target_main:
        raise ValueError('target main changed during validation')
    diff_hash = hashlib.sha256(_diff(root, base, head)).hexdigest()
    if not mission_id or not repository or not _source_stable(root, base, head, diff_hash):
        raise ValueError("review source or mission identity is unstable")
    if not deepseek_receipt or not openai_receipt:
        raise ValueError("both lane receipts are required")
    _, manifest = full.build_manifest(root, base, head, repository)
    full.validate_manifest(root, manifest, repository, base, head, review_ready=True)
    lanes = []
    for expected_provider, raw, validator in (
        ("deepseek", deepseek_receipt, deepseek_validator),
        ("openai", openai_receipt, openai_validator),
    ):
        role = 'independent_reviewer' if expected_provider == 'deepseek' else 'final_reviewer'
        qualified = qualification_validators[expected_provider]()
        if (qualified.get('role') != role or qualified.get('mode') != 'real_provider'
                or qualified.get('identity', {}).get('provider') != expected_provider):
            raise ValueError('invalid qualification role/provider')
        verified = validator(raw)
        execution = verified.get('execution_identity', {})
        unsigned_execution = dict(execution)
        execution_hash = unsigned_execution.pop('execution_sha256', None)
        if execution_hash != full.sha256(full.canonical(unsigned_execution)):
            raise ValueError('execution identity integrity mismatch')
        if (verified.get('full_manifest') != manifest
                or execution.get('manifest_sha256') != manifest['manifest_sha256']
                or execution.get('qualification_receipt_identity') != full.sha256(full.canonical(qualified))
                or execution.get('role') != role or execution.get('provider') != expected_provider
                or execution.get('model_configuration') != qualified.get('identity')
                or execution.get('model') != verified.get('model')
                or execution.get('manifest_implementation_sha256') != full.sha256(Path(full.__file__).read_bytes())
                or any(execution.get(key) != verified.get(key) for key in
                       ('repository', 'mission_id', 'base_sha', 'head_sha', 'diff_sha256',
                        'runner_sha256', 'registry_sha256'))):
            raise ValueError('qualification/full scope identity chain mismatch')
        full.validate_coverage(_diff(root, base, head), manifest, verified.get('chunks', []))
        full.validate_tasks(_diff(root, base, head), manifest, verified.get('task_assignments'))
        if (len(verified.get('groups', [])) != len(manifest['groups'])
                or any({k: a.get(k) for k in e} != e
                       for a, e in zip(verified['groups'], manifest['groups']))):
            raise ValueError('required group coverage mismatch')
        if verified != raw:
            raise ValueError("review validator did not return the exact receipt")
        if (verified.get("provider") != expected_provider
                or verified.get("base_sha") != base
                or verified.get("head_sha") != head
                or verified.get("mission_id") != mission_id
                or verified.get("repository") != repository
                or verified.get("diff_sha256") != diff_hash):
            raise ValueError("lane identity or exact source binding mismatch")
        if verified.get("review_result") != "PASS":
            raise ValueError("review lane did not pass")
        findings = verified.get("findings")
        if not isinstance(findings, list):
            raise ValueError("review lane omitted findings")
        if any(not isinstance(item, dict) or item.get("severity") in {"P0", "P1", "P2"}
               or item.get("severity") not in {"P3"} for item in findings):
            raise ValueError("unresolved or invalid finding remains")
        model = verified.get("model")
        if not isinstance(model, str) or not model:
            raise ValueError("review model identity missing")
        lanes.append({"provider": expected_provider, "model": model,
                      "reasoning_effort": verified.get("reasoning_effort"),
                      "receipt_sha256": hashlib.sha256(json.dumps(raw, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()})
    if (not _source_stable(root, base, head, diff_hash)
            or full.git(root, "rev-parse", "refs/remotes/origin/main").decode().strip() != target_main):
        raise ValueError("review source changed during validation")
    return {"status": "PASS", "base_sha": base, "head_sha": head,
            "diff_sha256": diff_hash, "manifest_sha256": manifest["manifest_sha256"], "lanes": lanes}


def validate_gate(*, root, base, head, **kwargs):
    """Production gate: only the complete current main candidate scope."""
    target_main = full.git(root, 'rev-parse', 'refs/remotes/origin/main').decode().strip()
    if base != target_main or full.git(root, 'merge-base', base, head).decode().strip() != base:
        raise ValueError('final gate requires the complete current target main scope')
    return _validate_scope_evidence(root=root, base=base, head=head, target_main=target_main, **kwargs)


def validate_premerge_gate(*, root, base, head, plan, scope, repository, **kwargs):
    """Separate simulated gate; it cannot authorize integration against real main."""
    from harness.premerge_plan import validate_plan
    verified_plan = validate_plan(root, plan, repository)
    if scope not in verified_plan['scopes']:
        raise ValueError('unknown premerge scope')
    expected = verified_plan['scopes'][scope]
    if base != expected['base_sha'] or head != expected['head_sha']:
        raise ValueError('premerge exact scope mismatch')
    result = _validate_scope_evidence(root=root, base=base, head=head,
        target_main=verified_plan['actual_main_sha'], repository=repository, **kwargs)
    validate_plan(root, plan, repository)
    return {**result, 'status': 'SIMULATED_PREMERGE_PASS' if expected['simulated'] else 'PASS',
            'premerge_scope': scope, 'premerge_plan_sha256': verified_plan['plan_sha256'],
            'actual_main_sha': verified_plan['actual_main_sha'], 'simulated': expected['simulated'],
            'actual_merge_performed': False, 'production_main_gate_eligible': not expected['simulated']}


def main() -> int:
    """Validate both real lane receipts, private keys and live qualification."""
    import argparse
    import os
    import sys

    scripts = Path(__file__).resolve().parent
    sys.path.insert(0, str(scripts))
    sys.path.insert(0, str(scripts.parent / "src"))
    import deepseek_review as secure
    import reviewer_v2_deepseek as deepseek
    import reviewer_v2_openai as openai
    from harness.model_registry import load_registry
    from harness.model_qualification import validate_qualification_receipt

    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--deepseek-receipt", required=True)
    parser.add_argument("--openai-receipt", required=True)
    parser.add_argument("--deepseek-token-file", required=True)
    parser.add_argument("--deepseek-auth-key-file")
    parser.add_argument("--openai-auth-key-file", required=True)
    parser.add_argument("--deepseek-qualification", required=True)
    parser.add_argument("--openai-qualification", required=True)
    parser.add_argument("--mission-id", default="codex-mission-harness")
    parser.add_argument("--registry")
    parser.add_argument("--premerge-plan", type=Path)
    parser.add_argument("--premerge-scope", choices=("pr2", "v2-after-pr2"))
    args = parser.parse_args()
    try:
        root = Path(args.repo).resolve(strict=True)
        base, head = secure.full_sha(args.base), secure.full_sha(args.head)
        if secure.git(root, "rev-parse", "HEAD").decode().strip() != head:
            raise ValueError("checkout changed from reviewed HEAD")
        if secure.git(root, "status", "--porcelain"):
            raise ValueError("review checkout is dirty")
        registry = load_registry(args.registry)
        independent = registry.role("independent_reviewer")
        final = registry.role("final_reviewer")
        deepseek_key = secure.read_token_file(args.deepseek_token_file, root)
        deepseek_auth_key = secure.read_token_file(
            args.deepseek_auth_key_file or args.deepseek_token_file, root)
        openai_key = secure.read_token_file(args.openai_auth_key_file, root)
        validate_qualification_receipt(Path(args.deepseek_qualification), independent,
                                       auth_key=deepseek_auth_key, role="independent_reviewer",
                                       registry_path=args.registry)
        validate_qualification_receipt(Path(args.openai_qualification), final,
                                       auth_key=openai_key, role="final_reviewer",
                                       registry_path=args.registry)
        deepseek_path = Path(args.deepseek_receipt)
        openai_path = Path(args.openai_receipt)
        receipts = []
        for path in (deepseek_path, openai_path):
            _, fd = secure.open_private_directory(path.parent, root, create=False)
            try:
                receipts.append(json.loads(secure.read_private_artifact(fd, path.name)))
            finally:
                os.close(fd)
        repository = secure.repository_identity(
            secure.git(root, "config", "--get", "remote.origin.url").decode().strip())
        if bool(args.premerge_plan) != bool(args.premerge_scope):
            raise ValueError('premerge plan and scope must be supplied together')
        gate_function = validate_premerge_gate if args.premerge_plan else validate_gate
        gate_options = ({'plan': json.loads(args.premerge_plan.read_bytes()), 'scope': args.premerge_scope}
                        if args.premerge_plan else {})
        proof = gate_function(**gate_options,
            qualification_validators={
                'deepseek': lambda: validate_qualification_receipt(Path(args.deepseek_qualification), independent,
                    auth_key=deepseek_auth_key, role='independent_reviewer', registry_path=args.registry),
                'openai': lambda: validate_qualification_receipt(Path(args.openai_qualification), final,
                    auth_key=openai_key, role='final_reviewer', registry_path=args.registry)},
            root=root, base=base, head=head, deepseek_receipt=receipts[0],
            openai_receipt=receipts[1], mission_id=args.mission_id, repository=repository,
            deepseek_validator=lambda value: deepseek.validate(
                value, base, head, root, deepseek_path, args.mission_id, repository, deepseek_key,
                registry_path=args.registry),
            openai_validator=lambda value: openai.validate(
                value, root=root, base=base, head=head, spec=final,
                auth_key=openai_key, receipt_path=openai_path, mission_id=args.mission_id,
                registry_path=args.registry))
        print(json.dumps(proof, sort_keys=True))
    except Exception:
        print(json.dumps({"status": "BLOCKED_EXTERNAL",
                          "error": "dual review gate has no valid approval evidence"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
