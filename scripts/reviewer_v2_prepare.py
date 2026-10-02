#!/usr/bin/env python3
"""Prepare and independently validate full Git scope. Never calls a provider."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from harness import full_diff_manifest as full
import deepseek_review as secure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='.')
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    root = Path(args.repo).resolve(strict=True)
    base, head = secure.full_sha(args.base), secure.full_sha(args.head)
    repository = secure.repository_identity(full.git(root, 'config', '--get', 'remote.origin.url').decode().strip())
    diff, manifest = full.build_manifest(root, base, head, repository)
    proof = full.validate_manifest(root, manifest, repository, base, head)
    tasks = full.review_tasks(diff, manifest)
    full.validate_tasks(diff, manifest, tasks)
    proof.update(base_sha=base, head_sha=head, full_diff_bytes=len(diff),
                 changed_file_count=manifest['changed_file_count'], chunking_policy=full.CHUNKING,
                 task_assignments_sha256=full.sha256(full.canonical(tasks)),
                 model_requests=0, REVIEWER_V2='NOT_QUALIFIED', scope='explicit base..head; caller must justify target base')
    evidence, fd = secure.open_private_directory(Path(args.evidence).resolve(), root)
    try:
        import os
        import uuid
        for name, value in [('canonical-diff.patch', diff), ('canonical-diff-manifest.json', full.canonical(manifest)),
                            ('coverage-proof.json', full.canonical(proof)), ('task-assignments.json', full.canonical(tasks))]:
            secure.write_private_artifact(fd, name, value, uuid.uuid4().hex)
        for c, task in zip(manifest['chunks'], tasks):
            secure.write_private_artifact(fd, f"chunk-{c['index']:03d}.patch", diff[c['start']:c['end']], uuid.uuid4().hex)
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(proof, sort_keys=True))
    return 0 if proof['review_ready'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
