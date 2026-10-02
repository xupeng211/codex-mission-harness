"""Frozen ancestor integration plan. Never updates refs or merges a branch."""
from . import full_diff_manifest as full

VERSION = 'cmh-premerge-plan/v1'


def build_plan(root, repository, main, pr2, v2):
    for value in (main, pr2, v2):
        full.read_diff(root, value, value)  # Validate full commit object identities.
    if main == pr2 or pr2 == v2:
        raise ValueError('premerge plan requires distinct pending changes')
    if (full.git(root, 'merge-base', main, pr2).decode().strip() != main or
            full.git(root, 'merge-base', pr2, v2).decode().strip() != pr2):
        raise ValueError('premerge plan requires verified main -> PR2 -> V2 ancestry')
    pr2_tree = full.git(root, 'rev-parse', pr2 + '^{tree}').decode().strip()
    v2_tree = full.git(root, 'rev-parse', v2 + '^{tree}').decode().strip()
    first = full.git(root, 'merge-tree', '--write-tree', main, pr2).decode().strip()
    second = full.git(root, 'merge-tree', '--write-tree', pr2, v2).decode().strip()
    if first != pr2_tree or second != v2_tree:
        raise ValueError('simulated integration differs from candidate trees')
    value = {'version': VERSION, 'repository': repository, 'actual_main_sha': main,
             'pr2_head_sha': pr2, 'v2_head_sha': v2,
             'method': 'ancestor tree integration; prospective fast-forward base, no ref updates',
             'pr2_integration_tree': first, 'v2_integration_tree': second,
             'scopes': {'pr2': {'base_sha': main, 'head_sha': pr2, 'simulated': False},
                        'v2-after-pr2': {'base_sha': pr2, 'head_sha': v2, 'simulated': True}},
             'actual_merge_performed': False,
             'postmerge_requirement': 'Fetch actual main. If base SHA differs from prospective base, '
                                      'regenerate manifest and exact-base review evidence; never rebind a receipt.'}
    value['plan_sha256'] = full.sha256(full.canonical(value))
    return value


def validate_plan(root, value, repository):
    if not isinstance(value, dict) or value.get('version') != VERSION:
        raise ValueError('invalid premerge plan')
    actual_main = full.git(root, 'rev-parse', 'refs/remotes/origin/main').decode().strip()
    expected = build_plan(root, repository, actual_main, value['pr2_head_sha'], value['v2_head_sha'])
    if value != expected:
        raise ValueError('premerge plan changed or actual main advanced')
    return expected
