"""Prospective integration is explicit and cannot bypass the production gate."""
import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from harness import full_diff_manifest as full
from harness.premerge_plan import build_plan, validate_plan
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_gate as gate


class PremergePlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q'); self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.heads = []
        for label in ('main', 'pr2', 'v2'):
            (self.root / label).write_text(label)
            self.git('add', '.'); self.git('commit', '-qm', label)
            self.heads.append(self.git('rev-parse', 'HEAD'))
        self.main, self.pr2, self.v2 = self.heads
        self.git('update-ref', 'refs/remotes/origin/main', self.main)
        self.repository = 'ssh://github.com/example/harness.git'
        self.plan = build_plan(self.root, self.repository, *self.heads)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args]).decode().strip()

    def test_ancestor_integration_is_deterministic_without_ref_updates(self):
        before = self.git('show-ref')
        self.assertEqual(self.plan, build_plan(self.root, self.repository, *self.heads))
        self.assertEqual(before, self.git('show-ref'))
        self.assertEqual(self.plan['v2_integration_tree'], self.git('rev-parse', self.v2+'^{tree}'))
        self.assertFalse(self.plan['actual_merge_performed'])

    def test_frozen_plan_validates(self):
        self.assertEqual(validate_plan(self.root, self.plan, self.repository), self.plan)

    def test_mutations_and_wrong_repository_rejected(self):
        for field in self.plan:
            changed = copy.deepcopy(self.plan); changed[field] = 'wrong'
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                validate_plan(self.root, changed, self.repository)
        with self.assertRaises(ValueError): validate_plan(self.root, self.plan, 'other')

    def test_advanced_main_invalidates_plan(self):
        self.git('update-ref', 'refs/remotes/origin/main', self.pr2)
        with self.assertRaises(ValueError): validate_plan(self.root, self.plan, self.repository)

    def test_divergent_history_cannot_claim_safe_integration(self):
        self.git('checkout', '-q', '--detach', self.main)
        (self.root / 'fork').write_text('fork'); self.git('add', '.'); self.git('commit', '-qm', 'fork')
        fork = self.git('rev-parse', 'HEAD')
        with self.assertRaises(ValueError): build_plan(self.root, self.repository, self.main, self.pr2, fork)

    def test_production_gate_still_rejects_prospective_base(self):
        with self.assertRaisesRegex(ValueError, 'complete current target main'):
            gate.validate_gate(root=self.root, base=self.pr2, head=self.v2)

    def test_simulation_status_cannot_be_confused_with_real_main_pass(self):
        # Only the shared evidence checker is stubbed here; production artifact checks
        # are covered by full-diff end-to-end tests.
        with patch.object(gate, '_validate_scope_evidence', return_value={'status': 'PASS'}) as checker:
            result = gate.validate_premerge_gate(root=self.root, base=self.pr2, head=self.v2,
                plan=self.plan, scope='v2-after-pr2', repository=self.repository)
        self.assertEqual(result['status'], 'SIMULATED_PREMERGE_PASS')
        self.assertTrue(result['simulated']); self.assertFalse(result['production_main_gate_eligible'])
        self.assertFalse(result['actual_merge_performed'])
        self.assertEqual(checker.call_args.kwargs['target_main'], self.main)

    def test_wrong_scope_cannot_reuse_receipts(self):
        for scope, base, head in [('pr2', self.pr2, self.v2), ('v2-after-pr2', self.main, self.v2),
                                 ('unknown', self.main, self.pr2)]:
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                gate.validate_premerge_gate(root=self.root, base=base, head=head,
                    plan=self.plan, scope=scope, repository=self.repository)

    def test_plan_rechecked_after_evidence_validation(self):
        def advance(**kwargs):
            self.git('update-ref', 'refs/remotes/origin/main', self.pr2)
            return {'status':'PASS'}
        with patch.object(gate, '_validate_scope_evidence', side_effect=advance):
            with self.assertRaises(ValueError):
                gate.validate_premerge_gate(root=self.root, base=self.pr2, head=self.v2,
                    plan=self.plan, scope='v2-after-pr2', repository=self.repository)


if __name__ == '__main__': unittest.main()
