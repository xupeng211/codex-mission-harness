"""Offline supplied-claim contract fixtures, not live model certification."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_deepseek as ds
import reviewer_v2_openai as oa
from harness import model_qualification as q
from harness.model_registry import load_registry
from harness.reviewer_v2_contract import (SUPPLIED_CLAIM_GUIDANCE, bind_findings,
                                          parse_synthesis, sha256)


class SuppliedClaimGuidanceTests(unittest.TestCase):
    def response(self, finding, source, disposition, rationale, quote=''):
        expected = bind_findings([finding], 'C', 0)
        value = {'findings': [], 'summary': 'The decision follows the supplied bound source and applicable context.',
                 'decisions': [{'finding_id': expected[0]['finding_id'], 'decision': disposition,
                     'rationale': rationale, 'source_quote': quote,
                     'source_id': sha256(source) if disposition == 'DISPUTED' else ''}]}
        return parse_synthesis(json.dumps(value), expected, source=source, structured_evidence=True)

    def test_supported_invariant_can_be_upheld_without_source_comment(self):
        source = b'def records(values):\n    return sorted(values)\n'
        finding = {'severity': 'P1', 'title': 'Record order contract violated',
                   'evidence': 'Bound interface spec requires original order; sorting changes caller order.'}
        result = self.response(finding, source, 'UPHELD',
            'The bound interface specification requires original order but this implementation sorts records.')
        self.assertEqual(result['review_result'], 'FAIL')
        self.assertIn('Do not DISPUTE solely because source lacks', SUPPLIED_CLAIM_GUIDANCE)

    def test_unsupported_external_requirement_can_be_disputed(self):
        source = b'def records(values):\n    return list(values)\n'
        finding = {'severity': 'P2', 'title': 'Missing encryption',
                   'evidence': 'Invented requirement: records must encrypt all values.'}
        result = self.response(finding, source, 'DISPUTED',
            'The available bound interface concerns preserving records; no evidence establishes an encryption requirement.',
            'return list(values)')
        self.assertEqual(result['review_result'], 'PASS')
        self.assertIn('Unsupported invented external requirements', SUPPLIED_CLAIM_GUIDANCE)

    def test_source_conflict_can_be_disputed(self):
        source = b'def records(values):\n    return list(values)\n'
        finding = {'severity': 'P1', 'title': 'Records are sorted', 'evidence': 'Claimed sorting changes order.'}
        result = self.response(finding, source, 'DISPUTED',
            'The source copies the supplied sequence without sorting, contradicting the claimed order change.',
            'return list(values)')
        self.assertEqual(result['review_result'], 'PASS')

    def test_vague_unverifiable_claim_can_be_disputed(self):
        source = b'def records(values):\n    return list(values)\n'
        finding = {'severity': 'P2', 'title': 'Something is unsafe', 'evidence': 'Unspecified problem.'}
        result = self.response(finding, source, 'DISPUTED',
            'This claim provides no verifiable behavior, triggering condition or applicable safety invariant.',
            'return list(values)')
        self.assertEqual(result['review_result'], 'PASS')
        self.assertIn('vague unverifiable claims', SUPPLIED_CLAIM_GUIDANCE)

    def test_prompts_keep_both_evidence_and_nonautomatic_truth_boundaries(self):
        prompts = [ds._prompt_head('a', 'b', 'c', 'group'),
                   oa._prompt('group', base='a', head='b', diff=b'source', ids=[]),
                   oa._synthesis_prompt([], 'a', 'b')]
        prompts += [q.qualification_prompt(case) for case in q.CASES]
        for prompt in prompts:
            self.assertIn(SUPPLIED_CLAIM_GUIDANCE, prompt)
            self.assertIn('Do not UPHOLD solely because', prompt)
            self.assertIn('contract\'s applicability', prompt)
        for case in q.CASES:
            prompt = q.qualification_prompt(case)
            self.assertIn('not truth of the claimed defect', prompt)
            self.assertIn('does not authorize inventing additional external requirements', prompt)

    def test_all_original_qualification_outcomes_remain_deterministic(self):
        def invoke(spec, prompt):
            case = next(case for case in q.CASES if q.qualification_prompt(case) == prompt)
            expected = q.expected_findings(case)
            decisions = [{'finding_id': expected[int(key[1:])-1]['finding_id'], 'decision': kind,
                          'rationale': 'The supplied behavioral claim is checked against the actual implementation.',
                          'source_quote': '    return a + b' if kind == 'DISPUTED' else ''}
                         for key, kind in case.expected.items()]
            return json.dumps({'findings': [], 'decisions': decisions,
                               'summary': 'The canonical fixture contract and actual implementation were compared.'})
        result = q.evaluate_cases(load_registry().role('independent_reviewer'), invoke)
        self.assertEqual(result.cases_failed, ())
        self.assertEqual(result.cases_passed, tuple(case.name for case in q.CASES))
        self.assertEqual(q.CASES[0].source, 'def total(a, b):\n    return a + b\n')
        self.assertEqual(q.CASES[1].expected, {'F1': 'UPHELD'})
        self.assertEqual(q.CASES[2].expected, {'F1': 'DISPUTED'})
