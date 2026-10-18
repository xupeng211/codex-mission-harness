"""Offline prompt/acceptance regressions; these do not qualify a live model."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_deepseek as ds
import reviewer_v2_openai as oa
from harness import model_qualification as q
from harness.model_registry import load_registry
from harness.reviewer_v2_contract import FINDING_GUIDANCE, parse_chunk


class FindingGuidanceTests(unittest.TestCase):
    def test_guidance_distinguishes_optional_changes_from_demonstrated_risk(self):
        for text in ('including P3', 'triggering condition', 'consequence',
                     'Do not invent an input restriction', 'suggestions, not formal findings',
                     'never suppress a real defect', 'incorrect charge', 'billing error'):
            self.assertIn(text, FINDING_GUIDANCE)
        for text in ('documentation completeness', 'optional type hints',
                     'defensive validation without a demonstrated defect/risk'):
            self.assertIn(text, FINDING_GUIDANCE)

    def test_all_review_and_qualification_prompts_receive_same_guidance(self):
        for case in q.CASES:
            self.assertIn(FINDING_GUIDANCE, q.qualification_prompt(case))
        self.assertIn(FINDING_GUIDANCE, ds._prompt_head('a', 'b', 'c', 'group'))
        self.assertIn(FINDING_GUIDANCE, oa._prompt('chunk', base='a', head='b', diff=b'source'))
        self.assertIn(FINDING_GUIDANCE, oa._prompt('group', base='a', head='b', diff=b'source', ids=[]))
        self.assertIn(FINDING_GUIDANCE, oa._synthesis_prompt([], 'a', 'b'))

    def test_real_clean_false_positives_still_fail_qualification(self):
        for title, evidence in (
                ('No input type validation in total()', 'Generic addition without a required input restriction.'),
                ('Missing docstring and type hints', 'Generic helper lacks optional documentation and annotations.')):
            def invoke(spec, prompt):
                return json.dumps({'decisions': [], 'findings': [{'severity': 'P3',
                    'title': title, 'evidence': evidence}], 'summary': 'Optional improvement with no demonstrated concrete defect.'})
            result = q.evaluate_cases(load_registry().role('independent_reviewer'), invoke)
            self.assertIn('clean', result.cases_failed)

    def test_clean_expectation_unchanged_and_empty_findings_pass_clean(self):
        clean = q.CASES[0]
        self.assertEqual(clean.source, 'def total(a, b):\n    return a + b\n')
        self.assertEqual(clean.findings, ())
        self.assertEqual(clean.expected, {})
        result = q.evaluate_cases(load_registry().role('independent_reviewer'),
            lambda spec, prompt: json.dumps({'decisions': [], 'findings': [],
                'summary': 'No concrete correctness or contract issue is present.'}))
        self.assertIn('clean', result.cases_passed)

    def test_true_type_and_documentation_defects_are_not_filtered_at_any_severity(self):
        for severity in ('P1', 'P2', 'P3'):
            for title, evidence in (
                    ('Incorrect payment arithmetic', 'The declared numeric-payment API concatenates string amounts, charging 1020 instead of 30.'),
                    ('Timeout unit contract violation', 'The public API promises milliseconds but passes the value as seconds, stalling production jobs.')):
                finding = {'severity': severity, 'title': title, 'evidence': evidence}
                raw = json.dumps({'findings': [finding]})
                self.assertEqual(parse_chunk(raw), [finding])
                self.assertEqual(oa._result(raw.encode())['findings'], [finding])

    def test_group_rationale_contract_remains_explicit(self):
        for instruction in (ds.DECISION_RATIONALE_INSTRUCTION, oa.DECISION_RATIONALE_INSTRUCTION):
            self.assertIn('including UPHELD and DISPUTED', instruction)
            self.assertIn('at least 24 characters', instruction)
        self.assertEqual(ds.DECISION_SCHEMA['properties']['rationale']['minLength'], 24)
