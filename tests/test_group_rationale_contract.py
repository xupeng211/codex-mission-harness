"""Offline regression for the persisted group-000 empty-UPHELD failure."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reviewer_v2_deepseek as ds
import reviewer_v2_openai as oa
from harness import reviewer_v2_contract as contract
from direct_deepseek_fixture import envelope


class GroupRationaleContractTests(unittest.TestCase):
    def setUp(self):
        findings = [{'severity': 'P1', 'title': 'Missing validation',
                     'evidence': 'source.py accepts an unchecked value'} for _ in range(12)]
        self.expected = contract.bind_findings(findings, 'C', 0)
        self.value = {'findings': [], 'summary': 'The supplied source still lacks the required validation.',
                      'decisions': [{'finding_id': f['finding_id'], 'decision': 'UPHELD',
                                     'rationale': 'The unchecked input still bypasses the required validation.',
                                     'source_id': '', 'source_quote': ''} for f in self.expected]}

    def parse(self, value):
        return contract.parse_synthesis(json.dumps(value), self.expected, source=b'source',
                                        structured_evidence=True)

    def test_real_failure_shape_is_rejected_without_repair_or_source_binding(self):
        for index in (2, 4, 5, 6, 7, 8, 11):
            self.value['decisions'][index]['rationale'] = ''
        original = copy.deepcopy(self.value)
        with patch.object(contract, 'validate_source_binding', wraps=contract.validate_source_binding) as binding:
            with self.assertRaisesRegex(ValueError, 'disposition'):
                self.parse(self.value)
            # The first two valid decisions may bind; the first invalid one must not.
            self.assertEqual(binding.call_count, 2)
        self.assertEqual(self.value, original)
        with self.assertRaises(ValueError):
            oa._result(json.dumps(self.value).encode(), group=True)

    def test_direct_envelope_rejects_empty_rationale_before_parser(self):
        self.value['decisions'][0]['rationale'] = ''
        raw = envelope(self.value, 'offline group prompt', ds.SYNTHESIS_SCHEMA).decode()
        state = {'stage': 'group'}
        with patch.object(ds, 'parse_synthesis') as parser:
            with self.assertRaises(ds.ReviewStageFailure):
                ds._parse_stage(raw, parser, state, prompt='offline group prompt')
            parser.assert_not_called()

    def test_every_canonical_disposition_requires_minimum_rationale(self):
        for kind in ('UPHELD', 'DISPUTED'):
            for rationale in ('', 'x' * 23, ' ' * 24):
                with self.subTest(kind=kind, rationale=rationale):
                    value = copy.deepcopy(self.value)
                    value['decisions'][0].update(decision=kind, rationale=rationale)
                    with patch.object(contract, 'validate_source_binding') as binding:
                        with self.assertRaises(ValueError):
                            self.parse(value)
                        binding.assert_not_called()
                    with self.assertRaises(ValueError):
                        oa._result(json.dumps(value).encode(), group=True)

    def test_substantive_upheld_is_valid_and_preserves_finding(self):
        result = self.parse(self.value)
        self.assertEqual(len(result['findings']), 12)
        self.assertEqual(oa._result(json.dumps(self.value).encode(), group=True), self.value)

    def test_noncanonical_dispositions_are_not_added(self):
        for kind in ('REJECTED', 'MODIFIED'):
            self.value['decisions'][0]['decision'] = kind
            with self.assertRaises(ValueError):
                self.parse(self.value)

    def test_all_model_facing_decision_prompts_explicitly_require_upheld_rationale(self):
        for instruction in (ds.DECISION_RATIONALE_INSTRUCTION, oa.DECISION_RATIONALE_INSTRUCTION):
            self.assertIn('including UPHELD and DISPUTED', instruction)
            self.assertIn('at least 24 characters after trimming whitespace', instruction)
            self.assertIn('not rationale', instruction)
            example = json.loads(instruction[instruction.index('{'):instruction.rindex('}') + 1])
            self.assertEqual(example['decision'], 'UPHELD')
            self.assertGreaterEqual(len(example['rationale'].strip()), 24)
        prompt = oa._prompt('group', base='a', head='b', diff=b'source', ids=self.expected)
        self.assertIn(oa.DECISION_RATIONALE_INSTRUCTION, prompt)
        source = Path(ds.__file__).read_text()
        self.assertEqual(source.count('+ DECISION_RATIONALE_INSTRUCTION'), 2)
        self.assertEqual(ds.DECISION_SCHEMA['properties']['rationale']['minLength'], 24)
