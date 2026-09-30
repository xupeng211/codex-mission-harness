import json
import unittest

from harness.reviewer_v2_contract import bind_findings, parse_chunk, parse_synthesis


FINDING = {"severity": "P1", "title": "Missing check", "evidence": "path.py:14 accepts bad input"}
SOURCE = b"diff --git a/path.py b/path.py\n+if value is None: raise ValueError()\n"
SUMMARY = "The path validates input and preserves all relevant boundaries."


class ReviewerV2ContractTests(unittest.TestCase):
    def setUp(self):
        self.expected = bind_findings([FINDING], "C", 2)
        self.identity = self.expected[0]["finding_id"]

    def response(self, decisions, findings=None):
        return json.dumps({"findings": [] if findings is None else findings,
                           "decisions": decisions, "summary": SUMMARY})

    def decision(self, identity=None, kind="UPHELD", quote=""):
        return {"finding_id": identity or self.identity, "decision": kind,
                "rationale": "The exact source confirms this finding is valid.",
                "source_quote": quote}

    def test_no_blocker(self):
        result = parse_synthesis(self.response([]), [], source=SOURCE)
        self.assertEqual(result["review_result"], "PASS")

    def test_upheld_carries_original_severity_and_content(self):
        result = parse_synthesis(self.response([self.decision()]), self.expected, source=SOURCE)
        self.assertEqual(result["review_result"], "FAIL")
        self.assertEqual(result["findings"], [FINDING])

    def test_dispute_requires_quote_in_exact_source(self):
        decision = self.decision(kind="DISPUTED", quote="if value is None: raise ValueError()")
        self.assertEqual(parse_synthesis(self.response([decision]), self.expected,
                                         source=SOURCE)["review_result"], "PASS")
        with self.assertRaisesRegex(ValueError, "source quote"):
            parse_synthesis(self.response([self.decision(kind="DISPUTED", quote="made up quote")]),
                            self.expected, source=SOURCE)
        with self.assertRaisesRegex(ValueError, "source quote"):
            parse_synthesis(self.response([decision]), self.expected, source=None)

    def test_multiple_blockers_complete(self):
        expected = bind_findings([FINDING, {**FINDING, "severity": "P2"}], "C", 2)
        decisions = [self.decision(item["finding_id"]) for item in expected]
        self.assertEqual(len(parse_synthesis(self.response(decisions), expected,
                                             source=SOURCE)["findings"]), 2)
        for bad in (decisions[:1], decisions + [decisions[0]],
                    [self.decision("C999F999"), decisions[1]]):
            with self.assertRaises(ValueError):
                parse_synthesis(self.response(bad), expected, source=SOURCE)

    def test_invalid_structure_and_chunk(self):
        for raw in ('not JSON', '{}', self.response([])[:-1]):
            with self.assertRaises(ValueError):
                parse_synthesis(raw, self.expected, source=SOURCE)
        self.assertEqual(parse_chunk(json.dumps({"findings": [FINDING]})), [FINDING])
        with self.assertRaises(ValueError):
            parse_chunk(json.dumps({"findings": [FINDING], "review_result": "PASS"}))


if __name__ == "__main__":
    unittest.main()
