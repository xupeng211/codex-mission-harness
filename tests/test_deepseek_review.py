import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("deepseek_review", ROOT / "scripts" / "deepseek_review.py")
review = importlib.util.module_from_spec(spec); spec.loader.exec_module(review)

BASE, HEAD = "a" * 40, "b" * 40

def receipt(**overrides):
    source = b"fixture diff\n"
    value = {"version": review.VERSION, "repository": "fixture", "mission_id": "fixture", "base_sha": BASE, "head_sha": HEAD,
             "diff_sha256": "d" * 64, "manifest_sha256": "e" * 64,
             "chunks": [{"index": 0, "start": 0, "end": len(source), "sha256": review.digest(source),
                         "output_sha256": "f" * 64, "result": {"review_result": "PASS", "findings": []}}],
             "provider": "deepseek", "model": review.MODEL, "command_sha256": "c" * 64,
             "review_result": "PASS", "findings": []}
    value.update(overrides); value["integrity_sha256"] = review.digest(review.canon(value)); return value

class DeepSeekReceiptTest(unittest.TestCase):
    def test_deterministic_chunking_and_full_coverage(self):
        diff = (b"x\n" * 20000)
        first, second = review.chunks(diff), review.chunks(diff)
        self.assertEqual(first, second); self.assertEqual(first[0]["start"], 0); self.assertEqual(first[-1]["end"], len(diff))
        self.assertEqual(b"".join(diff[c["start"]:c["end"]] for c in first), diff)
    def test_valid_exact_receipt(self): self.assertEqual(review.validate(receipt(), BASE, HEAD)["review_result"], "PASS")
    def test_wrong_head_and_base_rejected(self):
        with self.assertRaises(ValueError): review.validate(receipt(), BASE, "c" * 40)
        with self.assertRaises(ValueError): review.validate(receipt(), "c" * 40, HEAD)
    def test_duplicate_or_missing_chunks_rejected(self):
        with self.assertRaises(ValueError): review.validate(receipt(chunks=[]), BASE, HEAD)
        with self.assertRaises(ValueError): review.validate(receipt(chunks=[{"index": 1, "result": {"review_result": "PASS"}}]), BASE, HEAD)
    def test_gapped_or_corrupt_chunk_coverage_rejected(self):
        bad = receipt(); bad["chunks"][0]["start"] = 1
        payload = {key: value for key, value in bad.items() if key != "integrity_sha256"}
        bad["integrity_sha256"] = review.digest(review.canon(payload))
        with self.assertRaises(ValueError): review.validate(bad, BASE, HEAD)
    def test_chunk_and_aggregate_findings_must_match(self):
        finding = {"severity": "P3", "title": "x", "evidence": "y"}
        with self.assertRaises(ValueError): review.validate(receipt(findings=[finding]), BASE, HEAD)
    def test_corruption_and_provenance_rejected(self):
        bad = receipt(); bad["provider"] = "fake"
        with self.assertRaises(ValueError): review.validate(bad, BASE, HEAD)
        bad = receipt(); bad["integrity_sha256"] = "0" * 64
        with self.assertRaises(ValueError): review.validate(bad, BASE, HEAD)
    def test_blocking_finding_requires_fail(self):
        finding = {"severity": "P1", "title": "x", "evidence": "y"}
        with self.assertRaises(ValueError): review.validate(receipt(findings=[finding]), BASE, HEAD)
        chunks = receipt()["chunks"]; chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        self.assertEqual(review.validate(receipt(review_result="FAIL", findings=[finding], chunks=chunks), BASE, HEAD)["review_result"], "FAIL")
    def test_p3_is_nonblocking(self):
        finding = {"severity": "P3", "title": "x", "evidence": "y"}
        chunks = receipt()["chunks"]; chunks[0]["result"] = {"review_result": "PASS", "findings": [finding]}
        self.assertEqual(review.validate(receipt(findings=[finding], chunks=chunks), BASE, HEAD)["review_result"], "PASS")
