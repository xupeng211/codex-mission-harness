import importlib.util
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

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
    def test_claude_launcher_resolution_excludes_relative_and_reviewed_tree_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            trusted_bin = Path(tmp) / "trusted-bin"
            root.mkdir(); trusted_bin.mkdir()
            parent_launcher = Path(tmp) / "claude"
            parent_launcher.write_text("#!/bin/sh\nexit 98\n")
            parent_launcher.chmod(0o755)
            repo_launcher = root / "claude"
            repo_launcher.write_text("#!/bin/sh\nexit 99\n")
            repo_launcher.chmod(0o755)
            trusted_launcher = trusted_bin / "claude"
            trusted_launcher.write_text("#!/bin/sh\nexit 0\n")
            trusted_launcher.chmod(0o755)
            supplied_path = os.pathsep.join(["", str(root), str(Path(tmp)), ".", str(trusted_bin), "/usr/bin"])
            executable, safe_path = review.resolve_claude_launcher(root, supplied_path)
            self.assertEqual(executable, str(trusted_launcher.resolve()))
            self.assertNotIn(str(root), safe_path.split(os.pathsep))
            self.assertNotIn(str(Path(tmp).resolve()), safe_path.split(os.pathsep))
            self.assertNotIn(".", safe_path.split(os.pathsep))
            self.assertFalse(safe_path.startswith(os.pathsep))
            self.assertFalse(safe_path.endswith(os.pathsep))

    def test_claude_launcher_resolution_fails_when_only_repo_binary_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            launcher = root / "claude"
            launcher.write_text("#!/bin/sh\nexit 0\n")
            launcher.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "trusted absolute Claude Code launcher"):
                review.resolve_claude_launcher(root, str(root))
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
    def test_durable_artifact_result_must_match_receipt_chunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            artifact = evidence / "chunk-000.json"
            artifact.write_text(json.dumps({"review_result": "PASS", "findings": [
                {"severity": "P3", "title": "artifact finding", "evidence": "durable"},
            ]}))
            value = receipt()
            value["chunks"][0]["output_sha256"] = review.sha(artifact)
            source = b"fixture diff\n"
            value["diff_sha256"] = review.digest(source)
            manifest = {
                "version": "cmh-deepseek-chunks/v1", "base_sha": BASE,
                "head_sha": HEAD, "diff_sha256": value["diff_sha256"],
                "chunks": [{key: value["chunks"][0][key]
                            for key in ("index", "start", "end", "sha256")}],
            }
            value["manifest_sha256"] = review.digest(review.canon(manifest))
            payload = {key: item for key, item in value.items() if key != "integrity_sha256"}
            value["integrity_sha256"] = review.digest(review.canon(payload))
            with patch.object(review, "git", return_value=source), \
                    self.assertRaisesRegex(ValueError, "chunk result does not match"):
                review.validate(value, BASE, HEAD, root=evidence,
                                receipt_path=evidence / "receipt.json")
    def test_non_utf8_chunk_is_embedded_as_exact_base64(self):
        source = b"diff --git a/x b/x\n+\xff\x00\n"
        chunk = {"index": 0, "start": 0, "end": len(source), "sha256": review.digest(source)}
        rendered = review.prompt(BASE, HEAD, "d" * 64, "e" * 64, chunk, source)
        self.assertIn("BASE64-ENCODED EXACT DIFF BYTES:", rendered)
        self.assertIn("ZGlmZiAtLWdpdCBhL3ggYi94Civ/AAo=", rendered)
        self.assertNotIn("\ufffd", rendered)
    def test_reviewer_result_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "invalid reviewer output"):
            review.reviewer_result('{"review_result":"PASS","findings":"not-a-list"}')
        with self.assertRaisesRegex(ValueError, "invalid reviewer output"):
            review.reviewer_result('{"review_result":"PASS","findings":[{"severity":"CRITICAL","title":"x","evidence":"y"}]}')
        with self.assertRaisesRegex(ValueError, "reviewer verdict mismatch"):
            review.reviewer_result('{"review_result":"PASS","findings":[{"severity":"P1","title":"x","evidence":"y"}]}')
    def test_mission_and_repository_binding_are_required_when_expected(self):
        value = receipt(repository="git@example/repo", mission_id="mission-a")
        self.assertEqual(review.validate(value, BASE, HEAD, mission_id="mission-a",
                                         repository="git@example/repo")["review_result"], "PASS")
        with self.assertRaisesRegex(ValueError, "mission binding"):
            review.validate(value, BASE, HEAD, mission_id="mission-b",
                            repository="git@example/repo")
        with self.assertRaisesRegex(ValueError, "repository binding"):
            review.validate(value, BASE, HEAD, mission_id="mission-a",
                            repository="git@example/other")
    def test_run_scoped_artifact_paths_cannot_overwrite_prior_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "harness-test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin",
                            "git@github.com:fixture/repo.git"], check=True)
            source = repo / "tracked.txt"
            source.write_text("base\n")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            source.write_text("head\n")
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "head"], check=True)
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            token_file = root / "review-token"
            token_file.write_text("unit-test-token")
            evidence = root / "evidence"
            args = Namespace(repo=str(repo), base=base, head=head, mission_id="fixture",
                             evidence=str(evidence), token_file=str(token_file), timeout=1)
            raw = json.dumps({"review_result": "PASS", "findings": []})
            completed = subprocess.CompletedProcess(["claude"], 0, raw, "")
            invocations = []

            def capture_invocation(command, prompt_text, env, timeout):
                invocations.append((command, env))
                return completed

            with patch.object(review, "resolve_claude_launcher",
                              return_value=("/trusted/bin/claude", "/trusted/bin:/usr/bin")), \
                    patch.object(review, "invoke_reviewer", side_effect=capture_invocation), \
                    contextlib.redirect_stdout(io.StringIO()) as captured:
                review.run(args)
                first_result = json.loads(captured.getvalue())
                first_receipt = Path(first_result["receipt"])
                first_chunk = first_receipt.parent / "chunk-000.json"
                first_receipt_before = first_receipt.read_bytes()
                first_chunk_before = first_chunk.read_bytes()
                captured.seek(0); captured.truncate(0)
                review.run(args)
                second_result = json.loads(captured.getvalue())

            self.assertEqual(len(invocations), 2)
            for command, env in invocations:
                self.assertEqual(command[0], "/trusted/bin/claude")
                self.assertEqual(env["PATH"], "/trusted/bin:/usr/bin")
            second_receipt = Path(second_result["receipt"])
            self.assertNotEqual(first_receipt.parent, second_receipt.parent)
            self.assertTrue(first_receipt.is_file())
            self.assertTrue(second_receipt.is_file())
            self.assertIn(head[:12], first_receipt.name)
            second_chunk = second_receipt.parent / "chunk-000.json"
            self.assertNotEqual(first_chunk, second_chunk)
            self.assertEqual(first_receipt.read_bytes(), first_receipt_before)
            self.assertEqual(first_chunk.read_bytes(), first_chunk_before)
            for receipt_path in (first_receipt, second_receipt):
                self.assertEqual(
                    review.validate(json.loads(receipt_path.read_text()), base, head, repo,
                                    receipt_path, "fixture", "git@github.com:fixture/repo.git")["review_result"],
                    "PASS",
                )
