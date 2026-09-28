import importlib.util
import contextlib
import io
import json
import os
import stat
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
TEST_SECRET = "unit-test-review-secret"

_validate = review.validate
def _validated(*args, **kwargs):
    kwargs.setdefault("secret", TEST_SECRET)
    return _validate(*args, **kwargs)
review.validate = _validated

def receipt(**overrides):
    source = b"fixture diff\n"
    aggregate = {"review_result": "PASS", "findings": [], "dispositions": []}
    value = {"version": review.VERSION, "repository": "fixture", "mission_id": "fixture", "base_sha": BASE, "head_sha": HEAD,
             "diff_sha256": "d" * 64, "manifest_sha256": "e" * 64,
             "chunks": [{"index": 0, "start": 0, "end": len(source), "sha256": review.digest(source),
                         "output_sha256": "f" * 64, "result": {"review_result": "PASS", "findings": []}}],
             "chunk_findings": [], "aggregate_result": aggregate,
             "aggregate_output_sha256": "g" * 64,
             "provider": "deepseek", "model": review.MODEL, "command_sha256": "c" * 64,
             "review_result": "PASS", "findings": []}
    value.update(overrides); value["integrity_sha256"] = review.digest(review.canon(value)); value["auth_hmac_sha256"] = review.auth_digest(value, TEST_SECRET); return value

def disposition_for(item, *, decision="DISPUTED", chunk_index=0, finding_index=0):
    rationale = (
        "The complete diff confirms this concern against the exact reviewed code."
        if decision == "UPHELD" else
        "The complete diff disproves this localized concern with concrete evidence."
    )
    return {
        "chunk_index": chunk_index,
        "finding_index": finding_index,
        "source_severity": item["severity"],
        "finding_sha256": review.digest(review.canon(item)),
        "decision": decision,
        "rationale": rationale,
    }


def run_fixture(root, *, large_diff=False):
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
    source.write_text(("x" * 74 + "\n") * 7000 if large_diff else "head\n")
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "head"], check=True)
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    token_file = root / "review-token"
    token_file.write_text(TEST_SECRET)
    token_file.chmod(0o600)
    args = Namespace(repo=str(repo), base=base, head=head, mission_id="fixture",
                     evidence=str(root / "evidence"), token_file=str(token_file), timeout=1)
    return args, Path(args.evidence)

class DeepSeekReceiptTest(unittest.TestCase):
    def test_chunk_and_aggregate_schemas_have_separate_disposition_contracts(self):
        self.assertNotIn("dispositions", review.CHUNK_SCHEMA["properties"])
        self.assertIn("dispositions", review.AGGREGATE_SCHEMA["properties"])
        self.assertIn("dispositions", review.AGGREGATE_SCHEMA["required"])

    def test_claude_launcher_resolution_excludes_relative_and_reviewed_tree_paths(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp) / "repo"
            trusted_bin = Path(tmp) / "trusted-bin"
            root.mkdir(); trusted_bin.mkdir(); trusted_bin.chmod(0o755)
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

    def test_claude_launcher_resolution_rejects_writable_path_and_executable(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root = Path(tmp) / "repo"
            untrusted_bin = Path(tmp) / "group-writable-bin"
            root.mkdir(); untrusted_bin.mkdir(); untrusted_bin.chmod(0o770)
            untrusted_launcher = untrusted_bin / "claude"
            untrusted_launcher.write_text("#!/bin/sh\nexit 0\n")
            untrusted_launcher.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "trusted absolute Claude Code launcher"):
                review.resolve_claude_launcher(root, str(untrusted_bin))

            trusted_bin = Path(tmp) / "trusted-bin"
            trusted_bin.mkdir(); trusted_bin.chmod(0o755)
            writable_launcher = trusted_bin / "claude"
            writable_launcher.write_text("#!/bin/sh\nexit 0\n")
            writable_launcher.chmod(0o775)
            with self.assertRaisesRegex(ValueError, "Claude Code launcher is not trusted"):
                review.resolve_claude_launcher(root, str(trusted_bin))

    def test_claude_launcher_resolution_fails_when_only_repo_binary_exists(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
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

    def test_review_authentication_is_required_and_secret_bound(self):
        value = receipt()
        with self.assertRaisesRegex(ValueError, "authentication"):
            _validate(value, BASE, HEAD, secret=None)
        with self.assertRaisesRegex(ValueError, "authentication"):
            _validate(value, BASE, HEAD, secret="wrong-secret")
        self.assertEqual(_validate(value, BASE, HEAD, secret=TEST_SECRET)["review_result"], "PASS")
    def test_blocking_finding_requires_fail(self):
        finding = {"severity": "P1", "title": "x", "evidence": "y"}
        with self.assertRaises(ValueError): review.validate(receipt(findings=[finding]), BASE, HEAD)
        chunks = receipt()["chunks"]; chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(review_result="FAIL", findings=[finding], chunks=chunks,
                        chunk_findings=[finding],
                        aggregate_result={"review_result": "FAIL", "findings": [finding],
                                          "dispositions": [disposition_for(finding, decision="UPHELD")]})
        self.assertEqual(review.validate(value, BASE, HEAD)["review_result"], "FAIL")

    def test_v2_deepseek_receipt_is_stale_under_disposition_policy(self):
        with self.assertRaisesRegex(ValueError, "exact-head binding"):
            review.validate(receipt(version="cmh-deepseek-review/v2"), BASE, HEAD)

    def test_v3_deepseek_receipt_is_stale_under_credential_free_repository_policy(self):
        with self.assertRaisesRegex(ValueError, "exact-head binding"):
            review.validate(receipt(version="cmh-deepseek-review/v3"), BASE, HEAD)

    def test_repository_identity_removes_remote_credentials_and_query_data(self):
        cases = {
            "https://review-user:secret@github.com/owner/repo.git?access_token=secret#fragment":
                "https://github.com/owner/repo.git",
            "ssh://review-user:secret@github.com/owner/repo.git": "ssh://github.com/owner/repo.git",
            "git@github.com:owner/repo.git": "ssh://github.com/owner/repo.git",
        }
        for remote, expected in cases.items():
            with self.subTest(remote=remote):
                identity = review.repository_identity(remote)
                self.assertEqual(identity, expected)
                self.assertNotIn("secret", identity)

    def test_receipt_rejects_noncanonical_credential_bearing_repository_identity(self):
        with self.assertRaisesRegex(ValueError, "repository identity is not canonical"):
            review.validate(
                receipt(repository="https://review-user:secret@github.com/owner/repo.git"),
                BASE, HEAD,
            )

    def test_complete_diff_can_dispute_blocker_with_hash_bound_rationale(self):
        finding = {"severity": "P2", "title": "localized concern", "evidence": "chunk evidence"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(
            chunks=chunks,
            chunk_findings=[finding],
            aggregate_result={
                "review_result": "PASS", "findings": [],
                "dispositions": [disposition_for(finding)],
            },
            review_result="PASS", findings=[],
        )
        self.assertEqual(review.validate(value, BASE, HEAD)["review_result"], "PASS")

    def test_blocking_chunk_finding_cannot_be_silently_dropped(self):
        finding = {"severity": "P1", "title": "must be accounted for", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(
            chunks=chunks, chunk_findings=[finding],
            aggregate_result={"review_result": "PASS", "findings": [], "dispositions": []},
            review_result="PASS", findings=[],
        )
        with self.assertRaisesRegex(ValueError, "omitted a blocking chunk finding disposition"):
            review.validate(value, BASE, HEAD)

    def test_disposition_must_bind_exact_blocking_chunk_finding(self):
        finding = {"severity": "P2", "title": "localized concern", "evidence": "chunk evidence"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        bad_disposition = disposition_for(finding)
        bad_disposition["finding_sha256"] = "0" * 64
        value = receipt(
            chunks=chunks, chunk_findings=[finding],
            aggregate_result={"review_result": "PASS", "findings": [],
                              "dispositions": [bad_disposition]},
            review_result="PASS", findings=[],
        )
        with self.assertRaisesRegex(ValueError, "does not bind the chunk finding"):
            review.validate(value, BASE, HEAD)

    def test_upheld_blocker_must_remain_in_aggregate_findings(self):
        finding = {"severity": "P1", "title": "upheld concern", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(
            chunks=chunks, chunk_findings=[finding],
            aggregate_result={"review_result": "PASS", "findings": [],
                              "dispositions": [disposition_for(finding, decision="UPHELD")]},
            review_result="PASS", findings=[],
        )
        with self.assertRaisesRegex(ValueError, "omitted an upheld blocking chunk finding"):
            review.validate(value, BASE, HEAD)

    def test_disputed_blocker_cannot_also_be_upheld_in_aggregate(self):
        finding = {"severity": "P2", "title": "disputed concern", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(
            chunks=chunks, chunk_findings=[finding],
            aggregate_result={"review_result": "FAIL", "findings": [finding],
                              "dispositions": [disposition_for(finding)]},
            review_result="FAIL", findings=[finding],
        )
        with self.assertRaisesRegex(ValueError, "both disputed and upheld"):
            review.validate(value, BASE, HEAD)

    def test_duplicate_and_orphaned_dispositions_are_rejected(self):
        finding = {"severity": "P2", "title": "localized concern", "evidence": "chunk"}
        chunks = [{"index": 0, "result": {"findings": [finding]}}]
        duplicate = disposition_for(finding)
        with self.assertRaisesRegex(ValueError, "duplicated a blocking finding"):
            review.validate_blocker_dispositions(
                chunks, {"findings": [], "dispositions": [duplicate, duplicate]}
            )
        orphan = disposition_for(finding, finding_index=1)
        with self.assertRaisesRegex(ValueError, "refers to no blocking chunk finding"):
            review.validate_blocker_dispositions(
                chunks, {"findings": [], "dispositions": [orphan]}
            )
    def test_unknown_aggregate_verdict_is_rejected(self):
        with self.assertRaises(ValueError):
            review.validate(receipt(review_result="GARBAGE"), BASE, HEAD)
    def test_p3_is_nonblocking(self):
        finding = {"severity": "P3", "title": "x", "evidence": "y"}
        chunks = receipt()["chunks"]; chunks[0]["result"] = {"review_result": "PASS", "findings": [finding]}
        value = receipt(findings=[finding], chunks=chunks, chunk_findings=[finding],
                        aggregate_result={"review_result": "PASS", "findings": [finding],
                                          "dispositions": []})
        self.assertEqual(review.validate(value, BASE, HEAD)["review_result"], "PASS")

    def test_aggregate_synthesis_cannot_drop_blocking_chunk_finding(self):
        finding = {"severity": "P1", "title": "must survive", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        value = receipt(
            chunks=chunks, chunk_findings=[finding],
            aggregate_result={"review_result": "PASS", "findings": []},
            findings=[], review_result="PASS",
        )
        with self.assertRaisesRegex(ValueError, "omitted blocker dispositions"):
            review.validate(value, BASE, HEAD)
    def test_durable_artifact_result_must_match_receipt_chunk(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            evidence.mkdir(mode=0o700)
            repo = Path(tmp) / "repo"
            repo.mkdir()
            artifact = evidence / "chunk-000.json"
            artifact.write_text(json.dumps({"review_result": "PASS", "findings": [
                {"severity": "P3", "title": "artifact finding", "evidence": "durable"},
            ]}))
            artifact.chmod(0o600)
            value = receipt()
            value["chunks"][0]["output_sha256"] = review.sha(artifact)
            source = b"fixture diff\n"
            value["diff_sha256"] = review.digest(source)
            manifest = {
                "version": "cmh-deepseek-chunks/v2", "base_sha": BASE,
                "head_sha": HEAD, "diff_sha256": value["diff_sha256"],
                "chunks": [{key: value["chunks"][0][key]
                            for key in ("index", "start", "end", "sha256")}],
            }
            value["manifest_sha256"] = review.digest(review.canon(manifest))
            payload = {key: item for key, item in value.items()
                       if key not in {"integrity_sha256", "auth_hmac_sha256"}}
            value["integrity_sha256"] = review.digest(review.canon(payload))
            value["auth_hmac_sha256"] = review.auth_digest(value, TEST_SECRET)
            with patch.object(review, "git", return_value=source), \
                    self.assertRaisesRegex(ValueError, "chunk result does not match"):
                review.validate(value, BASE, HEAD, root=repo,
                                receipt_path=evidence / "receipt.json")

    def test_evidence_directory_rejects_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            evidence_target = root / "evidence-target"
            evidence_target.mkdir(mode=0o755)
            evidence_target.chmod(0o755)
            evidence_link = root / "evidence-link"
            evidence_link.symlink_to(evidence_target, target_is_directory=True)
            sentinel = evidence_target / "sentinel"
            sentinel.write_text("untouched")

            with self.assertRaises(OSError):
                review.open_private_directory(evidence_link, repo)

            self.assertEqual(sentinel.read_text(), "untouched")
            self.assertEqual(stat.S_IMODE(evidence_target.stat().st_mode), 0o755)

    def test_private_evidence_directory_accepts_filesystem_root_anchor(self):
        # Exercise the root-anchor branch directly.  A root anchor is selected
        # when the target is outside the configured owner home, and must be
        # activated before the walk over target.parts[1:].
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            evidence = root / "evidence"
            fake_home = type("Pwd", (), {"pw_dir": "/home/owner-home-not-present"})()
            with patch.object(review.pwd, "getpwuid", return_value=fake_home):
                _, evidence_fd = review.open_private_directory(evidence, repo)
            try:
                self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o700)
            finally:
                os.close(evidence_fd)

    def test_private_artifacts_are_fsynced_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            _, evidence_fd = review.open_private_directory(evidence, repo)
            calls = []
            real_fsync = os.fsync
            try:
                with patch.object(review.os, "fsync", side_effect=lambda fd: (calls.append(fd), real_fsync(fd))[1]):
                    review.write_private_artifact(evidence_fd, "artifact.json", b"first", "run-a")
                self.assertEqual(len(calls), 2)
                artifact = evidence / "artifact.json"
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
                self.assertEqual(artifact.read_bytes(), b"first")

                with self.assertRaises(FileExistsError):
                    review.write_private_artifact(evidence_fd, "artifact.json", b"replacement", "run-b")
                self.assertEqual(artifact.read_bytes(), b"first")
            finally:
                os.close(evidence_fd)

    def test_private_artifact_reader_rejects_symlink_and_permissive_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            _, evidence_fd = review.open_private_directory(evidence, repo)
            try:
                victim = root / "victim"
                victim.write_text("not evidence")
                victim.chmod(0o600)
                (evidence / "linked.json").symlink_to(victim)
                with self.assertRaises(OSError):
                    review.read_private_artifact(evidence_fd, "linked.json")

                permissive = evidence / "permissive.json"
                permissive.write_text("{}")
                permissive.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "private owner-owned"):
                    review.read_private_artifact(evidence_fd, "permissive.json")
            finally:
                os.close(evidence_fd)

    def test_token_reader_requires_private_regular_file_without_changing_parent_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            credential_dir = root / "credentials"
            credential_dir.mkdir(mode=0o750)
            token_file = credential_dir / "token"
            token_file.write_text(TEST_SECRET)
            token_file.chmod(0o600)

            self.assertEqual(review.read_token_file(token_file, repo), TEST_SECRET)
            self.assertEqual(stat.S_IMODE(credential_dir.stat().st_mode), 0o750)

            token_file.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "mode 0600"):
                review.read_token_file(token_file, repo)
    def test_non_utf8_chunk_is_embedded_as_exact_base64(self):
        source = b"diff --git a/x b/x\n+\xff\x00\n"
        chunk = {"index": 0, "start": 0, "end": len(source), "sha256": review.digest(source)}
        rendered = review.prompt(BASE, HEAD, "d" * 64, "e" * 64, chunk, source)
        self.assertIn("BASE64-ENCODED EXACT DIFF BYTES:", rendered)
        self.assertIn("ZGlmZiAtLWdpdCBhL3ggYi94Civ/AAo=", rendered)
        self.assertNotIn("\ufffd", rendered)

    def test_aggregate_prompt_provides_precomputed_blocker_indices_and_hashes(self):
        blocker = {"severity": "P2", "title": "concern", "evidence": "chunk detail"}
        chunks = [{"index": 2, "result": {"findings": [blocker]}}]
        indexed, required = review.indexed_chunk_findings(chunks)
        source = b"exact diff\n"
        rendered = review.aggregate_prompt(
            BASE, HEAD, "d" * 64, "e" * 64, chunks, source, indexed, required,
        )
        self.assertEqual(required, [{
            "chunk_index": 2, "finding_index": 0, "source_severity": "P2",
            "finding_sha256": review.digest(review.canon(blocker)),
        }])
        self.assertIn('"chunk_index": 2', rendered)
        self.assertIn('"finding_sha256": "' + review.digest(review.canon(blocker)) + '"', rendered)
        self.assertIn("do not calculate, modify, omit, or duplicate these values", rendered)
    def test_reviewer_result_rejects_invalid_shape(self):
        with self.assertRaisesRegex(ValueError, "invalid reviewer output"):
            review.reviewer_result('{"review_result":"PASS","findings":"not-a-list"}')
        with self.assertRaisesRegex(ValueError, "invalid reviewer output"):
            review.reviewer_result('{"review_result":"PASS","findings":[{"severity":"CRITICAL","title":"x","evidence":"y"}]}')
        with self.assertRaisesRegex(ValueError, "reviewer verdict mismatch"):
            review.reviewer_result('{"review_result":"PASS","findings":[{"severity":"P1","title":"x","evidence":"y"}]}')
        with self.assertRaisesRegex(ValueError, "omitted blocker dispositions"):
            review.reviewer_result('{"review_result":"PASS","findings":[]}', require_dispositions=True)
        with self.assertRaisesRegex(ValueError, "cannot contain aggregate dispositions"):
            review.reviewer_result('{"review_result":"PASS","findings":[],"dispositions":[]}', forbid_dispositions=True)
    def test_mission_and_repository_binding_are_required_when_expected(self):
        value = receipt(repository="example/repo", mission_id="mission-a")
        self.assertEqual(review.validate(value, BASE, HEAD, mission_id="mission-a",
                                         repository="example/repo")["review_result"], "PASS")
        with self.assertRaisesRegex(ValueError, "mission binding"):
            review.validate(value, BASE, HEAD, mission_id="mission-b",
                            repository="example/repo")
        with self.assertRaisesRegex(ValueError, "repository binding"):
            review.validate(value, BASE, HEAD, mission_id="mission-a",
                            repository="example/other")
    def test_run_scoped_artifact_paths_cannot_overwrite_prior_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Harness Test"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "harness-test@example.invalid"], check=True)
            remote = "https://review-user:review-password@github.com/fixture/repo.git?access_token=review-token"
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", remote], check=True)
            source = repo / "tracked.txt"
            source.write_text("base\n")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            source.write_text("head\n")
            (repo / ".gitattributes").write_text("tracked.txt diff=attack\n")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt", ".gitattributes"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "head"], check=True)
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            textconv_marker = root / "textconv-was-run"
            attacker_repo = root / "attacker.git"
            subprocess.run(["git", "clone", "--bare", "-q", str(repo), str(attacker_repo)], check=True)
            subprocess.run([
                "git", "--git-dir", str(attacker_repo), "remote", "set-url", "origin",
                "https://ambient-user:ambient-secret@attacker.invalid/repo.git",
            ], check=True)
            ambient_git = {
                "GIT_DIR": str(attacker_repo),
                "GIT_WORK_TREE": str(repo),
                "GIT_INDEX_FILE": str(root / "attacker-index"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "diff.attack.textconv",
                "GIT_CONFIG_VALUE_0": f"touch {textconv_marker}; cat",
                "HTTPS_PROXY": "http://proxy.example.invalid:8080",
                "OPENAI_API_KEY": "ambient-api-key-must-not-pass",
            }
            token_file = root / "review-token"
            token_file.write_text(TEST_SECRET)
            token_file.chmod(0o600)
            evidence = root / "evidence"
            args = Namespace(repo=str(repo), base=base, head=head, mission_id="fixture",
                             evidence=str(evidence), token_file=str(token_file), timeout=1)
            invocations = []

            def capture_invocation(command, prompt_text, env, timeout):
                invocations.append((command, {
                    name: value for name, value in env.items()
                    if name not in {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}
                }))
                if prompt_text.startswith("You are the final independent reviewer"):
                    result = {"review_result": "PASS", "findings": [], "dispositions": []}
                else:
                    result = {"review_result": "PASS", "findings": []}
                return subprocess.CompletedProcess(["claude"], 0, json.dumps(result), "")

            with patch.dict(os.environ, ambient_git), \
                    patch.object(review, "resolve_claude_launcher",
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

            self.assertEqual(len(invocations), 4)
            self.assertFalse(textconv_marker.exists())
            for command, env in invocations:
                self.assertEqual(command[0], "/trusted/bin/claude")
                self.assertEqual(env["PATH"], "/trusted/bin:/usr/bin")
                self.assertEqual(env["HTTPS_PROXY"], ambient_git["HTTPS_PROXY"])
                self.assertNotIn("GIT_DIR", env)
                self.assertNotIn("OPENAI_API_KEY", env)
            second_receipt = Path(second_result["receipt"])
            self.assertNotEqual(first_receipt.parent, second_receipt.parent)
            self.assertTrue(first_receipt.is_file())
            self.assertTrue(second_receipt.is_file())
            self.assertIn(head[:12], first_receipt.name)
            for receipt_path in (first_receipt, second_receipt):
                receipt_bytes = receipt_path.read_bytes()
                self.assertEqual(json.loads(receipt_bytes)["repository"], "https://github.com/fixture/repo.git")
                for credential in (b"review-user", b"review-password", b"review-token"):
                    self.assertNotIn(credential, receipt_bytes)
            expected_command_hash = review.digest(review.canon({
                "chunk": invocations[0][0], "aggregate": invocations[1][0],
            }))
            self.assertEqual(
                json.loads(first_receipt.read_text())["command_sha256"],
                expected_command_hash,
            )
            second_chunk = second_receipt.parent / "chunk-000.json"
            self.assertNotEqual(first_chunk, second_chunk)
            self.assertEqual(first_receipt.read_bytes(), first_receipt_before)
            self.assertEqual(first_chunk.read_bytes(), first_chunk_before)
            with patch.dict(os.environ, ambient_git):
                for receipt_path in (first_receipt, second_receipt):
                    self.assertEqual(
                        review.validate(json.loads(receipt_path.read_text()), base, head, repo,
                                        receipt_path, "fixture", remote)["review_result"],
                        "PASS",
                    )
            self.assertFalse(textconv_marker.exists())

    def _execute_review(self, args, responder):
        with patch.object(review, "resolve_claude_launcher",
                          return_value=("/trusted/bin/claude", "/trusted/bin:/usr/bin")), \
                patch.object(review, "invoke_reviewer", side_effect=responder):
            review.run(args)

    def _successful_chunk(self):
        return subprocess.CompletedProcess(
            ["claude"], 0, json.dumps({"review_result": "PASS", "findings": []}), "",
        )

    @staticmethod
    def _aggregate_prompt(prompt_text):
        return prompt_text.startswith("You are the final independent reviewer")

    def _failure_record(self, caught):
        self.assertIsNotNone(caught.exception.evidence_path)
        path = Path(caught.exception.evidence_path)
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        raw = path.read_bytes()
        self.assertEqual(review.digest(raw), caught.exception.evidence_sha256)
        record = json.loads(raw)
        unsigned = {key: value for key, value in record.items() if key != "integrity_sha256"}
        self.assertEqual(record["integrity_sha256"], review.digest(review.canon(unsigned)))
        self.assertEqual(record["schema_version"], "cmh-review-attempt-failure/v1")
        self.assertEqual(record["repository"], "ssh://github.com/fixture/repo.git")
        self.assertEqual(record["mission_id"], "fixture")
        self.assertRegex(record["base_sha"], r"^[0-9a-f]{40}$")
        self.assertRegex(record["head_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(record["model"], review.MODEL)
        self.assertFalse(record["receipt_written"])
        self.assertEqual(record["retryable"], caught.exception.retryable)
        return record, raw

    def test_aggregate_failures_get_typed_bound_private_diagnostics(self):
        cases = (
            ("capacity", "Selected model is at capacity", "",
             "TRANSIENT_CAPACITY", True),
            ("request_timeout", "", "request timed out",
             "TRANSIENT_TRANSPORT", True),
            ("connection_reset", "", "ECONNRESET: connection reset by peer",
             "TRANSIENT_TRANSPORT", True),
            ("authentication", '{"status":401,"type":"token_revoked"}', "",
             "AUTHENTICATION_FAILURE", False),
            ("payment", '{"status":402,"type":"payment_required"}', "",
             "PAYMENT_OR_BILLING_FAILURE", False),
            ("unsupported_model", '{"error":{"type":"unsupported_model"}}', "",
             "MODEL_UNAVAILABLE_OR_UNSUPPORTED", False),
            ("unknown", "unrecognized provider failure marker", "",
             "UNKNOWN_EXTERNAL_FAILURE", False),
        )
        for name, stdout, stderr, expected_class, retryable in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, evidence = run_fixture(root)

                def responder(command, prompt_text, env, timeout):
                    if not self._aggregate_prompt(prompt_text):
                        return self._successful_chunk()
                    return subprocess.CompletedProcess(["claude"], 1, stdout, stderr)

                with self.assertRaises(review.ReviewAttemptFailure) as caught:
                    self._execute_review(args, responder)
                record, raw = self._failure_record(caught)
                self.assertEqual(caught.exception.classification.value, expected_class)
                self.assertEqual(record["failure_classification"], expected_class)
                self.assertEqual(record["retryable"], retryable)
                self.assertEqual(record["stage"], "aggregate")
                self.assertEqual(record["base_sha"], args.base)
                self.assertEqual(record["head_sha"], args.head)
                self.assertEqual(record["diff_sha256"], review.digest(
                    subprocess.check_output(["git", "-C", str(args.repo), "diff", "--no-ext-diff",
                                             "--no-textconv", "--binary", f"{args.base}..{args.head}"])))
                self.assertEqual(len(record["completed_chunk_artifacts"]), 1)
                self.assertEqual(record["process_stdout_sha256"], review.digest(stdout.encode()))
                self.assertEqual(record["process_stderr_sha256"], review.digest(stderr.encode()))
                self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))
                self.assertFalse(list(evidence.rglob("aggregate.json")))
                self.assertTrue(list(evidence.rglob("chunk-000.json")))
                self.assertNotIn(b"diff --git", raw)
                payload = caught.exception.as_payload()
                self.assertEqual(payload["failure_classification"], expected_class)
                self.assertEqual(payload["retryable"], retryable)
                self.assertEqual(payload["failure_evidence_path"], caught.exception.evidence_path)

    def test_aggregate_timeout_exception_is_typed_transport_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, _ = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_chunk()
                raise subprocess.TimeoutExpired(command, timeout, output=b"request timed out")

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["stage"], "aggregate")
            self.assertEqual(record["terminal_status"], "TIMED_OUT")
            self.assertEqual(record["failure_classification"], "TRANSIENT_TRANSPORT")
            self.assertTrue(record["retryable"])

    def test_all_seventeen_chunks_pass_but_aggregate_failure_has_no_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp), large_diff=True)
            diff = subprocess.check_output([
                "git", "-C", str(args.repo), "diff", "--no-ext-diff", "--no-textconv",
                "--binary", f"{args.base}..{args.head}",
            ])
            self.assertEqual(len(review.chunks(diff)), 17)
            completed = []

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    completed.append(prompt_text)
                    return self._successful_chunk()
                return subprocess.CompletedProcess(
                    ["claude"], 1, "Selected model is at capacity", "",
                )

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(len(completed), 17)
            self.assertEqual(record["stage"], "aggregate")
            self.assertEqual(record["failure_classification"], "TRANSIENT_CAPACITY")
            self.assertEqual(len(record["completed_chunk_artifacts"]), 17)
            failure_dir = Path(caught.exception.evidence_path).parent
            self.assertTrue(all((failure_dir / item["path"]).is_file()
                                for item in record["completed_chunk_artifacts"]))
            self.assertEqual(len(list(evidence.rglob("chunk-*.json"))), 17)
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_malformed_aggregate_output_is_nonretryable_and_not_receipted(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_chunk()
                return subprocess.CompletedProcess(["claude"], 0, "not-json", "")

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["failure_classification"], "INVALID_REVIEWER_OUTPUT")
            self.assertFalse(record["retryable"])
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_chunk_failure_uses_same_typed_sanitized_evidence_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                return subprocess.CompletedProcess(["claude"], 1, "", "request timeout")

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["stage"], "chunk")
            self.assertEqual(record["chunk_index"], 0)
            self.assertEqual(record["failure_classification"], "TRANSIENT_TRANSPORT")
            self.assertTrue(record["retryable"])
            self.assertFalse(record["completed_chunk_artifacts"])
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_credential_echo_is_discarded_and_only_hashes_are_persisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_chunk()
                return subprocess.CompletedProcess(["claude"], 1, "", TEST_SECRET)

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, raw = self._failure_record(caught)
            self.assertEqual(record["reason_code"], "credential_echo_detected")
            self.assertEqual(record["failure_classification"], "POLICY_OR_CONTRACT_FAILURE")
            self.assertFalse(record["retryable"])
            self.assertNotIn(TEST_SECRET.encode(), raw)
            self.assertNotIn(TEST_SECRET, str(caught.exception))
            self.assertNotIn(TEST_SECRET, json.dumps(caught.exception.as_payload()))
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_aggregate_contract_failure_is_durable_and_nonretryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_chunk()
                return subprocess.CompletedProcess(
                    ["claude"], 0,
                    json.dumps({"review_result": "PASS", "findings": []}), "",
                )

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["reason_code"], "review_contract_rejected")
            self.assertEqual(record["failure_classification"], "POLICY_OR_CONTRACT_FAILURE")
            self.assertFalse(record["retryable"])
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))
