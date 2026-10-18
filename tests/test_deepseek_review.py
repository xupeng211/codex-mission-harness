import importlib.util
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import time
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


def process_is_live(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False

_validate = review.validate
def _validated(*args, **kwargs):
    kwargs.setdefault("secret", TEST_SECRET)
    return _validate(*args, **kwargs)
review.validate = _validated

def receipt(**overrides):
    source = b"fixture diff\n"
    value = {"version": review.VERSION, "repository": "fixture", "mission_id": "fixture", "base_sha": BASE, "head_sha": HEAD,
             "diff_sha256": "d" * 64, "manifest_sha256": "e" * 64,
             "chunks": [{"index": 0, "start": 0, "end": len(source), "sha256": review.digest(source),
                         "output_sha256": "f" * 64, "result": {"review_result": "PASS", "findings": []}}],
             "groups": [], "group_manifest_sha256": "e" * 64,
             "chunk_findings": [],
             "aggregate_output_sha256": "g" * 64,
             "provider": "deepseek", "model": review.MODEL, "command_sha256": "c" * 64,
             "aggregate_result": {"review_result": "PASS", "findings": [], "dispositions": []},
             "review_result": "PASS", "findings": []}
    value.update(overrides)
    if "chunk_findings" not in overrides:
        value["chunk_findings"]=[finding for chunk in value["chunks"]
                                 for finding in chunk.get("result",{}).get("findings",[])]
    if "groups" not in overrides:
        try: layout=review.aggregate_group_layout(value["chunks"])
        except (KeyError,TypeError): layout=[]
        groups=[]
        for item in layout:
            selected=[chunk for chunk in value["chunks"] if chunk["index"] in item["chunk_indexes"]]
            _,required=review.indexed_chunk_findings(selected)
            dispositions=[{**entry,"decision":"DISPUTED",
                           "rationale":"The complete bounded group source disproves this finding."}
                          for entry in required]
            result={"review_result":"PASS","findings":[],"dispositions":dispositions,
                    "summary":"The reviewed group changes no interfaces or state transitions."}
            groups.append({**item,"sha256":"d"*64,"output_sha256":"h"*64,"result":result})
        value["groups"]=groups
    if "aggregate_result" not in overrides:
        value["aggregate_result"]={"review_result":"PASS","findings":[],"dispositions":[]}
    if "review_result" not in overrides:
        value["review_result"]=value["aggregate_result"]["review_result"]
    if "findings" not in overrides:
        value["findings"]=value["aggregate_result"]["findings"]
    if "group_manifest_sha256" not in overrides:
        value["group_manifest_sha256"] = review.aggregate_group_manifest_hash(
            value["base_sha"], value["head_sha"], value["diff_sha256"],
            value["manifest_sha256"], value["groups"],
        )
    value["integrity_sha256"] = review.digest(review.canon(value)); value["auth_hmac_sha256"] = review.auth_digest(value, TEST_SECRET); return value

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

def group_disposition_for(item, *, decision="UPHELD", group_index=0, finding_index=0):
    return {
        "group_index": group_index,
        "finding_index": finding_index,
        "source_severity": item["severity"],
        "finding_sha256": review.digest(review.canon(item)),
        "decision": decision,
        "rationale": "The bounded group review confirms this finding across the edited source.",
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
    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_reviewer_output_is_bounded_before_read_or_receipt(self):
        program = f"import sys;sys.stdout.write('x'*{review.MAX_REVIEW_OUTPUT_BYTES + 1})"
        with self.assertRaisesRegex(ValueError, "output exceeds bound"):
            review._invoke_reviewer_unmetered([sys.executable, "-c", program], "prompt", os.environ.copy(), 5)

    def test_exact_diff_has_byte_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "source.txt").write_text("before\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            (repo / "source.txt").write_text("after\n" * 100)
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "head"], check=True)
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            with self.assertRaisesRegex(ValueError, "bounded source size"):
                review.bounded_diff(repo, base, head, max_bytes=32)

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_invoke_reviewer_timeout_terminates_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child.pid"
            program = ("import pathlib,signal,subprocess,sys,time;"
                       "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                       "child=subprocess.Popen([sys.executable,'-c',"
                       "'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)']);"
                       "pathlib.Path(sys.argv[1]).write_text(str(child.pid));time.sleep(30)")
            with self.assertRaises(subprocess.TimeoutExpired):
                review._invoke_reviewer_unmetered([sys.executable, "-c", program, str(marker)],
                                       "prompt", os.environ.copy(), 1)
            child_pid = int(marker.read_text())
            for _ in range(40):
                if not process_is_live(child_pid):
                    break
                time.sleep(0.05)
            self.assertFalse(process_is_live(child_pid))

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_invoke_reviewer_interrupt_terminates_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child.pid"
            program = "sleep 30 & echo $! > \"$1\"; wait"
            original_sleep = review.time.sleep
            calls = [0]
            def interrupt_after_start(_seconds):
                calls[0] += 1
                if calls[0] == 1:
                    deadline = time.monotonic() + 1
                    while not marker.exists() and time.monotonic() < deadline:
                        original_sleep(0.01)
                    self.assertTrue(marker.exists(), "child PID marker was not published")
                    return None
                raise KeyboardInterrupt()
            with patch.object(review.time, "sleep", side_effect=interrupt_after_start):
                with self.assertRaises(KeyboardInterrupt):
                    review._invoke_reviewer_unmetered(["/bin/sh", "-c", program, "sh", str(marker)],
                                           "prompt", os.environ.copy(), 30)
            child_pid = int(marker.read_text())
            for _ in range(40):
                if not process_is_live(child_pid):
                    break
                original_sleep(0.05)
            self.assertFalse(process_is_live(child_pid))

    def test_legacy_oversized_scope_rejected_before_any_launcher_or_model_call(self):
        with tempfile.TemporaryDirectory() as directory:
            args,_=run_fixture(Path(directory))
            repo=Path(args.repo)
            (repo/'tracked.txt').write_text('x' * (review.MAX_LEGACY_DIFF_BYTES+1))
            subprocess.run(['git','-C',str(repo),'commit','-qam','oversized'],check=True)
            args.head=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
            with patch.object(review,'resolve_claude_launcher') as launcher:
                with self.assertRaisesRegex(ValueError,'bounded source size'):
                    review.run(args)
                launcher.assert_not_called()

    def test_legacy_final_synthesis_receives_disputed_original_findings(self):
        blocker={'severity':'P1','title':'cross-group risk','evidence':'original evidence'}
        chunk={'index':0,'result':{'review_result':'FAIL','findings':[blocker]}}
        disposition=disposition_for(blocker,decision='DISPUTED')
        group={'index':0,'start':0,'end':1,'chunk_indexes':[0], 'sha256':'a'*64,
               'output_sha256':'b'*64,'result':{'summary':'local dispute',
               'review_result':'PASS','findings':[],'dispositions':[disposition]}}
        prompt=review.aggregate_prompt(BASE,HEAD,'c'*64,'d'*64,'e'*64,[group],[],[],original_chunks=[chunk])
        self.assertIn('original_chunk_findings',prompt)
        self.assertIn('cross-group risk',prompt)
        self.assertIn('original evidence',prompt)
        self.assertIn('DISPUTED',prompt)
        self.assertIn('Reevaluate every original disputed chunk finding',prompt)

    def test_full_sha_is_checked_before_starting_diff_process(self):
        with patch.object(review.subprocess,'Popen') as process:
            with self.assertRaisesRegex(ValueError,'full SHA'):
                review.bounded_diff(Path('/nonexistent'),'--output=/tmp/unwanted',HEAD)
            process.assert_not_called()

    # This transport-only fixture mocks the separately tested live resource gate.
    @patch("harness.formal_delivery_gate.require_active_transport", new=lambda *_args: None)
    def test_timeout_kills_descendant_even_if_leader_exits_on_term(self):
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/'child.pid'
            program=("import pathlib,subprocess,sys,time;"
                     "child=subprocess.Popen([sys.executable,'-c',"
                     "'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)']);"
                     "pathlib.Path(sys.argv[1]).write_text(str(child.pid));time.sleep(30)")
            with self.assertRaises(subprocess.TimeoutExpired):
                review._invoke_reviewer_unmetered([sys.executable,'-c',program,str(marker)],'prompt',os.environ.copy(),1)
            pid=int(marker.read_text())
            for _ in range(40):
                if not process_is_live(pid):break
                time.sleep(0.05)
            self.assertFalse(process_is_live(pid))

    def test_v5_receipts_are_stale_after_resource_and_dispute_audit_policy(self):
        with self.assertRaisesRegex(ValueError,'exact-head binding'):
            review.validate(receipt(version='cmh-deepseek-review/v5'),BASE,HEAD)

    def test_chunk_and_aggregate_schemas_have_separate_disposition_contracts(self):
        self.assertNotIn("dispositions", review.CHUNK_SCHEMA["properties"])
        self.assertIn("dispositions", review.GROUP_SCHEMA["properties"])
        self.assertIn("summary", review.GROUP_SCHEMA["required"])
        self.assertIn("chunk_index", review.GROUP_SCHEMA["properties"]["dispositions"]["items"]["properties"])
        self.assertIn("group_index", review.AGGREGATE_SCHEMA["properties"]["dispositions"]["items"]["properties"])
        self.assertEqual(review.AGGREGATE_SCHEMA["properties"]["dispositions"]["items"]["properties"]["decision"]["enum"],["UPHELD"])
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
    def test_aggregate_groups_are_deterministic_bounded_and_cover_every_chunk(self):
        diff=(b"line\n"*120000); plan=review.chunks(diff)
        first=review.aggregate_groups(diff,plan); second=review.aggregate_groups(diff,plan)
        self.assertEqual(first,second)
        self.assertGreater(len(first),1)
        self.assertEqual([i for group in first for i in group["chunk_indexes"]],
                         list(range(len(plan))))
        self.assertEqual(b"".join(diff[g["start"]:g["end"]] for g in first),diff)
        self.assertTrue(all(g["end"]-g["start"]<=review.AGGREGATE_GROUP_BYTES for g in first))
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

    def test_group_manifest_binds_exact_group_coverage_and_source_hashes(self):
        value=receipt(); value["groups"][0]["sha256"]="0"*64
        value["integrity_sha256"]=review.digest(review.canon({k:v for k,v in value.items()
                                                               if k not in {"integrity_sha256","auth_hmac_sha256"}}))
        value["auth_hmac_sha256"]=review.auth_digest(value,TEST_SECRET)
        with self.assertRaisesRegex(ValueError,"aggregate group manifest hash mismatch"):
            review.validate(value,BASE,HEAD)
    def test_blocking_finding_requires_fail(self):
        finding = {"severity": "P1", "title": "x", "evidence": "y"}
        with self.assertRaises(ValueError): review.validate(receipt(findings=[finding]), BASE, HEAD)
        chunks = receipt()["chunks"]; chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        group = receipt(chunks=chunks)["groups"][0]
        group["result"] = {"review_result": "FAIL", "findings": [finding],
                           "dispositions": [disposition_for(finding, decision="UPHELD")],
                           "summary": "The group review confirms the finding across the edited source."}
        value = receipt(review_result="FAIL", findings=[finding], chunks=chunks,
                        chunk_findings=[finding], groups=[group],
                        aggregate_result={"review_result":"FAIL","findings":[finding],
                                          "dispositions":[group_disposition_for(finding)]})
        self.assertEqual(review.validate(value, BASE, HEAD)["review_result"], "FAIL")

    def test_v2_deepseek_receipt_is_stale_under_disposition_policy(self):
        with self.assertRaisesRegex(ValueError, "exact-head binding"):
            review.validate(receipt(version="cmh-deepseek-review/v2"), BASE, HEAD)

    def test_v4_deepseek_receipt_is_stale_under_bounded_aggregation_policy(self):
        with self.assertRaisesRegex(ValueError, "exact-head binding"):
            review.validate(receipt(version="cmh-deepseek-review/v4"), BASE, HEAD)

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
        value = receipt(chunks=chunks,chunk_findings=[finding])
        self.assertEqual(review.validate(value, BASE, HEAD)["review_result"], "PASS")

    def test_blocking_chunk_finding_cannot_be_silently_dropped(self):
        finding = {"severity": "P1", "title": "must be accounted for", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        group=receipt(chunks=chunks)["groups"][0]
        group["result"]={"review_result":"PASS","findings":[],"dispositions":[],
                         "summary":"The group review does not identify any changed interfaces."}
        value = receipt(chunks=chunks,chunk_findings=[finding],groups=[group])
        with self.assertRaisesRegex(ValueError, "omitted a blocking chunk finding disposition"):
            review.validate(value, BASE, HEAD)

    def test_disposition_must_bind_exact_blocking_chunk_finding(self):
        finding = {"severity": "P2", "title": "localized concern", "evidence": "chunk evidence"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        bad_disposition = disposition_for(finding)
        bad_disposition["finding_sha256"] = "0" * 64
        group=receipt(chunks=chunks)["groups"][0]
        group["result"]={"review_result":"PASS","findings":[],"dispositions":[bad_disposition],
                         "summary":"The group review does not identify any changed interfaces."}
        value = receipt(chunks=chunks,chunk_findings=[finding],groups=[group])
        with self.assertRaisesRegex(ValueError, "does not bind the chunk finding"):
            review.validate(value, BASE, HEAD)

    def test_upheld_blocker_must_remain_in_aggregate_findings(self):
        finding = {"severity": "P1", "title": "upheld concern", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        group=receipt(chunks=chunks)["groups"][0]
        group["result"]={"review_result":"PASS","findings":[],
                         "dispositions":[disposition_for(finding,decision="UPHELD")],
                         "summary":"The group review does not identify any changed interfaces."}
        value = receipt(chunks=chunks,chunk_findings=[finding],groups=[group])
        with self.assertRaisesRegex(ValueError, "omitted an upheld blocking chunk finding"):
            review.validate(value, BASE, HEAD)

    def test_disputed_blocker_cannot_also_be_upheld_in_aggregate(self):
        finding = {"severity": "P2", "title": "disputed concern", "evidence": "chunk"}
        chunks = receipt()["chunks"]
        chunks[0]["result"] = {"review_result": "FAIL", "findings": [finding]}
        group=receipt(chunks=chunks)["groups"][0]
        group["result"]={"review_result":"FAIL","findings":[finding],
                         "dispositions":[disposition_for(finding)],
                         "summary":"The group review confirms the finding across the edited source."}
        value = receipt(chunks=chunks,chunk_findings=[finding],groups=[group])
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
        group=receipt(chunks=chunks)["groups"][0]
        group["result"]={"review_result":"FAIL","findings":[finding],
                         "dispositions":[disposition_for(finding,decision="UPHELD")],
                         "summary":"The group review confirms the finding across the edited source."}
        value = receipt(chunks=chunks,chunk_findings=[finding],groups=[group],
                        aggregate_result={"review_result":"FAIL","findings":[finding],"dispositions":[]},
                        findings=[finding],review_result="FAIL")
        with self.assertRaisesRegex(ValueError, "omitted a blocking chunk finding disposition"):
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
            value["groups"][0]["sha256"] = review.digest(source)
            manifest = {
                "version": "cmh-deepseek-chunks/v2", "base_sha": BASE,
                "head_sha": HEAD, "diff_sha256": value["diff_sha256"],
                "chunks": [{key: value["chunks"][0][key]
                            for key in ("index", "start", "end", "sha256")}],
            }
            value["manifest_sha256"] = review.digest(review.canon(manifest))
            value["group_manifest_sha256"] = review.aggregate_group_manifest_hash(
                BASE,HEAD,value["diff_sha256"],value["manifest_sha256"],value["groups"],
            )
            payload = {key: item for key, item in value.items()
                       if key not in {"integrity_sha256", "auth_hmac_sha256"}}
            value["integrity_sha256"] = review.digest(review.canon(payload))
            value["auth_hmac_sha256"] = review.auth_digest(value, TEST_SECRET)
            evidence.chmod(0o755)
            with patch.object(review, "bounded_diff", return_value=source), \
                    self.assertRaisesRegex(ValueError, "owner-only"):
                review.validate(value, BASE, HEAD, root=repo,receipt_path=evidence / "receipt.json")
            self.assertEqual(stat.S_IMODE(evidence.stat().st_mode),0o755)
            evidence.chmod(0o700)
            with patch.object(review, "bounded_diff", return_value=source), \
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
            credential_dir.chmod(0o750)
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

    def test_group_and_final_prompts_bind_blocker_dispositions(self):
        blocker = {"severity": "P2", "title": "concern", "evidence": "chunk detail"}
        chunks = [{"index": 2,"start":0,"end":11,"sha256":"a"*64,
                   "result": {"findings": [blocker]}}]
        indexed, required = review.indexed_chunk_findings(chunks)
        source = b"exact diff\n"
        group={"index":0,"start":0,"end":len(source),"chunk_indexes":[2],
               "sha256":review.digest(source)}
        group_rendered = review.aggregate_group_prompt(
            BASE,HEAD,"d"*64,"e"*64,"f"*64,group,chunks,source,indexed,required,
        )
        self.assertEqual(required, [{
            "chunk_index": 2, "finding_index": 0, "source_severity": "P2",
            "finding_sha256": review.digest(review.canon(blocker)),
        }])
        self.assertIn('"chunk_index": 2', group_rendered)
        self.assertIn('"finding_sha256": "' + review.digest(review.canon(blocker)) + '"', group_rendered)
        self.assertIn("do not calculate, modify, omit, or duplicate these values", group_rendered)
        group_result={"review_result":"FAIL","findings":[blocker],"summary":"A bounded group summary.",
                      "dispositions":[disposition_for(blocker,chunk_index=2)]}
        groups=[{**group,"output_sha256":"0"*64,"result":group_result}]
        final_findings,final_required=review.indexed_chunk_findings(
            [{"index":0,"result":group_result}],source_index_field="group_index",
        )
        final_rendered=review.aggregate_prompt(
            BASE,HEAD,"d"*64,"e"*64,"f"*64,groups,final_findings,final_required,
        )
        self.assertIn('"group_index": 0',final_rendered)
        self.assertIn("this synthesis does not have the source needed to dispute one",final_rendered)
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
                if prompt_text.startswith("You are the final cross-group independent reviewer"):
                    result = {"review_result": "PASS", "findings": [], "dispositions": []}
                elif prompt_text.startswith("You are an independent synthesis reviewer"):
                    result = {"review_result":"PASS","findings":[],"dispositions":[],
                              "summary":"The reviewed group changes no interfaces or state transitions."}
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

            self.assertEqual(len(invocations), 6)
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
                "chunk": invocations[0][0], "group": invocations[1][0],
                "aggregate": invocations[2][0],
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

    def test_large_diff_uses_bounded_hierarchy_and_commit_last_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,evidence=run_fixture(Path(tmp),large_diff=True)
            diff=subprocess.check_output([
                "git","-C",args.repo,"diff","--no-ext-diff","--no-textconv",
                "--binary",f"{args.base}..{args.head}",
            ])
            invocations=[]
            def responder(command,prompt_text,env,timeout):
                invocations.append(prompt_text)
                if self._aggregate_prompt(prompt_text):
                    self.assertFalse(list(evidence.rglob("aggregate.json")))
                    self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))
                    result={"review_result":"PASS","findings":[],"dispositions":[]}
                elif self._group_prompt(prompt_text):
                    result={"review_result":"PASS","findings":[],"dispositions":[],
                            "summary":"This group changes no interfaces or state transitions."}
                else:
                    result={"review_result":"PASS","findings":[]}
                self.assertLessEqual(len(prompt_text.encode()),review.MAX_REVIEW_PROMPT_BYTES)
                return subprocess.CompletedProcess(["claude"],0,json.dumps(result),"")
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self._execute_review(args,responder)
            payload=json.loads(captured.getvalue()); receipt_path=Path(payload["receipt"])
            receipt_value=json.loads(receipt_path.read_text())
            self.assertEqual(payload["status"],"PASS")
            self.assertEqual(receipt_value["diff_sha256"],review.digest(diff))
            self.assertEqual(len(receipt_value["chunks"]),len(review.chunks(diff)))
            groups=receipt_value["groups"]
            self.assertGreater(len(groups),1)
            self.assertEqual([index for group in groups for index in group["chunk_indexes"]],
                             list(range(len(receipt_value["chunks"]))))
            self.assertTrue(all(group["end"]-group["start"]<=review.AGGREGATE_GROUP_BYTES
                                for group in groups))
            final_prompt=invocations[-1]
            self.assertIn("ReviewedGroupSummaries=",final_prompt)
            self.assertNotIn("UTF-8 COMPLETE DIFF:",final_prompt)
            self.assertNotIn("diff --git",final_prompt)
            self.assertEqual(len(invocations),len(receipt_value["chunks"])+len(groups)+1)
            self.assertEqual(review.validate(
                receipt_value,args.base,args.head,args.repo,receipt_path,"fixture",
                "git@github.com:fixture/repo.git",
            )["review_result"],"PASS")
            for group in groups:
                artifact=receipt_path.parent/f"group-{group['index']:03d}.json"
                self.assertEqual(review.sha(artifact),group["output_sha256"])

    def test_group_cannot_omit_chunk_blocker_or_publish_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            args,evidence=run_fixture(Path(tmp)); finding={
                "severity":"P1","title":"chunk blocker","evidence":"exact chunk evidence",
            }
            def responder(command,prompt_text,env,timeout):
                if self._aggregate_prompt(prompt_text):
                    self.fail("final aggregation must not run after a group drops a blocker")
                if self._group_prompt(prompt_text):
                    result={"review_result":"PASS","findings":[],"dispositions":[],
                            "summary":"The group summary intentionally omits a source blocker."}
                else:
                    result={"review_result":"FAIL","findings":[finding]}
                return subprocess.CompletedProcess(["claude"],0,json.dumps(result),"")
            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args,responder)
            record,_=self._failure_record(caught)
            self.assertEqual(record["stage"],"aggregate_group")
            self.assertEqual(record["group_index"],0)
            self.assertEqual(record["failure_classification"],"POLICY_OR_CONTRACT_FAILURE")
            self.assertEqual(record["failure_phase"],"REVIEW_CONTRACT_VALIDATION")
            self.assertTrue(record["process_succeeded"])
            self.assertEqual(len(record["completed_chunk_artifacts"]),1)
            self.assertFalse(record["completed_group_artifacts"])
            self.assertTrue(list(evidence.rglob("chunk-000.json")))
            self.assertFalse(list(evidence.rglob("group-000.json")))
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_final_synthesis_cannot_dispute_a_group_blocker(self):
        finding={"severity":"P1","title":"group blocker","evidence":"bounded source evidence"}
        groups=[{"index":0,"result":{"findings":[finding]}}]
        required=group_disposition_for(finding,decision="DISPUTED")
        with self.assertRaisesRegex(ValueError,"cannot dispute"):
            review.validate_blocker_dispositions(
                groups,{"findings":[],"dispositions":[required]},
                allow_disputes=False,source_index_field="group_index",
            )

    def _execute_review(self, args, responder):
        with patch.object(review, "resolve_claude_launcher",
                          return_value=("/trusted/bin/claude", "/trusted/bin:/usr/bin")), \
                patch.object(review, "invoke_reviewer", side_effect=responder):
            review.run(args)

    def _successful_chunk(self):
        return subprocess.CompletedProcess(
            ["claude"], 0, json.dumps({"review_result": "PASS", "findings": []}), "",
        )

    def _successful_group(self):
        result={"review_result":"PASS","findings":[],"dispositions":[],
                "summary":"The reviewed group changes no interfaces or state transitions."}
        return subprocess.CompletedProcess(["claude"],0,json.dumps(result),"")

    @staticmethod
    def _aggregate_prompt(prompt_text):
        return prompt_text.startswith("You are the final cross-group independent reviewer")

    @staticmethod
    def _group_prompt(prompt_text):
        return prompt_text.startswith("You are an independent synthesis reviewer")

    def _successful_nonfinal_prompt(self,prompt_text):
        return self._successful_group() if self._group_prompt(prompt_text) else self._successful_chunk()

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
            ("cli_configuration", "", "error: unexpected argument --invalid-option",
             "POLICY_OR_CONTRACT_FAILURE", False),
            ("generic_schema", "structured output schema validation failed", "",
             "UNKNOWN_EXTERNAL_FAILURE", False),
            ("generic_json", "invalid JSON in reviewer response", "",
             "UNKNOWN_EXTERNAL_FAILURE", False),
            ("unknown", "unrecognized provider failure marker", "",
             "UNKNOWN_EXTERNAL_FAILURE", False),
        )
        for name, stdout, stderr, expected_class, retryable in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args, evidence = run_fixture(root)

                def responder(command, prompt_text, env, timeout):
                    if not self._aggregate_prompt(prompt_text):
                        return self._successful_nonfinal_prompt(prompt_text)
                    return subprocess.CompletedProcess(["claude"], 1, stdout, stderr)

                with self.assertRaises(review.ReviewAttemptFailure) as caught:
                    self._execute_review(args, responder)
                record, raw = self._failure_record(caught)
                self.assertEqual(caught.exception.classification.value, expected_class)
                self.assertEqual(record["failure_classification"], expected_class)
                self.assertEqual(record["retryable"], retryable)
                self.assertEqual(record["failure_phase"], "PROCESS_OR_PROVIDER")
                self.assertFalse(record["process_succeeded"])
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

    def test_process_failure_classifier_ignores_generic_output_shape_words(self):
        cases = (
            ("structured output schema validation failed", "UNKNOWN_EXTERNAL_FAILURE", False),
            ("invalid JSON", "UNKNOWN_EXTERNAL_FAILURE", False),
            ("Selected model is at capacity", "TRANSIENT_CAPACITY", True),
            ("request timeout", "TRANSIENT_TRANSPORT", True),
            ("HTTP 401 token_revoked", "AUTHENTICATION_FAILURE", False),
            ("HTTP 402 billing_error", "PAYMENT_OR_BILLING_FAILURE", False),
            ("unsupported model", "MODEL_UNAVAILABLE_OR_UNSUPPORTED", False),
            ("unexpected argument", "POLICY_OR_CONTRACT_FAILURE", False),
        )
        for signal, expected, retryable in cases:
            with self.subTest(signal=signal):
                details = review.classify_process_failure([signal])
                self.assertEqual(details.classification.value, expected)
                self.assertEqual(details.retryable, retryable)

    def test_nonzero_group_exit_never_uses_format_retry_or_echoes_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))
            calls = {"group": 0}
            opaque = "structured output failed; invalid JSON; SECRET_SOURCE_MARKER"

            def responder(command, prompt_text, env, timeout):
                if self._group_prompt(prompt_text):
                    calls["group"] += 1
                    return subprocess.CompletedProcess(["claude"], 1, opaque, "")
                if self._aggregate_prompt(prompt_text):
                    self.fail("final synthesis cannot run after a failed group process")
                return self._successful_chunk()

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, raw = self._failure_record(caught)
            self.assertEqual(calls["group"], 1)
            self.assertEqual(record["stage"], "aggregate_group")
            self.assertEqual(record["exit_code"], 1)
            self.assertEqual(record["failure_phase"], "PROCESS_OR_PROVIDER")
            self.assertFalse(record["process_succeeded"])
            self.assertEqual(record["failure_classification"], "UNKNOWN_EXTERNAL_FAILURE")
            self.assertFalse(record["retryable"])
            self.assertEqual(record["group_output_attempt_artifacts"], [])
            self.assertFalse(list(evidence.rglob("group-*-output-attempt-*.json")))
            self.assertNotIn(b"SECRET_SOURCE_MARKER", raw)
            self.assertNotIn(b"structured output failed", raw)

    def test_aggregate_timeout_exception_is_typed_transport_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, _ = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_nonfinal_prompt(prompt_text)
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
                    if not self._group_prompt(prompt_text):
                        completed.append(prompt_text)
                    return self._successful_nonfinal_prompt(prompt_text)
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
            self.assertGreater(len(record["completed_group_artifacts"]),1)
            failure_dir = Path(caught.exception.evidence_path).parent
            self.assertTrue(all((failure_dir / item["path"]).is_file()
                                for item in record["completed_chunk_artifacts"]))
            self.assertTrue(all((failure_dir / item["path"]).is_file()
                                for item in record["completed_group_artifacts"]))
            self.assertEqual(len(list(evidence.rglob("chunk-*.json"))), 17)
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_malformed_aggregate_output_is_nonretryable_and_not_receipted(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))

            def responder(command, prompt_text, env, timeout):
                if not self._aggregate_prompt(prompt_text):
                    return self._successful_nonfinal_prompt(prompt_text)
                return subprocess.CompletedProcess(["claude"], 0, "not-json", "")

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["failure_classification"], "INVALID_REVIEWER_OUTPUT")
            self.assertEqual(record["failure_phase"], "STRUCTURED_OUTPUT_VALIDATION")
            self.assertTrue(record["process_succeeded"])
            self.assertFalse(record["retryable"])
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_group_output_diagnostics_identify_safe_structural_reasons(self):
        valid = {
            "review_result": "PASS", "findings": [], "dispositions": [],
            "summary": "The bounded group preserves the reviewed interfaces and state flows.",
        }
        cases = (
            ("not-json", "JSON_PARSE_FAILED"),
            (json.dumps({"review_result": "PASS", "findings": [], "dispositions": []}),
             "MISSING_REQUIRED_FIELD"),
            (json.dumps({"review_result": "PASS", "findings": []}),
             "MISSING_REQUIRED_FIELD"),
            (json.dumps({**valid, "summary": "short"}), "SUMMARY_TOO_SHORT"),
            (json.dumps({**valid, "summary": "x" * 4001}), "SUMMARY_TOO_LONG"),
            (json.dumps({**valid, "dispositions": {}}), "INVALID_DISPOSITIONS_TYPE"),
            (json.dumps({**valid, "dispositions": [{}]}), "INVALID_DISPOSITION_SHAPE"),
            (json.dumps({**valid, "findings": [{"severity": "P1"}],
                         "review_result": "FAIL"}), "INVALID_FINDING_SHAPE"),
            (json.dumps({**valid, "extra": "SENSITIVE_SOURCE_MARKER"}), "UNEXPECTED_FIELDS"),
            (json.dumps({**valid, "review_result": "PASS",
                         "findings": [{"severity": "P1", "title": "blocker",
                                       "evidence": "bounded evidence"}]}),
             "VERDICT_MISMATCH"),
            (json.dumps({**valid, "review_result": []}), "INVALID_REVIEW_RESULT"),
            (json.dumps({**valid, "review_result": "FAIL",
                         "findings": [{"severity": [], "title": "blocker",
                                       "evidence": "bounded evidence"}]}),
             "INVALID_FINDING_SHAPE"),
            (json.dumps({**valid, "dispositions": [{
                "chunk_index": 0, "finding_index": 0, "source_severity": [],
                "finding_sha256": "0" * 64, "decision": "UPHELD",
                "rationale": "A bounded rationale with enough detail.",
            }]}), "INVALID_DISPOSITION_SHAPE"),
            (json.dumps({**valid, "dispositions": [{
                "chunk_index": 0, "finding_index": 0, "source_severity": "P1",
                "finding_sha256": "0" * 64, "decision": {},
                "rationale": "A bounded rationale with enough detail.",
            }]}), "INVALID_DISPOSITION_SHAPE"),
        )
        for raw, expected in cases:
            with self.subTest(expected=expected):
                diagnostic = review.reviewer_output_diagnostics(
                    raw, require_dispositions=True, allow_summary=True,
                    require_summary=True,
                )
                self.assertEqual(diagnostic["reason_code"], expected)
                self.assertNotIn("SENSITIVE_SOURCE_MARKER", json.dumps(diagnostic))

        wrapped = review.reviewer_output_diagnostics(
            json.dumps({"structured_output": valid}),
            require_dispositions=True, allow_summary=True, require_summary=True,
        )
        self.assertEqual(wrapped["selected_wrapper"], "structured_output")
        self.assertEqual(wrapped["reason_code"], "VALID")
        self.assertTrue(wrapped["summary_present"])
        self.assertEqual(wrapped["summary_character_length"], len(valid["summary"]))

    def test_group_format_retry_accepts_one_malformed_response_without_weakening_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))
            calls = {"group": 0}
            malformed = json.dumps({
                "review_result": "PASS", "findings": [], "dispositions": [],
                "summary": "The bounded group preserves the reviewed interfaces and state flows.",
                "extra": "SENSITIVE_SOURCE_MARKER",
            })
            valid = self._successful_group().stdout

            def responder(command, prompt_text, env, timeout):
                if self._group_prompt(prompt_text):
                    calls["group"] += 1
                    return subprocess.CompletedProcess(
                        ["claude"], 0, malformed if calls["group"] == 1 else valid, "",
                    )
                if self._aggregate_prompt(prompt_text):
                    return subprocess.CompletedProcess(
                        ["claude"], 0,
                        json.dumps({"review_result": "PASS", "findings": [],
                                    "dispositions": []}), "",
                    )
                return self._successful_chunk()

            with contextlib.redirect_stdout(io.StringIO()) as captured:
                self._execute_review(args, responder)
            payload = json.loads(captured.getvalue())
            self.assertEqual(payload["status"], "PASS")
            self.assertEqual(calls["group"], 2)
            attempts = list(evidence.rglob("group-000-output-attempt-*.json"))
            self.assertEqual(len(attempts), 1)
            attempt = json.loads(attempts[0].read_text())
            self.assertEqual(attempt["reason_code"], "UNEXPECTED_FIELDS")
            self.assertEqual(
                attempt["failure_classification"],
                "TRANSIENT_STRUCTURED_OUTPUT_FORMAT_FAILURE",
            )
            self.assertTrue(attempt["retryable"])
            self.assertTrue(attempt["retry_scheduled"])
            self.assertEqual(attempt["reason_code"], "UNEXPECTED_FIELDS")
            self.assertNotIn(b"SENSITIVE_SOURCE_MARKER", attempts[0].read_bytes())
            self.assertTrue(list(evidence.rglob("deepseek-receipt-*.json")))

    def test_group_missing_summary_uses_only_exit_zero_format_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))
            group_calls = 0

            def responder(command, prompt_text, env, timeout):
                nonlocal group_calls
                if self._group_prompt(prompt_text):
                    group_calls += 1
                    if group_calls == 1:
                        return subprocess.CompletedProcess(
                            ["claude"], 0,
                            json.dumps({"review_result":"PASS","findings":[],
                                        "dispositions":[]}), "",
                        )
                    return self._successful_group()
                if self._aggregate_prompt(prompt_text):
                    return subprocess.CompletedProcess(
                        ["claude"], 0,
                        json.dumps({"review_result":"PASS","findings":[],
                                    "dispositions":[]}), "",
                    )
                return self._successful_chunk()

            with contextlib.redirect_stdout(io.StringIO()):
                self._execute_review(args, responder)
            attempts = list(evidence.rglob("group-000-output-attempt-*.json"))
            self.assertEqual(group_calls, 2)
            self.assertEqual(len(attempts), 1)
            attempt = json.loads(attempts[0].read_text())
            self.assertEqual(attempt["reason_code"], "MISSING_REQUIRED_FIELD")
            self.assertEqual(attempt["failure_classification"],
                             "TRANSIENT_STRUCTURED_OUTPUT_FORMAT_FAILURE")
            self.assertTrue(attempt["retry_scheduled"])

    def test_group_format_retry_cap_fails_closed_and_preserves_attempt_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            args, evidence = run_fixture(Path(tmp))
            calls = {"group": 0}
            malformed = json.dumps({
                "review_result": "PASS", "findings": [], "dispositions": [],
                "summary": "The bounded group preserves the reviewed interfaces and state flows.",
                "extra": "SENSITIVE_SOURCE_MARKER",
            })

            def responder(command, prompt_text, env, timeout):
                if self._group_prompt(prompt_text):
                    calls["group"] += 1
                    return subprocess.CompletedProcess(["claude"], 0, malformed, "")
                if self._aggregate_prompt(prompt_text):
                    self.fail("final synthesis must not run after bounded retries fail")
                return self._successful_chunk()

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, raw = self._failure_record(caught)
            self.assertEqual(calls["group"], 2)
            self.assertEqual(record["failure_classification"], "INVALID_REVIEWER_OUTPUT")
            self.assertFalse(record["retryable"])
            self.assertEqual(record["reason_code"], "structured_output_retry_exhausted")
            self.assertEqual(record["failure_phase"], "STRUCTURED_OUTPUT_VALIDATION")
            self.assertTrue(record["process_succeeded"])
            self.assertEqual(len(record["group_output_attempt_artifacts"]), 2)
            self.assertNotIn(b"SENSITIVE_SOURCE_MARKER", raw)
            failure_dir = Path(caught.exception.evidence_path).parent
            for ref in record["group_output_attempt_artifacts"]:
                artifact = failure_dir / ref["path"]
                self.assertTrue(artifact.is_file())
                self.assertNotIn(b"SENSITIVE_SOURCE_MARKER", artifact.read_bytes())
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
                    return self._successful_nonfinal_prompt(prompt_text)
                return subprocess.CompletedProcess(["claude"], 1, "", TEST_SECRET)

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, raw = self._failure_record(caught)
            self.assertEqual(record["reason_code"], "credential_echo_detected")
            self.assertEqual(record["failure_classification"], "POLICY_OR_CONTRACT_FAILURE")
            self.assertEqual(record["failure_phase"], "PROCESS_OR_PROVIDER")
            self.assertFalse(record["process_succeeded"])
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
                    return self._successful_nonfinal_prompt(prompt_text)
                return subprocess.CompletedProcess(
                    ["claude"], 0,
                    json.dumps({"review_result": "PASS", "findings": []}), "",
                )

            with self.assertRaises(review.ReviewAttemptFailure) as caught:
                self._execute_review(args, responder)
            record, _ = self._failure_record(caught)
            self.assertEqual(record["reason_code"], "review_contract_rejected")
            self.assertEqual(record["failure_classification"], "POLICY_OR_CONTRACT_FAILURE")
            self.assertEqual(record["failure_phase"], "REVIEW_CONTRACT_VALIDATION")
            self.assertTrue(record["process_succeeded"])
            self.assertFalse(record["retryable"])
            self.assertFalse(list(evidence.rglob("aggregate.json")))
            self.assertFalse(list(evidence.rglob("deepseek-receipt-*.json")))
