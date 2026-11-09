"""Real admission subprocesses, pinned legacy planner and explicit protocol doubles.

The selector double tests query plumbing, not FP semantics or review validity.
Exact new-FP integration is a separate no-provider check; CI needs no private path.
"""

from datetime import datetime, timedelta, timezone
import json
import io
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from footballprediction_contract import CONTRACT_HEAD, read_git, require_source
from harness.adapters import FootballPredictionAdapter
from harness.factory import Factory, FactoryBlocked, git
from harness.factory_project import FootballPredictionContract
import test_factory_project as project_fixtures


LIMITS = {
    "approval_id": "TEST-only-no-provider",
    "max_deepseek_chunks": 8,
    "max_canonical_diff_bytes": 100000,
    "allow_unknown_provider_usage": True,
}

# Fixed two-part protocol double, deliberately not a copy of FP's planner.
# Only the subprocess query under test decides selector/fallback/dispatch counts.
SELECTOR_DOUBLE = """
from types import SimpleNamespace
MAX_CHUNK_DIFF_BYTES=32000
MAX_CHUNK_PROMPT_BYTES=40000
VERSION='TEST-only/frozen-input'
def source_context_version_for(mission):
    assert mission=='selector-fixture'
    return VERSION
class Manifest:
    def __init__(self, diff, version):
        self.source_context_version=version
        cut=len(diff)//2
        self.chunks=([SimpleNamespace(index=0,start=0,end=len(diff))] if COUNT==1 else
            [SimpleNamespace(index=0,start=0,end=cut),SimpleNamespace(index=1,start=cut,end=len(diff))])
    def payload(self):
        return dict(TEST_ONLY=True,version=self.source_context_version,count=len(self.chunks))
def plan(diff, **kwargs):
    assert kwargs['source_context_version']==VERSION, 'wrong selected version'
    assert kwargs['repo_root'].is_dir(), 'missing Git source root'
    return Manifest(diff, MANIFEST_VERSION)
def build_chunk_prompt(*, chunk, source, manifest, scope_sha):
    # Multibyte text exposes a character-count capacity bug; later chunks differ.
    return '界' * (13000 if chunk.index==0 else LAST_PROMPT_CHARS)
"""


class AdmissionQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "candidate"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "score.py").write_text("# TEST-only source\n")
        self.commit()
        self.base = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "score.py").write_text("# TEST-only source change\n")
        self.commit()
        self.trusted = self.root / "trusted-query-double"
        self.module = self.trusted / "scripts/devops/deepseek_review_chunks.py"
        self.module.parent.mkdir(parents=True)
        self.write_double()
        self.spec = {"mission_id": "selector-fixture"}
        self.target = self.target_for(self.repo, self.base)
        self.adapter = FootballPredictionAdapter()
        self.contract = FootballPredictionContract(self.adapter)

    def commit(self):
        git(self.repo, "add", ".")
        git(
            self.repo,
            "-c",
            "user.name=TEST-only",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-qm",
            "TEST-only query fixture",
        )

    @staticmethod
    def target_for(repo, base):
        return {
            "base": base,
            "head": git(repo, "rev-parse", "HEAD"),
            "mission_scope_sha256": "c" * 64,
            "scope_approval_id": "TEST-only",
        }

    def write_double(self, *, count=2, last=12000, extra=""):
        self.module.write_text(
            SELECTOR_DOUBLE
            + f"\nCOUNT={count}\nLAST_PROMPT_CHARS={last}\nMANIFEST_VERSION=VERSION\n"
            + extra
        )

    def admit(self, limits=None):
        # Only query plumbing is isolated here. Full source/target checks are
        # covered by existing integration and the separate exact-FP check.
        with (
            patch("harness.factory_project.verify_target"),
            patch.object(self.adapter, "_trusted_base_checkout", return_value=self.trusted),
        ):
            return self.contract.review_admission(
                self.spec, self.repo, self.target, limits or LIMITS
            )

    def test_selector_drives_small_diff_protocol_count_and_all_utf8_prompt_sizes(self):
        result = self.admit()
        self.assertLess(result["canonical_diff_bytes"], 32000)
        self.assertTrue(result["chunked"])
        self.assertEqual(result["deepseek_backend_runs"], 2)
        self.assertEqual(result["chunk_manifest"]["version"], "TEST-only/frozen-input")
        self.assertEqual(result["chunk_prompt_bytes"], [39000, 36000])

    def test_frozen_single_chunk_still_uses_chunk_protocol_and_checks_prompt(self):
        self.write_double(count=1)
        result = self.admit()
        self.assertTrue(result["chunked"])
        self.assertEqual(result["deepseek_backend_runs"], 1)
        self.assertEqual(result["chunk_prompt_bytes"], [39000])

    def test_later_final_prompt_over_utf8_limit_is_rejected(self):
        self.write_double(last=13334)  # 40002 bytes, only 13334 characters.
        with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
            self.admit()

    def test_chunk_and_full_diff_authorizations_remain_fail_closed(self):
        result = self.admit()
        for field, value in (
            ("max_deepseek_chunks", 1),
            ("max_canonical_diff_bytes", result["canonical_diff_bytes"] - 1),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "zero dispatch"):
                self.admit({**LIMITS, field: value})

    def test_broken_selector_never_falls_back_to_valid_legacy_constants(self):
        legacy = "\nSOURCE_CONTEXT_MISSION='selector-fixture'\nSOURCE_CONTEXT_VERSION=VERSION\n"
        cases = [
            "source_context_version_for=None\n",
            "def source_context_version_for(mission): raise RuntimeError('TEST-only')\n",
            "def source_context_version_for(mission): return 'unknown-version'\n",
            "def source_context_version_for(mission): return ''\n",
            "def source_context_version_for(mission): return False\n",
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                self.write_double(extra=legacy + extra)
                with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
                    self.admit()

    def test_manifest_cannot_disagree_with_selected_version(self):
        self.write_double(extra="MANIFEST_VERSION='wrong-version'\n")
        with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
            self.admit()

    def test_incomplete_legacy_interface_is_not_treated_as_no_context(self):
        for extra in (
            "SOURCE_CONTEXT_MISSION='selector-fixture'\n",
            "SOURCE_CONTEXT_VERSION='old-version'\n",
            "SOURCE_CONTEXT_MISSION=None\nSOURCE_CONTEXT_VERSION='old-version'\n",
        ):
            with self.subTest(extra=extra):
                self.write_double(extra="del source_context_version_for\n" + extra)
                with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
                    self.admit()

    def test_candidate_cannot_supply_or_override_trusted_selector(self):
        candidate_module = self.repo / "scripts/devops/deepseek_review_chunks.py"
        candidate_module.parent.mkdir(parents=True)
        candidate_module.write_text("raise AssertionError('candidate protocol must not execute')\n")
        self.commit()
        self.target = self.target_for(self.repo, self.base)
        self.assertEqual(self.admit()["deepseek_backend_runs"], 2)

    def test_query_rejects_wrong_head_or_dirty_source(self):
        actual = self.target
        self.target = {**actual, "head": "0" * 40}
        with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
            self.admit()
        self.target = actual
        (self.repo / "untracked.txt").write_text("TEST-only dirty source")
        with self.assertRaisesRegex(ValueError, "planning failed before dispatch"):
            self.admit()

    def test_two_chunk_query_rejects_before_factory_paid_reservation_or_backend(self):
        fx = project_fixtures.ProjectContractTests(
            "test_scope_materialized_only_in_candidate_and_bound_to_exact_head"
        )
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        runtime = project_fixtures.ProjectRuntime()
        runtime.simulation = False
        runtime.project_review_admission = lambda spec, cwd, target, limits: (
            self.contract.review_admission(spec, cwd, target, limits)
        )
        runtime.prepare_project_review = Mock(side_effect=AssertionError("backend preparation"))
        runtime.project_review = Mock(side_effect=AssertionError("backend start"))
        config = {
            **fx.config,
            "simulation": False,
            "project_review_limits": {**LIMITS, "max_deepseek_chunks": 1},
        }
        factory = Factory(self.root / "TEST-only-reservation-state", config, runtime)
        self.addCleanup(factory.close)
        spec = {**fx.spec, "mission_id": "selector-fixture"}
        scope = json.loads(spec["approved_mission_scope"]["content"])
        scope["mission_id"] = spec["mission_id"]
        path = "docs/agentic/missions/selector-fixture.json"
        scope["authorized_paths"] = ["score.py", path]
        content = json.dumps(scope) + "\n"
        from harness.factory_project import sha256

        spec.update(scope=scope["authorized_paths"], mission_scope_file=path)
        spec["approved_mission_scope"] = {
            **spec["approved_mission_scope"],
            "path": path,
            "mission_id": spec["mission_id"],
            "content": content,
            "sha256": sha256(content.encode()),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
        factory.submit(spec)
        spec, cwd = factory.prepare(spec["mission_id"])
        (cwd / "score.py").write_text("# TEST-only changed source\n")
        target = factory.checkpoint(spec, cwd)
        with (
            patch("harness.factory_preflight.inspect_prepaid", return_value={"findings": []}),
            patch("harness.factory_project.verify_target"),
            patch.object(self.adapter, "_trusted_base_checkout", return_value=self.trusted),
        ):
            with self.assertRaisesRegex(FactoryBlocked, "zero dispatch"):
                factory.project_review(spec, cwd, target, "second_reviewer")
        self.assertEqual(
            factory.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0
        )
        runtime.prepare_project_review.assert_not_called()
        runtime.project_review.assert_not_called()
        self.assertEqual(runtime.calls, [])


class LegacyPlannerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Mandatory exact old pin, never current main or an optional skip.
        source = require_source()
        cls.snapshot_tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.snapshot_tmp.cleanup)
        cls.snapshot = Path(cls.snapshot_tmp.name)
        cls.source = source
        archive = read_git(source, "archive", CONTRACT_HEAD, "scripts")
        with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
            stream.extractall(cls.snapshot, filter="data")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "TEST-only-candidate"
        self.repo.mkdir()
        for name in (
            "tests/unit/test_project_knowledge_convergence.py",
            "scripts/ops/ai_workflow_gate.py",
            "scripts/ops/helpers/pr_authorization_matrix.py",
            "scripts/ops/helpers/pr_authorization_rules.py",
        ):
            dest = self.repo / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(read_git(self.source, "show", f"{CONTRACT_HEAD}:{name}"))
        git(self.repo, "init", "-q")
        (self.repo / "score.py").write_text("# TEST-only base\n")
        self.commit()
        self.base = git(self.repo, "rev-parse", "HEAD")
        self.trusted = self.snapshot

    def commit(self):
        git(self.repo, "add", ".")
        git(
            self.repo,
            "-c",
            "user.name=TEST-only",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-qm",
            "TEST-only legacy fixture",
        )

    def admit(self, mission, text):
        (self.repo / "score.py").write_text(text)
        self.commit()
        target = AdmissionQueryTests.target_for(self.repo, self.base)
        adapter = FootballPredictionAdapter()
        with (
            patch("harness.factory_project.verify_target"),
            patch.object(adapter, "_trusted_base_checkout", return_value=self.trusted),
        ):
            return FootballPredictionContract(adapter).review_admission(
                {"mission_id": mission}, self.repo, target, LIMITS
            )

    def test_real_legacy_ordinary_small_diff_uses_one_nonchunk_backend(self):
        result = self.admit("ordinary-fixture", "# TEST-only small change\n")
        self.assertFalse(result["chunked"])
        self.assertEqual(result["deepseek_backend_runs"], 1)
        self.assertEqual(result["chunk_prompt_bytes"], [])

    def test_real_legacy_large_diff_counts_all_manifest_chunks(self):
        result = self.admit("ordinary-fixture", "".join(f"value_{i}={i}\n" for i in range(3000)))
        self.assertTrue(result["chunked"])
        self.assertGreater(result["deepseek_backend_runs"], 1)
        self.assertEqual(result["deepseek_backend_runs"], result["chunk_manifest"]["chunk_count"])
        self.assertEqual(len(result["chunk_prompt_bytes"]), result["deepseek_backend_runs"])
        self.assertTrue(all(n <= 40000 for n in result["chunk_prompt_bytes"]))

    def test_real_legacy_frozen_context_uses_its_original_protocol(self):
        result = self.admit(
            "FP_CANONICAL_CONTRACT_BACKFLOW_MINIMAL_FIX", "# TEST-only old mission\n"
        )
        self.assertTrue(result["chunked"])
        self.assertEqual(
            result["chunk_manifest"]["source_context_version"], "frozen-git-source-context/v1"
        )
        self.assertEqual(result["deepseek_backend_runs"], result["chunk_manifest"]["chunk_count"])
        self.assertTrue(result["chunk_prompt_bytes"])
        self.assertTrue(all(n <= 40000 for n in result["chunk_prompt_bytes"]))

    def test_pre_context_signature_receives_only_supported_arguments(self):
        # Explicit old-interface double delegates to the pinned planner, which
        # still computes the diff partition. No version/mission map is added.
        self.trusted = self.root / "pre-context-interface-double"
        shutil.copytree(self.snapshot, self.trusted)
        module = self.trusted / "scripts/devops/deepseek_review_chunks.py"
        module.rename(module.with_name("legacy_planner.py"))
        module.write_text("""from scripts.devops import legacy_planner as old
MAX_CHUNK_DIFF_BYTES=old.MAX_CHUNK_DIFF_BYTES
MAX_CHUNK_PROMPT_BYTES=old.MAX_CHUNK_PROMPT_BYTES
build_chunk_prompt=old.build_chunk_prompt
def plan(diff, *, base_sha, head_sha, mission_id, mission_scope_sha256):
    return old.plan(diff, base_sha=base_sha, head_sha=head_sha, mission_id=mission_id,
                    mission_scope_sha256=mission_scope_sha256)
""")
        result = self.admit("ordinary-fixture", "# TEST-only no-context API\n")
        self.assertFalse(result["chunked"])
        self.assertEqual(result["deepseek_backend_runs"], 1)


if __name__ == "__main__":
    unittest.main()
