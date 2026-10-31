"""普通源码任务的 Ruff 权威准入回归；固定项目规则真实执行，外部服务不启动。"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from harness.adapters import FootballPredictionAdapter
from harness.factory import FactoryBlocked, git
from harness.factory_container import binding
from harness.factory_project import FootballPredictionContract, review_manifest, scope_binding, verify_target
from harness.factory_remote import run as remote_run
import test_factory_project_integration as integration
from test_factory_preflight_inspection import publication_body


class RuffAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.CanonicalRuntimeIntegrationTests.setUpClass()
        cls.addClassCleanup(integration.CanonicalRuntimeIntegrationTests.doClassCleanups)

    def setUp(self):
        self.fx = integration.CanonicalRuntimeIntegrationTests("test_pr_body_uses_original_trusted_preflight")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.addCleanup(lambda: self.assertEqual(self.fx.starts, [], "不得启动 provider"))

    def base(self, files=None):
        for path, content in (files or {}).items():
            local = self.fx.repo / path
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_text(content)
        if files:
            self.commit(self.fx.repo)
            self.fx.base = git(self.fx.repo, "rev-parse", "HEAD")

    def candidate(self, *paths):
        self.fx.scope["authorized_paths"].extend(paths)
        return self.fx.candidate()

    @staticmethod
    def commit(cwd):
        git(cwd, "add", "--all", "--", ".")
        git(cwd, "-c", "user.name=Offline Ruff regression", "-c", "user.email=test@localhost",
            "commit", "-qm", "Local regression change")

    @staticmethod
    def put(cwd, path, value):
        local = cwd / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(value)

    def rejected(self, spec, cwd):
        with patch.object(self.fx.runtime, "container_gate") as container, \
                patch.object(self.fx.runtime, "prepare_project_review") as provider:
            with self.assertRaisesRegex(FactoryBlocked, "separate policy mission"):
                self.fx.f.checkpoint(spec, cwd)
            container.assert_not_called()
            provider.assert_not_called()

    def unchecked_target(self, spec, cwd, previous):
        target = copy.deepcopy(previous)
        target.update(head=git(cwd, "rev-parse", "HEAD"), tree=git(cwd, "rev-parse", "HEAD^{tree}"))
        target["commit"] = target["head"]
        target["files"] = [p for p in git(cwd, "diff", "--no-ext-diff", "--no-textconv",
            "--name-only", "-z", "--no-renames", spec["base"], target["head"], "--").split("\0") if p]
        target["diff_sha256"] = hashlib.sha256(git(cwd, "diff", "--no-ext-diff", "--no-textconv",
            "--binary", "--no-renames", spec["base"], target["head"], "--").encode()).hexdigest()
        target.update(scope_binding(spec, cwd, target["head"], git))
        target["review_range"] = review_manifest(cwd, target, git)
        return target

    def test_new_nested_ruff_is_rejected_at_real_checkpoint(self):
        spec, cwd, _ = self.candidate("src/ruff.toml")
        self.put(cwd, "src/ruff.toml", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_new_nested_dot_ruff_is_rejected(self):
        spec, cwd, _ = self.candidate("src/deeper/.ruff.toml")
        self.put(cwd, "src/deeper/.ruff.toml", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_new_nested_pyproject_ruff_is_rejected(self):
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", "[tool.ruff.lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_empty_ruff_table_is_still_configuration(self):
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", "[tool.ruff]\n")
        self.rejected(spec, cwd)

    def test_base_ruff_modification_is_rejected(self):
        self.base({"src/ruff.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/ruff.toml")
        self.put(cwd, "src/ruff.toml", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_base_dot_ruff_deletion_is_rejected(self):
        self.base({"src/.ruff.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/.ruff.toml")
        (cwd / "src/.ruff.toml").unlink()
        self.rejected(spec, cwd)

    def test_pyproject_removing_ruff_table_is_rejected(self):
        self.base({"src/pyproject.toml": '[project]\nname = "probe"\n[tool.ruff]\nline-length = 88\n'})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", '[project]\nname = "probe"\n')
        self.rejected(spec, cwd)

    def test_ruff_rename_out_of_discovery_path_is_rejected(self):
        self.base({"src/ruff.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/ruff.toml", "src/business.toml")
        git(cwd, "mv", "src/ruff.toml", "src/business.toml")
        self.rejected(spec, cwd)

    def test_pyproject_rename_is_rejected_from_base(self):
        self.base({"src/pyproject.toml": "[tool.ruff]\nline-length = 88\n"})
        spec, cwd, _ = self.candidate("src/pyproject.toml", "src/metadata.toml")
        git(cwd, "mv", "src/pyproject.toml", "src/metadata.toml")
        self.rejected(spec, cwd)

    def test_earlier_commit_configuration_change_cannot_hide_behind_later_docs(self):
        spec, cwd, _ = self.candidate("src/ruff.toml", "docs/later.md")
        self.put(cwd, "src/ruff.toml", "[lint]\nselect = []\n")
        self.commit(cwd)
        self.put(cwd, "docs/later.md", "A later harmless documentation change.\n")
        self.rejected(spec, cwd)

    def test_unchanged_configs_and_extend_dependency_allow_source_task(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": '[lint]\nselect = ["F"]\n',
                   "src/package/pyproject.toml": "[tool.ruff]\nline-length = 88\n"})
        spec, cwd, target = self.candidate()
        self.assertTrue(verify_target(spec, cwd, target))
        self.assertTrue(binding(spec, cwd, target))

    def test_nested_pyproject_without_ruff_and_unrelated_toml_remain_allowed(self):
        spec, cwd, _ = self.candidate("src/pyproject.toml", "src/business.toml")
        self.put(cwd, "src/pyproject.toml", '[project]\nname = "business"\n')
        self.put(cwd, "src/business.toml", '[business]\nlabel = "not QA"\n')
        target = self.fx.f.checkpoint(spec, cwd)
        self.assertTrue(verify_target(spec, cwd, target))

    def test_only_unrelated_pyproject_metadata_can_change_with_ruff_unchanged(self):
        self.base({"src/pyproject.toml": '[project]\nname = "old"\n[tool.ruff]\nline-length = 88\n'})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", '[project]\nname = "new"\n[tool.ruff]\nline-length = 88\n')
        target = self.fx.f.checkpoint(spec, cwd)
        self.assertTrue(verify_target(spec, cwd, target))

    def test_changing_direct_extend_dependency_is_rejected(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/shared.toml")
        self.put(cwd, "quality/shared.toml", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_deleting_extend_dependency_is_rejected(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/shared.toml")
        (cwd / "quality/shared.toml").unlink()
        self.rejected(spec, cwd)

    def test_extend_chain_cannot_leave_a_second_direct_dependency_unprotected(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": 'extend = "rules.toml"\n',
                   "quality/rules.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/rules.toml")
        self.put(cwd, "quality/rules.toml", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_external_extend_is_refused_without_reading_outside_repository(self):
        self.base({"src/ruff.toml": 'extend = "../../outside.toml"\n'})
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            self.candidate()

    def test_missing_extend_is_refused(self):
        self.base({"src/ruff.toml": 'extend = "../quality/missing.toml"\n'})
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            self.candidate()

    def test_extend_cycle_is_refused(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": 'extend = "../src/ruff.toml"\n'})
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            self.candidate()

    def test_symlink_config_is_refused_without_following_it(self):
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        local = cwd / "src/pyproject.toml"
        local.parent.mkdir()
        local.symlink_to(self.fx.root / "must-not-be-read")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["src/pyproject.toml"])

    def test_ruff_file_mode_change_is_rejected(self):
        self.base({"src/ruff.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/ruff.toml")
        (cwd / "src/ruff.toml").chmod(0o755)
        self.rejected(spec, cwd)


    def test_existing_nested_pyproject_ruff_setting_change_is_rejected(self):
        self.base({"src/pyproject.toml": "[tool.ruff]\nline-length = 88\n"})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", "[tool.ruff]\nline-length = 120\n")
        self.rejected(spec, cwd)

    def test_existing_metadata_pyproject_cannot_add_ruff(self):
        self.base({"src/pyproject.toml": '[project]\nname = "business"\n'})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", '[project]\nname = "business"\n[tool.ruff]\n')
        self.rejected(spec, cwd)

    def test_base_pyproject_ruff_deletion_is_rejected(self):
        self.base({"src/pyproject.toml": "[tool.ruff]\nline-length = 88\n"})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        (cwd / "src/pyproject.toml").unlink()
        self.rejected(spec, cwd)

    def test_rename_into_discovered_ruff_name_is_rejected(self):
        self.base({"src/business.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/business.toml", "src/ruff.toml")
        git(cwd, "mv", "src/business.toml", "src/ruff.toml")
        self.rejected(spec, cwd)

    def test_renaming_extend_dependency_is_rejected(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/shared.toml", "quality/moved.toml")
        git(cwd, "mv", "quality/shared.toml", "quality/moved.toml")
        self.rejected(spec, cwd)

    def test_extend_dependency_is_protected_even_without_toml_suffix(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.rules"\n',
                   "quality/shared.rules": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/shared.rules")
        self.put(cwd, "quality/shared.rules", "[lint]\nselect = []\n")
        self.rejected(spec, cwd)

    def test_extend_dependency_symlink_type_change_is_rejected_without_following(self):
        self.base({"src/ruff.toml": 'extend = "../quality/shared.toml"\n',
                   "quality/shared.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("quality/shared.toml")
        local = cwd / "quality/shared.toml"
        local.unlink()
        local.symlink_to(self.fx.root / "must-not-be-read")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["quality/shared.toml"])

    def test_configuration_file_to_directory_change_is_rejected(self):
        self.base({"src/ruff.toml": '[lint]\nselect = ["F"]\n'})
        spec, cwd, _ = self.candidate("src/ruff.toml", "src/ruff.toml/child.txt")
        (cwd / "src/ruff.toml").unlink()
        self.put(cwd, "src/ruff.toml/child.txt", "business metadata\n")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "Ruff.*separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["src/ruff.toml/child.txt"])

    def test_malformed_pyproject_is_an_explicit_unknown_authority_refusal(self):
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", "[tool.ruff\n")
        self.rejected(spec, cwd)

    def test_environment_extended_path_is_not_read_or_expanded(self):
        self.base({"src/ruff.toml": 'extend = "$HOME/not-a-repository-config.toml"\n'})
        with self.assertRaisesRegex(ValueError, "cannot safely resolve extend.*separate policy mission"):
            self.candidate()

    def test_absolute_extend_is_not_read(self):
        self.base({"src/ruff.toml": 'extend = "/not-a-repository-config.toml"\n'})
        with self.assertRaisesRegex(ValueError, "cannot safely resolve extend.*separate policy mission"):
            self.candidate()

    def test_ruff_value_type_changes_are_not_metadata_only(self):
        self.base({"src/pyproject.toml": "[tool.ruff]\nunsafe-fixes = true\n"})
        spec, cwd, _ = self.candidate("src/pyproject.toml")
        self.put(cwd, "src/pyproject.toml", "[tool.ruff]\nunsafe-fixes = 1\n")
        self.rejected(spec, cwd)

    def test_candidate_authorization_markers_do_not_allow_configuration_change(self):
        spec, cwd, _ = self.candidate("src/ruff.toml")
        self.put(cwd, "src/ruff.toml", "# owner-approved = true\n[lint]\nselect = []\n")
        self.commit(cwd)
        spec = {**spec, "allow_qa_changes": True}
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["src/ruff.toml"])

    def test_actual_verify_container_binding_and_remote_entry_reject_before_actions(self):
        spec, cwd, previous = self.candidate("src/ruff.toml")
        self.put(cwd, "src/ruff.toml", "[lint]\nselect = []\n")
        self.commit(cwd)
        target = self.unchecked_target(spec, cwd, previous)
        for entry in (verify_target, binding):
            with self.subTest(entry=entry.__name__), self.assertRaisesRegex(ValueError, "separate policy mission"):
                entry(spec, cwd, target)
        remote = Mock(adapter=FootballPredictionAdapter())
        with patch("harness.factory_remote.Remote", return_value=remote):
            with self.assertRaisesRegex(ValueError, "separate policy mission"):
                remote_run("publish", {}, spec, cwd, target, publication_body(self.fx, target),
                           self.fx.root / "remote.raw", 5)
        remote.publish.assert_not_called()
        remote.command.assert_not_called()
        remote.api.assert_not_called()

    def test_partial_paths_argument_does_not_hide_full_base_configuration_change(self):
        spec, cwd, _ = self.candidate("src/ruff.toml")
        self.put(cwd, "src/ruff.toml", "[lint]\nselect = []\n")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])

    def test_original_root_authority_scope_and_identity_still_reject(self):
        spec, cwd, target = self.candidate()
        for path in ("ruff.toml", ".ruff.toml", "pyproject.toml", "scripts/devops/quality.py"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "separate policy mission"):
                FootballPredictionContract().policy(spec, cwd, [path])
        bad = {**target, "head": "0" * 40}
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_target(spec, cwd, bad)
        with self.assertRaisesRegex(ValueError, "scope/policy rejected"):
            FootballPredictionContract().policy(spec, cwd, ["unauthorized.py"])

    def test_original_ruff_still_supports_nested_config_but_admission_rejects_change(self):
        source = integration.require_source()
        original = subprocess.check_output(["git", "-C", str(source), "show",
            integration.PROJECT_BASE + ":ruff.toml"], timeout=10)
        self.base({"ruff.toml": original.decode()})
        spec, cwd, _ = self.candidate("src/probe.py", "src/ruff.toml")
        self.put(cwd, "src/probe.py", "import os\n")
        first = self.fx.f.checkpoint(spec, cwd)
        git(cwd, "update-ref", "refs/remotes/origin/main", spec["base"])
        helper = self.fx.snapshot / "scripts/devops/static_quality_changed_lines.py"
        env = {**os.environ, "GITHUB_BASE_REF": "main", "BASE_REF": spec["base"], "HEAD_REF": first["head"]}
        def check(label):
            value = subprocess.run([sys.executable, "-B", str(helper), "src/probe.py"],
                cwd=cwd, env=env, capture_output=True, text=True, timeout=15)
            directory = os.environ.get("HARNESS_RUFF_EVIDENCE_DIR")
            if directory:
                out = Path(directory)
                (out / (label + ".stdout.raw")).write_text(value.stdout)
                (out / (label + ".stderr.raw")).write_text(value.stderr)
                (out / (label + ".invocation.json")).write_text(json.dumps(
                    {"argv": value.args, "cwd": str(cwd), "exit_code": value.returncode,
                     "root_sha256": hashlib.sha256((cwd / "ruff.toml").read_bytes()).hexdigest(),
                     "source_sha256": hashlib.sha256((cwd / "src/probe.py").read_bytes()).hexdigest(),
                     "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest()}, indent=2) + "\n")
            return value
        before = check("ruff-before")
        self.assertEqual(before.returncode, 1, before.stderr)
        self.assertIn("F401", before.stdout + before.stderr)
        self.put(cwd, "src/ruff.toml", 'extend = "../ruff.toml"\n[lint]\nselect = []\nextend-select = []\n')
        after = check("ruff-after")
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual((cwd / "ruff.toml").read_bytes(), original)
        self.rejected(spec, cwd)


if __name__ == "__main__":
    unittest.main()
