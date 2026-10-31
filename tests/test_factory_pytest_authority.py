"""固定 pytest 9.0.2 配置权威：真实准入和原验证计划，纯本地 Git/pytest。"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import unittest
from unittest.mock import Mock, patch

from harness.adapters import FootballPredictionAdapter
from harness.factory import FactoryBlocked, git
from harness.factory_container import binding
from harness.factory_project import FootballPredictionContract, review_manifest, scope_binding, verify_target
from harness.factory_remote import run as remote_run
import test_factory_project_integration as integration
from test_factory_preflight_inspection import publication_body


class PytestAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        integration.CanonicalRuntimeIntegrationTests.setUpClass()
        cls.addClassCleanup(integration.CanonicalRuntimeIntegrationTests.doClassCleanups)
        cls.original = integration.require_source()

    def setUp(self):
        self.fx = integration.CanonicalRuntimeIntegrationTests("test_pr_body_uses_original_trusted_preflight")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.addCleanup(lambda: self.assertEqual(self.fx.starts, [], "不得启动 provider"))
        self.base({"pytest.ini": (self.original / "pytest.ini").read_text()})

    @staticmethod
    def put(cwd, path, value):
        local = cwd / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(value)

    @staticmethod
    def commit(cwd):
        git(cwd, "add", "--all", "--", ".")
        git(cwd, "-c", "user.name=Offline pytest regression", "-c", "user.email=test@localhost",
            "commit", "-qm", "Local regression change")

    def base(self, files):
        for path, value in files.items():
            self.put(self.fx.repo, path, value)
        self.commit(self.fx.repo)
        self.fx.base = git(self.fx.repo, "rev-parse", "HEAD")

    def candidate(self, *paths):
        self.fx.scope["authorized_paths"].extend(paths)
        return self.fx.candidate()

    def rejected(self, spec, cwd, reason="separate policy mission"):
        with patch.object(self.fx.runtime, "container_gate") as container, \
                patch.object(self.fx.runtime, "prepare_project_review") as provider, \
                patch("harness.factory_remote.Remote") as remote:
            with self.assertRaisesRegex(FactoryBlocked, reason):
                self.fx.f.checkpoint(spec, cwd)
            container.assert_not_called()
            provider.assert_not_called()
            remote.assert_not_called()
        self.assertEqual(self.fx.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0)

    def allowed(self, spec, cwd):
        target = self.fx.f.checkpoint(spec, cwd)
        self.assertTrue(verify_target(spec, cwd, target))
        return target

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

    def test_nested_pytest_ini_rejected_before_external_actions(self):
        spec, cwd, _ = self.candidate("tests/unit/pytest.ini")
        self.put(cwd, "tests/unit/pytest.ini", "[pytest]\npython_functions = allowed_*\n")
        self.rejected(spec, cwd)

    def test_current_discovery_names_and_sections_are_protected(self):
        configs = {
            ".pytest.ini": "[pytest]\npython_functions = allowed_*\n",
            "pytest.toml": '[pytest]\npython_functions = ["allowed_*"]\n',
            ".pytest.toml": '[pytest]\npython_functions = ["allowed_*"]\n',
            "tox.ini": "[pytest]\npython_functions = allowed_*\n",
            "setup.cfg": "[tool:pytest]\npython_functions = allowed_*\n",
            "pyproject.toml": '[tool.pytest.ini_options]\npython_functions = ["allowed_*"]\n',
        }
        spec, cwd, _ = self.candidate(*(f"tests/deep/{name}" for name in configs))
        for name, content in configs.items():
            with self.subTest(name=name):
                path = f"tests/deep/{name}"
                self.put(cwd, path, content)
                self.rejected(spec, cwd)
                (cwd / path).unlink()
        self.put(cwd, "tests/deep/pyproject.toml", '[tool.pytest]\npython_functions = ["allowed_*"]\n')
        self.rejected(spec, cwd)

    def test_empty_exclusive_files_still_change_selection(self):
        names = ("pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml")
        spec, cwd, _ = self.candidate(*(f"package/{n}" for n in names))
        for name in names:
            with self.subTest(name=name):
                self.put(cwd, "package/" + name, "")
                self.rejected(spec, cwd)
                (cwd / ("package/" + name)).unlink()

    def test_empty_applicable_tables_are_protected(self):
        spec, cwd, _ = self.candidate("tests/pyproject.toml", "tests/tox.ini", "tests/setup.cfg")
        for name, content in [("pyproject.toml", "[tool.pytest.ini_options]\n"),
                              ("pyproject.toml", "[tool.pytest]\n"),
                              ("tox.ini", "[pytest]\n"), ("setup.cfg", "[tool:pytest]\n")]:
            with self.subTest(name=name, content=content):
                self.put(cwd, "tests/" + name, content)
                self.rejected(spec, cwd)
                (cwd / ("tests/" + name)).unlink()

    def test_modified_base_configuration_is_rejected(self):
        self.base({"tests/unit/setup.cfg": "[metadata]\nname = fixed\n[tool:pytest]\npython_functions = test_*\n"})
        spec, cwd, _ = self.candidate("tests/unit/setup.cfg")
        self.put(cwd, "tests/unit/setup.cfg", "[metadata]\nname = fixed\n[tool:pytest]\npython_functions = allowed_*\n")
        self.rejected(spec, cwd)

    def test_deletion_cannot_reveal_lower_priority_configuration(self):
        self.base({"tests/unit/pytest.toml": '[pytest]\npython_functions = ["test_*"]\n',
                   "tests/unit/pytest.ini": "[pytest]\npython_functions = allowed_*\n"})
        spec, cwd, _ = self.candidate("tests/unit/pytest.toml")
        (cwd / "tests/unit/pytest.toml").unlink()
        self.rejected(spec, cwd)

    def test_removing_pytest_table_is_not_metadata_only(self):
        self.base({"tests/unit/pyproject.toml": '[project]\nname = "fixed"\n[tool.pytest.ini_options]\n'})
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml")
        self.put(cwd, "tests/unit/pyproject.toml", '[project]\nname = "fixed"\n')
        self.rejected(spec, cwd)

    def test_rename_out_of_discovery_name_is_rejected(self):
        self.base({"tests/unit/tox.ini": "[pytest]\npython_functions = test_*\n"})
        spec, cwd, _ = self.candidate("tests/unit/tox.ini", "tests/unit/business.ini")
        git(cwd, "mv", "tests/unit/tox.ini", "tests/unit/business.ini")
        self.rejected(spec, cwd)

    def test_rename_into_discovery_name_is_rejected(self):
        self.base({"tests/unit/business.cfg": "[tool:pytest]\npython_functions = test_*\n"})
        spec, cwd, _ = self.candidate("tests/unit/business.cfg", "tests/unit/setup.cfg")
        git(cwd, "mv", "tests/unit/business.cfg", "tests/unit/setup.cfg")
        self.rejected(spec, cwd)

    def test_mode_change_with_identical_pytest_table_is_rejected(self):
        self.base({"tests/unit/pyproject.toml": "[tool.pytest.ini_options]\n"})
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml")
        (cwd / "tests/unit/pyproject.toml").chmod(0o755)
        self.rejected(spec, cwd)

    def test_file_to_directory_change_is_rejected(self):
        self.base({"tests/unit/tox.ini": "[pytest]\n"})
        spec, cwd, _ = self.candidate("tests/unit/tox.ini", "tests/unit/tox.ini/metadata.txt")
        (cwd / "tests/unit/tox.ini").unlink()
        self.put(cwd, "tests/unit/tox.ini/metadata.txt", "business\n")
        self.rejected(spec, cwd, "does not certify symlinks/submodules")
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])

    def test_earlier_configuration_commit_is_not_hidden_by_latest_source_change(self):
        spec, cwd, _ = self.candidate("tests/unit/pytest.ini")
        self.put(cwd, "tests/unit/pytest.ini", "[pytest]\n")
        self.commit(cwd)
        self.put(cwd, "score.py", "def score():\n    return 3\n")
        self.rejected(spec, cwd)

    def test_partial_caller_paths_do_not_limit_authority_check(self):
        spec, cwd, _ = self.candidate("tests/unit/tox.ini")
        self.put(cwd, "tests/unit/tox.ini", "[pytest]\n")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])

    def test_unrelated_metadata_edit_preserves_identical_pytest_sections(self):
        self.base({"tests/unit/pyproject.toml": '[project]\nname = "old"\n[tool.pytest.ini_options]\naddopts = "-q"\n',
                   "tests/unit/setup.cfg": "[tool:pytest]\naddopts = -q\n[metadata]\nname = old\n",
                   "tests/unit/tox.ini": "[pytest]\naddopts = -q\n[tox]\nenvlist = old\n"})
        paths = ["tests/unit/pyproject.toml", "tests/unit/setup.cfg", "tests/unit/tox.ini"]
        spec, cwd, _ = self.candidate(*paths)
        for path in paths:
            self.put(cwd, path, (cwd / path).read_text().replace("old", "new"))
        self.allowed(spec, cwd)

    def test_unrelated_new_metadata_and_other_ini_cfg_toml_are_allowed(self):
        values = {"src/pyproject.toml": '[project]\nname = "metadata"\n',
                  "tests/unit/tox.ini": "[tox]\nenvlist = py\n",
                  "tests/unit/setup.cfg": "[metadata]\nname = business\n",
                  "tests/unit/business.toml": '[pytest]\npython_functions = ["allowed_*"]\n',
                  "tests/unit/business.ini": "[pytest]\npython_functions = allowed_*\n"}
        spec, cwd, _ = self.candidate(*values)
        for path, value in values.items():
            self.put(cwd, path, value)
        self.allowed(spec, cwd)

    def test_fully_unchanged_nested_configs_allow_source_task(self):
        self.base({"tests/unit/tox.ini": "[pytest]\naddopts = -q\n",
                   "src/.pytest.toml": "[pytest]\n"})
        spec, cwd, target = self.candidate()
        self.assertTrue(verify_target(spec, cwd, target))
        self.assertTrue(binding(spec, cwd, target))

    def test_symlink_configuration_is_refused_without_following_target(self):
        spec, cwd, _ = self.candidate("tests/unit/setup.cfg")
        local = cwd / "tests/unit/setup.cfg"
        local.parent.mkdir(parents=True)
        local.symlink_to(self.fx.root / "must-not-read")
        self.rejected(spec, cwd, "does not certify symlinks/submodules")
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])
        self.assertFalse((self.fx.root / "must-not-read").exists())

    def test_unsupported_git_entry_is_refused(self):
        spec, cwd, _ = self.candidate("tests/unit/tox.ini")
        git(cwd, "update-index", "--add", "--cacheinfo", "160000",
            git(cwd, "rev-parse", "HEAD"), "tests/unit/tox.ini")
        git(cwd, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "gitlink fixture")
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])

    def test_unparseable_or_ambiguous_configuration_is_explicitly_refused(self):
        spec, cwd, _ = self.candidate("tests/unit/tox.ini", "tests/unit/setup.cfg")
        for path, value in [("tests/unit/tox.ini", "[pytest\n"),
                            ("tests/unit/setup.cfg", "[pytest]\naddopts = -q\n"),
                            ("tests/unit/tox.ini", "[pytest]\nx = 1\nx = 2\n")]:
            with self.subTest(path=path, value=value):
                self.put(cwd, path, value)
                self.rejected(spec, cwd)
                (cwd / path).unlink()

    def test_fake_candidate_authorization_does_not_authorize_pytest_change(self):
        spec, cwd, _ = self.candidate("tests/unit/tox.ini")
        self.put(cwd, "tests/unit/tox.ini", "# owner-approved = true\n[pytest]\n")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy({**spec, "allow_qa_changes": True}, cwd, ["score.py"])

    def test_ini_comment_brackets_cannot_hide_actual_pytest_section(self):
        spec, cwd, _ = self.candidate("tests/unit/tox.ini")
        self.put(cwd, "tests/unit/tox.ini", "[pytest] # [comment]\npython_functions = allowed_*\n")
        self.rejected(spec, cwd)

    def test_verify_container_binding_and_remote_entry_refuse_before_io(self):
        spec, cwd, previous = self.candidate("tests/unit/pytest.ini")
        self.put(cwd, "tests/unit/pytest.ini", "[pytest]\npython_functions = allowed_*\n")
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

    def test_root_authority_scope_and_identity_checks_remain(self):
        spec, cwd, target = self.candidate()
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["pytest.ini"])
        with self.assertRaisesRegex(ValueError, "scope/policy rejected"):
            FootballPredictionContract().policy(spec, cwd, ["unauthorized.py"])
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify_target(spec, cwd, {**target, "head": "0" * 40})

    def canonical_pytest(self, cwd, target, label):
        planner = runpy.run_path(str(self.original / "scripts/devops/validation_profiles.py"))["_profile_command_plan"]
        plan = planner("targeted", target["files"])
        argv = next(argv for name, argv, _ in plan if name == "changed Python tests")
        collection = subprocess.run([*argv, "--collect-only", "-q"], cwd=cwd, capture_output=True, text=True, timeout=15)
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=15)
        root = os.environ.get("CMH_PYTEST_AUTHORITY_EVIDENCE")
        if root:
            out = Path(root)
            out.mkdir(parents=True, exist_ok=True)
            for name, value in [("collect", collection), ("run", result)]:
                (out / f"{label}.{name}.stdout.raw").write_text(value.stdout)
                (out / f"{label}.{name}.stderr.raw").write_text(value.stderr)
            (out / f"{label}.json").write_text(json.dumps({"plan": plan, "argv": argv,
                "collect_argv": collection.args, "collect_exit": collection.returncode,
                "run_exit": result.returncode, "provider_starts": self.fx.starts}, indent=2) + "\n")
        return collection, result

    def test_normal_collection_preserves_failing_test(self):
        test = "tests/unit/test_policy_probe.py"
        spec, cwd, _ = self.candidate(test)
        self.put(cwd, test, "def test_should_fail():\n    assert False\n\n\ndef allowed_control():\n    pass\n")
        target = self.allowed(spec, cwd)
        collected, result = self.canonical_pytest(cwd, target, "normal-failure-preserved")
        self.assertEqual(collected.returncode, 0)
        self.assertIn("test_policy_probe.py::test_should_fail", collected.stdout)
        self.assertNotIn("::allowed_control", collected.stdout)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("test_should_fail", result.stdout)

    def test_normal_passing_test_source_task_continues(self):
        test = "tests/unit/test_normal.py"
        spec, cwd, _ = self.candidate(test)
        self.put(cwd, test, "def test_first():\n    assert True\n\n\ndef test_second():\n    assert 1 == 1\n")
        target = self.allowed(spec, cwd)
        collected, result = self.canonical_pytest(cwd, target, "normal-source")
        self.assertEqual(collected.returncode, 0)
        for name in ("test_first", "test_second"):
            self.assertIn("test_normal.py::" + name, collected.stdout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def without_base_config(self):
        (self.fx.repo / "pytest.ini").unlink()
        self.commit(self.fx.repo)
        self.fx.base = git(self.fx.repo, "rev-parse", "HEAD")

    def test_no_configuration_still_allows_normal_source(self):
        self.without_base_config()
        spec, cwd, target = self.candidate()
        self.assertTrue(verify_target(spec, cwd, target))

    def test_pyproject_fallback_root_change_without_pytest_table_is_rejected(self):
        self.without_base_config()
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml")
        self.put(cwd, "tests/unit/pyproject.toml", '[project]\nname = "fallback-root"\n')
        self.rejected(spec, cwd)

    def test_unchanged_pyproject_fallback_metadata_edit_is_allowed(self):
        self.without_base_config()
        self.base({"tests/unit/pyproject.toml": '[project]\nname = "old"\n'})
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml")
        self.put(cwd, "tests/unit/pyproject.toml", '[project]\nname = "new"\n')
        self.allowed(spec, cwd)

    def test_fallback_pyproject_deletion_and_rename_are_rejected(self):
        self.without_base_config()
        self.base({"tests/pyproject.toml": '[project]\nname = "parent"\n',
                   "tests/unit/pyproject.toml": '[project]\nname = "child"\n'})
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml", "tests/unit/business.toml")
        git(cwd, "mv", "tests/unit/pyproject.toml", "tests/unit/business.toml")
        self.rejected(spec, cwd)

    def test_metadata_pyproject_ignored_when_real_configuration_exists(self):
        spec, cwd, _ = self.candidate("tests/unit/pyproject.toml")
        self.put(cwd, "tests/unit/pyproject.toml", '[project]\nname = "metadata"\n')
        self.allowed(spec, cwd)
