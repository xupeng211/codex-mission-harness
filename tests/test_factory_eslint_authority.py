"""固定 ESLint 配置权威回归：真实 Git/准入/原规则；Docker 和远端不执行。"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import Mock, patch

from harness.adapters import FootballPredictionAdapter
from harness.factory import FactoryBlocked, git
import harness.factory_container as container
from harness.factory_project import FootballPredictionContract, review_manifest, scope_binding, verify_target
from harness.factory_remote import run as remote_run
import test_factory_project_integration as integration
from test_factory_preflight_inspection import publication_body


class ESLintAuthorityTests(unittest.TestCase):
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
        self.base({p: git(self.original, "show", integration.PROJECT_BASE + ":" + p)
                   for p in (".eslintrc.json", "package.json")})

    @staticmethod
    def put(cwd, path, value):
        local = cwd / path
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text(value)

    @staticmethod
    def commit(cwd):
        git(cwd, "add", "--all", "--", ".")
        git(cwd, "-c", "user.name=Offline ESLint regression", "-c", "user.email=test@localhost",
            "commit", "-qm", "Local regression change")

    def base(self, files):
        for path, content in files.items():
            self.put(self.fx.repo, path, content)
        self.commit(self.fx.repo)
        self.fx.base = git(self.fx.repo, "rev-parse", "HEAD")

    def candidate(self, *paths):
        self.fx.scope["authorized_paths"].extend(paths)
        return self.fx.candidate()

    def record(self, label, value):
        directory = os.environ.get("HARNESS_ESLINT_EVIDENCE_DIR")
        if directory:
            path = Path(directory) / (self.id() + "." + label + ".json")
            with path.open("x") as stream:
                json.dump(value, stream, indent=2)
                stream.write("\n")

    def rejected(self, spec, cwd, reason="separate policy mission"):
        with patch.object(self.fx.runtime, "container_gate") as docker, \
                patch.object(self.fx.runtime, "prepare_project_review") as provider, \
                patch("harness.factory_remote.Remote") as remote:
            with self.assertRaisesRegex(FactoryBlocked, reason) as caught:
                self.fx.f.checkpoint(spec, cwd)
            docker.assert_not_called()
            provider.assert_not_called()
            remote.assert_not_called()
        self.assertEqual(self.fx.f.db.execute("SELECT COUNT(*) FROM operations WHERE paid=1").fetchone()[0], 0)
        return str(caught.exception)

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

    def test_original_nested_rule_override_is_rejected_at_checkpoint(self):
        spec, cwd, _ = self.candidate("src/.eslintrc.json", "src/probe.js")
        original = (cwd / ".eslintrc.json").read_bytes()
        self.put(cwd, "src/.eslintrc.json", '{"rules":{"no-var":"off","no-undef":"off"}}\n')
        self.put(cwd, "src/probe.js", "var probe = missingIdentifier;\n")
        reason = self.rejected(spec, cwd)
        self.assertEqual((cwd / ".eslintrc.json").read_bytes(), original)
        self.record("checkpoint", {"rejected": True, "reason": reason, "base": spec["base"],
            "head": git(cwd, "rev-parse", "HEAD"), "provider_starts": self.fx.starts,
            "root_config_sha256": hashlib.sha256(original).hexdigest()})

    def test_all_legacy_discovery_forms_at_multiple_levels_are_rejected(self):
        configs = {".eslintrc.js": "module.exports = {root:true};\n",
            ".eslintrc.cjs": "module.exports = {root:true};\n",
            ".eslintrc.yaml": "root: true\n", ".eslintrc.yml": "root: true\n",
            ".eslintrc.json": '{"root":true}', ".eslintrc": "root: true\n",
            "package.json": '{"eslintConfig":{"root":true}}'}
        spec, cwd, _ = self.candidate(*(f"src/deep/{p}" for p in configs))
        for name, content in configs.items():
            with self.subTest(name=name):
                path = "src/deep/" + name
                self.put(cwd, path, content)
                self.rejected(spec, cwd)
                (cwd / path).unlink()

    def test_root_legacy_ignore_and_flat_switch_names_are_rejected(self):
        paths = (".eslintrc.yaml", ".eslintrc.yml", ".eslintignore",
                 "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs")
        spec, cwd, _ = self.candidate(*paths)
        for name in paths:
            with self.subTest(name=name):
                self.put(cwd, name, "")
                self.rejected(spec, cwd)
                (cwd / name).unlink()

    def test_existing_root_configuration_still_rejects_changes(self):
        spec, cwd, _ = self.candidate(".eslintrc.json")
        self.put(cwd, ".eslintrc.json", "{}\n")
        self.rejected(spec, cwd)

    def test_nested_configuration_modification_deletion_and_rename_are_rejected(self):
        path = "src/.eslintrc.json"
        self.base({path: '{"rules":{"no-var":"error"}}\n'})
        spec, cwd, _ = self.candidate(path, "src/business.json")
        self.put(cwd, path, "{}\n")
        self.rejected(spec, cwd)
        (cwd / path).unlink()
        self.rejected(spec, cwd)
        self.put(cwd, "src/business.json", '{"rules":{"no-var":"error"}}\n')
        self.rejected(spec, cwd)

    def test_rename_into_discovery_and_higher_priority_addition_are_rejected(self):
        self.base({"src/business.json": "{}\n", "src/.eslintrc.json": "{}\n"})
        spec, cwd, _ = self.candidate("src/business.json", "src/.eslintrc.yml", "src/.eslintrc.js")
        git(cwd, "mv", "src/business.json", "src/.eslintrc.yml")
        self.rejected(spec, cwd)
        self.put(cwd, "src/.eslintrc.js", "module.exports = {};\n")
        self.rejected(spec, cwd)

    def test_configuration_mode_and_file_to_directory_changes_are_rejected(self):
        path = "src/.eslintrc.json"
        self.base({path: "{}\n"})
        spec, cwd, _ = self.candidate(path, path + "/child.txt")
        (cwd / path).chmod(0o755)
        self.rejected(spec, cwd)
        (cwd / path).unlink()
        self.put(cwd, path + "/child.txt", "business metadata\n")
        self.rejected(spec, cwd, "project text review does not certify")
        with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, [path + "/child.txt"])

    def test_symlink_configuration_is_rejected_without_reading_target(self):
        spec, cwd, _ = self.candidate("src/.eslintrc.json")
        (cwd / "src").mkdir()
        (cwd / "src/.eslintrc.json").symlink_to(self.fx.root / "must-not-be-read")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
            FootballPredictionContract().policy(spec, cwd, ["score.py"])

    def test_nested_package_config_changes_and_empty_config_addition_are_rejected(self):
        path = "src/package.json"
        self.base({path: '{"description":"old","eslintConfig":{}}'})
        spec, cwd, _ = self.candidate(path)
        for value in ('{"description":"new"}', '{"eslintConfig":{"root":true}}'):
            with self.subTest(value=value):
                self.put(cwd, path, value)
                self.rejected(spec, cwd)
        (cwd / path).unlink()
        self.rejected(spec, cwd)

    def test_package_config_mode_change_and_rename_are_rejected(self):
        path = "src/package.json"
        self.base({path: '{"eslintConfig":{}}'})
        spec, cwd, _ = self.candidate(path, "src/metadata.json")
        (cwd / path).chmod(0o755)
        self.rejected(spec, cwd)
        git(cwd, "mv", path, "src/metadata.json")
        self.rejected(spec, cwd)

    def test_root_package_lint_dependencies_ignore_and_unknown_fields_remain_frozen(self):
        spec, cwd, _ = self.candidate("package.json")
        original = json.loads((cwd / "package.json").read_text())
        changes = [{"scripts": {"lint": "true"}}, {"devDependencies": {"eslint": "1.0.0"}},
                   {"eslintIgnore": ["src/**"]}, {"eslintConfig": {}}, {"type": "module"},
                   {"unknown_execution_field": "unknown"}]
        for change in changes:
            with self.subTest(change=change):
                self.put(cwd, "package.json", json.dumps({**original, **change}))
                self.rejected(spec, cwd)

    def test_normal_javascript_and_unrelated_package_metadata_are_allowed(self):
        self.base({"src/package.json": '{"description":"old","eslintConfig":{}}'})
        spec, cwd, _ = self.candidate("src/probe.js", "src/package.json", "package.json")
        self.put(cwd, "src/probe.js", "const probe = 1;\n")
        self.put(cwd, "src/package.json", '{"description":"new","eslintConfig":{}}')
        root = json.loads((cwd / "package.json").read_text())
        self.put(cwd, "package.json", json.dumps({**root, "description": "Business metadata"}))
        target = self.allowed(spec, cwd)
        self.assertTrue(FootballPredictionContract().validate_pr_body(spec, cwd, target,
                         publication_body(self.fx, target)).is_file())

    def test_metadata_only_package_addition_deletion_and_nested_ignore_field_are_allowed(self):
        self.base({"src/package.json": '{"description":"metadata"}'})
        spec, cwd, _ = self.candidate("src/package.json", "src/deep/package.json")
        (cwd / "src/package.json").unlink()
        self.put(cwd, "src/deep/package.json", '{"description":"new","eslintIgnore":["**"]}')
        self.allowed(spec, cwd)

    def test_nested_flat_and_nested_eslintignore_do_not_select_configuration(self):
        paths = ("src/eslint.config.js", "src/eslint.config.mjs", "src/eslint.config.cjs", "src/.eslintignore")
        spec, cwd, _ = self.candidate(*paths)
        for path in paths:
            self.put(cwd, path, "// business fixture\n" if path.endswith(("js", "mjs", "cjs")) else "**\n")
        self.allowed(spec, cwd)

    def test_local_extends_chain_and_override_dependencies_are_frozen(self):
        self.base({"src/.eslintrc.json": '{"extends":"../quality/first.json",'
                   '"overrides":[{"files":["*.js"],"extends":"../quality/override.rules"}]}',
                   "quality/first.json": '{"extends":"./shared.rules"}',
                   "quality/shared.rules": '{"rules":{"no-var":"error"}}',
                   "quality/override.rules": "{}"})
        paths = ("quality/shared.rules", "quality/override.rules")
        spec, cwd, _ = self.candidate(*paths)
        for path in paths:
            with self.subTest(path=path):
                self.put(cwd, path, '{"rules":{"no-var":"off"}}')
                self.rejected(spec, cwd)
                git(cwd, "restore", "--source", spec["base"], "--", path)

    def test_extends_package_json_is_whole_dependency_not_eslintconfig_field(self):
        self.base({"src/.eslintrc.json": '{"extends":"../quality/package.json"}',
                   "quality/package.json": '{"rules":{"no-var":"error"}}'})
        spec, cwd, _ = self.candidate("quality/package.json")
        self.put(cwd, "quality/package.json", '{"rules":{"no-var":"off"}}')
        self.rejected(spec, cwd)

    def test_extends_deletion_rename_and_mode_change_are_rejected(self):
        path = "quality/shared.rules"
        self.base({"src/.eslintrc.json": '{"extends":"../quality/shared.rules"}', path: "{}"})
        spec, cwd, _ = self.candidate(path, "quality/business.rules")
        (cwd / path).chmod(0o755)
        self.rejected(spec, cwd)
        git(cwd, "mv", path, "quality/business.rules")
        self.rejected(spec, cwd)

    def test_missing_outside_cycle_dynamic_and_ambiguous_sources_fail_closed(self):
        configs = {"missing": '{"extends":"../quality/missing.json"}',
            "outside": '{"extends":"../../outside.json"}',
            "absolute": '{"extends":"/outside.json"}',
            "environment": '{"extends":"$HOME/config.json"}',
            "node-fallback": '{"extends":"../quality/shared"}',
            "cycle": '{"extends":"./.eslintrc.json"}',
            "unknown-package": '{"extends":"unknown-shareable"}',
            "parser": '{"parser":"./unknown.js"}',
            "duplicate": '{"root":false,"root":true}',
            "invalid": '{"root":', "non-json-yaml": "root: true\n"}
        for label, content in configs.items():
            with self.subTest(label=label):
                self.base({"src/.eslintrc.json": content})
                with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
                    FootballPredictionContract().policy({"base": self.fx.base}, self.fx.repo, [])

    def test_unchanged_executable_configuration_sources_are_unknown_without_execution(self):
        sentinel = self.fx.root / "must-not-exist"
        self.base({"src/.eslintrc.cjs": f'require("fs").writeFileSync({str(sentinel)!r}, "bad"); module.exports={{}};'})
        with self.assertRaisesRegex(ValueError, "cannot statically confirm executable"):
            FootballPredictionContract().policy({"base": self.fx.base}, self.fx.repo, [])
        self.assertFalse(sentinel.exists())

    def test_malformed_or_symlink_package_json_is_not_assumed_metadata(self):
        path = "src/package.json"
        spec, cwd, _ = self.candidate(path)
        for content in ('{"description":', '{"eslintConfig":false}', '{"eslintConfig":[],"eslintConfig":{}}'):
            with self.subTest(content=content):
                self.put(cwd, path, content)
                self.rejected(spec, cwd)
        (cwd / path).unlink()
        (cwd / path).symlink_to(self.fx.root / "must-not-be-read")
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "non-regular configuration"):
            FootballPredictionContract().policy(spec, cwd, [])

    def test_earlier_commit_and_partial_path_inventory_cannot_hide_configuration(self):
        spec, cwd, _ = self.candidate("src/.eslintrc.json")
        self.put(cwd, "src/.eslintrc.json", '{"rules":{"no-var":"off"}}')
        self.commit(cwd)
        self.put(cwd, "score.py", "def score():\n    return 3\n")
        self.commit(cwd)
        self.assertNotIn("src/.eslintrc.json", git(cwd, "diff", "--name-only", "HEAD~1", "HEAD"))
        for paths in ([], ["score.py"]):
            with self.subTest(paths=paths), self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
                FootballPredictionContract().policy(spec, cwd, paths)
        self.rejected(spec, cwd)

    def test_candidate_qa_authorization_marker_cannot_bypass(self):
        spec, cwd, _ = self.candidate("src/.eslintrc.json")
        self.put(cwd, "src/.eslintrc.json", '{"rules":{"no-var":"off"}}')
        self.commit(cwd)
        with self.assertRaisesRegex(ValueError, "separate policy mission"):
            FootballPredictionContract().policy({**spec, "allow_qa_changes": True}, cwd, [])

    def test_root_dependency_and_npm_execution_inputs_ignore_partial_path_arguments(self):
        paths = ("package-lock.json", "npm-shrinkwrap.json", ".npmrc")
        spec, cwd, _ = self.candidate(*paths)
        for path in paths:
            with self.subTest(path=path):
                self.put(cwd, path, "{}\n" if path.endswith("json") else "script-shell=/bin/true\n")
                self.commit(cwd)
                with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
                    FootballPredictionContract().policy(spec, cwd, [])
                (cwd / path).unlink()

    def test_real_verify_source_check_container_and_publication_reject_before_external_actions(self):
        spec, cwd, previous = self.candidate("src/.eslintrc.json", "src/probe.js")
        self.put(cwd, "src/.eslintrc.json", '{"rules":{"no-var":"off","no-undef":"off"}}')
        self.put(cwd, "src/probe.js", "var probe = missingIdentifier;\n")
        self.commit(cwd)
        target = self.unchecked_target(spec, cwd, previous)
        observations = {"base": spec["base"], "target": target, "refusals": {}}
        for entry in (verify_target, container.binding):
            with self.subTest(entry=entry.__name__), self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission") as caught:
                entry(spec, cwd, target)
            observations["refusals"][entry.__name__] = str(caught.exception)
        adapter = FootballPredictionAdapter()
        body = publication_body(self.fx, target)
        with patch.object(adapter, "_call") as original_preflight:
            with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission") as caught:
                FootballPredictionContract(adapter).validate_pr_body(spec, cwd, target, body)
            original_preflight.assert_not_called()
        observations["refusals"]["publication_preflight_wrapper"] = str(caught.exception)
        remote = Mock(adapter=adapter)
        with patch("harness.factory_remote.Remote", return_value=remote):
            with self.assertRaisesRegex(ValueError, "ESLint.*separate policy mission"):
                remote_run("publish", {}, spec, cwd, target, body, self.fx.root / "remote.raw", 10)
        remote.publish.assert_not_called()
        remote.command.assert_not_called()
        remote.api.assert_not_called()
        request = self.fx.root / "source-check.json"
        request.write_text(json.dumps({"spec": spec, "cwd": str(cwd), "target": target, "workspace": str(cwd)}))
        log = io.BytesIO()
        with self.assertRaisesRegex(ValueError, "Controller source verification failed"):
            container.source_check(self.fx.runtime, request, "candidate", log,
                                   self.fx.runtime.container_cancel, time.monotonic() + 20)
        self.assertIn(b"ESLint QA authority", log.getvalue())
        observations["source_check_raw"] = log.getvalue().decode()
        policy = {"image_id": "sha256:" + "1" * 64, "profiles": ["targeted"]}
        transcript = self.fx.root / "container.raw"
        original_client, clients = container.prepare_client, []

        def local_client(runtime, argv, *args, **kwargs):
            self.assertNotEqual(argv[0], "/usr/bin/docker")
            clients.append(argv)
            return original_client(runtime, argv, *args, **kwargs)

        with patch.object(container, "inspect_image") as inspect_image, \
                patch.object(container, "prepare_client", side_effect=local_client), \
                patch.object(container, "remove_owned") as remove:
            # Only the Python/Git source query is real. No Docker client is reached.
            result = self.fx.runtime.container_gate(policy, spec, cwd, target,
                                   ["make", "verify-targeted"], transcript, 20)
            inspect_image.assert_not_called()
            remove.assert_not_called()
        self.assertTrue(clients)
        self.assertEqual(result["status"], "BLOCKED_ENVIRONMENT")
        self.assertIn(b"ESLint QA authority", transcript.read_bytes())
        observations.update(container_result=result, container_raw=transcript.read_text(),
                            provider_starts=self.fx.starts, external_actions=[])
        self.record("admission", observations)


if __name__ == "__main__":
    unittest.main()
