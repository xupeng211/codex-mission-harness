"""Offline regressions for branch, full-diff and recoverable resource identity."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness.factory import FactoryBlocked, git
from harness.factory_container import recover, resources_for
from harness.factory_runtime import LocalRuntime
import test_factory_controller_gates as fixtures
from test_factory_container_lifecycle import DockerDouble


PROJECT_BASE = "a65464d1e5de498a072ed9a8fdf69ce46bcc04c5"


def evidence(name, value):
    directory = os.environ.get("HARNESS_CONTRACT_EVIDENCE_DIR")
    if directory:
        with (Path(directory) / (name + ".json")).open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")


def load_contract(case, name, filename):
    source = Path(os.environ.get("FOOTBALLPREDICTION_CONTRACT_REPO",
        str(Path(__file__).resolve().parents[2] / "FootballPrediction")))
    if not source.is_dir():
        case.skipTest("original FootballPrediction contract unavailable; UNVERIFIED")
    git(source, "cat-file", "-e", PROJECT_BASE + "^{commit}")
    # Read the fixed object, irrespective of the source worktree's branch.
    text = git(source, "show", PROJECT_BASE + ":scripts/devops/" + filename)
    path = case.root / filename
    path.write_text(text)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    if filename == "pr_ready_check.py":
        exact = load_contract(case, name + "_exact_head", "exact_head.py")
        with patch.dict(sys.modules, {"exact_head": exact}):
            spec.loader.exec_module(module)
    else:
        spec.loader.exec_module(module)
    return module


class BranchIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def test_prepared_and_reported_branch_equals_publication_identity(self):
        remote = self.fx.remote()
        self.assertEqual(git(self.fx.cwd, "branch", "--show-current"), remote.branch)
        self.assertEqual(self.fx.fx.f.report("feature")["CANDIDATE_BRANCH"], remote.branch)

    def test_wrong_local_branch_is_rejected_before_remote_writes(self):
        git(self.fx.cwd, "branch", "-m", "factory/wrong-task")
        remote = self.fx.remote()
        with self.assertRaises(ValueError):
            remote.publish(fixtures.DELIVERY, self.fx.spec, self.fx.target, self.fx.body)
        self.assertEqual(remote.writes, [])
        self.assertIsNone(remote.raw)

    def test_resume_rejects_wrong_branch_without_creating_replacement(self):
        git(self.fx.cwd, "branch", "-m", "factory/feature")
        before = git(self.fx.cwd, "show-ref", "--heads")
        with self.assertRaises(FactoryBlocked):
            self.fx.fx.f.prepare("feature")
        self.assertEqual(git(self.fx.cwd, "show-ref", "--heads"), before)
        self.assertEqual(git(self.fx.cwd, "branch", "--show-current"), "factory/feature")


class ContainerContractTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.ControllerGatesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root, self.cwd, self.spec, self.target = self.fx.root, self.fx.cwd, self.fx.spec, self.fx.target
        self.runtime = LocalRuntime()
        self.double = DockerDouble(self.fx, self.runtime)
        self.addCleanup(self.double.close)

    def gate(self, label="gate"):
        return self.runtime.container_gate(fixtures.CONTAINER, self.spec, self.cwd, self.target,
            ["make", "verify-targeted"], self.root / (label + ".raw"), 15)

    def large_candidate(self):
        # A valid, modest diff whose full target is larger than 64 KiB.
        extra = [f"src/fixture_{i:03d}.py" for i in range(200)]
        # A fresh mission is needed because submitted scope is immutable.
        from test_factory_project import ProjectContractTests
        fresh = ProjectContractTests("test_scope_materialized_only_in_candidate_and_bound_to_exact_head")
        fresh.setUp()
        self.addCleanup(fresh.doCleanups)
        fresh.scope["authorized_paths"] += extra + ["src/checked.py", "docs/followup.md"]
        fresh.spec["approved_mission_scope"] = fresh.approval()
        fresh.submit()
        self.spec, self.cwd = fresh.f.prepare("feature")
        (self.cwd / "src").mkdir()
        for name in extra:
            (self.cwd / name).write_text("VALUE = 1\n")
        (self.cwd / "src/checked.py").write_text("import os\n")
        first = fresh.f.checkpoint(self.spec, self.cwd)
        (self.cwd / "docs/followup.md").write_text("Documentation followup.\n")
        self.target = fresh.f.checkpoint(self.spec, self.cwd)
        self.assertNotEqual(first["head"], self.target["head"])
        self.assertLess(len(git(self.cwd, "diff", "--binary", self.target["base"], self.target["head"]).encode()),
                        fresh.f.config["max_review_bytes"])

    def test_actual_validation_env_binds_all_original_diff_helpers_to_full_base(self):
        self.large_candidate()
        # Existing convenience refs may point at the last rework commit. The
        # Controller snapshot must replace them with the approved full base.
        git(self.cwd, "update-ref", "refs/heads/main", self.target["head"])
        git(self.cwd, "update-ref", "refs/remotes/origin/main", self.target["head"])
        static = load_contract(self, "binding_static", "static_quality_changed_lines.py")
        profiles = load_contract(self, "binding_profiles", "validation_profiles.py")
        shell = git(Path(os.environ["FOOTBALLPREDICTION_CONTRACT_REPO"]), "show",
                    PROJECT_BASE + ":scripts/devops/gatekeeper.sh")
        functions = "\n".join(re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}", shell).group()
                              for name in ("collect_changed_files", "grep_added_lines"))
        observed = {}
        dispatch = self.double.dispatch

        def inspect(argv, **kwargs):
            if argv[1] == "run":
                workspace = Path(next(a.split(",dst=")[0].split("src=")[1]
                    for a in argv if a.startswith("type=bind,") and a.endswith("dst=/app")))
                start, end = argv.index("-i") + 1, argv.index("/usr/bin/timeout")
                env = dict(a.split("=", 1) for a in argv[start:end])
                observed.update(env=env, pinned_base=git(workspace, "rev-parse", "refs/remotes/origin/main"))
                with patch.dict(os.environ, {**env, "PATH": os.environ["PATH"],
                    "GIT_CONFIG_COUNT": "0"}, clear=True), patch.object(profiles, "ROOT", workspace):
                    previous = Path.cwd()
                    os.chdir(workspace)
                    try:
                        observed["static_base"] = static._resolve_git_diff_base()
                        lines = static.get_changed_line_ranges(["src/checked.py"])
                        diagnostic = {"filename": str(workspace / "src/checked.py"),
                            "location": {"row": 1, "column": 1}, "code": "F401", "message": "unused import"}
                        new, existing = static.classify_diagnostics([diagnostic], lines)
                        observed.update(new=len(new), existing=len(existing),
                            profile_base=profiles._resolve_branch_base(), selected=profiles.collect_changed_files())
                        files = subprocess.run(["bash", "-c", functions + "\ncollect_changed_files"],
                            check=True, capture_output=True, text=True)
                        added = subprocess.run(["bash", "-c", functions +
                            "\ngrep_added_lines src/checked.py '^import os$'"], capture_output=True, text=True)
                        observed.update(shell_files=files.stdout.splitlines(), shell_added_exit=added.returncode)
                    finally:
                        os.chdir(previous)
            return dispatch(argv, **kwargs)

        with self.double.hooks(), patch.object(self.double, "dispatch", side_effect=inspect):
            result = self.gate()
        evidence("full-base-contract", {"target": self.target, "observed": observed, "status": result["status"]})
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(observed["pinned_base"], self.target["base"])
        self.assertEqual(observed["static_base"], self.target["base"])
        self.assertEqual(observed["profile_base"], self.target["base"])
        self.assertEqual((observed["new"], observed["existing"]), (1, 0))
        self.assertIn("src/checked.py", observed["selected"])
        self.assertIn("src/checked.py", observed["shell_files"])
        self.assertEqual(observed["shell_added_exit"], 0)

    def test_misbound_base_ref_prevents_any_docker_dispatch(self):
        # Simulate an update-ref client that returns success with the wrong ref.
        popen = self.double.popen
        def corrupt(argv, *args, **kwargs):
            if "update-ref" in argv:
                argv = list(argv)
                argv[-1] = self.target["head"]
            return popen(argv, *args, **kwargs)
        with self.double.hooks(), patch("harness.factory_container.subprocess.Popen", side_effect=corrupt):
            result = self.gate()
        self.assertNotEqual(result["status"], "PASS")
        self.assertFalse(self.double.calls, "a mismatched approved base must be caught before resource creation")

    def test_large_legal_target_written_by_real_runner_can_recover(self):
        self.large_candidate()
        self.double.cleanup_blocked = True
        with self.double.hooks():
            result = self.gate()
        lifecycle = Path(result["lifecycle_record"])
        raw = lifecycle.read_bytes()
        self.double.cleanup_blocked = False
        with self.double.hooks():
            recovered = recover(fixtures.CONTAINER, self.spec, self.target, ["make", "verify-targeted"],
                                self.root / "gate.raw")
        evidence("large-lifecycle", {"file_count": len(self.target["files"]), "record_bytes": len(raw),
            "record": json.loads(raw), "recovery": recovered, "clients_reaped": all(p.poll() is not None for p in self.double.clients)})
        self.assertLessEqual(len(raw), 65536)
        self.assertTrue(recovered["cleanup_confirmed"], recovered)
        self.assertFalse(recovered["operation_replayed"])
        self.assertEqual(lifecycle.read_bytes(), raw)
        self.assertFalse(self.double.resources)

    def test_record_capacity_is_checked_before_resource_dispatch(self):
        resources = resources_for("cmh-validate-" + "a" * 32, self.spec, self.target, False)
        resources[0]["labels"]["excessive-metadata"] = "x" * 70000
        with self.double.hooks(), patch("harness.factory_container.resources_for", return_value=resources):
            with self.assertRaises(ValueError):
                self.gate()
        self.assertFalse(self.double.calls)

    def legacy_record(self, target):
        temporary = Path(tempfile.mkdtemp(prefix="cmh-validation-", dir=self.root))
        name = "cmh-validate-" + "b" * 32
        return {"target": target, "mission_id": self.spec["mission_id"], "policy": fixtures.CONTAINER,
            "profile": "targeted", "container_name": name,
            "resources": resources_for(name, self.spec, target, False), "temporary_directory": str(temporary)}

    def recover_record(self, record, *, raw=None, expected_target=None):
        transcript = self.root / "legacy.raw"
        path = transcript.with_suffix(".container.json")
        data = raw if raw is not None else json.dumps(record, sort_keys=True).encode()
        path.write_bytes(data)
        path.chmod(0o600)
        with patch("harness.factory_container.remove_owned", return_value=(True, 0)) as remove:
            result = recover(fixtures.CONTAINER, self.spec, expected_target or self.target,
                             ["make", "verify-targeted"], transcript)
        self.assertEqual(path.read_bytes(), data)
        return result, remove

    def test_legacy_small_and_large_records_recover_without_rewriting(self):
        small = self.legacy_record(self.target)
        result, remove = self.recover_record(small)
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertEqual(remove.call_count, 2)
        self.assertFalse(Path(small["temporary_directory"]).exists())
        self.large_candidate()
        large = self.legacy_record(self.target)
        self.assertGreater(len(json.dumps(large).encode()), 65536)
        result, remove = self.recover_record(large)
        evidence("legacy-lifecycle", {"large_record_bytes": len(json.dumps(large).encode()), "recovery": result})
        self.assertTrue(result["cleanup_confirmed"], result)
        self.assertEqual(remove.call_count, 2)
        self.assertEqual(remove.call_args_list[0].args, (large["container_name"], large["container_name"], large["resources"][0]["labels"]))

    def test_compact_format_retains_64k_cap_even_with_large_expected_target(self):
        self.large_candidate()
        with self.double.hooks():
            result = self.gate()
        record = json.loads(Path(result["lifecycle_record"]).read_text())
        record["padding"] = "x" * 70000
        recovered, remove = self.recover_record(record)
        self.assertFalse(recovered["cleanup_confirmed"])
        remove.assert_not_called()

    def test_invalid_records_never_remove_any_resources(self):
        with self.double.hooks():
            result = self.gate()
        valid = json.loads(Path(result["lifecycle_record"]).read_text())
        cases = {}
        for kind in ("target", "expected-target", "legacy-target", "mission", "policy", "resource", "path", "version", "oversize", "corrupt"):
            record = copy.deepcopy(valid)
            if kind == "target":
                if "target" in record: record["target"]["head"] = "0" * 40
                else: record["target_sha256"] = "0" * 64
            if kind == "mission": record["mission_id"] = "other"
            if kind == "policy": record["policy"]["image_id"] = "sha256:" + "b" * 64
            if kind == "resource": record["resources"][0]["labels"]["cmh.validation.owner"] = "other"
            if kind == "path": record["temporary_directory"] = str(self.root.parent / "unowned")
            if kind == "version": record["version"] = 999
            if kind == "legacy-target":
                record = self.legacy_record(copy.deepcopy(self.target))
                record["target"]["head"] = "0" * 40
            raw = b"x" * 200000 if kind == "oversize" else b"{" if kind == "corrupt" else None
            with self.subTest(kind=kind):
                target = {**self.target, "files": ["unrelated.py"]} if kind == "expected-target" else self.target
                recovered, remove = self.recover_record(record, raw=raw, expected_target=target)
                cases[kind] = recovered
                self.assertFalse(recovered["cleanup_confirmed"])
                remove.assert_not_called()
        evidence("rejected-lifecycle-records", cases)


if __name__ == "__main__":
    unittest.main()
