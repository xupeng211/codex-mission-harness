"""Factory/LocalRuntime integration with trusted Docker/GitHub doubles only."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.factory import Factory, FactoryBlocked, git, validate_config
from harness.factory_project import OFFLINE_PASS
from harness.factory_runtime import LocalRuntime
from harness.factory_validation import digest as validation_digest, preflight
from harness.factory_pr_ci import branch_for, expected_jobs
import test_factory_project as stage1


VALIDATION = {"image": "fixture/profile@sha256:" + "1" * 64,
              "postgres_image": "fixture/postgres@sha256:" + "2" * 64,
              "cpus": 1, "memory_mb": 512, "pids": 64, "tmpfs_mb": 128}
POLICY = {"repository": "fixture/repo", "workflow": "production-gate.yml", "base_branch": "main"}
WORKFLOW = """name: Production Gate
on:
  push:
    branches: [main]
  pull_request:
    types: [opened, synchronize, ready_for_review]
jobs:
  production-gate:
    name: Environment / Proxy / Static / Unit Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
  docker-build:
    name: Docker Build Validation
    runs-on: ubuntu-latest
    needs: production-gate
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
"""
LOCKS = {"package-lock.json":"fixture-lock\n", "requirements.txt":"fixture-requirements\n"}


class FakeDocker:
    fixture = True

    def __init__(self):
        self.calls, self.containers = [], {}
        self.failure = None
        self.exit_code = 0
        self.mutate = lambda value: None

    def capture(self, container, path, timeout, cancelled):
        running = json.loads(Path(path).with_suffix(".validation.json").read_text())
        assert running["status"] == "RUNNING" and running["ended"] is None and running["interrupted"] is None
        if self.failure == "timeout":
            Path(path).write_bytes(b"fixture interrupted partial log")
            raise TimeoutError("fixture execution timed out")
        self.call("start", container)
        Path(path).write_bytes(self.call("logs", container))
        return self.exit_code

    def call(self, *args, timeout=30):
        self.calls.append(args)
        if self.failure == "daemon" and args[0] == "info":
            raise RuntimeError("fixture unavailable daemon")
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"RepoDigests": [args[2]], "Id": "sha256:" + "a" * 64}]).encode()
        if args[0] == "create":
            name = args[args.index("--name") + 1]
            self.containers[name] = args
            if self.failure == "startup" and name.endswith("-profile"):
                raise RuntimeError("fixture ambiguous startup failure")
            if name.endswith("-profile"):
                mount = args[args.index("--mount") + 1]
                source = Path(re.search(r"src=([^,]+)", mount)[1])
                assert source.joinpath(".git").is_dir()
                assert not source.joinpath(".git/objects/info/alternates").exists()
                assert git(source, "rev-parse", "HEAD")
                assert git(source, "config", "--local", "core.hooksPath") == "/dev/null"
                assert "readonly" in mount
                assert "container:" in args[args.index("--network") + 1]
                assert not any("docker.sock" in a or "host-gateway" in a for a in args)
            return name.encode()
        if args[0] == "inspect":
            name = args[1]
            if self.failure == "timeout" and name.endswith("-profile"):
                raise subprocess.TimeoutExpired("fixture docker inspect", timeout)
            value = {"State": {"Status": "exited", "ExitCode": self.exit_code if name.endswith("-profile") else 0,
                               "OOMKilled": False, "Error": ""}, "HostConfig": {"NetworkMode": "none"}}
            self.mutate(value)
            return json.dumps([value]).encode()
        if args[0] == "start" and "--attach" in args:
            return "".join(hashlib.sha256(value.encode()).hexdigest()+"  /opt/cmh/"+name+"\n" for name,value in LOCKS.items()).encode()
        if args[0] == "logs":
            if self.failure == "logs":
                raise RuntimeError("fixture log stream incomplete")
            if self.failure == "environment":
                return b"fixture dependency preparation failed\n"
            marker = re.search(r"CMH_ENVIRONMENT_READY_[a-z0-9]+", self.containers[args[-1]][-1])[0]
            return (marker + "\nfixture profile stdout and stderr\n").encode()
        if args[0] == "rm":
            if self.failure == "cleanup" and args[-1].endswith("-profile"):
                raise RuntimeError("fixture cleanup failed")
            self.containers.pop(args[-1], None)
        return b"fixture transport completed"


class FakeGitHub:
    fixture = True

    def __init__(self, spec, target):
        self.spec, self.target = spec, target
        self.writes, self.calls = [], []
        self.mutate = lambda bundle: None
        self.new_run = None
        self.pr_exists = True
        self.merge = "c" * 40

    def bundle(self):
        t = self.target
        pr = {"number": 7, "state": "open", "draft": False, "merged": False, "mergeable": True,
              "merge_commit_sha": self.merge, "head": {"sha": t["head"], "ref": branch_for(self.spec, t), "repo": {"full_name": "fixture/repo"}},
              "base": {"sha": t["base"], "ref": "main", "repo": {"full_name": "fixture/repo"}},
              "body": f"Mission scope contract: `{t['mission_scope_file']}`", "created_at": "2026-01-01T00:00:00Z"}
        run = {"id": 20, "run_attempt": 1, "workflow_id": 9, "repository": {"full_name": "fixture/repo"},
               "head_repository": {"full_name": "fixture/repo"}, "head_sha": t["head"], "head_branch": branch_for(self.spec, t),
               "path": ".github/workflows/production-gate.yml", "event": "pull_request", "status": "completed",
               "conclusion": "success", "html_url": "https://github.com/fixture/repo/actions/runs/20", "check_suite_id": 12,
               "created_at": "2026-01-01T00:01:00Z", "pull_requests": [{"number": 7, "head": {"sha": t["head"]}, "base": {"sha": t["base"]}}]}
        names = expected_jobs(WORKFLOW).values()
        jobs = [{"id": i, "run_id": 20, "run_attempt": 1, "head_sha": t["head"], "name": n,
                 "status": "completed", "conclusion": "success", "completed_at": "2026-01-01T00:02:00Z",
                 "html_url": f"https://github.com/fixture/repo/actions/runs/20/job/{i}",
                 "check_run_url": f"https://api.github.com/repos/fixture/repo/check-runs/{i}",
                 "steps": [{"name": "Checkout code", "status": "completed", "conclusion": "success"}]} for i, n in enumerate(names, 30)]
        checks = [{"id":j["id"],"name": j["name"], "head_sha": t["head"], "status": "completed", "conclusion": "success",
                   "check_suite": {"id": 12}, "app": {"id": 15368}, "details_url": j["html_url"], "url": j["check_run_url"]} for j in jobs]
        logs = {str(j["id"]): "2026-01-01T00:01:00.000Z ##[group]Run actions/checkout@v4\n"
                "2026-01-01T00:01:01.000Z [command]/usr/bin/git log -1 --format=%H\n"
                f"2026-01-01T00:01:02.000Z {self.merge}\n"
                "2026-01-01T00:01:03.000Z ##[group]Run candidate command\n" for j in jobs}
        rules = [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": n, "integration_id": 15368} for n in names]}}]
        b = {"pr": pr, "pr_after": copy.deepcopy(pr), "run": run, "run_after": copy.deepcopy(run), "latest_run_id": 20, "latest_run_attempt": 1,
             "base_branch": {"commit": {"sha": t["base"]}}, "merge_commit": {"sha": self.merge, "parents": [{"sha": t["base"]}, {"sha": t["head"]}]},
             "workflow": {"id": 9, "path": ".github/workflows/production-gate.yml", "state": "active"},
             "workflow_text": WORKFLOW, "workflow_blob": git_blob(WORKFLOW), "rules": rules, "rules_after": copy.deepcopy(rules),
             "protection": None, "protection_after": None, "jobs": jobs, "checks": checks, "checkout_logs": logs}
        self.mutate(b)
        return b

    def get(self, path, text=False):
        self.calls.append(path)
        b = self.bundle()
        plain = path.split("?")[0]
        if plain.endswith("/pulls"):
            return [b["pr"]] if self.pr_exists else []
        if plain.endswith("/pulls/7"):
            return b["pr"]
        if plain.endswith("/branches/main") and "/rules/" not in plain:
            return b["base_branch"]
        if "/commits/" in plain and not plain.endswith("/check-runs"):
            return b["merge_commit"]
        if "/contents/" in plain:
            return {"type": "file", "encoding": "base64", "sha": b["workflow_blob"], "content": base64.b64encode(b["workflow_text"].encode()).decode()}
        if "/rules/" in plain:
            return b["rules"]
        if plain.endswith("/workflows/production-gate.yml"):
            return b["workflow"]
        if "/workflows/9/runs" in plain:
            runs = [b["run"]]
            if self.new_run:
                runs.append({**b["run"], **self.new_run})
            return {"workflow_runs": runs}
        if plain.endswith("/jobs"):
            return {"jobs": b["jobs"]}
        if plain.endswith("/logs"):
            return b["checkout_logs"][plain.split("/")[-2]]
        if plain.endswith("/check-runs"):
            return {"check_runs": b["checks"]}
        if "/actions/runs/" in plain:
            return b["run"]
        raise AssertionError("unexpected fake API request " + path)

    def protection(self, repository):
        return self.bundle()["protection"]

    def push(self, *args):
        self.writes.append(("push", args))

    def post(self, path, value):
        self.writes.append(("create-pr", value))
        self.pr_exists = True
        return {"number": 7}


def git_blob(value):
    data = value.encode()
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class Phase2Runtime(stage1.ProjectRuntime):
    def __init__(self):
        super().__init__()
        self.docker = FakeDocker()
        self.api = None
        self._validation_cancelled = False

    def project_validation(self, *args):
        with patch("harness.factory_validation.DockerExecutor", return_value=self.docker):
            return LocalRuntime.project_validation(self, *args)

    def project_ci(self, policy, spec, cwd, target, *args):
        if self.api is None or self.api.target != target:
            self.api = FakeGitHub(spec, target)
        with patch("harness.factory_pr_ci.GitHub", return_value=self.api):
            return LocalRuntime.project_ci(self, policy, spec, cwd, target, *args)

    def project_validate_ci(self, *args, **kwargs):
        with patch("harness.factory_pr_ci.GitHub", return_value=self.api):
            return LocalRuntime.project_validate_ci(self, *args, **kwargs)

    def project_final_gate(self, *args, context=None):
        if context is None or context["ci_status"] != "PASS":
            raise ValueError("fake canonical final gate needs validated PR context")
        return super().project_final_gate(*args)


class Phase2Tests(unittest.TestCase):
    def setUp(self):
        stage1.ProjectContractTests.setUp(self)
        self.f.close()
        (self.repo / ".github/workflows").mkdir(parents=True)
        (self.repo / ".github/workflows/production-gate.yml").write_text(WORKFLOW)
        for name,value in LOCKS.items(): (self.repo / name).write_text(value)
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Fixture", "-c", "user.email=f@localhost", "commit", "-qm", "workflow fixture")
        self.base = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "remote", "add", "origin", "https://github.com/fixture/repo.git")
        self.spec["base"] = self.base
        self.spec["approved_mission_scope"] = self.approval()
        self.config.update(trusted_validation=VALIDATION, project_pr_ci=POLICY, checks=[["make", "verify-strict"]], ci=[["make", "verify-pr"]])
        self.runtime = Phase2Runtime()
        self.f = Factory(self.root / "phase2-state", self.config, self.runtime)
        self.addCleanup(self.f.close)

    approval = stage1.ProjectContractTests.approval

    def candidate(self):
        self.f.submit(self.spec)
        spec, cwd = self.f.prepare("feature")
        (cwd / "score.py").write_text("def add(a,b):\n    return a+b\n\ndef average(v): return sum(v)/len(v) if v else 0\n")
        return spec, cwd, self.f.checkpoint(spec, cwd)

    def approve(self, target):
        self.f.approve_pr_publication("feature", target["head"], "offline fixture explicit approval", f"Mission scope contract: `{self.path}`")

    def gates(self, spec, cwd, target, kind):
        return self.f.gates(spec, cwd, target, kind, 0)

    def test_real_factory_localruntime_docker_path_exact_identity_and_no_shared_git(self):
        spec, cwd, target = self.candidate()
        before = git(cwd, "rev-parse", "HEAD^{tree}")
        result = self.gates(spec, cwd, target, "checks")[0]
        self.assertEqual(result["identity"]["head"], target["head"])
        self.assertEqual(result["identity"]["tree"], before)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["cleanup"], "COMPLETE")
        self.assertFalse(self.runtime.docker.containers)
        self.assertEqual(git(cwd, "rev-parse", "HEAD^{tree}"), before)
        launches = len(self.runtime.docker.calls)
        self.gates(spec, cwd, target, "checks")
        self.assertEqual(len(self.runtime.docker.calls), launches)
        Path(result["log_path"]).write_text("tampered")
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")

    def test_docker_all_infrastructure_faults_fail_closed_without_replay(self):
        for fault in ("daemon", "startup", "timeout", "logs", "cleanup", "environment"):
            with self.subTest(fault=fault):
                spec, cwd, target = self.candidate()
                self.runtime.docker.failure = fault
                # Distinct round keys, never rewriting historical UNKNOWN.
                with self.assertRaises(FactoryBlocked): self.f.gates(spec, cwd, target, "checks", len(self.runtime.docker.calls))
                rows = self.f.db.execute("SELECT result FROM operations WHERE stage='checks' ORDER BY started DESC").fetchall()
                result = json.loads(rows[0][0])
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertTrue(Path(result["log_path"]).exists())
                if fault == "cleanup": self.assertEqual(result["cleanup"], "FAILED")
                if fault == "timeout": self.assertTrue(result["interrupted"])
                self.runtime.docker.failure = None

    def test_abnormal_exit_and_source_mutation_are_unknown(self):
        spec, cwd, target = self.candidate()
        self.runtime.docker.exit_code = 137
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")
        result = json.loads(self.f.db.execute("SELECT result FROM operations WHERE stage='checks'").fetchone()[0])
        self.assertTrue(result["interrupted"])
        self.assertEqual(result["exit_code"], 137)
        self.runtime.docker.exit_code = 125
        original = self.runtime.docker.capture
        def mutated(container,path,timeout,cancelled):
            code = original(container,path,timeout,cancelled)
            with Path(path).open("ab") as stream: stream.write(b"CMH_SOURCE_INTEGRITY_FAILURE")
            return code
        self.runtime.docker.capture = mutated
        with self.assertRaises(FactoryBlocked): self.f.gates(spec,cwd,target,"checks",1)

    def test_preflight_cleanup_failure_is_visible_and_never_complete(self):
        spec, cwd, target = self.candidate()
        original = self.runtime.docker.call
        def failed_cleanup(*args, **kwargs):
            if args[0] == "rm" and args[-1].startswith("cmh-preflight-"):
                raise RuntimeError("fixture probe cleanup failed")
            return original(*args, **kwargs)
        self.runtime.docker.call = failed_cleanup
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")
        result = json.loads(self.f.db.execute("SELECT result FROM operations WHERE stage='checks'").fetchone()[0])
        self.assertEqual(result["cleanup"], "FAILED")
        self.assertTrue(result["cleanup_errors"])

    def test_unknown_docker_execution_is_not_redispatched_after_restart(self):
        spec, cwd, target = self.candidate()
        self.runtime.docker.failure = "timeout"
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")
        calls = len(self.runtime.docker.calls)
        self.f.close()
        self.f = Factory(self.root / "phase2-state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")
        self.assertEqual(len(self.runtime.docker.calls), calls)
        self.assertEqual(self.f.run("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_wrong_configured_repository_rejected_before_dispatch(self):
        self.config["project_pr_ci"] = {**POLICY,"repository":"wrong/repo"}
        f = Factory(self.root / "wrong-repo-state", self.config, self.runtime)
        self.addCleanup(f.close)
        with self.assertRaisesRegex(ValueError,"origin"): f.submit(self.spec)

    def test_nonzero_profile_exit_is_known_failure_and_oom_is_unknown(self):
        spec, cwd, target = self.candidate()
        self.runtime.docker.exit_code = 4
        self.assertEqual(self.gates(spec, cwd, target, "checks")[0]["status"], "FAIL")
        self.runtime.docker.mutate = lambda value: value["State"].update(OOMKilled=True)
        with self.assertRaises(FactoryBlocked): self.f.gates(spec, cwd, target, "checks", 1)

    def test_result_identity_mismatch_is_rejected_at_factory_boundary(self):
        spec, cwd, target = self.candidate()
        original = self.runtime.project_validation
        def wrong(*args):
            result = original(*args)
            result["identity"]["head"] = "f" * 40
            return result
        self.runtime.project_validation = wrong
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "checks")

    def test_pr_authorization_missing_then_explicit_approval_reuse_and_restore(self):
        spec, cwd, target = self.candidate()
        with self.assertRaisesRegex(FactoryBlocked, "approval"): self.gates(spec, cwd, target, "ci")
        self.assertIsNone(self.runtime.api)
        self.approve(target)
        result = self.gates(spec, cwd, target, "ci")[-1]
        self.assertEqual(result["context"]["pr_head_sha"], target["head"])
        self.assertEqual(result["context"]["synthetic_merge_sha"], "c" * 40)
        self.assertEqual(result["context"]["tested_revision"], "PR_SYNTHETIC_MERGE")
        self.assertFalse(self.runtime.api.writes)
        self.f.close()
        self.f = Factory(self.root / "phase2-state", self.config, self.runtime)
        self.addCleanup(self.f.close)
        self.assertEqual(self.gates(spec, cwd, target, "ci")[-1]["context"], result["context"])
        self.runtime.api.new_run = {"id": 21, "status": "in_progress", "conclusion": None}
        with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "ci")

    def test_fake_creation_needs_exact_publication_approval_no_merge(self):
        spec, cwd, target = self.candidate()
        self.runtime.api = FakeGitHub(spec, target)
        self.runtime.api.pr_exists = False
        self.approve(target)
        self.gates(spec, cwd, target, "ci")
        self.assertEqual([w[0] for w in self.runtime.api.writes], ["push", "create-pr"])
        self.assertFalse(self.runtime.api.writes[1][1]["draft"])
        self.assertEqual(self.runtime.api.writes[0][1][1], target["head"])

    def test_publication_approval_does_not_authorize_a_new_head_or_expired_grant(self):
        from harness.factory_pr_ci import validate_approval
        spec, cwd, target = self.candidate()
        self.approve(target)
        approval = self.f.publication_approval(spec, target)
        with self.assertRaises(ValueError): validate_approval(approval,POLICY,spec,{**target,"head":"f"*40})
        approval["expires_at"] = "2020-01-01T00:00:00+00:00"
        with self.assertRaises(ValueError): validate_approval(approval,POLICY,spec,target)
        self.assertIsNone(self.runtime.api)

    def test_matrix_or_conditional_jobs_are_explicitly_unsupported(self):
        for insertion in ("    if: github.event.pull_request.draft == false\n", "    strategy:\n      matrix:\n        os: [ubuntu-latest]\n"):
            text = WORKFLOW.replace("    needs: production-gate\n", "    needs: production-gate\n" + insertion)
            with self.assertRaises(ValueError): expected_jobs(text)

    def test_pr_identity_and_status_faults_rejected_via_factory_cache(self):
        spec, cwd, target = self.candidate()
        self.approve(target)
        self.gates(spec, cwd, target, "ci")
        mutations = [
            lambda b: b["pr"].update(number=8),
            lambda b: b["pr"]["head"].update(sha="a"*40),
            lambda b: b["pr"]["head"]["repo"].update(full_name="evil/repo"),
            lambda b: b["pr"]["head"].update(ref="wrong"),
            lambda b: b["pr"]["base"].update(sha="a"*40),
            lambda b: b["pr"]["base"].update(ref="dev"),
            lambda b: b["pr"].update(draft=True),
            lambda b: b["pr"].update(body=b["pr"]["body"]+"\nchanged governance metadata"),
            lambda b: b["merge_commit"]["parents"][0].update(sha="a"*40),
            lambda b: b["workflow"].update(id=10),
            lambda b: b.update(workflow_text=WORKFLOW+"# changed\n"),
            lambda b: b["run"].update(event="push"),
            lambda b: b["run"].update(run_attempt=2),
            lambda b: b["run"].update(path=".github/workflows/wrong.yml"),
            lambda b: b["run"].update(id=19),
            lambda b: b["run"].update(head_sha="a"*40),
            lambda b: b["run"]["pull_requests"][0].update(number=8),
            lambda b: b["run"].update(pull_requests=[]),
            lambda b: b["run"].update(created_at="2025-01-01T00:00:00Z"),
            lambda b: b["jobs"].pop(),
            lambda b: b["jobs"][0].update(run_attempt=2),
            lambda b: b["jobs"][0].update(status="in_progress"),
            lambda b: b["checks"][0]["app"].update(id=1),
            lambda b: b["checks"].pop(),
            lambda b: b["jobs"].append(copy.deepcopy(b["jobs"][0])),
            lambda b: b["rules"][0]["parameters"]["required_status_checks"].append({"context":"unknown", "integration_id":15368}),
            lambda b: b.update(protection={"requiresStatusChecks":True,"requiredStatusChecks":[{"context":"other", "app":None}]}),
            lambda b: b["checkout_logs"].update({"30":"missing checkout output"}),
            lambda b: b["checkout_logs"].update({"30":b["checkout_logs"]["30"].replace("c"*40,"a"*40)}),
        ]
        mutations += [lambda b, status=status: b["jobs"][0].update(conclusion=status)
                      for status in ("skipped", "cancelled", "failure", "timed_out", "neutral", None, "UNKNOWN")]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.runtime.api.mutate = mutate
                with self.assertRaises(FactoryBlocked): self.gates(spec, cwd, target, "ci")
        self.assertFalse(self.runtime.api.writes)

    def test_final_project_contract_rejection_blocks_full_pipeline(self):
        self.runtime.final_status = "FAIL"
        original = self.f.publication_approval
        def approved(spec,target):
            self.approve(target)
            return original(spec,target)
        self.f.publication_approval = approved
        original_probe = preflight
        def probe(policy,executor=None,*args,**kwargs):
            return original_probe(policy,self.runtime.docker,*args,**kwargs) if executor is not None else {"status":"VERIFIED"}
        with patch("harness.factory_validation.preflight", side_effect=probe):
            self.f.submit(self.spec)
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], "BLOCKED_PROJECT_CONTRACT")
        self.assertFalse(report["DONE"])

    def test_full_factory_run_is_offline_only_and_final_contract_not_bypassed(self):
        # No real provider: original Factory planning/implementation/review paths
        # run the existing trusted fixtures. Approval is recorded when frozen.
        original = self.f.publication_approval
        def approve_on_frozen(spec, target):
            self.approve(target)
            return original(spec, target)
        self.f.publication_approval = approve_on_frozen
        original_probe = preflight
        def probe(policy, executor=None, *args, **kwargs):
            return original_probe(policy, self.runtime.docker, *args, **kwargs) if executor is not None else {"status":"VERIFIED"}
        with patch("harness.factory_validation.preflight", side_effect=probe):
            self.f.submit(self.spec)
            report = self.f.run("feature")
        self.assertEqual(report["DELIVERY_STATUS"], OFFLINE_PASS, report)
        self.assertFalse(report["DONE"])
        self.assertEqual(report["PROJECT_ACCEPTANCE"], "OFFLINE_FIXTURE_ONLY")
        self.assertEqual(report["BUDGET_USED"]["money"], "FIXTURE_NO_PROVIDER_COST")
        self.assertTrue(all(json.loads(row[0]) == {"fixture_provider_calls":0}
                            for row in self.f.db.execute("SELECT usage FROM operations WHERE paid=1")))
        self.runtime.api.new_run = {"id":21,"status":"in_progress","conclusion":None}
        self.assertEqual(self.f.report("feature")["DELIVERY_STATUS"], "UNKNOWN")

    def test_preflight_requires_real_prerequisites_and_retains_paid_block(self):
        from harness.factory_preflight import inspect_prepaid
        spec, cwd, target = self.candidate()
        config = copy.deepcopy(self.config)
        config["simulation"] = False
        with patch("harness.factory_validation.preflight", side_effect=RuntimeError("no image")):
            evidence = inspect_prepaid(spec, config)
        self.assertEqual(evidence["status"], "HARD_BLOCKER")
        self.assertTrue(any(f["check"] == "trusted_validation" for f in evidence["findings"]))
        with patch("harness.factory_validation.preflight", return_value={"status":"VERIFIED","images":{},"config_sha256":validation_digest(VALIDATION)}):
            evidence = inspect_prepaid(spec, config)
        self.assertTrue(any(f["check"] == "first_paid_execution" for f in evidence["findings"]))
        self.assertFalse(any(f["check"] in {"checks[0]","ci[0]"} and f["level"]=="HARD_BLOCKER" for f in evidence["findings"]))
        config.pop("trusted_validation")
        self.assertEqual(inspect_prepaid(spec, config)["status"], "HARD_BLOCKER")

    def test_configuration_rejects_socket_mount_flags_and_push_project_mode(self):
        for value in ({**VALIDATION,"mounts":["/var/run/docker.sock"]}, {**VALIDATION,"image":"mutable:latest"}):
            with self.assertRaises(ValueError): validate_config({**self.config,"trusted_validation":value})
        with self.assertRaises(ValueError): validate_config({**self.config,"ci":[["docker","exec","dev","make","verify-pr"]]})


if __name__ == "__main__":
    unittest.main()
