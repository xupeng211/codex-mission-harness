"""FootballPrediction contract bridge, not a second reviewer or policy engine.

Authority is the immutable project base. Receipts remain project artifacts;
fixtures never acquire live delivery or merge authority.
"""
from __future__ import annotations

import hashlib
import fnmatch
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .adapters import FootballPredictionAdapter, GateResult


PROJECT = "footballprediction"
OFFLINE_PASS = "OFFLINE_CONTRACT_PASS"
LANES = {"reviewer": "codex", "second_reviewer": "deepseek"}
BACKENDS = {"codex": "codex-cli", "deepseek": "claude-code-deepseek"}
VALIDATION_AUTHORITY_PATHS = frozenset({
    "package.json", "package-lock.json", "pyproject.toml", "pytest.ini", "ruff.toml", ".ruff.toml",
    "mypy.ini", ".mypy.ini", ".eslintrc.json", ".eslintrc", ".eslintrc.js", ".eslintrc.cjs",
    "eslint.config.js", "eslint.config.mjs", ".coveragerc", "setup.cfg", "tox.ini",
})


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def validate_review_limits(value):
    keys = {"approval_id", "max_deepseek_chunks", "max_canonical_diff_bytes", "allow_unknown_provider_usage"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("explicit bounded canonical review authorization required; unsupported physical limits cannot be enforced")
    if (not isinstance(value["approval_id"], str) or not value["approval_id"].strip()
            or type(value["max_deepseek_chunks"]) is not int or not 1 <= value["max_deepseek_chunks"] <= 64
            or type(value["max_canonical_diff_bytes"]) is not int or not 1 <= value["max_canonical_diff_bytes"] <= 8 * 1024 * 1024
            or value["allow_unknown_provider_usage"] is not True):
        raise ValueError("canonical authorization must bound diff/chunks and explicitly accept UNKNOWN internal requests/usage/cost")
    return value


def approved_scope(spec):
    """Validate Controller input; preserve exact UTF-8 bytes, never infer approval."""
    value = spec.get("approved_mission_scope")
    required = {"approval_id", "mission_id", "base", "path", "content", "sha256", "expires_at"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("explicit Controller approved_mission_scope is required")
    if value["mission_id"] != spec["mission_id"] or value["base"] != spec["base"]:
        raise ValueError("scope approval mission/base mismatch")
    if not isinstance(value["approval_id"], str) or not value["approval_id"].strip():
        raise ValueError("scope approval identity is missing")
    if value["path"] != f"docs/agentic/missions/{spec['mission_id']}.json":
        raise ValueError("approved scope must name this mission under the canonical root")
    content = value["content"]
    if not isinstance(content, str) or len(content.encode()) > 65536:
        raise ValueError("scope approval must contain bounded exact UTF-8 bytes")
    if sha256(content.encode()) != value["sha256"]:
        raise ValueError("scope approval byte hash mismatch")
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate scope key")
            result[key] = item
        return result
    scope = json.loads(content, object_pairs_hook=unique)
    if not isinstance(scope, dict) or scope.get("mission_id") != spec["mission_id"]:
        raise ValueError("scope content belongs to another mission")
    if scope.get("workflow_class") not in {"NORMAL", "STRICT", "CRITICAL"}:
        raise ValueError("unknown project workflow class")
    try:
        expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("scope approval has expired or lacks a timezone")
    except (TypeError, AttributeError) as exc:
        raise ValueError("invalid scope approval expiry") from exc
    return value


def materialize_scope(spec, cwd, git):
    approval = approved_scope(spec)
    path = cwd / approval["path"]
    for parent in path.parents:
        if parent == cwd:
            break
        if parent.is_symlink():
            raise ValueError("scope ancestor is a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != approval["content"].encode():
            raise ValueError("existing scope differs from Controller approval")
    else:
        with path.open("xb") as stream:
            stream.write(approval["content"].encode())
    if git(cwd, "status", "--porcelain", "--", approval["path"]):
        git(cwd, "add", "--", approval["path"])
        git(cwd, "-c", "user.name=Delivery Factory", "-c", "user.email=factory@localhost",
            "commit", "-m", f"Bind Controller scope for {spec['mission_id']}")


def scope_binding(spec, cwd, head, git):
    approval = approved_scope(spec)
    path = approval["path"]
    entry = git(cwd, "ls-tree", head, "--", path)
    if not entry.startswith("100644 blob "):
        raise ValueError("approved scope must be a regular non-executable HEAD blob")
    committed = git(cwd, "show", f"{head}:{path}").encode()
    local = cwd / path
    if local.is_symlink() or local.read_bytes() != committed or committed != approval["content"].encode():
        raise ValueError("Builder changed or removed the approved scope")
    return {"mission_scope_file": path, "scope_blob": entry.split()[2],
            "mission_scope_sha256": sha256(committed), "scope_approval_id": approval["approval_id"]}


def review_manifest(cwd, target, git):
    """Enumerate every changed file/hunk. Availability is not semantic coverage."""
    base, head = target["base"], target["head"]
    options = ("--no-ext-diff", "--no-textconv", "--binary", "--no-renames")
    diff = git(cwd, "diff", *options, base, head, "--").encode()
    if sha256(diff) != target["diff_sha256"]:
        raise ValueError("full diff identity changed")
    files = []
    for path in target["files"]:
        versions = {}
        for label, revision in (("base", base), ("head", head)):
            entry = git(cwd, "ls-tree", revision, "--", path)
            if not entry:
                versions[label] = None
                continue
            mode, kind, blob = entry.split("\t", 1)[0].split()
            if mode not in {"100644", "100755"} or kind != "blob":
                raise ValueError("project text review does not certify symlinks/submodules")
            text = git(cwd, "show", f"{revision}:{path}")
            if "\0" in text:
                raise ValueError("project text review does not certify binary blobs")
            versions[label] = {"mode": mode, "blob": blob, "sha256": sha256(text.encode())}
        patch = git(cwd, "diff", *options, "--unified=0", base, head, "--", path)
        if "GIT binary patch" in patch or "Binary files " in patch:
            raise ValueError("binary change cannot be represented as reviewed text")
        matches = list(re.finditer(r"(?m)^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*", patch))
        hunks = []
        for index, match in enumerate(matches):
            stop = matches[index + 1].start() if index + 1 < len(matches) else len(patch)
            hunks.append({"base_start": int(match[1]), "base_count": int(match[2] or 1),
                          "head_start": int(match[3]), "head_count": int(match[4] or 1),
                          "sha256": sha256(patch[match.start():stop].encode())})
        files.append({"path": path, "versions": versions, "hunks": hunks,
                      "patch_sha256": sha256(patch.encode())})
    return {"version": "factory-project-review-range/v1", "base": base, "head": head,
            "tree": target["tree"], "diff_sha256": sha256(diff),
            "diff_policy": "factory-no-ext-diff-no-textconv-binary-no-renames",
            "scope_sha256": target["mission_scope_sha256"], "files": files,
            "range_delivery": "exact refs available in canonical detached worktree",
            "semantic_coverage": "NOT_MACHINE_PROVEN"}


def verify_target(spec, cwd, target):
    """Reconstruct Controller identity immediately before an external action."""
    from .factory import git
    cwd = Path(cwd)
    if (spec["base"] != target["base"] or git(cwd, "rev-parse", "HEAD") != target["head"]
            or git(cwd, "rev-parse", "HEAD^{tree}") != target["tree"]
            or git(cwd, "status", "--porcelain", "--untracked-files=all")):
        raise ValueError("candidate base/HEAD/tree/cleanliness mismatch")
    git(cwd, "merge-base", "--is-ancestor", target["base"], target["head"])
    files = list(filter(None, git(cwd, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "-z",
                                   "--no-renames", target["base"], target["head"], "--").split("\0")))
    if files != target["files"] or any(not any(fnmatch.fnmatchcase(p, pattern) for pattern in spec["scope"]) for p in files):
        raise ValueError("candidate full path inventory/scope mismatch")
    scope = scope_binding(spec, cwd, target["head"], git)
    if scope != {k: target[k] for k in scope}:
        raise ValueError("candidate mission/scope mismatch")
    review_manifest(cwd, target, git)
    tracked_source_digest(cwd, target["head"], require_committed=True)
    return FootballPredictionContract().policy(spec, cwd, files)


def tracked_source_digest(cwd, head, *, require_committed=False):
    from .factory import git
    result = hashlib.sha256()
    for entry in filter(None, git(cwd, "ls-tree", "-r", "-z", head).split("\0")):
        metadata, path = entry.split("\t", 1)
        mode, kind, blob = metadata.split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unsupported source entry in candidate")
        local = cwd / path
        value = os.readlink(local).encode() if local.is_symlink() else local.read_bytes()
        actual_blob = hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()
        actual_mode = "120000" if local.is_symlink() else "100755" if local.stat().st_mode & 0o111 else "100644"
        if require_committed and (actual_blob != blob or mode != actual_mode):
            raise ValueError("actual candidate source differs from committed HEAD bytes/mode")
        result.update(json.dumps([path, actual_mode, sha256(value)]).encode())
    return result.hexdigest()


class FootballPredictionContract:
    """Reuse trusted-base execution and original project receipt validators."""

    def __init__(self, adapter=None):
        self.adapter = adapter or FootballPredictionAdapter()

    def policy(self, spec, cwd, paths):
        for path in paths:
            if (path in self.adapter.REVIEW_CONTRACT_PATHS
                    or path in VALIDATION_AUTHORITY_PATHS
                    or Path(path).name == "conftest.py" or path.startswith(("requirements", "docker-compose"))
                    or path.startswith(("scripts/devops/", "scripts/ops/helpers/", "schemas/agentic/", ".github/",
                                        "scripts/test/", ".githooks/", ".devcontainer/", "config/"))):
                raise ValueError("candidate changed protected canonical authority; separate policy mission required")
        trusted = self.adapter._trusted_base_checkout(str(cwd), spec["base"])
        # These modules are byte-verified base policy, never candidate code.
        query = """
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from scripts.ops.helpers.agent_workflow_contract import MissionScope, validate_mission_scope
from scripts.devops.review_policy import required_backends, load_active_backend_eligibility
from scripts.devops.codex_review_contract import REVIEW_MODEL_PINNED, REVIEW_REASONING_EFFORT_PINNED
value = json.loads(sys.stdin.read())
scope = MissionScope.from_mapping(json.loads(value['scope']))
if scope.mission_id != value['mission_id']: raise ValueError('mission identity mismatch')
errors = validate_mission_scope(value['paths'], scope)
if errors: raise ValueError('; '.join(errors))
required = required_backends(scope.workflow_class)
eligible = load_active_backend_eligibility(Path('docs/agentic/independent_review_backends.json'))
if any(scope.workflow_class not in eligible.get(b, ()) for b in required):
    raise ValueError('required project backend is not eligible')
print(json.dumps({'workflow_class': scope.workflow_class, 'required_backends': list(required),
 'codex_model': REVIEW_MODEL_PINNED, 'codex_effort': REVIEW_REASONING_EFFORT_PINNED}))
"""
        result = subprocess.run(
            [self.adapter._trusted_python_interpreter(), "-I", "-B", "-c", query],
            cwd=trusted, env=self.adapter._trusted_git_environment(),
            input=json.dumps({"scope": approved_scope(spec)["content"],
                              "mission_id": spec["mission_id"], "paths": paths}),
            text=True, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise ValueError("canonical scope/policy rejected Controller input or changed paths")
        policy = json.loads(result.stdout)
        policy["factory_required_backends"] = list(BACKENDS.values())
        policy["factory_p3_blocks"] = True
        return policy

    def review_arguments(self, spec, cwd, target, lane):
        reviewer = LANES[lane]
        # Never take an evidence path from the Builder or mission input. The
        # isolated candidate's parent is the Controller-owned mission root.
        cwd = Path(cwd).absolute()
        if cwd.resolve(strict=True) != cwd:
            raise ValueError("canonical candidate path has symbolic-link components")
        evidence = self.adapter.review_evidence_dir(str(cwd), spec["mission_id"], reviewer, target["head"])
        self.adapter._private_dir(evidence, private_root=cwd.parent / ".cmh-review-evidence")
        argv = self.adapter.review_argv(
            reviewer, worktree=str(cwd), base=target["base"], head=target["head"],
            mission_id=spec["mission_id"], scope_file=str(cwd / target["mission_scope_file"]),
            evidence_dir=str(evidence), attempt_id=uuid.uuid4().hex)
        return argv, evidence

    def review_admission(self, spec, cwd, target, limits):
        """Run only the base's pure planner, never a provider or candidate module."""
        validate_review_limits(limits)
        verify_target(spec, cwd, target)
        trusted = self.adapter._trusted_base_checkout(str(cwd), target["base"])
        query = """
import hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))
from scripts.devops import deepseek_review_chunks as chunks
v=json.loads(sys.stdin.read()); t=v['target']; root=Path(v['cwd'])
def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
       '-c', 'core.fsmonitor=false', '-C', str(root), *args], stderr=subprocess.PIPE)
if git('rev-parse','HEAD').decode().strip()!=t['head'] or git('status','--porcelain','--untracked-files=all'):
    raise ValueError('admission candidate changed')
diff=git('diff','--binary','--no-ext-diff',t['base']+'...'+t['head'])
source_mission=getattr(chunks, 'SOURCE_CONTEXT_MISSION', None)
chunked=len(diff)>chunks.MAX_CHUNK_DIFF_BYTES or v['mission_id']==source_mission
kwargs=dict(base_sha=t['base'], head_sha=t['head'], mission_id=v['mission_id'],
    mission_scope_sha256=t['mission_scope_sha256'])
if source_mission is not None:
    kwargs.update(repo_root=root, source_context_version=chunks.SOURCE_CONTEXT_VERSION if v['mission_id']==source_mission else None)
manifest=chunks.plan(diff, **kwargs)
sizes=[len(chunks.build_chunk_prompt(chunk=c, source=diff[c.start:c.end], manifest=manifest,
    scope_sha=t['mission_scope_sha256']).encode()) for c in manifest.chunks] if chunked else []
if any(n>chunks.MAX_CHUNK_PROMPT_BYTES for n in sizes): raise ValueError('canonical prompt capacity exceeded')
print(json.dumps({'canonical_diff_sha256':hashlib.sha256(diff).hexdigest(), 'canonical_diff_bytes':len(diff),
 'deepseek_backend_runs':len(manifest.chunks) if chunked else 1, 'chunked':chunked,
 'chunk_manifest':manifest.payload(), 'chunk_prompt_bytes':sizes}))
"""
        result = subprocess.run([self.adapter._trusted_python_interpreter(), "-I", "-B", "-c", query],
            cwd=trusted, env=self.adapter._trusted_git_environment(), text=True, capture_output=True,
            input=json.dumps({"target": target, "cwd": str(cwd), "mission_id": spec["mission_id"]}), timeout=30)
        if result.returncode:
            raise ValueError("trusted canonical chunk planning failed before dispatch")
        plan = json.loads(result.stdout)
        if (plan["deepseek_backend_runs"] > limits["max_deepseek_chunks"]
                or plan["canonical_diff_bytes"] > limits["max_canonical_diff_bytes"]):
            raise ValueError("actual canonical diff/chunk count exceeds review authorization; zero dispatch")
        return {**plan, "target": target, "authorization": limits,
                "scope_approval_id": target["scope_approval_id"], "codex_outer_operations": 1,
                "provider_internal_requests": "UNKNOWN", "physical_cost_cap": "UNKNOWN"}

    def validate_pr_body(self, spec, cwd, target, body):
        trusted = self.adapter._trusted_base_checkout(str(cwd), target["base"])
        # Same canonical preflight as merge_ready, before any remote mutation.
        evidence = cwd.parent / ".cmh-publication"
        self.adapter._private_dir(evidence, private_root=evidence)
        path = evidence / (sha256(body.encode()) + ".md")
        if path.exists():
            if path.is_symlink() or path.read_text() != body:
                raise ValueError("publication body evidence changed")
        else:
            self.adapter._write_private_file(path, body)
        code = ("import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                "from scripts.devops import agent_workflow_preflight as p; "
                "from scripts.ops import ai_workflow_gate as g; "
                "from scripts.ops.helpers import git_change_helpers as h; "
                "p.ROOT=g.ROOT=h.ROOT_HELPER=Path(sys.argv[2]); "
                "sys.argv=['agent-preflight','--pr-body-file',sys.argv[3],'--mission-scope-file',sys.argv[4],"
                "'--base-ref',sys.argv[5],'--head-ref',sys.argv[6],'--require-review','--json']; raise SystemExit(p.main())")
        checked = self.adapter._call([self.adapter._trusted_python_interpreter(), "-I", "-B", "-c", code,
            str(trusted), str(cwd), str(path), str(cwd / target["mission_scope_file"]), target["base"], target["head"]],
            cwd=str(trusted), env={"HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            inherit_environment=False)
        document = self.adapter._json_document_prefix(checked.stdout)
        if checked.returncode or document.get("verdict") != "PASS":
            failures = [f.get("check", "UNKNOWN") + ": " + str(f.get("message", ""))[:300]
                        for f in document.get("findings", []) if f.get("status") != "PASS"]
            raise ValueError("canonical PR body/scope preflight rejected publication: " + "; ".join(failures)[:1600])
        return path

    def validate_review(self, spec, cwd, target, lane, result):
        """Always re-run the original validator, including on cached operations."""
        reviewer = LANES[lane]
        checked = self.adapter.review_result(
            reviewer, worktree=str(cwd), base=target["base"], head=target["head"],
            mission_id=spec["mission_id"], scope_file=str(cwd / target["mission_scope_file"]),
            stdout_path=result["stdout_path"], evidence_dir=result["evidence_dir"],
            exit_code=result["exit_code"], stderr_path=result["stderr_path"])
        if checked.status not in {"PASS", "FAIL"} or not checked.artifact or not isinstance(checked.data, dict):
            raise ValueError("canonical validator did not establish a current receipt")
        receipt = checked.data
        if (receipt.get("base_sha") != target["base"]
                or receipt.get("reviewed_head_sha", receipt.get("head_sha")) != target["head"]
                or receipt.get("mission_id") != spec["mission_id"]
                or receipt.get("mission_scope_sha256") != target["mission_scope_sha256"]):
            raise ValueError("canonical receipt target binding mismatch")
        if lane == "reviewer":
            provenance = receipt.get("model_provenance", {})
            if (provenance.get("review_model") != target["project_policy"]["codex_model"]
                    or provenance.get("review_reasoning_effort") != target["project_policy"]["codex_effort"]):
                raise ValueError("canonical executed model/effort differs from pinned project policy")
        if result["exit_code"] not in (0, 3) or (result["exit_code"] == 3 and checked.status != "FAIL"):
            raise ValueError("runner exit contradicts canonical verdict")
        return checked

    def final_gate(self, spec=None, cwd=None, target=None, receipts=None, context=None):
        # No PR publication, CI waiter or caller-supplied green status is added
        # here. Phase 2 must supply actual context to adapter.merge_ready().
        if context is None:
            return GateResult("BLOCKED_EXTERNAL", "canonical agent-merge-ready requires phase-2 exact PR/CI context")
        if set(receipts or {}) != set(LANES.values()):
            return GateResult("BLOCKED_EXTERNAL", "both canonical receipts are required by Factory")
        return self.adapter.merge_ready(
            worktree=str(cwd), base=target["base"], head=target["head"], mission_id=spec["mission_id"],
            scope_file=str(cwd / target["mission_scope_file"]), receipts=receipts,
            use_project_policy=True, **context)
