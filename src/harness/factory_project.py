"""FootballPrediction contract bridge, not a second reviewer or policy engine.

Authority is the immutable project base. Receipts remain project artifacts;
fixtures never acquire live delivery or merge authority.
"""
from __future__ import annotations

import hashlib
import fnmatch
import configparser
import json
import os
import posixpath
import re
import subprocess
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .adapters import FootballPredictionAdapter, GateResult


PROJECT = "footballprediction"
OFFLINE_PASS = "OFFLINE_CONTRACT_PASS"
LANES = {"reviewer": "codex", "second_reviewer": "deepseek"}
BACKENDS = {"codex": "codex-cli", "deepseek": "claude-code-deepseek"}
VALIDATION_AUTHORITY_PATHS = frozenset({
    "package-lock.json", "pyproject.toml", "pytest.ini", "ruff.toml", ".ruff.toml",
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


def protect_ruff_authority(spec, cwd):
    """只读完整 BASE/HEAD Git 对象；候选路径授权不授予 QA 变更权限。"""
    from .factory import git

    def refuse(reason):
        raise ValueError("Ruff QA authority " + reason + "; separate policy mission required")

    revisions = (spec["base"], git(cwd, "rev-parse", "HEAD"))
    if any(not re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions):
        refuse("requires exact BASE/HEAD")
    trees = {}
    for revision in revisions:
        entries = {}
        for entry in filter(None, git(cwd, "ls-tree", "-r", "-z", revision).split("\0")):
            metadata, path = entry.split("\t", 1)
            entries[path] = tuple(metadata.split())
        trees[revision] = entries
    before, after = (trees[revision] for revision in revisions)
    changed = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    names = {"ruff.toml", ".ruff.toml"}
    if any(Path(path).name in names for path in changed):
        refuse("configuration changed")
    cache = {}

    def settings(revision, path):
        key = (revision, path)
        if key not in cache:
            entry = trees[revision].get(path)
            if entry is None:
                return None
            mode, kind, blob = entry
            if kind != "blob" or mode not in {"100644", "100755"}:
                refuse("cannot inspect non-regular configuration " + path)
            try:
                document = tomllib.loads(git(cwd, "show", blob))
            except (tomllib.TOMLDecodeError, UnicodeError):
                refuse("cannot parse configuration " + path)
            if Path(path).name == "pyproject.toml":
                tool = document.get("tool", {})
                document = tool.get("ruff") if isinstance(tool, dict) else None
                if document is not None and not isinstance(document, dict):
                    refuse("has an invalid tool.ruff table in " + path)
            cache[key] = document
        return cache[key]

    def frozen_settings(revision, path):
        try:
            return json.dumps(settings(revision, path), sort_keys=True, allow_nan=False)
        except (TypeError, ValueError):
            refuse("cannot compare tool.ruff settings in " + path)

    for revision in revisions:
        # 不执行配置；pyproject 的其他业务元数据不自动成为 QA 权威。
        roots = [path for path in trees[revision]
                 if Path(path).name in names | {"pyproject.toml"}
                 and settings(revision, path) is not None]
        pending = [(path, ()) for path in roots]
        visited = set()
        while pending:
            path, ancestors = pending.pop()
            if path in ancestors:
                refuse("extend cycle at " + path)
            if path in visited:
                continue
            visited.add(path)
            config = settings(revision, path)
            if config is None:
                refuse("extend target has no Ruff configuration: " + path)
            if path in changed:
                # 同路径、同类型且 Ruff 表不变的 pyproject 元数据编辑仍可继续。
                metadata_only = (Path(path).name == "pyproject.toml"
                    and before.get(path) is not None and after.get(path) is not None
                    and before[path][:2] == after[path][:2]
                    and frozen_settings(revisions[0], path) == frozen_settings(revisions[1], path))
                if not metadata_only:
                    refuse("configuration or extend dependency changed: " + path)
            if "extend" not in config:
                continue
            extended = config["extend"]
            if (not isinstance(extended, str) or not extended or "\\" in extended
                    or "$" in extended or "~" in extended or ":" in extended
                    or extended.startswith("/")):
                refuse("cannot safely resolve extend in " + path)
            dependency = posixpath.normpath(posixpath.join(posixpath.dirname(path), extended))
            if dependency == ".." or dependency.startswith("../"):
                refuse("extend leaves repository: " + path)
            if dependency not in trees[revision]:
                refuse("extend target is missing: " + path)
            pending.append((dependency, (*ancestors, path)))


def protect_pytest_authority(spec, cwd):
    """冻结原 pytest 9 配置权威；只读完整 Git 端点，不运行候选配置。"""
    from .factory import git

    def refuse(reason):
        raise ValueError("pytest QA authority " + reason + "; separate policy mission required")

    revisions = (spec["base"], git(cwd, "rev-parse", "HEAD"))
    if any(not re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions):
        refuse("requires exact BASE/HEAD")
    trees = {}
    for revision in revisions:
        entries = {}
        for entry in filter(None, git(cwd, "ls-tree", "-r", "-z", revision).split("\0")):
            metadata, path = entry.split("\t", 1)
            entries[path] = tuple(metadata.split())
        trees[revision] = entries
    before, after = (trees[revision] for revision in revisions)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    # 这些专用文件即使为空也会被 pytest 9 选中，并可遮蔽低优先级配置。
    exclusive = {"pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini"}
    if any(Path(p).name in exclusive for p in changed):
        refuse("configuration changed")
    names = exclusive | {"pyproject.toml", "tox.ini", "setup.cfg"}
    cache = {}

    def settings(revision, path):
        key = (revision, path)
        if key in cache:
            return cache[key]
        entry = trees[revision].get(path)
        if entry is None:
            return None, False
        mode, kind, blob = entry
        if kind != "blob" or mode not in {"100644", "100755"}:
            refuse("cannot inspect non-regular configuration " + path)
        name = Path(path).name
        if name in exclusive:
            result = "exclusive configuration", True
        else:
            try:
                text = git(cwd, "show", blob)
                if name == "pyproject.toml":
                    tool = tomllib.loads(text).get("tool", {})
                    if not isinstance(tool, dict):
                        refuse("invalid tool table in " + path)
                    config = tool.get("pytest")
                    if config is not None and not isinstance(config, dict):
                        refuse("invalid tool.pytest table in " + path)
                    if config is not None and "ini_options" in config and not isinstance(config["ini_options"], dict):
                        refuse("invalid tool.pytest.ini_options table in " + path)
                    result = (json.dumps(config, sort_keys=True, allow_nan=False) if config is not None else None,
                              config is not None and ("ini_options" in config or bool(config)))
                else:
                    parser = configparser.RawConfigParser(default_section="\0", interpolation=None)
                    parser.optionxform = str
                    parser.read_string(text)
                    wanted = "tool:pytest" if name == "setup.cfg" else "pytest"
                    # iniconfig 的节边界在第0列；保守保留整节原字节，避免用另一个
                    # INI 解析器的值规范化隐藏测试选项变化。非标准/歧义语法明确拒绝。
                    section, lines, sections = None, [], set()
                    for line in text.splitlines(keepends=True):
                        if line.lstrip().startswith("["):
                            if not line.startswith("["):
                                refuse("ambiguous INI section in " + path)
                            header = line.split("#", 1)[0].split(";", 1)[0].rstrip()
                            if not header.endswith("]"):
                                refuse("cannot parse INI section in " + path)
                            section = header[1:-1]
                            if not section or section in sections:
                                refuse("ambiguous INI section in " + path)
                            sections.add(section)
                        if section == wanted:
                            lines.append(line)
                    if set(parser.sections()) != sections:
                        refuse("ambiguous INI section in " + path)
                    if name == "setup.cfg" and "pytest" in sections:
                        refuse("unsupported setup.cfg [pytest] section in " + path)
                    result = ("".join(lines) if wanted in sections else None, wanted in sections)
            except (configparser.Error, tomllib.TOMLDecodeError, UnicodeError, TypeError, ValueError):
                refuse("cannot safely inspect configuration " + path)
        cache[key] = result
        return result

    paths = {p for p in before.keys() | after.keys() if Path(p).name in names}
    for path in sorted(paths):
        values = [settings(revision, path)[0] for revision in revisions]
        if any(value is not None for value in values):
            identities = [trees[rev][path][:2] if path in trees[rev] else None for rev in revisions]
            if values[0] != values[1] or identities[0] != identities[1]:
                refuse("configuration or file type/mode changed: " + path)

    # pytest 9 在没有有效配置时仍可选择无 pytest 表的 pyproject 作为 rootdir。
    # 原 dispatcher/gatekeeper 的 pytest 参数位于 tests/；覆盖其目录及共同祖先，
    # 两端使用同一目录集合，普通新增测试本身不会被误当成配置变更。
    directories = {Path("."), Path("tests"), Path("tests/unit")}
    for path in before.keys() | after.keys():
        if path.startswith("tests/") and path.endswith(".py"):
            directories.update(Path(path).parents)
    for directory in directories:
        ancestors = (directory, *directory.parents)
        fallback = []
        for revision in revisions:
            if any(settings(revision, str(parent / name))[1] for parent in ancestors for name in names):
                fallback.append(None)
                continue
            selected = next((str(parent / "pyproject.toml") for parent in ancestors
                             if str(parent / "pyproject.toml") in trees[revision]), None)
            fallback.append((selected, trees[revision][selected][:2]) if selected else None)
        if fallback[0] != fallback[1]:
            refuse("pyproject fallback rootdir changed")


def protect_eslint_authority(spec, cwd):
    """冻结原 ESLint 8.57.1 的配置来源；不执行候选配置或 Node resolver。"""
    from .factory import git

    def refuse(reason):
        raise ValueError("ESLint QA authority " + reason + "; separate policy mission required")

    revisions = (spec["base"], git(cwd, "rev-parse", "HEAD"))
    if any(not re.fullmatch(r"[0-9a-f]{40}", revision) for revision in revisions):
        refuse("requires exact BASE/HEAD")
    trees = {}
    for revision in revisions:
        trees[revision] = {}
        for entry in filter(None, git(cwd, "ls-tree", "-r", "-z", revision).split("\0")):
            metadata, path = entry.split("\t", 1)
            trees[revision][path] = tuple(metadata.split())
    before, after = (trees[revision] for revision in revisions)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    legacy = {".eslintrc.js", ".eslintrc.cjs", ".eslintrc.yaml", ".eslintrc.yml",
              ".eslintrc.json", ".eslintrc"}
    # 原命令 cwd 固定为仓库根：ignore 只在 cwd 读取；flat 从 cwd 向上发现，
    # 不从被 lint 的源文件目录发现。8.57.1 的三种 flat 后缀均会自动切换模式。
    flat = {"eslint.config.js", "eslint.config.mjs", "eslint.config.cjs"}
    root_only = flat | {".eslintignore", "package-lock.json", "npm-shrinkwrap.json", ".npmrc"}
    if any(Path(p).name in legacy or p in root_only for p in changed):
        refuse("configuration/selection or file type/mode changed")
    cache = {}

    def document(revision, path):
        key = (revision, path)
        if key in cache:
            return cache[key]
        entry = trees[revision].get(path)
        if entry is None:
            return None
        if entry[0] not in {"100644", "100755"} or entry[1] != "blob":
            refuse("cannot inspect non-regular configuration " + path)

        def unique(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    refuse("ambiguous duplicate key in " + path)
                result[name] = value
            return result

        try:
            value = json.loads(git(cwd, "show", entry[2]), object_pairs_hook=unique,
                               parse_constant=lambda value: refuse("invalid JSON constant in " + path))
        except (json.JSONDecodeError, UnicodeError):
            refuse("cannot statically confirm configuration " + path)
        if not isinstance(value, dict):
            refuse("configuration must be an object: " + path)
        cache[key] = value
        return value

    # package.json 是混合文件。根 scripts/依赖等原有权威仍冻结，仅排除已知
    # 不参与原 QA 执行的展示元数据；未知根字段仍冻结。嵌套只比较 eslintConfig。
    metadata = {"description", "keywords", "author", "contributors", "license", "homepage",
                "repository", "bugs", "funding"}
    packages = {p for p in before.keys() | after.keys() if Path(p).name == "package.json"}
    for path in packages:
        values = [document(rev, path) for rev in revisions]
        configs = [value.get("eslintConfig") if value is not None else None for value in values]
        if any(value is not None and not isinstance(value, dict) for value in configs):
            refuse("cannot confirm eslintConfig in " + path)
        if (json.dumps(configs[0], sort_keys=True) != json.dumps(configs[1], sort_keys=True)
                or any(value is not None for value in configs)
                and before.get(path, ())[:2] != after.get(path, ())[:2]):
            refuse("package eslintConfig or file type/mode changed: " + path)
        if path == "package.json" and path in changed:
            authority = [{k: v for k, v in value.items() if k not in metadata}
                         if value is not None else None for value in values]
            if (any(value is None for value in values) or before[path][:2] != after[path][:2]
                    or json.dumps(authority[0], sort_keys=True) != json.dumps(authority[1], sort_keys=True)):
                refuse("root package execution/configuration authority changed")

    # 固定合同是 JSON + eslint:recommended + 已锁定 jsdoc 插件。额外的本地
    # extends（含 overrides）按精确路径追踪；不猜测 Node 的后缀/目录/包回退。
    # 动态 JS、非 JSON YAML、自定义 parser/plugin/共享包无法安全确认，阻断，
    # 不建设另一套 ESLint loader，也不让候选执行代码来证明自己安全。
    def dependencies(config, path):
        if not isinstance(config, dict):
            refuse("cannot confirm configuration object in " + path)
        plugins = config.get("plugins", [])
        if (config.get("parser") or not isinstance(plugins, list)
                or any(p != "jsdoc" for p in plugins)):
            refuse("cannot confirm parser/plugin sources in " + path)
        extends = config.get("extends", [])
        extends = [extends] if isinstance(extends, str) else extends
        if not isinstance(extends, list):
            refuse("cannot confirm extends in " + path)
        for name in extends:
            if not isinstance(name, str):
                refuse("cannot confirm extends in " + path)
            if name in {"eslint:recommended", "plugin:jsdoc/recommended"}:
                continue
            if (not name.startswith(("./", "../"))
                    or any(c in name for c in ("\\", "$", "~", ":"))):
                refuse("cannot safely resolve extends in " + path)
            dependency = posixpath.normpath(posixpath.join(posixpath.dirname(path), name))
            if dependency == ".." or dependency.startswith("../"):
                refuse("extends leaves repository: " + path)
            yield dependency
        overrides = config.get("overrides", [])
        if not isinstance(overrides, list):
            refuse("cannot confirm overrides in " + path)
        for override in overrides:
            yield from dependencies(override, path)

    for revision in revisions:
        roots = [(p, (), False) for p in trees[revision] if Path(p).name in legacy]
        roots += [(p, (), True) for p in packages if p in trees[revision]
                  and document(revision, p).get("eslintConfig") is not None]
        if any(p in trees[revision] for p in flat):
            refuse("cannot statically confirm flat configuration sources")
        if any(p in trees[revision] for p in {".npmrc", "npm-shrinkwrap.json"}):
            refuse("cannot confirm npm execution/dependency override sources")
        for path in root_only - flat:
            entry = trees[revision].get(path)
            if entry is not None and (entry[0] not in {"100644", "100755"} or entry[1] != "blob"):
                refuse("cannot inspect non-regular configuration " + path)
        pending, visited = roots, set()
        while pending:
            path, ancestors, package_config = pending.pop()
            if path in ancestors:
                refuse("extends cycle at " + path)
            if (path, package_config) in visited:
                continue
            visited.add((path, package_config))
            if path in changed and not package_config:
                refuse("extends dependency changed: " + path)
            if path.endswith((".js", ".cjs")):
                refuse("cannot statically confirm executable configuration " + path)
            config = document(revision, path)
            if config is None:
                refuse("extends target is missing: " + path)
            if package_config:
                config = config["eslintConfig"]
            pending.extend((p, (*ancestors, path), False) for p in dependencies(config, path))


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
        protect_ruff_authority(spec, cwd)
        protect_pytest_authority(spec, cwd)
        protect_eslint_authority(spec, cwd)
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
        verify_target(spec, cwd, target)
        trusted = self.adapter._trusted_base_checkout(str(cwd), target["base"])
        # Same canonical preflight as merge_ready, before any remote mutation.
        evidence = cwd.parent / ".cmh-publication"
        self.adapter._private_dir(evidence, private_root=evidence)
        path = evidence / (sha256(body.encode()) + ".md")
        if path.exists():
            if path.is_symlink() or path.read_bytes() != body.encode("utf-8"):
                raise ValueError("publication body evidence changed")
        else:
            self.adapter._write_private_file(path, body)
        code = ("import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                "approved_base=sys.argv[5]; " + self.adapter._preflight_data_binding() +
                "sys.argv=['agent-preflight','--pr-body-file',sys.argv[3],'--mission-scope-file',sys.argv[4],"
                "'--base-ref',sys.argv[5],'--head-ref',sys.argv[6],'--require-review','--json']; raise SystemExit(p.main())")
        checked = self.adapter._call([self.adapter._trusted_python_interpreter(), "-I", "-B", "-c", code,
            str(trusted), str(cwd), str(path), str(cwd / target["mission_scope_file"]), target["base"], target["head"]],
            # governance_p1_checks also invokes Git without an explicit cwd.
            cwd=str(cwd), env=self.adapter._trusted_git_environment(),
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
        # Factory supplies validated PR context; the original project command
        # still rechecks scope, receipts, governance and remote merge readiness.
        if context is None:
            return GateResult("BLOCKED_EXTERNAL", "canonical agent-merge-ready requires phase-2 exact PR/CI context")
        if set(receipts or {}) != set(LANES.values()):
            return GateResult("BLOCKED_EXTERNAL", "both canonical receipts are required by Factory")
        return self.adapter.merge_ready(
            worktree=str(cwd), base=target["base"], head=target["head"], mission_id=spec["mission_id"],
            scope_file=str(cwd / target["mission_scope_file"]), receipts=receipts,
            use_project_policy=True, **context)
