"""Static prepaid admission for the existing local Factory, never project execution.

Findings are not a delivery verdict. Only known incompatibilities block; unknown
dependencies, future changes and remote access remain explicitly unverified.
"""
from __future__ import annotations

import codecs
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .sandbox import SAFE_PATH


SCAN_BYTES = 64 * 1024 * 1024
CONFIG_BYTES = 256 * 1024
MAKE_BYTES = 512 * 1024  # Static file-read bound only; no paid budget change.


def _git_environment():
    return {"PATH": SAFE_PATH, "HOME": "/nonexistent", "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"}


def _read_git(repo, *args):
    # Missing objects in partial clones must not trigger a fetch or write.
    return subprocess.check_output(["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
                                    "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                                   env=_git_environment(), stderr=subprocess.PIPE, timeout=10).decode()


def text_capacity(repo, commit, limit):
    """Count the same UTF-8/NUL-free regular blobs as the independent reviewer.

    Stream blobs without retaining source text. A bounded partial scan is a
    lower bound, never proof of fitting. GNU timeout bounds blocked pipe reads.
    """
    entries = []
    for row in filter(None, _read_git(repo, "ls-tree", "-r", "-l", "-z", commit).split("\0")):
        metadata, _ = row.split("\t", 1)
        mode, kind, oid, size = metadata.split()
        if mode in ("100644", "100755") and kind == "blob":
            entries.append((oid, int(size)))
    proc = subprocess.Popen(["timeout", "--kill-after=1", "10", "git", "--no-replace-objects",
                             "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                             "-C", str(repo), "cat-file", "--batch"], env=_git_environment(),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    total, scanned, complete = 0, 0, True
    try:
        for oid, size in entries:
            if scanned + size > SCAN_BYTES:
                complete = False
                break
            proc.stdin.write((oid + "\n").encode())
            proc.stdin.flush()
            if proc.stdout.readline().split() != [oid.encode(), b"blob", str(size).encode()]:
                raise ValueError("bounded committed-blob scan did not complete")
            decoder = codecs.getincrementaldecoder("utf-8")()
            text, remaining = True, size
            while remaining:
                block = proc.stdout.read(min(65536, remaining))
                if not block:
                    raise ValueError("bounded committed-blob scan did not complete")
                remaining -= len(block)
                scanned += len(block)
                if b"\0" in block:
                    text = False
                if text:
                    try:
                        decoder.decode(block, final=remaining == 0)
                    except UnicodeDecodeError:
                        text = False
            if proc.stdout.read(1) != b"\n":
                raise ValueError("invalid committed-blob boundary")
            if text:
                total += size
            if total > limit:
                complete = False
                break  # The lower bound already proves admission exceeds capacity.
        return {"text_bytes_lower_bound": total, "scan_complete": complete,
                "scanned_blob_bytes": scanned, "limit_bytes": limit}
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()


def committed_text(repo, commit, name):
    entry = _read_git(repo, "ls-tree", "-l", commit, "--", name)
    if not entry:
        return None
    metadata, _ = entry.split("\t", 1)
    mode, kind, _, size = metadata.split()
    limit = MAKE_BYTES if name == "Makefile" else CONFIG_BYTES
    if mode not in ("100644", "100755") or kind != "blob" or int(size) > limit:
        raise ValueError("configuration is not a bounded regular committed text file")
    return _read_git(repo, "show", f"{commit}:{name}")


def docker_gate(argv):
    """Recognize daemon operations, not harmless version/help/config queries."""
    if not argv:
        return False
    name = Path(argv[0]).name
    if "/" in argv[0] and (not Path(argv[0]).is_absolute() or str(Path(argv[0]).parent) not in SAFE_PATH.split(":")):
        return False  # A repository wrapper's basename is not a daemon contract.
    args = argv[1:]
    if name == "docker" and args and args[0] == "compose":
        name, args = "docker-compose", args[1:]
    if name == "docker-compose":
        # Only these ordinary options are interpreted. Everything else remains
        # unverified in the enclosing command finding.
        while args and args[0] in ("-f", "--file", "-p", "--project-name", "--profile"):
            if len(args) < 2:
                return False
            args = args[2:]
        operations = {"exec", "run", "up", "down", "build", "restart", "start", "stop", "logs", "ps"}
    elif name == "docker":
        operations = {"exec", "run", "build", "pull", "push", "start", "stop", "restart", "logs", "ps"}
    else:
        return False
    if not args or args[0] not in operations:
        return False
    if not {"--help", "-h"} & set(args[1:]):
        return True
    if args[0] not in {"run", "exec"}:
        return False
    # run/exec stop parsing client flags at IMAGE / CONTAINER / SERVICE.
    # Help after that boundary belongs to the container program. Interpret
    # only common flags here; unknown option arity remains unverified.
    switches = {"-d", "--detach", "--interactive"}
    values = {"-e", "--env", "-u", "--user", "-w", "--workdir"}
    if name == "docker-compose":
        switches |= {"-T", "--no-TTY"}
    else:
        switches |= {"-i", "-t", "--tty"}
    if args[0] == "run":
        switches |= {"--rm"}
        values |= {"--name", "--entrypoint", "-v", "--volume"}
    elif name == "docker-compose":
        values |= {"--index"}
    index = 1
    while index < len(args):
        token = args[index]
        if token in {"--help", "-h"}:
            return False
        if token == "--" or not token.startswith("-"):
            return True
        flag, separator, _ = token.partition("=")
        if flag in switches and not separator:
            index += 1
        elif flag in values:
            index += 1 if separator else 2
        else:
            return False
    return False


def make_docker_dependency(text, argv):
    """Recognize literal Docker use in reachable ordinary Make rules only.

    Do not run make (even -n can execute $(shell ...)), or implement Make syntax.
    Dynamic/include/eval constructs are reported as unverified by the caller.
    """
    # Make directives are not tab-prefixed shell recipe lines. In particular,
    # an unrelated recipe's `else` must not hide an ordinary reachable gate.
    if re.search(r"(?m)^ *(?:-?include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|define|override)\b|\$\((?:shell|eval|call)\b", text):
        raise ValueError("dynamic Make syntax is not interpreted")
    if re.search(r"(?m)^ *(?:\.ONESHELL|\.IGNORE)\s*:|^ *(?:SHELL|\.SHELLFLAGS)\s*[:?+]?=", text):
        raise ValueError("Make shell/error semantics are not interpreted")
    variables = {"MAKE": "make"}
    immediate = set()
    rules, current = {}, []
    for line in text.splitlines():
        if not line.startswith("\t"):
            if "\\#" in line:
                raise ValueError("escaped Make comments are not interpreted")
            line = line.split("#", 1)[0].rstrip()
        assignment = re.match(r"^ *([A-Za-z_]\w*|\.DEFAULT_GOAL)\s*([:?+]?=)\s*(.*)$", line)
        rule = re.match(r"^([\w. /-]+):([^=]*)$", line)
        if assignment:
            name, op, value = assignment.groups()
            if name == "MAKEFLAGS" and value.strip() != "--no-print-directory":
                raise ValueError("Make execution flags are not interpreted")
            if (op == ":=" or op == "+=" and name in immediate) and "$" in value:
                raise ValueError("immediate dynamic Make assignment is not interpreted")
            if op == "?=" and name in variables:
                continue
            variables[name] = (variables.get(name, "") + " " + value) if op == "+=" else value
            if op == ":=":
                immediate.add(name)
            elif op == "=":
                immediate.discard(name)
        elif not line.startswith(("\t", "#")) and re.match(r"^.+:[^#]*=", line):
            raise ValueError("target-specific Make assignment is not interpreted")
        elif rule:
            current = rule[1].split()
            for name in current:
                rules[name] = [rule[2].split("#", 1)[0], []]
        elif line.startswith("\t"):
            for name in current:
                rules[name][1].append(line.lstrip("\t"))
        elif line.strip() and not line.startswith("#"):
            current = []
    goals = [a for a in argv[1:] if not a.startswith("-") and "=" not in a]
    if not goals:
        default = variables.get(".DEFAULT_GOAL", "").split("#", 1)[0].strip()
        if default and not re.fullmatch(r"[\w./-]+", default):
            raise ValueError("dynamic default Make goal is not interpreted")
        goals = [default or next((name for name in rules if not name.startswith(".")), "")]
    seen, pending = set(), goals[:]
    while pending:
        goal = pending.pop()
        if goal in seen or goal not in rules:
            continue
        seen.add(goal)
        dependencies, recipe = rules[goal]
        pending.extend(dependencies.split())
        for line in recipe:
            for _ in range(8):
                expanded = re.sub(r"\$\((\w+)\)|\$\{(\w+)\}",
                                  lambda m: variables.get(m[1] or m[2], m[0]), line)
                if expanded == line:
                    break
                line = expanded
            # Conditional/ignored/fallback recipes are not proof that Docker
            # must succeed. Never infer a hard blocker from a quoted mention.
            if not re.search(r"[;&|\\]", line) and not line.lstrip("@+ ").startswith("-"):
                try:
                    words = shlex.split(line.lstrip("@+ "))
                    if words and words[0] in ("exec", "command"):
                        words = words[1:]
                    if docker_gate(words):
                        return True
                except ValueError:
                    pass
            nested = re.match(r"\s*[@+]*make\s+(.*)", line) if not re.search(r"[;&|\\]", line) else None
            if nested:
                try:
                    arguments = shlex.split(nested[1])
                except ValueError:
                    raise ValueError("recursive Make command is not understood") from None
                if any(a.startswith("-") or "=" in a for a in arguments):
                    raise ValueError("recursive Make overrides are not interpreted")
                pending.extend(arguments)
    return False


def workflow_push(text, branch_prefix):
    """Conservative event/filter check; no GitHub authentication or requests."""
    import yaml
    class UniqueLoader(yaml.SafeLoader):
        pass
    def unique_mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node)
            if not isinstance(key, (str, int, float, bool, type(None))) or key in result:
                raise yaml.constructor.ConstructorError(None, None, "ambiguous workflow mapping", key_node.start_mark)
            result[key] = loader.construct_object(value_node)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
    try:
        data = yaml.load(text, Loader=UniqueLoader)
    except yaml.YAMLError:
        return "UNVERIFIED", "workflow YAML could not be safely parsed"
    if not isinstance(data, dict):
        return "UNVERIFIED", "workflow structure could not be determined"
    # PyYAML's YAML 1.1 loader reads GitHub's unquoted `on` as True.
    trigger = data.get("on", data.get(True))
    if isinstance(trigger, str):
        trigger = [trigger]
    if isinstance(trigger, list):
        if any(not isinstance(event, str) for event in trigger):
            return "UNVERIFIED", "workflow event list could not be determined"
        return ("WARNING", "push event is declared; remote execution is not verified") if "push" in trigger else ("HARD_BLOCKER", "workflow has no push event; Factory publishes candidate branches by push")
    if not isinstance(trigger, dict):
        return "UNVERIFIED", "workflow trigger could not be determined"
    if any(not isinstance(event, str) for event in trigger):
        return "UNVERIFIED", "workflow event mapping could not be determined"
    if "push" not in trigger:
        return "HARD_BLOCKER", "workflow has no push event; Factory does not create PRs or dispatch workflows"
    push = trigger["push"]
    if push is None:
        return "WARNING", "unfiltered push is declared; remote execution is not verified"
    if not isinstance(push, dict):
        return "UNVERIFIED", "push filters could not be determined"
    if set(push) - {"branches", "branches-ignore", "paths", "paths-ignore", "tags", "tags-ignore"}:
        return "UNVERIFIED", "unsupported push configuration cannot be determined"
    tag_keys = {"tags", "tags-ignore"} & set(push)
    if tag_keys and not {"branches", "branches-ignore"} & set(push):
        if len(tag_keys) != 1 or any(not isinstance(push[key], list) or not push[key]
                                   or any(not isinstance(p, str) for p in push[key]) for key in tag_keys):
            return "UNVERIFIED", "tag filters could not be determined"
        return "HARD_BLOCKER", "tag-only push filters exclude branch pushes; Factory publishes candidate branches, not tags"
    branches = push.get("branches")
    if branches is not None:
        if not isinstance(branches, list) or any(not isinstance(p, str) for p in branches):
            return "UNVERIFIED", "branch filters could not be determined"
        # Only literal allowlists can conclusively exclude every Factory suffix.
        if branches and all(not re.search(r"[!*?\[\]{}+\\]", p) for p in branches):
            if all(not p.startswith(branch_prefix) for p in branches):
                return "HARD_BLOCKER", "push branch allowlist excludes Factory candidate branches"
    for key in ("branches", "branches-ignore", "paths", "paths-ignore", "tags", "tags-ignore"):
        if key in push:
            return "UNVERIFIED", "push filters depend on future branch/diff or unsupported glob semantics"
    return "WARNING", "push event is declared; remote execution is not verified"


def inspect_prepaid(spec, config):
    """Inspect the immutable baseline, not mutable working-tree diagnostics."""
    repo, commit = Path(spec["repository"]), spec["base"]
    from .factory_candidate import requested as local_requested
    local_mode = local_requested(spec)
    findings = []
    def add(level, check, detail, **values):
        findings.append({"level": level, "check": check, "detail": detail, **values})
    if config.get("project_contract") == "footballprediction" and not local_mode:
        from .adapters import FootballPredictionAdapter
        # Canonical tool-based review does not serialize the whole repository.
        # Check admission identity only; future diff and receipts remain unknown.
        for path in FootballPredictionAdapter.REVIEW_CONTRACT_PATHS:
            try:
                entry = _read_git(repo, "ls-tree", commit, "--", path)
                if not entry.startswith(("100644 blob ", "100755 blob ")):
                    add("HARD_BLOCKER", "project_contract", "canonical policy source missing or unsupported", path=path)
            except (OSError, ValueError, subprocess.SubprocessError):
                add("UNVERIFIED", "project_contract", "canonical baseline source cannot be inspected", path=path)
        add("UNVERIFIED", "independent_context", "canonical reviewer reads exact diff and relevant source; full-repository prompt capacity is not the contract")
        add("UNVERIFIED", "project_final_gate", "canonical receipts and current exact PR/CI must pass before live readiness")
        if not config["simulation"]:
            add("HARD_BLOCKER", "first_paid_execution", "canonical DeepSeek outer operation may execute up to 64 backend calls; physical cost ceiling is unproven and first live paid execution remains blocked")
    elif config["independent_review_required"] and not local_mode:
        try:
            capacity = text_capacity(repo, commit, config["max_context_bytes"])
            if capacity["text_bytes_lower_bound"] > capacity["limit_bytes"]:
                add("HARD_BLOCKER", "independent_context", "committed baseline exceeds full-source reviewer capacity; nothing was truncated", **capacity)
            elif not capacity["scan_complete"]:
                add("UNVERIFIED", "independent_context", "bounded scan is incomplete; fitting is not proven", **capacity)
            else:
                add("WARNING", "independent_context", "baseline fits; implementation can still exceed capacity", **capacity)
        except (OSError, ValueError, subprocess.SubprocessError):
            add("UNVERIFIED", "independent_context", "committed text capacity could not be determined within the static scan")
    add("UNVERIFIED", "final_diff", "future diff size, binary changes, submodules and review coverage cannot be certified before implementation")
    if not config["simulation"]:
        for executable in ("bwrap", "timeout"):
            if not shutil.which(executable, path=SAFE_PATH):
                add("HARD_BLOCKER", "local_runtime", f"required executable {executable} is absent from gate runtime PATH")
    trusted_ready = False
    validation = config.get("trusted_validation")
    if validation:
        try:
            from .factory_validation import preflight, dependency_locks
            readiness = preflight(validation, expected_locks=dependency_locks(repo, commit))
            if readiness["status"] != "VERIFIED":
                raise ValueError("real Controller prerequisites are not verified")
            trusted_ready = True
            add("WARNING", "trusted_validation", "isolated Controller daemon/image readiness probe passed; formal project profiles have not run", evidence=readiness)
        except Exception as exc:
            add("HARD_BLOCKER", "trusted_validation", "trusted validation prerequisites failed: " + str(exc))
    for kind in ("checks", "ci"):
        for index, command in enumerate(config[kind]):
            check = f"{kind}[{index}]"
            name = Path(command[0]).name
            if not shutil.which(command[0], path=SAFE_PATH) and not command[0].startswith("./"):
                add("HARD_BLOCKER", check, "configured executable is absent from gate runtime PATH")
            docker = docker_gate(command)
            if name in ("sh", "bash", "dash"):
                # Only ordinary -c/-lc invocations are recognized. Additional
                # flags (e.g. -n), files and other modes are never interpreted.
                if len(command) >= 3 and command[1] in ("-c", "-lc"):
                    script = command[2]
                    if not re.search(r"[;&|\\\n`$<>()]", script):
                        try:
                            words = shlex.split(script)
                            docker = docker_gate(words[1:] if words and words[0] == "exec" else words)
                        except ValueError:
                            pass
                else:
                    add("UNVERIFIED", check, "Shell options/mode could not be statically interpreted")
            if name in ("make", "gmake"):
                try:
                    makefile = committed_text(repo, commit, "Makefile")
                    if makefile is None:
                        add("UNVERIFIED", check, "Makefile is absent at baseline; a future implementation may add it")
                    elif any(a.startswith("-") or "=" in a for a in command[1:]):
                        add("UNVERIFIED", check, "Make overrides prevent a reliable static dependency check")
                    else:
                        docker = make_docker_dependency(makefile, command)
                except (OSError, ValueError, subprocess.SubprocessError):
                    add("UNVERIFIED", check, "committed Make dependencies could not be determined")
            canonical = command in (["make", "verify-targeted"], ["make", "verify-pr"], ["make", "verify-strict"])
            if docker and not (trusted_ready and canonical):
                add("HARD_BLOCKER", check, "Docker-dependent gate is incompatible with the current network-isolated sandbox, which exposes no Docker daemon/socket")
            if config.get("project_contract") == "footballprediction" and canonical:
                if not trusted_ready:
                    add("HARD_BLOCKER", check, "canonical project profiles require an actually available trusted validation path; default sandbox has no daemon")
            add("UNVERIFIED", check, "command was not executed; packages, services, dynamic scripts and test behavior remain unverified")
    hosted = config.get("hosted_ci")
    if hosted:
        prefix = f"factory/{spec['mission_id']}-"
        for workflow in hosted["workflows"]:
            try:
                text = committed_text(repo, commit, ".github/workflows/" + workflow)
                if text is None:
                    add("HARD_BLOCKER", "hosted_ci", "authorized workflow is absent at baseline", workflow=workflow)
                else:
                    level, detail = workflow_push(text, prefix)
                    add(level, "hosted_ci", detail, workflow=workflow)
            except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, ImportError):
                add("UNVERIFIED", "hosted_ci", "workflow could not be safely parsed", workflow=workflow)
        add("UNVERIFIED", "hosted_access", "remote workflow, permissions, required jobs and repository policy were not contacted or verified")
    if config.get("project_pr_ci"):
        try:
            from .factory_pr_ci import expected_jobs
            source = committed_text(repo, commit, ".github/workflows/production-gate.yml")
            expected_jobs(source)
        except Exception as exc:
            add("HARD_BLOCKER", "project_pr_ci", "trusted PR workflow is unsupported: " + str(exc))
        add("UNVERIFIED", "project_pr_ci", "PR publication requires separate exact-candidate approval; current remote rules/jobs/runs have not been verified")
    add("UNVERIFIED", "provider_access", "model access and project-specific receipt compatibility are not established by static preflight")
    blockers = [f for f in findings if f["level"] == "HARD_BLOCKER"]
    return {"version": 1, "status": "HARD_BLOCKER" if blockers else "NO_KNOWN_HARD_BLOCKER",
            "baseline": commit, "findings": findings, "model_inference_calls": 0,
            "project_commands_executed": 0, "delivery_ready_asserted": False}
