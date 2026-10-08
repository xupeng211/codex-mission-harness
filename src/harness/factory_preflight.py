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
    if mode not in ("100644", "100755") or kind != "blob" or int(size) > CONFIG_BYTES:
        raise ValueError("configuration is not a bounded regular committed text file")
    return _read_git(repo, "show", f"{commit}:{name}")


def docker_gate(argv):
    """Recognize daemon operations, not harmless version/help/config queries."""
    if not argv:
        return False
    name = Path(argv[0]).name
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
        return bool(args and args[0] in {"exec", "run", "up", "down", "build", "restart", "start", "stop", "logs", "ps"})
    return name == "docker" and bool(args and args[0] in {"exec", "run", "build", "pull", "push", "start", "stop", "restart", "logs", "ps"})


def make_docker_dependency(text, argv):
    """Recognize literal Docker use in reachable ordinary Make rules only.

    Do not run make (even -n can execute $(shell ...)), or implement Make syntax.
    Dynamic/include/eval constructs are reported as unverified by the caller.
    """
    if re.search(r"(?m)^\s*(?:-?include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|define|override)\b|\$\((?:shell|eval|call)\b", text):
        raise ValueError("dynamic Make syntax is not interpreted")
    variables = {"MAKE": "make"}
    immediate = set()
    rules, current = {}, []
    for line in text.splitlines():
        assignment = re.match(r"^([A-Za-z_]\w*)\s*([:?+]?=)\s*(.*)$", line)
        rule = re.match(r"^([\w. /-]+):([^=]*)$", line)
        if assignment:
            name, op, value = assignment.groups()
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
        goals = [next((name for name in rules if not name.startswith(".")), "")]
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
    findings = []
    def add(level, check, detail, **values):
        findings.append({"level": level, "check": check, "detail": detail, **values})
    if config["independent_review_required"]:
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
    for kind in ("checks", "ci"):
        for index, command in enumerate(config[kind]):
            check = f"{kind}[{index}]"
            name = Path(command[0]).name
            if not shutil.which(command[0], path=SAFE_PATH) and not command[0].startswith("./"):
                add("HARD_BLOCKER", check, "configured executable is absent from gate runtime PATH")
            docker = docker_gate(command)
            if name in ("sh", "bash", "dash") and any(a in ("-c", "-lc") for a in command[1:]):
                index = next(i for i, a in enumerate(command) if a in ("-c", "-lc"))
                if index + 1 < len(command):
                    script = command[index + 1]
                    if not re.search(r"[;&|\\]", script):
                        try:
                            words = shlex.split(script)
                            docker = docker_gate(words[1:] if words and words[0] == "exec" else words)
                        except ValueError:
                            pass
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
            if docker:
                add("HARD_BLOCKER", check, "Docker-dependent gate is incompatible with the current network-isolated sandbox, which exposes no Docker daemon/socket")
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
    add("UNVERIFIED", "provider_access", "model access and project-specific receipt compatibility are not established by static preflight")
    blockers = [f for f in findings if f["level"] == "HARD_BLOCKER"]
    return {"version": 1, "status": "HARD_BLOCKER" if blockers else "NO_KNOWN_HARD_BLOCKER",
            "baseline": commit, "findings": findings, "model_inference_calls": 0,
            "project_commands_executed": 0, "delivery_ready_asserted": False}
