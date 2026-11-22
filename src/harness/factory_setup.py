"""One-time project onboarding without requiring architecture knowledge."""
from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import sys
from pathlib import Path

from .factory import git, private_dir, validate_config
from .factory_budget import PRESETS, ROUNDS
from .model_registry import read_private_token


def project_checks(repo):
    makefile = repo / "Makefile"
    if makefile.exists() and any(line.startswith('verify:') for line in makefile.read_text().splitlines()):
        return [["make", "verify"]], [["make", "lint"]] if any(line.startswith('lint:') for line in makefile.read_text().splitlines()) else [["make", "verify"]]
    tests = list((repo / "tests").rglob("test*.py")) if (repo / "tests").is_dir() else []
    if tests:
        if all("unittest" in p.read_text() for p in tests):
            check = ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
        else:
            check = ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        return [check], [["python3", "-c", "import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('.').rglob('*.py') if '.git' not in p.parts]"]]
    raise ValueError("project has no recognized tests; its maintainer must configure real test/CI commands once (config/factory.example.json)")


def setup(config_path, repository, token_file, size, codex_home=None, model=None,
          transport="official", proxy_endpoint=None, proxy_policy_file=None, proxy_provider="cli_proxy_api",
          reviewer_codex_home=None, deepseek_max_output_tokens=16384):
    repo = repository.resolve(strict=True)
    if Path(git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ValueError("choose the project Git root directory")
    if config_path.exists():
        raise ValueError(f"configuration already exists and was preserved: {config_path}")
    if not shutil.which("codex") or not shutil.which("bwrap"):
        raise ValueError("install official Codex CLI and bubblewrap before setup; see README")
    checks, ci = project_checks(repo)
    if token_file is None:
        token_file = config_path.absolute().parent / "deepseek-token"
        if not token_file.exists():
            if not sys.stdin.isatty():
                raise ValueError("DeepSeek credential required: rerun interactively or supply --deepseek-token-file")
            token = getpass.getpass("DeepSeek API key (hidden): ").strip()
            if not token:
                raise ValueError("a second independent provider credential is required")
            private_dir(token_file.parent)
            fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(token + "\n")
    token_file = token_file.absolute()
    read_private_token(token_file)
    profile = {"provider": "openai"}
    if codex_home:
        profile["codex_home"] = str(codex_home.resolve(strict=True))
    if model:
        profile["model"] = model
    developer = dict(profile, transport={"type": transport})
    reviewer = dict(profile, transport={"type": "official"})
    if reviewer_codex_home:
        from .codex import AppServerCodex
        reviewer["codex_home"] = AppServerCodex._codex_home(str(reviewer_codex_home.resolve(strict=True)))
    if transport == "cli_proxy":
        developer.pop("codex_home", None)
        from .factory_proxy import validate_transport, ProxyPolicy
        developer["transport"].update(endpoint=proxy_endpoint, configured_provider=proxy_provider,
                                      policy_file=str(proxy_policy_file) if proxy_policy_file else "")
        ProxyPolicy(validate_transport(developer), model=developer["model"])
    elif proxy_endpoint or proxy_policy_file:
        raise ValueError("proxy options require explicit --transport cli_proxy")
    config = validate_config({"version": 1, "repository": str(repo), "budget": PRESETS[size],
                              "max_rounds": ROUNDS[size], "timeout_seconds": 900,
                              "checks": checks, "ci": ci, "profiles": {
                                  "developer": developer, "reviewer": reviewer,
                                  "second_reviewer": {"provider": "deepseek", "model": "deepseek-flash",
                                                      "transport": {"type": "direct"}, "token_file": str(token_file),
                                                      "max_output_tokens": deepseek_max_output_tokens}}})
    workflows = sorted(p.name for p in (repo / ".github/workflows").glob("*.y*ml"))
    if workflows:
        try:
            remote = git(repo, "remote", "get-url", "origin")
        except Exception:
            remote = ""
        match = re.fullmatch(r"(?:git@github.com:|https://github.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?", remote)
        if match:
            if not shutil.which("gh"):
                raise ValueError("this project uses GitHub Actions; install gh and run gh auth login before setup")
            config["hosted_ci"] = {"repository": match[1], "workflows": workflows}
            config = validate_config(config)
    private_dir(config_path.absolute().parent)
    fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"SETUP": "CONFIGURED", "REPOSITORY": str(repo), "CONFIG": str(config_path.absolute()),
            "BUDGET": config["budget"], "MODEL_INFERENCE_CALLS": 0,
            "NEXT": 'harness submit "describe the feature"',
            "NOTE": "Configuration is not provider qualification. CLI proxy supports developer/planner only; OpenAI reviewer remains official, DeepSeek remains direct. Each mission verifies runtime identity."}
