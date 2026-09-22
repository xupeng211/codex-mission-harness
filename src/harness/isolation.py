from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


def run(*argv: str, cwd: str | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()


@dataclass(frozen=True)
class Worktree:
    repo: str
    base_sha: str
    branch: str
    path: str


class WorktreeManager:
    def ensure(self, repo: str, mission_id: str, root: Path) -> Worktree:
        repo = str(Path(repo).resolve())
        if not Path(repo, ".git").exists() and not Path(repo).joinpath(".git").is_file():
            raise ValueError(f"not a git repository: {repo}")
        base = run("git", "-C", repo, "rev-parse", "origin/main")
        branch = "harness/" + mission_id
        path = root / mission_id
        listing = run("git", "-C", repo, "worktree", "list", "--porcelain")
        records = [block.splitlines() for block in listing.strip().split("\n\n") if block]
        expected = str(path.resolve())
        for lines in records:
            values = dict(line.split(" ", 1) for line in lines if " " in line)
            if values.get("worktree") == expected:
                if values.get("branch") not in {f"refs/heads/{branch}", None}:
                    raise RuntimeError(f"mission path belongs to another branch: {expected}")
                return Worktree(repo, base, branch, expected)
        if path.exists():
            raise RuntimeError(f"refusing non-mission-owned path: {path}")
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-C", repo, "worktree", "add", "-b", branch, str(path), base], check=True)
        return Worktree(repo, base, branch, str(path))


def compose_namespace(mission_id: str) -> str:
    safe = "".join(ch if ch.isalnum() else "-" for ch in mission_id.lower()).strip("-")
    return f"cmh-{safe[:36]}-{hashlib.sha256(mission_id.encode()).hexdigest()[:8]}"


def docker_env(mission_id: str) -> dict[str, str]:
    return {"COMPOSE_PROJECT_NAME": compose_namespace(mission_id)}
