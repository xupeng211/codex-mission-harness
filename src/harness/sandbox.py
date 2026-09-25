"""Fail-closed execution boundary for candidate-controlled project gates."""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PROJECT_GATE_ENV = frozenset({
    "BASE_REF", "COMPOSE_PROJECT_NAME", "HEAD_REF", "JSON",
    "MISSION_SCOPE_FILE", "PR_BODY",
})


class SandboxUnavailable(RuntimeError):
    """The gate cannot run without the required isolation boundary."""


@dataclass(frozen=True)
class SandboxInvocation:
    argv: list[str]
    cwd: str
    env: dict[str, str]
    config_path: Path


def _git_value(worktree: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(worktree), *args], text=True,
            stderr=subprocess.PIPE,
            env={"PATH": SAFE_PATH, "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"},
            timeout=15,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxUnavailable(f"cannot prepare isolated project gate Git view: {exc}") from exc


def _git_config(worktree: Path, key: str, default: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(worktree), "config", "--local", "--get", key],
            stdout=subprocess.PIPE,
            text=True, stderr=subprocess.DEVNULL,
            env={"PATH": SAFE_PATH, "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"},
            timeout=15, check=True,
        )
        value = completed.stdout.strip()
    except subprocess.CalledProcessError:
        return default
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxUnavailable(f"cannot read safe Git format settings: {exc}") from exc
    return value


def _safe_git_config(worktree: Path, metadata_dir: Path, job_id: str) -> tuple[Path, Path, Path]:
    common = Path(_git_value(worktree, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    git_dir = Path(_git_value(worktree, "rev-parse", "--path-format=absolute", "--git-dir")).resolve()
    if (not common.is_dir() or not git_dir.is_dir() or
            not (common / "config").is_file() or (common / "config").is_symlink()):
        raise SandboxUnavailable("project gate Git metadata directory is unavailable")

    worktree_config = _git_config(worktree, "extensions.worktreeConfig", "false").lower()
    if worktree_config not in {"false", "no", "off", "0", ""}:
        raise SandboxUnavailable("Git per-worktree configuration is unsupported by the gate sandbox")

    format_version = _git_config(worktree, "core.repositoryformatversion", "0")
    if format_version not in {"0", "1"}:
        raise SandboxUnavailable("unsupported Git repository format for isolated project gate")
    filemode = _git_config(worktree, "core.filemode", "true").lower()
    if filemode not in {"true", "false"}:
        raise SandboxUnavailable("invalid Git filemode setting for isolated project gate")
    object_format = _git_config(worktree, "extensions.objectformat", "sha1").lower()
    if object_format not in {"sha1", "sha256"}:
        raise SandboxUnavailable("unsupported Git object format for isolated project gate")

    lines = [
        "[core]",
        f"\trepositoryformatversion = {format_version}",
        f"\tfilemode = {filemode}",
        "\tbare = false",
        "\tlogallrefupdates = true",
    ]
    if object_format == "sha256":
        lines.extend(("[extensions]", "\tobjectformat = sha256"))
    metadata_dir = metadata_dir.resolve(strict=False)
    try:
        metadata_dir.relative_to(worktree)
    except ValueError:
        pass
    else:
        raise SandboxUnavailable("sandbox Git config storage must be outside the candidate worktree")
    metadata_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = metadata_dir / f"{job_id}.gitconfig"
    try:
        with config_path.open("x", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
        config_path.chmod(0o600)
    except OSError as exc:
        raise SandboxUnavailable(f"cannot create isolated Git config: {exc}") from exc
    return common, git_dir, config_path


def _ensure_masked_path_args(path: Path, masked_roots: tuple[Path, ...]) -> list[str]:
    """Recreate only destination parents hidden by a tmpfs mount."""
    resolved = path.resolve(strict=False)
    for root in masked_roots:
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            continue
        current = root
        result: list[str] = []
        for part in relative.parts:
            current = current / part
            result.extend(("--dir", str(current)))
        return result
    return []


def project_gate_invocation(
    argv: list[str], cwd: str, env: dict[str, str], metadata_dir: Path, job_id: str,
) -> SandboxInvocation:
    """Build a bubblewrap command with no inherited credentials or network."""
    executable = shutil.which("bwrap")
    if not executable:
        raise SandboxUnavailable("bubblewrap is required for candidate-controlled project gates")
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(value, str) or "\x00" in value for value in argv)):
        raise SandboxUnavailable("project gate command is malformed")
    if not isinstance(env, dict) or any(
            not isinstance(key, str) or key not in PROJECT_GATE_ENV or
            not isinstance(value, str) or "\x00" in value for key, value in env.items()):
        raise SandboxUnavailable("project gate requested an environment value outside the allowlist")

    try:
        worktree = Path(cwd).resolve(strict=True)
    except OSError as exc:
        raise SandboxUnavailable(f"project gate worktree is unavailable: {exc}") from exc
    if not worktree.is_dir() or Path(_git_value(worktree, "rev-parse", "--show-toplevel")).resolve() != worktree:
        raise SandboxUnavailable("project gate cwd is not the repository worktree root")
    common, git_dir, config_path = _safe_git_config(worktree, metadata_dir, job_id)

    sandbox_env = {
        "PATH": SAFE_PATH,
        "HOME": "/tmp/cmh-home",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "CI": "1",
    }
    sandbox_env.update(env)

    evidence_dir: Path | None = None
    if "MISSION_SCOPE_FILE" in env:
        scope = Path(env["MISSION_SCOPE_FILE"]).resolve(strict=False)
        try:
            relative_scope = scope.relative_to(worktree)
        except ValueError as exc:
            raise SandboxUnavailable("mission scope file is outside the candidate worktree") from exc
        if not scope.is_file():
            raise SandboxUnavailable("mission scope file is not a regular file")
        sandbox_env["MISSION_SCOPE_FILE"] = str(Path("/mnt") / relative_scope)
    if "PR_BODY" in env:
        raw_body = Path(env["PR_BODY"])
        if raw_body.is_symlink():
            raise SandboxUnavailable("prepared PR body must not be a symbolic link")
        try:
            body = raw_body.resolve(strict=True)
        except OSError as exc:
            raise SandboxUnavailable("prepared PR body is unavailable") from exc
        expected_root = worktree.parent / ".cmh-gate-evidence"
        if (body.name != "pr-body.md" or body.parent.parent.parent != expected_root.resolve()
                or not body.is_file() or body.is_symlink()):
            raise SandboxUnavailable("prepared PR body is outside the approved gate evidence location")
        try:
            children = {entry.name for entry in body.parent.iterdir()}
        except OSError as exc:
            raise SandboxUnavailable("prepared PR body evidence is unavailable") from exc
        if children != {"pr-body.md"}:
            raise SandboxUnavailable("prepared PR evidence directory contains unexpected files")
        evidence_dir = body.parent
        sandbox_env["PR_BODY"] = "/tmp/cmh-pr-evidence/pr-body.md"

    root_dirs = (Path("/home"), Path("/root"), Path("/run"), Path("/tmp"),
                 Path("/var/tmp"), Path("/sys"))
    for root in root_dirs:
        if not root.is_dir():
            raise SandboxUnavailable(f"required sandbox mountpoint is unavailable: {root}")
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (OSError, KeyError) as exc:
        raise SandboxUnavailable("cannot identify the controller home directory for masking") from exc
    home_is_masked = False
    for root in root_dirs:
        try:
            home.relative_to(root)
            home_is_masked = True
            break
        except ValueError:
            continue
    if not home_is_masked and home == Path("/"):
        raise SandboxUnavailable("refusing to run a project gate with the controller home at filesystem root")
    masked_roots = tuple(dict.fromkeys((*root_dirs, home)))

    # Linked worktrees keep their Git directory in the shared repository. A
    # regular checkout instead gets Git metadata overlaid inside /mnt.
    gitfile = worktree / ".git"
    if gitfile.is_symlink() or not (gitfile.is_file() or gitfile.is_dir()):
        raise SandboxUnavailable("project worktree has unsupported Git metadata layout")
    linked_worktree = gitfile.is_file()
    common_target = common if linked_worktree else Path("/mnt/.git")

    command = [
        executable,
        "--unshare-all", "--die-with-parent", "--new-session",
        "--ro-bind", "/", "/",
        "--tmpfs", "/home", "--tmpfs", "/root", "--tmpfs", "/run",
        "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/sys",
        "--proc", "/proc", "--dev", "/dev",
        "--dir", "/tmp/cmh-home",
    ]
    if not home_is_masked:
        if not home.is_dir():
            raise SandboxUnavailable("controller home directory cannot be masked")
        command.extend(("--tmpfs", str(home)))
    command.extend(("--bind", str(worktree), "/mnt"))
    if linked_worktree:
        command.extend(_ensure_masked_path_args(common, masked_roots))
        command.extend(("--ro-bind", str(common), str(common_target)))
    else:
        command.extend(("--ro-bind", str(common), str(common_target)))
    # Local Git config can contain HTTP authorization headers or credential
    # helpers. Replace it with a minimal format-only config before the command.
    command.extend(("--ro-bind", str(config_path), str(common_target / "config")))
    if evidence_dir is not None:
        command.extend(("--dir", "/tmp/cmh-pr-evidence",
                        "--ro-bind", str(evidence_dir), "/tmp/cmh-pr-evidence"))
    command.extend(("--clearenv",))
    for key, value in sorted(sandbox_env.items()):
        command.extend(("--setenv", key, value))
    command.extend(("--chdir", "/mnt", "--", *argv))
    return SandboxInvocation(command, "/", sandbox_env, config_path)


def preflight_project_gate(invocation: SandboxInvocation) -> None:
    """Verify the isolation namespace can start before registering a gate job."""
    try:
        separator = invocation.argv.index("--")
        command = [*invocation.argv[:separator + 1], "/bin/true"]
        result = subprocess.run(
            command, cwd=invocation.cwd, env=invocation.env,
            text=True, capture_output=True, check=False, timeout=15,
        )
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        raise SandboxUnavailable(f"bubblewrap isolation preflight failed: {exc}") from exc
    if result.returncode != 0:
        raise SandboxUnavailable(
            f"bubblewrap isolation preflight exited {result.returncode}"
        )
