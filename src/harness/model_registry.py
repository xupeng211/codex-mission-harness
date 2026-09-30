"""Strict role-to-model registry and noninteractive provider preflight.

The registry is an allowlist, not a fallback preference list. A changed model
must pass real provider qualification before it is enabled for a review gate.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config" / "models.json"
ROLES = frozenset({"builder", "independent_reviewer", "final_reviewer"})
PROVIDERS = frozenset({"deepseek", "openai"})
EFFORTS = frozenset({"low", "medium", "high", "xhigh"})


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    reasoning_effort: str | None = None

    def identity(self) -> dict[str, str | None]:
        return {"provider": self.provider, "model": self.model,
                "reasoning_effort": self.reasoning_effort}


@dataclass(frozen=True)
class ModelRegistry:
    roles: dict[str, ModelSpec]
    path: Path

    def role(self, name: str) -> ModelSpec:
        if name not in ROLES:
            raise ValueError(f"unknown model role: {name}")
        return self.roles[name]


def load_registry(path: str | Path | None = None) -> ModelRegistry:
    source = Path(path) if path is not None else DEFAULT_REGISTRY_PATH
    raw = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != {"version", "roles"} or raw["version"] != 1:
        raise ValueError("invalid model registry version or fields")
    roles = raw["roles"]
    if not isinstance(roles, dict) or set(roles) != ROLES:
        raise ValueError("model registry must define exactly the required roles")
    parsed = {}
    for role, value in roles.items():
        if not isinstance(value, dict) or set(value) not in (
                {"provider", "model"}, {"provider", "model", "reasoning_effort"}):
            raise ValueError(f"invalid model configuration for {role}")
        provider, model = value["provider"], value["model"]
        effort = value.get("reasoning_effort")
        if provider not in PROVIDERS or not isinstance(model, str) or not model.strip() \
                or model != model.strip() or any(char.isspace() for char in model) \
                or any(char in model for char in ('"', "'", "\\", "/")):
            raise ValueError(f"invalid provider or model for {role}")
        if provider == "deepseek" and effort is not None:
            raise ValueError("DeepSeek role cannot specify Codex reasoning effort")
        if provider == "openai" and effort not in EFFORTS:
            raise ValueError("OpenAI role requires supported reasoning effort")
        parsed[role] = ModelSpec(provider, model, effort)
    if parsed["independent_reviewer"].provider == parsed["final_reviewer"].provider:
        raise ValueError("review lanes require different providers")
    return ModelRegistry(parsed, source.resolve())


@dataclass(frozen=True)
class PreflightResult:
    identity: dict[str, str | None]
    authenticated: bool
    available: bool | None
    evidence: str


def read_private_token(path: Path) -> str:
    if not path.is_absolute():
        raise ValueError("DeepSeek token file must be an absolute regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384:
            raise ValueError("DeepSeek token file must be owner-owned, nonempty, mode 0600")
        token = os.read(fd, info.st_size + 1).decode("utf-8").strip()
        if not token:
            raise ValueError("DeepSeek token file is empty")
        return token
    finally:
        os.close(fd)


def preflight(spec: ModelSpec, *, token_file: str | Path | None = None,
              probe: bool = False, timeout: int = 30) -> PreflightResult:
    """Check local auth; optional probe confirms actual model availability.

    No provider call is made unless ``probe=True``. The caller must persist a
    successful probe with the same identity before treating a model as qualified.
    Provider text and credentials are never returned in this result.
    """
    if spec.provider == "deepseek":
        if token_file is None:
            raise ValueError("DeepSeek requires an explicit token file")
        token = read_private_token(Path(token_file))
        if not shutil.which("claude"):
            raise RuntimeError("trusted DeepSeek launcher unavailable")
        if probe:
            from .model_qualification import _actual_provider_invoke
            _actual_provider_invoke(spec, 'Return only {"decisions":[]}.', token=token,
                                    timeout=timeout)
        return PreflightResult(spec.identity(), True, True if probe else None,
                               "actual_model_probe" if probe else "local_auth_only")
    if spec.provider == "openai":
        from .openai_invocation import CANONICAL_BINARY, canonical_environment

        env = canonical_environment()
        result = subprocess.run([str(CANONICAL_BINARY), "login", "status"],
                                capture_output=True, text=True, env=env,
                                timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError("Codex noninteractive authentication check failed")
        if probe:
            from .model_qualification import _actual_provider_invoke
            _actual_provider_invoke(spec, 'Return only {"decisions":[]}.', token=None,
                                    timeout=timeout)
        return PreflightResult(spec.identity(), True, True if probe else None,
                               "actual_model_probe" if probe else "local_auth_only")
    raise ValueError("unsupported provider")
