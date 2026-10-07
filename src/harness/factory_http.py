"""Private single-request DeepSeek worker, bounded by the controller watchdog."""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

from .factory_runtime import official_rubric
from .model_registry import read_private_token
from .factory_budget import tokens
from .factory_proxy import digest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("provider redirect rejected; authentic endpoint identity is required")


def request(profile, payload, transcript, timeout):
    if profile.get("provider") != "deepseek" or profile.get("transport", {"type": "direct"}) != {"type": "direct"}:
        raise ValueError("DeepSeek review requires its fixed direct official route")
    token = read_private_token(Path(profile["token_file"]))
    body = {"model": profile["model"], "messages": [
        {"role": "system", "content": official_rubric()},
        {"role": "user", "content": json.dumps(payload, ensure_ascii=False)}],
        "response_format": {"type": "json_object"}, "max_tokens": profile.get("max_output_tokens", 8192)}
    url = "https://api.deepseek.com/chat/completions"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
    Path(transcript).write_bytes(raw)
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("DeepSeek response limit exceeded")
    result = json.loads(raw)
    route = {"route_type": "direct", "configured_provider": "deepseek", "endpoint": url,
             "auth_source": profile["token_file"], "requested_model": profile["model"]}
    identity = {"provider": "deepseek", "endpoint": url, "requested_model": profile["model"],
                "model": result.get("model"), "reported_model": result.get("model"), "response_id": result.get("id"),
                "route_identity": route, "qualification_identity": digest({"route": route, "profile": profile})}
    receipt = {"usage": result.get("usage"), "response_id": result.get("id"), "runtime_identity": identity,
               "usage_complete": tokens(result.get("usage")) is not None, "money": "UNKNOWN"}
    try:
        if not receipt["usage_complete"] or not result.get("id"):
            raise ValueError("DeepSeek completion usage/response identity is unproven")
        if result.get("model") != profile["model"]:
            raise ValueError("DeepSeek returned a different model identity; configure the canonical returned model in a new authorization")
        choice = result["choices"][0]
        if choice.get("finish_reason") != "stop":
            raise ValueError("DeepSeek review was truncated or incomplete")
        # Completed malformed content can be verified as UNKNOWN by the review
        # validator and receive its one charged schema recovery; never PASS.
        content = choice["message"]["content"]
        try:
            receipt["output"] = json.loads(content)
        except (ValueError, TypeError):
            receipt["output"] = content
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        receipt["error"] = str(exc)
    return receipt


def main():
    args = json.load(sys.stdin)
    print(json.dumps(request(**args)))


if __name__ == "__main__":
    main()
