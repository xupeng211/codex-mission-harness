#!/usr/bin/env python3
"""Run real model qualification and publish a private, durable receipt."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from harness.model_registry import load_registry  # noqa: E402
from harness.model_qualification import (  # noqa: E402
    qualify_live, qualification_receipt, validate_qualification_receipt,
)
from harness.model_registry import read_private_token  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("builder", "independent_reviewer",
                                                       "final_reviewer"))
    parser.add_argument("--token-file")
    parser.add_argument("--auth-key-file")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--registry")
    args = parser.parse_args()
    spec = load_registry(args.registry).role(args.role)
    if args.timeout < 1 or args.timeout > 900:
        parser.error("timeout must be between 1 and 900 seconds")
    if not args.output.is_absolute() or args.output.exists():
        parser.error("output must be a new absolute path")
    repository = Path(__file__).resolve().parents[1]
    try:
        args.output.resolve().relative_to(repository)
    except ValueError:
        pass
    else:
        parser.error("qualification evidence must be outside the reviewed repository")
    auth_path = args.auth_key_file or args.token_file
    if not auth_path:
        parser.error("--auth-key-file is required (DeepSeek may reuse --token-file)")
    auth_key = read_private_token(Path(auth_path))
    result = qualify_live(spec, token_file=args.token_file, timeout=args.timeout)
    if not result.passed:
        print(json.dumps({"status": "FAIL", "identity": result.identity,
                          "cases_failed": result.cases_failed}), file=sys.stderr)
        return 1
    receipt = qualification_receipt(result, auth_key=auth_key, registry_path=args.registry)
    payload = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    validate_qualification_receipt(args.output, spec, auth_key=auth_key,
                                   registry_path=args.registry)
    print(json.dumps({"status": "PASS", "identity": result.identity,
                      "receipt": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
