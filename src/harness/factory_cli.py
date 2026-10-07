"""Customer-facing delivery commands; internal engineering needs no extra prompts."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

from .factory import Factory, validate_config
from .factory_fixture import demo
from .factory_runtime import official_rubric, LocalRuntime
from .model_registry import read_private_token


DEFAULT_STATE = Path.home() / ".local" / "state" / "codex-factory"
DEFAULT_CONFIG = Path.home() / ".config" / "codex-factory" / "config.json"
COMMANDS = {"submit", "factory-run", "factory-resume", "factory-status", "factory-approve", "factory-demo", "factory-doctor"}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="harness", description="Submit a product request and receive a verified candidate. Merge/release remain human-controlled.")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="Describe a product request; run the factory autonomously")
    submit.add_argument("--repository", type=Path, required=True)
    submit.add_argument("--request", required=True)
    submit.add_argument("--mission-id", default=None)
    submit.add_argument("--acceptance", action="append", default=[])
    submit.add_argument("--constraint", action="append", default=[])
    submit.add_argument("--scope", action="append", default=None)
    submit.add_argument("--base", default="HEAD")
    submit.add_argument("--mission-scope-file", help="optional committed project governance contract")
    for command in ("factory-run", "factory-resume"):
        child = sub.add_parser(command)
        child.add_argument("mission", type=Path if command == "factory-run" else str)
    status = sub.add_parser("factory-status")
    status.add_argument("mission_id")
    approve = sub.add_parser("factory-approve", help="Record explicit human approval; never execute merge/release")
    approve.add_argument("mission_id")
    approve.add_argument("--action", choices=["merge", "release"], required=True)
    approve.add_argument("--head", required=True)
    approve.add_argument("--reason", required=True)
    fixture = sub.add_parser("factory-demo", help="Free local end-to-end acceptance, including a real code fix")
    fixture.add_argument("--output", type=Path)
    sub.add_parser("factory-doctor", help="Check local configuration and capabilities without model inference")
    for name, child in sub.choices.items():
        if name != "factory-demo":
            child.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
            child.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args(argv)
    try:
        if args.command == "factory-demo":
            root = args.output or Path(tempfile.mkdtemp(prefix="codex-factory-demo-")) / "acceptance"
            result = demo(root)
            result["ACCEPTANCE_REPORT"] = str(root / "acceptance-report.json")
        else:
            if not args.config.is_file():
                parser.error(f"operator configuration missing: {args.config}; copy config/factory.example.json and set project checks, budget and the DeepSeek token path once")
            config = validate_config(json.loads(args.config.read_text()))
            if config["simulation"]:
                parser.error("fixture policy is only available through factory-demo; it cannot execute customer missions")
            if args.command == "factory-doctor":
                official_rubric()
                lanes = {}
                for lane, profile in config["profiles"].items():
                    try:
                        if profile["provider"] == "openai":
                            LocalRuntime().profile_identity(profile)
                        else:
                            read_private_token(Path(profile["token_file"]))
                        lanes[lane] = "LOCAL_CONFIGURATION_VALID; inference/access not checked"
                    except (ValueError, OSError, RuntimeError) as exc:
                        lanes[lane] = "NOT_READY: " + str(exc)
                result = {"CONFIG": "VALID", "OFFICIAL_RUBRIC": "VERIFIED", "CODEX": shutil.which("codex") or "UNAVAILABLE",
                          "BUBBLEWRAP": shutil.which("bwrap") or "UNAVAILABLE", "MODEL_INFERENCE_CALLS": 0,
                          "LANES": lanes,
                          "LIVE_ENGINE_QUALIFICATION": "NOT_ASSERTED", "HOSTED_CI": "NOT_CONFIGURED; ci commands run locally"}
            else:
                factory = Factory(args.state_dir, config, progress=lambda mission, state: print(f"Factory {mission}: {state}", file=sys.stderr, flush=True))
                try:
                    if args.command == "submit":
                        spec = {"version": 2, "mission_id": args.mission_id or "delivery-" + uuid.uuid4().hex[:12],
                                "repository": str(args.repository), "objective": args.request, "acceptance": args.acceptance,
                                "constraints": args.constraint, "scope": args.scope or ["**"], "base": args.base}
                        if args.mission_scope_file:
                            spec["mission_scope_file"] = args.mission_scope_file
                        result = factory.run(factory.submit(spec))
                    elif args.command == "factory-run":
                        result = factory.run(factory.submit(json.loads(args.mission.read_text())))
                    elif args.command == "factory-resume":
                        result = factory.run(args.mission)
                    elif args.command == "factory-status":
                        result = factory.report(args.mission_id)
                    else:
                        result = factory.approve(args.mission_id, args.action, args.reason, args.head)
                finally:
                    factory.close()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        parser.exit(2, f"Factory stopped safely: {exc}\n")


if __name__ == "__main__":
    main()
