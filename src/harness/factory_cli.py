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
from .factory_setup import setup
from .factory_budget import PRESETS


DEFAULT_STATE = Path.home() / ".local" / "state" / "codex-factory"
DEFAULT_CONFIG = Path.home() / ".config" / "codex-factory" / "config.json"
COMMANDS = {"setup", "submit", "status", "delivery", "resume", "cancel", "approve", "factory-run", "factory-resume", "factory-status", "factory-approve", "factory-demo", "factory-doctor"}


def readable(result):
    if "SETUP" in result:
        return f"配置完成。项目：{result['REPOSITORY']}\n下一步：{result['NEXT']}\n真实登录/模型访问会在任务执行时验证。"
    if "CANCELLATION" in result:
        return f"任务 {result['MISSION']}：已请求取消。已发生的调用和证据保留，不会重复发送。"
    if "APPROVAL" in result:
        return f"已记录对 {result['TARGET_HEAD']} 的 {result['ACTION']} 批准；尚未执行合并或发布。"
    if "DELIVERY_STATUS" not in result:
        return json.dumps(result, ensure_ascii=False, indent=2)
    budget = result['BUDGET_USED']
    lines = [f"任务：{result['MISSION']}", f"状态：{result['DELIVERY_STATUS']}",
             f"执行次数：{budget['agent_runs']}/{budget['limit']}；已观察 token：{budget['observed_tokens']}；未知 usage：{budget['unknown_usage_runs'] + budget['partial_usage_runs']}",
             f"未知 token 保留额：{budget['unknown_token_reservation']}；金额：{budget['money']}"]
    if result['DELIVERY_STATUS'] == 'READY_FOR_USER_ACCEPTANCE':
        lines += [f"测试：{result['TEST_RESULT']}；本地 CI：{result['LOCAL_CI']}；GitHub CI：{result['HOSTED_CI']}",
                  f"候选版本：{result['TARGET_HEAD']}", f"候选源码：{result['CANDIDATE']}",
                  "开发、测试和审核已完成。最终合并/发布仍需你的明确批准。"]
    else:
        lines += ["原因：" + '; '.join(result['BLOCKERS_REMAINING'])]
    preflight = result.get("PREPAID_PREFLIGHT")
    if isinstance(preflight, dict):
        lines += ["付费前预检：" + preflight["status"]]
        lines += [f"{finding['level']} {finding['check']}：{finding['detail']}" for finding in preflight["findings"]]
    lines += ["完整证据：harness delivery --json"]
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="harness", description="Submit a product request and receive a verified candidate. Merge/release remain human-controlled.")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="Describe a product request; run the factory autonomously")
    submit.add_argument("request_text", nargs="?")
    submit.add_argument("--repository", type=Path)
    submit.add_argument("--request")
    submit.add_argument("--mission-id", default=None)
    submit.add_argument("--acceptance", action="append", default=[])
    submit.add_argument("--constraint", action="append", default=[])
    submit.add_argument("--scope", action="append", default=None)
    submit.add_argument("--base", default="HEAD")
    submit.add_argument("--mission-scope-file", help="optional committed project governance contract")
    for command in ("factory-run", "factory-resume"):
        child = sub.add_parser(command, aliases=["resume"] if command == "factory-resume" else [])
        child.add_argument("mission", type=Path if command == "factory-run" else str, nargs=None if command == "factory-run" else "?")
    status = sub.add_parser("factory-status", aliases=["status", "delivery"])
    status.add_argument("mission_id", nargs="?")
    cancel = sub.add_parser("cancel", help="Stop a task; preserve all evidence and paid reservations")
    cancel.add_argument("mission_id", nargs="?")
    onboarding = sub.add_parser("setup", help="Configure a project once; no inference")
    onboarding.add_argument("--repository", type=Path, default=Path.cwd())
    onboarding.add_argument("--deepseek-token-file", type=Path)
    onboarding.add_argument("--size", choices=list(PRESETS), default="standard")
    onboarding.add_argument("--codex-home", type=Path)
    onboarding.add_argument("--reviewer-codex-home", type=Path)
    onboarding.add_argument("--deepseek-max-output-tokens", type=int, default=16384)
    onboarding.add_argument("--model")
    onboarding.add_argument("--transport", choices=["official", "cli_proxy"], default="official")
    onboarding.add_argument("--proxy-endpoint")
    onboarding.add_argument("--proxy-policy-file", type=Path)
    onboarding.add_argument("--proxy-provider", default="cli_proxy_api")
    approve = sub.add_parser("factory-approve", aliases=["approve"], help="Record explicit human approval; never execute merge/release")
    approve.add_argument("mission_id")
    approve.add_argument("--action", choices=["merge", "release"], required=True)
    approve.add_argument("--head", required=True)
    approve.add_argument("--reason", required=True)
    fixture = sub.add_parser("factory-demo", help="Free local end-to-end acceptance, including a real code fix")
    fixture.add_argument("--output", type=Path)
    sub.add_parser("factory-doctor", help="Check local configuration and capabilities without model inference")
    for child in dict.fromkeys(sub.choices.values()):
        if child.prog != "harness factory-demo":
            child.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
            child.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
            child.add_argument("--json", action="store_true", help="Print the complete machine-readable evidence report")
    args = parser.parse_args(argv)
    friendly = args.command in {"setup", "submit", "status", "delivery", "resume", "cancel", "approve"}
    args.command = {"status": "factory-status", "delivery": "factory-status", "resume": "factory-resume", "approve": "factory-approve"}.get(args.command, args.command)
    try:
        if args.command == "setup":
            result = setup(args.config, args.repository, args.deepseek_token_file, args.size, args.codex_home, args.model,
                           args.transport, args.proxy_endpoint, args.proxy_policy_file, args.proxy_provider,
                           args.reviewer_codex_home, args.deepseek_max_output_tokens)
        elif args.command == "factory-demo":
            root = args.output or Path(tempfile.mkdtemp(prefix="codex-factory-demo-")) / "acceptance"
            result = demo(root)
            result["ACCEPTANCE_REPORT"] = str(root / "acceptance-report.json")
        else:
            if not args.config.is_file():
                parser.error(f"operator configuration missing: {args.config}; run harness setup --repository /path/to/project once")
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
                          "LIVE_ENGINE_QUALIFICATION": "NOT_ASSERTED", "HOSTED_CI": config.get("hosted_ci", "NOT_CONFIGURED; ci commands run locally")}
            else:
                factory = Factory(args.state_dir, config, progress=lambda mission, state: print(f"Factory {mission}: {state}", file=sys.stderr, flush=True))
                try:
                    if args.command == "submit":
                        request = args.request or args.request_text
                        repository = args.repository or config.get("repository")
                        if not request or args.request and args.request_text or not repository:
                            raise ValueError('submit needs one requirement and a configured project; use harness setup then harness submit "feature"')
                        spec = {"version": 2, "mission_id": args.mission_id or "delivery-" + uuid.uuid4().hex[:12],
                                "repository": str(repository), "objective": request, "acceptance": args.acceptance,
                                "constraints": args.constraint, "scope": args.scope or ["**"], "base": args.base}
                        if args.mission_scope_file:
                            spec["mission_scope_file"] = args.mission_scope_file
                        result = factory.run(factory.submit(spec))
                    elif args.command == "factory-run":
                        result = factory.run(factory.submit(json.loads(args.mission.read_text())))
                    elif args.command in ("factory-resume", "factory-status", "cancel"):
                        mission = getattr(args, "mission", None) or getattr(args, "mission_id", None)
                        if mission is None:
                            latest = factory.db.execute("SELECT id FROM missions ORDER BY rowid DESC LIMIT 1").fetchone()
                            if latest is None:
                                raise ValueError("no submitted task; submit a requirement first")
                            mission = latest[0]
                        result = factory.run(mission) if args.command == "factory-resume" else factory.cancel(mission) if args.command == "cancel" else factory.report(mission)
                    else:
                        result = factory.approve(args.mission_id, args.action, args.reason, args.head)
                finally:
                    factory.close()
        print(readable(result) if friendly and not args.json else json.dumps(result, ensure_ascii=False, indent=2))
        if args.command in ("submit", "factory-run", "factory-resume") and result.get("DELIVERY_STATUS") != "READY_FOR_USER_ACCEPTANCE":
            # A shell caller must not mistake UNKNOWN or stopped work for a
            # successfully delivered candidate. Read-only status still exits 0.
            raise SystemExit(1)
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        parser.exit(2, f"Factory stopped safely: {exc}\n")


if __name__ == "__main__":
    main()
