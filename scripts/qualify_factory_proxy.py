#!/usr/bin/env python3
"""Bounded real developer/planner + direct DeepSeek qualification, NEW ledger.

No old mission, no full Factory READY claim, no automatic retry on uncertainty.
The output directory must be new. Proxy review remains explicitly unqualified.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from harness.factory import Factory, FactoryBlocked, git
from harness.factory_runtime import LocalRuntime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--policy-file", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--deepseek-token-file", type=Path, required=True)
    parser.add_argument("--deepseek-model", default="deepseek-flash")
    args = parser.parse_args()
    root = args.output.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = root / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "score.py").write_text("def add(a, b):\n    return a + b\n")
    (source / ".gitignore").write_text("__pycache__/\n")
    git(source, "add", ".")
    git(source, "-c", "user.name=Qualification", "-c", "user.email=qualification@localhost", "commit", "-qm", "baseline")
    original = git(source, "rev-parse", "HEAD")
    transport = {"type": "cli_proxy", "endpoint": args.endpoint, "configured_provider": "cli_proxy_api", "policy_file": str(args.policy_file.absolute())}
    config = {"version": 1, "budget": {"max_agent_runs": 6, "max_run_tokens": 120000, "max_total_tokens": 720000, "max_wall_seconds": 1800},
              "max_rounds": 1, "timeout_seconds": 300,
              "checks": [["python3", "-m", "unittest", "discover", "-s", "tests"]],
              "ci": [["python3", "-m", "compileall", "-q", "score.py"]],
              "profiles": {"developer": {"provider": "openai", "model": args.model, "effort": "high", "transport": transport},
                           "reviewer": {"provider": "openai", "model": args.model, "transport": {"type": "official"}},
                           "second_reviewer": {"provider": "deepseek", "model": args.deepseek_model, "token_file": str(args.deepseek_token_file.absolute()), "max_output_tokens": 4096}}}
    (root / "config.json").write_text(json.dumps(config, indent=2)+"\n")
    (root / "config.json").chmod(0o600)
    runtime = LocalRuntime()
    factory = Factory(root / "state", config, runtime)
    result = {"MISSION": "EXPLICIT_CLI_PROXY_DEVELOPER_QUALIFICATION", "full_factory_ready": False,
              "proxy_openai_reviewer": "NOT_QUALIFIED", "source_original_head": original}
    try:
        mission = factory.submit({"version": 2, "mission_id": "cli-proxy-developer-qualification", "repository": str(source),
                                  "objective": "Add average(values): empty returns zero, fractional arithmetic is preserved; keep add unchanged.",
                                  "acceptance": ["average([1, 2]) == 1.5", "average([]) == 0", "add(2, 3) == 5"], "scope": ["score.py", "tests/**", ".gitignore"]})
        spec, cwd = factory.prepare(mission)
        plan = factory.agent(spec, cwd, "plan", 0, {"objective": spec["objective"],
                     "instruction": "Return a concise plan with exactly one implementation task, acceptance criteria and no decisions_required. No tools or edits are needed for this small isolated Python fixture."})
        result["plan"] = "PASS"
        result["plan_runtime"] = plan["runtime_identity"]
        implementation = factory.agent(spec, cwd, "implement", 0, {"objective": spec["objective"], "plan": plan["output"],
                     "instruction": "Implement the small Python fixture: add average(values) preserving fractional arithmetic and returning zero for empty input. Add unittest regressions in tests/test_score.py. Work only inside this repo. Do not commit or merge. Return structured summary/known_risks. Keep the implementation minimal."})
        result["implement"] = "PASS"
        result["implementation_runtime"] = implementation["runtime_identity"]
        git(cwd, "add", ".")
        git(cwd, "-c", "user.name=Qualification", "-c", "user.email=qualification@localhost", "commit", "-qm", "proxy implementation checkpoint")
        target = factory.target(spec, cwd)
        result["local_gates"] = factory.gates(spec, cwd, target, "checks", 0)
        result["developer_ready"] = True
        result["qualification"] = "CLI_PROXY_DEVELOPER_READY"
        result["deepseek_review"] = factory.review(spec, cwd, target, "second_reviewer")
    except FactoryBlocked as exc:
        if not result.get("developer_ready"):
            result["qualification"] = "UNKNOWN_OR_BLOCKED"
        else:
            result["deepseek_review"] = {"status": exc.status, "completed": False}
        result["reason"] = str(exc)
    finally:
        from harness.factory_budget import accounting
        rows = factory.db.execute("SELECT * FROM operations ORDER BY started").fetchall()
        result["accounting"] = accounting(rows, config["budget"])
        result["operations"] = [{"id": r["id"], "stage": r["stage"], "lane": r["lane"], "status": r["status"]} for r in rows]
        result["original_source_unchanged"] = git(source, "rev-parse", "HEAD") == original and not git(source, "status", "--porcelain")
        (root / "qualification-report.json").write_text(json.dumps(result, indent=2)+"\n")
        factory.close()
    print(json.dumps({k: result[k] for k in ["MISSION", "proxy_openai_reviewer", "accounting", "operations", "original_source_unchanged"]}, indent=2))
    return 0 if result.get("qualification") == "CLI_PROXY_DEVELOPER_READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
