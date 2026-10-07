from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .adapters import FootballPredictionAdapter, SimulatedAdapter
from .codex import AppServerCodex, FixtureCodex
from .domain import MissionSpec
from .isolation import WorktreeManager, run as git_run
from .journal import Journal
from .process import ProcessSupervisor
from .supervisor import Supervisor


def validate_builder_qualification(receipt_path: Path | None,
                                   auth_key_file: Path | None) -> None:
    """Require a distinct live builder certificate before starting App Server."""
    from .model_qualification import require_builder_qualification
    require_builder_qualification(receipt_path, auth_key_file)


def load_spec(path: Path) -> MissionSpec:
    return MissionSpec.from_mapping(json.loads(path.read_text()))


def reconcile_supplied_spec(journal: Journal, supplied: MissionSpec) -> tuple[MissionSpec, bool]:
    """Existing missions are governed only by their immutable durable contract."""
    try:
        persisted = journal.spec(supplied.mission_id)
    except KeyError:
        return supplied, False
    if persisted != supplied:
        raise ValueError("supplied mission spec differs from the persisted mission contract")
    return persisted, True


def approval_head(journal: Journal, spec: MissionSpec, row) -> str:
    """Return the adapter-owned source identity used to bind an approval."""
    if spec.adapter == "simulation":
        # Simulation owns a synthetic identity; never replace it with a real
        # repository SHA merely because the fixture has a worktree path.
        return row["current_head"]
    WorktreeManager().validate(row["repo"], row["branch"], row["worktree"])
    return git_run("git", "-C", row["worktree"], "rev-parse", "HEAD")


def build(root: Path, adapter_name: str = "footballprediction", codex=None,
          forbidden_actions: tuple[str, ...] = (), worktree: str | None = None,
          builder_qualification: Path | None = None,
          builder_auth_key_file: Path | None = None) -> Supervisor:
    journal = Journal(root / "data" / "harness.sqlite")
    if adapter_name == "simulation":
        adapter, selected_codex = SimulatedAdapter(), (codex or FixtureCodex())
    elif adapter_name == "footballprediction":
        if codex is None:
            validate_builder_qualification(builder_qualification, builder_auth_key_file)
        codex_args = {"forbidden_actions": forbidden_actions}
        if worktree is not None:
            codex_args["worktree"] = worktree
        if codex is None:
            codex_args["builder_qualification"] = builder_qualification
            codex_args["builder_auth_key_file"] = builder_auth_key_file
        adapter, selected_codex = FootballPredictionAdapter(), (codex or AppServerCodex(**codex_args))
    else:
        raise ValueError("adapter must be exactly footballprediction or simulation")
    return Supervisor(journal, ProcessSupervisor(journal, root / "data" / "logs"), selected_codex, adapter)


def describe(supervisor: Supervisor, mission_id: str) -> None:
    status = supervisor.journal.status(mission_id)
    row = supervisor.journal.mission(mission_id)
    print(f"MISSION={mission_id}\nSTATE={status.state}\nHEAD={status.head or 'UNKNOWN'}\nWORKTREE={status.worktree or 'UNKNOWN'}")
    print(f"BACKGROUND_JOBS={status.background_jobs}\nCOMPLETED_GATES={row['completed_gates_json']}\nPENDING_GATE={status.pending_gate or 'NONE'}")
    print(f"APPROVAL={row['approval_state']}\nTERMINAL={'YES' if status.terminal else 'NO'}")


def main() -> None:
    from .factory_cli import COMMANDS, main as factory_main
    if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
        factory_main(sys.argv[1:])
        return
    parser = argparse.ArgumentParser(prog="harness")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run"); run.add_argument("mission", type=Path)
    run.add_argument("--legacy", action="store_true", help="explicitly opt into deprecated v1 execution")
    run.add_argument("--builder-qualification", type=Path)
    run.add_argument("--builder-auth-key-file", type=Path)
    status = sub.add_parser("status"); status.add_argument("mission_id")
    resume = sub.add_parser("resume"); resume.add_argument("mission", type=Path)
    resume.add_argument("--legacy", action="store_true", help="explicitly opt into deprecated v1 execution")
    resume.add_argument("--builder-qualification", type=Path)
    resume.add_argument("--builder-auth-key-file", type=Path)
    approve = sub.add_parser("approve"); approve.add_argument("mission_id"); approve.add_argument("--action", required=True); approve.add_argument("--reason", default="")
    args = parser.parse_args()
    if args.command in ("run", "resume") and not args.legacy:
        parser.error("v1 execution is deprecated; new product requests use 'harness submit'. Historical execution requires --legacy")
    if args.command == "status":
        # status is read-only and deliberately does not start Codex.
        journal = Journal(args.root / "data" / "harness.sqlite")
        try:
            row = journal.mission(args.mission_id)
        except KeyError:
            parser.error(f"unknown mission: {args.mission_id}")
        observed = journal.status(args.mission_id)
        print(f"MISSION={args.mission_id}\nSTATE={observed.state}\nHEAD={observed.head or 'UNKNOWN'}\nWORKTREE={observed.worktree or 'UNKNOWN'}")
        print(f"BACKGROUND_JOBS={observed.background_jobs}\nCOMPLETED_GATES={row['completed_gates_json']}\nPENDING_GATE={observed.pending_gate or 'NONE'}")
        print(f"APPROVAL={row['approval_state']}\nTERMINAL={'YES' if observed.terminal else 'NO'}")
        return
    if args.command == "approve":
        journal = Journal(args.root / "data" / "harness.sqlite")
        try:
            spec = journal.spec(args.mission_id)
            row = journal.mission(args.mission_id)
        except KeyError:
            parser.error(f"unknown mission: {args.mission_id}")
        observed_head = approval_head(journal, spec, row)
        journal.reconcile_head(args.mission_id, observed_head)
        journal.approve(args.mission_id, args.action, args.reason, observed_head=observed_head)
        print(f"MISSION={args.mission_id}\nAPPROVAL={args.action}:APPROVED")
        return
    supplied_spec = load_spec(args.mission)
    journal = Journal(args.root / "data" / "harness.sqlite")
    spec, exists = reconcile_supplied_spec(journal, supplied_spec)
    if spec.adapter != "simulation" and spec.merge_policy != "owner_approval":
        raise ValueError("live legacy missions require explicit owner approval; automatic merge is disabled")
    print("DEPRECATED_PATH=V1_REVIEWER_ORCHESTRATION; new missions use harness submit", file=sys.stderr)
    worktrees = WorktreeManager()
    if exists:
        existing = journal.mission(spec.mission_id)
        tree = worktrees.validate(existing["repo"], existing["branch"], existing["worktree"])
    else:
        tree = worktrees.ensure(
            spec.repository, spec.mission_id, args.root / "data" / "worktrees",
        )
    supervisor = build(
        args.root, spec.adapter, forbidden_actions=spec.forbidden_actions, worktree=tree.path,
        builder_qualification=args.builder_qualification,
        builder_auth_key_file=args.builder_auth_key_file,
    )
    try:
        if not exists:
            supervisor.create(spec, tree.path, tree.base_sha, tree.branch)
        supervisor.run_until_terminal(spec.mission_id, spec)
        describe(supervisor, spec.mission_id)
    finally:
        close = getattr(supervisor.codex, "close", None)
        if callable(close):
            close()


if __name__ == "__main__":
    main()
