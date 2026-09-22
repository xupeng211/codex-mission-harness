from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import FootballPredictionAdapter, SimulatedAdapter
from .codex import AppServerCodex, FixtureCodex
from .domain import MissionSpec
from .isolation import WorktreeManager
from .journal import Journal
from .process import ProcessSupervisor
from .supervisor import Supervisor


def load_spec(path: Path) -> MissionSpec:
    data = json.loads(path.read_text())
    required = {"schema_version", "mission_id", "repository", "objective"}
    if data.get("schema_version") != 1 or not required <= data.keys():
        raise ValueError("mission spec must be v1 and include mission_id, repository, objective")
    for field in ("required_gates", "reviews", "post_merge_gates", "forbidden_actions"):
        if field in data:
            data[field] = tuple(data[field])
    adapter = data.get("adapter", "footballprediction")
    if not isinstance(adapter, str) or adapter not in {"footballprediction", "simulation"}:
        raise ValueError("adapter must be exactly footballprediction or simulation")
    return MissionSpec(**data)


def build(root: Path, adapter_name: str = "footballprediction", codex=None) -> Supervisor:
    journal = Journal(root / "data" / "harness.sqlite")
    if adapter_name == "simulation":
        adapter, selected_codex = SimulatedAdapter(), (codex or FixtureCodex())
    elif adapter_name == "footballprediction":
        adapter, selected_codex = FootballPredictionAdapter(), (codex or AppServerCodex())
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
    parser = argparse.ArgumentParser(prog="harness")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run"); run.add_argument("mission", type=Path)
    status = sub.add_parser("status"); status.add_argument("mission_id")
    resume = sub.add_parser("resume"); resume.add_argument("mission", type=Path)
    approve = sub.add_parser("approve"); approve.add_argument("mission_id"); approve.add_argument("--action", required=True); approve.add_argument("--reason", default="")
    args = parser.parse_args()
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
        journal.approve(args.mission_id, args.action, args.reason)
        print(f"MISSION={args.mission_id}\nAPPROVAL={args.action}:APPROVED")
        return
    spec = load_spec(args.mission)
    supervisor = build(args.root, spec.adapter)
    try:
        existing = supervisor.journal.mission(spec.mission_id)
        WorktreeManager().validate(existing["repo"], existing["branch"], existing["worktree"])
    except KeyError:
        tree = WorktreeManager().ensure(spec.repository, spec.mission_id, args.root / "data" / "worktrees")
        supervisor.create(spec, tree.path, tree.base_sha, tree.branch)
    supervisor.run_until_wait(spec.mission_id, spec)
    describe(supervisor, spec.mission_id)


if __name__ == "__main__":
    main()
