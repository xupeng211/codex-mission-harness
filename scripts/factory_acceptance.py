#!/usr/bin/env python3
"""Opt-in real provider acceptance. Never run by unit tests or CI.

Uses a fresh isolated project/ledger. Every model invocation is the production
LocalRuntime. The sole injected code defect is recorded in the real implement
result; no model output, test result, finding or usage is fabricated.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

from harness.factory import Factory, READY, git
from harness.factory_runtime import LocalRuntime


class InjectedRuntime(LocalRuntime):
    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        result = super().agent(role, profile, cwd, payload, transcript, timeout, denied_roots)
        if role == "implement" and payload.get("task_index") == 0:
            path = cwd / "score.py"
            before = path.read_text()
            function = next(n for n in ast.parse(before).body if isinstance(n, ast.FunctionDef) and n.name == "average")
            # Preserve all real model-written tests. This unusual size is an
            # explicit acceptance defect, which independent review must find.
            insert = function.body[0].lineno - 1
            lines = before.splitlines(keepends=True)
            lines[insert:insert] = ["    if len(values) == 37:\n", "        return 0  # acceptance fault: silently wrong for 37 values\n"]
            after = "".join(lines)
            path.write_text(after)
            result["acceptance_fault_injection"] = {"path": "score.py", "kind": "incorrect average for length 37",
                "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
                "model_result_unchanged": True, "tests_unchanged": True}
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--mission-id", default="real-factory-acceptance")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    repo = args.output / "source"
    repo.mkdir()
    config = json.loads(args.config.read_text())
    git(repo, "init", "-q")
    (repo / ".gitignore").write_text("__pycache__/\n*.pyc\n.pytest_cache/\n")
    (repo / "score.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "tests").mkdir()
    (repo / "tests/test_score.py").write_text("import unittest\nfrom score import add\nclass Tests(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2,3),5)\n")
    if "hosted_ci" in config:
        workflow = repo / ".github/workflows/ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("""name: Acceptance CI
on: [push]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.14']
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: ${{ matrix.python-version }}
      - run: python -m unittest discover -s tests -v
      - run: python -c \"import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path('.').rglob('*.py')]\"
""")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=Acceptance", "-c", "user.email=acceptance@localhost", "commit", "-qm", "baseline")
    base = git(repo, "rev-parse", "HEAD")
    factory = Factory(args.output / "state", config, InjectedRuntime(),
                      progress=lambda m, s: print(f"{m}: {s}", flush=True))
    try:
        mission = factory.submit({"version": 2, "mission_id": args.mission_id, "repository": str(repo),
            "objective": "Add average(values) for numeric lists/tuples of ANY size. Empty input returns 0. Preserve fractions and negative results and existing add. Include regression tests. Use exactly one implementation task.",
            "scope": ["score.py", "tests/**"], "acceptance": ["arbitrary numeric collection sizes work", "empty input returns zero", "fractions and negatives preserved", "existing add unchanged"]})
        result = factory.run(mission)
        events = [dict(r) for r in factory.db.execute("SELECT * FROM events WHERE mission=? ORDER BY sequence", (mission,))]
        operations = [dict(r) for r in factory.db.execute("SELECT * FROM operations WHERE mission=? ORDER BY started", (mission,))]
        proven_findings = [json.loads(e["payload"]) for e in events if e["kind"] == "rework"]
        result["ACCEPTANCE"] = {"SIMULATED_CALLS": 0, "INJECTED_DEFECT": "length-37 average; after real implementation, before real tests",
            "SOURCE_UNCHANGED": git(repo, "rev-parse", "HEAD") == base and not git(repo, "status", "--porcelain"),
            "STAGES": [o["stage"] for o in operations], "REAL_FINDINGS_AND_REWORK": proven_findings}
        (args.output / "acceptance-report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        (args.output / "audit.json").write_text(json.dumps({"events": events, "operations": operations}, indent=2) + "\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        review_triggered = any(f.get("department") in ("reviewer", "second_reviewer") and f.get("findings") for r in proven_findings for f in r["feedback"])
        if result["DELIVERY_STATUS"] != READY or not review_triggered or not any(o["stage"] == "rework" for o in operations):
            raise SystemExit(1)
    finally:
        factory.close()


if __name__ == "__main__":
    main()
