"""Cost-free acceptance scenario; fixture code is never selected for live missions."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .factory import Factory, git


def fixture_config():
    return {"version": 1, "simulation": True, "budget": {"max_agent_runs": 12},
            "max_rounds": 3, "timeout_seconds": 30, "independent_review_required": True,
            "checks": [["python3", "-m", "unittest", "discover", "-s", "tests"]],
            "ci": [["python3", "-m", "compileall", "-q", "."]],
            "profiles": {"developer": {"provider": "openai", "model": "fixture-developer"},
                         "reviewer": {"provider": "openai", "model": "fixture-reviewer"},
                         "second_reviewer": {"provider": "deepseek", "model": "fixture-independent", "token_file": "/fixture/not-a-real-token"}}}


class AcceptanceRuntime:
    simulation = True

    def __init__(self):
        self.calls = []

    def agent(self, role, profile, cwd, payload, transcript, timeout, denied_roots):
        self.calls.append({"role": role, "provider": profile["provider"], "payload": payload})
        if role == "plan":
            output = {"plan": "Add average without changing add; verify empty, integral and fractional inputs.",
                      "tasks": ["Implement average and regression tests"],
                      "decisions_required": [],
                      "acceptance": ["Preserve add", "Return zero for empty input", "Preserve fractional results"]}
        elif role in ("implement", "rework"):
            # The first implementation deliberately contains a defect that
            # existing tests miss. Independent QC must initiate ordinary rework.
            operator = "//" if role == "implement" else "/"
            (cwd / "score.py").write_text("def add(a, b):\n    return a + b\n\n\ndef average(values):\n    if not values:\n        return 0\n    return sum(values) " + operator + " len(values)\n")
            (cwd / "tests").mkdir(exist_ok=True)
            extra = "\n    def test_fractional(self):\n        self.assertEqual(average([1, 2]), 1.5)\n" if role == "rework" else ""
            (cwd / "tests" / "test_score.py").write_text("import unittest\nfrom score import add, average\n\nclass ScoreTests(unittest.TestCase):\n    def test_existing(self):\n        self.assertEqual(add(2, 3), 5)\n    def test_average(self):\n        self.assertEqual(average([2, 4]), 3)\n        self.assertEqual(average([]), 0)\n" + extra)
            output = {"summary": "Added average(values), preserving add and empty/fractional behavior.", "known_risks": []}
        elif role == "review":
            output = self.review_output(cwd, payload)
        else:
            raise ValueError(role)
        transcript.write_text(json.dumps({"fixture": True, "role": role, "output": output}))
        return {"output": output, "usage": {"fixture_provider_calls": 0}, "runtime_identity": {"provider": profile["provider"], "model": profile.get("model"), "fixture": True}}

    @staticmethod
    def review_output(cwd, payload):
        if "feedback" in payload or "reviews" in payload or "plan" in payload:
            raise AssertionError("independent reviewer received prior conclusions")
        source = (cwd / "score.py").read_text()
        findings = []
        if " // " in source:
            line = next(index for index, value in enumerate(source.splitlines(), 1) if " // " in value)
            findings.append({"title": "[P2] Preserve fractional average results",
                             "body": "For inputs such as [1, 2], floor division returns 1 rather than the required 1.5; use true division.",
                             "confidence_score": 1.0, "priority": 2,
                             "code_location": {"absolute_file_path": str(cwd / "score.py"), "line_range": {"start": line, "end": line}}})
        return {"findings": findings, "overall_correctness": "patch is incorrect" if findings else "patch is correct",
                "overall_explanation": "Fractional results are lost." if findings else "Empty, integral and fractional behavior is implemented; add is preserved.",
                "overall_confidence_score": 1.0}

    def second_review(self, profile, cwd, payload, transcript, timeout):
        return self.agent("review", profile, cwd, payload, transcript, timeout, [])

    def gate(self, command, cwd, target, transcript, timeout):
        # Only the fixture's generated source runs here. Live gates always use
        # the existing bubblewrap boundary and never fall back to this runtime.
        with transcript.open("xb") as stream:
            result = subprocess.run(command, cwd=cwd, timeout=timeout, stdout=stream, stderr=subprocess.STDOUT,
                                    env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "PYTHONDONTWRITEBYTECODE": "1"})
        # compileall is a real check but its bytecode is not delivery content.
        for path in cwd.rglob("__pycache__"):
            for child in path.iterdir():
                child.unlink()
            path.rmdir()
        return {"status": "PASS" if result.returncode == 0 else "FAIL", "exit_code": result.returncode,
                "log": transcript.read_text()}


def demo(root: Path):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = root / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "score.py").write_text("def add(a, b):\n    return a + b\n")
    git(source, "add", ".")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-qm", "baseline")
    original_head = git(source, "rev-parse", "HEAD")
    runtime = AcceptanceRuntime()
    factory = Factory(root / "state", fixture_config(), runtime)
    try:
        factory.submit({"version": 2, "mission_id": "average-feature", "repository": str(source),
                        "objective": "Add average(values). Empty input returns 0; preserve fractional values and existing add behavior.",
                        "acceptance": ["average([1, 2]) == 1.5", "average([]) == 0", "add(2, 3) == 5"]})
        report = factory.run("average-feature")
        report["E2E_STAGES"] = [row[0] for row in factory.db.execute("SELECT stage FROM operations ORDER BY started")]
        report["SOURCE_UNCHANGED"] = original_head == git(source, "rev-parse", "HEAD") and not git(source, "status", "--porcelain")
        (root / "acceptance-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        return report
    finally:
        factory.close()
