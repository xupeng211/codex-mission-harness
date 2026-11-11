#!/usr/bin/python3
"""Offline CLI double. Never imports a provider or opens a network socket."""
import json
from pathlib import Path
import sys
import time

if sys.argv[1:] == ["--version"]:
    print("agy offline-fixture")
    raise SystemExit
args = sys.argv[1:]
root = Path.cwd()
packet = json.loads((root / "review-input.json").read_text())
mode = (Path(__file__).with_suffix(".mode")).read_text().strip()
with Path(__file__).with_suffix(".calls").open("a") as stream:
    stream.write(json.dumps(args) + "\n")
assert "--new-project" in args and "--sandbox" in args
assert args[args.index("--output-format") + 1] == "json"
assert not {"--continue", "--dangerously-skip-permissions"} & set(args)
Path(args[args.index("--log-file") + 1]).write_text("offline fixture lifecycle\n")
if mode == "sleep":
    # An independent session descendant exercises subreaper ownership.
    import subprocess
    subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
    time.sleep(30)
source = root / "source/score.py"
text = source.read_text()
findings = []
if " // " in text:
    line = next(i for i, row in enumerate(text.splitlines(), 1) if " // " in row)
    for priority in range(4):
        findings.append({"title": f"[P{priority}] offline synthetic finding", "body": "Synthetic trigger [1,2] loses fraction; source division is evidence; no live review.",
            "priority": priority, "confidence_score": 1.0,
            "code_location": {"absolute_file_path": str(source), "line_range": {"start": line, "end": line}}})
review = {"findings": findings, "overall_correctness": "patch is incorrect" if findings else "patch is correct",
          "overall_explanation": "Offline fixture static result", "overall_confidence_score": 1.0}
report = {"completion": "COMPLETE", "verdict": "FAIL" if findings else "PASS", "target": packet["target"],
          "read_scope": ["source/score.py and full diff"], "context_gaps": ["No code or tests executed"], "review": review}
if mode == "version":
    report["target"]["head"] = "0" * 40
if mode == "incomplete":
    report["completion"] = "INCOMPLETE"
envelope = {"status": "ERROR" if mode == "error" else "SUCCESS", "conversation_id": "offline-new-session",
            "response": json.dumps(report), "duration_seconds": .1,
            "usage": {"input_tokens": 10, "output_tokens": 20, "total_tokens": 30}}
if mode == "error":
    envelope.update(error="The stream was interrupted", finished_reason="error")
    Path(args[args.index("--log-file") + 1]).write_text("Run: attempt 1 failed (INTERNAL (code 500): Internal error encountered.), retrying in 4s\n")
if mode == "mutate":
    source.write_text("changed")
if mode == "invalid":
    print("invalid JSON")
elif mode == "truncated":
    print(json.dumps(envelope)[:80])
elif mode == "repeated":
    print(json.dumps(envelope) * 2)
else:
    print(json.dumps(envelope))
