from __future__ import annotations

import os
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from .journal import Journal, now


BOOTSTRAP = """import json, os, sys
try:
    request = json.load(sys.stdin)
    os.chdir(request['cwd'])
    os.execvpe(request['argv'][0], request['argv'], request['env'])
except BaseException as exc:
    print('harness bootstrap failed: %s' % exc, file=sys.stderr)
    raise
"""


def proc_start_ticks(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # ``comm`` is parenthesized and may itself contain spaces or ')'.
        # Locate its final delimiter, then field 22 (starttime) is index 19
        # in the remaining fields beginning with state (field 3).
        comm_end = stat.rfind(")")
        if comm_end < 0:
            return None
        fields = stat[comm_end + 2 :].split()
        return fields[19] if len(fields) > 19 else None
    except (FileNotFoundError, IndexError, ValueError):
        return None


@dataclass(frozen=True)
class JobResult:
    job_id: str
    state: str
    exit_code: int | None
    launch_head: str | None


class ProcessSupervisor:
    """Owns only registered mission processes; never guesses by command text or kills unknown PIDs."""

    def __init__(self, journal: Journal, log_root: Path):
        self.journal, self.log_root = journal, log_root
        self._children: dict[str, subprocess.Popen[bytes]] = {}
        self.launcher_pid = os.getpid()
        self.launcher_start_ticks = proc_start_ticks(self.launcher_pid)
        log_root.mkdir(parents=True, exist_ok=True)

    def start(self, mission_id: str, name: str, argv: list[str], cwd: str, env: dict[str, str], launch_head: str) -> str:
        job_id = uuid.uuid4().hex
        out, err = self.log_root / f"{job_id}.out", self.log_root / f"{job_id}.err"
        # Reserve before spawning: concurrent supervisors observe the same durable job, never launch twice.
        try:
            self.journal.db.execute("BEGIN IMMEDIATE")
            old = self.journal.db.execute("SELECT job_id FROM jobs WHERE mission_id=? AND name=? AND state IN ('STARTING','RUNNING')",
                                          (mission_id, name)).fetchone()
            if old:
                self.journal.db.commit()
                return old[0]
            self.journal.db.execute(
                "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at,launcher_pid,launcher_start_ticks,lease_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (job_id, mission_id, name, json.dumps(argv), launch_head, "STARTING", str(out), str(err), now(),
                 self.launcher_pid, self.launcher_start_ticks, uuid.uuid4().hex),
            )
            self.journal.db.commit()
        except Exception:
            self.journal.db.rollback()
            raise
        lease = self.journal.db.execute("SELECT lease_token FROM jobs WHERE job_id=?", (job_id,)).fetchone()[0]
        with out.open("wb") as stdout, err.open("wb") as stderr:
            try:
                # The bootstrap cannot run the gate until its PID has been journaled. If
                # this controller dies before publication its stdin closes and no gate runs.
                proc = subprocess.Popen([sys.executable, "-c", BOOTSTRAP], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                        start_new_session=True)
            except OSError as exc:
                self.journal.db.execute("UPDATE jobs SET state='FAILED_LAUNCH',ended_at=? WHERE job_id=?", (now(), job_id))
                self.journal.event(mission_id, "process_launch_failed", {"job_id": job_id, "error": str(exc)})
                self.journal.db.commit()
                raise
        updated = self.journal.db.execute(
            "UPDATE jobs SET pid=?,pgid=?,start_ticks=?,state='RUNNING' WHERE job_id=? AND state='STARTING' AND lease_token=? AND launcher_pid=? AND launcher_start_ticks IS ?",
            (proc.pid, os.getpgid(proc.pid), proc_start_ticks(proc.pid), job_id, lease, self.launcher_pid, self.launcher_start_ticks),
        ).rowcount
        if updated != 1:
            proc.terminate()
            raise RuntimeError("launch lease was lost before gate release")
        self.journal.db.commit()
        assert proc.stdin is not None
        proc.stdin.write(json.dumps({"argv": argv, "cwd": cwd, "env": {**os.environ, **env}}).encode())
        proc.stdin.close()
        self.journal.event(mission_id, "process_started", {"job_id": job_id, "name": name, "pid": proc.pid, "argv": argv})
        self.journal.db.commit()
        self._children[job_id] = proc  # prevents Popen finalizer from reaping our registered child
        return job_id

    def poll(self, mission_id: str) -> list[JobResult]:
        rows = self.journal.db.execute("SELECT * FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')", (mission_id,)).fetchall()
        results = []
        for row in rows:
            if row["state"] == "STARTING":
                # Only the recorded launcher may publish a PID. A dead launcher means the
                # bootstrap was never released, so retrying is safe and deterministic.
                observed = proc_start_ticks(row["launcher_pid"]) if row["launcher_pid"] else None
                launcher_alive = (observed is not None and row["launcher_start_ticks"] is not None and
                                  observed == row["launcher_start_ticks"])
                if launcher_alive:
                    results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                    continue
                self.journal.db.execute("UPDATE jobs SET state='LOST',ended_at=? WHERE job_id=? AND state='STARTING'",
                                        (now(), row["job_id"]))
                self.journal.event(mission_id, "process_lost", {"job_id": row["job_id"], "reason": "stale_starting_lease"})
                results.append(JobResult(row["job_id"], "LOST", None, row["launch_head"]))
                continue
            pid, ticks = row["pid"], row["start_ticks"]
            child = self._children.get(row["job_id"])
            if child is not None:
                code = child.poll()
                if code is None:
                    results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                    continue
                self._children.pop(row["job_id"], None)
                state = "EXITED"
                self.journal.db.execute("UPDATE jobs SET state=?,exit_code=?,ended_at=? WHERE job_id=?",
                                        (state, code, now(), row["job_id"]))
                self.journal.event(mission_id, "process_exited", {"job_id": row["job_id"], "exit_code": code})
                results.append(JobResult(row["job_id"], state, code, row["launch_head"]))
                continue
            current = proc_start_ticks(pid) if pid else None
            if ticks is not None and current is not None and current == ticks:
                results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                continue
            # waitpid works for children; /proc absence after a restart is a safe, explicit LOST state.
            code = None
            try:
                waited_pid, status = os.waitpid(pid, os.WNOHANG)
                if waited_pid == pid:
                    code = os.waitstatus_to_exitcode(status)
            except ChildProcessError:
                pass
            state = "EXITED" if code is not None else "LOST"
            self.journal.db.execute("UPDATE jobs SET state=?,exit_code=?,ended_at=? WHERE job_id=?",
                                    (state, code, now(), row["job_id"]))
            self.journal.event(mission_id, "process_" + state.lower(), {"job_id": row["job_id"], "exit_code": code})
            results.append(JobResult(row["job_id"], state, code, row["launch_head"]))
        self.journal.db.commit()
        return results
