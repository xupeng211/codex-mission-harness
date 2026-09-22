from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .journal import Journal, now


def proc_start_ticks(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/stat").read_text().split()[21]
    except (FileNotFoundError, IndexError):
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
                "INSERT INTO jobs(job_id,mission_id,name,argv_json,launch_head,state,stdout_path,stderr_path,started_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (job_id, mission_id, name, str(argv), launch_head, "STARTING", str(out), str(err), now()),
            )
            self.journal.db.commit()
        except Exception:
            self.journal.db.rollback()
            raise
        with out.open("wb") as stdout, err.open("wb") as stderr:
            try:
                proc = subprocess.Popen(argv, cwd=cwd, env={**os.environ, **env}, stdout=stdout, stderr=stderr,
                                        start_new_session=True)
            except OSError as exc:
                self.journal.db.execute("UPDATE jobs SET state='FAILED_LAUNCH',ended_at=? WHERE job_id=?", (now(), job_id))
                self.journal.event(mission_id, "process_launch_failed", {"job_id": job_id, "error": str(exc)})
                self.journal.db.commit()
                raise
        self.journal.db.execute(
            "UPDATE jobs SET pid=?,pgid=?,start_ticks=?,state='RUNNING' WHERE job_id=?",
            (proc.pid, os.getpgid(proc.pid), proc_start_ticks(proc.pid), job_id),
        )
        self.journal.event(mission_id, "process_started", {"job_id": job_id, "name": name, "pid": proc.pid, "argv": argv})
        self.journal.db.commit()
        self._children[job_id] = proc  # prevents Popen finalizer from reaping our registered child
        return job_id

    def poll(self, mission_id: str) -> list[JobResult]:
        rows = self.journal.db.execute("SELECT * FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')", (mission_id,)).fetchall()
        results = []
        for row in rows:
            if row["state"] == "STARTING":
                # A different supervisor can observe the durable reservation before the launcher publishes PID.
                results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
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
            if current == ticks:
                results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                continue
            # waitpid works for children; /proc absence after a restart is a safe, explicit LOST state.
            code = None
            try:
                _, status = os.waitpid(pid, os.WNOHANG)
                if status:
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
