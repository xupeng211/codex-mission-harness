from __future__ import annotations

import os
import json
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from .journal import Journal, now
from .sandbox import SandboxUnavailable, preflight_project_gate, project_gate_invocation


BOOTSTRAP = """import json, os, sys
try:
    request = json.load(sys.stdin)
    os.chdir(request['cwd'])
    os.execvpe(request['argv'][0], request['argv'], request['env'])
except BaseException as exc:
    print('harness bootstrap failed: %s' % exc, file=sys.stderr)
    raise
"""


def proc_identity(pid: int) -> tuple[str, str | None]:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # ``comm`` is parenthesized and may itself contain spaces or ')'.
        # Locate its final delimiter, then field 22 (starttime) is index 19
        # in the remaining fields beginning with state (field 3).
        comm_end = stat.rfind(")")
        if comm_end < 0:
            return "UNKNOWN", None
        fields = stat[comm_end + 2 :].split()
        return ("PRESENT", fields[19]) if len(fields) > 19 else ("UNKNOWN", None)
    except FileNotFoundError:
        return "ABSENT", None
    except (OSError, IndexError, ValueError):
        return "UNKNOWN", None


def proc_start_ticks(pid: int) -> str | None:
    status, ticks = proc_identity(pid)
    return ticks if status == "PRESENT" else None


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

    def start(self, mission_id: str, name: str, argv: list[str], cwd: str, env: dict[str, str],
              launch_head: str, sandbox_profile: str | None = None) -> str:
        if self.launcher_start_ticks is None:
            raise RuntimeError("cannot reserve a gate without launcher process identity")
        job_id = uuid.uuid4().hex
        lease = uuid.uuid4().hex
        out, err = self.log_root / f"{job_id}.out", self.log_root / f"{job_id}.err"
        child_env = {**os.environ, **env}
        bootstrap_env = None
        if sandbox_profile is not None:
            if sandbox_profile != "project-gate":
                raise ValueError(f"unsupported process sandbox profile: {sandbox_profile}")
            invocation = project_gate_invocation(argv, cwd, env, self.log_root, job_id)
            preflight_project_gate(invocation)
            argv, cwd, child_env = invocation.argv, invocation.cwd, invocation.env
            bootstrap_env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
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
                 self.launcher_pid, self.launcher_start_ticks, lease),
            )
            self.journal.db.commit()
        except Exception:
            self.journal.db.rollback()
            raise
        try:
            with out.open("wb") as stdout, err.open("wb") as stderr:
                # The bootstrap cannot run the gate until its PID has been journaled. If
                # this controller dies before publication its stdin closes and no gate runs.
                proc = subprocess.Popen([sys.executable, "-c", BOOTSTRAP], stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                        start_new_session=True, env=bootstrap_env)
        except Exception as exc:
            try:
                changed = self.journal.db.execute(
                    "UPDATE jobs SET state='FAILED_LAUNCH',ended_at=? "
                    "WHERE job_id=? AND state='STARTING' AND lease_token=? "
                    "AND launcher_pid=? AND launcher_start_ticks IS ?",
                    (now(), job_id, lease, self.launcher_pid, self.launcher_start_ticks),
                ).rowcount
                if changed:
                    self.journal.event(mission_id, "process_launch_failed", {
                        "job_id": job_id, "error": str(exc),
                    })
                self.journal.db.commit()
            except Exception:
                self.journal.db.rollback()
                raise
            raise
        # Register the handle before any durable RUNNING publication or pipe
        # release. Every later failure can then be polled/reaped deterministically.
        self._children[job_id] = proc
        try:
            pgid = os.getpgid(proc.pid)
            child_start_ticks = proc_start_ticks(proc.pid)
            if child_start_ticks is None:
                raise RuntimeError("cannot publish gate without child process identity")
            updated = self.journal.db.execute(
                "UPDATE jobs SET pid=?,pgid=?,start_ticks=?,state='RUNNING' "
                "WHERE job_id=? AND state='STARTING' AND lease_token=? "
                "AND launcher_pid=? AND launcher_start_ticks IS ?",
                (proc.pid, pgid, child_start_ticks, job_id, lease,
                 self.launcher_pid, self.launcher_start_ticks),
            ).rowcount
            if updated != 1:
                raise RuntimeError("launch lease was lost before gate release")
            self.journal.db.commit()
        except Exception as exc:
            # stdin has not received the release payload, so terminating this
            # bootstrap cannot interrupt a gate. Always retire our exact
            # reservation, even when identity lookup or RUNNING publication
            # itself raised before a normal polling path existed.
            self.journal.db.rollback()
            try:
                proc.terminate()
                proc.wait()
            except Exception:
                pass
            self._children.pop(job_id, None)
            try:
                changed = self.journal.db.execute(
                    "UPDATE jobs SET state='FAILED_LAUNCH',ended_at=? "
                    "WHERE job_id=? AND state='STARTING' AND lease_token=? "
                    "AND launcher_pid=? AND launcher_start_ticks IS ?",
                    (now(), job_id, lease, self.launcher_pid,
                     self.launcher_start_ticks),
                ).rowcount
                if changed:
                    self.journal.event(mission_id, "process_launch_failed", {
                        "job_id": job_id, "error": str(exc),
                        "phase": "publish",
                    })
                self.journal.db.commit()
            except Exception:
                self.journal.db.rollback()
                raise
            raise
        assert proc.stdin is not None
        payload = json.dumps({"argv": argv, "cwd": cwd, "env": child_env}).encode()
        try:
            written = proc.stdin.write(payload)
            if written != len(payload):
                raise BrokenPipeError("short bootstrap release write")
            proc.stdin.close()
        except (OSError, ValueError) as exc:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass
            # The release outcome is unknown: a short write cannot execute the
            # gate, while a close error may have delivered EOF and started it.
            # Stop and reap only our registered child, then retire the exact
            # RUNNING lease so neither this controller nor a restart can wait
            # forever on a bootstrap that will receive no further input.
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            except OSError:
                pass
            self._children.pop(job_id, None)
            try:
                self.journal.db.execute("BEGIN IMMEDIATE")
                changed = self.journal.db.execute(
                    "UPDATE jobs SET state='LOST',ended_at=? WHERE job_id=? "
                    "AND state='RUNNING' AND lease_token=? AND pid=? AND start_ticks=? "
                    "AND launcher_pid=? AND launcher_start_ticks IS ?",
                    (now(), job_id, lease, proc.pid, child_start_ticks,
                     self.launcher_pid, self.launcher_start_ticks),
                ).rowcount
                if changed:
                    self.journal.event(mission_id, "process_release_failed", {
                        "job_id": job_id, "name": name, "pid": proc.pid,
                        "error": str(exc), "state": "LOST",
                    })
                self.journal.db.commit()
            except Exception:
                self.journal.db.rollback()
                raise
            raise
        self.journal.event(mission_id, "process_started", {"job_id": job_id, "name": name, "pid": proc.pid, "argv": argv})
        self.journal.db.commit()
        return job_id

    def poll(self, mission_id: str) -> list[JobResult]:
        rows = self.journal.db.execute(
            "SELECT * FROM jobs WHERE mission_id=? AND "
            "(state IN ('STARTING','RUNNING') OR "
            "(state IN ('EXITED','LOST') AND name LIKE 'review:%'))",
            (mission_id,),
        ).fetchall()
        results = []
        for row in rows:
            # Terminal review jobs remain visible until the supervisor consumes
            # their receipt/result atomically.  This closes the crash window
            # between child reaping and review state publication without
            # treating an already-consumed job as active work.
            if row["state"] in {"EXITED", "LOST"}:
                results.append(JobResult(row["job_id"], row["state"], row["exit_code"], row["launch_head"]))
                continue
            if row["state"] == "STARTING":
                # Only the recorded launcher may publish a PID. A dead launcher means the
                # bootstrap was never released, so retrying is safe and deterministic.
                owner_status, observed = (proc_identity(row["launcher_pid"])
                                          if row["launcher_pid"] else ("UNKNOWN", None))
                launcher_alive = (owner_status == "PRESENT" and
                                  row["launcher_start_ticks"] is not None and
                                  observed == row["launcher_start_ticks"])
                if launcher_alive:
                    results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                    continue
                if owner_status == "UNKNOWN":
                    results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                    continue
                changed = self.journal.db.execute(
                    "UPDATE jobs SET state='LOST',ended_at=? WHERE job_id=? AND state='STARTING' "
                    "AND lease_token IS ? AND launcher_pid IS ? AND launcher_start_ticks IS ?",
                    (now(), row["job_id"], row["lease_token"], row["launcher_pid"],
                     row["launcher_start_ticks"]),
                ).rowcount
                if changed != 1:
                    continue
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
                changed = self.journal.db.execute(
                    "UPDATE jobs SET state=?,exit_code=?,ended_at=? WHERE job_id=? "
                    "AND state='RUNNING' AND lease_token IS ? AND pid IS ? "
                    "AND start_ticks IS ? AND launcher_pid IS ? "
                    "AND launcher_start_ticks IS ?",
                    (state, code, now(), row["job_id"], row["lease_token"],
                     row["pid"], row["start_ticks"], row["launcher_pid"],
                     row["launcher_start_ticks"]),
                ).rowcount
                if changed:
                    self.journal.event(mission_id, "process_exited", {
                        "job_id": row["job_id"], "exit_code": code,
                    })
                    results.append(JobResult(row["job_id"], state, code, row["launch_head"]))
                continue
            process_status, current = proc_identity(pid) if pid else ("UNKNOWN", None)
            if process_status == "UNKNOWN":
                results.append(JobResult(row["job_id"], "RUNNING", None, row["launch_head"]))
                continue
            if ticks is not None and process_status == "PRESENT" and current == ticks:
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
            changed = self.journal.db.execute(
                "UPDATE jobs SET state=?,exit_code=?,ended_at=? WHERE job_id=? "
                "AND state='RUNNING' AND lease_token IS ? AND pid IS ? "
                "AND start_ticks IS ? AND launcher_pid IS ? "
                "AND launcher_start_ticks IS ?",
                (state, code, now(), row["job_id"], row["lease_token"],
                 row["pid"], row["start_ticks"], row["launcher_pid"],
                 row["launcher_start_ticks"]),
            ).rowcount
            if changed:
                self.journal.event(mission_id, "process_" + state.lower(), {
                    "job_id": row["job_id"], "exit_code": code,
                })
                results.append(JobResult(row["job_id"], state, code, row["launch_head"]))
        self.journal.db.commit()
        return results

    def wait_for_mission(self, mission_id: str) -> bool:
        """Wait only for children registered by this controller.

        A restarted controller has no child handle and must not guess or wait
        on an unrelated PID; it returns False so the caller can reconcile the
        durable process identity instead.
        """
        rows = self.journal.db.execute(
            "SELECT job_id FROM jobs WHERE mission_id=? AND state IN ('STARTING','RUNNING')",
            (mission_id,),
        ).fetchall()
        children = [self._children[row["job_id"]] for row in rows if row["job_id"] in self._children]
        if len(children) != len(rows):
            return False
        for child in children:
            child.wait()
        return True
