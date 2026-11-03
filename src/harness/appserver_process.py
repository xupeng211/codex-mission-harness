"""Linux, per-AppServer child-tree ownership. No process-name or PGID killing.

The dedicated subreaper stays alive until its children (including reparented,
setsid/double-fork descendants) have been reaped. Only an authenticated ECHILD
acknowledgement permits its owner to reap it and clean task resources. This is
not a boundary against privileged processes or peers attacking the controller.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


LIMIT = 65536
STOP_SECONDS = 5.0
TERM_SECONDS = 0.25


def process_identity(pid):
    path = Path(f"/proc/{pid}")
    fields = (path / "stat").read_text().rsplit(") ", 1)[1].split()
    return {"pid": pid, "starttime": fields[19], "ppid": int(fields[1]),
            "pgid": int(fields[2]), "sid": int(fields[3]), "uid": path.stat().st_uid,
            "state": fields[0]}


def _send(channel, value):
    data = json.dumps(value, sort_keys=True).encode()
    if len(data) > LIMIT:
        raise RuntimeError("AppServer ownership message exceeds limit")
    channel.sendall(data)


def _receive(channel):
    data = channel.recv(LIMIT + 1)
    if not data or len(data) > LIMIT:
        raise RuntimeError("AppServer ownership channel missing or oversized")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise RuntimeError("invalid AppServer ownership message")
    return value


class AppServerProcess:
    """Controller handle; unknown shutdown is sticky and never retries dispatch."""

    def __init__(self, binding, record=None):
        self.binding = {"execution_id": uuid.uuid4().hex, **json.loads(json.dumps(binding))}
        self.record = record
        self.proc = self.identity = self.channel = self.pidfd = None
        self.stopped = self.failure = None
        self._lock = threading.RLock()
        self._record_identity = None

    def _event(self, event, **data):
        row = {"event": event, "at": time.time(), "binding": self.binding, "supervisor": self.identity, **data}
        if self.record is not None:
            flags = os.O_WRONLY | os.O_NOFOLLOW
            flags |= os.O_CREAT | os.O_EXCL if self._record_identity is None else os.O_APPEND
            fd = os.open(self.record, flags, 0o600)
            try:
                info = os.fstat(fd)
                identity = (info.st_dev, info.st_ino)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                        or self._record_identity not in (None, identity)):
                    raise RuntimeError("AppServer ownership evidence identity changed")
                self._record_identity = identity
                data = (json.dumps(row, sort_keys=True) + "\n").encode()
                if os.write(fd, data) != len(data):
                    raise OSError("short AppServer ownership evidence write")
                os.fsync(fd)
            finally:
                os.close(fd)
        return row

    def _anchor(self):
        # Like owned-client: WNOWAIT, never poll before the stop proof. The
        # private socket and pidfd further bind replies to this allocation.
        if self.proc is None or self.proc.returncode is not None or self.identity is None:
            raise RuntimeError("AppServer supervisor ownership is unavailable or reaped")
        os.waitid(os.P_PID, self.proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        actual = process_identity(self.proc.pid)
        if (any(actual[k] != self.identity[k] for k in self.identity if k != "state")
                or actual["ppid"] != os.getpid() or actual["uid"] != os.geteuid()
                or actual["pgid"] != self.proc.pid or actual["sid"] != self.proc.pid):
            raise RuntimeError("AppServer supervisor startup identity changed")

    def start(self, argv, **kwargs):
        if (sys.platform != "linux" or not hasattr(os, "pidfd_open")
                or not hasattr(signal, "pidfd_send_signal") or not hasattr(os, "WNOWAIT")):
            raise RuntimeError("AppServer requires Linux subreaper, pidfd and WNOWAIT support")
        if self.proc is not None:
            raise RuntimeError("AppServer execution cannot be restarted")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.channel = parent
        parent.settimeout(STOP_SECONDS + 2)
        helper = Path(__file__).resolve()
        if helper.is_relative_to(Path(kwargs["cwd"]).resolve()):
            parent.close(); child.close()
            raise RuntimeError("AppServer supervisor cannot reside inside the delegated worktree")
        command = [sys.executable, "-I", "-B", str(helper), str(child.fileno()),
                   json.dumps(self.binding, sort_keys=True), "--", *map(str, argv)]
        try:
            self.proc = subprocess.Popen(command, **{**kwargs, "start_new_session": True,
                                                     "pass_fds": (child.fileno(),)})
            self.pidfd = os.pidfd_open(self.proc.pid)
            self.identity = process_identity(self.proc.pid)
            self._anchor()
            hello = _receive(parent)
            if hello != {"event": "ready", "binding": self.binding, "supervisor": self.identity,
                         "mechanism": "linux-subreaper-pidfd-v1"}:
                # State can change between snapshots; a running supervisor
                # must otherwise have exactly the original startup identity.
                expected = {**self.identity, "state": hello.get("supervisor", {}).get("state")}
                if hello != {"event": "ready", "binding": self.binding, "supervisor": expected,
                             "mechanism": "linux-subreaper-pidfd-v1"}:
                    raise RuntimeError("AppServer supervisor handshake differs")
            self._event("allocated", argv_sha256=hashlib.sha256(json.dumps(list(map(str, argv))).encode()).hexdigest(),
                        helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest())
            _send(parent, {"command": "start", "binding": self.binding})
            response = _receive(parent)
            if response.get("binding") != self.binding or response.get("event") != "started":
                raise RuntimeError("AppServer payload startup unconfirmed")
            self.payload = response["payload"]
            self._event("started", payload=response["payload"])
            return self.proc
        finally:
            child.close()

    def stop(self):
        with self._lock:
            if self.failure is not None:
                raise RuntimeError(self.failure)
            if self.stopped is not None:
                return self.stopped
            try:
                if self.proc is None:
                    if self.channel is not None:
                        self.channel.close()
                    self.stopped = {"confirmed": True, "binding": self.binding, "proof": "not_started"}
                    return self.stopped
                self._anchor()
                _send(self.channel, {"command": "stop", "binding": self.binding})
                result = _receive(self.channel)
                self.last_stop_attempt = result
                self._anchor()
                if (result.get("event") != "stopped" or result.get("binding") != self.binding
                        or result.get("supervisor") != {k:v for k,v in self.identity.items() if k != "state"}
                        or result.get("confirmed") is not True or result.get("proof") != "ECHILD"):
                    raise RuntimeError("AppServer descendant stop proof is unconfirmed")
                self._event("stopped", result=result)
                _send(self.channel, {"command": "release", "binding": self.binding})
                if self.proc.wait(timeout=2) != 0:
                    raise RuntimeError("AppServer supervisor release failed")
                self.channel.close()
                os.close(self.pidfd)
                self.pidfd = None
                self.stopped = result
                return result
            except Exception as error:
                self.failure = f"AppServer stop UNKNOWN: {type(error).__name__}: {error}"
                try:
                    self._event("unknown", confirmed=False, error=self.failure,
                                stop_attempt=getattr(self, "last_stop_attempt", None))
                except Exception:
                    pass  # The failure remains sticky even if evidence cannot be appended.
                raise RuntimeError(self.failure) from error


def validate_supervised_stop(reference, expected, *, outcome="complete"):
    """Recheck the task Controller's durable ECHILD/event/command binding.

    This is local integrity evidence, not hostile-same-uid attestation. Old
    operations without these original records cannot acquire a stop proof.
    """
    def read(path, limit=1024 * 1024):
        path = Path(path)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise RuntimeError("supervised evidence path changed")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > limit):
                raise RuntimeError("supervised evidence is not private/bounded")
            return stream.read(limit + 1)
    raw = read(reference["path"])
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise RuntimeError("supervised stop evidence changed")
    doc = json.loads(raw)
    stop_path = Path(reference["path"])
    if doc["journal"] != str(stop_path.with_name(stop_path.name.removesuffix(".stop.json") + ".process.jsonl")):
        raise RuntimeError("supervised journal belongs to another operation")
    journal = read(doc["journal"])
    if hashlib.sha256(journal).hexdigest() != doc["journal_sha256"]:
        raise RuntimeError("supervised process journal changed")
    rows = [json.loads(line) for line in journal.splitlines()]
    binding = doc["binding"]
    if (set(binding) != set(expected) | {"execution_id"}
            or {k: v for k, v in binding.items() if k != "execution_id"} != expected
            or not isinstance(binding["execution_id"], str) or re.fullmatch(r"[0-9a-f]{32}", binding["execution_id"]) is None
            or [v.get("event") for v in rows] != ["allocated", "started", "stopped"]
            or any(v.get("binding") != binding for v in rows)):
        raise RuntimeError("supervised operation/target binding mismatch")
    supervisor, payload, stop = doc["supervisor"], doc["payload"], doc["stop"]
    if (doc["supervisor_exit"] != 0 or stop.get("event") != "stopped"
            or stop.get("binding") != binding or stop.get("confirmed") is not True
            or stop.get("proof") != "ECHILD" or doc["outcome"] != outcome
            or stop.get("supervisor") != {k: v for k, v in supervisor.items() if k != "state"}
            or any(v.get("supervisor") != supervisor for v in rows)
            or rows[1].get("payload") != payload or rows[2].get("result") != stop
            or rows[0].get("helper_sha256") != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or rows[0].get("argv_sha256") != hashlib.sha256(json.dumps(expected["argv"]).encode()).hexdigest()):
        raise RuntimeError("supervised ECHILD/identity/command proof is unconfirmed")
    matches = [v for v in stop["reaped"] if v["pid"] == payload["pid"]]
    if len(matches) != 1 or doc["exit_code"] != os.waitstatus_to_exitcode(matches[0]["status"]):
        raise RuntimeError("supervised payload exit is unconfirmed")
    return doc["exit_code"]


def _stop_children():
    """Single-threaded subreaper: signal unreaped direct children via pidfds.

    Killing an intermediate parent adopts its surviving descendants, regardless
    of their session/group. ECHILD, not an empty PGID scan, is the completion
    proof. No parent can fork after the final child has been reaped.
    """
    deadline = time.monotonic() + STOP_SECONDS
    escalation = time.monotonic() + TERM_SECONDS
    signals, reaped, sent = [], [], set()
    while True:
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return {"confirmed": True, "proof": "ECHILD", "signals": signals, "reaped": reaped}
            if pid == 0:
                break
            reaped.append({"pid": pid, "status": status})
        if len(signals) + len(reaped) > 128:
            raise RuntimeError("AppServer descendant evidence capacity exceeded")
        children = Path(f"/proc/self/task/{os.getpid()}/children").read_text().split()
        for raw in children:
            pid = int(raw)
            # This single-threaded parent never reaps between the snapshot,
            # pidfd_open and signal. A zombie child's PID cannot be recycled.
            identity = process_identity(pid)
            if identity["ppid"] != os.getpid() or identity["uid"] != os.geteuid():
                raise RuntimeError("AppServer adopted child ownership is unconfirmed")
            sig = signal.SIGTERM if time.monotonic() < escalation else signal.SIGKILL
            key = (pid, identity["starttime"], int(sig))
            if key not in sent and identity["state"] not in ("Z", "X"):
                fd = os.pidfd_open(pid)
                try:
                    signal.pidfd_send_signal(fd, sig)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(fd)
                signals.append({"identity": identity, "signal": int(sig)})
                sent.add(key)
        if time.monotonic() >= deadline:
            raise TimeoutError("AppServer descendant shutdown deadline exceeded")
        time.sleep(.01)


def _supervise(fd, binding, argv):
    channel = socket.socket(fileno=fd)
    channel.set_inheritable(False)  # Never delegate this capability to a tool.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "AppServer subreaper unavailable")
    enabled = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(enabled), 0, 0, 0) != 0 or enabled.value != 1:
        raise RuntimeError("AppServer subreaper activation unconfirmed")
    # Verify capabilities before starting any payload.
    probe = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(probe, 0)  # Capability check, no signal delivered.
    finally:
        os.close(probe)
    identity = process_identity(os.getpid())
    _send(channel, {"event": "ready", "binding": binding, "supervisor": identity,
                    "mechanism": "linux-subreaper-pidfd-v1"})
    command = _receive(channel)
    if command == {"command": "start", "binding": binding}:
        try:
            proc = subprocess.Popen(argv, close_fds=True, start_new_session=True)
            payload = process_identity(proc.pid)
            response = {"event": "started", "binding": binding, "payload": payload}
        except Exception as error:
            response = {"event": "start_error", "binding": binding, "error": type(error).__name__}
        # Only the payload owns JSON-RPC stdio. Its exit must remain observable
        # as EOF even while the independent subreaper retains the ownership.
        for stream in (0, 1, 2):
            os.close(stream)
        try:
            _send(channel, response)
            command = _receive(channel)
        except (OSError, RuntimeError):
            command = {"command": "stop", "binding": binding}
    if command != {"command": "stop", "binding": binding}:
        raise RuntimeError("invalid AppServer supervisor command")
    try:
        result = _stop_children()
    except Exception as error:
        result = {"confirmed": False, "proof": "UNKNOWN", "error": f"{type(error).__name__}: {error}"}
    try:
        _send(channel, {"event": "stopped", "binding": binding,
                        "supervisor": {k:v for k,v in identity.items() if k != "state"}, **result})
        # Retain the anchor until its controller has accepted the proof. An
        # unknown result is never released automatically to a replacement task.
        command = _receive(channel)
        if result["confirmed"] and command == {"command": "release", "binding": binding}:
            return
    except (OSError, RuntimeError):
        if result["confirmed"]:
            return
    # Keep adoptive ownership on UNKNOWN; no speculative group kill or restart.
    while True:
        time.sleep(60)


if __name__ == "__main__":
    try:
        _supervise(int(sys.argv[1]), json.loads(sys.argv[2]), sys.argv[4:])
    except BaseException:
        os._exit(1)
    os._exit(0)
