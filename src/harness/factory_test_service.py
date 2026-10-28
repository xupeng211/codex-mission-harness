"""One Controller-owned, disposable PostgreSQL for the canonical project gate.

No compose, host ports, persistent volumes, user services or agent Docker access.
"""
from __future__ import annotations

import json
import math
import os
import secrets
import subprocess
import time


class ExecutionStopped(RuntimeError):
    def __init__(self, outcome):
        super().__init__(outcome)
        self.outcome = outcome


class ProjectPostgres:
    def __init__(self, image, name, directory, target, mission, cancel, deadline, env, log):
        self.image, self.name, self.directory = image, name, directory
        self.cancel, self.deadline, self.env, self.log = cancel, deadline, env, log
        self.owner = name.removeprefix("cmh-validate-")
        self.user = "cmh_" + self.owner[:16]
        self.password = secrets.token_hex(24)
        self.secret_file = directory / "test-db-password"
        self.env_file = directory / "postgres.env"
        self.attempted = False
        self.evidence = {"image_id": image, "container_name": name, "mission_id": mission,
                         "target": target, "storage": "tmpfs_only", "host_ports": [],
                         "network": "none_shared_loopback", "ready": False,
                         "cleanup_confirmed": False, "persistent_volumes_created": []}
        self.labels = {"cmh.qa.owner": self.owner, "cmh.qa.mission": mission,
                       "cmh.qa.head": target["head"], "cmh.qa.scope": target["mission_scope_sha256"]}

    def check(self):
        if self.cancel.is_set():
            raise ExecutionStopped("CANCELLED")
        if time.monotonic() >= self.deadline:
            raise ExecutionStopped("TIMEOUT")

    def record(self, value):
        # Only this newly generated test password is handled here; no personal
        # or production credentials are read. Never emit it, even on failure.
        self.log.write((json.dumps(value, ensure_ascii=False).replace(self.password, "[TEST_PASSWORD_REDACTED]") + "\n").encode())
        self.log.flush()

    def command(self, args, *, cleanup=False, password=False):
        if not cleanup:
            self.check()
        limit = 15 if cleanup else max(0.05, min(15, self.deadline - time.monotonic()))
        env = {**self.env, **({"PGPASSWORD": self.password} if password else {})}
        try:
            result = subprocess.run(["/usr/bin/docker", *args], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit)
        except (OSError, subprocess.SubprocessError) as error:
            self.record({"service_command": args, "exit_code": None, "error_type": type(error).__name__})
            raise
        self.record({"service_command": args, "exit_code": result.returncode,
                     "stdout": result.stdout.decode(errors="replace"),
                     "stderr": result.stderr.decode(errors="replace")})
        return result

    def start(self):
        self.check()
        for path, content in ((self.secret_file, self.password), (self.env_file,
                f"POSTGRES_USER={self.user}\nPOSTGRES_DB={self.user}\nPOSTGRES_PASSWORD={self.password}\n"
                "PGDATA=/var/lib/postgresql/data/pgdata\n"
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n")):
            with path.open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
        lifetime = max(1, math.ceil(self.deadline - time.monotonic()))
        self.evidence["lifetime_limit_seconds"] = lifetime
        args = ["run", "--detach", "--rm", "--pull=never", "--name", self.name, "--network=none",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--user=postgres", "--pids-limit=128", "--memory=1g", "--cpus=1",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777",
                "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,size=512m,mode=1777",
                "--env-file", str(self.env_file)]
        for key, value in self.labels.items():
            args.extend(["--label", key + "=" + value])
        args.extend(["--entrypoint=/usr/bin/timeout", self.image, "-s", "TERM", "-k", "5", str(lifetime),
                     "/usr/local/bin/docker-entrypoint.sh", "postgres", "-c", "listen_addresses=127.0.0.1",
                     "-c", "max_connections=50", "-c", "sc002.init_sql_context=development"])
        # Mark before dispatch, so a lost Docker response still gets an
        # ownership-checked cleanup attempt, never an unbounded retry.
        self.attempted = True
        if self.command(args).returncode:
            raise RuntimeError("isolated PostgreSQL could not start; see service log")
        metadata = self.command(["inspect", "--format",
                '{"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
                '"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}', self.name])
        if metadata.returncode:
            raise RuntimeError("test service isolation could not be inspected")
        isolation = json.loads(metadata.stdout)
        self.evidence["docker_isolation"] = isolation
        if (not isinstance(isolation, dict) or isolation.get("network") != "none" or isolation.get("ports")
                or any(m.get("Type") in {"bind", "volume"} for m in isolation.get("mounts", []))):
            raise RuntimeError("test service has unexpected network, host ports or persistent mounts")
        ready_deadline = min(self.deadline, time.monotonic() + 60)
        while time.monotonic() < ready_deadline:
            self.check()
            result = self.command(["exec", "--user=postgres", "--env", "PGPASSWORD", self.name,
                                   "psql", "-w", "-h", "127.0.0.1", "-U", self.user, "-d", self.user,
                                   "--set=ON_ERROR_STOP=1", "-Atc", "SELECT 1"], password=True)
            if result.returncode == 0 and result.stdout.strip() == b"1":
                self.evidence["ready"] = True
                self.evidence["connection"] = {"host": "127.0.0.1", "port": 5432,
                                               "user": self.user, "database": self.user,
                                               "password": "EPHEMERAL_NOT_RECORDED"}
                return
            # Bounded polling; cancellation interrupts this wait immediately.
            self.cancel.wait(0.2)
        self.check()
        raise RuntimeError("isolated PostgreSQL did not become ready within 60 seconds")

    def validation_argv(self, argv):
        if not self.evidence["ready"]:
            raise RuntimeError("validation cannot run before PostgreSQL readiness")
        argv = list(argv)
        argv[argv.index("--network=none")] = "--network=container:" + self.name
        index = argv.index("--workdir=/app")
        argv[index:index] = ["--mount", f"type=bind,src={self.secret_file},dst=/run/cmh-test-db-password,readonly"]
        # The fixed shell reads only the task's single synthetic password file,
        # then replaces itself with env -i. No image/host environment survives.
        index = argv.index("--entrypoint=/usr/bin/env")
        argv[index] = "--entrypoint=/bin/sh"
        index = argv.index("-i", index)
        argv[index:index] = ["-c", 'password="$(cat /run/cmh-test-db-password)" || exit 125; '
                            'exec /usr/bin/env -i DB_PASSWORD="$password" "$@"', "cmh-qa"]
        argv.pop(index + 3)  # env -i is already in the fixed wrapper, not in its arguments.
        # Insert before the Python program, never after its argv.
        index = argv.index("python3")
        argv[index:index] = ["DB_HOST=127.0.0.1", "DB_PORT=5432", "DB_USER=" + self.user,
                             "DB_NAME=" + self.user, "DB_ADMIN_NAME=postgres", "DB_BLUEPRINT_DEBUG=1"]
        return argv

    def close(self):
        if not self.attempted:
            self.evidence["cleanup_confirmed"] = True
            return
        try:
            labels = self.command(["inspect", "--format", "{{json .Config.Labels}}", self.name], cleanup=True)
            if labels.returncode == 0:
                actual = json.loads(labels.stdout)
                if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in self.labels.items()):
                    raise RuntimeError("refusing to delete a container without this task's ownership labels")
                try:
                    self.command(["logs", "--tail", "200", self.name], cleanup=True)
                except (OSError, subprocess.SubprocessError) as error:
                    self.evidence["logs_error_type"] = type(error).__name__
                self.command(["rm", "--force", "--volumes", self.name], cleanup=True)
            absence = self.command(["ps", "-a", "--filter", "name=^/" + self.name + "$",
                                    "--format", "{{.Names}}"], cleanup=True)
            self.evidence["cleanup_confirmed"] = absence.returncode == 0 and not absence.stdout.strip()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.evidence["cleanup_error_type"] = type(error).__name__
        finally:
            for path in (self.env_file, self.secret_file):
                path.unlink(missing_ok=True)

