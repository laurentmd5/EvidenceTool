"""
Docker container provider — per PRODUCT_CONTRACT.md Section 15 (V0.4 Contract).

Checks:
  - container.exists / docker.container_exists
  - container.running / docker.container_running
  - container.restarting / docker.container_restarting
  - container.health / docker.container_health
  - container.exit_code / docker.container_exit_code
  - container.logs / docker.container_logs

Strict Read-Only Invariant:
  This provider only executes non-mutating inspection commands (`docker inspect`, `docker logs`).
  It never executes mutating actions (`docker run`, `docker stop`, `docker restart`, `docker exec`, etc.).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "docker_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("docker")
@provider("container")
class DockerProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        container = context.get("container") or context.get("container_name")
        if not container:
            container = context.require("container")
        host = context.get("host", "")

        inspect_data, daemon_error, not_found, error_msg = self._inspect(container, host)

        obs_list = [
            self._check_exists(container, host, inspect_data, daemon_error, not_found, error_msg),
            self._check_running(container, host, inspect_data, daemon_error, not_found, error_msg),
            self._check_restarting(container, host, inspect_data, daemon_error, not_found, error_msg),
            self._check_health(container, host, inspect_data, daemon_error, not_found, error_msg),
            self._check_exit_code(container, host, inspect_data, daemon_error, not_found, error_msg),
            self._check_logs(container, host, inspect_data, daemon_error, not_found, error_msg),
        ]

        aliased_obs = []
        for obs in obs_list:
            alias_id = f"docker.{obs.id.replace('container.', 'container_')}"
            aliased_obs.append(
                Observation(
                    id=alias_id,
                    source="docker",
                    category="container",
                    collector=COLLECTOR,
                    method=obs.method,
                    value=obs.value,
                    message=obs.message,
                    observed_at=obs.observed_at,
                    host=obs.host,
                )
            )

        return obs_list + aliased_obs

    def _inspect(self, container: str, host: str | None) -> tuple[dict[str, Any] | None, bool, bool, str]:
        inspect_res = run_command(["docker", "inspect", container], host=host)
        if not inspect_res.ran:
            return None, True, False, inspect_res.error or "Command could not be executed"
        if inspect_res.returncode != 0:
            stderr = inspect_res.stderr.lower()
            if "no such container" in stderr or "no such object" in stderr or "error: no such" in stderr:
                return None, False, True, f"Container '{container}' does not exist"
            return None, True, False, f"Docker inspect failed: {inspect_res.stderr}"

        try:
            parsed = json.loads(inspect_res.stdout)
            if isinstance(parsed, list) and len(parsed) > 0:
                return parsed[0], False, False, ""
            return None, True, False, "Docker inspect returned unexpected empty structure"
        except Exception as e:
            return None, True, False, f"Failed to parse docker inspect JSON: {e}"

    def _check_exists(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker inspect {container}"
        if daemon_error:
            val: dict[str, Any] = {"status": "UNKNOWN", "error": error_msg}
            msg = error_msg
        elif not_found:
            val = {"status": "FAIL", "exists": False}
            msg = f"Container '{container}' does not exist"
        else:
            container_id = inspect_data.get("Id", "")[:12] if inspect_data else ""
            name = inspect_data.get("Name", "") if inspect_data else ""
            val = {"status": "PASS", "exists": True, "id": container_id, "name": name}
            msg = f"Container '{container}' exists (ID: {container_id})"

        return Observation(
            id="container.exists",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_running(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker inspect {container}"
        if daemon_error or not_found or not inspect_data:
            val: dict[str, Any] = {"status": "UNKNOWN"}
            msg = f"Cannot check running state: {error_msg}"
        else:
            state = inspect_data.get("State", {})
            is_running = state.get("Running", False)
            status_str = state.get("Status", "unknown")
            if is_running:
                val = {"status": "PASS", "running": True, "state": status_str}
                msg = f"Container '{container}' is running"
            else:
                exit_code = state.get("ExitCode", 0)
                val = {"status": "FAIL", "running": False, "state": status_str, "exit_code": exit_code}
                msg = f"Container '{container}' is not running (state: {status_str}, exit code: {exit_code})"

        return Observation(
            id="container.running",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_restarting(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker inspect {container}"
        if daemon_error or not_found or not inspect_data:
            val: dict[str, Any] = {"status": "UNKNOWN"}
            msg = f"Cannot check restarting state: {error_msg}"
        else:
            state = inspect_data.get("State", {})
            is_restarting = state.get("Restarting", False)
            restart_count = inspect_data.get("RestartCount", 0)
            if is_restarting or (state.get("Status") == "restarting"):
                val = {"status": "FAIL", "restarting": True, "restart_count": restart_count}
                msg = f"Container '{container}' is in a crash-restart loop (restarting: true, count: {restart_count})"
            else:
                val = {"status": "PASS", "restarting": False, "restart_count": restart_count}
                msg = f"Container '{container}' is not in a restart loop"

        return Observation(
            id="container.restarting",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_health(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker inspect {container}"
        if daemon_error or not_found or not inspect_data:
            val: dict[str, Any] = {"status": "UNKNOWN"}
            msg = f"Cannot check health: {error_msg}"
        else:
            state = inspect_data.get("State", {})
            health = state.get("Health")
            if not health:
                val = {"status": "PASS", "healthcheck": False, "health_status": "none"}
                msg = f"Container '{container}' has no healthcheck configured (treated as healthy)"
            else:
                h_status = health.get("Status", "").lower()
                failing_streak = health.get("FailingStreak", 0)
                if h_status == "healthy":
                    val = {"status": "PASS", "healthcheck": True, "health_status": "healthy"}
                    msg = f"Container '{container}' health status is healthy"
                elif h_status == "unhealthy":
                    val = {"status": "FAIL", "healthcheck": True, "health_status": "unhealthy", "failing_streak": failing_streak}
                    msg = f"Container '{container}' is unhealthy (failing streak: {failing_streak})"
                elif h_status == "starting":
                    val = {"status": "UNKNOWN", "healthcheck": True, "health_status": "starting"}
                    msg = f"Container '{container}' health status is still starting"
                else:
                    val = {"status": "UNKNOWN", "healthcheck": True, "health_status": h_status}
                    msg = f"Container '{container}' health status: {h_status}"

        return Observation(
            id="container.health",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_exit_code(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker inspect {container}"
        if daemon_error or not_found or not inspect_data:
            val: dict[str, Any] = {"status": "UNKNOWN"}
            msg = f"Cannot check exit code: {error_msg}"
        else:
            state = inspect_data.get("State", {})
            exit_code = state.get("ExitCode", 0)
            is_running = state.get("Running", False)
            oom_killed = state.get("OOMKilled", False)
            if is_running:
                val = {"status": "PASS", "running": True, "exit_code": exit_code}
                msg = f"Container '{container}' is currently running"
            elif exit_code == 0:
                val = {"status": "PASS", "running": False, "exit_code": 0}
                msg = f"Container '{container}' exited normally with code 0"
            else:
                extra = " (OOMKilled)" if oom_killed else ""
                val = {"status": "FAIL", "running": False, "exit_code": exit_code, "oom_killed": oom_killed}
                msg = f"Container '{container}' exited with error code {exit_code}{extra}"

        return Observation(
            id="container.exit_code",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_logs(
        self,
        container: str,
        host: str | None,
        inspect_data: dict[str, Any] | None,
        daemon_error: bool,
        not_found: bool,
        error_msg: str,
    ) -> Observation:
        method = f"docker logs --tail 50 {container}"
        if daemon_error or not_found or not inspect_data:
            val: dict[str, Any] = {"status": "UNKNOWN"}
            msg = f"Cannot collect logs: {error_msg}"
        else:
            logs_res = run_command(["docker", "logs", "--tail", "50", container], host=host)
            if not logs_res.ran:
                val = {"status": "UNKNOWN", "error": logs_res.error}
                msg = f"Could not execute docker logs: {logs_res.error}"
            elif logs_res.returncode != 0:
                val = {"status": "UNKNOWN", "returncode": logs_res.returncode, "stderr": logs_res.stderr}
                msg = f"docker logs exited {logs_res.returncode}: {logs_res.stderr}"
            else:
                tail = (logs_res.stdout + "\n" + logs_res.stderr).strip()
                state = inspect_data.get("State", {})
                oom_killed = state.get("OOMKilled", False)
                if oom_killed:
                    val = {"status": "FAIL", "oom_killed": True, "tail": tail}
                    msg = f"Container '{container}' was killed by OOM (Out of Memory)"
                else:
                    lines_count = len(tail.splitlines()) if tail else 0
                    val = {"status": "PASS", "lines_count": lines_count, "tail": tail}
                    msg = f"Container '{container}' logs collected ({lines_count} lines)"

        return Observation(
            id="container.logs",
            source="docker",
            category="container",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )
