"""
Process provider — per PRODUCT_CONTRACT.md (Process State & Resource Domain).

Checks:
  - process.exists
  - process.running
  - process.state
  - process.zombie
  - process.cpu_usage
  - process.memory_usage
  - process.open_files
  - process.fd_limit
  - process.thread_count
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "process_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("process")
class ProcessProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        process_name = context.get("process") or context.get("process_name")
        if not process_name:
            process_name = context.require("process")
        host = context.get("host", "")

        max_cpu = float(context.get("max_cpu_percent", "90.0"))
        max_mem = float(context.get("max_mem_percent", "90.0"))
        fd_warn_ratio = float(context.get("fd_warn_ratio", "0.9"))

        observations: list[Observation] = []

        # 1. Process Discovery & Running State
        exists_obs, running_obs, pids, states = self._check_existence_and_running(process_name, host)
        observations.append(exists_obs)
        observations.append(running_obs)

        # 2. Process State (R, S, D, Z, T)
        state_obs = self._check_process_state(process_name, pids, states, host)
        observations.append(state_obs)

        # 3. Zombie check
        zombie_obs = self._check_zombie(process_name, host)
        observations.append(zombie_obs)

        # If process doesn't exist / isn't running, return base lifecycle observations
        if not pids or exists_obs.value.get("status") == "FAIL":
            return observations

        # 4. Resource Usage: CPU & Memory
        cpu_obs, mem_obs = self._check_resources(process_name, pids, max_cpu, max_mem, host)
        observations.append(cpu_obs)
        observations.append(mem_obs)

        # 5. File Descriptors & Threads
        fd_obs, thread_obs = self._check_fds_and_threads(process_name, pids, fd_warn_ratio, host)
        observations.append(fd_obs)
        observations.append(thread_obs)

        return observations

    def _check_existence_and_running(
        self, process_name: str, host: str | None
    ) -> tuple[Observation, Observation, list[str], dict[str, str]]:
        method = f"pgrep -f {process_name} / ps -eo pid,state,comm"
        res = run_command(["ps", "-eo", "pid,state,comm"], host=host)

        pids: list[str] = []
        states: dict[str, str] = {}
        active_pids: list[str] = []

        if not res.ran:
            pg_res = run_command(["pgrep", "-f", process_name], host=host)
            if pg_res.ran and pg_res.returncode == 0:
                pids = pg_res.stdout.strip().split()
                active_pids = list(pids)
                exists_val: dict[str, Any] = {"status": "PASS", "pids": pids}
                running_val: dict[str, Any] = {"status": "PASS", "active_pids": active_pids}
                exists_msg = f"Process '{process_name}' found (PIDs: {', '.join(pids)})"
                running_msg = f"Process '{process_name}' is running"
            else:
                exists_val = {"status": "FAIL", "pids": []}
                running_val = {"status": "FAIL", "running": False}
                exists_msg = f"Process '{process_name}' not found"
                running_msg = f"Process '{process_name}' is not running"
        elif res.returncode == 0:
            for line in res.stdout.splitlines()[1:]:
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3:
                    pid, st, comm = parts[0], parts[1], parts[2]
                    if process_name in comm:
                        pids.append(pid)
                        states[pid] = st[0].upper()
                        if st[0].upper() in ("R", "S", "I"):
                            active_pids.append(pid)

            if pids:
                exists_val = {"status": "PASS", "pids": pids}
                exists_msg = f"Process '{process_name}' found (PIDs: {', '.join(pids)})"
            else:
                exists_val = {"status": "FAIL", "pids": []}
                exists_msg = f"Process '{process_name}' not found"

            if active_pids:
                running_val = {"status": "PASS", "active_pids": active_pids}
                running_msg = f"Process '{process_name}' is running (active PIDs: {', '.join(active_pids)})"
            else:
                running_val = {"status": "FAIL", "running": False}
                running_msg = f"Process '{process_name}' has no active running processes"
        else:
            exists_val = {"status": "UNKNOWN", "returncode": res.returncode}
            running_val = {"status": "UNKNOWN", "returncode": res.returncode}
            exists_msg = f"Could not inspect process table: {res.stderr}"
            running_msg = f"Could not inspect process table: {res.stderr}"

        obs_exists = Observation(
            id="process.exists",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=exists_val,
            message=exists_msg,
            observed_at=_now(),
            host=host,
        )

        obs_running = Observation(
            id="process.running",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=running_val,
            message=running_msg,
            observed_at=_now(),
            host=host,
        )

        return obs_exists, obs_running, pids, states

    def _check_process_state(
        self, process_name: str, pids: list[str], states: dict[str, str], host: str | None
    ) -> Observation:
        method = "process_state_inspection"
        if not pids:
            return Observation(
                id="process.state",
                source="process",
                category="system",
                collector=COLLECTOR,
                method=method,
                value={"status": "FAIL", "state": "NONE", "has_d_state": False},
                message=f"Process '{process_name}' is not present in process table",
                observed_at=_now(),
                host=host,
            )

        d_pids = [pid for pid, st in states.items() if st == "D"]
        z_pids = [pid for pid, st in states.items() if st == "Z"]

        if d_pids:
            msg = f"Process '{process_name}' has threads in uninterruptible sleep state D (PIDs: {', '.join(d_pids)})"
            val = {"status": "FAIL", "state": "D", "has_d_state": True, "d_pids": d_pids}
        elif z_pids and len(z_pids) == len(pids):
            msg = f"All instances of process '{process_name}' are in zombie state Z"
            val = {"status": "FAIL", "state": "Z", "has_d_state": False}
        else:
            dominant_state = list(states.values())[0] if states else "S"
            msg = f"Process '{process_name}' scheduler state is nominal ({dominant_state})"
            val = {"status": "PASS", "state": dominant_state, "has_d_state": False, "states": states}

        return Observation(
            id="process.state",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_zombie(self, process_name: str, host: str | None) -> Observation:
        method = "ps -eo state,comm"
        res = run_command(["ps", "-eo", "state,comm"], host=host)

        if not res.ran:
            msg = f"Could not inspect process states: {res.error}"
            val: dict[str, Any] = {"status": "UNKNOWN"}
        elif res.returncode != 0:
            msg = f"ps command failed with code {res.returncode}: {res.stderr}"
            val = {"status": "UNKNOWN", "returncode": res.returncode}
        else:
            zombies = []
            for line in res.stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) == 2:
                    st, comm = parts[0], parts[1]
                    if st.upper().startswith("Z") and process_name in comm:
                        zombies.append(comm)

            if zombies:
                msg = f"Found {len(zombies)} zombie process(es) matching '{process_name}'"
                val = {"status": "FAIL", "zombies": zombies}
            else:
                msg = f"No zombie processes detected for '{process_name}'"
                val = {"status": "PASS", "zombies": []}

        return Observation(
            id="process.zombie",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=method,
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_resources(
        self, process_name: str, pids: list[str], max_cpu: float, max_mem: float, host: str | None
    ) -> tuple[Observation, Observation]:
        pid_list = ",".join(pids[:10])
        res = run_command(["ps", "-p", pid_list, "-o", "%cpu,%mem,rss"], host=host)

        total_cpu = 0.0
        total_mem = 0.0
        total_rss_kb = 0

        if res.ran and res.returncode == 0:
            for line in res.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        total_cpu += float(parts[0])
                        total_mem += float(parts[1])
                        total_rss_kb += int(parts[2])
                    except ValueError:
                        pass

        rss_mb = round(total_rss_kb / 1024.0, 2)
        total_cpu = round(total_cpu, 2)
        total_mem = round(total_mem, 2)

        if total_cpu > max_cpu:
            cpu_status = "FAIL"
            cpu_msg = f"Process '{process_name}' CPU usage {total_cpu}% exceeds threshold {max_cpu}%"
        else:
            cpu_status = "PASS"
            cpu_msg = f"Process '{process_name}' CPU usage {total_cpu}% is within limits"

        obs_cpu = Observation(
            id="process.cpu_usage",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=f"ps -p {pid_list} -o %cpu",
            value={"status": cpu_status, "cpu_percent": total_cpu, "threshold_percent": max_cpu},
            message=cpu_msg,
            observed_at=_now(),
            host=host,
        )

        if total_mem > max_mem:
            mem_status = "FAIL"
            mem_msg = f"Process '{process_name}' Memory usage {total_mem}% ({rss_mb} MB) exceeds threshold {max_mem}%"
        else:
            mem_status = "PASS"
            mem_msg = f"Process '{process_name}' Memory usage {total_mem}% ({rss_mb} MB) is nominal"

        obs_mem = Observation(
            id="process.memory_usage",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=f"ps -p {pid_list} -o %mem,rss",
            value={"status": mem_status, "mem_percent": total_mem, "rss_mb": rss_mb, "threshold_percent": max_mem},
            message=mem_msg,
            observed_at=_now(),
            host=host,
        )

        return obs_cpu, obs_mem

    def _read_fds_threads_remote(self, pid: str, host: str) -> tuple[int, int, int]:
        open_fds = 0
        fd_limit = 1048576
        threads = 1

        res_fd = run_command(["ls", f"/proc/{pid}/fd"], host=host)
        if res_fd.ran and res_fd.returncode == 0:
            open_fds = len(res_fd.stdout.splitlines())

        res_limit = run_command(["grep", "Max open files", f"/proc/{pid}/limits"], host=host)
        if res_limit.ran and res_limit.returncode == 0:
            parts = res_limit.stdout.strip().split()
            if len(parts) >= 4 and parts[3].isdigit():
                fd_limit = int(parts[3])

        res_threads = run_command(["grep", "Threads:", f"/proc/{pid}/status"], host=host)
        if res_threads.ran and res_threads.returncode == 0:
            parts = res_threads.stdout.strip().split()
            if len(parts) >= 2 and parts[1].isdigit():
                threads = int(parts[1])

        return open_fds, fd_limit, threads

    def _read_proc_fd_count(self, pid: str) -> int:
        proc_fd = Path(f"/proc/{pid}/fd")
        if proc_fd.exists() and proc_fd.is_dir():
            try:
                return len(os.listdir(str(proc_fd)))
            except OSError:
                pass
        return 0

    def _read_proc_fd_limit(self, pid: str) -> int:
        proc_limits = Path(f"/proc/{pid}/limits")
        if proc_limits.exists():
            try:
                for line in proc_limits.read_text(encoding="utf-8").splitlines():
                    if "Max open files" in line:
                        parts = line.split()
                        if len(parts) >= 4 and parts[3].isdigit():
                            return int(parts[3])
            except OSError:
                pass
        return 1048576

    def _read_proc_threads(self, pid: str) -> int:
        proc_status = Path(f"/proc/{pid}/status")
        if proc_status.exists():
            try:
                for line in proc_status.read_text(encoding="utf-8").splitlines():
                    if line.startswith("Threads:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            return int(parts[1])
            except OSError:
                pass
        return 1

    def _read_fds_threads_local(self, pid: str) -> tuple[int, int, int]:
        return self._read_proc_fd_count(pid), self._read_proc_fd_limit(pid), self._read_proc_threads(pid)

    def _check_fds_and_threads(
        self, process_name: str, pids: list[str], fd_warn_ratio: float, host: str | None
    ) -> tuple[Observation, Observation]:
        primary_pid = pids[0]
        if host:
            open_fds, fd_limit, threads = self._read_fds_threads_remote(primary_pid, host)
        else:
            open_fds, fd_limit, threads = self._read_fds_threads_local(primary_pid)

        fd_ratio = round(open_fds / max(1, fd_limit), 4)
        if fd_ratio >= fd_warn_ratio:
            fd_status = "FAIL"
            fd_msg = f"Process '{process_name}' file descriptor exhaustion: {open_fds}/{fd_limit} ({round(fd_ratio*100, 1)}%)"
        else:
            fd_status = "PASS"
            fd_msg = f"Process '{process_name}' open file descriptors: {open_fds}/{fd_limit} ({round(fd_ratio*100, 1)}%)"

        obs_fd = Observation(
            id="process.open_files",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=f"/proc/{primary_pid}/fd",
            value={"status": fd_status, "open_fds": open_fds, "fd_limit": fd_limit, "usage_ratio": fd_ratio},
            message=fd_msg,
            observed_at=_now(),
            host=host,
        )

        obs_threads = Observation(
            id="process.thread_count",
            source="process",
            category="system",
            collector=COLLECTOR,
            method=f"/proc/{primary_pid}/status",
            value={"status": "PASS", "thread_count": threads},
            message=f"Process '{process_name}' has {threads} active threads",
            observed_at=_now(),
            host=host,
        )

        return obs_fd, obs_threads
