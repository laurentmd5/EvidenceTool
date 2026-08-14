"""
Shared helper for providers that need to run a shell command.

Per NFR-005 (security) in the product discussion: commands are run with a
timeout, never through a shell string (no shell=True), and any failure to
even execute the command (binary missing, permission denied, timeout)
degrades gracefully to an UNKNOWN evidence rather than raising -- a
provider must never crash EvidenceTool just because a tool isn't
installed on the host it's inspecting.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    ran: bool  # False if the command could not even be started or if SSH transport failed
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None  # populated when `ran` is False


def run_command(args: list[str], timeout: float = 5.0, host: str | None = None) -> CommandResult:
    # If host is provided, wrap in ssh
    actual_args = args
    if host:
        control_path = "/tmp/evidencetool_ssh_%h_%p_%r"
        actual_args = [
            "ssh",
            "--",
            "-o", "BatchMode=yes",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={control_path}",
            "-o", "ControlPersist=60s",
            "-o", "StrictHostKeyChecking=yes",
            host,
            "--"
        ] + args

    try:
        proc = subprocess.run( # nosec B603
            actual_args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        # Distinguish SSH transport errors (255) from business logic failures
        if host and proc.returncode == 255:
            return CommandResult(
                ran=False,
                returncode=proc.returncode,
                stdout=proc.stdout.strip(),
                stderr=proc.stderr.strip(),
                error=f"SSH Transport Error: {proc.stderr.strip()}",
            )

        return CommandResult(
            ran=True,
            returncode=proc.returncode,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
        )
    except FileNotFoundError:
        return CommandResult(
            ran=False, returncode=None, stdout="", stderr="",
            error=f"command not found: {actual_args[0]}",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            ran=False, returncode=None, stdout="", stderr="",
            error=f"command timed out after {timeout}s: {' '.join(actual_args)}",
        )
    except OSError as exc:
        return CommandResult(
            ran=False, returncode=None, stdout="", stderr="",
            error=f"failed to run command: {exc}",
        )




def file_exists(path: str, host: str | None = None, timeout: float = 5.0) -> bool:
    """Check if a file exists, either locally or remotely."""
    if not host:
        return os.path.exists(path)
    res = run_command(["test", "-e", path], timeout=timeout, host=host)
    return res.ran and res.returncode == 0


def get_free_disk_space(path: str, host: str | None = None, timeout: float = 5.0) -> int | None:
    """Get free disk space in bytes for a given path."""
    if not host:
        try:
            return shutil.disk_usage(path).free
        except OSError:
            return None

    res = run_command(["df", "-B1", "--output=avail", path], timeout=timeout, host=host)
    if not res.ran or res.returncode != 0:
        return None

    lines = res.stdout.strip().split("\n")
    if len(lines) >= 2:
        try:
            return int(lines[1].strip())
        except ValueError:
            return None
    return None
