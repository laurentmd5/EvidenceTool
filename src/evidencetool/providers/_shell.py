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

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    ran: bool  # False if the command could not even be started
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None  # populated when `ran` is False


def run_command(args: list[str], timeout: float = 5.0) -> CommandResult:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
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
            error=f"command not found: {args[0]}",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            ran=False, returncode=None, stdout="", stderr="",
            error=f"command timed out after {timeout}s: {' '.join(args)}",
        )
    except OSError as exc:
        return CommandResult(
            ran=False, returncode=None, stdout="", stderr="",
            error=f"failed to run command: {exc}",
        )
