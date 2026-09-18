"""
Unit tests for Process State, Resources, and Situation Correlation.
"""

from __future__ import annotations

from unittest.mock import Mock

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.policy.loader import load_policy
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.process import ProcessProvider


def test_process_d_state_io_wait(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "ps" in args and "pid,state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="PID STATE COMM\n4567 D db_worker", stderr="")
        if "ps" in args and "%cpu" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="%CPU %MEM RSS\n 0.1  1.0 20000", stderr="")
        if "ps" in args and "state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="D db_worker", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "db_worker"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.exists"].value["status"] == "PASS"
    assert obs_map["process.state"].value["status"] == "FAIL"
    assert obs_map["process.state"].value["has_d_state"] is True
    assert "uninterruptible sleep" in obs_map["process.state"].message


def test_process_cpu_saturation(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "ps" in args and "pid,state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="PID STATE COMM\n1001 R compute_task", stderr="")
        if "ps" in args and "%cpu" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="%CPU %MEM RSS\n 98.5  2.0 40000", stderr="")
        if "ps" in args and "state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="R compute_task", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "compute_task", "max_cpu_percent": "90.0"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.cpu_usage"].value["status"] == "FAIL"
    assert obs_map["process.cpu_usage"].value["cpu_percent"] == 98.5


def test_process_memory_pressure(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "ps" in args and "pid,state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="PID STATE COMM\n2002 S mem_heavy_service", stderr="")
        if "ps" in args and "%cpu" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="%CPU %MEM RSS\n 5.0  94.2 8000000", stderr="")
        if "ps" in args and "state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="S mem_heavy_service", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "mem_heavy_service", "max_mem_percent": "85.0"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.memory_usage"].value["status"] == "FAIL"
    assert obs_map["process.memory_usage"].value["mem_percent"] == 94.2


def test_process_fd_exhaustion(monkeypatch):
    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "ps" in args and "pid,state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="PID STATE COMM\n3003 S file_server", stderr="")
        if "ps" in args and "%cpu" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="%CPU %MEM RSS\n 1.0  2.0 10000", stderr="")
        if "ps" in args and "state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="S file_server", stderr="")
        if "ls" in args and "/proc/3003/fd" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="\n".join(str(i) for i in range(950)), stderr="")
        if "grep" in args and "limits" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="Max open files  1000  1000  files", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "file_server", "host": "srv1", "fd_warn_ratio": "0.9"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["process.open_files"].value["status"] == "FAIL"
    assert obs_map["process.open_files"].value["open_fds"] == 950
    assert obs_map["process.open_files"].value["fd_limit"] == 1000


def test_process_situation_io_wait_correlation(monkeypatch):
    catalog = load_catalog("catalogs/process.yaml")
    policy = load_policy("policies/process.yaml")

    p = ProcessProvider()

    def mock_run_command(args, **kwargs):
        if "ps" in args and "pid,state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="PID STATE COMM\n4567 D db_worker", stderr="")
        if "ps" in args and "%cpu" in "".join(args):
            return Mock(ran=True, returncode=0, stdout="%CPU %MEM RSS\n 0.1  1.0 20000", stderr="")
        if "ps" in args and "state,comm" in args:
            return Mock(ran=True, returncode=0, stdout="D db_worker", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.process.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"process": "db_worker"}))
    evidence = [evaluate_observation(o) for o in obs]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "ALLOW"
    assert "PROCESS_IO_WAIT" in decision.reason
