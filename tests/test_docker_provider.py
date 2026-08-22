"""
Unit tests for Docker provider and Docker situational correlation.
"""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from evidencetool.diagnose import diagnose
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.evidence import EvidenceStatus
from evidencetool.policy.loader import load_policy
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.docker import DockerProvider
from evidencetool.providers.registry import get_provider


def _make_inspect(
    running: bool = True,
    status: str = "running",
    restarting: bool = False,
    exit_code: int = 0,
    health_status: str | None = "healthy",
    oom_killed: bool = False,
    restart_count: int = 0,
) -> str:
    state: dict = {
        "Running": running,
        "Status": status,
        "Restarting": restarting,
        "ExitCode": exit_code,
        "OOMKilled": oom_killed,
    }
    if health_status:
        state["Health"] = {"Status": health_status, "FailingStreak": 3 if health_status == "unhealthy" else 0}

    return json.dumps([
        {
            "Id": "abc123def45678901234567890",
            "Name": "/test_app",
            "State": state,
            "RestartCount": restart_count,
        }
    ])


def test_docker_provider_registration():
    docker_p = get_provider("docker")
    container_p = get_provider("container")
    assert isinstance(docker_p, DockerProvider)
    assert isinstance(container_p, DockerProvider)


def test_docker_healthy_container(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True, health_status="healthy"), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="App started successfully\nListening on port 8080", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="Unknown command")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "PASS"
    assert obs_map["container.running"].value["status"] == "PASS"
    assert obs_map["container.restarting"].value["status"] == "PASS"
    assert obs_map["container.health"].value["status"] == "PASS"
    assert obs_map["container.exit_code"].value["status"] == "PASS"
    assert obs_map["container.logs"].value["status"] == "PASS"


def test_docker_container_not_found(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=1, stdout="", stderr="Error: No such container: missing_app")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "missing_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "FAIL"
    assert obs_map["container.running"].value["status"] == "UNKNOWN"
    assert obs_map["container.health"].value["status"] == "UNKNOWN"


def test_docker_container_stopped(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=False, status="exited", exit_code=0), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Clean shutdown", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "PASS"
    assert obs_map["container.running"].value["status"] == "FAIL"
    assert obs_map["container.exit_code"].value["status"] == "PASS"


def test_docker_container_crash_loop(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(
                ran=True,
                returncode=0,
                stdout=_make_inspect(running=False, status="restarting", restarting=True, exit_code=1, restart_count=12),
                stderr="",
            )
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Fatal error: database connection refused", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "PASS"
    assert obs_map["container.restarting"].value["status"] == "FAIL"
    assert obs_map["container.exit_code"].value["status"] == "FAIL"


def test_docker_container_unhealthy(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True, status="running", health_status="unhealthy"), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Healthcheck timed out", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "PASS"
    assert obs_map["container.running"].value["status"] == "PASS"
    assert obs_map["container.health"].value["status"] == "FAIL"


def test_docker_daemon_error(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=1, stdout="", stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "UNKNOWN"
    assert "Cannot connect to the Docker daemon" in obs_map["container.exists"].message


def test_docker_full_diagnosis_flow(tmp_path, monkeypatch):
    from pathlib import Path

    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "docker.yaml"
    policy_path = Path(__file__).resolve().parents[1] / "policies" / "docker.yaml"

    catalog = load_catalog(str(catalog_path))
    policy = load_policy(str(policy_path))

    # Scenario: Container stopped -> Should ALLOW restart_container per policy
    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=False, status="exited", exit_code=0), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Stopped gracefully", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    result = diagnose("docker", policy, {"container": "test_app"}, catalog=catalog)

    assert result.decision.status == DecisionStatus.ALLOW
    assert result.metrics.success is True
    assert any(e.id == "container.running" and e.status == EvidenceStatus.FAIL for e in result.evidence)


def test_docker_container_oom_killed(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(
                ran=True,
                returncode=0,
                stdout=_make_inspect(running=False, status="exited", exit_code=137, oom_killed=True),
                stderr="",
            )
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Killed\nOut of memory", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exit_code"].value["status"] == "FAIL"
    assert obs_map["container.logs"].value["status"] == "FAIL"
    assert "OOM" in obs_map["container.logs"].message


def test_docker_health_starting(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True, health_status="starting"), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=0, stdout="Starting up...", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.health"].value["status"] == "UNKNOWN"
    assert "starting" in obs_map["container.health"].message


def test_docker_inspect_invalid_json(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout="invalid json {", stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "UNKNOWN"
    assert "Failed to parse docker inspect JSON" in obs_map["container.exists"].message


def test_docker_logs_failure(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True), stderr="")
        if "logs" in args:
            return Mock(ran=True, returncode=1, stdout="", stderr="error reading logs")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.logs"].value["status"] == "UNKNOWN"


def test_docker_missing_container_context():
    provider = DockerProvider()
    with pytest.raises(ValueError, match="Missing required context variable: container"):
        provider.collect(ProviderContext({}))


def test_docker_other_health_status(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True, health_status="custom_status"), stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.health"].value["status"] == "UNKNOWN"
    assert "custom_status" in obs_map["container.health"].message


def test_docker_empty_inspect_structure(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        return Mock(ran=True, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.exists"].value["status"] == "UNKNOWN"


def test_docker_logs_not_ran(monkeypatch):
    provider = DockerProvider()

    def mock_run_command(args, **kwargs):
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True), stderr="")
        if "logs" in args:
            return Mock(ran=False, returncode=None, stdout="", stderr="", error="command not found")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "test_app"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["container.logs"].value["status"] == "UNKNOWN"
    assert "command not found" in obs_map["container.logs"].message


def test_docker_remote_ssh(monkeypatch):
    provider = DockerProvider()

    captured_args = []
    def mock_run_command(args, host=None, **kwargs):
        captured_args.append((args, host))
        if "inspect" in args:
            return Mock(ran=True, returncode=0, stdout=_make_inspect(running=True), stderr="")
        return Mock(ran=True, returncode=0, stdout="remote log line", stderr="")

    monkeypatch.setattr("evidencetool.providers.docker.run_command", mock_run_command)

    obs = provider.collect(ProviderContext({"container": "remote_app", "host": "prod-docker-01"}))
    assert len(obs) > 0
    assert any(h == "prod-docker-01" for _, h in captured_args)
    assert obs[0].host == "prod-docker-01"


