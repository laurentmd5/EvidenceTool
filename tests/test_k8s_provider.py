"""
Unit tests for Kubernetes Provider (Mode A: kubectl CLI).
"""

from __future__ import annotations

import json
from unittest.mock import Mock

from evidencetool.capability.models import CapabilitySet, ExecutionContext, KubernetesCapability
from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.evidence.evaluator import evaluate_observation
from evidencetool.policy.loader import load_policy
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.k8s import K8sProvider
from evidencetool.providers.registry import get_provider


def test_k8s_provider_registration():
    p1 = get_provider("k8s")
    p2 = get_provider("kubernetes")
    assert isinstance(p1, K8sProvider)
    assert isinstance(p2, K8sProvider)


def test_k8s_healthy_pod(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "spec": {"nodeName": "node-worker-01"},
        "status": {
            "phase": "Running",
            "conditions": [
                {"type": "PodScheduled", "status": "True"},
                {"type": "ContainersReady", "status": "True"},
                {"type": "Ready", "status": "True"},
            ],
            "containerStatuses": [
                {
                    "name": "api",
                    "ready": True,
                    "restartCount": 0,
                    "state": {"running": {"startedAt": "2026-08-25T10:00:00Z"}},
                }
            ],
        },
    }

    node_payload = {
        "status": {
            "conditions": [
                {"type": "Ready", "status": "True"},
                {"type": "MemoryPressure", "status": "False"},
                {"type": "DiskPressure", "status": "False"},
            ]
        }
    }

    def mock_run_command(args, **kwargs):
        if "pod" in args:
            return Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr="")
        if "node" in args:
            return Mock(ran=True, returncode=0, stdout=json.dumps(node_payload), stderr="")
        return Mock(ran=False, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("evidencetool.providers.k8s.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"pod": "api-service-789", "namespace": "production"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.pod_phase"].value["status"] == "PASS"
    assert obs_map["k8s.containers_ready"].value["status"] == "PASS"
    assert obs_map["k8s.container_crashloop"].value["status"] == "PASS"
    assert obs_map["k8s.container_oom_killed"].value["status"] == "PASS"
    assert obs_map["k8s.image_pull_status"].value["status"] == "PASS"
    assert obs_map["k8s.config_secret_status"].value["status"] == "PASS"
    assert obs_map["k8s.pod_scheduled"].value["status"] == "PASS"
    assert obs_map["k8s.node_ready"].value["status"] == "PASS"


def test_k8s_oom_killed(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "spec": {"nodeName": "node-worker-01"},
        "status": {
            "phase": "Running",
            "conditions": [
                {"type": "PodScheduled", "status": "True"},
                {"type": "ContainersReady", "status": "False"},
            ],
            "containerStatuses": [
                {
                    "name": "worker",
                    "ready": False,
                    "restartCount": 3,
                    "state": {"running": {}},
                    "lastState": {
                        "terminated": {"reason": "OOMKilled", "exitCode": 137}
                    },
                }
            ],
        },
    }

    def mock_run_command(args, **kwargs):
        if "pod" in args:
            return Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr="")
        return Mock(ran=True, returncode=0, stdout=json.dumps({"status": {"conditions": [{"type": "Ready", "status": "True"}]}}), stderr="")

    monkeypatch.setattr("evidencetool.providers.k8s.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"pod": "worker-456", "namespace": "default"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.container_oom_killed"].value["status"] == "FAIL"
    assert obs_map["k8s.container_oom_killed"].value["failure"] == "OOM_KILLED"
    assert obs_map["k8s.container_oom_killed"].value["exit_code"] == 137


def test_k8s_crashloop_backoff(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "spec": {"nodeName": "node-worker-01"},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "ContainersReady", "status": "False"}],
            "containerStatuses": [
                {
                    "name": "backend",
                    "ready": False,
                    "restartCount": 8,
                    "state": {
                        "waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}
                    },
                }
            ],
        },
    }

    def mock_run_command(args, **kwargs):
        if "pod" in args:
            return Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr="")
        return Mock(ran=True, returncode=0, stdout=json.dumps({"status": {"conditions": [{"type": "Ready", "status": "True"}]}}), stderr="")

    monkeypatch.setattr("evidencetool.providers.k8s.run_command", mock_run_command)

    obs = p.collect(ProviderContext({"pod": "backend-123", "namespace": "default"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.container_crashloop"].value["status"] == "FAIL"
    assert obs_map["k8s.container_crashloop"].value["failure"] == "CRASH_LOOP_BACKOFF"
    assert obs_map["k8s.container_crashloop"].value["restart_count"] == 8


def test_k8s_image_pull_failure(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "status": {
            "phase": "Pending",
            "conditions": [{"type": "ContainersReady", "status": "False"}],
            "containerStatuses": [
                {
                    "name": "web",
                    "ready": False,
                    "state": {
                        "waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image 'registry.internal/app:v99'"}
                    },
                }
            ],
        }
    }

    monkeypatch.setattr(
        "evidencetool.providers.k8s.run_command",
        lambda args, **kwargs: Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr=""),
    )

    obs = p.collect(ProviderContext({"pod": "web-0", "namespace": "default"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.image_pull_status"].value["status"] == "FAIL"
    assert obs_map["k8s.image_pull_status"].value["failure"] == "IMAGE_PULL_FAILURE"


def test_k8s_configmap_secret_missing(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "status": {
            "phase": "Pending",
            "conditions": [{"type": "ContainersReady", "status": "False"}],
            "containerStatuses": [
                {
                    "name": "auth",
                    "ready": False,
                    "state": {
                        "waiting": {
                            "reason": "CreateContainerConfigError",
                            "message": "secret 'jwt-private-key' not found",
                        }
                    },
                }
            ],
        }
    }

    monkeypatch.setattr(
        "evidencetool.providers.k8s.run_command",
        lambda args, **kwargs: Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr=""),
    )

    obs = p.collect(ProviderContext({"pod": "auth-svc", "namespace": "default"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.config_secret_status"].value["status"] == "FAIL"
    assert obs_map["k8s.config_secret_status"].value["failure"] == "CONFIG_SECRET_MISSING"


def test_k8s_unschedulable_pending(monkeypatch):
    p = K8sProvider()

    pod_payload = {
        "status": {
            "phase": "Pending",
            "conditions": [
                {
                    "type": "PodScheduled",
                    "status": "False",
                    "reason": "Unschedulable",
                    "message": "0/8 nodes are available: 8 Insufficient cpu",
                }
            ],
        }
    }

    monkeypatch.setattr(
        "evidencetool.providers.k8s.run_command",
        lambda args, **kwargs: Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr=""),
    )

    obs = p.collect(ProviderContext({"pod": "ml-training-job", "namespace": "default"}))
    obs_map = {o.id: o for o in obs}

    assert obs_map["k8s.pod_scheduled"].value["status"] == "FAIL"
    assert obs_map["k8s.pod_scheduled"].value["failure"] == "SCHEDULING_FAILED"
    assert "Insufficient cpu" in obs_map["k8s.pod_scheduled"].value["message"]


def test_k8s_capability_denied_on_kube_system():
    p = K8sProvider()
    context = ProviderContext(
        {"pod": "coredns-123", "namespace": "kube-system"},
        execution=ExecutionContext(
            capabilities=CapabilitySet(
                kubernetes=KubernetesCapability(
                    allowed_namespaces=("production", "staging"),
                    denied_namespaces=frozenset({"kube-system"}),
                )
            )
        ),
    )

    obs = p.collect(context)
    obs_map = {o.id: o for o in obs}
    assert obs_map["k8s.pod_phase"].value["status"] == "UNKNOWN"
    assert obs_map["k8s.pod_phase"].value["capability_denied"] is True


def test_k8s_situation_correlation_and_decision(monkeypatch):
    catalog = load_catalog("catalogs/kubernetes.yaml")
    policy = load_policy("policies/kubernetes.yaml")

    p = K8sProvider()

    pod_payload = {
        "spec": {"nodeName": "node-worker-01"},
        "status": {
            "phase": "Running",
            "conditions": [
                {"type": "PodScheduled", "status": "True"},
                {"type": "ContainersReady", "status": "False"},
            ],
            "containerStatuses": [
                {
                    "name": "web",
                    "ready": False,
                    "restartCount": 5,
                    "state": {"running": {}},
                    "lastState": {
                        "terminated": {"reason": "OOMKilled", "exitCode": 137}
                    },
                }
            ],
        },
    }

    def mock_run_command(args, **kwargs):
        if "pod" in args:
            return Mock(ran=True, returncode=0, stdout=json.dumps(pod_payload), stderr="")
        return Mock(ran=True, returncode=0, stdout=json.dumps({"status": {"conditions": [{"type": "Ready", "status": "True"}]}}), stderr="")

    monkeypatch.setattr("evidencetool.providers.k8s.run_command", mock_run_command)

    observations = p.collect(ProviderContext({"pod": "web-789", "namespace": "default"}))
    evidence = [evaluate_observation(o) for o in observations]
    state = correlate_state(evidence, catalog)
    decision = decide(state_or_evidence=state, policy=policy)

    assert decision.status.value == "BLOCK"
    assert "K8S_OOM_KILLED" in decision.reason
    assert "k8s.container_oom_killed" in decision.blocking_evidence
