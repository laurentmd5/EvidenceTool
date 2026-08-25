"""
Kubernetes provider — per PRODUCT_CONTRACT.md (V0.7 Kubernetes Provider).

Checks (Mode A: kubectl CLI):
  - k8s.pod_phase
  - k8s.containers_ready
  - k8s.container_crashloop
  - k8s.container_oom_killed
  - k8s.image_pull_status
  - k8s.config_secret_status
  - k8s.pod_scheduled
  - k8s.node_ready
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from evidencetool.capability.models import CapabilityDenied
from evidencetool.models.observation import Observation
from evidencetool.providers._shell import run_command
from evidencetool.providers.base import ProviderContext
from evidencetool.providers.registry import provider

COLLECTOR = "k8s_provider"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@provider("k8s")
@provider("kubernetes")
class K8sProvider:
    def collect(self, context: ProviderContext) -> list[Observation]:
        self._capabilities = context.execution.capabilities
        host = context.get("host", "")
        pod_name = context.get("pod") or context.get("pod_name") or context.get("target") or ""
        namespace = context.get("namespace") or context.get("ns") or "default"

        if not pod_name:
            raise ValueError("Kubernetes provider requires 'pod' or 'pod_name' in context.")

        method = f"kubectl get pod {pod_name} -n {namespace} -o json"
        try:
            self._capabilities.require_kubernetes("k8s_get_pod", namespace)
        except CapabilityDenied as exc:
            return [self._unknown_obs("k8s.pod_phase", method, pod_name, namespace, host, str(exc))]

        # 1. Fetch Pod JSON
        timeout = self._capabilities.kubernetes.timeout_seconds
        res = run_command(
            ["kubectl", "get", "pod", pod_name, "-n", namespace, "-o", "json"],
            timeout=timeout,
            host=host,
        )

        if not res.ran or res.returncode != 0:
            err = res.stderr.strip() if res.ran else (res.error or "Command failed")
            return [
                Observation(
                    id="k8s.pod_phase",
                    source="k8s",
                    category="orchestration",
                    collector=COLLECTOR,
                    method=method,
                    value={"status": "FAIL", "failure": "POD_NOT_FOUND", "error": err},
                    message=f"Could not get pod '{pod_name}' in namespace '{namespace}': {err}",
                    observed_at=_now(),
                    host=host,
                )
            ]

        try:
            pod_json: dict[str, Any] = json.loads(res.stdout)
        except Exception as e:
            return [
                Observation(
                    id="k8s.pod_phase",
                    source="k8s",
                    category="orchestration",
                    collector=COLLECTOR,
                    method=method,
                    value={"status": "FAIL", "failure": "JSON_PARSE_ERROR", "error": str(e)},
                    message=f"Failed to parse kubectl json output: {e}",
                    observed_at=_now(),
                    host=host,
                )
            ]

        # Extract all observations
        observations: list[Observation] = []
        status_dict: dict[str, Any] = pod_json.get("status", {})
        spec_dict: dict[str, Any] = pod_json.get("spec", {})

        observations.append(self._check_pod_phase(status_dict, pod_name, namespace, host))
        observations.append(self._check_containers_ready(status_dict, pod_name, namespace, host))
        observations.append(self._check_crashloop(status_dict, pod_name, namespace, host))
        observations.append(self._check_oom_killed(status_dict, pod_name, namespace, host))
        observations.append(self._check_image_pull(status_dict, pod_name, namespace, host))
        observations.append(self._check_config_secret(status_dict, pod_name, namespace, host))
        observations.append(self._check_pod_scheduled(status_dict, pod_name, namespace, host))

        # Node check if pod is scheduled
        node_name = spec_dict.get("nodeName")
        if node_name:
            node_obs = self._check_node_ready(node_name, pod_name, namespace, host)
            if node_obs:
                observations.append(node_obs)

        return observations

    def _check_pod_phase(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        phase = status.get("phase", "Unknown")
        if phase in ("Running", "Succeeded"):
            val: dict[str, Any] = {"status": "PASS", "phase": phase}
            msg = f"Pod '{pod}' is in phase '{phase}'"
        else:
            val = {"status": "FAIL", "failure": f"POD_{phase.upper()}", "phase": phase}
            msg = f"Pod '{pod}' is in phase '{phase}' (not healthy)"

        return Observation(
            id="k8s.pod_phase",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"pod.status.phase({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_containers_ready(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        conditions: list[dict[str, Any]] = status.get("conditions", [])
        is_ready = any(c.get("type") in ("ContainersReady", "Ready") and c.get("status") == "True" for c in conditions)

        if is_ready:
            val: dict[str, Any] = {"status": "PASS", "ready": True}
            msg = f"All containers in pod '{pod}' are ready"
        else:
            val = {"status": "FAIL", "failure": "CONTAINERS_NOT_READY", "ready": False}
            msg = f"Containers in pod '{pod}' are not ready"

        return Observation(
            id="k8s.containers_ready",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"pod.status.conditions({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_crashloop(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        container_statuses: list[dict[str, Any]] = status.get("containerStatuses", [])
        crashloop = False
        restarts = 0
        culprit = ""

        for cs in container_statuses:
            waiting = cs.get("state", {}).get("waiting", {})
            if waiting.get("reason") == "CrashLoopBackOff":
                crashloop = True
                culprit = cs.get("name", "unknown")
                restarts = cs.get("restartCount", 0)
                break

        if crashloop:
            val: dict[str, Any] = {
                "status": "FAIL",
                "failure": "CRASH_LOOP_BACKOFF",
                "container": culprit,
                "restart_count": restarts,
            }
            msg = f"Container '{culprit}' in pod '{pod}' is in CrashLoopBackOff ({restarts} restarts)"
        else:
            val = {"status": "PASS"}
            msg = f"No containers in pod '{pod}' in CrashLoopBackOff"

        return Observation(
            id="k8s.container_crashloop",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"containerStatuses.state.waiting.reason({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_oom_killed(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        container_statuses: list[dict[str, Any]] = status.get("containerStatuses", [])
        oom_killed = False
        culprit = ""
        exit_code = 0

        for cs in container_statuses:
            terminated = cs.get("lastState", {}).get("terminated") or cs.get("state", {}).get("terminated")
            if terminated:
                reason = terminated.get("reason", "")
                code = terminated.get("exitCode", 0)
                if reason == "OOMKilled" or code == 137:
                    oom_killed = True
                    culprit = cs.get("name", "unknown")
                    exit_code = code
                    break

        if oom_killed:
            val: dict[str, Any] = {
                "status": "FAIL",
                "failure": "OOM_KILLED",
                "container": culprit,
                "exit_code": exit_code,
            }
            msg = f"Container '{culprit}' in pod '{pod}' was terminated due to OOMKilled (exit code {exit_code})"
        else:
            val = {"status": "PASS"}
            msg = f"No container OOMKilled events detected in pod '{pod}'"

        return Observation(
            id="k8s.container_oom_killed",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"containerStatuses.terminated({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_image_pull(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        all_statuses: list[dict[str, Any]] = status.get("initContainerStatuses", []) + status.get("containerStatuses", [])
        pull_failed = False
        reason_found = ""
        culprit = ""

        for cs in all_statuses:
            waiting = cs.get("state", {}).get("waiting", {})
            reason = waiting.get("reason", "")
            if reason in ("ImagePullBackOff", "ErrImagePull", "InvalidImageName"):
                pull_failed = True
                reason_found = reason
                culprit = cs.get("name", "unknown")
                break

        if pull_failed:
            val: dict[str, Any] = {
                "status": "FAIL",
                "failure": "IMAGE_PULL_FAILURE",
                "container": culprit,
                "reason": reason_found,
            }
            msg = f"Container '{culprit}' failed image pull: {reason_found}"
        else:
            val = {"status": "PASS"}
            msg = f"Image pull status nominal for pod '{pod}'"

        return Observation(
            id="k8s.image_pull_status",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"image_pull_check({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_config_secret(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        container_statuses: list[dict[str, Any]] = status.get("containerStatuses", [])
        config_failed = False
        culprit = ""
        err_msg = ""

        for cs in container_statuses:
            waiting = cs.get("state", {}).get("waiting", {})
            reason = waiting.get("reason", "")
            if reason in ("CreateContainerConfigError", "CreateContainerError"):
                config_failed = True
                culprit = cs.get("name", "unknown")
                err_msg = waiting.get("message", reason)
                break

        if config_failed:
            val: dict[str, Any] = {
                "status": "FAIL",
                "failure": "CONFIG_SECRET_MISSING",
                "container": culprit,
                "error": err_msg,
            }
            msg = f"Container '{culprit}' failed config/secret load: {err_msg}"
        else:
            val = {"status": "PASS"}
            msg = f"ConfigMap and Secret loading nominal for pod '{pod}'"

        return Observation(
            id="k8s.config_secret_status",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"config_secret_check({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_pod_scheduled(self, status: dict[str, Any], pod: str, ns: str, host: str | None) -> Observation:
        conditions: list[dict[str, Any]] = status.get("conditions", [])
        sched_cond = next((c for c in conditions if c.get("type") == "PodScheduled"), None)

        if sched_cond and sched_cond.get("status") == "True":
            val: dict[str, Any] = {"status": "PASS", "scheduled": True}
            msg = f"Pod '{pod}' is successfully scheduled"
        elif sched_cond and sched_cond.get("status") == "False":
            reason = sched_cond.get("reason", "Unschedulable")
            sched_msg = sched_cond.get("message", "Scheduling failed")
            val = {
                "status": "FAIL",
                "failure": "SCHEDULING_FAILED",
                "reason": reason,
                "message": sched_msg,
            }
            msg = f"Pod '{pod}' scheduling failed ({reason}): {sched_msg}"
        else:
            val = {"status": "PASS", "scheduled": True}
            msg = f"Pod '{pod}' scheduling status assumed nominal"

        return Observation(
            id="k8s.pod_scheduled",
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=f"pod.conditions.PodScheduled({ns}/{pod})",
            value=val,
            message=msg,
            observed_at=_now(),
            host=host,
        )

    def _check_node_ready(self, node_name: str, pod: str, ns: str, host: str | None) -> Observation | None:
        try:
            self._capabilities.require_kubernetes("k8s_get_node", ns)
        except CapabilityDenied:
            return None

        timeout = self._capabilities.kubernetes.timeout_seconds
        res = run_command(["kubectl", "get", "node", node_name, "-o", "json"], timeout=timeout, host=host)

        if not res.ran or res.returncode != 0:
            return Observation(
                id="k8s.node_ready",
                source="k8s",
                category="orchestration",
                collector=COLLECTOR,
                method=f"kubectl get node {node_name} -o json",
                value={"status": "FAIL", "failure": "NODE_NOT_FOUND", "node": node_name},
                message=f"Node '{node_name}' could not be queried",
                observed_at=_now(),
                host=host,
            )

        try:
            node_json: dict[str, Any] = json.loads(res.stdout)
            conditions: list[dict[str, Any]] = node_json.get("status", {}).get("conditions", [])
            ready_cond = next((c for c in conditions if c.get("type") == "Ready"), None)
            is_ready = ready_cond is not None and ready_cond.get("status") == "True"

            pressure = any(
                c.get("type") in ("MemoryPressure", "DiskPressure", "PIDPressure") and c.get("status") == "True"
                for c in conditions
            )

            if is_ready and not pressure:
                val: dict[str, Any] = {"status": "PASS", "node": node_name, "ready": True}
                msg = f"Node '{node_name}' is Ready without pressure"
            else:
                val = {
                    "status": "FAIL",
                    "failure": "NODE_NOT_READY" if not is_ready else "NODE_PRESSURE",
                    "node": node_name,
                    "ready": is_ready,
                    "pressure": pressure,
                }
                msg = f"Node '{node_name}' is in unhealthy state (Ready={is_ready}, Pressure={pressure})"

            return Observation(
                id="k8s.node_ready",
                source="k8s",
                category="orchestration",
                collector=COLLECTOR,
                method=f"node.conditions({node_name})",
                value=val,
                message=msg,
                observed_at=_now(),
                host=host,
            )
        except Exception:
            return None

    def _unknown_obs(
        self, evidence_id: str, method: str, pod: str, ns: str, host: str | None, reason: str
    ) -> Observation:
        return Observation(
            id=evidence_id,
            source="k8s",
            category="orchestration",
            collector=COLLECTOR,
            method=method,
            value={"status": "UNKNOWN", "capability_denied": True},
            message=f"Capability denied on namespace '{ns}': {reason}",
            observed_at=_now(),
            host=host,
            execution_scope="remote" if host else "local",
            target=pod,
            capability="k8s_get_pod",
            transport_status="capability_denied",
        )
