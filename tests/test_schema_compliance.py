"""
Systematic JSON Output Schema Compliance Tests.

Validates that DiagnosisResult JSON outputs across all operational domains
(Nginx, Docker, Kubernetes, Network, Process, Data, Distributed, Agent Gate)
strictly comply with the official Draft-07 JSON Schema in
`schemas/diagnosis-result.schema.json`.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import jsonschema
import pytest

from evidencetool.agent import AgentDiagnosisRequest, AgentSafetyGate
from evidencetool.cli.render import to_contract_dict, to_json
from evidencetool.diagnose import diagnose
from evidencetool.diagnostic.loader import load_catalog
from evidencetool.models.policy import EvidenceRequirement, OnUnknown, Policy, PolicySchema, RiskLevel


@pytest.fixture(scope="module")
def json_schema() -> dict:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "diagnosis-result.schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    jsonschema.Draft7Validator.check_schema(schema)
    return schema


def test_schema_itself_is_valid_draft7(json_schema):
    """Ensure the JSON schema itself is valid according to the Draft-07 specification."""
    assert json_schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert "required" in json_schema
    assert set(json_schema["required"]) == {"incident", "evidence", "policy", "decision", "recommendation"}


def test_nginx_legacy_diagnosis_matches_schema(json_schema, tmp_path):
    """Test Nginx V1_LEGACY policy diagnosis conforms to schema."""
    conf = tmp_path / "nginx.conf"
    conf.write_text("events {}\nhttp {}\n", encoding="utf-8")

    policy = Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V1_LEGACY,
        required_evidence=[
            EvidenceRequirement(id="nginx.config_valid", on_unknown=OnUnknown.BLOCK),
            EvidenceRequirement(id="systemd.service_exists", on_unknown=OnUnknown.BLOCK),
            EvidenceRequirement(id="systemd.service_active", on_unknown=OnUnknown.IGNORE),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "nginx: syntax is ok\nnginx: test is successful"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = diagnose("nginx", policy, context={"config_path": str(conf)})
        result_dict = to_contract_dict(result)

        # Validate against JSON schema
        jsonschema.validate(instance=result_dict, schema=json_schema)

        # Also test serialized JSON string roundtrip
        json_str = to_json(result)
        parsed = json.loads(json_str)
        jsonschema.validate(instance=parsed, schema=json_schema)


def test_nginx_situational_diagnosis_matches_schema(json_schema):
    """Test Nginx V2_SITUATIONAL policy diagnosis conforms to schema."""
    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "nginx.yaml"
    catalog = load_catalog(str(catalog_path))

    policy = Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["NGINX_SERVICE_DOWN"],
        blocked_by=["NGINX_CONFIG_INVALID", "TLS_CERTIFICATE_EXPIRED"],
        required_evidence=[],
    )

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "ActiveState=inactive\nLoadState=loaded"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = diagnose(
            "nginx",
            policy,
            catalog=catalog,
            context={"config_path": "/etc/nginx/nginx.conf"},
        )
        result_dict = to_contract_dict(result)
        jsonschema.validate(instance=result_dict, schema=json_schema)


def test_docker_diagnosis_matches_schema(json_schema):
    """Test Docker container diagnosis conforms to schema."""
    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "docker.yaml"
    catalog = load_catalog(str(catalog_path))

    policy = Policy(
        version="1.0",
        action="restart_container",
        risk=RiskLevel.LOW,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["CONTAINER_STOPPED", "CONTAINER_CRASH_LOOP"],
        blocked_by=["CONTAINER_NOT_FOUND"],
    )

    inspect_data = json.dumps([
        {
            "State": {
                "Status": "exited",
                "Running": False,
                "Restarting": False,
                "ExitCode": 1,
            }
        }
    ])

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = inspect_data
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = diagnose("docker", policy, catalog=catalog, context={"container": "test_app"})
        result_dict = to_contract_dict(result)
        jsonschema.validate(instance=result_dict, schema=json_schema)


def test_kubernetes_diagnosis_matches_schema(json_schema):
    """Test Kubernetes diagnostic output conforms to schema."""
    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "kubernetes.yaml"
    catalog = load_catalog(str(catalog_path))

    policy = Policy(
        version="1.0",
        action="restart_deployment",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["K8S_POD_HEALTHY"],
        blocked_by=["K8S_CRASH_LOOP_BACKOFF", "K8S_OOM_KILLED"],
    )

    k8s_pod_json = json.dumps({
        "status": {
            "phase": "Running",
            "conditions": [{"type": "PodScheduled", "status": "True"}],
            "containerStatuses": [
                {
                    "name": "web",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-09-18T10:00:00Z"}},
                }
            ],
        },
        "spec": {"nodeName": "worker-01"},
    })

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = k8s_pod_json
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = diagnose(
            "k8s",
            policy,
            catalog=catalog,
            context={"pod": "api-deployment-xyz", "namespace": "default"},
        )
        result_dict = to_contract_dict(result)
        jsonschema.validate(instance=result_dict, schema=json_schema)


def test_distributed_causal_diagnosis_matches_schema(json_schema):
    """Test Distributed diagnosis with CausalExplanation conforms to schema."""
    from evidencetool.causality.engine import reconstruct_causality
    from evidencetool.causality.loader import load_causal_catalog
    from evidencetool.decision.correlation import correlate_state
    from evidencetool.decision.engine import decide
    from evidencetool.diagnose import DiagnosisResult
    from evidencetool.models.incident import OperationalIncident

    catalog_path = Path(__file__).resolve().parents[1] / "catalogs" / "distributed.yaml"
    catalog = load_catalog(str(catalog_path))

    causality_catalog_path = Path(__file__).resolve().parents[1] / "causality" / "distributed.yaml"
    causal_rules = load_causal_catalog(str(causality_catalog_path))

    policy = Policy(
        version="1.0",
        action="restart_application",
        risk=RiskLevel.HIGH,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["DISTRIBUTED_HEALTHY"],
        blocked_by=["DATABASE_CONNECTIVITY_FAILURE"],
    )

    result = diagnose("dependency", policy, catalog=catalog, context={"url": "http://127.0.0.1:8080/health"})

    # Reconstruct causality
    state = correlate_state(result.evidence, catalog)
    decision = decide(state, policy)
    causality = reconstruct_causality(result.evidence, state, causal_rules)

    incident = OperationalIncident(
        incident_id="inc-test-01",
        target="distributed-app",
        observations=[e.observation for e in result.evidence],
        situations=state.situations,
        causality=causality,
        decision=decision,
        policy=policy,
        created_at=datetime.now(timezone.utc),
    )

    causal_result = DiagnosisResult(
        incident=incident,
        evidence=result.evidence,
        policy=policy,
        decision=decision,
        recommendation="Action blocked due to connectivity failure.",
        causality=causality,
        metrics=result.metrics,
    )

    result_dict = to_contract_dict(causal_result)
    assert "causality" in result_dict
    assert result_dict["causality"]["status"] in {
        "ROOT_CAUSE_IDENTIFIED",
        "ROOT_CAUSE_CONSTRAINED",
        "ROOT_CAUSE_UNKNOWN",
    }
    jsonschema.validate(instance=result_dict, schema=json_schema)


def test_agent_safety_gate_matches_schema(json_schema):
    """Test AgentSafetyGate output including authority block conforms to schema."""
    gate = AgentSafetyGate(
        catalog="catalogs/distributed.yaml",
        default_policy="policies/distributed.yaml",
    )

    request = AgentDiagnosisRequest(
        agent_id="remediation-bot",
        action="restart_application",
        target="orders-api",
        context={"url": "http://127.0.0.1:8080/health"},
    )

    result = gate.evaluate(request)
    result_dict = result.to_dict()

    # Must contain authority metadata
    assert "authority" in result_dict
    assert result_dict["authority"]["caller_id"] == "remediation-bot"
    assert result_dict["authority"]["caller_type"] == "AI_AGENT"

    # Schema must validate cleanly
    jsonschema.validate(instance=result_dict, schema=json_schema)
