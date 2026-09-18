"""
Adversarial and Correctness Tests — V1.0.2

Validates fundamental decision-engine properties:
1. Uncertainty is local to the hypothesis it affects (no cross-domain contamination).
2. UNKNOWN != FAIL and UNKNOWN != PASS.
3. Provider failure produces UNKNOWN fallback observations across V2 signatures.
4. Network input bounds (RESP parser, MySQL handshake, SSH timeout, curl timeout).
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from evidencetool.decision.correlation import correlate_state
from evidencetool.decision.engine import decide
from evidencetool.decision.integrity import validate_decision_integrity
from evidencetool.diagnose import diagnose
from evidencetool.models.correlation import Situation
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.evidence import Evidence, EvidenceStatus
from evidencetool.models.observation import Observation
from evidencetool.models.policy import Policy, PolicySchema, RiskLevel
from evidencetool.providers._shell import run_command
from evidencetool.providers.dependency import DependencyProvider
from evidencetool.providers.mysql import MAX_MYSQL_HANDSHAKE_SIZE, MySQLProvider
from evidencetool.providers.redis import MAX_RESP_BULK_SIZE, MAX_RESP_LINE_LENGTH, _read_resp_line, _read_resp_response


def make_evidence(ev_id: str, status: EvidenceStatus) -> Evidence:
    obs = Observation(
        id=ev_id,
        source=ev_id.split(".")[0],
        category="system",
        collector="test",
        method="unit_test",
        value={"status": status.value},
        message=f"Test evidence for {ev_id}",
        observed_at=datetime.now(timezone.utc),
    )
    return Evidence(observation=obs, status=status, message=f"Test {ev_id}")


@pytest.fixture
def multi_domain_catalog() -> list[Situation]:
    return [
        Situation(
            id="NGINX_NOMINAL",
            description="Nginx is running normally",
            signature={
                "nginx.config_valid": EvidenceStatus.PASS,
                "systemd.service_active": EvidenceStatus.PASS,
            },
        ),
        Situation(
            id="NGINX_SERVICE_DOWN",
            description="Nginx config is valid but service is inactive",
            signature={
                "nginx.config_valid": EvidenceStatus.PASS,
                "systemd.service_active": EvidenceStatus.FAIL,
            },
        ),
        Situation(
            id="NGINX_CONFIG_BROKEN",
            description="Nginx configuration is invalid",
            signature={
                "nginx.config_valid": EvidenceStatus.FAIL,
            },
        ),
        Situation(
            id="REDIS_HEALTHY",
            description="Redis is reachable and responding",
            signature={
                "redis.reachable": EvidenceStatus.PASS,
                "redis.ping": EvidenceStatus.PASS,
            },
        ),
        Situation(
            id="REDIS_OUTAGE",
            description="Redis is completely unreachable",
            signature={
                "redis.reachable": EvidenceStatus.FAIL,
            },
        ),
        Situation(
            id="DATABASE_UNHEALTHY",
            description="Postgres connection failed",
            signature={
                "postgres.reachable": EvidenceStatus.FAIL,
            },
        ),
    ]


@pytest.fixture
def restart_nginx_policy() -> Policy:
    return Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["NGINX_SERVICE_DOWN"],
        blocked_by=["NGINX_CONFIG_BROKEN"],
    )


# ---------------------------------------------------------------------------
# Test A: Happy path — All PASS, allowed situation matches cleanly
# ---------------------------------------------------------------------------
def test_a_happy_path_allowed(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, multi_domain_catalog)
    decision = decide(state, restart_nginx_policy)

    assert decision.status == DecisionStatus.ALLOW
    assert "NGINX_SERVICE_DOWN" in decision.reason
    assert len(decision.blocking_evidence) == 0

    integrity = validate_decision_integrity(decision, restart_nginx_policy, evidence, state)
    assert integrity.is_valid


# ---------------------------------------------------------------------------
# Test B: Failure detection — Evidence matches a blocked situation
# ---------------------------------------------------------------------------
def test_b_failure_blocked(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.FAIL),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, multi_domain_catalog)
    decision = decide(state, restart_nginx_policy)

    assert decision.status == DecisionStatus.BLOCK
    assert "NGINX_CONFIG_BROKEN" in decision.reason
    assert "nginx.config_valid" in decision.blocking_evidence

    integrity = validate_decision_integrity(decision, restart_nginx_policy, evidence, state)
    assert integrity.is_valid


# ---------------------------------------------------------------------------
# Test C: Local UNKNOWN in allowed situation -> BLOCK (UNKNOWN != PASS)
# ---------------------------------------------------------------------------
def test_c_local_unknown_blocks(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.UNKNOWN),
    ]
    state = correlate_state(evidence, multi_domain_catalog)
    decision = decide(state, restart_nginx_policy)

    assert decision.status == DecisionStatus.BLOCK
    assert "cannot be evaluated: unresolved" in decision.reason
    assert "systemd.service_active" in decision.blocking_evidence


# ---------------------------------------------------------------------------
# Test D: HIGH-02 Core Invariant — UNKNOWN in unrelated domain DOES NOT
# contaminate a clean decision in the target domain!
# ---------------------------------------------------------------------------
def test_d_local_uncertainty_no_cross_contamination(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
        # Redis is UNKNOWN due to network glitch or provider failure:
        make_evidence("redis.reachable", EvidenceStatus.UNKNOWN),
        make_evidence("redis.ping", EvidenceStatus.UNKNOWN),
    ]
    state = correlate_state(evidence, multi_domain_catalog)

    # Redis situation is ambiguous locally:
    redis_eval = next(ev for ev in state.evaluations if ev.situation.id == "REDIS_OUTAGE")
    assert redis_eval.is_ambiguous

    # Nginx situation is NOT ambiguous:
    nginx_eval = next(ev for ev in state.evaluations if ev.situation.id == "NGINX_SERVICE_DOWN")
    assert not nginx_eval.is_ambiguous
    assert nginx_eval.matched

    decision = decide(state, restart_nginx_policy)
    # Fundamental guarantee: Nginx decision is ALLOW, not blocked by Redis UNKNOWN!
    assert decision.status == DecisionStatus.ALLOW
    assert "NGINX_SERVICE_DOWN" in decision.reason

    # Decision integrity passes because local ambiguity for Nginx is 0
    integrity = validate_decision_integrity(decision, restart_nginx_policy, evidence, state)
    assert integrity.is_valid


# ---------------------------------------------------------------------------
# Test E: HIGH-01 Fallback UNKNOWN in V2 when provider crashes
# ---------------------------------------------------------------------------
def test_e_v2_fallback_unknown_on_provider_crash(multi_domain_catalog, restart_nginx_policy):
    policy = Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["NGINX_SERVICE_DOWN"],
        blocked_by=["NGINX_CONFIG_BROKEN"],
        required_evidence=[],  # Empty required_evidence, relies on catalog signatures!
    )

    # Mock get_provider to simulate crash of systemd provider
    with patch("evidencetool.providers.registry.get_provider") as mock_get_provider:
        mock_instance = MagicMock()
        mock_instance.collect.side_effect = RuntimeError("systemctl daemon connection lost")
        mock_get_provider.return_value = mock_instance

        res = diagnose(
            target="nginx",
            policy=policy,
            context={"config_path": "/etc/nginx/nginx.conf"},
            catalog=multi_domain_catalog,
        )

        # Observations must contain fallback UNKNOWN for systemd.service_active derived from catalog
        systemd_obs = [o for o in res.incident.observations if o.id == "systemd.service_active"]
        assert len(systemd_obs) > 0
        assert systemd_obs[0].value.get("status") == "UNKNOWN"

        # The decision must be BLOCK due to unresolved evidence, NOT "no situation matches"
        assert res.decision.status == DecisionStatus.BLOCK


# ---------------------------------------------------------------------------
# Test F: Multiple situations — A=MATCH, B=UNKNOWN, C=NO_MATCH
# ---------------------------------------------------------------------------
def test_f_multiple_situations_isolation(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
        make_evidence("redis.reachable", EvidenceStatus.UNKNOWN),
        make_evidence("postgres.reachable", EvidenceStatus.PASS),  # DATABASE_UNHEALTHY fails to match
    ]
    state = correlate_state(evidence, multi_domain_catalog)

    eval_a = next(e for e in state.evaluations if e.situation.id == "NGINX_SERVICE_DOWN")
    eval_b = next(e for e in state.evaluations if e.situation.id == "REDIS_OUTAGE")
    eval_c = next(e for e in state.evaluations if e.situation.id == "DATABASE_UNHEALTHY")

    assert eval_a.matched is True
    assert eval_a.is_ambiguous is False

    assert eval_b.matched is False
    assert eval_b.is_ambiguous is True

    assert eval_c.matched is False
    assert eval_c.is_ambiguous is False

    decision = decide(state, restart_nginx_policy)
    assert decision.status == DecisionStatus.ALLOW


# ---------------------------------------------------------------------------
# Test G: Irrelevant UNKNOWN evidence never contaminates decision
# ---------------------------------------------------------------------------
def test_g_completely_unrelated_unknown(multi_domain_catalog, restart_nginx_policy):
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
        make_evidence("custom_sensor.temperature", EvidenceStatus.UNKNOWN),
    ]
    state = correlate_state(evidence, multi_domain_catalog)
    assert not state.ambiguous
    decision = decide(state, restart_nginx_policy)
    assert decision.status == DecisionStatus.ALLOW


# ---------------------------------------------------------------------------
# Test H: Precedence — blocked_by ALWAYS overrides allow
# ---------------------------------------------------------------------------
def test_h_precedence_blocked_over_allowed(multi_domain_catalog):
    policy = Policy(
        version="1.0",
        action="restart_nginx",
        risk=RiskLevel.MEDIUM,
        schema=PolicySchema.V2_SITUATIONAL,
        allow=["NGINX_SERVICE_DOWN"],
        blocked_by=["NGINX_SERVICE_DOWN"],  # Contradictory policy: both allow and blocked_by
    )
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
        make_evidence("systemd.service_active", EvidenceStatus.FAIL),
    ]
    state = correlate_state(evidence, multi_domain_catalog)
    decision = decide(state, policy)

    assert decision.status == DecisionStatus.BLOCK
    assert "explicitly blocked" in decision.reason


# ---------------------------------------------------------------------------
# Test I: Missing evidence is distinct from UNKNOWN
# ---------------------------------------------------------------------------
def test_i_missing_evidence_distinct_from_unknown(multi_domain_catalog, restart_nginx_policy):
    # Only config_valid provided; service_active completely missing (never probed)
    evidence = [
        make_evidence("nginx.config_valid", EvidenceStatus.PASS),
    ]
    state = correlate_state(evidence, multi_domain_catalog)

    eval_sit = next(e for e in state.evaluations if e.situation.id == "NGINX_SERVICE_DOWN")
    assert eval_sit.matched is False
    assert eval_sit.is_ambiguous is False  # Missing is NOT ambiguous (unknown)
    assert "systemd.service_active" in eval_sit.missing_evidence

    decision = decide(state, restart_nginx_policy)
    assert decision.status == DecisionStatus.BLOCK
    assert "No known situation matches" in decision.reason
    assert "systemd.service_active" in decision.blocking_evidence


# ---------------------------------------------------------------------------
# Test J: Network Input Bounds — Redis RESP Parser (CRIT-01)
# ---------------------------------------------------------------------------
def test_j_redis_resp_parser_bounds():
    class FakeSocket:
        def __init__(self, data: bytes):
            self.data = data
            self.pos = 0

        def recv(self, bufsize: int) -> bytes:
            if self.pos >= len(self.data):
                return b""
            chunk = self.data[self.pos : self.pos + bufsize]
            self.pos += len(chunk)
            return chunk

    # 1. Test line length limit (protects against infinite lines)
    huge_line = b"X" * (MAX_RESP_LINE_LENGTH + 100) + b"\r\n"
    sock = FakeSocket(huge_line)
    line = _read_resp_line(sock)
    assert len(line) <= MAX_RESP_LINE_LENGTH

    # 2. Test bulk string size limit ($2147483647 does NOT allocate 2GB)
    malicious_resp = f"${MAX_RESP_BULK_SIZE + 1000}\r\n".encode("ascii")
    sock2 = FakeSocket(malicious_resp)
    rtype, payload = _read_resp_response(sock2)
    assert rtype == "$"
    assert "TRUNCATED" in payload
    assert "exceeds" in payload


# ---------------------------------------------------------------------------
# Test K: Network Input Bounds — MySQL Handshake (CRIT-02)
# ---------------------------------------------------------------------------
def test_k_mysql_handshake_bounds():
    class FakeSocket:
        def __init__(self, header: bytes):
            self.header = header
            self.recv_count = 0

        def recv(self, n: int) -> bytes:
            self.recv_count += 1
            if self.recv_count == 1:
                return self.header
            return b"A" * n

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    # Header with payload_len = 100,000 bytes > MAX_MYSQL_HANDSHAKE_SIZE (65536)
    bad_header = (MAX_MYSQL_HANDSHAKE_SIZE + 5000).to_bytes(3, "little") + b"\x00"
    fake_sock = FakeSocket(bad_header)

    provider = MySQLProvider()
    with patch("socket.create_connection", return_value=fake_sock):
        val, msg, _, _ = provider._check_mysql_local("127.0.0.1", 3306, timeout=1.0)
        assert val["status"] == "FAIL"
        assert "too large" in val.get("error", "") or "too large" in msg


# ---------------------------------------------------------------------------
# Test L: SSH ConnectTimeout (HIGH-03)
# ---------------------------------------------------------------------------
def test_l_ssh_connect_timeout():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "ok"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        run_command(["echo", "hi"], host="remote-host", timeout=7.0)

        # Ensure SSH was called with ConnectTimeout
        called_args = mock_run.call_args[0][0]
        assert "ssh" in called_args
        assert "-o" in called_args
        assert "ConnectTimeout=7" in called_args


# ---------------------------------------------------------------------------
# Test M: Dependency curl -m timeout (MED-02)
# ---------------------------------------------------------------------------
def test_m_curl_max_time():
    provider = DependencyProvider()
    with patch("evidencetool.providers.dependency.run_command") as mock_run:
        mock_res = MagicMock()
        mock_res.ran = True
        mock_res.returncode = 0
        mock_res.stdout = "200:0.05"
        mock_res.stderr = ""
        mock_run.return_value = mock_res

        provider._probe_remote(
            url="http://example.com/health",
            host="remote-host",
            timeout=3.0,
            sla_budget_ms=500.0,
            allow_insecure_tls=False,
        )

        called_cmd = mock_run.call_args[0][0]
        assert "-m" in called_cmd
        m_index = called_cmd.index("-m")
        assert called_cmd[m_index + 1] == "3"
