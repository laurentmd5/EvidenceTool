from evidencetool.models.policy import OnUnknown, RiskLevel
from evidencetool.policy.loader import load_policy_from_string

SAMPLE_POLICY = """
version: "1"

action: restart_nginx

risk: LOW

required_evidence:
  - id: nginx.config.valid
    on_unknown: BLOCK
  - id: tls.certificate.exists
    on_unknown: BLOCK
  - id: tls.private_key.exists
    on_unknown: BLOCK
  - id: filesystem.disk_io
    on_unknown: IGNORE

human_approval: false
"""


def test_load_policy_parses_all_fields():
    policy = load_policy_from_string(SAMPLE_POLICY)
    assert policy.version == "1"
    assert policy.action == "restart_nginx"
    assert policy.risk == RiskLevel.LOW
    assert policy.human_approval is False
    assert len(policy.required_evidence) == 4


def test_load_policy_preserves_on_unknown_per_item():
    policy = load_policy_from_string(SAMPLE_POLICY)
    cert = policy.requirement_for("tls.certificate.exists")
    disk = policy.requirement_for("filesystem.disk_io")
    assert cert.on_unknown == OnUnknown.BLOCK
    assert disk.on_unknown == OnUnknown.IGNORE


def test_load_policy_default_on_unknown_is_block_when_omitted():
    text = """
version: "1"
action: restart_nginx
risk: LOW
required_evidence:
  - id: nginx.config.valid
human_approval: false
"""
    policy = load_policy_from_string(text)
    req = policy.requirement_for("nginx.config.valid")
    assert req.on_unknown == OnUnknown.BLOCK


def test_load_policy_supports_max_age():
    text = """
version: "1"
action: restart_nginx
risk: LOW
required_evidence:
  - id: nginx.config.valid
    on_unknown: BLOCK
    max_age: 30
human_approval: false
"""
    policy = load_policy_from_string(text)
    req = policy.requirement_for("nginx.config.valid")
    assert req.max_age == 30
