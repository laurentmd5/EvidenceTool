"""
EvidenceTool CLI — Section 9 of PRODUCT_CONTRACT.md.

    evidencetool diagnose nginx
    evidencetool diagnose nginx --output json
    evidencetool diagnose nginx --policy policies/nginx.yaml
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from evidencetool.cli.render import to_json, to_text
from evidencetool.diagnose import diagnose_nginx
from evidencetool.models.decision import DecisionStatus
from evidencetool.policy.loader import load_policy

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "policies" / "nginx.yaml"


@click.group()
def cli():
    """EvidenceTool — evidence before action."""


@cli.command()
@click.argument("target", type=click.Choice(["nginx"]))
@click.option(
    "--output",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--policy",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a policy YAML file. Defaults to the bundled nginx policy.",
)
@click.option("--service", default="nginx", help="systemd service name to inspect.")
@click.option("--config-path", default=None, help="Path to nginx.conf.")
@click.option("--certificate-path", default=None, help="Path to the TLS certificate.")
@click.option("--private-key-path", default=None, help="Path to the TLS private key.")
@click.option("--metrics-file", default=None, help="Path to write Prometheus textfile metrics (e.g. ./evidencetool.prom)")
def diagnose(
    target: str,
    output: str,
    policy_path: str | None,
    service: str,
    config_path: str | None,
    certificate_path: str | None,
    private_key_path: str | None,
    metrics_file: str | None,
):
    """Diagnose an incident for TARGET (currently only 'nginx' is supported)."""
    policy = load_policy(policy_path or DEFAULT_POLICY_PATH)

    kwargs = {"service": service}
    if config_path:
        kwargs["config_path"] = config_path
    if certificate_path:
        kwargs["certificate_path"] = certificate_path
    if private_key_path:
        kwargs["private_key_path"] = private_key_path

    result = diagnose_nginx(policy, **kwargs)
    
    if metrics_file:
        from evidencetool.observability.metrics import write_metrics
        write_metrics(result.metrics, metrics_file)

    if output == "json":
        click.echo(to_json(result))
    else:
        click.echo(to_text(result))

    # If there was an integrity violation, always exit with non-zero code (e.g., 3).
    if not result.metrics.success:
        sys.exit(3)

    # Exit code reflects the decision, useful for scripting/CI:
    # 0 = ALLOW, 1 = BLOCK, 2 = HUMAN_REVIEW
    exit_codes = {
        DecisionStatus.ALLOW: 0,
        DecisionStatus.BLOCK: 1,
        DecisionStatus.HUMAN_REVIEW: 2,
    }
    sys.exit(exit_codes[result.decision.status])


if __name__ == "__main__":
    cli()
