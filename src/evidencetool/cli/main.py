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

from evidencetool.capability.loader import load_capability_policy
from evidencetool.capability.models import ExecutionContext
from evidencetool.cli.render import to_json, to_text
from evidencetool.diagnose import diagnose
from evidencetool.models.decision import DecisionStatus
from evidencetool.models.policy import PolicySchema
from evidencetool.policy.loader import load_policy

RESERVED_CONTEXT_KEYS = {"host", "target_host", "domain", "port"}
DEFAULT_POLICY_DIR = Path(__file__).resolve().parents[3] / "policies"
DEFAULT_CATALOG_DIR = Path(__file__).resolve().parents[3] / "catalogs"


@click.group()
def cli() -> None:
    """EvidenceTool — evidence before action."""


@cli.command(name="diagnose")
@click.argument("target", type=str)
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
    help="Path to a policy YAML file. Defaults to policies/{target}.yaml.",
)
@click.option(
    "-a",
    "--arg",
    "args",
    multiple=True,
    help="Key-value pair to pass to providers (e.g. -a config_path=/etc/nginx/nginx.conf)",
)
@click.option(
    "--host",
    type=str,
    default=None,
    help="Target host to run remote diagnostics via SSH (e.g. prod-web-01).",
)
@click.option("--target-host", default=None, help="Network target host or address.")
@click.option("--port", type=int, default=None, help="Network target port (1-65535).")
@click.option("--capability-policy", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Path to an execution capability policy YAML file.")
@click.option(
    "--catalog",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a catalog YAML file containing situation signatures.",
)
@click.option("--metrics-file", default=None, help="Path to write Prometheus textfile metrics (e.g. ./evidencetool.prom)")
def diagnose_cmd(  # noqa: C901
    target: str,
    output: str,
    policy_path: str | None,
    args: tuple[str, ...],
    host: str | None,
    target_host: str | None,
    port: int | None,
    capability_policy: str | None,
    metrics_file: str | None,
    catalog: str | None,
) -> None:
    """Diagnose an incident for TARGET."""
    if not policy_path:
        policy_path = str(DEFAULT_POLICY_DIR / f"{target}.yaml")
        if not Path(policy_path).exists():
            click.echo(f"Error: Policy file {policy_path} not found. Please provide one with --policy.", err=True)
            sys.exit(1)

    policy = load_policy(policy_path)

    catalog_situations = None
    if not catalog and policy.schema == PolicySchema.V2_SITUATIONAL:
        default_catalog = DEFAULT_CATALOG_DIR / f"{target}.yaml"
        if default_catalog.exists():
            catalog = str(default_catalog)
        else:
            click.echo(
                f"Error: Catalog file {default_catalog} not found for V2 policy. "
                "Please provide one with --catalog.",
                err=True,
            )
            sys.exit(1)

    if catalog:
        from evidencetool.diagnostic.loader import load_catalog
        catalog_situations = load_catalog(catalog)

    context = {}
    if host:
        import re
        # Validate host format to prevent SSH command injection.
        # It must not start with a hyphen, and must consist only of alphanumeric, dot, hyphen, @, and brackets (for IPv6).
        if not re.match(r"^([a-zA-Z0-9_-]+@)?([a-zA-Z0-9_.-]+|\[[a-fA-F0-9:]+\])$", host):
            click.echo(f"Error: Invalid host format '{host}'.", err=True)
            sys.exit(1)
        if host.startswith("-"):
            click.echo("Error: Host cannot start with a hyphen.", err=True)
            sys.exit(1)

        context["host"] = host
    if target_host:
        context["target_host"] = target_host
    if port is not None:
        if not 1 <= port <= 65535:
            click.echo("Error: port must be an integer between 1 and 65535.", err=True)
            sys.exit(1)
        context["port"] = str(port)

    for arg in args:
        if "=" in arg:
            k, v = arg.split("=", 1)
            if k in RESERVED_CONTEXT_KEYS:
                click.echo(f"Error: '{k}' is reserved; use the dedicated CLI option.", err=True)
                sys.exit(1)
            context[k] = v
        else:
            click.echo(f"Warning: Ignoring malformed argument '{arg}' (expected key=value)", err=True)

    if "port" in context:
        try:
            port = int(context["port"])
        except ValueError:
            click.echo("Error: port must be an integer between 1 and 65535.", err=True)
            sys.exit(1)
        if not 1 <= port <= 65535:
            click.echo("Error: port must be an integer between 1 and 65535.", err=True)
            sys.exit(1)

    capabilities = load_capability_policy(capability_policy) if capability_policy else None
    execution = ExecutionContext(
        transport_host=host,
        capabilities=capabilities or ExecutionContext().capabilities,
    )
    result = diagnose(target, policy, context, catalog=catalog_situations, execution=execution)

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
