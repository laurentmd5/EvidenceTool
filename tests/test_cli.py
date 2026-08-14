import pytest
from click.testing import CliRunner
from evidencetool.cli.main import cli
from pathlib import Path


def test_cli_host_validation_rejections():
    runner = CliRunner()
    
    invalid_hosts = [
        "-oProxyCommand=calc",
        "foo; whoami",
        "$(whoami)",
        "`whoami`",
        "user@host -p 2222",
    ]
    
    for host in invalid_hosts:
        result = runner.invoke(cli, ["diagnose", "nginx", "--host", host])
        assert result.exit_code != 0
        assert "Error: " in result.output


def test_cli_host_validation_acceptances():
    runner = CliRunner()
    
    # We just need it to get past the host validation and fail on missing policy or something else,
    # or we can mock diagnose to return a dummy result.
    # We will just verify it doesn't fail with the host validation error.
    valid_hosts = [
        "prod-web-01",
        "user@192.168.1.10",
        "user@example.com",
        "[2001:db8::1]",
        "user@[2001:db8::1]",
    ]
    
    with pytest.MonkeyPatch.context() as m:
        m.setattr("evidencetool.cli.main.diagnose", lambda *args, **kwargs: type("MockResult", (), {"metrics": type("Metrics", (), {"success": True}), "decision": type("Decision", (), {"status": 0})})())
        m.setattr("evidencetool.cli.main.load_policy", lambda *args, **kwargs: None)
        
        # mock path exists to bypass policy check
        m.setattr(Path, "exists", lambda self: True)
        
        for host in valid_hosts:
            result = runner.invoke(cli, ["diagnose", "nginx", "--host", host])
            # Should not hit the validation error
            assert "Invalid host format" not in result.output
            assert "Host cannot start with a hyphen" not in result.output
