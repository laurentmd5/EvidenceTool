from __future__ import annotations

from unittest.mock import MagicMock, patch

from evidencetool.providers._shell import run_command


def test_local_command_execution():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "hello\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = run_command(["echo", "hello"])

        assert result.ran is True
        assert result.returncode == 0
        assert result.stdout == "hello"
        mock_run.assert_called_once_with(["echo", "hello"], capture_output=True, text=True, timeout=5.0)


def test_ssh_transport_execution():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "hello\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = run_command(["echo", "hello"], host="prod-web-01")

        assert result.ran is True
        assert result.returncode == 0
        assert result.stdout == "hello"

        args = mock_run.call_args[0][0]
        assert args[0] == "ssh"
        assert "prod-web-01" in args
        assert "--" in args
        assert "-o" in args
        assert "BatchMode=yes" in args
        assert "ControlMaster=auto" in args
        assert "StrictHostKeyChecking=yes" in args
        assert "echo" in args
        assert "hello" in args


def test_ssh_transport_error_classification():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        # SSH client exits with 255 on transport errors (e.g. connection refused)
        mock_proc.returncode = 255
        mock_proc.stdout = ""
        mock_proc.stderr = "ssh: connect to host prod-web-01 port 22: Connection refused"
        mock_run.return_value = mock_proc

        result = run_command(["echo", "hello"], host="prod-web-01")

        # Crucial: ran should be False, to trigger UNKNOWN rather than FAIL
        assert result.ran is False
        assert result.returncode == 255
        assert "Connection refused" in result.error
        assert "SSH Transport Error:" in result.error


def test_ssh_business_error_classification():
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        # Remote command exits with 1 (business failure)
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "command failed"
        mock_run.return_value = mock_proc

        result = run_command(["some_cmd"], host="prod-web-01")

        # Crucial: ran should be True because transport worked, command just failed
        assert result.ran is True
        assert result.returncode == 1
