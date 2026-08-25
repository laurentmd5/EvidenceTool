"""
Unit tests for MySQL Provider.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from evidencetool.providers.base import ProviderContext
from evidencetool.providers.mysql import MySQLProvider
from evidencetool.providers.registry import get_provider


def test_mysql_provider_registration():
    p = get_provider("mysql")
    assert isinstance(p, MySQLProvider)


def test_mysql_unreachable():
    p = MySQLProvider()
    with patch("evidencetool.providers.mysql.socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "3306"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["mysql.reachable"].value["status"] == "FAIL"
    assert obs_map["mysql.reachable"].value["failure"] == "CONNECTION_REFUSED"


def test_mysql_handshake_success():
    p = MySQLProvider()

    # MySQL Handshake Packet:
    # 4 bytes header: len=45, seq=0
    # Payload: protocol=10, server="8.0.33\x00", connection_id=...
    server_ver = b"8.0.33\x00"
    payload = b"\x0a" + server_ver + b"\x01\x00\x00\x00"
    header = len(payload).to_bytes(3, "little") + b"\x00"

    mock_sock = Mock()
    mock_sock.recv.side_effect = [header, payload]

    class MockSocketCM:
        def close(self):
            pass
        def __enter__(self):
            return mock_sock
        def __exit__(self, *args):
            pass

    with patch("evidencetool.providers.mysql.socket.create_connection", return_value=MockSocketCM()):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "3306"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["mysql.reachable"].value["status"] == "PASS"
    assert obs_map["mysql.ping"].value["status"] == "PASS"
    assert obs_map["mysql.ping"].value["server_version"] == "8.0.33"
    assert obs_map["mysql.max_connections"].value["status"] == "PASS"


def test_mysql_too_many_connections_error():
    p = MySQLProvider()

    # Error packet for 1040 (0x0410)
    err_code = (1040).to_bytes(2, "little")
    payload = b"\xff" + err_code + b"#08004Too many connections"
    header = len(payload).to_bytes(3, "little") + b"\x00"

    mock_sock = Mock()
    mock_sock.recv.side_effect = [header, payload]

    class MockSocketCM:
        def close(self):
            pass
        def __enter__(self):
            return mock_sock
        def __exit__(self, *args):
            pass

    with patch("evidencetool.providers.mysql.socket.create_connection", return_value=MockSocketCM()):
        obs = p.collect(ProviderContext({"target_host": "127.0.0.1", "port": "3306"}))

    obs_map = {o.id: o for o in obs}
    assert obs_map["mysql.ping"].value["status"] == "FAIL"
    assert obs_map["mysql.max_connections"].value["status"] == "FAIL"
    assert obs_map["mysql.max_connections"].value["failure"] == "TOO_MANY_CONNECTIONS"
