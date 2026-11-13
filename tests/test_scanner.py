
from unittest.mock import MagicMock, patch

from scanner.host_discovery import discover_hosts
from scanner.port_scanner import scan_ports
from scanner.vulnerability_lookup import lookup_vulnerabilities


def test_host_discovery():
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = ["127.0.0.1"]
    mock_scanner.__getitem__.return_value.state.return_value = "up"

    with patch(
        "scanner.host_discovery.nmap.PortScanner",
        return_value=mock_scanner
    ):
        hosts = discover_hosts("127.0.0.1/32")

    assert hosts == ["127.0.0.1"]


def test_port_scanner():
    mock_scanner = MagicMock()
    mock_scanner.all_hosts.return_value = ["127.0.0.1"]

    mock_host = MagicMock()
    mock_host.all_protocols.return_value = ["tcp"]
    mock_host.__getitem__.return_value = {
        8000: {
            "state": "open",
            "name": "http",
            "version": "0.6"
        }
    }

    mock_scanner.__getitem__.return_value = mock_host

    with patch(
        "scanner.port_scanner.nmap.PortScanner",
        return_value=mock_scanner
    ):
        results = scan_ports("127.0.0.1", "8000")

    assert len(results) == 1
    assert results[0]["port"] == 8000
    assert results[0]["state"] == "open"
    assert results[0]["service"] == "http"


def test_vulnerability_lookup():
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-12345",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Example test vulnerability"
                        }
                    ]
                }
            }
        ]
    }

    with patch(
        "scanner.vulnerability_lookup.requests.get",
        return_value=mock_response
    ):
        results = lookup_vulnerabilities("TestService", "1.0")

    assert len(results) == 1
    assert results[0]["id"] == "CVE-2026-12345"
    assert results[0]["match_type"] == "unverified_keyword_match"
    assert results[0]["search_term"] == "TestService 1.0"
