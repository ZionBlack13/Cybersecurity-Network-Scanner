
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(hosts, ports, vulnerabilities):
    report = {
        "project": "Cybersecurity Network Scanner",
        "scan_date": datetime.now(
            timezone.utc
        ).isoformat(),
        "summary": {
            "total_hosts": len(hosts),
            "total_ports": len(ports),
            "potential_cve_matches": len(vulnerabilities)
        },
        "hosts": hosts,
        "ports": ports,
        "vulnerabilities": vulnerabilities
    }

    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    filename = (
        "security_report_"
        + datetime.now(timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        + ".json"
    )

    filepath = report_dir / filename

    with open(filepath, "w") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved: {filepath}")
    return str(filepath)


if __name__ == "__main__":
    sample_hosts = ["127.0.0.1"]

    sample_ports = [
        {
            "host": "127.0.0.1",
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "9.0"
        }
    ]

    sample_vulnerabilities = []

    generate_report(
        sample_hosts,
        sample_ports,
        sample_vulnerabilities
    )
