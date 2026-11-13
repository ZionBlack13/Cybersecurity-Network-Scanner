from scanner.html_report import generate_html_report
import argparse
import ipaddress
from scanner.host_discovery import discover_hosts
from scanner.port_scanner import scan_ports
from scanner.vulnerability_lookup import lookup_vulnerabilities
from scanner.report_generator import generate_report
    
def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Network Scanner"
    )

    parser.add_argument(
        "--target",
        default="127.0.0.1/32",
        help="Authorized IP address or network to scan"
    )

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range to scan"
    )

    args = parser.parse_args()

    try:
        ipaddress.ip_network(args.target, strict=False)
    except ValueError:
        parser.error(
            f"Invalid IP address or network: {args.target}"
        )


    print("=" * 50)
    print("CYBERSECURITY NETWORK SCANNER")
    print("=" * 50)

    print("\n[1] Discovering hosts...")
    hosts = discover_hosts(args.target)

    print("\n[2] Scanning ports...")
    ports = []
    for host in hosts:
        ports.extend(scan_ports(host, args.ports))

    print("\n[3] Checking potential vulnerabilities...")
    vulnerabilities = []

    for port in ports:
        if port["state"] != "open":
            continue

        service = port.get("service", "")
        version = port.get("version", "")

        if not service or not version:
            continue

        matches = lookup_vulnerabilities(service, version)

        for match in matches:
            match["host"] = port["host"]
            match["port"] = port["port"]
            vulnerabilities.append(match)

    
    print("\n[4] Generating security report...")

    report_path = generate_report(
        hosts, ports, vulnerabilities
    )

    html_path = generate_html_report(
        hosts, ports, vulnerabilities
    )

    print("\nScan completed!")
    print(f"JSON Report: {report_path}")
    print(f"HTML Report: {html_path}")


if __name__ == "__main__":
    main()
