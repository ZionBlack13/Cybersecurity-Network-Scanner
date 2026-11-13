
import nmap


def scan_ports(target="127.0.0.1", ports="1-1024"):
    scanner = nmap.PortScanner()

    print(f"\nScanning ports on {target}...")

    scanner.scan(
        hosts=target,
        ports=ports,
        arguments="-sT -sV"
    )

    results = []

    for host in scanner.all_hosts():
        print(f"\nHost: {host}")

        for protocol in scanner[host].all_protocols():
            for port in sorted(scanner[host][protocol]):
                service = scanner[host][protocol][port]

                result = {
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "state": service["state"],
                    "service": service.get("name", "unknown"),
                    "version": service.get("version", "")
                }

                results.append(result)

                if result["state"] == "open":
                    print(
                        f"[+] Port {port}/{protocol} OPEN "
                        f"| Service: {result['service']} "
                        f"| Version: {result['version']}"
                    )

    print("\nPort scan completed.")

    return results


if __name__ == "__main__":
    scan_ports()
