
import nmap

def discover_hosts(network="127.0.0.1/32"):
    scanner = nmap.PortScanner()

    print(f"Scanning network: {network}")

    scanner.scan(hosts=network, arguments="-sn")

    active_hosts = []

    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            print(f"[+] Active host found: {host}")
            active_hosts.append(host)

    print(f"\nTotal active hosts: {len(active_hosts)}")

    return active_hosts


if __name__ == "__main__":
    discover_hosts()


