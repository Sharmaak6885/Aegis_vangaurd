"""
TCP Port Scanner Module
Non-intrusive TCP connect scanner that checks common service ports
and performs banner grabbing on open ports.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import (
    Finding, Severity, print_banner, print_finding,
    get_target_hosts, resolve_hostname, print_progress
)

# Common ports and their services
COMMON_PORTS = {
    21: ("FTP", "File Transfer Protocol — may allow anonymous access"),
    22: ("SSH", "Secure Shell — remote access service"),
    23: ("Telnet", "Unencrypted remote access — should never be open"),
    25: ("SMTP", "Mail server — can be used for email enumeration"),
    53: ("DNS", "Domain Name Service"),
    80: ("HTTP", "Web server (unencrypted)"),
    110: ("POP3", "Mail retrieval protocol"),
    111: ("RPCBind", "RPC port mapper — internal service exposure"),
    135: ("MSRPC", "Microsoft RPC — Windows service exposure"),
    139: ("NetBIOS", "Windows networking — file share exposure"),
    143: ("IMAP", "Mail access protocol"),
    443: ("HTTPS", "Web server (encrypted)"),
    445: ("SMB", "Windows file sharing — high-value target"),
    993: ("IMAPS", "Encrypted mail access"),
    995: ("POP3S", "Encrypted mail retrieval"),
    1433: ("MSSQL", "Microsoft SQL Server — database exposure"),
    1521: ("Oracle", "Oracle Database — database exposure"),
    2049: ("NFS", "Network File System — file share exposure"),
    3306: ("MySQL", "MySQL Database — critical if exposed"),
    3389: ("RDP", "Remote Desktop — high-value target"),
    5432: ("PostgreSQL", "PostgreSQL Database — critical if exposed"),
    5900: ("VNC", "Virtual Network Computing — remote desktop"),
    6379: ("Redis", "Redis cache/database — often unauthenticated"),
    8080: ("HTTP-Alt", "Alternative HTTP — often admin or proxy"),
    8443: ("HTTPS-Alt", "Alternative HTTPS — often admin panel"),
    8888: ("HTTP-Alt2", "Alternative HTTP — Jupyter/admin"),
    9090: ("Prometheus", "Monitoring service"),
    9200: ("Elasticsearch", "Search engine — data exposure"),
    9300: ("Elasticsearch-T", "Elasticsearch transport — internal"),
    11211: ("Memcached", "Cache service — amplification risk"),
    27017: ("MongoDB", "MongoDB — critical if exposed"),
    27018: ("MongoDB-Alt", "MongoDB secondary"),
}

# Ports that are EXPECTED to be open on web servers
EXPECTED_PORTS = {80, 443}

# Ports that are HIGH RISK if exposed
HIGH_RISK_PORTS = {21, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
MEDIUM_RISK_PORTS = {22, 25, 111, 135, 139, 2049, 8080, 8443, 8888, 9090, 11211}


def scan_port(host: str, port: int, timeout: float = 3.0) -> dict | None:
    """Scan a single port on a host. Returns port info if open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            banner = ""
            try:
                if port not in (80, 443):
                    sock.send(b"\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
            except Exception:
                pass

            sock.close()
            service_name, service_desc = COMMON_PORTS.get(port, ("Unknown", "Unknown service"))
            return {
                "port": port,
                "state": "open",
                "service": service_name,
                "description": service_desc,
                "banner": banner,
            }
        sock.close()
        return None
    except Exception:
        return None


def run() -> list[Finding]:
    """Run port scan on all target hosts."""
    print_banner("TCP PORT SCANNER")
    all_findings = []

    for host in get_target_hosts():
        print(f"\n  === Port Scan: {host} ===")

        # Resolve to IP
        ips = resolve_hostname(host)
        if not ips:
            print(f"  [ERROR] Cannot resolve {host}")
            continue

        target_ip = ips[0]
        print(f"  Resolved: {host} → {target_ip}")
        print(f"  Scanning {len(COMMON_PORTS)} common ports...\n")

        # Scan all ports in parallel
        open_ports = []
        total = len(COMMON_PORTS)

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {
                executor.submit(scan_port, target_ip, port): port
                for port in COMMON_PORTS.keys()
            }

            done_count = 0
            for future in as_completed(futures):
                done_count += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    port = result["port"]
                    service = result["service"]
                    banner = result["banner"][:60] if result["banner"] else ""
                    print(f"  [OPEN] {port:>5}/tcp  {service:<15} {banner}")
                if done_count % 10 == 0:
                    print_progress(done_count, total, f"({len(open_ports)} open)")

        print_progress(total, total, f"({len(open_ports)} open)")

        if not open_ports:
            print("  No open ports found (host may be filtered by firewall)")
            all_findings.append(Finding(
                title=f"No open ports detected on {host} (heavily filtered)",
                category="Port Scanning",
                severity=Severity.INFO,
                description=f"TCP port scan of {len(COMMON_PORTS)} common ports on {host} found no open ports. The host may be behind a firewall that drops all unsolicited connections.",
                evidence=f"Scanned {len(COMMON_PORTS)} ports on {target_ip}: all filtered/closed",
                impact="Strong firewall posture — no unexpected services exposed",
                remediation="No action needed — continue monitoring",
                cwe="CWE-200",
                owasp="A05:2021 Security Misconfiguration",
                url=f"https://{host}",
            ))
            continue

        # Generate findings for open ports
        open_ports.sort(key=lambda x: x["port"])

        # High-risk ports
        for port_info in open_ports:
            port = port_info["port"]
            if port in HIGH_RISK_PORTS:
                finding = Finding(
                    title=f"High-risk port {port}/tcp ({port_info['service']}) open on {host}",
                    category="Port Scanning",
                    severity=Severity.HIGH,
                    description=f"Port {port}/tcp ({port_info['service']}) is open on {host}. {port_info['description']}. "
                                f"This service should not be directly exposed to the internet.",
                    evidence=f"Host: {target_ip}\nPort: {port}/tcp (OPEN)\nService: {port_info['service']}"
                             + (f"\nBanner: {port_info['banner']}" if port_info["banner"] else ""),
                    impact=f"Exposed {port_info['service']} service can be targeted for brute-force, exploitation, or data extraction",
                    remediation=f"Restrict {port_info['service']} access via firewall rules, VPN, or security groups. Never expose database or remote-access ports to the internet.",
                    cwe="CWE-284",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"tcp://{host}:{port}",
                )
                all_findings.append(finding)
                print_finding(finding)

            elif port in MEDIUM_RISK_PORTS:
                finding = Finding(
                    title=f"Service port {port}/tcp ({port_info['service']}) open on {host}",
                    category="Port Scanning",
                    severity=Severity.MEDIUM,
                    description=f"Port {port}/tcp ({port_info['service']}) is open. {port_info['description']}",
                    evidence=f"Host: {target_ip}\nPort: {port}/tcp (OPEN)\nService: {port_info['service']}"
                             + (f"\nBanner: {port_info['banner']}" if port_info["banner"] else ""),
                    impact=f"Exposed {port_info['service']} increases the attack surface",
                    remediation=f"Evaluate if {port_info['service']} needs to be publicly accessible. Consider IP-based access restrictions.",
                    cwe="CWE-284",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"tcp://{host}:{port}",
                )
                all_findings.append(finding)
                print_finding(finding)

            elif port not in EXPECTED_PORTS:
                finding = Finding(
                    title=f"Unexpected port {port}/tcp ({port_info['service']}) open on {host}",
                    category="Port Scanning",
                    severity=Severity.LOW,
                    description=f"Port {port}/tcp ({port_info['service']}) is open but not typically expected on a web application server.",
                    evidence=f"Host: {target_ip}\nPort: {port}/tcp (OPEN)\nService: {port_info['service']}"
                             + (f"\nBanner: {port_info['banner']}" if port_info["banner"] else ""),
                    impact="Unexpected services may have unpatched vulnerabilities",
                    remediation="Review if this service is needed. Close unnecessary ports via firewall.",
                    cwe="CWE-284",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"tcp://{host}:{port}",
                )
                all_findings.append(finding)
                print_finding(finding)

        # Summary finding
        all_findings.append(Finding(
            title=f"Port scan summary: {len(open_ports)} open ports on {host}",
            category="Port Scanning",
            severity=Severity.INFO,
            description=f"TCP port scan of {host} ({target_ip}) found {len(open_ports)} open ports out of {len(COMMON_PORTS)} tested.",
            evidence="Open ports:\n" + "\n".join(
                f"  {p['port']:>5}/tcp  {p['service']:<15} {p['banner'][:40] if p['banner'] else ''}"
                for p in open_ports
            ),
            impact="Each open port is a potential entry point for attackers",
            remediation="Close all unnecessary ports. Implement network segmentation and firewall rules.",
            cwe="CWE-284",
            owasp="A05:2021 Security Misconfiguration",
            url=f"https://{host}",
        ))

    print(f"\n  Total port scan findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
