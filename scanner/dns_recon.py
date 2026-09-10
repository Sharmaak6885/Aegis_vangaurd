"""
DNS Reconnaissance Module
Enumerates DNS records, checks SPF/DKIM/DMARC, attempts zone transfers,
and discovers subdomains via Certificate Transparency logs.
"""

import re
import json
import socket
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_hosts, get_target_base, resolve_hostname
)


def query_ct_logs(domain: str) -> list[str]:
    """Query Certificate Transparency logs via crt.sh for subdomains."""
    subdomains = set()
    try:
        resp = safe_request(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20,
        )
        if resp and resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{domain}") or line == domain:
                        if "*" not in line:
                            subdomains.add(line)
    except Exception as e:
        print(f"  [ERROR] crt.sh query failed: {e}")
    return sorted(subdomains)


def get_dns_records(domain: str) -> dict:
    """Get DNS records using dnspython if available, fallback to socket."""
    records = {}

    # Try dnspython first
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass

        return records
    except ImportError:
        pass

    # Fallback: socket-based resolution
    try:
        ips = resolve_hostname(domain)
        if ips:
            records["A"] = ips
    except Exception:
        pass

    return records


def check_zone_transfer(domain: str, nameservers: list[str]) -> list[Finding]:
    """Attempt DNS zone transfer (AXFR) against nameservers."""
    findings = []

    try:
        import dns.query
        import dns.zone

        for ns in nameservers[:5]:
            ns_clean = ns.rstrip(".")
            try:
                ns_ip = resolve_hostname(ns_clean)
                if not ns_ip:
                    continue
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip[0], domain, timeout=5))
                if zone:
                    names = [str(n) for n in zone.nodes.keys()][:20]
                    finding = Finding(
                        title=f"DNS Zone Transfer (AXFR) allowed on {ns_clean}",
                        category="DNS Security",
                        severity=Severity.CRITICAL,
                        description=f"The nameserver {ns_clean} allows unauthenticated zone transfers (AXFR). "
                                    f"This exposes the entire DNS zone, revealing all subdomains, internal hostnames, and network architecture.",
                        evidence=f"Nameserver: {ns_clean}\nZone records exposed: {len(names)}\nSample: {', '.join(names[:10])}",
                        impact="Complete enumeration of all DNS records including internal hostnames, mail servers, and potentially sensitive subdomains",
                        remediation="Restrict AXFR to authorized secondary nameservers only. Configure ACLs on the DNS server to deny zone transfers to unauthorized IPs.",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                        url=f"dns://{ns_clean}",
                    )
                    findings.append(finding)
                    print_finding(finding)
            except Exception:
                print(f"    AXFR blocked on {ns_clean} [OK]")

    except ImportError:
        print("  [SKIP] dnspython not installed — zone transfer test skipped")

    return findings


def check_email_security(domain: str, txt_records: list[str]) -> list[Finding]:
    """Check SPF, DKIM, and DMARC records."""
    findings = []

    # Check SPF
    spf_found = False
    for txt in txt_records:
        if "v=spf1" in txt.lower():
            spf_found = True
            print(f"  [OK] SPF record found: {txt[:80]}")
            # Check for overly permissive SPF
            if "+all" in txt.lower():
                findings.append(Finding(
                    title="SPF record uses +all (allows any sender)",
                    category="DNS Security",
                    severity=Severity.HIGH,
                    description="The SPF record ends with +all, which allows any server to send email for this domain. This makes the domain vulnerable to email spoofing.",
                    evidence=f"SPF: {txt}",
                    impact="Attackers can spoof emails from this domain, enabling phishing attacks",
                    remediation="Change +all to -all (hard fail) or ~all (soft fail) in the SPF record",
                    cwe="CWE-290",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"dns://{domain}/TXT",
                ))
            elif "~all" in txt.lower():
                findings.append(Finding(
                    title="SPF record uses ~all (soft fail — not enforced)",
                    category="DNS Security",
                    severity=Severity.LOW,
                    description="The SPF record uses ~all (soft fail). While emails from unauthorized senders will be flagged, they won't be rejected outright.",
                    evidence=f"SPF: {txt}",
                    impact="Spoofed emails may still be delivered to some recipients",
                    remediation="Consider changing ~all to -all for strict enforcement once all legitimate senders are listed",
                    cwe="CWE-290",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"dns://{domain}/TXT",
                ))
            break

    if not spf_found:
        findings.append(Finding(
            title=f"No SPF record found for {domain}",
            category="DNS Security",
            severity=Severity.MEDIUM,
            description="No SPF (Sender Policy Framework) record is configured. SPF prevents email spoofing by specifying which servers are authorized to send email for the domain.",
            evidence=f"No TXT record containing 'v=spf1' found for {domain}",
            impact="Attackers can send emails that appear to come from this domain",
            remediation="Add an SPF TXT record: v=spf1 include:<mail-provider> -all",
            cwe="CWE-290",
            owasp="A05:2021 Security Misconfiguration",
            url=f"dns://{domain}/TXT",
        ))

    # Check DMARC
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = get_dns_records(dmarc_domain)
    dmarc_txt = dmarc_records.get("TXT", [])

    dmarc_found = False
    for txt in dmarc_txt:
        if "v=dmarc1" in txt.lower():
            dmarc_found = True
            print(f"  [OK] DMARC record found: {txt[:80]}")
            if "p=none" in txt.lower():
                findings.append(Finding(
                    title=f"DMARC policy is set to 'none' (monitoring only)",
                    category="DNS Security",
                    severity=Severity.LOW,
                    description="DMARC policy is set to p=none, which only monitors but does not reject or quarantine spoofed emails.",
                    evidence=f"DMARC: {txt}",
                    impact="Email spoofing is monitored but not prevented",
                    remediation="Consider upgrading to p=quarantine or p=reject after reviewing DMARC reports",
                    cwe="CWE-290",
                    owasp="A05:2021 Security Misconfiguration",
                    url=f"dns://{dmarc_domain}/TXT",
                ))
            break

    if not dmarc_found:
        findings.append(Finding(
            title=f"No DMARC record found for {domain}",
            category="DNS Security",
            severity=Severity.MEDIUM,
            description="No DMARC record is configured. DMARC builds on SPF and DKIM to provide email authentication and reporting.",
            evidence=f"No TXT record containing 'v=dmarc1' found at _dmarc.{domain}",
            impact="No protection against email spoofing via domain alignment",
            remediation="Add a DMARC TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
            cwe="CWE-290",
            owasp="A05:2021 Security Misconfiguration",
            url=f"dns://{dmarc_domain}/TXT",
        ))

    return findings


def run() -> list[Finding]:
    """Run DNS reconnaissance on all target hosts."""
    print_banner("DNS RECONNAISSANCE")
    all_findings = []
    scanned_base_domains = set()

    for host in get_target_hosts():
        base_domain = ".".join(host.split(".")[-2:])  # e.g., archscale.in
        
        if base_domain in scanned_base_domains:
            print(f"\n  [SKIP] DNS Recon for {base_domain} already performed.")
            continue
        scanned_base_domains.add(base_domain)
        
        print(f"\n  === DNS Recon: {host} (base: {base_domain}) ===")

        # 1. Resolve IPs
        ips = resolve_hostname(host)
        print(f"  Resolved IPs: {', '.join(ips) if ips else 'none'}")

        # 2. Get DNS records
        print(f"\n  Fetching DNS records for {base_domain}...")
        records = get_dns_records(base_domain)
        for rtype, values in records.items():
            for val in values[:5]:
                print(f"    {rtype}: {val[:80]}")

        # 3. Check zone transfer
        ns_records = records.get("NS", [])
        if ns_records:
            print(f"\n  Testing zone transfer against {len(ns_records)} nameservers...")
            zt_findings = check_zone_transfer(base_domain, ns_records)
            all_findings.extend(zt_findings)
        else:
            print("  [SKIP] No NS records found for zone transfer test")

        # 4. Check email security
        txt_records = records.get("TXT", [])
        print(f"\n  Checking email security (SPF/DMARC)...")
        email_findings = check_email_security(base_domain, txt_records)
        all_findings.extend(email_findings)

        # 5. Certificate Transparency subdomain discovery
        print(f"\n  Querying Certificate Transparency logs for {base_domain}...")
        ct_subdomains = query_ct_logs(base_domain)
        if ct_subdomains:
            print(f"  Found {len(ct_subdomains)} subdomains via CT logs:")
            for sub in ct_subdomains[:20]:
                print(f"    • {sub}")

            finding = Finding(
                title=f"Certificate Transparency reveals {len(ct_subdomains)} subdomains for {base_domain}",
                category="DNS Reconnaissance",
                severity=Severity.INFO,
                description=f"Certificate Transparency logs reveal {len(ct_subdomains)} subdomains for {base_domain}. "
                            f"While CT logs are public by design, exposed subdomains increase the attack surface.",
                evidence=f"Subdomains found: {', '.join(ct_subdomains[:15])}{'...' if len(ct_subdomains) > 15 else ''}",
                impact="Each subdomain is a potential attack vector that may host vulnerable services",
                remediation="Audit all discovered subdomains. Ensure staging/dev/internal subdomains are not publicly accessible.",
                cwe="CWE-200",
                owasp="A05:2021 Security Misconfiguration",
                url=f"https://crt.sh/?q={base_domain}",
            )
            all_findings.append(finding)
            print_finding(finding)

    print(f"\n  Total DNS findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
