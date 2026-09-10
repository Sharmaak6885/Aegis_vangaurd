"""
SSL/TLS Analyzer
Tests SSL/TLS configuration of target domains for security weaknesses.
"""

import ssl
import socket
import datetime
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_target_hosts
)


def analyze_ssl(hostname: str, port: int = 443) -> list[Finding]:
    """Analyze SSL/TLS configuration of a host."""
    findings = []
    print(f"\n  Analyzing SSL/TLS: {hostname}:{port}")

    try:
        # Create SSL context
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=hostname,
        )
        conn.settimeout(10)
        conn.connect((hostname, port))

        # Get certificate info
        cert = conn.getpeercert()
        cipher = conn.cipher()
        protocol = conn.version()

        print(f"  Protocol: {protocol}")
        print(f"  Cipher: {cipher[0] if cipher else 'Unknown'}")
        print(f"  Key bits: {cipher[2] if cipher else 'Unknown'}")

        # Check certificate expiry
        if cert:
            not_after = cert.get("notAfter", "")
            if not_after:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                print(f"  Certificate expires: {not_after} ({days_left} days)")

                if days_left < 0:
                    findings.append(Finding(
                        title=f"SSL certificate expired on {hostname}",
                        category="SSL/TLS",
                        severity=Severity.CRITICAL,
                        description="The SSL certificate has expired, causing browser security warnings and potential man-in-the-middle vulnerabilities",
                        evidence=f"Certificate expired: {not_after}",
                        impact="Users will see security warnings, and MITM attacks become feasible",
                        remediation="Renew the SSL certificate immediately",
                        cwe="CWE-295",
                        owasp="A02:2021 Cryptographic Failures",
                        url=f"https://{hostname}",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        title=f"SSL certificate expiring soon on {hostname}",
                        category="SSL/TLS",
                        severity=Severity.MEDIUM,
                        description=f"The SSL certificate will expire in {days_left} days",
                        evidence=f"Certificate expires: {not_after} ({days_left} days remaining)",
                        impact="Service disruption if the certificate is not renewed before expiry",
                        remediation="Renew the SSL certificate. Consider using auto-renewal with Let's Encrypt or similar CA.",
                        cwe="CWE-295",
                        owasp="A02:2021 Cryptographic Failures",
                        url=f"https://{hostname}",
                    ))
                else:
                    print(f"  [OK] Certificate valid for {days_left} days")

            # Check subject
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            print(f"  Subject: {subject.get('commonName', 'N/A')}")
            print(f"  Issuer: {issuer.get('organizationName', 'N/A')}")

            # Check SAN
            san = cert.get("subjectAltName", [])
            san_domains = [name for type_, name in san if type_ == "DNS"]
            print(f"  SANs: {', '.join(san_domains[:5])}")

        # Check protocol version
        if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            findings.append(Finding(
                title=f"Deprecated TLS protocol in use on {hostname}",
                category="SSL/TLS",
                severity=Severity.HIGH,
                description=f"The server negotiated {protocol}, which is deprecated and vulnerable to known attacks",
                evidence=f"Negotiated protocol: {protocol}",
                impact="Known attacks like POODLE, BEAST, and CRIME can be used against deprecated protocols",
                remediation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Only support TLS 1.2 and TLS 1.3.",
                cwe="CWE-327",
                owasp="A02:2021 Cryptographic Failures",
                url=f"https://{hostname}",
            ))
        else:
            print(f"  [OK] Protocol {protocol} is current")

        # Check cipher strength
        if cipher and cipher[2] < 128:
            findings.append(Finding(
                title=f"Weak cipher suite on {hostname}",
                category="SSL/TLS",
                severity=Severity.MEDIUM,
                description=f"The negotiated cipher suite uses {cipher[2]}-bit keys, which is below the recommended minimum of 128 bits",
                evidence=f"Cipher: {cipher[0]}, Key bits: {cipher[2]}",
                impact="Weak encryption can be brute-forced by motivated attackers",
                remediation="Configure the server to prefer cipher suites with 128-bit or higher keys",
                cwe="CWE-326",
                owasp="A02:2021 Cryptographic Failures",
                url=f"https://{hostname}",
            ))
        else:
            print(f"  [OK] Cipher strength adequate ({cipher[2]} bits)" if cipher else "")

        conn.close()

    except ssl.SSLError as e:
        print(f"  [SSL ERROR] {e}")
        findings.append(Finding(
            title=f"SSL/TLS error on {hostname}",
            category="SSL/TLS",
            severity=Severity.HIGH,
            description=f"SSL/TLS connection error: {str(e)}",
            evidence=f"Error: {str(e)}",
            impact="SSL misconfiguration may prevent secure connections or enable MITM attacks",
            remediation="Review and fix the SSL/TLS configuration",
            cwe="CWE-295",
            owasp="A02:2021 Cryptographic Failures",
            url=f"https://{hostname}",
        ))
    except socket.timeout:
        print(f"  [TIMEOUT] Connection to {hostname}:{port} timed out")
    except Exception as e:
        print(f"  [ERROR] {e}")

    # Test HTTP to HTTPS redirect
    print(f"\n  Testing HTTP→HTTPS redirect for {hostname}...")
    http_url = f"http://{hostname}"
    resp = safe_request(http_url, allow_redirects=False, timeout=10)
    if resp:
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if location.startswith("https://"):
                print(f"  [OK] HTTP redirects to HTTPS: {location[:60]}")
                if resp.status_code != 301:
                    findings.append(Finding(
                        title=f"HTTP to HTTPS redirect uses {resp.status_code} instead of 301 on {hostname}",
                        category="SSL/TLS",
                        severity=Severity.INFO,
                        description=f"HTTP to HTTPS redirect uses status code {resp.status_code}. A 301 (Permanent Redirect) is preferred for SEO and browser caching.",
                        evidence=f"http://{hostname} → {resp.status_code} → {location}",
                        impact="Temporary redirects may not be cached by browsers, causing unnecessary HTTP requests",
                        remediation="Use 301 (Moved Permanently) for HTTP to HTTPS redirects",
                        cwe="CWE-319",
                        owasp="A02:2021 Cryptographic Failures",
                        url=http_url,
                    ))
            else:
                findings.append(Finding(
                    title=f"HTTP redirect does not point to HTTPS on {hostname}",
                    category="SSL/TLS",
                    severity=Severity.HIGH,
                    description=f"HTTP redirects to {location} instead of HTTPS, leaving traffic vulnerable to interception",
                    evidence=f"http://{hostname} → {resp.status_code} → {location}",
                    impact="Users accessing the site via HTTP are not redirected to HTTPS, exposing traffic to MITM attacks",
                    remediation="Configure HTTP to redirect to the HTTPS equivalent URL",
                    cwe="CWE-319",
                    owasp="A02:2021 Cryptographic Failures",
                    url=http_url,
                ))
        elif resp.status_code == 200:
            findings.append(Finding(
                title=f"HTTP accessible without redirect to HTTPS on {hostname}",
                category="SSL/TLS",
                severity=Severity.MEDIUM,
                description="The site is accessible over plain HTTP without redirecting to HTTPS",
                evidence=f"http://{hostname} → 200 OK (no redirect to HTTPS)",
                impact="Users who access the site via HTTP will have their traffic sent unencrypted",
                remediation="Add a redirect from HTTP to HTTPS. Enable HSTS header.",
                cwe="CWE-319",
                owasp="A02:2021 Cryptographic Failures",
                url=http_url,
            ))

    return findings


def run() -> list[Finding]:
    """Run SSL/TLS analysis on all target hosts."""
    print_banner("SSL/TLS ANALYSIS")
    all_findings = []

    hosts = get_target_hosts()

    for host in hosts:
        findings = analyze_ssl(host)
        all_findings.extend(findings)

    print(f"\n  Total SSL/TLS findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
