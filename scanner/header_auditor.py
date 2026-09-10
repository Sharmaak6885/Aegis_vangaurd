"""
Security Headers Auditor
Tests HTTP security headers on target domains against best practices.
"""

from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)


# Expected security headers and their ideal values
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS",
        "severity": Severity.HIGH,
        "cwe": "CWE-319",
        "owasp": "A02:2021 Cryptographic Failures",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "check": lambda v: v is not None and "max-age" in v.lower(),
    },
    "Content-Security-Policy": {
        "description": "CSP prevents XSS, clickjacking, and other injection attacks",
        "severity": Severity.HIGH,
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "remediation": "Implement a strict Content-Security-Policy that restricts script-src, style-src, and default-src to trusted origins",
        "check": lambda v: v is not None,
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling framing of the page",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-1021",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed internally)",
        "check": lambda v: v is not None and v.upper() in ["DENY", "SAMEORIGIN"],
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks",
        "severity": Severity.LOW,
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "check": lambda v: v is not None and v.lower() == "nosniff",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still relevant for older browsers)",
        "severity": Severity.INFO,
        "cwe": "CWE-79",
        "owasp": "A03:2021 Injection",
        "remediation": "Add header: X-XSS-Protection: 0 (rely on CSP instead) or 1; mode=block for legacy support",
        "check": lambda v: v is not None,
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests",
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "owasp": "A01:2021 Broken Access Control",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "check": lambda v: v is not None,
    },
    "Permissions-Policy": {
        "description": "Controls which browser features the page can use (camera, mic, geolocation)",
        "severity": Severity.LOW,
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "check": lambda v: v is not None,
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Prevents Flash/PDF cross-domain data loading",
        "severity": Severity.INFO,
        "cwe": "CWE-16",
        "owasp": "A05:2021 Security Misconfiguration",
        "remediation": "Add header: X-Permitted-Cross-Domain-Policies: none",
        "check": lambda v: v is not None,
    },
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = {
    "Server": {
        "description": "Reveals server software and version — aids attacker reconnaissance",
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "remediation": "Remove or anonymize the Server header to reduce information disclosure",
    },
    "X-Powered-By": {
        "description": "Reveals framework/technology in use — aids targeted attacks",
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "remediation": "Remove the X-Powered-By header entirely",
    },
    "X-AspNet-Version": {
        "description": "Reveals ASP.NET version",
        "severity": Severity.LOW,
        "cwe": "CWE-200",
        "remediation": "Remove ASP.NET version headers",
    },
}


def audit_headers(url: str, label: str) -> list[Finding]:
    """Audit security headers for a given URL."""
    findings = []
    print(f"\n  Scanning: {url} ({label})")

    response = safe_request(url)
    if not response:
        print(f"  [SKIP] Could not reach {url}")
        return findings

    headers = response.headers
    print(f"  Status: {response.status_code}")
    print(f"  Headers received: {len(headers)}")

    # Check for missing security headers
    for header_name, config in SECURITY_HEADERS.items():
        value = headers.get(header_name)
        is_present = config["check"](value)

        if not is_present:
            finding = Finding(
                title=f"Missing {header_name} header on {label}",
                category="Security Headers",
                severity=config["severity"],
                description=config["description"],
                evidence=f"URL: {url}\nHeader '{header_name}' is {'present but misconfigured: ' + value if value else 'missing'}",
                impact=f"Without {header_name}, the application is vulnerable to attacks that this header mitigates",
                remediation=config["remediation"],
                cwe=config["cwe"],
                owasp=config.get("owasp", ""),
                url=url,
            )
            findings.append(finding)
            print_finding(finding)
        else:
            print(f"  [OK] {header_name}: {value[:80]}")

    # Check for information disclosure headers
    for header_name, config in DANGEROUS_HEADERS.items():
        value = headers.get(header_name)
        if value:
            finding = Finding(
                title=f"Information disclosure via {header_name} on {label}",
                category="Information Disclosure",
                severity=config["severity"],
                description=config["description"],
                evidence=f"URL: {url}\n{header_name}: {value}",
                impact="Attackers can use this information to identify specific vulnerabilities in the disclosed software version",
                remediation=config["remediation"],
                cwe=config["cwe"],
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)

    # Check cookie security
    for cookie_header in response.headers.get("Set-Cookie", "").split(","):
        if cookie_header.strip():
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0].strip()

            if "secure" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing Secure flag on {label}",
                    category="Session Security",
                    severity=Severity.MEDIUM,
                    description="Cookies without the Secure flag can be transmitted over unencrypted HTTP connections",
                    evidence=f"Set-Cookie: {cookie_header.strip()[:200]}",
                    impact="Session tokens could be intercepted in transit via man-in-the-middle attacks",
                    remediation="Add the Secure flag to all cookies containing sensitive data",
                    cwe="CWE-614",
                    owasp="A02:2021 Cryptographic Failures",
                    url=url,
                ))

            if "httponly" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing HttpOnly flag on {label}",
                    category="Session Security",
                    severity=Severity.MEDIUM,
                    description="Cookies without HttpOnly can be accessed by client-side JavaScript, enabling XSS-based session theft",
                    evidence=f"Set-Cookie: {cookie_header.strip()[:200]}",
                    impact="If XSS exists, attackers can steal session tokens via document.cookie",
                    remediation="Add the HttpOnly flag to all session and authentication cookies",
                    cwe="CWE-1004",
                    owasp="A03:2021 Injection",
                    url=url,
                ))

            if "samesite" not in cookie_lower:
                findings.append(Finding(
                    title=f"Cookie '{cookie_name}' missing SameSite attribute on {label}",
                    category="Session Security",
                    severity=Severity.LOW,
                    description="Cookies without SameSite can be sent in cross-site requests, enabling CSRF attacks",
                    evidence=f"Set-Cookie: {cookie_header.strip()[:200]}",
                    impact="CSRF attacks may be possible if no other anti-CSRF mechanisms are in place",
                    remediation="Add SameSite=Strict or SameSite=Lax to all cookies",
                    cwe="CWE-1275",
                    owasp="A01:2021 Broken Access Control",
                    url=url,
                ))

    return findings


def run() -> list[Finding]:
    """Run security header audits on all target domains."""
    print_banner("SECURITY HEADERS AUDIT")

    all_findings = []

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Authentication Service"),
        (get_login_url(), "Login Page"),
        (f"{get_auth_base()}/auth/forgot-password", "Password Reset"),
    ]

    for url, label in targets:
        findings = audit_headers(url, label)
        all_findings.extend(findings)

    print(f"\n  Total header findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
