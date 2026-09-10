"""
CORS Misconfiguration Tester
Tests Cross-Origin Resource Sharing configuration for security weaknesses.
"""

from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)


def test_cors(url: str, label: str) -> list[Finding]:
    """Test CORS configuration for a given URL."""
    findings = []
    print(f"\n  Testing CORS on: {url} ({label})")

    # Test 1: Arbitrary Origin
    print("  [Test 1] Arbitrary origin...")
    resp = safe_request(url, headers={"Origin": "https://evil.com"})
    if resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "https://evil.com":
            severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
            finding = Finding(
                title=f"CORS reflects arbitrary origin on {label}",
                category="CORS Misconfiguration",
                severity=severity,
                description=f"The server reflects the arbitrary Origin header value in Access-Control-Allow-Origin. "
                           f"{'Combined with Allow-Credentials: true, this allows full cross-origin authenticated requests from any domain.' if acac.lower() == 'true' else 'This allows cross-origin requests from any domain.'}",
                evidence=f"Request Origin: https://evil.com\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac or 'not set'}",
                impact="Attackers can make authenticated cross-origin requests from any domain, potentially stealing sensitive data",
                remediation="Implement a strict allowlist of trusted origins. Never reflect the Origin header directly.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)
        elif acao == "*":
            finding = Finding(
                title=f"CORS allows all origins (wildcard) on {label}",
                category="CORS Misconfiguration",
                severity=Severity.MEDIUM if acac.lower() != "true" else Severity.HIGH,
                description="The server sets Access-Control-Allow-Origin to wildcard (*), allowing any website to make cross-origin requests.",
                evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac or 'not set'}",
                impact="Any website can read responses from this endpoint. If the endpoint returns sensitive data, it can be stolen cross-origin.",
                remediation="Replace wildcard with specific trusted origins. Use a whitelist-based approach.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)
        else:
            print(f"    ACAO: {acao or '(not set)'} -- Arbitrary origin rejected [OK]")

    # Test 2: Null Origin
    print("  [Test 2] Null origin...")
    resp = safe_request(url, headers={"Origin": "null"})
    if resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "null":
            finding = Finding(
                title=f"CORS allows null origin on {label}",
                category="CORS Misconfiguration",
                severity=Severity.MEDIUM,
                description="The server allows the 'null' origin, which can be triggered by sandboxed iframes, data: URLs, and local files.",
                evidence=f"Request Origin: null\nAccess-Control-Allow-Origin: null",
                impact="Attackers can use sandboxed iframes to make cross-origin requests with null origin",
                remediation="Do not include 'null' in the list of allowed origins.",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)
        else:
            print(f"    ACAO: {acao or '(not set)'} -- Null origin rejected [OK]")

    # Test 3: Subdomain match bypass
    print("  [Test 3] Subdomain bypass...")
    bypass_origins = [
        "https://evil-archscale.in",
        "https://archscale.in.evil.com",
        "https://app.archscale.in.evil.com",
    ]
    for origin in bypass_origins:
        resp = safe_request(url, headers={"Origin": origin})
        if resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == origin:
                finding = Finding(
                    title=f"CORS subdomain validation bypass on {label}",
                    category="CORS Misconfiguration",
                    severity=Severity.HIGH,
                    description=f"The server allows a spoofed origin '{origin}' that superficially matches the real domain. This indicates the CORS validation uses substring matching instead of exact matching.",
                    evidence=f"Request Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    impact="Attackers can register lookalike domains and make authenticated cross-origin requests",
                    remediation="Use exact origin matching with a strict whitelist. Do not use substring or regex-based matching.",
                    cwe="CWE-942",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                )
                findings.append(finding)
                print_finding(finding)

    # Test 4: Preflight (OPTIONS) request
    print("  [Test 4] Preflight request...")
    resp = safe_request(
        url,
        method="OPTIONS",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
        },
    )
    if resp:
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        methods = resp.headers.get("Access-Control-Allow-Methods", "")
        allowed_headers = resp.headers.get("Access-Control-Allow-Headers", "")
        print(f"    Preflight ACAO: {acao or '(not set)'}")
        print(f"    Allowed Methods: {methods or '(not set)'}")
        print(f"    Allowed Headers: {allowed_headers or '(not set)'}")

        if acao == "https://evil.com" or acao == "*":
            finding = Finding(
                title=f"Preflight CORS allows untrusted origin on {label}",
                category="CORS Misconfiguration",
                severity=Severity.MEDIUM,
                description="The preflight (OPTIONS) response allows untrusted origins, which may enable cross-origin requests with custom headers.",
                evidence=f"Preflight Origin: https://evil.com\nACAO: {acao}\nAllowed Methods: {methods}\nAllowed Headers: {allowed_headers}",
                impact="Attackers can send cross-origin requests with custom headers and methods",
                remediation="Restrict preflight responses to trusted origins only",
                cwe="CWE-942",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)

    return findings


def run() -> list[Finding]:
    """Run CORS tests on all target endpoints."""
    print_banner("CORS MISCONFIGURATION TESTING")
    all_findings = []

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Auth Service"),
        (get_login_url(), "Login Page"),
        (f"{get_auth_base()}/auth/forgot-password", "Password Reset"),
    ]

    for url, label in targets:
        findings = test_cors(url, label)
        all_findings.extend(findings)

    print(f"\n  Total CORS findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
