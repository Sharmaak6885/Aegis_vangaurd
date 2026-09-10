"""
Content Security Policy (CSP) Analyzer Module
Deep analysis of CSP headers: directive parsing, bypass detection, grading.
"""

import re
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)

# Dangerous CSP values
UNSAFE_VALUES = {
    "'unsafe-inline'": {
        "severity": Severity.HIGH,
        "description": "Allows inline scripts/styles, defeating CSP's XSS protection",
        "remediation": "Use nonces or hashes instead of 'unsafe-inline'",
    },
    "'unsafe-eval'": {
        "severity": Severity.HIGH,
        "description": "Allows eval() and similar dynamic code execution",
        "remediation": "Refactor code to avoid eval(), new Function(), setTimeout(string), and setInterval(string)",
    },
    "data:": {
        "severity": Severity.MEDIUM,
        "description": "Allows data: URIs which can be used for script injection",
        "remediation": "Remove data: from script-src. If needed for images, restrict to img-src only",
    },
    "blob:": {
        "severity": Severity.MEDIUM,
        "description": "Allows blob: URIs which can be used to execute scripts",
        "remediation": "Remove blob: from script-src unless absolutely required",
    },
    "*": {
        "severity": Severity.HIGH,
        "description": "Wildcard allows resources from any origin",
        "remediation": "Replace wildcard with specific trusted origins",
    },
    "http:": {
        "severity": Severity.MEDIUM,
        "description": "Allows loading resources over unencrypted HTTP",
        "remediation": "Use https: or specific HTTPS origins instead",
    },
}

# Critical directives that should be present
CRITICAL_DIRECTIVES = {
    "default-src": "Fallback for all resource types — should be restrictive",
    "script-src": "Controls JavaScript execution — most important for XSS prevention",
    "style-src": "Controls CSS loading — 'unsafe-inline' is common but weakens protection",
    "img-src": "Controls image loading",
    "font-src": "Controls font loading",
    "connect-src": "Controls fetch/XHR/WebSocket destinations",
    "frame-ancestors": "Replaces X-Frame-Options — prevents clickjacking",
    "form-action": "Controls where forms can submit — prevents form hijacking",
    "base-uri": "Controls <base> element — prevents base tag injection",
    "object-src": "Controls plugins (Flash, Java) — should be 'none'",
}

# Known CSP bypass hosts (CDNs/services that can be abused)
BYPASS_HOSTS = {
    "*.googleapis.com": "Google APIs can host arbitrary JSONP endpoints",
    "*.gstatic.com": "Google Static can be used for resource injection",
    "*.cloudflare.com": "Cloudflare CDN may host exploitable resources",
    "*.jsdelivr.net": "jsDelivr serves any npm package (arbitrary JS)",
    "*.unpkg.com": "unpkg serves any npm package (arbitrary JS)",
    "*.cdnjs.cloudflare.com": "CDNJS hosts libraries with known bypass patterns",
    "*.rawgit.com": "RawGit serves arbitrary GitHub files",
    "*.raw.githubusercontent.com": "GitHub raw content (arbitrary files)",
    "*.pastebin.com": "Pastebin hosts arbitrary content",
    "*.google.com": "Google services have JSONP endpoints exploitable for CSP bypass",
}


def parse_csp(csp_header: str) -> dict:
    """Parse CSP header into a dictionary of directives."""
    directives = {}
    for directive in csp_header.split(";"):
        directive = directive.strip()
        if not directive:
            continue
        parts = directive.split(None, 1)
        name = parts[0].lower()
        values = parts[1].split() if len(parts) > 1 else []
        directives[name] = values
    return directives


def grade_csp(directives: dict) -> tuple[str, int]:
    """Grade CSP strictness from A+ to F."""
    score = 100

    # No default-src: -30
    if "default-src" not in directives:
        score -= 30

    # Check script-src (most critical)
    script_src = directives.get("script-src", directives.get("default-src", ["*"]))
    for val in script_src:
        if val == "'unsafe-inline'":
            score -= 25
        elif val == "'unsafe-eval'":
            score -= 20
        elif val == "*":
            score -= 30
        elif val == "data:":
            score -= 10
        elif val == "http:":
            score -= 10

    # Missing critical directives
    for directive in ["frame-ancestors", "form-action", "base-uri", "object-src"]:
        if directive not in directives:
            score -= 5

    # object-src not 'none'
    if "object-src" in directives and "'none'" not in directives["object-src"]:
        score -= 10

    score = max(0, min(100, score))

    if score >= 90:
        return "A", score
    elif score >= 80:
        return "B", score
    elif score >= 60:
        return "C", score
    elif score >= 40:
        return "D", score
    else:
        return "F", score


def analyze_csp(url: str, label: str) -> list[Finding]:
    """Analyze CSP header for a given URL."""
    findings = []

    response = safe_request(url)
    if not response:
        return findings

    csp = response.headers.get("Content-Security-Policy", "")
    csp_ro = response.headers.get("Content-Security-Policy-Report-Only", "")

    if not csp and not csp_ro:
        findings.append(Finding(
            title=f"No Content-Security-Policy header on {label}",
            category="CSP Analysis",
            severity=Severity.HIGH,
            description="No Content-Security-Policy header is set. CSP is the primary defense against "
                        "Cross-Site Scripting (XSS) attacks and other injection-based attacks.",
            evidence=f"URL: {url}\nContent-Security-Policy: (not set)\nContent-Security-Policy-Report-Only: (not set)",
            impact="Without CSP, the application has no browser-enforced protection against XSS, "
                   "clickjacking via frames, or other injection attacks",
            remediation="Implement a strict Content-Security-Policy. Start with:\n"
                        "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                        "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; "
                        "form-action 'self'; base-uri 'self'; object-src 'none'",
            cwe="CWE-693",
            owasp="A05:2021 Security Misconfiguration",
            url=url,
        ))
        print_finding(findings[-1])
        return findings

    # Determine which CSP to analyze
    if csp:
        print(f"\n  CSP (enforced): {csp[:120]}...")
    if csp_ro:
        print(f"  CSP (report-only): {csp_ro[:120]}...")
        if not csp:
            findings.append(Finding(
                title=f"CSP is report-only (not enforced) on {label}",
                category="CSP Analysis",
                severity=Severity.MEDIUM,
                description="Content-Security-Policy-Report-Only is set but Content-Security-Policy is not. "
                            "Report-only mode logs violations but does not block them.",
                evidence=f"Content-Security-Policy: (not set)\nContent-Security-Policy-Report-Only: {csp_ro[:200]}",
                impact="CSP violations are logged but not blocked — no actual XSS protection",
                remediation="Move from report-only to enforced mode once you've resolved reported violations",
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            ))

    active_csp = csp or csp_ro
    directives = parse_csp(active_csp)

    # Grade the CSP
    grade, score = grade_csp(directives)
    print(f"\n  CSP Grade: {grade} ({score}/100)")

    # Check for unsafe values in directives
    for directive, values in directives.items():
        for value in values:
            if value.lower() in UNSAFE_VALUES:
                config = UNSAFE_VALUES[value.lower()]
                # unsafe-inline in style-src is common and less dangerous
                sev = config["severity"]
                if value == "'unsafe-inline'" and directive == "style-src":
                    sev = Severity.LOW

                findings.append(Finding(
                    title=f"CSP {directive} contains {value} on {label}",
                    category="CSP Analysis",
                    severity=sev,
                    description=f"The CSP directive '{directive}' includes '{value}'. {config['description']}.",
                    evidence=f"Directive: {directive} {' '.join(values)}",
                    impact=f"The security benefit of CSP for {directive} is weakened by '{value}'",
                    remediation=config["remediation"],
                    cwe="CWE-693",
                    owasp="A05:2021 Security Misconfiguration",
                    url=url,
                ))

    # Check for missing critical directives
    for directive, description in CRITICAL_DIRECTIVES.items():
        if directive not in directives and directive != "default-src":
            # If default-src covers it, it's less critical
            if "default-src" in directives:
                sev = Severity.LOW
            else:
                sev = Severity.MEDIUM

            findings.append(Finding(
                title=f"CSP missing '{directive}' directive on {label}",
                category="CSP Analysis",
                severity=sev,
                description=f"The CSP does not include the '{directive}' directive. {description}.",
                evidence=f"Missing directive: {directive}\nCurrent CSP: {active_csp[:200]}",
                impact=f"Without {directive}, the browser falls back to default-src (if set) or allows all sources",
                remediation=f"Add '{directive}' directive to the Content-Security-Policy header",
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            ))

    # Check for bypass-prone hosts
    for directive, values in directives.items():
        if directive in ("script-src", "default-src"):
            for value in values:
                for bypass_host, bypass_desc in BYPASS_HOSTS.items():
                    if bypass_host.lstrip("*").lstrip(".") in value:
                        findings.append(Finding(
                            title=f"CSP {directive} allows potentially bypassable host: {value}",
                            category="CSP Analysis",
                            severity=Severity.MEDIUM,
                            description=f"The CSP allows scripts from '{value}'. {bypass_desc}. "
                                        f"This CDN/service may host content that can bypass CSP restrictions.",
                            evidence=f"Directive: {directive}\nAllowed host: {value}\nBypass risk: {bypass_desc}",
                            impact="Attackers may find JSONP endpoints or hosted scripts on this CDN to bypass CSP",
                            remediation="Use 'strict-dynamic' with nonces/hashes instead of host-based allowlists. "
                                        "If host allowlisting is needed, use the most specific path possible.",
                            cwe="CWE-693",
                            owasp="A05:2021 Security Misconfiguration",
                            url=url,
                        ))

    # CSP summary finding
    findings.append(Finding(
        title=f"CSP grade: {grade} ({score}/100) on {label}",
        category="CSP Analysis",
        severity=Severity.INFO if grade in ("A", "B") else Severity.MEDIUM if grade == "C" else Severity.HIGH,
        description=f"Content-Security-Policy evaluation for {label} scored {score}/100 (Grade {grade}). "
                    f"{'Enforced' if csp else 'Report-Only'} mode. "
                    f"{len(directives)} directives configured.",
        evidence=f"CSP: {active_csp[:300]}\nDirectives: {', '.join(directives.keys())}",
        impact="CSP is a critical defense layer against XSS and injection attacks",
        remediation="Review and strengthen CSP directives. Target grade A or higher.",
        cwe="CWE-693",
        owasp="A05:2021 Security Misconfiguration",
        url=url,
    ))

    return findings


def run() -> list[Finding]:
    """Run CSP analysis on all targets."""
    print_banner("CONTENT SECURITY POLICY ANALYSIS")
    all_findings = []

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Auth Service"),
        (get_login_url(), "Login Page"),
    ]

    for url, label in targets:
        print(f"\n  === CSP Analysis: {url} ({label}) ===")
        findings = analyze_csp(url, label)
        all_findings.extend(findings)

    print(f"\n  Total CSP findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
