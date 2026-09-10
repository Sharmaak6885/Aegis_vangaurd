"""
Information Disclosure Scanner
Analyzes client-side JavaScript bundles, source maps, and page content for
hardcoded API keys, staging URLs, internal endpoints, and other sensitive data.
"""

import re
from urllib.parse import urljoin, urlparse
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)


# Patterns to search for in JS bundles and HTML
SENSITIVE_PATTERNS = {
    "AWS Access Key": {
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    "AWS Secret Key": {
        "pattern": r'(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    "Google API Key": {
        "pattern": r'AIza[0-9A-Za-z_-]{35}',
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    "Firebase Config": {
        "pattern": r'firebase[A-Za-z]*\s*[:=]\s*["\'][A-Za-z0-9_-]+',
        "severity": Severity.MEDIUM,
        "cwe": "CWE-798",
    },
    "JWT Token": {
        "pattern": r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        "severity": Severity.HIGH,
        "cwe": "CWE-200",
    },
    "Private Key": {
        "pattern": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-321",
    },
    "Internal IP": {
        "pattern": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
    "Staging/Dev URL": {
        "pattern": r'https?://(?:staging|dev|test|local|internal|debug|sandbox)[.\-][a-zA-Z0-9.-]+',
        "severity": Severity.MEDIUM,
        "cwe": "CWE-200",
    },
    "Localhost URL": {
        "pattern": r'https?://localhost[:\d]*[/\w]*',
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
    "Database Connection String": {
        "pattern": r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    "Hardcoded Password": {
        "pattern": r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})',
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    "Email Address": {
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "severity": Severity.INFO,
        "cwe": "CWE-200",
    },
    "Slack Webhook": {
        "pattern": r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    "Stripe Key": {
        "pattern": r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    "SendGrid Key": {
        "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "severity": Severity.CRITICAL,
        "cwe": "CWE-798",
    },
    "Twilio Key": {
        "pattern": r'SK[0-9a-fA-F]{32}',
        "severity": Severity.HIGH,
        "cwe": "CWE-798",
    },
    "API Endpoint": {
        "pattern": r'(?:api[_-]?(?:url|base|endpoint|host|server))\s*[:=]\s*["\']([^"\']+)',
        "severity": Severity.LOW,
        "cwe": "CWE-200",
    },
    "S3 Bucket": {
        "pattern": r'(?:s3://[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\.s3\.amazonaws\.com)',
        "severity": Severity.MEDIUM,
        "cwe": "CWE-200",
    },
}


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Extract all JavaScript bundle URLs from HTML."""
    js_urls = set()

    # Script src attributes
    for match in re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE):
        if match.endswith(".js"):
            full_url = urljoin(base_url, match)
            js_urls.add(full_url)

    # Preloaded JS
    for match in re.findall(r'<link[^>]+href=["\']([^"\']+\.js)["\']', html, re.IGNORECASE):
        full_url = urljoin(base_url, match)
        js_urls.add(full_url)

    return list(js_urls)


def scan_content(content: str, source_url: str, source_label: str) -> list[Finding]:
    """Scan content for sensitive patterns."""
    findings = []

    for name, config in SENSITIVE_PATTERNS.items():
        matches = re.findall(config["pattern"], content, re.IGNORECASE)
        if matches:
            # Deduplicate
            unique_matches = list(set(matches))[:5]  # Max 5 unique matches per pattern

            # Filter out false positives
            filtered = []
            for m in unique_matches:
                match_str = m if isinstance(m, str) else str(m)
                # Skip very short matches and common false positives
                if len(match_str) < 4:
                    continue
                if match_str in ("test", "true", "false", "null", "undefined", "example"):
                    continue
                # Skip placeholder emails
                if name == "Email Address" and any(x in match_str for x in ["example.com", "test.com", "placeholder"]):
                    continue
                filtered.append(match_str)

            if filtered:
                # Mask sensitive values in evidence
                masked = []
                for m in filtered:
                    if len(m) > 10:
                        masked.append(m[:6] + "***" + m[-3:])
                    else:
                        masked.append(m[:3] + "***")

                finding = Finding(
                    title=f"{name} found in {source_label}",
                    category="Information Disclosure",
                    severity=config["severity"],
                    description=f"Pattern matching '{name}' detected in {source_label}. This could expose sensitive credentials or internal infrastructure details.",
                    evidence=f"Source: {source_url}\nMatches ({len(filtered)}): {', '.join(masked[:3])}",
                    impact=f"Exposed {name.lower()} can be used by attackers for unauthorized access or further reconnaissance",
                    remediation=f"Remove {name.lower()} from client-side code. Use environment variables and server-side configuration instead.",
                    cwe=config["cwe"],
                    owasp="A05:2021 Security Misconfiguration",
                    url=source_url,
                )
                findings.append(finding)
                print_finding(finding)

    return findings


def check_source_maps(js_urls: list[str]) -> list[Finding]:
    """Check if source maps are accessible."""
    findings = []

    for js_url in js_urls[:10]:  # Check first 10 JS files
        map_url = js_url + ".map"
        resp = safe_request(map_url, timeout=5)
        if resp and resp.status_code == 200 and len(resp.text) > 100:
            if '"sources"' in resp.text or '"mappings"' in resp.text:
                finding = Finding(
                    title="JavaScript source map accessible in production",
                    category="Information Disclosure",
                    severity=Severity.MEDIUM,
                    description="JavaScript source maps are accessible on the production server. Source maps reveal the original unminified source code, making it trivial to understand the application's logic and find vulnerabilities.",
                    evidence=f"Source map URL: {map_url}\nResponse size: {len(resp.text)} bytes\nContains source mapping data",
                    impact="Attackers can read the original source code, understand business logic, find hardcoded values, and identify vulnerabilities more easily",
                    remediation="Remove source maps from production deployment. Configure the build tool to exclude .map files from the production bundle.",
                    cwe="CWE-540",
                    owasp="A05:2021 Security Misconfiguration",
                    url=map_url,
                )
                findings.append(finding)
                print_finding(finding)

    return findings


def check_common_exposed_files(base_url: str, label: str) -> list[Finding]:
    """Check for commonly exposed sensitive files."""
    findings = []

    sensitive_files = [
        (".env", "Environment configuration file"),
        (".env.local", "Local environment configuration"),
        (".env.production", "Production environment configuration"),
        (".git/config", "Git configuration file"),
        (".git/HEAD", "Git HEAD reference"),
        ("package.json", "NPM package configuration"),
        ("webpack.config.js", "Webpack configuration"),
        ("next.config.js", "Next.js configuration"),
        ("api/debug", "Debug endpoint"),
        ("graphql", "GraphQL endpoint"),
        (".DS_Store", "macOS directory metadata"),
        ("wp-admin", "WordPress admin (CMS detection)"),
        ("admin", "Admin panel"),
        ("swagger", "API documentation"),
        ("api-docs", "API documentation"),
    ]

    print(f"\n  Checking {len(sensitive_files)} common files on {label}...")

    # SPA Fingerprinting: Detect catch-all routing
    print("    Fingerprinting routing behavior for common files...")
    baseline_lengths = []
    for test_path in ["does-not-exist-aegis-123", "missing-file-456", "notfound-789"]:
        resp = safe_request(f"{base_url.rstrip('/')}/{test_path}", timeout=5)
        if resp and resp.status_code == 200:
            baseline_lengths.append(len(resp.text))
            
    spa_baseline_len = None
    if len(baseline_lengths) >= 2 and len(set(baseline_lengths)) == 1:
        spa_baseline_len = baseline_lengths[0]
        print(f"    [INFO] Detected SPA catch-all route. Baseline length: {spa_baseline_len} bytes")

    for filepath, desc in sensitive_files:
        url = f"{base_url.rstrip('/')}/{filepath}"
        resp = safe_request(url, timeout=5)
        if resp and resp.status_code == 200 and len(resp.text) > 0:
            # Skip generic error pages / redirects to login
            if "login" in resp.url.lower() and resp.url != url:
                continue
            if "<title>404" in resp.text.lower():
                continue

            # Filter SPA false positives (same length as the catch-all baseline)
            # Or if it contains typical SPA HTML tags but we are looking for .env
            if spa_baseline_len is not None and abs(len(resp.text) - spa_baseline_len) < 50:
                print(f"    [SKIP] {filepath} matches SPA catch-all baseline (false positive)")
                continue

            severity = Severity.INFO
            if filepath.startswith(".env") or filepath.startswith(".git"):
                severity = Severity.CRITICAL
            elif filepath in ("package.json", "webpack.config.js", "next.config.js"):
                severity = Severity.MEDIUM
            elif "admin" in filepath or "debug" in filepath or "swagger" in filepath:
                severity = Severity.MEDIUM

            finding = Finding(
                title=f"Accessible file: {filepath} on {label}",
                category="Information Disclosure",
                severity=severity,
                description=f"{desc} is accessible on the production server at {url}",
                evidence=f"URL: {url}\nStatus: {resp.status_code}\nContent length: {len(resp.text)} bytes\nPreview: {resp.text[:150]}...",
                impact="May expose internal configuration, dependencies, or infrastructure details useful for further attacks",
                remediation=f"Block access to {filepath} via server configuration or middleware. Return 404 for sensitive files.",
                cwe="CWE-538",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            )
            findings.append(finding)
            print_finding(finding)
        else:
            if resp:
                print(f"    [OK] {filepath}: {resp.status_code}")

    return findings


def run() -> list[Finding]:
    """Run all information disclosure scans."""
    print_banner("INFORMATION DISCLOSURE SCAN")
    all_findings = []

    targets = [
        (get_login_url() + "?returnTo=https://app.archscale.in/studio/mission-control/my-space", get_auth_base(), "Auth Service"),
        (get_target_base(), get_target_base(), "Main Application"),
    ]

    for page_url, base_url, label in targets:
        print(f"\n  === Scanning {label}: {page_url} ===")

        # Fetch the page
        response = safe_request(page_url)
        if not response:
            continue

        # Scan the HTML page itself
        html_findings = scan_content(response.text, page_url, f"{label} HTML")
        all_findings.extend(html_findings)

        # Extract and scan JS bundles
        js_urls = extract_js_urls(response.text, base_url)
        print(f"\n  Found {len(js_urls)} JavaScript bundles")

        for js_url in js_urls[:15]:  # Limit to 15 bundles
            print(f"  Scanning: {js_url.split('/')[-1]}")
            js_resp = safe_request(js_url, timeout=10)
            if js_resp and js_resp.status_code == 200:
                js_findings = scan_content(js_resp.text, js_url, f"{label} JS bundle")
                all_findings.extend(js_findings)

        # Check for source maps
        source_map_findings = check_source_maps(js_urls)
        all_findings.extend(source_map_findings)

        # Check for exposed files
        file_findings = check_common_exposed_files(base_url, label)
        all_findings.extend(file_findings)

    print(f"\n  Total information disclosure findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
