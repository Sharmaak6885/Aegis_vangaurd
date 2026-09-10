"""
Open Redirect Tester
Tests the returnTo parameter on the SSO login page for open redirect vulnerabilities.
"""

from urllib.parse import urlencode, urlparse, parse_qs
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_auth_base, get_login_url
)


# Payloads to test for open redirect
REDIRECT_PAYLOADS = [
    # Basic external redirects
    "https://evil.com",
    "http://evil.com",
    "//evil.com",
    # Protocol-relative
    "///evil.com",
    "////evil.com",
    # Backslash tricks
    "https://evil.com\\@app.archscale.in",
    "https://app.archscale.in.evil.com",
    # URL encoding bypasses
    "https:%2F%2Fevil.com",
    "https://evil%2Ecom",
    # JavaScript protocol
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    # Domain confusion
    "https://evil.com#https://app.archscale.in",
    "https://evil.com?https://app.archscale.in",
    # CRLF injection attempt
    "https://app.archscale.in%0d%0aLocation:%20https://evil.com",
    # Null byte
    "https://app.archscale.in%00.evil.com",
    # Subdomain matching bypass
    "https://apparchscale.in",
    "https://app.archscale.in.evil.com",
    "https://evil.com/app.archscale.in",
    # Empty and special values
    "",
    "null",
    "undefined",
    # Relative path traversal
    "/../../../etc/passwd",
    "/\\evil.com",
]


def test_open_redirect() -> list[Finding]:
    """Test the returnTo parameter for open redirect vulnerabilities."""
    print_banner("OPEN REDIRECT TESTING")
    findings = []

    print(f"  Target: {get_login_url()}")
    print(f"  Parameter: returnTo")
    print(f"  Testing {len(REDIRECT_PAYLOADS)} payloads...\n")

    for i, payload in enumerate(REDIRECT_PAYLOADS):
        url = f"{get_login_url()}?returnTo={payload}"
        print(f"  [{i+1}/{len(REDIRECT_PAYLOADS)}] Testing: {payload[:60]}{'...' if len(payload) > 60 else ''}")

        # Test with follow redirects disabled to see the raw redirect
        response = safe_request(url, allow_redirects=False, timeout=10)
        if not response:
            continue

        # Check if the server redirects to our payload
        location = response.headers.get("Location", "")
        status = response.status_code

        is_redirect = status in (301, 302, 303, 307, 308)

        if is_redirect and location:
            parsed_location = urlparse(location)
            # Check if redirected to an external domain
            if parsed_location.netloc and "archscale" not in parsed_location.netloc.lower():
                finding = Finding(
                    title="Open Redirect via returnTo parameter",
                    category="Open Redirect",
                    severity=Severity.HIGH,
                    description="The login page's returnTo parameter allows redirection to external domains. An attacker can craft a phishing link that appears to be a legitimate ArchScale login URL but redirects victims to a malicious site after login.",
                    evidence=f"Request: GET {url}\nResponse: {status} → Location: {location}",
                    impact="Attackers can craft convincing phishing URLs using the trusted archscale.in domain to redirect users to credential-harvesting sites after authentication",
                    remediation="Validate returnTo parameter server-side: only allow redirects to whitelisted domains (*.archscale.in). Reject any absolute URLs pointing to external domains.",
                    cwe="CWE-601",
                    owasp="A01:2021 Broken Access Control",
                    url=url,
                )
                findings.append(finding)
                print_finding(finding)
                continue

        # Also check if the payload is reflected in the page body (DOM-based redirect potential)
        response_with_follow = safe_request(url, allow_redirects=True, timeout=10)
        if response_with_follow and payload in response_with_follow.text:
            if payload.startswith("http") and "archscale" not in payload:
                finding = Finding(
                    title="returnTo parameter reflected in page (potential DOM-based redirect)",
                    category="Open Redirect",
                    severity=Severity.MEDIUM,
                    description="The returnTo parameter value is reflected in the page content without proper sanitization. If client-side JavaScript processes this value, it could lead to DOM-based open redirect.",
                    evidence=f"Request: GET {url}\nPayload '{payload[:60]}' found reflected in response body",
                    impact="If client-side JS reads and processes this value, attackers could redirect users post-authentication",
                    remediation="Sanitize the returnTo parameter before reflecting it in the DOM. Use a server-side allowlist for valid redirect targets.",
                    cwe="CWE-601",
                    owasp="A01:2021 Broken Access Control",
                    url=url,
                )
                findings.append(finding)
                print_finding(finding)

    # Test returnTo parameter absence behavior
    print("\n  Testing behavior without returnTo parameter...")
    response = safe_request(get_login_url(), allow_redirects=False)
    if response:
        print(f"  Without returnTo: Status {response.status_code}")
        location = response.headers.get("Location", "None")
        print(f"  Default redirect: {location}")

    # Test returnTo with same-origin URLs (baseline)
    print("\n  Testing same-origin returnTo (baseline)...")
    baseline_url = f"{get_login_url()}?returnTo=https://app.archscale.in/studio/projects"
    response = safe_request(baseline_url, allow_redirects=False)
    if response:
        print(f"  Same-origin returnTo: Status {response.status_code}")

    if not findings:
        findings.append(Finding(
            title="returnTo parameter appears to validate redirect targets",
            category="Open Redirect",
            severity=Severity.INFO,
            description="Testing of the returnTo parameter with various bypass payloads did not result in successful open redirects. The server appears to validate redirect targets.",
            evidence=f"Tested {len(REDIRECT_PAYLOADS)} payloads against {get_login_url()}?returnTo=<payload>. No external redirects observed.",
            impact="Low — the redirect validation appears to be functioning correctly",
            remediation="Continue monitoring. Ensure the allowlist is maintained as new subdomains are added.",
            cwe="CWE-601",
            owasp="A01:2021 Broken Access Control",
            url=get_login_url(),
            status="not_vulnerable",
        ))

    return findings


def run() -> list[Finding]:
    """Run all open redirect tests."""
    return test_open_redirect()


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
