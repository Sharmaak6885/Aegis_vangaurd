"""
OAuth Flow Analyzer
Inspects the Google OAuth login flow for security misconfigurations.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_auth_base, get_login_url
)


def analyze_oauth_flow() -> list[Finding]:
    """Analyze the Google OAuth flow for misconfigurations."""
    print_banner("OAUTH FLOW ANALYSIS")
    findings = []

    # Step 1: Load the login page and find the Google OAuth initiation URL
    print("  Step 1: Loading login page...")
    response = safe_request(get_login_url() + "?returnTo=https://app.archscale.in/studio/mission-control/my-space")
    if not response:
        print("  [ERROR] Cannot reach login page")
        return findings

    page_content = response.text

    # Look for Google OAuth URLs or buttons
    google_oauth_patterns = [
        r'https://accounts\.google\.com/o/oauth2/v2/auth[^"\'>\s]*',
        r'https://accounts\.google\.com/o/oauth2/auth[^"\'>\s]*',
        r'/api/auth/google[^"\'>\s]*',
        r'/auth/google[^"\'>\s]*',
        r'href="([^"]*google[^"]*)"',
        r"href='([^']*google[^']*)'",
        r'action="([^"]*google[^"]*)"',
    ]

    oauth_urls = []
    for pattern in google_oauth_patterns:
        matches = re.findall(pattern, page_content, re.IGNORECASE)
        oauth_urls.extend(matches)

    print(f"  Found {len(oauth_urls)} potential OAuth URLs")

    # Step 2: Try to find the OAuth initiation endpoint by clicking "Continue with Google"
    # Check common OAuth initiation endpoints
    oauth_endpoints = [
        f"{get_auth_base()}/auth/google",
        f"{get_auth_base()}/api/auth/google",
        f"{get_auth_base()}/oauth/google",
        f"{get_auth_base()}/login/google",
        f"{get_auth_base()}/api/v1/auth/google",
        f"{get_auth_base()}/auth/google/callback",
    ]

    print("\n  Step 2: Probing OAuth initiation endpoints...")
    for endpoint in oauth_endpoints:
        resp = safe_request(endpoint, allow_redirects=False, timeout=10)
        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            print(f"  [FOUND] {endpoint} → {location[:100]}")
            oauth_urls.append(location)

            # Parse the OAuth URL parameters
            parsed = urlparse(location)
            params = parse_qs(parsed.query)

            # Check for state parameter (CSRF protection)
            if "state" not in params:
                finding = Finding(
                    title="Missing 'state' parameter in OAuth authorization request",
                    category="OAuth Misconfiguration",
                    severity=Severity.HIGH,
                    description="The OAuth 2.0 authorization request does not include a 'state' parameter. This parameter is critical for preventing Cross-Site Request Forgery (CSRF) attacks during the OAuth flow.",
                    evidence=f"OAuth URL: {location[:300]}\nMissing parameter: state",
                    impact="An attacker can initiate an OAuth flow and trick a victim into linking the attacker's account, or hijack the authentication callback",
                    remediation="Generate a cryptographically random 'state' parameter for each OAuth request, store it in the session, and validate it when the callback is received",
                    cwe="CWE-352",
                    owasp="A01:2021 Broken Access Control",
                    url=endpoint,
                )
                findings.append(finding)
                print_finding(finding)
            else:
                print(f"    [OK] state parameter present: {params['state'][0][:30]}...")

            # Check for nonce parameter
            if "nonce" not in params:
                finding = Finding(
                    title="Missing 'nonce' parameter in OAuth authorization request",
                    category="OAuth Misconfiguration",
                    severity=Severity.MEDIUM,
                    description="The OAuth/OIDC authorization request does not include a 'nonce' parameter. This parameter prevents token replay attacks.",
                    evidence=f"OAuth URL: {location[:300]}\nMissing parameter: nonce",
                    impact="Without a nonce, ID tokens could potentially be replayed in a different session",
                    remediation="Include a cryptographically random 'nonce' parameter in the authorization request and validate it in the received ID token",
                    cwe="CWE-294",
                    owasp="A07:2021 Identification and Authentication Failures",
                    url=endpoint,
                )
                findings.append(finding)
                print_finding(finding)

            # Check redirect_uri
            if "redirect_uri" in params:
                redirect_uri = params["redirect_uri"][0]
                print(f"    Redirect URI: {redirect_uri}")

                # Check if redirect_uri uses HTTP (should be HTTPS)
                if redirect_uri.startswith("http://"):
                    finding = Finding(
                        title="OAuth redirect_uri uses HTTP instead of HTTPS",
                        category="OAuth Misconfiguration",
                        severity=Severity.HIGH,
                        description="The OAuth redirect_uri uses HTTP, which means the authorization code is transmitted in plaintext",
                        evidence=f"redirect_uri: {redirect_uri}",
                        impact="Authorization codes can be intercepted in transit via MITM attacks",
                        remediation="Use HTTPS for all OAuth redirect URIs",
                        cwe="CWE-319",
                        owasp="A02:2021 Cryptographic Failures",
                        url=endpoint,
                    )
                    findings.append(finding)
                    print_finding(finding)

            # Check response_type
            if "response_type" in params:
                resp_type = params["response_type"][0]
                print(f"    Response type: {resp_type}")
                if "token" in resp_type and "code" not in resp_type:
                    finding = Finding(
                        title="OAuth using implicit flow (response_type=token)",
                        category="OAuth Misconfiguration",
                        severity=Severity.MEDIUM,
                        description="The OAuth flow uses the implicit grant type, which exposes tokens in the URL fragment. The authorization code flow with PKCE is recommended.",
                        evidence=f"response_type: {resp_type}",
                        impact="Access tokens are exposed in browser history, referrer headers, and logs",
                        remediation="Switch to Authorization Code flow with PKCE (response_type=code)",
                        cwe="CWE-522",
                        owasp="A07:2021 Identification and Authentication Failures",
                        url=endpoint,
                    )
                    findings.append(finding)
                    print_finding(finding)

            # Check scope
            if "scope" in params:
                scope = params["scope"][0]
                print(f"    Scope: {scope}")
                sensitive_scopes = ["admin", "write", "delete", "manage"]
                for s in sensitive_scopes:
                    if s in scope.lower():
                        findings.append(Finding(
                            title=f"OAuth requests potentially excessive scope: {s}",
                            category="OAuth Misconfiguration",
                            severity=Severity.LOW,
                            description=f"The OAuth scope includes '{s}' which may grant more permissions than needed for authentication",
                            evidence=f"scope: {scope}",
                            impact="Over-privileged OAuth tokens increase the blast radius if compromised",
                            remediation="Request only the minimum scopes needed (openid, email, profile)",
                            cwe="CWE-250",
                            owasp="A01:2021 Broken Access Control",
                            url=endpoint,
                        ))

            # Check client_id
            if "client_id" in params:
                client_id = params["client_id"][0]
                print(f"    Client ID: {client_id[:30]}...")

        elif resp:
            print(f"  [SKIP] {endpoint} → {resp.status_code}")

    # Step 3: Check if OAuth callback endpoint is accessible
    print("\n  Step 3: Testing OAuth callback endpoint...")
    
    # SPA Fingerprinting for callbacks
    baseline_lengths = []
    for test_path in ["/does-not-exist-callback-1", "/missing-callback-2", "/notfound-callback-3"]:
        resp = safe_request(f"{get_auth_base()}{test_path}", timeout=5)
        if resp and resp.status_code == 200:
            baseline_lengths.append(len(resp.text))
            
    spa_baseline_len = None
    if len(baseline_lengths) >= 2 and len(set(baseline_lengths)) == 1:
        spa_baseline_len = baseline_lengths[0]

    callback_urls = [
        f"{get_auth_base()}/auth/google/callback",
        f"{get_auth_base()}/api/auth/callback/google",
        f"{get_auth_base()}/oauth/callback",
    ]

    for callback in callback_urls:
        resp = safe_request(callback, allow_redirects=False, timeout=10)
        if resp:
            print(f"  Callback {callback}: {resp.status_code}")
            if resp.status_code == 200:
                if spa_baseline_len is not None and abs(len(resp.text) - spa_baseline_len) < 50:
                    print(f"    [SKIP] Callback {callback} matches SPA catch-all baseline")
                    continue
                    
                findings.append(Finding(
                    title="OAuth callback endpoint accessible without authorization code",
                    category="OAuth Misconfiguration",
                    severity=Severity.LOW,
                    description="The OAuth callback endpoint returns 200 without a valid authorization code, which may indicate insufficient validation",
                    evidence=f"GET {callback} → 200 OK",
                    impact="May expose error messages or internal state information",
                    remediation="Return appropriate error responses when required parameters are missing",
                    cwe="CWE-284",
                    owasp="A07:2021 Identification and Authentication Failures",
                    url=callback,
                ))
                break  # Only report the first accessible callback to prevent duplicates

    # Step 4: Analyze page for embedded OAuth configuration
    print("\n  Step 4: Scanning page for embedded OAuth config...")
    sensitive_patterns = {
        "Google Client ID": r'[0-9]+-[a-zA-Z0-9_]+\.apps\.googleusercontent\.com',
        "OAuth Client Secret": r'client[_-]?secret["\s:=]+["\']([^"\']+)',
        "API Key": r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})',
    }

    for name, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, page_content, re.IGNORECASE)
        if matches:
            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ""
                if name == "Google Client ID":
                    print(f"  [INFO] Found {name}: {match_str[:40]}...")
                    # Client IDs are public — this is informational only
                    findings.append(Finding(
                        title=f"Google OAuth Client ID exposed in page source",
                        category="Information Disclosure",
                        severity=Severity.INFO,
                        description="Google OAuth Client ID is visible in the login page source. While Client IDs are considered semi-public, they reveal the OAuth application configuration.",
                        evidence=f"Client ID: {match_str}",
                        impact="Low — Client IDs are designed to be public, but they can be used to enumerate the OAuth configuration",
                        remediation="This is expected behavior for OAuth. Ensure the Client Secret is never exposed client-side.",
                        cwe="CWE-200",
                        owasp="A05:2021 Security Misconfiguration",
                        url=LOGIN_URL,
                    ))
                elif "secret" in name.lower():
                    finding = Finding(
                        title=f"OAuth Client Secret exposed in client-side code!",
                        category="Secrets Exposure",
                        severity=Severity.CRITICAL,
                        description="An OAuth client secret is exposed in client-side JavaScript. This is a critical vulnerability that allows attackers to impersonate the application.",
                        evidence=f"Found pattern matching {name}: {match_str[:20]}***",
                        impact="Attackers can impersonate the application, forge OAuth tokens, and gain unauthorized access",
                        remediation="Immediately rotate the OAuth client secret. Move it to server-side only. Never include secrets in client-side code.",
                        cwe="CWE-798",
                        owasp="A07:2021 Identification and Authentication Failures",
                        url=LOGIN_URL,
                    )
                    findings.append(finding)
                    print_finding(finding)

    print(f"\n  Total OAuth findings: {len(findings)}")
    return findings


def run() -> list[Finding]:
    """Run all OAuth analysis tests."""
    return analyze_oauth_flow()


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
