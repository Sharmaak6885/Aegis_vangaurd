"""
Rate Limiting & Brute-Force Protection Tester
Tests auth endpoints for rate limiting, CAPTCHA, and account lockout protections.
"""

import time
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_auth_base, get_login_url
)


def test_rate_limit(url: str, label: str, method: str = "GET",
                    num_requests: int = 15, delay: float = 0.1) -> list[Finding]:
    """Send rapid sequential requests to test rate limiting."""
    findings = []
    print(f"\n  Testing rate limiting: {url} ({label})")
    print(f"  Sending {num_requests} rapid {method} requests...")

    statuses = []
    response_times = []
    rate_limited = False
    captcha_detected = False
    lockout_detected = False

    for i in range(num_requests):
        start = time.time()
        resp = safe_request(
            url,
            method=method,
            timeout=10,
            allow_redirects=False,
        )
        elapsed = time.time() - start
        response_times.append(elapsed)

        if resp:
            statuses.append(resp.status_code)
            print(f"    [{i+1:>2}/{num_requests}] {resp.status_code} ({elapsed:.2f}s)")

            # Check for rate limiting signals
            if resp.status_code == 429:
                rate_limited = True
                retry_after = resp.headers.get("Retry-After", "not set")
                print(f"    [!] Rate limited! Retry-After: {retry_after}")
                break

            # Check for CAPTCHA
            body_lower = resp.text.lower() if resp.text else ""
            if any(kw in body_lower for kw in ["captcha", "recaptcha", "hcaptcha", "turnstile", "challenge"]):
                captcha_detected = True
                print(f"    [!] CAPTCHA/Challenge detected!")

            # Check for lockout
            if any(kw in body_lower for kw in [
                "locked", "too many attempts", "temporarily blocked",
                "account disabled", "try again later", "slow down"
            ]):
                lockout_detected = True
                print(f"    [!] Lockout signal detected!")

        time.sleep(delay)

    # Analyze results
    avg_time = sum(response_times) / len(response_times) if response_times else 0
    time_increase = response_times[-1] / response_times[0] if len(response_times) > 1 and response_times[0] > 0 else 1

    if rate_limited:
        findings.append(Finding(
            title=f"Rate limiting active on {label}",
            category="Rate Limiting",
            severity=Severity.INFO,
            description=f"Rate limiting is properly implemented on {label}. The server returned 429 (Too Many Requests) "
                        f"after {len(statuses)} rapid requests.",
            evidence=f"URL: {url}\nTriggered after: {len(statuses)} requests\n"
                     f"Status codes: {statuses}\nAvg response time: {avg_time:.3f}s",
            impact="Positive — brute-force protection is active",
            remediation="No action needed — rate limiting is working correctly",
            cwe="CWE-307",
            owasp="A07:2021 Identification and Authentication Failures",
            url=url,
            status="not_vulnerable",
        ))
        print_finding(findings[-1])

    elif captcha_detected:
        findings.append(Finding(
            title=f"CAPTCHA/Challenge detected on {label}",
            category="Rate Limiting",
            severity=Severity.INFO,
            description=f"A CAPTCHA or challenge mechanism was detected on {label}, providing protection against automated requests.",
            evidence=f"URL: {url}\nCAPTCHA detected after: {len(statuses)} requests",
            impact="Positive — automated brute-force is mitigated by CAPTCHA",
            remediation="Ensure CAPTCHA is properly implemented and cannot be easily bypassed",
            cwe="CWE-307",
            owasp="A07:2021 Identification and Authentication Failures",
            url=url,
            status="not_vulnerable",
        ))

    elif lockout_detected:
        findings.append(Finding(
            title=f"Account lockout mechanism detected on {label}",
            category="Rate Limiting",
            severity=Severity.INFO,
            description=f"An account lockout mechanism was detected on {label}.",
            evidence=f"URL: {url}\nLockout detected after: {len(statuses)} requests",
            impact="Positive — brute-force attacks will trigger account lockout",
            remediation="Ensure lockout is time-based (not permanent) to prevent account lockout denial-of-service",
            cwe="CWE-307",
            owasp="A07:2021 Identification and Authentication Failures",
            url=url,
            status="not_vulnerable",
        ))

    else:
        # No rate limiting detected
        status_set = set(statuses)
        if all(s in (200, 301, 302, 303, 307, 308) for s in statuses):
            findings.append(Finding(
                title=f"No rate limiting detected on {label}",
                category="Rate Limiting",
                severity=Severity.HIGH,
                description=f"No rate limiting was detected after sending {num_requests} rapid requests to {label}. "
                            f"All requests returned successful status codes without any throttling, CAPTCHA, or lockout.",
                evidence=f"URL: {url}\nRequests sent: {num_requests}\n"
                         f"Status codes: {statuses}\n"
                         f"Avg response time: {avg_time:.3f}s\n"
                         f"Time increase factor: {time_increase:.1f}x",
                impact="Without rate limiting, attackers can perform brute-force attacks against authentication, "
                       "credential stuffing, or resource exhaustion attacks",
                remediation="Implement rate limiting on all authentication endpoints:\n"
                            "• Return 429 Too Many Requests after threshold\n"
                            "• Include Retry-After header\n"
                            "• Implement progressive delays\n"
                            "• Consider CAPTCHA after N failed attempts\n"
                            "• Implement IP-based and account-based rate limits",
                cwe="CWE-307",
                owasp="A07:2021 Identification and Authentication Failures",
                url=url,
            ))
            print_finding(findings[-1])

    # Check for progressive delay (response time increasing)
    if time_increase > 3 and not rate_limited:
        findings.append(Finding(
            title=f"Possible progressive delay on {label}",
            category="Rate Limiting",
            severity=Severity.INFO,
            description=f"Response time increased {time_increase:.1f}x from first to last request, "
                        f"suggesting progressive delay/throttling may be in effect.",
            evidence=f"First request: {response_times[0]:.3f}s\nLast request: {response_times[-1]:.3f}s\n"
                     f"Increase: {time_increase:.1f}x",
            impact="Progressive delay can slow down brute-force attacks",
            remediation="Consider combining progressive delay with hard rate limits (429 responses)",
            cwe="CWE-307",
            owasp="A07:2021 Identification and Authentication Failures",
            url=url,
        ))

    return findings


def run() -> list[Finding]:
    """Run rate limiting tests on all auth endpoints."""
    print_banner("RATE LIMITING & BRUTE-FORCE PROTECTION")
    all_findings = []

    auth_base = get_auth_base()
    login_url = get_login_url()

    targets = [
        (login_url, "Login Page", "GET"),
        (login_url, "Login POST", "POST"),
        (f"{auth_base}/auth/forgot-password", "Password Reset", "GET"),
    ]

    # Also test common API endpoints
    api_endpoints = [
        (f"{auth_base}/api/auth/login", "API Login"),
        (f"{auth_base}/api/auth/register", "API Register"),
        (f"{auth_base}/api/auth/forgot-password", "API Password Reset"),
        (f"{auth_base}/api/v1/auth/login", "API v1 Login"),
    ]

    # Probe API endpoints first to see which exist
    for url, label in api_endpoints:
        resp = safe_request(url, timeout=5, allow_redirects=False)
        if resp and resp.status_code not in (404, 405):
            targets.append((url, label, "POST"))
            print(f"  [FOUND] {label}: {url} → {resp.status_code}")

    for url, label, method in targets:
        findings = test_rate_limit(url, label, method=method)
        all_findings.extend(findings)

    print(f"\n  Total rate limiting findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
