"""
Cookie Security Auditor Module
Deep analysis of cookie security attributes across all endpoints.
"""

from urllib.parse import urlparse
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)


def parse_set_cookie(header_value: str) -> dict:
    """Parse a Set-Cookie header into components."""
    parts = header_value.split(";")
    cookie = {"raw": header_value.strip()}

    # First part is name=value
    if "=" in parts[0]:
        name, _, value = parts[0].partition("=")
        cookie["name"] = name.strip()
        cookie["value"] = value.strip()
    else:
        cookie["name"] = parts[0].strip()
        cookie["value"] = ""

    # Parse attributes
    cookie["secure"] = False
    cookie["httponly"] = False
    cookie["samesite"] = None
    cookie["domain"] = None
    cookie["path"] = None
    cookie["expires"] = None
    cookie["max_age"] = None

    for part in parts[1:]:
        part = part.strip().lower()
        if part == "secure":
            cookie["secure"] = True
        elif part == "httponly":
            cookie["httponly"] = True
        elif part.startswith("samesite="):
            cookie["samesite"] = part.split("=", 1)[1].strip()
        elif part.startswith("domain="):
            cookie["domain"] = part.split("=", 1)[1].strip()
        elif part.startswith("path="):
            cookie["path"] = part.split("=", 1)[1].strip()
        elif part.startswith("expires="):
            cookie["expires"] = part.split("=", 1)[1].strip()
        elif part.startswith("max-age="):
            cookie["max_age"] = part.split("=", 1)[1].strip()

    return cookie


def audit_cookie(cookie: dict, url: str, label: str) -> list[Finding]:
    """Audit a single cookie for security issues."""
    findings = []
    name = cookie.get("name", "unknown")
    parsed_url = urlparse(url)

    # Check if this looks like a session/auth cookie
    is_sensitive = any(kw in name.lower() for kw in [
        "session", "sess", "sid", "token", "auth", "jwt", "login",
        "csrf", "xsrf", "identity", "user", "access", "refresh",
    ])

    # 1. Missing Secure flag
    if not cookie["secure"]:
        sev = Severity.HIGH if is_sensitive else Severity.MEDIUM
        findings.append(Finding(
            title=f"Cookie '{name}' missing Secure flag ({label})",
            category="Cookie Security",
            severity=sev,
            description=f"Cookie '{name}' does not have the Secure flag set. "
                        f"Without this flag, the cookie can be transmitted over unencrypted HTTP connections.",
            evidence=f"Set-Cookie: {cookie['raw'][:200]}",
            impact="Cookie value can be intercepted via man-in-the-middle attacks on HTTP connections"
                   + (" — this appears to be a session/auth cookie" if is_sensitive else ""),
            remediation="Add the Secure flag: Set-Cookie: name=value; Secure",
            cwe="CWE-614",
            owasp="A02:2021 Cryptographic Failures",
            url=url,
        ))

    # 2. Missing HttpOnly flag
    if not cookie["httponly"]:
        sev = Severity.HIGH if is_sensitive else Severity.MEDIUM
        findings.append(Finding(
            title=f"Cookie '{name}' missing HttpOnly flag ({label})",
            category="Cookie Security",
            severity=sev,
            description=f"Cookie '{name}' does not have the HttpOnly flag. "
                        f"JavaScript can access this cookie via document.cookie, enabling XSS-based theft.",
            evidence=f"Set-Cookie: {cookie['raw'][:200]}",
            impact="If an XSS vulnerability exists, attackers can steal this cookie via JavaScript"
                   + (" — this appears to be a session/auth cookie" if is_sensitive else ""),
            remediation="Add the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
            cwe="CWE-1004",
            owasp="A05:2021 Security Misconfiguration",
            url=url,
        ))

    # 3. Missing or weak SameSite
    if cookie["samesite"] is None:
        sev = Severity.MEDIUM if is_sensitive else Severity.LOW
        findings.append(Finding(
            title=f"Cookie '{name}' missing SameSite attribute ({label})",
            category="Cookie Security",
            severity=sev,
            description=f"Cookie '{name}' does not set the SameSite attribute. "
                        f"Without it, the browser may send this cookie with cross-site requests (CSRF).",
            evidence=f"Set-Cookie: {cookie['raw'][:200]}",
            impact="Cross-Site Request Forgery (CSRF) attacks may be possible",
            remediation="Add SameSite=Strict or SameSite=Lax: Set-Cookie: name=value; SameSite=Strict",
            cwe="CWE-1275",
            owasp="A01:2021 Broken Access Control",
            url=url,
        ))
    elif cookie["samesite"] == "none" and not cookie["secure"]:
        findings.append(Finding(
            title=f"Cookie '{name}' uses SameSite=None without Secure flag ({label})",
            category="Cookie Security",
            severity=Severity.HIGH,
            description=f"Cookie '{name}' has SameSite=None but lacks the Secure flag. "
                        f"Modern browsers reject this combination — SameSite=None requires Secure.",
            evidence=f"Set-Cookie: {cookie['raw'][:200]}",
            impact="Cookie will be rejected by modern browsers, potentially breaking functionality",
            remediation="Add the Secure flag when using SameSite=None",
            cwe="CWE-614",
            owasp="A05:2021 Security Misconfiguration",
            url=url,
        ))

    # 4. Overly broad Domain scope
    if cookie["domain"]:
        domain = cookie["domain"].lstrip(".")
        host_domain = parsed_url.netloc
        if domain != host_domain and not host_domain.endswith(f".{domain}"):
            findings.append(Finding(
                title=f"Cookie '{name}' has broad Domain scope ({label})",
                category="Cookie Security",
                severity=Severity.MEDIUM,
                description=f"Cookie '{name}' domain is set to '{domain}', which may be broader than needed. "
                            f"This allows sibling subdomains to read this cookie.",
                evidence=f"Cookie domain: {domain}\nServer: {host_domain}\nSet-Cookie: {cookie['raw'][:150]}",
                impact="Cookies accessible to other subdomains can be stolen if any sibling subdomain is compromised",
                remediation=f"Set the Domain attribute to the most specific subdomain needed, or omit it to restrict to the exact origin",
                cwe="CWE-732",
                owasp="A01:2021 Broken Access Control",
                url=url,
            ))

    # 5. __Host- prefix compliance
    if name.startswith("__Host-"):
        issues = []
        if not cookie["secure"]:
            issues.append("missing Secure flag")
        if cookie["domain"]:
            issues.append(f"has Domain={cookie['domain']}")
        if cookie["path"] and cookie["path"] != "/":
            issues.append(f"Path is {cookie['path']} (must be /)")

        if issues:
            findings.append(Finding(
                title=f"__Host- prefixed cookie '{name}' violates requirements ({label})",
                category="Cookie Security",
                severity=Severity.MEDIUM,
                description=f"Cookie '{name}' uses the __Host- prefix but violates the requirements: {', '.join(issues)}. "
                            f"__Host- cookies must have Secure, no Domain, and Path=/.",
                evidence=f"Set-Cookie: {cookie['raw'][:200]}\nViolations: {', '.join(issues)}",
                impact="Browser may reject or silently ignore this cookie, causing authentication issues",
                remediation="Ensure __Host- cookies are Secure, have no Domain attribute, and Path=/",
                cwe="CWE-732",
                owasp="A05:2021 Security Misconfiguration",
                url=url,
            ))

    # 6. __Secure- prefix compliance
    if name.startswith("__Secure-") and not cookie["secure"]:
        findings.append(Finding(
            title=f"__Secure- prefixed cookie '{name}' missing Secure flag ({label})",
            category="Cookie Security",
            severity=Severity.MEDIUM,
            description=f"Cookie '{name}' uses the __Secure- prefix but lacks the Secure flag.",
            evidence=f"Set-Cookie: {cookie['raw'][:200]}",
            impact="Browser may reject this cookie, causing authentication issues",
            remediation="Add the Secure flag to __Secure- prefixed cookies",
            cwe="CWE-614",
            owasp="A05:2021 Security Misconfiguration",
            url=url,
        ))

    # 7. Very long cookie value (potential for buffer overflow in older systems)
    if len(cookie.get("value", "")) > 4096:
        findings.append(Finding(
            title=f"Cookie '{name}' has unusually large value ({len(cookie['value'])} bytes) ({label})",
            category="Cookie Security",
            severity=Severity.LOW,
            description=f"Cookie '{name}' value is {len(cookie['value'])} bytes. Very large cookies can cause issues with proxy servers and older web servers.",
            evidence=f"Cookie size: {len(cookie['value'])} bytes (limit: 4096 recommended)",
            impact="May cause 413 errors with some proxies or load balancers",
            remediation="Reduce cookie size. Store large session data server-side.",
            cwe="CWE-400",
            owasp="A05:2021 Security Misconfiguration",
            url=url,
        ))

    return findings


def run() -> list[Finding]:
    """Run cookie security audit on all targets."""
    print_banner("COOKIE SECURITY AUDIT")
    all_findings = []
    all_cookies = []

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Auth Service"),
        (get_login_url() + "?returnTo=https://app.archscale.in/studio/mission-control/my-space", "Login Page"),
        (get_auth_base() + "/auth/forgot-password", "Password Reset"),
    ]

    for url, label in targets:
        print(f"\n  === Cookie Audit: {url} ({label}) ===")

        response = safe_request(url)
        if not response:
            print(f"  [SKIP] Could not reach {url}")
            continue

        # Get all Set-Cookie headers
        set_cookie_headers = response.headers.get("Set-Cookie", "")

        # Also check raw headers for multiple Set-Cookie
        cookies_found = []
        for header_name, header_value in response.raw.headers.items() if hasattr(response, 'raw') and hasattr(response.raw, 'headers') else []:
            if header_name.lower() == "set-cookie":
                cookie = parse_set_cookie(header_value)
                cookies_found.append(cookie)

        # Fallback: parse from response.headers
        if not cookies_found and set_cookie_headers:
            for cookie_str in set_cookie_headers.split("\n"):
                if cookie_str.strip():
                    cookie = parse_set_cookie(cookie_str)
                    cookies_found.append(cookie)

        # Also check response.cookies jar
        if response.cookies:
            for cookie_obj in response.cookies:
                cookie = {
                    "name": cookie_obj.name,
                    "value": cookie_obj.value,
                    "secure": cookie_obj.secure,
                    "httponly": cookie_obj.has_nonstandard_attr("httponly") or cookie_obj.has_nonstandard_attr("HttpOnly"),
                    "samesite": None,
                    "domain": cookie_obj.domain,
                    "path": cookie_obj.path,
                    "expires": str(cookie_obj.expires) if cookie_obj.expires else None,
                    "max_age": None,
                    "raw": f"{cookie_obj.name}={cookie_obj.value}; {'Secure; ' if cookie_obj.secure else ''}Domain={cookie_obj.domain}; Path={cookie_obj.path}",
                }
                # Deduplicate by name
                if not any(c.get("name") == cookie["name"] for c in cookies_found):
                    cookies_found.append(cookie)

        if not cookies_found:
            print(f"  No cookies set by {label}")
            continue

        print(f"  Found {len(cookies_found)} cookies:")
        for cookie in cookies_found:
            name = cookie.get("name", "?")
            flags = []
            if cookie.get("secure"):
                flags.append("Secure")
            if cookie.get("httponly"):
                flags.append("HttpOnly")
            if cookie.get("samesite"):
                flags.append(f"SameSite={cookie['samesite']}")
            flag_str = " | ".join(flags) if flags else "NO FLAGS"
            print(f"    • {name} [{flag_str}]")

            cookie_findings = audit_cookie(cookie, url, label)
            all_findings.extend(cookie_findings)
            all_cookies.append((cookie, label))

    # Summary
    if all_cookies:
        total_cookies = len(all_cookies)
        missing_secure = sum(1 for c, _ in all_cookies if not c.get("secure"))
        missing_httponly = sum(1 for c, _ in all_cookies if not c.get("httponly"))
        missing_samesite = sum(1 for c, _ in all_cookies if c.get("samesite") is None)

        print(f"\n  Cookie Security Summary:")
        print(f"    Total cookies: {total_cookies}")
        print(f"    Missing Secure: {missing_secure}")
        print(f"    Missing HttpOnly: {missing_httponly}")
        print(f"    Missing SameSite: {missing_samesite}")

    print(f"\n  Total cookie findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
