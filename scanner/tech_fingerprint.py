"""
Technology Fingerprinting Module
Detects web frameworks, servers, CDNs, WAFs, and maps versions to known CVEs.
"""

import re
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_base, get_auth_base, get_login_url
)

# Technology signatures: (header/pattern -> technology)
HEADER_SIGNATURES = {
    "Server": {
        "nginx": ("nginx", "Web Server"),
        "apache": ("Apache HTTP Server", "Web Server"),
        "microsoft-iis": ("Microsoft IIS", "Web Server"),
        "cloudflare": ("Cloudflare", "CDN/WAF"),
        "gunicorn": ("Gunicorn", "Python WSGI Server"),
        "uvicorn": ("Uvicorn", "Python ASGI Server"),
        "express": ("Express.js", "Node.js Framework"),
        "openresty": ("OpenResty", "Nginx+Lua"),
        "cowboy": ("Cowboy", "Erlang HTTP Server"),
        "caddy": ("Caddy", "Web Server"),
    },
    "X-Powered-By": {
        "express": ("Express.js", "Node.js Framework"),
        "asp.net": ("ASP.NET", "Microsoft Framework"),
        "php": ("PHP", "Server-Side Language"),
        "next.js": ("Next.js", "React Framework"),
        "nuxt": ("Nuxt.js", "Vue Framework"),
        "django": ("Django", "Python Framework"),
        "flask": ("Flask", "Python Framework"),
        "rails": ("Ruby on Rails", "Ruby Framework"),
        "laravel": ("Laravel", "PHP Framework"),
    },
    "X-Frame-Options": {},
    "Via": {
        "cloudfront": ("AWS CloudFront", "CDN"),
        "akamai": ("Akamai", "CDN"),
        "fastly": ("Fastly", "CDN"),
        "varnish": ("Varnish", "Cache/CDN"),
    },
}

# Cookie-based detection
COOKIE_SIGNATURES = {
    "__next": ("Next.js", "React Framework"),
    "JSESSIONID": ("Java", "Server-Side"),
    "laravel_session": ("Laravel", "PHP Framework"),
    "csrftoken": ("Django", "Python Framework"),
    "rack.session": ("Ruby/Rack", "Ruby Framework"),
    "connect.sid": ("Express.js", "Node.js Framework"),
    "_rails": ("Ruby on Rails", "Ruby Framework"),
    "PHPSESSID": ("PHP", "Server-Side"),
    "ASP.NET": ("ASP.NET", "Microsoft Framework"),
    "wordpress_": ("WordPress", "CMS"),
    "wp-": ("WordPress", "CMS"),
    "_gh_sess": ("GitHub", "Git Platform"),
}

# HTML/JS-based detection
HTML_SIGNATURES = [
    (r'<meta[^>]*generator[^>]*content="WordPress', "WordPress", "CMS", Severity.INFO),
    (r'<meta[^>]*generator[^>]*content="Drupal', "Drupal", "CMS", Severity.INFO),
    (r'<meta[^>]*generator[^>]*content="Joomla', "Joomla", "CMS", Severity.INFO),
    (r'__NEXT_DATA__', "Next.js", "React Framework", Severity.INFO),
    (r'__NUXT__', "Nuxt.js", "Vue Framework", Severity.INFO),
    (r'ng-version="', "Angular", "Frontend Framework", Severity.INFO),
    (r'data-reactroot', "React", "Frontend Library", Severity.INFO),
    (r'data-v-[a-f0-9]{8}', "Vue.js", "Frontend Framework", Severity.INFO),
    (r'data-svelte', "Svelte", "Frontend Framework", Severity.INFO),
    (r'ember-view', "Ember.js", "Frontend Framework", Severity.INFO),
    (r'wp-content/', "WordPress", "CMS", Severity.INFO),
    (r'wp-includes/', "WordPress", "CMS", Severity.INFO),
    (r'jquery[.-](\d+\.\d+\.\d+)', "jQuery", "JavaScript Library", Severity.INFO),
    (r'bootstrap[.-](\d+\.\d+\.\d+)', "Bootstrap", "CSS Framework", Severity.INFO),
    (r'_next/static', "Next.js", "React Framework", Severity.INFO),
    (r'gatsby-', "Gatsby", "React Framework", Severity.INFO),
    (r'remix-', "Remix", "React Framework", Severity.INFO),
    (r'firebase', "Firebase", "Google Cloud", Severity.INFO),
    (r'supabase', "Supabase", "Backend Platform", Severity.INFO),
    (r'clerk\.', "Clerk", "Auth Provider", Severity.INFO),
    (r'auth0', "Auth0", "Auth Provider", Severity.INFO),
    (r'google-analytics|gtag\(', "Google Analytics", "Analytics", Severity.INFO),
    (r'hotjar', "Hotjar", "Analytics", Severity.INFO),
    (r'sentry', "Sentry", "Error Monitoring", Severity.INFO),
    (r'cloudflare', "Cloudflare", "CDN/WAF", Severity.INFO),
]

# WAF detection signatures
WAF_SIGNATURES = [
    ("cf-ray", "header", "Cloudflare WAF"),
    ("cf-cache-status", "header", "Cloudflare"),
    ("x-sucuri-id", "header", "Sucuri WAF"),
    ("x-sucuri-cache", "header", "Sucuri WAF"),
    ("x-aws-waf", "header", "AWS WAF"),
    ("x-amz-cf-id", "header", "AWS CloudFront"),
    ("x-azure-ref", "header", "Azure CDN"),
    ("x-akamai-transformed", "header", "Akamai"),
    ("server: AkamaiGHost", "header", "Akamai"),
    ("x-cdn", "header", "Generic CDN"),
    ("x-cache", "header", "Cache/CDN Layer"),
    ("x-vercel-id", "header", "Vercel"),
    ("x-vercel-cache", "header", "Vercel"),
    ("x-render-origin-server", "header", "Render"),
    ("x-fly-request-id", "header", "Fly.io"),
]

# Known CVEs by technology (simplified local database)
KNOWN_CVES = {
    "jQuery": {
        "1.x": ["CVE-2019-11358 (Prototype pollution)", "CVE-2020-11022 (XSS via htmlPrefilter)"],
        "2.x": ["CVE-2019-11358 (Prototype pollution)", "CVE-2020-11022 (XSS via htmlPrefilter)"],
        "3.0": ["CVE-2019-11358 (Prototype pollution)"],
    },
    "WordPress": {
        "*": ["Check WPScan for version-specific CVEs"],
    },
    "Angular": {
        "1.x": ["CVE-2020-7676 (XSS in $sanitize)", "Multiple sandbox escapes"],
    },
    "Apache HTTP Server": {
        "2.4.49": ["CVE-2021-41773 (Path traversal)"],
        "2.4.50": ["CVE-2021-42013 (Path traversal bypass)"],
    },
    "nginx": {
        "1.16": ["CVE-2019-20372 (HTTP request smuggling)"],
    },
}


def detect_from_headers(headers: dict) -> list[tuple[str, str, str]]:
    """Detect technologies from HTTP response headers."""
    detected = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_name, signatures in HEADER_SIGNATURES.items():
        value = headers_lower.get(header_name.lower(), "").lower()
        if value:
            for pattern, (tech, category) in signatures.items():
                if pattern in value:
                    version = ""
                    # Try to extract version
                    ver_match = re.search(r'[\d]+\.[\d]+(?:\.[\d]+)?', headers.get(header_name, ""))
                    if ver_match:
                        version = ver_match.group()
                    detected.append((tech, category, version))

    return detected


def detect_from_cookies(cookies: dict) -> list[tuple[str, str]]:
    """Detect technologies from cookie names."""
    detected = []
    for cookie_name in cookies:
        for pattern, (tech, category) in COOKIE_SIGNATURES.items():
            if pattern.lower() in cookie_name.lower():
                detected.append((tech, category))
    return detected


def detect_waf(headers: dict) -> list[str]:
    """Detect WAF/CDN presence from headers."""
    wafs = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for signature, sig_type, waf_name in WAF_SIGNATURES:
        if sig_type == "header":
            sig_lower = signature.lower()
            if ":" in sig_lower:
                key, val = sig_lower.split(":", 1)
                if key.strip() in headers_lower and val.strip() in headers_lower.get(key.strip(), ""):
                    wafs.append(waf_name)
            else:
                if sig_lower in headers_lower:
                    wafs.append(waf_name)

    return list(set(wafs))


def run() -> list[Finding]:
    """Run technology fingerprinting on all targets."""
    print_banner("TECHNOLOGY FINGERPRINTING")
    all_findings = []
    all_tech = {}  # {tech: {category, version, sources}}

    targets = [
        (get_target_base(), "Main Application"),
        (get_auth_base(), "Auth Service"),
        (get_login_url(), "Login Page"),
    ]

    for url, label in targets:
        print(f"\n  === Fingerprinting: {url} ({label}) ===")

        response = safe_request(url, timeout=10)
        if not response:
            print(f"  [SKIP] Could not reach {url}")
            continue

        # 1. Header-based detection
        print(f"  Checking headers...")
        header_techs = detect_from_headers(dict(response.headers))
        for tech, category, version in header_techs:
            key = tech
            if key not in all_tech:
                all_tech[key] = {"category": category, "version": version, "sources": []}
            all_tech[key]["sources"].append(f"{label} (header)")
            print(f"    [HEADER] {tech} {version} ({category})")

        # 2. Cookie-based detection
        if response.cookies:
            print(f"  Checking cookies...")
            cookie_techs = detect_from_cookies(dict(response.cookies))
            for tech, category in cookie_techs:
                if tech not in all_tech:
                    all_tech[tech] = {"category": category, "version": "", "sources": []}
                all_tech[tech]["sources"].append(f"{label} (cookie)")
                print(f"    [COOKIE] {tech} ({category})")

        # 3. HTML/JS-based detection
        print(f"  Scanning page content...")
        for pattern, tech, category, _ in HTML_SIGNATURES:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                version = ""
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)
                if tech not in all_tech:
                    all_tech[tech] = {"category": category, "version": version, "sources": []}
                elif version and not all_tech[tech]["version"]:
                    all_tech[tech]["version"] = version
                all_tech[tech]["sources"].append(f"{label} (html)")
                print(f"    [HTML] {tech} {version} ({category})")

        # 4. WAF detection
        print(f"  Detecting WAF/CDN...")
        wafs = detect_waf(dict(response.headers))
        for waf in wafs:
            if waf not in all_tech:
                all_tech[waf] = {"category": "WAF/CDN", "version": "", "sources": []}
            all_tech[waf]["sources"].append(f"{label} (waf)")
            print(f"    [WAF] {waf}")

    # Generate findings
    if all_tech:
        # Summary finding
        tech_list = "\n".join(
            f"  • {tech} {info['version']} ({info['category']}) — detected in: {', '.join(set(info['sources']))}"
            for tech, info in sorted(all_tech.items())
        )

        all_findings.append(Finding(
            title=f"Technology fingerprint: {len(all_tech)} technologies detected",
            category="Technology Fingerprinting",
            severity=Severity.INFO,
            description=f"Technology fingerprinting detected {len(all_tech)} technologies across all scanned endpoints.",
            evidence=tech_list,
            impact="Technology fingerprint helps attackers identify version-specific vulnerabilities and tailor their attacks",
            remediation="Remove version information from response headers. Suppress X-Powered-By. Configure Server header to be generic.",
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            url=get_target_base(),
        ))

        # Check for version disclosure
        version_disclosed = {
            tech: info for tech, info in all_tech.items()
            if info["version"] and info["category"] not in ("Analytics", "CDN/WAF")
        }
        if version_disclosed:
            finding = Finding(
                title=f"Software version numbers disclosed ({len(version_disclosed)} technologies)",
                category="Technology Fingerprinting",
                severity=Severity.LOW,
                description="Specific software version numbers are exposed in HTTP headers or page content. "
                            "This allows attackers to identify exact CVEs for the deployed versions.",
                evidence="\n".join(
                    f"  {tech}: {info['version']} ({info['category']})"
                    for tech, info in version_disclosed.items()
                ),
                impact="Version-specific CVE exploitation becomes possible with known software versions",
                remediation="Remove version numbers from all HTTP response headers and page content",
                cwe="CWE-200",
                owasp="A05:2021 Security Misconfiguration",
                url=get_target_base(),
            )
            all_findings.append(finding)
            print_finding(finding)

        # Check for known CVEs
        for tech, info in all_tech.items():
            if tech in KNOWN_CVES and info["version"]:
                ver_prefix = info["version"].split(".")[0] + ".x"
                cves = KNOWN_CVES[tech].get(ver_prefix, KNOWN_CVES[tech].get("*", []))
                if cves:
                    finding = Finding(
                        title=f"Known CVEs for {tech} {info['version']}",
                        category="Technology Fingerprinting",
                        severity=Severity.MEDIUM,
                        description=f"{tech} version {info['version']} has known vulnerabilities that may be exploitable.",
                        evidence=f"Technology: {tech} {info['version']}\nKnown CVEs:\n" + "\n".join(f"  • {c}" for c in cves),
                        impact="Exploitation of known CVEs could lead to unauthorized access or data theft",
                        remediation=f"Update {tech} to the latest stable version. Apply security patches.",
                        cwe="CWE-1104",
                        owasp="A06:2021 Vulnerable and Outdated Components",
                        url=get_target_base(),
                    )
                    all_findings.append(finding)
                    print_finding(finding)

        # WAF findings
        wafs_found = [tech for tech, info in all_tech.items() if info["category"] == "WAF/CDN"]
        if wafs_found:
            all_findings.append(Finding(
                title=f"WAF/CDN detected: {', '.join(wafs_found)}",
                category="Technology Fingerprinting",
                severity=Severity.INFO,
                description=f"Web Application Firewall or CDN detected: {', '.join(wafs_found)}. "
                            f"This may filter malicious requests and provide DDoS protection.",
                evidence=f"Detected: {', '.join(wafs_found)}",
                impact="WAF presence indicates an additional security layer, but may provide false sense of security if misconfigured",
                remediation="Ensure WAF rules are properly configured. Regularly update WAF signatures.",
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                url=get_target_base(),
            ))
        else:
            all_findings.append(Finding(
                title="No WAF/CDN detected",
                category="Technology Fingerprinting",
                severity=Severity.MEDIUM,
                description="No Web Application Firewall (WAF) or CDN was detected protecting the application. "
                            "Without a WAF, the application relies solely on its own input validation.",
                evidence="No WAF signatures found in response headers",
                impact="Application is directly exposed to common web attacks (SQLi, XSS, etc.) without an additional filtering layer",
                remediation="Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity) in front of the application",
                cwe="CWE-693",
                owasp="A05:2021 Security Misconfiguration",
                url=get_target_base(),
            ))

    print(f"\n  Total fingerprinting findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
