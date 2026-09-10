"""
Subdomain Enumeration Module
Discovers subdomains via Certificate Transparency logs, DNS brute-force,
and HTTP probing of discovered hosts.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils import (
    Finding, Severity, safe_request, print_banner, print_finding,
    get_target_hosts, resolve_hostname, print_progress
)

# Common subdomain prefixes to brute-force
COMMON_PREFIXES = [
    "api", "app", "auth", "admin", "beta", "blog", "cdn", "ci", "cms",
    "dashboard", "db", "demo", "dev", "docs", "email", "ftp", "gateway",
    "git", "gitlab", "grafana", "graphql", "help", "hub", "internal",
    "jenkins", "jira", "kibana", "lab", "ldap", "legacy", "login", "logs",
    "mail", "manage", "media", "metrics", "mobile", "monitor", "mq",
    "mysql", "new", "next", "node", "ns", "ns1", "ns2", "old", "ops",
    "panel", "pay", "payment", "portal", "postgres", "preview", "prod",
    "prometheus", "proxy", "queue", "rabbit", "redis", "registry",
    "relay", "remote", "repo", "report", "rest", "sandbox", "search",
    "secure", "sentry", "server", "shop", "smtp", "solr", "sso",
    "stage", "staging", "static", "status", "store", "support", "swagger",
    "sync", "syslog", "test", "testing", "tools", "track", "traefik",
    "tunnel", "upload", "vault", "vpn", "web", "webhook", "websocket",
    "wiki", "worker", "www", "ws",
]


def dns_brute_single(prefix: str, base_domain: str) -> str | None:
    """Check if a single subdomain resolves."""
    subdomain = f"{prefix}.{base_domain}"
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(subdomain, None)
        return subdomain
    except (socket.gaierror, socket.timeout):
        return None


def dns_brute_force(base_domain: str, max_workers: int = 20) -> list[str]:
    """Brute-force subdomains using common prefixes with parallel DNS resolution."""
    found = []
    total = len(COMMON_PREFIXES)

    print(f"\n  Brute-forcing {total} subdomain prefixes for {base_domain}...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(dns_brute_single, prefix, base_domain): prefix
            for prefix in COMMON_PREFIXES
        }

        done_count = 0
        for future in as_completed(futures):
            done_count += 1
            result = future.result()
            if result:
                found.append(result)
                print(f"\r  [FOUND] {result}                    ")
            if done_count % 10 == 0:
                print_progress(done_count, total, f"({len(found)} found)")

    print_progress(total, total, f"({len(found)} found)")
    return sorted(found)


def probe_http(subdomain: str) -> dict | None:
    """Probe a subdomain for HTTP/HTTPS services."""
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            resp = safe_request(url, timeout=5, allow_redirects=True)
            if resp:
                # Extract page title
                title = ""
                if "<title>" in resp.text.lower():
                    import re
                    match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                    if match:
                        title = match.group(1).strip()[:80]

                return {
                    "subdomain": subdomain,
                    "url": resp.url,
                    "status": resp.status_code,
                    "title": title,
                    "server": resp.headers.get("Server", ""),
                    "content_length": len(resp.text),
                    "redirect": resp.url != url,
                }
        except Exception:
            pass
    return None


def ct_log_search(base_domain: str) -> list[str]:
    """Search Certificate Transparency logs via crt.sh."""
    subdomains = set()
    try:
        resp = safe_request(
            f"https://crt.sh/?q=%.{base_domain}&output=json",
            timeout=20,
        )
        if resp and resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(f".{base_domain}") or line == base_domain:
                        if "*" not in line:
                            subdomains.add(line)
    except Exception as e:
        print(f"  [ERROR] CT log search failed: {e}")
    return sorted(subdomains)


def run() -> list[Finding]:
    """Run subdomain enumeration on target domains."""
    print_banner("SUBDOMAIN ENUMERATION")
    all_findings = []

    for host in get_target_hosts():
        base_domain = ".".join(host.split(".")[-2:])
        print(f"\n  === Subdomain Enumeration: {base_domain} ===")

        # 1. CT Log search
        print(f"\n  [1/3] Searching Certificate Transparency logs...")
        ct_subs = ct_log_search(base_domain)
        print(f"  CT logs: {len(ct_subs)} subdomains found")

        # 2. DNS brute-force
        print(f"\n  [2/3] DNS brute-force...")
        brute_subs = dns_brute_force(base_domain)
        print(f"  Brute-force: {len(brute_subs)} subdomains resolved")

        # 3. Combine and deduplicate
        all_subs = sorted(set(ct_subs) | set(brute_subs))
        print(f"\n  [3/3] Total unique subdomains: {len(all_subs)}")

        if not all_subs:
            print("  No subdomains discovered.")
            break  # Only process the base domain once

        # 4. HTTP probe discovered subdomains
        print(f"\n  HTTP probing {len(all_subs)} subdomains...")
        live_hosts = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(probe_http, sub): sub for sub in all_subs[:50]}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    status = result["status"]
                    title = result["title"][:40] if result["title"] else "No title"
                    print(f"    [LIVE] {result['subdomain']} → {status} | {title}")

        # Generate findings
        if live_hosts:
            # Categorize interesting findings
            dev_staging = [h for h in live_hosts if any(
                kw in h["subdomain"] for kw in ["dev", "staging", "test", "beta", "sandbox", "internal", "debug"]
            )]
            admin_panels = [h for h in live_hosts if any(
                kw in h["subdomain"] for kw in ["admin", "panel", "manage", "dashboard", "jenkins", "grafana", "kibana"]
            )]
            api_endpoints = [h for h in live_hosts if any(
                kw in h["subdomain"] for kw in ["api", "rest", "graphql", "gateway", "webhook"]
            )]

            if dev_staging:
                finding = Finding(
                    title=f"Dev/staging subdomains publicly accessible for {base_domain}",
                    category="Subdomain Enumeration",
                    severity=Severity.HIGH,
                    description=f"Development or staging subdomains were found accessible: "
                                f"{', '.join(h['subdomain'] for h in dev_staging)}. "
                                f"These environments often have weaker security controls.",
                    evidence="\n".join(
                        f"{h['subdomain']} → {h['status']} | {h['title']}" for h in dev_staging
                    ),
                    impact="Dev/staging environments may expose unreleased features, debug endpoints, or test credentials",
                    remediation="Restrict dev/staging access via VPN, IP allowlisting, or authentication. Remove unnecessary DNS records.",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    url=dev_staging[0]["url"],
                )
                all_findings.append(finding)
                print_finding(finding)

            if admin_panels:
                finding = Finding(
                    title=f"Admin/management subdomains exposed for {base_domain}",
                    category="Subdomain Enumeration",
                    severity=Severity.MEDIUM,
                    description=f"Administrative subdomains found: "
                                f"{', '.join(h['subdomain'] for h in admin_panels)}",
                    evidence="\n".join(
                        f"{h['subdomain']} → {h['status']} | {h['title']}" for h in admin_panels
                    ),
                    impact="Admin panels may be targeted for brute-force or exploit attacks",
                    remediation="Protect admin subdomains with VPN access, IP restrictions, and multi-factor authentication",
                    cwe="CWE-200",
                    owasp="A01:2021 Broken Access Control",
                    url=admin_panels[0]["url"],
                )
                all_findings.append(finding)
                print_finding(finding)

            # General enumeration finding
            finding = Finding(
                title=f"Subdomain enumeration discovered {len(all_subs)} subdomains ({len(live_hosts)} live)",
                category="Subdomain Enumeration",
                severity=Severity.INFO,
                description=f"Subdomain enumeration of {base_domain} discovered {len(all_subs)} unique subdomains, "
                            f"of which {len(live_hosts)} responded to HTTP requests.",
                evidence=f"Sources: CT logs ({len(ct_subs)}), DNS brute-force ({len(brute_subs)})\n"
                         f"Live hosts:\n" + "\n".join(
                    f"  {h['subdomain']} → {h['status']} | {h.get('server', 'Unknown')}" for h in live_hosts[:15]
                ),
                impact="Each live subdomain represents a potential attack surface entry point",
                remediation="Review all discovered subdomains. Decommission unused services. Ensure all subdomains have proper security controls.",
                cwe="CWE-200",
                owasp="A05:2021 Security Misconfiguration",
                url=f"https://crt.sh/?q={base_domain}",
            )
            all_findings.append(finding)
            print_finding(finding)

        break  # Only enumerate base domain once

    print(f"\n  Total subdomain findings: {len(all_findings)}")
    return all_findings


if __name__ == "__main__":
    results = run()
    print(f"\nCompleted. Found {len(results)} issues.")
