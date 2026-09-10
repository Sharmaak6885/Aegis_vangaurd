"""
AS-09 Security Scanner — Main Orchestrator v2.0
Runs all security scan modules in parallel and produces unified findings + HTML report.

Usage:
    python main.py                                          # Default scan
    python main.py --target https://example.com             # Custom target
    python main.py --modules headers,cors,ssl               # Select modules
    python main.py --format both                            # JSON + HTML output
    python main.py --threads 10                             # Parallel threads
    python main.py --help                                   # Show all options
"""

import argparse
import json
import sys
import os
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add scanner directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import Finding, save_results, print_banner, set_target, get_target, RESULTS_DIR

# Import all scanner modules
import header_auditor
import redirect_tester
import oauth_analyzer
import info_disclosure
import cors_tester
import ssl_analyzer
import dns_recon
import subdomain_enum
import port_scanner
import tech_fingerprint
import cookie_auditor
import csp_analyzer
import rate_limiter
import error_analyzer
import report_generator


# ─── All available scanner modules ──────────────────────────────────────────
ALL_MODULES = {
    "headers":      ("Security Headers",          header_auditor),
    "redirects":    ("Open Redirects",             redirect_tester),
    "oauth":        ("OAuth Flow",                 oauth_analyzer),
    "info":         ("Information Disclosure",      info_disclosure),
    "cors":         ("CORS Configuration",          cors_tester),
    "ssl":          ("SSL/TLS",                     ssl_analyzer),
    "dns":          ("DNS Reconnaissance",          dns_recon),
    "subdomains":   ("Subdomain Enumeration",       subdomain_enum),
    "ports":        ("Port Scanner",                port_scanner),
    "tech":         ("Technology Fingerprinting",   tech_fingerprint),
    "cookies":      ("Cookie Security",             cookie_auditor),
    "csp":          ("CSP Analysis",                csp_analyzer),
    "ratelimit":    ("Rate Limiting",               rate_limiter),
    "errors":       ("Error Handling",              error_analyzer),
}


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AS-09 Security Audit Scanner — Comprehensive security assessment platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    Full scan with defaults
  python main.py --target https://example.com       Scan custom target
  python main.py --modules headers,cors,ssl         Run specific modules
  python main.py --format html                      Generate HTML report only
  python main.py --threads 10 --verbose             Parallel scan with verbose output

Available modules:
  """ + "\n  ".join(f"{k:<12} {v[0]}" for k, v in ALL_MODULES.items()),
    )

    parser.add_argument(
        "--target", "-t",
        default="https://app.archscale.in",
        help="Target URL to scan (default: https://app.archscale.in)",
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        help="Comma-separated list of modules to run, or 'all' (default: all)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "html", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory (default: ../results)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of parallel scanner threads (default: 5)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )

    return parser.parse_args()


def calculate_security_score(findings: list[dict]) -> dict:
    """Calculate an overall security score based on findings."""
    severity_weights = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }

    total_deductions = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_deductions += severity_weights.get(sev, 0)

    score = max(0, 100 - total_deductions)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "deductions": total_deductions,
    }


def generate_surface_map(findings: list[dict]) -> dict:
    """Generate attack surface data from findings."""
    domains = set()
    endpoints = set()
    categories = {}

    for f in findings:
        url = f.get("url", "")
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc)
            endpoints.add(url)

        cat = f.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"count": 0, "severities": []}
        categories[cat]["count"] += 1
        categories[cat]["severities"].append(f.get("severity", "info"))

    target = get_target()
    return {
        "domains": list(domains),
        "endpoint_count": len(endpoints),
        "categories": categories,
        "technologies_detected": [],  # Will be populated by tech_fingerprint module
        "attack_vectors": [
            {"name": "Authentication Surface", "endpoints": [f"{target['auth']}/login", f"{target['auth']}/auth/forgot-password"], "risk": "high"},
            {"name": "OAuth Integration", "endpoints": ["Google OAuth flow", "OAuth callback"], "risk": "medium"},
            {"name": "Client-Side Assets", "endpoints": ["JavaScript bundles", "Source maps", "Static files"], "risk": "low"},
            {"name": "API Surface", "endpoints": ["Unauthenticated API endpoints"], "risk": "high"},
            {"name": "Infrastructure", "endpoints": ["SSL/TLS", "DNS", "HTTP headers"], "risk": "medium"},
            {"name": "DNS/Subdomains", "endpoints": ["CT logs", "DNS brute-force", "Zone transfers"], "risk": "medium"},
            {"name": "Network Services", "endpoints": ["TCP ports", "Service banners"], "risk": "medium"},
        ],
    }


def run_module(name: str, label: str, module) -> tuple[str, list[Finding], float]:
    """Run a single scanner module and return (name, findings, duration)."""
    start = time.time()
    try:
        findings = module.run()
        duration = time.time() - start
        return name, findings, duration
    except Exception as e:
        duration = time.time() - start
        print(f"\n  [FAIL] {label} failed: {e}")
        import traceback
        traceback.print_exc()
        return name, [], duration


def main():
    """Run all security scanners and compile results."""
    args = parse_args()
    start_time = time.time()

    # Configure target
    set_target(args.target)
    target = get_target()

    # Determine output directory
    output_dir = args.output or RESULTS_DIR
    os.makedirs(output_dir, exist_ok=True)

    # Determine modules to run
    if args.modules == "all":
        modules_to_run = list(ALL_MODULES.items())
    else:
        module_names = [m.strip() for m in args.modules.split(",")]
        modules_to_run = []
        for name in module_names:
            if name in ALL_MODULES:
                modules_to_run.append((name, ALL_MODULES[name]))
            else:
                print(f"  [WARN] Unknown module: {name}")
                print(f"  Available: {', '.join(ALL_MODULES.keys())}")

    if not modules_to_run:
        print("  No valid modules selected. Use --help for options.")
        sys.exit(1)

    # Print banner
    print("\n" + "=" * 70)
    print("  +============================================================+")
    print("  |          AS-09 Security Audit Scanner v2.0                  |")
    print("  |          Multi-Tenant Security Assessment Platform          |")
    print("  +============================================================+")
    print("=" * 70)
    print(f"\n  Target:    {target['base']}")
    print(f"  Auth:      {target['auth']}")
    print(f"  Modules:   {len(modules_to_run)} / {len(ALL_MODULES)}")
    print(f"  Threads:   {args.threads}")
    print(f"  Format:    {args.format}")
    print(f"  Output:    {output_dir}")

    all_findings: list[Finding] = []
    module_results = {}

    # Run modules in parallel
    print(f"\n{'-' * 70}")
    print(f"  Starting {len(modules_to_run)} scanner modules...")
    print(f"{'-' * 70}")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {}
        for key, (label, module) in modules_to_run:
            future = executor.submit(run_module, key, label, module)
            futures[future] = (key, label)

        completed = 0
        for future in as_completed(futures):
            completed += 1
            key, label = futures[future]
            name, findings, duration = future.result()

            all_findings.extend(findings)
            module_results[name] = {
                "label": label,
                "findings_count": len(findings),
                "duration": round(duration, 2),
            }

            status = "OK" if findings is not None else "FAIL"
            print(f"\n  [{completed}/{len(modules_to_run)}] {status} {label}: "
                  f"{len(findings)} findings ({duration:.1f}s)")

    # Convert findings to dicts
    findings_dicts = [f.to_dict() if isinstance(f, Finding) else f for f in all_findings]

    # Calculate security score
    score_data = calculate_security_score(findings_dicts)

    # Generate surface map
    surface_map = generate_surface_map(findings_dicts)

    # Extract technologies from tech fingerprint findings
    for f in findings_dicts:
        if f.get("category") == "Technology Fingerprinting" and "technologies detected" in f.get("title", "").lower():
            # Parse technologies from evidence
            for line in f.get("evidence", "").split("\n"):
                if line.strip().startswith("•"):
                    tech = line.strip().lstrip("•").split("(")[0].strip()
                    if tech and tech not in surface_map["technologies_detected"]:
                        surface_map["technologies_detected"].append(tech)

    # Compile final report
    elapsed = time.time() - start_time
    report = {
        "meta": {
            "tool": "AS-09 Security Audit Scanner",
            "version": "2.0.0",
            "target": target["base"],
            "auth_domain": target["auth"],
            "scope": "Comprehensive multi-tenant security assessment",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "duration_seconds": round(elapsed, 2),
            "scanner_modules": [label for _, (label, _) in modules_to_run],
            "module_results": module_results,
        },
        "executive_summary": {
            "scope_statement": (
                "This assessment evaluates the security posture of the ArchScale multi-tenant platform. "
                "It covers authentication surfaces, OAuth configuration, HTTP security headers, SSL/TLS, "
                "CORS policies, DNS infrastructure, subdomain enumeration, port scanning, technology fingerprinting, "
                "cookie security, Content Security Policy, rate limiting, and error handling."
            ),
            "security_score": score_data,
            "key_risks": [],
        },
        "surface_map": surface_map,
        "findings": findings_dicts,
        "hardening": {
            "immediate": [],
            "short_term": [],
            "long_term": [],
        },
    }

    # Categorize key risks and hardening recommendations
    for f in sorted(findings_dicts,
                    key=lambda x: ["critical", "high", "medium", "low", "info"].index(
                        x.get("severity", "info"))):
        sev = f.get("severity", "info")
        if sev in ("critical", "high"):
            report["executive_summary"]["key_risks"].append({
                "title": f["title"],
                "severity": sev,
                "category": f["category"],
            })
            report["hardening"]["immediate"].append({
                "finding_id": f["id"],
                "title": f["title"],
                "action": f["remediation"],
                "priority": "P0" if sev == "critical" else "P1",
            })
        elif sev == "medium":
            report["hardening"]["short_term"].append({
                "finding_id": f["id"],
                "title": f["title"],
                "action": f["remediation"],
                "priority": "P2",
            })
        else:
            report["hardening"]["long_term"].append({
                "finding_id": f["id"],
                "title": f["title"],
                "action": f["remediation"],
                "priority": "P3" if sev == "low" else "P4",
            })

    # Save results
    if args.format in ("json", "both"):
        json_path = os.path.join(output_dir, "findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  [SAVED] JSON report: {json_path}")

        # Also save for dashboard
        dashboard_data_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "dashboard", "public", "data"
        )
        os.makedirs(dashboard_data_dir, exist_ok=True)
        dashboard_path = os.path.join(dashboard_data_dir, "findings.json")
        with open(dashboard_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  [SAVED] Dashboard data: {dashboard_path}")

    if args.format in ("html", "both"):
        html_path = os.path.join(output_dir, "report.html")
        report_generator.generate_html_report(report, html_path)

    # Print summary
    print("\n" + "=" * 70)
    print("  +============================================================+")
    print("  |                    SCAN COMPLETE                            |")
    print("  +============================================================+")
    print("=" * 70)
    print(f"\n  Duration:        {elapsed:.1f}s")
    print(f"  Modules Run:     {len(modules_to_run)}")
    print(f"  Security Score:  {score_data['score']}/100 (Grade: {score_data['grade']})")
    print(f"  Total Findings:  {score_data['total_findings']}")
    print(f"    Critical:      {score_data['severity_counts']['critical']}")
    print(f"    High:          {score_data['severity_counts']['high']}")
    print(f"    Medium:        {score_data['severity_counts']['medium']}")
    print(f"    Low:           {score_data['severity_counts']['low']}")
    print(f"    Info:          {score_data['severity_counts']['info']}")
    print(f"\n  Results:         {output_dir}")
    print()


if __name__ == "__main__":
    main()
