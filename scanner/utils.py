"""
Shared utilities for the AS-09 Security Scanner Suite.
Provides common HTTP helpers, logging, result formatting, and configurable targets.
"""

import json
import os
import time
import datetime
import socket
import requests
from urllib.parse import urlparse, urljoin
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── Configurable Target System ─────────────────────────────────────────────
# These are the default targets; they can be overridden via CLI --target flag.
_target_config = {
    "base": "https://app.archscale.in",
    "auth": "https://auth.archscale.in",
    "login": "https://auth.archscale.in/login",
    "hosts": ["app.archscale.in", "auth.archscale.in"],
}


def set_target(url: str):
    """Configure scanning targets from a single base URL."""
    global _target_config
    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    scheme = parsed.scheme or "https"
    base = f"{scheme}://{hostname}"

    _target_config = {
        "base": base,
        "auth": base.replace("app.", "auth.") if "app." in base else base,
        "login": base.replace("app.", "auth.") + "/login" if "app." in base else base + "/login",
        "hosts": [hostname],
    }
    # Add auth hostname if different
    auth_host = hostname.replace("app.", "auth.") if "app." in hostname else hostname
    if auth_host != hostname:
        _target_config["hosts"].append(auth_host)
        _target_config["auth"] = f"{scheme}://{auth_host}"
        _target_config["login"] = f"{scheme}://{auth_host}/login"


def get_target() -> dict:
    """Get current target configuration."""
    return _target_config.copy()


# Legacy compatibility — these read from config so existing modules work
@property
def _tb():
    return _target_config["base"]


TARGET_BASE = _target_config["base"]
AUTH_BASE = _target_config["auth"]
LOGIN_URL = _target_config["login"]


def get_target_base() -> str:
    return _target_config["base"]


def get_auth_base() -> str:
    return _target_config["auth"]


def get_login_url() -> str:
    return _target_config["login"]


def get_target_hosts() -> list[str]:
    return _target_config["hosts"]


# ─── HTTP Configuration ─────────────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}


# ─── Severity Levels ────────────────────────────────────────────────────────
class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @staticmethod
    def color(sev: str) -> str:
        return {
            "critical": "\033[91m",  # Red
            "high": "\033[93m",      # Yellow
            "medium": "\033[33m",    # Orange
            "low": "\033[96m",       # Cyan
            "info": "\033[94m",      # Blue
        }.get(sev, "\033[0m")

    @staticmethod
    def weight(sev: str) -> int:
        return {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}.get(sev, 0)


# ─── Finding Class ───────────────────────────────────────────────────────────
_finding_counter = 0


class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        title: str,
        category: str,
        severity: str,
        description: str,
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        cwe: str = "",
        owasp: str = "",
        url: str = "",
        status: str = "confirmed",
    ):
        global _finding_counter
        _finding_counter += 1
        self.id = f"AS09-{_finding_counter:05d}"
        self.title = title
        self.category = category
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.impact = impact
        self.remediation = remediation
        self.cwe = cwe
        self.owasp = owasp
        self.url = url
        self.status = status
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "url": self.url,
            "status": self.status,
            "timestamp": self.timestamp,
        }


# ─── HTTP Helpers ────────────────────────────────────────────────────────────
def safe_request(
    url: str,
    method: str = "GET",
    allow_redirects: bool = True,
    timeout: int = 15,
    headers: Optional[dict] = None,
    **kwargs,
) -> Optional[requests.Response]:
    """Make an HTTP request with error handling."""
    try:
        merged_headers = {**DEFAULT_HEADERS, **(headers or {})}
        response = requests.request(
            method,
            url,
            headers=merged_headers,
            allow_redirects=allow_redirects,
            timeout=timeout,
            verify=True,
            **kwargs,
        )
        return response
    except requests.exceptions.SSLError as e:
        print(f"  [SSL ERROR] {url}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"  [CONN ERROR] {url}: {e}")
        return None
    except requests.exceptions.Timeout:
        print(f"  [TIMEOUT] {url}")
        return None
    except Exception as e:
        print(f"  [ERROR] {url}: {e}")
        return None


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """Attempt a TCP connection to host:port. Returns (is_open, banner)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        banner = ""
        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            sock.close()
            return True, banner
        sock.close()
        return False, ""
    except Exception:
        return False, ""


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = list(set(r[4][0] for r in results))
        return ips
    except socket.gaierror:
        return []


# ─── Parallel Execution ─────────────────────────────────────────────────────
def run_parallel(tasks: list, max_workers: int = 10) -> list:
    """
    Run a list of (callable, *args) tuples in parallel.
    Returns list of results.
    """
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for task in tasks:
            fn = task[0]
            args = task[1:] if len(task) > 1 else ()
            future = executor.submit(fn, *args)
            futures[future] = task

        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    if isinstance(result, list):
                        results.extend(result)
                    else:
                        results.append(result)
            except Exception as e:
                print(f"  [PARALLEL ERROR] {e}")

    return results


# ─── Output Helpers ──────────────────────────────────────────────────────────
def save_results(filename: str, data: dict) -> str:
    """Save results to JSON file."""
    filepath = os.path.join(RESULTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  [SAVED] {filepath}")
    return filepath


def print_banner(title: str):
    """Print a formatted banner for a scan module."""
    width = 60
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def print_finding(finding: Finding):
    """Print a finding to console."""
    color = Severity.color(finding.severity)
    reset = "\033[0m"
    print(f"\n  {color}[{finding.severity.upper()}]{reset} {finding.title}")
    print(f"    Category: {finding.category}")
    if finding.evidence:
        evidence_preview = finding.evidence[:200] + "..." if len(finding.evidence) > 200 else finding.evidence
        print(f"    Evidence: {evidence_preview}")


def print_progress(current: int, total: int, label: str = ""):
    """Print a simple progress indicator."""
    pct = int((current / total) * 100) if total > 0 else 0
    bar_len = 30
    filled = int(bar_len * current / total) if total > 0 else 0
    bar = "#" * filled + "-" * (bar_len - filled)
    print(f"\r  [{bar}] {pct}% {label}", end="", flush=True)
    if current >= total:
        print()
