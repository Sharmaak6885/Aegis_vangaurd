"""
HTML Report Generator
Generates a professional, self-contained HTML security report from scan findings.
"""

import os
import json
import datetime


def generate_html_report(report_data: dict, output_path: str) -> str:
    """Generate a self-contained HTML report from scan data."""

    findings = report_data.get("findings", [])
    meta = report_data.get("meta", {})
    score_data = report_data.get("executive_summary", {}).get("security_score", {})
    surface = report_data.get("surface_map", {})
    hardening = report_data.get("hardening", {})
    key_risks = report_data.get("executive_summary", {}).get("key_risks", [])

    score = score_data.get("score", 0)
    grade = score_data.get("grade", "?")
    counts = score_data.get("severity_counts", {})

    score_color = "#22c55e" if score >= 75 else "#eab308" if score >= 50 else "#f97316" if score >= 25 else "#ef4444"

    severity_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280",
    }

    # Load patch files
    scanner_dir = os.path.dirname(os.path.abspath(__file__))
    patches = {}
    patch_mapping = {
        "Rate Limiting": "rate-limit.ts",
        "Security Headers": "security-headers.ts",
        "CORS Configuration": "cors-config.ts",
        "Cookie Security": "cookie-config.ts",
        "CSP Analysis": "csp-nextjs.ts",
        "Error Handling": "nginx-hardening.conf",
        "Information Disclosure": "nginx-hardening.conf",
    }
    for category, filename in patch_mapping.items():
        try:
            with open(os.path.join(scanner_dir, "patches", filename), "r") as f:
                patches[category] = f.read()
        except FileNotFoundError:
            pass

    # Build findings rows
    findings_html = ""
    for i, f in enumerate(findings):
        sev = f.get("severity", "info")
        color = severity_colors.get(sev, "#6b7280")
        
        patch_html = ""
        cat = f.get("category", "")
        if cat in patches:
            patch_html = f"<div><strong>Recommended Patch ({patch_mapping[cat]}):</strong><pre>{patches[cat]}</pre></div>"

        findings_html += f"""
        <tr class="finding-row" onclick="this.nextElementSibling.classList.toggle('hidden')">
            <td><span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{sev.upper()}</span></td>
            <td>{f.get('title', '')}</td>
            <td>{cat}</td>
            <td><code>{f.get('cwe', 'N/A')}</code></td>
        </tr>
        <tr class="finding-detail hidden">
            <td colspan="4">
                <div class="detail-grid">
                    <div><strong>Description:</strong> {f.get('description', '')}</div>
                    <div><strong>Evidence:</strong> <pre>{f.get('evidence', 'N/A')}</pre></div>
                    {patch_html}
                    <div><strong>Impact:</strong> {f.get('impact', '')}</div>
                    <div><strong>Remediation:</strong> {f.get('remediation', '')}</div>
                    <div><strong>OWASP:</strong> {f.get('owasp', 'N/A')} | <strong>URL:</strong> <a href="{f.get('url', '#')}" target="_blank">{f.get('url', 'N/A')}</a></div>
                </div>
            </td>
        </tr>"""

    # Hardening items
    hardening_html = ""
    for priority, items in [("Immediate (P0/P1)", hardening.get("immediate", [])),
                             ("Short-term (P2)", hardening.get("short_term", [])),
                             ("Long-term (P3/P4)", hardening.get("long_term", []))]:
        if items:
            hardening_html += f"<h3>{priority}</h3><ul>"
            for item in items:
                hardening_html += f"<li><strong>{item.get('title', '')}</strong>: {item.get('action', '')}</li>"
            hardening_html += "</ul>"

    # Technologies
    tech_html = "".join(
        f'<span class="tech-tag">{t}</span>' for t in surface.get("technologies_detected", [])
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis Vanguard Report — {meta.get('target', 'Target')}</title>
<style>
:root {{
    --bg: #0a0a0f;
    --bg-card: #111118;
    --bg-elevated: #1a1a24;
    --border: #2a2a3a;
    --text: #e4e4ef;
    --text-muted: #6b6b80;
    --accent: #3b82f6;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    font-size: 14px;
}}
.container {{ max-width: 1200px; margin: 0 auto; padding: 40px 24px; }}
h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 8px; }}
h2 {{ font-size: 20px; font-weight: 600; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
h3 {{ font-size: 16px; font-weight: 600; margin: 16px 0 8px; }}
.subtitle {{ color: var(--text-muted); font-size: 13px; }}
.meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin: 24px 0;
}}
.meta-item {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
}}
.meta-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 4px; }}
.meta-value {{ font-size: 18px; font-weight: 700; }}
.score-section {{
    display: flex;
    align-items: center;
    gap: 32px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px;
    margin: 24px 0;
}}
.score-ring {{
    width: 120px;
    height: 120px;
    flex-shrink: 0;
}}
.score-details {{ flex: 1; }}
.sev-bar {{
    display: flex;
    gap: 8px;
    margin-top: 12px;
}}
.sev-item {{
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
}}
.sev-dot {{
    width: 10px;
    height: 10px;
    border-radius: 50%;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
}}
th {{
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-elevated);
    border-bottom: 2px solid var(--border);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
}}
td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}
.finding-row {{ cursor: pointer; transition: background 0.15s; }}
.finding-row:hover {{ background: var(--bg-elevated); }}
.finding-detail {{ background: var(--bg-card); }}
.finding-detail.hidden {{ display: none; }}
.detail-grid {{ display: grid; gap: 8px; padding: 8px 0; font-size: 13px; }}
.detail-grid pre {{
    background: var(--bg);
    padding: 8px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
}}
.sev-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
code {{
    background: var(--bg-elevated);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 12px;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.tech-tag {{
    display: inline-block;
    padding: 4px 12px;
    background: var(--bg-elevated);
    border: 1px solid var(--border);
    border-radius: 20px;
    font-size: 12px;
    margin: 4px;
}}
ul {{ padding-left: 20px; }}
li {{ margin: 4px 0; }}
.risk-list {{ list-style: none; padding: 0; }}
.risk-item {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin: 6px 0;
}}
.footer {{
    margin-top: 48px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 12px;
    text-align: center;
}}
@media print {{
    body {{ background: white; color: black; font-size: 11px; }}
    .container {{ max-width: 100%; padding: 20px; }}
    .finding-detail {{ display: table-row !important; }}
    .finding-detail.hidden {{ display: table-row !important; }}
    .score-section, .meta-item {{ border-color: #ddd; }}
    h2 {{ page-break-before: always; }}
}}
</style>
</head>
<body>
<div class="container">
    <h1>🛡️ Aegis Vanguard Report</h1>
    <p class="subtitle">
        Target: <strong>{meta.get('target', 'N/A')}</strong> |
        Auth: <strong>{meta.get('auth_domain', 'N/A')}</strong> |
        Scope: {meta.get('scope', 'N/A')} |
        Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </p>

    <!-- Score Section -->
    <div class="score-section">
        <svg class="score-ring" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="#2a2a3a" stroke-width="6"/>
            <circle cx="50" cy="50" r="42" fill="none" stroke="{score_color}" stroke-width="6"
                    stroke-linecap="round" stroke-dasharray="{2 * 3.14159 * 42}"
                    stroke-dashoffset="{2 * 3.14159 * 42 * (1 - score / 100)}"
                    transform="rotate(-90 50 50)"/>
            <text x="50" y="45" text-anchor="middle" font-size="24" font-weight="700" fill="{score_color}">{grade}</text>
            <text x="50" y="62" text-anchor="middle" font-size="10" fill="#6b6b80">{score}/100</text>
        </svg>
        <div class="score-details">
            <h2 style="margin:0;border:none;">Security Score</h2>
            <p style="color:var(--text-muted);">{score_data.get('total_findings', 0)} findings across {len(meta.get('scanner_modules', []))} scanner modules</p>
            <div class="sev-bar">
                <div class="sev-item"><span class="sev-dot" style="background:#ef4444"></span>Critical: {counts.get('critical', 0)}</div>
                <div class="sev-item"><span class="sev-dot" style="background:#f97316"></span>High: {counts.get('high', 0)}</div>
                <div class="sev-item"><span class="sev-dot" style="background:#eab308"></span>Medium: {counts.get('medium', 0)}</div>
                <div class="sev-item"><span class="sev-dot" style="background:#3b82f6"></span>Low: {counts.get('low', 0)}</div>
                <div class="sev-item"><span class="sev-dot" style="background:#6b7280"></span>Info: {counts.get('info', 0)}</div>
            </div>
        </div>
    </div>

    <!-- Scan Metadata -->
    <div class="meta-grid">
        <div class="meta-item">
            <div class="meta-label">Scan Duration</div>
            <div class="meta-value">{meta.get('duration_seconds', 0):.0f}s</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Modules Run</div>
            <div class="meta-value">{len(meta.get('scanner_modules', []))}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Domains</div>
            <div class="meta-value">{len(surface.get('domains', []))}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Total Endpoints</div>
            <div class="meta-value">{surface.get('endpoint_count', 0)}</div>
        </div>
    </div>

    <!-- Key Risks -->
    {"<h2>⚠️ Key Risks</h2><ul class='risk-list'>" + "".join(
        f'<li class="risk-item"><span class="sev-badge" style="background:{severity_colors.get(r["severity"], "#6b7280")}20;color:{severity_colors.get(r["severity"], "#6b7280")};border:1px solid {severity_colors.get(r["severity"], "#6b7280")}40">{r["severity"].upper()}</span> {r["title"]}</li>'
        for r in key_risks[:10]
    ) + "</ul>" if key_risks else ""}

    <!-- Technologies -->
    <h2>🔧 Technologies Detected</h2>
    <div>{tech_html or '<p style="color:var(--text-muted)">No technologies fingerprinted yet.</p>'}</div>

    <!-- Findings -->
    <h2>🔍 All Findings ({len(findings)})</h2>
    <p style="color:var(--text-muted);font-size:12px;margin-bottom:12px;">Click a row to expand details.</p>
    <table>
        <thead>
            <tr>
                <th style="width:90px;">Severity</th>
                <th>Finding</th>
                <th style="width:180px;">Category</th>
                <th style="width:100px;">CWE</th>
            </tr>
        </thead>
        <tbody>
            {findings_html}
        </tbody>
    </table>

    <!-- Hardening Plan -->
    <h2>🛠️ Hardening Recommendations</h2>
    {hardening_html or '<p style="color:var(--text-muted)">No hardening recommendations generated.</p>'}

    <div class="footer">
        Aegis Vanguard Scanner v{meta.get('version', '2.0.0')} |
        ArchScale Guild Intern Technology Hackathon |
        Report generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"  [SAVED] HTML report: {output_path}")
    return output_path


if __name__ == "__main__":
    # Test with existing findings
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    findings_path = os.path.join(results_dir, "findings.json")

    if os.path.exists(findings_path):
        with open(findings_path, encoding="utf-8") as f:
            data = json.load(f)
        output = os.path.join(results_dir, "report.html")
        generate_html_report(data, output)
        print(f"Report generated: {output}")
    else:
        print("No findings.json found. Run the scanner first.")
