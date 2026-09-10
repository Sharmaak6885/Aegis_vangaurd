"use client";

import { useEffect, useState, useMemo } from "react";
import { Activity, CheckCircle2, XCircle, AlertCircle, RefreshCw, ExternalLink } from "lucide-react";
import { AuditReport, Finding, SEVERITY_CONFIG } from "@/lib/types";
import { getFindings } from "@/lib/data";

const EXPECTED_HEADERS = [
  { name: "Strict-Transport-Security", importance: "critical", description: "Forces HTTPS connections" },
  { name: "Content-Security-Policy", importance: "critical", description: "Prevents XSS and injection attacks" },
  { name: "X-Frame-Options", importance: "high", description: "Prevents clickjacking" },
  { name: "X-Content-Type-Options", importance: "medium", description: "Prevents MIME-sniffing" },
  { name: "Referrer-Policy", importance: "medium", description: "Controls referrer information" },
  { name: "Permissions-Policy", importance: "medium", description: "Controls browser feature access" },
  { name: "X-XSS-Protection", importance: "low", description: "Legacy XSS filter" },
  { name: "X-Permitted-Cross-Domain-Policies", importance: "low", description: "Flash/PDF cross-domain control" },
];

export default function HeadersPage() {
  const [data, setData] = useState<AuditReport | null>(null);
  const [liveResults, setLiveResults] = useState<Record<string, Record<string, string | null>> | null>(null);
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    getFindings().then(setData);
  }, []);

  const headerFindings = useMemo(() => {
    if (!data) return [];
    return data.findings.filter((f) => f.category === "Security Headers" || f.category === "Session Security");
  }, [data]);

  const domains = ["app.archscale.in", "auth.archscale.in"];

  // Build a matrix of which headers are missing per domain
  const headerMatrix = useMemo(() => {
    const matrix: Record<string, Record<string, "present" | "missing" | "misconfigured">> = {};
    for (const domain of domains) {
      matrix[domain] = {};
      for (const header of EXPECTED_HEADERS) {
        // Check if there's a finding about this header being missing on this domain
        const relatedFinding = headerFindings.find(
          (f) => f.title.includes(header.name) && f.url.includes(domain)
        );
        matrix[domain][header.name] = relatedFinding ? "missing" : "present";
      }
    }
    return matrix;
  }, [headerFindings]);

  const runLiveScan = async () => {
    setScanning(true);
    try {
      const res = await fetch("/api/headers-check");
      const result = await res.json();
      setLiveResults(result);
    } catch {
      console.error("Live scan failed");
    }
    setScanning(false);
  };

  if (!data) {
    return (
      <div className="p-8 space-y-4">
        <div className="h-8 w-48 shimmer rounded" />
        <div className="h-96 shimmer rounded-xl" />
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 max-w-[1200px] mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Activity size={24} className="text-[var(--color-accent)]" />
            Security Headers Audit
          </h1>
          <p className="text-sm text-[var(--color-text-muted)] mt-1">
            HTTP security header analysis across all target domains
          </p>
        </div>
        <button
          onClick={runLiveScan}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-[var(--color-accent)] hover:bg-[var(--color-accent-hover)] text-white rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={scanning ? "animate-spin" : ""} />
          {scanning ? "Scanning..." : "Live Scan"}
        </button>
      </div>

      {/* Header Compliance Matrix */}
      <div className="glass-card overflow-hidden">
        <div className="p-4 border-b border-[var(--color-border)]">
          <h2 className="text-sm font-semibold">Header Compliance Matrix</h2>
          <p className="text-xs text-[var(--color-text-muted)] mt-0.5">
            ✓ Present · ✗ Missing · Based on scanner results
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)]">
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider w-72">
                  Header
                </th>
                <th className="text-left px-4 py-3 text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider">
                  Importance
                </th>
                {domains.map((d) => (
                  <th key={d} className="text-center px-4 py-3 text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider font-mono">
                    {d}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {EXPECTED_HEADERS.map((header) => (
                <tr key={header.name} className="border-b border-[var(--color-border-subtle)] hover:bg-[var(--color-bg-hover)] transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-mono text-xs font-medium text-[var(--color-text-primary)]">{header.name}</div>
                    <div className="text-[10px] text-[var(--color-text-muted)] mt-0.5">{header.description}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`badge-${header.importance} text-[10px] font-bold uppercase px-2 py-0.5 rounded-full`}>
                      {header.importance}
                    </span>
                  </td>
                  {domains.map((domain) => {
                    const status = headerMatrix[domain]?.[header.name] || "missing";
                    return (
                      <td key={domain} className="px-4 py-3 text-center">
                        {status === "present" ? (
                          <CheckCircle2 size={18} className="mx-auto text-green-500" />
                        ) : (
                          <XCircle size={18} className="mx-auto text-red-400" />
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cookie Security */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">Cookie Security Analysis</h2>
        <div className="space-y-2">
          {data.findings
            .filter((f) => f.category === "Session Security")
            .map((f, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-subtle)]">
                <AlertCircle size={16} className="text-yellow-400 mt-0.5 shrink-0" />
                <div>
                  <div className="text-sm font-medium text-[var(--color-text-primary)]">{f.title}</div>
                  <div className="text-xs text-[var(--color-text-muted)] mt-0.5">{f.remediation}</div>
                </div>
              </div>
            ))}
          {data.findings.filter((f) => f.category === "Session Security").length === 0 && (
            <div className="text-sm text-[var(--color-text-muted)] text-center py-8">
              No cookie security issues detected in the unauthenticated scan.
            </div>
          )}
        </div>
      </div>

      {/* CORS Findings */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">CORS Configuration</h2>
        <div className="space-y-2">
          {data.findings
            .filter((f) => f.category === "CORS Misconfiguration")
            .map((f, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-subtle)]">
                <AlertCircle size={16} className="text-yellow-400 mt-0.5 shrink-0" />
                <div className="flex-1">
                  <div className="text-sm font-medium text-[var(--color-text-primary)]">{f.title}</div>
                  <pre className="text-xs text-[var(--color-text-muted)] mt-1 font-mono">{f.evidence}</pre>
                  <div className="text-xs text-green-400/80 mt-2 bg-green-500/5 border border-green-500/20 rounded p-2">
                    ✦ {f.remediation}
                  </div>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
