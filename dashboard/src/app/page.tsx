"use client";

import { useEffect, useState, useMemo } from "react";
import {
  Shield,
  AlertTriangle,
  Globe,
  Lock,
  Clock,
  Zap,
  TrendingDown,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import Link from "next/link";
import { AuditReport, SEVERITY_CONFIG, Finding } from "@/lib/types";
import { getFindings } from "@/lib/data";

function AnimatedCounter({ target, duration = 1500 }: { target: number; duration?: number }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    if (target === 0) return;
    let start = 0;
    const step = Math.max(1, Math.ceil(target / (duration / 16)));
    const timer = setInterval(() => {
      start += step;
      if (start >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(start);
      }
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return <>{count}</>;
}

function SecurityScoreRing({ score, grade }: { score: number; grade: string }) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const scoreColor =
    score >= 75 ? "#22c55e" : score >= 50 ? "#eab308" : score >= 25 ? "#f97316" : "#ef4444";

  return (
    <div className="relative w-32 h-32 mx-auto">
      <svg className="w-32 h-32 -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={radius} fill="none" stroke="var(--color-border)" strokeWidth="6" />
        <circle
          cx="50" cy="50" r={radius} fill="none"
          stroke={scoreColor} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          className="score-ring transition-all duration-1000"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold" style={{ color: scoreColor }}>
          {grade}
        </span>
        <span className="text-xs text-[var(--color-text-muted)]">{score}/100</span>
      </div>
    </div>
  );
}

function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  return (
    <div className="flex h-2 rounded-full overflow-hidden bg-[var(--color-bg-elevated)] gap-0.5">
      {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
        const count = counts[sev] || 0;
        const pct = (count / total) * 100;
        if (pct === 0) return null;
        return (
          <div
            key={sev}
            className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${pct}%`,
              backgroundColor: SEVERITY_CONFIG[sev].color,
              minWidth: count > 0 ? "4px" : 0,
            }}
          />
        );
      })}
    </div>
  );
}

export default function OverviewPage() {
  const [data, setData] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getFindings().then((d) => {
      setData(d);
      setLoading(false);
    });
  }, []);

  const categoryBreakdown = useMemo(() => {
    if (!data) return [];
    const cats: Record<string, { count: number; severity: string }> = {};
    data.findings.forEach((f: Finding) => {
      if (!cats[f.category]) {
        cats[f.category] = { count: 0, severity: "info" };
      }
      cats[f.category].count++;
      const order = ["critical", "high", "medium", "low", "info"];
      if (order.indexOf(f.severity) < order.indexOf(cats[f.category].severity)) {
        cats[f.category].severity = f.severity;
      }
    });
    return Object.entries(cats)
      .map(([name, d]) => ({ name, ...d }))
      .sort((a, b) => {
        const order = ["critical", "high", "medium", "low", "info"];
        return order.indexOf(a.severity) - order.indexOf(b.severity);
      });
  }, [data]);

  if (loading || !data) {
    return (
      <div className="p-8 space-y-6">
        <div className="h-8 w-64 shimmer rounded" />
        <div className="grid grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-32 shimmer rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  const { security_score, scope_statement, key_risks } = data.executive_summary;
  const sc = security_score.severity_counts;

  return (
    <div className="p-6 lg:p-8 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between animate-fade-in">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Posture Overview</h1>
          <p className="text-sm text-[var(--color-text-muted)] mt-1 max-w-2xl">
            {scope_statement}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-[var(--color-text-muted)] bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-lg px-3 py-2">
            <Clock size={12} />
            <span>
              Scanned {new Date(data.meta.timestamp).toLocaleDateString()} in{" "}
              {data.meta.duration_seconds.toFixed(0)}s
            </span>
          </div>
          <a
            href="/api/download-report"
            download
            className="flex items-center gap-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 transition-colors border border-blue-500 rounded-lg px-4 py-2"
          >
            Download HTML Report
          </a>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in animate-fade-in-delay-1">
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
            <Shield size={14} />
            Total Findings
          </div>
          <div className="text-3xl font-bold">
            <AnimatedCounter target={security_score.total_findings} />
          </div>
          <SeverityBar counts={sc as unknown as Record<string, number>} />
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center gap-2 text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
            <AlertTriangle size={14} className="text-[var(--color-high)]" />
            High Severity
          </div>
          <div className="text-3xl font-bold text-[var(--color-high)]">
            <AnimatedCounter target={(sc.critical || 0) + (sc.high || 0)} />
          </div>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            {sc.critical || 0} critical · {sc.high || 0} high
          </p>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center gap-2 text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
            <Globe size={14} />
            Domains Tested
          </div>
          <div className="text-3xl font-bold">
            <AnimatedCounter target={data.surface_map.domains.length || 2} />
          </div>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">
            {data.meta.scanner_modules.length} scanner modules
          </p>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center gap-2 text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wider mb-3">
            <Lock size={14} />
            Security Grade
          </div>
          <SecurityScoreRing score={security_score.score} grade={security_score.grade} />
        </div>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in animate-fade-in-delay-2">
        {/* Key Risks */}
        <div className="lg:col-span-2 glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <Zap size={14} className="text-[var(--color-high)]" />
              Key Risks
            </h2>
            <Link
              href="/findings"
              className="text-xs text-[var(--color-accent)] hover:underline flex items-center gap-1"
            >
              View all <ArrowRight size={12} />
            </Link>
          </div>
          <div className="space-y-2">
            {key_risks.length > 0 ? (
              key_risks.slice(0, 6).map((risk, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] transition-colors"
                >
                  <span
                    className={`badge-${risk.severity} text-[10px] font-bold uppercase px-2 py-0.5 rounded-full`}
                  >
                    {risk.severity}
                  </span>
                  <span className="text-sm flex-1 text-[var(--color-text-secondary)]">
                    {risk.title}
                  </span>
                  <span className="text-[10px] text-[var(--color-text-muted)] font-mono">
                    {risk.category}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-sm text-[var(--color-text-muted)] p-4 text-center">
                No critical or high severity findings detected.
              </div>
            )}
          </div>
        </div>

        {/* Category Breakdown */}
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <TrendingDown size={14} />
            Finding Categories
          </h2>
          <div className="space-y-3">
            {categoryBreakdown.map((cat, i) => (
              <div key={i} className="flex items-center justify-between group">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <div
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{
                      backgroundColor:
                        SEVERITY_CONFIG[cat.severity as keyof typeof SEVERITY_CONFIG]?.color || "#6b7280",
                    }}
                  />
                  <span className="text-sm text-[var(--color-text-secondary)] truncate">
                    {cat.name}
                  </span>
                </div>
                <span className="text-sm font-mono font-medium text-[var(--color-text-primary)] ml-2">
                  {cat.count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Target Info & Technologies */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in animate-fade-in-delay-3">
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold mb-4">Target Information</h2>
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between py-2 border-b border-[var(--color-border-subtle)]">
              <span className="text-[var(--color-text-muted)]">Primary Target</span>
              <a
                href={data.meta.target}
                target="_blank"
                rel="noopener"
                className="text-[var(--color-accent)] flex items-center gap-1 hover:underline font-mono text-xs"
              >
                {data.meta.target} <ExternalLink size={10} />
              </a>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-[var(--color-border-subtle)]">
              <span className="text-[var(--color-text-muted)]">Auth Domain</span>
              <span className="font-mono text-xs">{data.meta.auth_domain}</span>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-[var(--color-border-subtle)]">
              <span className="text-[var(--color-text-muted)]">Scope</span>
              <span className="text-xs">{data.meta.scope}</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[var(--color-text-muted)]">Scanner Modules</span>
              <span className="text-xs">{data.meta.scanner_modules.length} modules</span>
            </div>
          </div>
        </div>

        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold mb-4">Technologies Detected</h2>
          <div className="flex flex-wrap gap-2">
            {data.surface_map.technologies_detected.map((tech, i) => (
              <span
                key={i}
                className="text-xs px-3 py-1.5 rounded-full bg-[var(--color-bg-elevated)] border border-[var(--color-border)] text-[var(--color-text-secondary)]"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 animate-fade-in animate-fade-in-delay-4">
        <Link
          href="/findings"
          className="glass-card p-5 hover:border-blue-500/50 transition-colors group cursor-pointer"
        >
          <AlertTriangle size={20} className="text-[var(--color-accent)] mb-3" />
          <h3 className="text-sm font-semibold mb-1">Explore Findings</h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            Browse all {security_score.total_findings} vulnerabilities with evidence and remediation.
          </p>
        </Link>
        <Link
          href="/surface-map"
          className="glass-card p-5 hover:border-blue-500/50 transition-colors group cursor-pointer"
        >
          <Globe size={20} className="text-[var(--color-accent)] mb-3" />
          <h3 className="text-sm font-semibold mb-1">Attack Surface</h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            Visualize the mapped endpoints, domains, and attack vectors.
          </p>
        </Link>
        <Link
          href="/hardening"
          className="glass-card p-5 hover:border-blue-500/50 transition-colors group cursor-pointer"
        >
          <Shield size={20} className="text-[var(--color-accent)] mb-3" />
          <h3 className="text-sm font-semibold mb-1">Hardening Plan</h3>
          <p className="text-xs text-[var(--color-text-muted)]">
            Prioritized remediation roadmap with root-cause fixes.
          </p>
        </Link>
      </div>
    </div>
  );
}
