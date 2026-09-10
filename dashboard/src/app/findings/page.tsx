"use client";

import { useEffect, useState, useMemo } from "react";
import {
  AlertTriangle,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Bug,
  BookOpen,
} from "lucide-react";
import { AuditReport, Finding, SEVERITY_CONFIG } from "@/lib/types";
import { getFindings } from "@/lib/data";
import clsx from "clsx";

function SeverityBadge({ severity }: { severity: string }) {
  const config = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG];
  return (
    <span
      className="text-[10px] font-bold uppercase px-2.5 py-1 rounded-full whitespace-nowrap"
      style={{
        background: config?.bg,
        color: config?.color,
        border: `1px solid ${config?.border}`,
      }}
    >
      {config?.label || severity}
    </span>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={clsx(
        "glass-card overflow-hidden transition-all duration-200",
        expanded && "ring-1 ring-[var(--color-accent)]/30"
      )}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left p-4 flex items-start gap-3 hover:bg-[var(--color-bg-hover)] transition-colors"
      >
        <ChevronRight
          size={16}
          className={clsx(
            "mt-0.5 text-[var(--color-text-muted)] transition-transform shrink-0",
            expanded && "rotate-90"
          )}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              {finding.title}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-1.5 text-[10px] text-[var(--color-text-muted)]">
            <span className="font-mono">{finding.id}</span>
            <span>·</span>
            <span>{finding.category}</span>
            {finding.cwe && (
              <>
                <span>·</span>
                <span className="font-mono">{finding.cwe}</span>
              </>
            )}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-0 ml-7 space-y-4 border-t border-[var(--color-border-subtle)]">
          <div className="pt-4">
            <h4 className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-1.5">
              Description
            </h4>
            <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed">
              {finding.description}
            </p>
          </div>

          {finding.evidence && (
            <div>
              <h4 className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-1.5">
                Evidence
              </h4>
              <pre className="text-xs text-[var(--color-text-secondary)] bg-[var(--color-bg)] border border-[var(--color-border-subtle)] rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.impact && (
            <div>
              <h4 className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-1.5">
                Impact
              </h4>
              <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed">
                {finding.impact}
              </p>
            </div>
          )}

          {finding.remediation && (
            <div>
              <h4 className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <span className="text-green-400">✦</span> Remediation
              </h4>
              <p className="text-sm text-green-400/80 leading-relaxed bg-green-500/5 border border-green-500/20 rounded-lg p-3">
                {finding.remediation}
              </p>
            </div>
          )}

          <div className="flex items-center gap-4 text-[10px] text-[var(--color-text-muted)] pt-2">
            {finding.owasp && (
              <span className="flex items-center gap-1">
                <BookOpen size={10} /> {finding.owasp}
              </span>
            )}
            {finding.url && (
              <a
                href={finding.url}
                target="_blank"
                rel="noopener"
                className="flex items-center gap-1 text-[var(--color-accent)] hover:underline"
              >
                <ExternalLink size={10} /> View Target
              </a>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingsPage() {
  const [data, setData] = useState<AuditReport | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  useEffect(() => {
    getFindings().then(setData);
  }, []);

  const categories = useMemo(() => {
    if (!data) return [];
    return [...new Set(data.findings.map((f) => f.category))];
  }, [data]);

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.findings.filter((f) => {
      const matchSearch =
        !search ||
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.description.toLowerCase().includes(search.toLowerCase()) ||
        f.id.toLowerCase().includes(search.toLowerCase());
      const matchSeverity = severityFilter === "all" || f.severity === severityFilter;
      const matchCategory = categoryFilter === "all" || f.category === categoryFilter;
      return matchSearch && matchSeverity && matchCategory;
    });
  }, [data, search, severityFilter, categoryFilter]);

  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const sorted = useMemo(
    () =>
      [...filtered].sort(
        (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
      ),
    [filtered]
  );

  if (!data) {
    return (
      <div className="p-8 space-y-4">
        <div className="h-8 w-48 shimmer rounded" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-20 shimmer rounded-xl" />
        ))}
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8 max-w-[1200px] mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Bug size={24} className="text-[var(--color-accent)]" />
          Security Findings
        </h1>
        <p className="text-sm text-[var(--color-text-muted)] mt-1">
          {data.executive_summary.security_score.total_findings} vulnerabilities identified across{" "}
          {data.meta.scanner_modules.length} scanner modules
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3 mb-6">
        <div className="relative flex-1">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]"
          />
          <input
            type="text"
            placeholder="Search findings..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-sm bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-lg focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)]"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="px-3 py-2 text-sm bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-lg text-[var(--color-text-secondary)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
        >
          <option value="all">All Severities</option>
          {severityOrder.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_CONFIG[s as keyof typeof SEVERITY_CONFIG].label}
            </option>
          ))}
        </select>

        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="px-3 py-2 text-sm bg-[var(--color-bg-card)] border border-[var(--color-border)] rounded-lg text-[var(--color-text-secondary)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
        >
          <option value="all">All Categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>

      {/* Results count */}
      <div className="text-xs text-[var(--color-text-muted)] mb-3">
        Showing {sorted.length} of {data.findings.length} findings
      </div>

      {/* Findings List */}
      <div className="space-y-2">
        {sorted.map((finding) => (
          <FindingDetail key={finding.id} finding={finding} />
        ))}
        {sorted.length === 0 && (
          <div className="glass-card p-12 text-center">
            <AlertTriangle size={32} className="mx-auto text-[var(--color-text-muted)] mb-3" />
            <p className="text-sm text-[var(--color-text-muted)]">
              No findings match your filters.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
