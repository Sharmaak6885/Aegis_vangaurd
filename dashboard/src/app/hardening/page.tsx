"use client";

import { useEffect, useState } from "react";
import { Wrench, AlertTriangle, Clock, CheckCircle2, ArrowRight } from "lucide-react";
import { AuditReport, SEVERITY_CONFIG } from "@/lib/types";
import { getFindings } from "@/lib/data";

const PRIORITY_CONFIG: Record<string, { label: string; color: string; bg: string }> = {
  P0: { label: "Immediate", color: "#ef4444", bg: "rgba(239,68,68,0.1)" },
  P1: { label: "Urgent", color: "#f97316", bg: "rgba(249,115,22,0.1)" },
  P2: { label: "Short-term", color: "#eab308", bg: "rgba(234,179,8,0.1)" },
  P3: { label: "Planned", color: "#3b82f6", bg: "rgba(59,130,246,0.1)" },
  P4: { label: "Backlog", color: "#6b7280", bg: "rgba(107,114,128,0.1)" },
};

export default function HardeningPage() {
  const [data, setData] = useState<AuditReport | null>(null);

  useEffect(() => {
    getFindings().then(setData);
  }, []);

  if (!data) {
    return (
      <div className="p-8 space-y-4">
        <div className="h-8 w-48 shimmer rounded" />
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-24 shimmer rounded-xl" />
        ))}
      </div>
    );
  }

  const { hardening } = data;
  const totalItems = hardening.immediate.length + hardening.short_term.length + hardening.long_term.length;

  const sections = [
    {
      title: "Immediate Action Required",
      subtitle: "Fix within 24-48 hours — active risk exposure",
      icon: <AlertTriangle size={18} className="text-red-400" />,
      items: hardening.immediate,
      borderColor: "border-l-red-500",
    },
    {
      title: "Short-term Improvements",
      subtitle: "Resolve within 1-2 weeks — defense-in-depth",
      icon: <Clock size={18} className="text-yellow-400" />,
      items: hardening.short_term,
      borderColor: "border-l-yellow-500",
    },
    {
      title: "Long-term Hardening",
      subtitle: "Plan for next quarter — posture maturation",
      icon: <CheckCircle2 size={18} className="text-blue-400" />,
      items: hardening.long_term,
      borderColor: "border-l-blue-500",
    },
  ];

  const categoryPatches: Record<string, { file: string; code: string; lang: string }> = {
    "Rate Limiting": {
      file: "rate-limit.ts",
      lang: "typescript",
      code: `import rateLimit from 'express-rate-limit';

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts' }
});`,
    },
    "Security Headers": {
      file: "security-headers.ts",
      lang: "typescript",
      code: `import helmet from 'helmet';

export const securityHeaders = helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  noSniff: true,
});`,
    },
    "CORS Configuration": {
      file: "cors-config.ts",
      lang: "typescript",
      code: `import cors from 'cors';

const allowedOrigins = ['https://app.archscale.in'];
export const strictCors = cors({
  origin: (origin, cb) => cb(null, !origin || allowedOrigins.includes(origin)),
  credentials: true,
});`,
    },
    "Cookie Security": {
      file: "cookie-config.ts",
      lang: "typescript",
      code: `import session from 'express-session';

export const secureSession = session({
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict'
  }
});`,
    },
    "CSP Analysis": {
      file: "csp-nextjs.ts",
      lang: "typescript",
      code: `// next.config.js
module.exports = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [{
        key: 'Content-Security-Policy',
        value: "default-src 'self'; script-src 'self'; block-all-mixed-content;"
      }]
    }]
  }
}`,
    },
    "Error Handling": {
      file: "nginx-hardening.conf",
      lang: "nginx",
      code: `server_tokens off;

location ~ /\\.(?!well-known).* {
    deny all;
}
if ($request_method !~ ^(GET|HEAD|POST|OPTIONS|PUT|DELETE)$ ) {
    return 405;
}`,
    },
  };

  return (
    <div className="p-6 lg:p-8 max-w-[1200px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Wrench size={24} className="text-[var(--color-accent)]" />
          Hardening Recommendations
        </h1>
        <p className="text-sm text-[var(--color-text-muted)] mt-1">
          {totalItems} prioritized actions to improve the platform&apos;s security posture
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-3 gap-4">
        {sections.map((section, i) => (
          <div key={i} className="glass-card p-4 text-center">
            <div className="flex justify-center mb-2">{section.icon}</div>
            <div className="text-2xl font-bold">{section.items.length}</div>
            <div className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mt-1">
              {section.title.split(" ")[0]}
            </div>
          </div>
        ))}
      </div>

      {/* Sections */}
      {sections.map((section, si) => (
        <div key={si} className="glass-card overflow-hidden">
          <div className="p-5 border-b border-[var(--color-border)] flex items-center gap-3">
            {section.icon}
            <div>
              <h2 className="text-sm font-semibold">{section.title}</h2>
              <p className="text-[10px] text-[var(--color-text-muted)]">{section.subtitle}</p>
            </div>
            <span className="ml-auto text-xs bg-[var(--color-bg-elevated)] px-2.5 py-1 rounded-full text-[var(--color-text-muted)] font-medium">
              {section.items.length}
            </span>
          </div>
          <div className="divide-y divide-[var(--color-border-subtle)]">
            {section.items.map((item, i) => {
              const prioConfig = PRIORITY_CONFIG[item.priority] || PRIORITY_CONFIG.P4;
              return (
                <div
                  key={i}
                  className={`p-4 hover:bg-[var(--color-bg-hover)] transition-colors border-l-2 ${section.borderColor}`}
                >
                  <div className="flex items-start gap-3">
                    <span
                      className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full whitespace-nowrap mt-0.5"
                      style={{ background: prioConfig.bg, color: prioConfig.color, border: `1px solid ${prioConfig.color}33` }}
                    >
                      {prioConfig.label}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-[var(--color-text-primary)]">{item.title}</div>
                      <div className="text-xs text-[var(--color-text-muted)] mt-1.5 flex items-start gap-1.5">
                        <ArrowRight size={10} className="text-green-400 mt-0.5 shrink-0" />
                        <span className="text-green-400/80">{item.action}</span>
                      </div>
                      
                      {/* Code Patch */}
                      {(() => {
                        const finding = data.findings.find(f => f.id === item.finding_id);
                        if (finding && categoryPatches[finding.category]) {
                          const patch = categoryPatches[finding.category];
                          return (
                            <div className="mt-3 bg-[#0a0a0f] border border-[var(--color-border-subtle)] rounded-md overflow-hidden">
                              <div className="px-3 py-1.5 bg-[#111118] border-b border-[var(--color-border-subtle)] flex items-center justify-between text-[10px] font-mono text-gray-400">
                                <span>{patch.file}</span>
                                <span className="uppercase text-gray-500">{patch.lang}</span>
                              </div>
                              <pre className="p-3 text-[11px] font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                                {patch.code}
                              </pre>
                            </div>
                          );
                        }
                        return null;
                      })()}
                      
                      <div className="text-[10px] text-[var(--color-text-muted)] font-mono mt-3 opacity-50 hover:opacity-100 transition-opacity">
                        Finding ID: {item.finding_id}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
            {section.items.length === 0 && (
              <div className="p-8 text-center text-sm text-[var(--color-text-muted)]">
                No items in this category. ✓
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
