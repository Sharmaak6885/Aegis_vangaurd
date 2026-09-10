"use client";

import { useEffect, useState } from "react";
import { Globe, Server, Cpu, Layers, Shield, Wifi } from "lucide-react";
import { AuditReport, SEVERITY_CONFIG } from "@/lib/types";
import { getFindings } from "@/lib/data";

function RiskBadge({ risk }: { risk: string }) {
  const colors: Record<string, string> = {
    high: "bg-red-500/10 text-red-400 border-red-500/30",
    medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  };
  return (
    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${colors[risk] || colors.low}`}>
      {risk}
    </span>
  );
}

export default function SurfaceMapPage() {
  const [data, setData] = useState<AuditReport | null>(null);

  useEffect(() => {
    getFindings().then(setData);
  }, []);

  if (!data) {
    return (
      <div className="p-8 space-y-4">
        <div className="h-8 w-48 shimmer rounded" />
        <div className="h-64 shimmer rounded-xl" />
      </div>
    );
  }

  const { surface_map } = data;
  const icons: Record<string, React.ReactNode> = {
    "Authentication Surface": <Shield size={18} className="text-red-400" />,
    "OAuth Integration": <Layers size={18} className="text-orange-400" />,
    "Client-Side Assets": <Cpu size={18} className="text-blue-400" />,
    "API Surface": <Server size={18} className="text-purple-400" />,
    "Infrastructure": <Wifi size={18} className="text-green-400" />,
  };

  return (
    <div className="p-6 lg:p-8 max-w-[1200px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Globe size={24} className="text-[var(--color-accent)]" />
          Attack Surface Map
        </h1>
        <p className="text-sm text-[var(--color-text-muted)] mt-1">
          Mapped endpoints, domains, and attack vectors from external reconnaissance
        </p>
      </div>

      {/* Domain Map */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">Domain Architecture</h2>
        <div className="flex flex-col items-center gap-4">
          {/* Visual Domain Map */}
          <div className="w-full max-w-2xl mx-auto">
            <div className="relative flex items-center justify-center gap-8 py-8">
              {/* Central node */}
              <div className="relative z-10">
                <div className="w-32 h-32 rounded-2xl bg-gradient-to-br from-blue-600/20 to-cyan-500/20 border border-blue-500/40 flex flex-col items-center justify-center gap-1">
                  <Globe size={24} className="text-blue-400" />
                  <span className="text-xs font-bold text-blue-300">archscale.in</span>
                  <span className="text-[9px] text-[var(--color-text-muted)]">Platform Root</span>
                </div>
              </div>

              {/* Child domains */}
              <div className="flex flex-col gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-3 h-px bg-blue-500/50" />
                  <div className="px-4 py-3 rounded-xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)] min-w-[200px]">
                    <div className="flex items-center gap-2">
                      <Server size={14} className="text-purple-400" />
                      <span className="text-xs font-bold text-[var(--color-text-primary)] font-mono">app.archscale.in</span>
                    </div>
                    <span className="text-[10px] text-[var(--color-text-muted)]">Main Application SPA</span>
                    <div className="flex gap-1 mt-1.5">
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">Studio</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">Client</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">Vendor</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="w-3 h-px bg-blue-500/50" />
                  <div className="px-4 py-3 rounded-xl bg-[var(--color-bg-elevated)] border border-[var(--color-border)] min-w-[200px]">
                    <div className="flex items-center gap-2">
                      <Shield size={14} className="text-red-400" />
                      <span className="text-xs font-bold text-[var(--color-text-primary)] font-mono">auth.archscale.in</span>
                    </div>
                    <span className="text-[10px] text-[var(--color-text-muted)]">Centralized SSO Service</span>
                    <div className="flex gap-1 mt-1.5">
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">OAuth</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">Login</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">Password</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Vectors */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">Attack Vectors</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {surface_map.attack_vectors.map((vector, i) => (
            <div
              key={i}
              className="p-4 rounded-xl bg-[var(--color-bg)] border border-[var(--color-border-subtle)] hover:border-[var(--color-border)] transition-colors"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  {icons[vector.name] || <Globe size={18} className="text-[var(--color-text-muted)]" />}
                  <span className="text-sm font-medium">{vector.name}</span>
                </div>
                <RiskBadge risk={vector.risk} />
              </div>
              <div className="space-y-1">
                {vector.endpoints.map((ep, j) => (
                  <div key={j} className="text-xs text-[var(--color-text-muted)] font-mono flex items-center gap-1.5">
                    <span className="w-1 h-1 rounded-full bg-[var(--color-text-muted)]" />
                    {ep}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technologies */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">Technology Fingerprint</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {surface_map.technologies_detected.map((tech, i) => (
            <div
              key={i}
              className="flex items-center gap-3 p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border-subtle)]"
            >
              <Cpu size={14} className="text-[var(--color-accent)] shrink-0" />
              <span className="text-sm text-[var(--color-text-secondary)]">{tech}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Category Heatmap */}
      <div className="glass-card p-6">
        <h2 className="text-sm font-semibold mb-4">Finding Distribution by Category</h2>
        <div className="space-y-2">
          {Object.entries(surface_map.categories).map(([cat, info]) => {
            const maxSev = info.severities.sort(
              (a, b) =>
                ["critical", "high", "medium", "low", "info"].indexOf(a) -
                ["critical", "high", "medium", "low", "info"].indexOf(b)
            )[0];
            const config = SEVERITY_CONFIG[maxSev as keyof typeof SEVERITY_CONFIG];
            const maxCount = Math.max(...Object.values(surface_map.categories).map((c) => c.count));
            const pct = (info.count / maxCount) * 100;

            return (
              <div key={cat} className="flex items-center gap-3">
                <span className="text-xs text-[var(--color-text-secondary)] w-48 truncate">{cat}</span>
                <div className="flex-1 h-6 bg-[var(--color-bg)] rounded overflow-hidden">
                  <div
                    className="h-full rounded flex items-center px-2 transition-all duration-700"
                    style={{ width: `${Math.max(pct, 8)}%`, backgroundColor: config?.bg || "rgba(107,114,128,0.1)", borderRight: `2px solid ${config?.color || "#6b7280"}` }}
                  >
                    <span className="text-[10px] font-bold" style={{ color: config?.color }}>{info.count}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
