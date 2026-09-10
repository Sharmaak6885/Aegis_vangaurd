"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  AlertTriangle,
  Globe,
  Wrench,
  FileText,
  Activity,
  ChevronRight,
  Scan,
  Terminal,
  Radar,
  Play,
} from "lucide-react";
import clsx from "clsx";

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/scan", label: "Run Scan", icon: Play },
  { href: "/findings", label: "Findings", icon: AlertTriangle },
  { href: "/surface-map", label: "Attack Surface", icon: Globe },
  { href: "/headers", label: "Headers Audit", icon: Activity },
  { href: "/hardening", label: "Hardening Plan", icon: Wrench },
  { href: "/methodology", label: "Methodology", icon: FileText },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-[260px] h-screen flex flex-col border-r border-[var(--color-border)] bg-[var(--color-bg)] shrink-0">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-[var(--color-border)]">
        <Link href="/" className="flex items-center gap-3 group">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <div className="text-sm font-semibold text-[var(--color-text-primary)] tracking-tight">
              Aegis Vanguard
            </div>
            <div className="text-[10px] font-medium text-[var(--color-text-muted)] uppercase tracking-widest">
              Security Report
            </div>
          </div>
        </Link>
      </div>

      {/* Target Info */}
      <div className="px-5 py-4 border-b border-[var(--color-border)]">
        <div className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-widest mb-2">
          Target
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-500 pulse-dot" />
          <span className="text-xs text-[var(--color-text-secondary)] font-mono">
            app.archscale.in
          </span>
        </div>
        <div className="flex items-center gap-2 mt-1.5">
          <span className="w-2 h-2 rounded-full bg-green-500 pulse-dot" />
          <span className="text-xs text-[var(--color-text-secondary)] font-mono">
            auth.archscale.in
          </span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 sidebar-scroll overflow-y-auto">
        <div className="text-[10px] font-semibold text-[var(--color-text-muted)] uppercase tracking-widest px-2 mb-3">
          Dashboard
        </div>
        <ul className="space-y-0.5">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  className={clsx(
                    "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150",
                    isActive
                      ? "bg-[var(--color-bg-elevated)] text-[var(--color-text-primary)] shadow-sm"
                      : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]"
                  )}
                >
                  <Icon
                    size={16}
                    className={clsx(
                      isActive
                        ? "text-blue-400"
                        : "text-[var(--color-text-muted)]"
                    )}
                  />
                  <span className="flex-1">{item.label}</span>
                  {isActive && (
                    <ChevronRight size={14} className="text-[var(--color-text-muted)]" />
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-[var(--color-border)]">
        <div className="text-[10px] text-[var(--color-text-muted)] leading-relaxed">
          <div className="font-semibold uppercase tracking-widest mb-1">
            ArchScale Guild Hackathon
          </div>
          <div>AS-09 · Platform Security</div>
          <div className="mt-1 text-[var(--color-text-muted)]">
            Unauthenticated Assessment
          </div>
        </div>
      </div>
    </aside>
  );
}
