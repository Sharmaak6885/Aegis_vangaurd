"use client";

import { FileText, Search, Shield, Server, ArrowRight } from "lucide-react";

export default function MethodologyPage() {
  const steps = [
    {
      id: "01",
      title: "Reconnaissance & Surface Mapping",
      icon: <Search size={20} className="text-blue-400" />,
      description: "Passive and active enumeration of the ArchScale platform's external footprint.",
      details: [
        "Subdomain enumeration and DNS analysis",
        "Technology stack fingerprinting",
        "Identification of API endpoints and entry points",
        "Analysis of client-side assets (JS bundles, source maps)",
      ],
      tools: ["Custom Python Scanners", "Browser DevTools", "info_disclosure.py"],
    },
    {
      id: "02",
      title: "Authentication Surface Testing",
      icon: <Shield size={20} className="text-orange-400" />,
      description: "Evaluating the security of the centralized SSO and OAuth integration.",
      details: [
        "Analysis of Google OAuth 2.0 implementation (state/nonce parameters)",
        "Open redirect vulnerability testing on authentication callbacks",
        "Session management and cookie security flag auditing",
        "Analysis of client-side secrets exposure",
      ],
      tools: ["oauth_analyzer.py", "redirect_tester.py", "Burp Suite (Manual)"],
    },
    {
      id: "03",
      title: "Infrastructure & Configuration Auditing",
      icon: <Server size={20} className="text-green-400" />,
      description: "Assessing the security posture of the underlying infrastructure and HTTP configurations.",
      details: [
        "SSL/TLS protocol and cipher strength analysis",
        "HTTP security header compliance (HSTS, CSP, etc.)",
        "Cross-Origin Resource Sharing (CORS) misconfiguration testing",
        "Verification of HTTP to HTTPS redirection",
      ],
      tools: ["ssl_analyzer.py", "header_auditor.py", "cors_tester.py"],
    },
  ];

  return (
    <div className="p-6 lg:p-8 max-w-[1200px] mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <FileText size={24} className="text-[var(--color-accent)]" />
          Audit Methodology
        </h1>
        <p className="text-sm text-[var(--color-text-muted)] mt-1 max-w-3xl">
          Due to strict Rules of Engagement and lack of authorized tenant credentials, this audit
          focused exclusively on unauthenticated attack surfaces, OAuth misconfigurations, and
          external infrastructure posture.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Rules of Engagement */}
        <div className="glass-card p-6 space-y-4">
          <h2 className="text-lg font-semibold border-b border-[var(--color-border-subtle)] pb-2">
            Rules of Engagement (RoE)
          </h2>
          <ul className="space-y-3 text-sm text-[var(--color-text-secondary)]">
            <li className="flex items-start gap-2">
              <span className="text-green-400 font-bold">✓</span>
              <span>
                <strong className="text-[var(--color-text-primary)]">Permitted:</strong> Passive
                reconnaissance, HTTP header analysis, TLS configuration checks, and analysis of
                publicly accessible client-side code.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-red-400 font-bold">✗</span>
              <span>
                <strong className="text-[var(--color-text-primary)]">Prohibited:</strong> Active
                exploitation, denial of service (DoS), automated vulnerability scanning (e.g., Nessus,
                Acunetix) that generates excessive traffic, and attempts to bypass authentication
                mechanisms using stolen credentials.
              </span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-blue-400 font-bold">ℹ</span>
              <span>
                <strong className="text-[var(--color-text-primary)]">Scope constraint:</strong> No
                valid tenant accounts were provided; testing was limited to the unauthenticated
                perspective.
              </span>
            </li>
          </ul>
        </div>

        {/* Custom Toolkit */}
        <div className="glass-card p-6 space-y-4">
          <h2 className="text-lg font-semibold border-b border-[var(--color-border-subtle)] pb-2">
            Custom Assessment Toolkit
          </h2>
          <p className="text-sm text-[var(--color-text-secondary)]">
            To adhere to the RoE and avoid the noise of generic automated scanners, a custom Python
            scanner suite was developed specifically for this engagement.
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono text-[var(--color-text-muted)] mt-2">
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">header_auditor.py</div>
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">redirect_tester.py</div>
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">oauth_analyzer.py</div>
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">info_disclosure.py</div>
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">cors_tester.py</div>
            <div className="bg-[var(--color-bg-elevated)] p-2 rounded">ssl_analyzer.py</div>
          </div>
        </div>
      </div>

      {/* Execution Phases */}
      <div>
        <h2 className="text-lg font-semibold mb-6">Execution Phases</h2>
        <div className="space-y-6 relative">
          {/* Vertical connecting line */}
          <div className="absolute left-8 top-8 bottom-8 w-px bg-[var(--color-border)] hidden md:block" />

          {steps.map((step, index) => (
            <div key={step.id} className="relative flex flex-col md:flex-row gap-6">
              <div className="hidden md:flex flex-col items-center z-10 shrink-0 w-16">
                <div className="w-10 h-10 rounded-full bg-[var(--color-bg-elevated)] border-2 border-[var(--color-border)] flex items-center justify-center font-bold text-xs">
                  {step.id}
                </div>
              </div>
              <div className="glass-card p-6 flex-1 hover:border-[var(--color-border)] transition-colors">
                <div className="flex items-center gap-3 mb-3">
                  <div className="p-2 rounded-lg bg-[var(--color-bg-elevated)]">{step.icon}</div>
                  <h3 className="text-base font-semibold">{step.title}</h3>
                </div>
                <p className="text-sm text-[var(--color-text-secondary)] mb-4">
                  {step.description}
                </p>
                <div className="grid md:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
                      Key Activities
                    </h4>
                    <ul className="space-y-1.5">
                      {step.details.map((detail, i) => (
                        <li key={i} className="text-xs flex items-start gap-2 text-[var(--color-text-secondary)]">
                          <ArrowRight size={12} className="text-[var(--color-accent)] shrink-0 mt-0.5" />
                          <span>{detail}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
                      Tools Utilized
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {step.tools.map((tool, i) => (
                        <span key={i} className="text-[10px] px-2 py-1 rounded bg-[var(--color-bg-elevated)] text-[var(--color-text-muted)] font-mono">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
