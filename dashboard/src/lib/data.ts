import { AuditReport } from "./types";

let cachedData: AuditReport | null = null;

export async function getFindings(): Promise<AuditReport> {
  if (cachedData) return cachedData;

  try {
    const res = await fetch("/data/findings.json");
    if (!res.ok) throw new Error("Failed to load findings data");
    cachedData = await res.json();
    return cachedData!;
  } catch {
    // Return fallback structure if data isn't loaded yet
    return {
      meta: {
        tool: "AS-09 Security Audit Scanner",
        version: "1.0.0",
        target: "https://app.archscale.in",
        auth_domain: "https://auth.archscale.in",
        scope: "Unauthenticated external assessment",
        timestamp: new Date().toISOString(),
        duration_seconds: 0,
        scanner_modules: [],
      },
      executive_summary: {
        scope_statement: "Loading...",
        security_score: {
          score: 0,
          grade: "-",
          total_findings: 0,
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          deductions: 0,
        },
        key_risks: [],
      },
      surface_map: {
        domains: [],
        endpoint_count: 0,
        categories: {},
        technologies_detected: [],
        attack_vectors: [],
      },
      findings: [],
      hardening: { immediate: [], short_term: [], long_term: [] },
    };
  }
}
