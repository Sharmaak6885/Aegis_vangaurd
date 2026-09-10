export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  cwe: string;
  owasp: string;
  url: string;
  status: string;
  timestamp: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SecurityScore {
  score: number;
  grade: string;
  total_findings: number;
  severity_counts: SeverityCounts;
  deductions: number;
}

export interface AttackVector {
  name: string;
  endpoints: string[];
  risk: string;
}

export interface SurfaceMap {
  domains: string[];
  endpoint_count: number;
  categories: Record<string, { count: number; severities: string[] }>;
  technologies_detected: string[];
  attack_vectors: AttackVector[];
}

export interface HardeningItem {
  finding_id: string;
  title: string;
  action: string;
  priority: string;
}

export interface AuditReport {
  meta: {
    tool: string;
    version: string;
    target: string;
    auth_domain: string;
    scope: string;
    timestamp: string;
    duration_seconds: number;
    scanner_modules: string[];
  };
  executive_summary: {
    scope_statement: string;
    security_score: SecurityScore;
    key_risks: { title: string; severity: string; category: string }[];
  };
  surface_map: SurfaceMap;
  findings: Finding[];
  hardening: {
    immediate: HardeningItem[];
    short_term: HardeningItem[];
    long_term: HardeningItem[];
  };
}

export const SEVERITY_CONFIG = {
  critical: { label: "Critical", color: "#ef4444", bg: "rgba(239,68,68,0.1)", border: "rgba(239,68,68,0.3)" },
  high: { label: "High", color: "#f97316", bg: "rgba(249,115,22,0.1)", border: "rgba(249,115,22,0.3)" },
  medium: { label: "Medium", color: "#eab308", bg: "rgba(234,179,8,0.1)", border: "rgba(234,179,8,0.3)" },
  low: { label: "Low", color: "#3b82f6", bg: "rgba(59,130,246,0.1)", border: "rgba(59,130,246,0.3)" },
  info: { label: "Info", color: "#6b7280", bg: "rgba(107,114,128,0.1)", border: "rgba(107,114,128,0.3)" },
} as const;
