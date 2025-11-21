export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string;
  type: string;
  file: string;
  line?: number | null;
  snippet: string;
  severity: Severity;
  confidence: number;
  evidence_hash: string;
}

export interface Metrics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number;
}

export interface ProjectInfo {
  name: string;
  path: string;
  commit: string | null;
  scan_time: string;
}

export interface Report {
  report_version: string;
  project: ProjectInfo;
  standards: string[];
  findings: Finding[];
  metrics: Metrics;
  merkle_root: string;
  agent_signature: string;
  agent_version: string;
}

export interface VerificationResult {
  valid: boolean;
  message: string;
}

export interface AttestationRecord {
  attest_id: number;
  merkle_root: string;
  public_key_hex: string;
  status: string;
  timestamp: string;
}
