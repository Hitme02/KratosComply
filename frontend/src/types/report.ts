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
  // Compliance metadata
  compliance_frameworks_affected?: string[];
  control_id?: string;
  control_category?: string;
  control_pass_fail_status?: string;
  required_evidence_missing?: string;
  auditor_explanation?: string;
}

export interface Metrics {
  critical: number;
  high: number;
  medium: number;
  low: number;
  risk_score: number; // Legacy field - represents control failure score, not security risk
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
  system_evidence?: Array<{
    control_id: string;
    framework: string;
    evidence_type: string;
    evidence_present: boolean;
    evidence_source: string;
    expiry_detected: boolean;
  }>;
  control_states?: Record<string, string>; // control_id -> ControlState
  evidence_hashes?: string[];
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
  id: number;
  attest_id?: number; // Legacy field
  merkle_root: string;
  public_key_hex: string;
  status?: string; // Legacy field
  timestamp?: string; // Legacy field
  created_at: string;
  frameworks_covered: string[];
  control_coverage_percent: number | null;
  human_attestations?: any[];
}
