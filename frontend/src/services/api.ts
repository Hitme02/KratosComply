import axios from "axios";
import type { AttestationRecord, Report, VerificationResult } from "@/types/report";

const api = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_URL ?? "http://localhost:8000",
  headers: { "Content-Type": "application/json" },
});

export async function verifyReport(payload: {
  report: Report;
  public_key_hex: string;
}): Promise<VerificationResult> {
  const { data } = await api.post<VerificationResult>("/verify-report", payload);
  return data;
}

export async function attestReport(payload: {
  merkle_root: string;
  public_key_hex: string;
  metadata?: Record<string, unknown>;
}): Promise<AttestationRecord> {
  const { data } = await api.post<AttestationRecord>("/attest", payload);
  return data;
}

export async function fetchAttestations(): Promise<AttestationRecord[]> {
  try {
    const { data } = await api.get<AttestationRecord[]>("/attestations");
    return data;
  } catch (error) {
    // Endpoint optional in backend; fall back to empty state if missing
    return [];
  }
}

export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  owner: string;
  description: string;
  private: boolean;
  updated_at: string;
  default_branch: string;
}

export interface GitHubReposResponse {
  username: string;
  repositories: GitHubRepository[];
}

export async function fetchGitHubRepos(code: string, state: string): Promise<GitHubReposResponse> {
  const { data } = await api.post<GitHubReposResponse>("/github/callback", { code, state });
  return data;
}

export function getGitHubAuthUrl(): string {
  const baseURL = import.meta.env.VITE_BACKEND_URL ?? "http://localhost:8000";
  return `${baseURL}/api/auth/github`;
}
