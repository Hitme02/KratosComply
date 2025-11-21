import { create } from "zustand";
import type { AttestationRecord, Report, VerificationResult } from "@/types/report";

interface ReportState {
  report?: Report;
  publicKeyHex: string;
  verification?: VerificationResult;
  attestations: AttestationRecord[];
  isVerifying: boolean;
  isAttesting: boolean;
  uploadError?: string;
  setReport: (report: Report | undefined) => void;
  setPublicKeyHex: (value: string) => void;
  setVerification: (result: VerificationResult | undefined) => void;
  setAttestations: (records: AttestationRecord[]) => void;
  addAttestation: (record: AttestationRecord) => void;
  setUploadError: (message?: string) => void;
  setIsVerifying: (flag: boolean) => void;
  setIsAttesting: (flag: boolean) => void;
  reset: () => void;
}

export const useReportStore = create<ReportState>((set) => ({
  report: undefined,
  publicKeyHex: "",
  verification: undefined,
  attestations: [],
  isVerifying: false,
  isAttesting: false,
  uploadError: undefined,
  setReport: (report) => set({ report }),
  setPublicKeyHex: (publicKeyHex) => set({ publicKeyHex }),
  setVerification: (verification) => set({ verification }),
  setAttestations: (records) => set({ attestations: records }),
  addAttestation: (record) =>
    set((state) => ({ attestations: [record, ...state.attestations].slice(0, 50) })),
  setUploadError: (message) => set({ uploadError: message }),
  setIsVerifying: (flag) => set({ isVerifying: flag }),
  setIsAttesting: (flag) => set({ isAttesting: flag }),
  reset: () =>
    set({ report: undefined, verification: undefined, uploadError: undefined }),
}));
