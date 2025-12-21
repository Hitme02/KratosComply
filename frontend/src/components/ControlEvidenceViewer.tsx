/**
 * Control-wise Evidence Viewer for Audit Cockpit.
 *
 * This component displays evidence organized by compliance control,
 * showing what was proven, what was attested, and what is missing.
 */
import { motion } from "framer-motion";
import { CheckCircle2, XCircle, Clock, FileText, Shield } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useReportStore } from "@/hooks/useReportStore";
import { cn } from "@/lib/utils";

type ControlState = "VERIFIED_MACHINE" | "VERIFIED_SYSTEM" | "ATTESTED_HUMAN" | "MISSING_EVIDENCE" | "EXPIRED_EVIDENCE";

interface ControlEvidence {
  control_id: string;
  framework: string;
  control_category: string;
  state: ControlState;
  evidence_present: boolean;
  evidence_expired: boolean;
  findings_count: number;
  frameworks_affected: string[];
}

const stateConfig: Record<ControlState, { icon: typeof CheckCircle2; color: string; label: string }> = {
  VERIFIED_MACHINE: { icon: CheckCircle2, color: "text-emerald-400", label: "Machine Verified" },
  VERIFIED_SYSTEM: { icon: Shield, color: "text-blue-400", label: "System Verified" },
  ATTESTED_HUMAN: { icon: FileText, color: "text-purple-400", label: "Human Attested" },
  MISSING_EVIDENCE: { icon: XCircle, color: "text-red-400", label: "Evidence Missing" },
  EXPIRED_EVIDENCE: { icon: Clock, color: "text-amber-400", label: "Evidence Expired" },
};

export function ControlEvidenceViewer() {
  const { report } = useReportStore();

  if (!report) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Control Evidence Viewer</CardTitle>
          <CardDescription>Upload a compliance evidence report to view control-wise evidence status.</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  // Group findings by control_id
  const controlsMap = new Map<string, ControlEvidence>();

  report.findings.forEach((finding) => {
    const controlId = finding.control_id || "UNKNOWN";
    const key = `${controlId}-${finding.compliance_frameworks_affected?.join(",") || ""}`;

    if (!controlsMap.has(key)) {
      // Determine control state based on finding
      let state: ControlState = "MISSING_EVIDENCE";
      if (finding.control_pass_fail_status === "PASS") {
        // This is simplified - in real implementation, we'd check evidence type
        state = "VERIFIED_MACHINE";
      }

      controlsMap.set(key, {
        control_id: controlId,
        framework: finding.compliance_frameworks_affected?.[0] || "UNKNOWN",
        control_category: finding.control_category || "Unknown",
        state,
        evidence_present: finding.control_pass_fail_status !== "FAIL",
        evidence_expired: false, // Would be determined from expiry dates
        findings_count: 0,
        frameworks_affected: finding.compliance_frameworks_affected || [],
      });
    }

    const control = controlsMap.get(key)!;
    control.findings_count += 1;
  });

  const controls = Array.from(controlsMap.values());
  const controlsByState = {
    VERIFIED_MACHINE: controls.filter((c) => c.state === "VERIFIED_MACHINE"),
    VERIFIED_SYSTEM: controls.filter((c) => c.state === "VERIFIED_SYSTEM"),
    ATTESTED_HUMAN: controls.filter((c) => c.state === "ATTESTED_HUMAN"),
    MISSING_EVIDENCE: controls.filter((c) => c.state === "MISSING_EVIDENCE"),
    EXPIRED_EVIDENCE: controls.filter((c) => c.state === "EXPIRED_EVIDENCE"),
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Control Evidence Status</CardTitle>
        <CardDescription>
          Evidence organized by compliance control. Shows what was proven, what was attested, and what is missing.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Summary Stats */}
        <div className="grid gap-4 md:grid-cols-5">
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/15 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-emerald-200">Machine Verified</p>
            <p className="mt-3 text-3xl font-bold text-emerald-300">{controlsByState.VERIFIED_MACHINE.length}</p>
          </div>
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/15 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-blue-200">System Verified</p>
            <p className="mt-3 text-3xl font-bold text-blue-300">{controlsByState.VERIFIED_SYSTEM.length}</p>
          </div>
          <div className="rounded-xl border border-purple-500/30 bg-purple-500/15 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-purple-200">Human Attested</p>
            <p className="mt-3 text-3xl font-bold text-purple-300">{controlsByState.ATTESTED_HUMAN.length}</p>
          </div>
          <div className="rounded-xl border border-red-500/30 bg-red-500/15 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-red-200">Evidence Missing</p>
            <p className="mt-3 text-3xl font-bold text-red-300">{controlsByState.MISSING_EVIDENCE.length}</p>
          </div>
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/15 p-4">
            <p className="text-xs font-medium uppercase tracking-wider text-amber-200">Evidence Expired</p>
            <p className="mt-3 text-3xl font-bold text-amber-300">{controlsByState.EXPIRED_EVIDENCE.length}</p>
          </div>
        </div>

        {/* Control List */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-foreground/70">Controls by Status</h3>
          {controls.map((control) => {
            const config = stateConfig[control.state];
            const Icon = config.icon;

            return (
              <motion.div
                key={`${control.control_id}-${control.framework}`}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-border/60 bg-muted/30 p-5"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Icon className={cn("h-5 w-5", config.color)} />
                      <div>
                        <p className="font-bold text-foreground">{control.control_id}</p>
                        <p className="text-sm text-foreground/70">{control.control_category}</p>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {control.frameworks_affected.map((fw) => (
                        <Badge key={fw} variant="outline">{fw}</Badge>
                      ))}
                      {control.findings_count > 0 && (
                        <Badge variant="secondary">{control.findings_count} evidence gap{control.findings_count !== 1 ? "s" : ""}</Badge>
                      )}
                    </div>
                  </div>
                  <Badge className={cn("ml-2", config.color.replace("text-", "bg-").replace("-400", "-500/20"))}>
                    {config.label}
                  </Badge>
                </div>
              </motion.div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

