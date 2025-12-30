/**
 * Dashboard - Audit Cockpit (Core Page)
 * 
 * Rename explicitly: "Compliance Dashboard" or "Audit Readiness Dashboard"
 * 
 * Primary questions answered:
 * - Which frameworks am I preparing for?
 * - Which controls are satisfied?
 * - Which controls lack evidence?
 * - What will fail an audit today?
 * 
 * Widgets allowed:
 * - Framework readiness indicator
 * - Control status breakdown
 * - Evidence expiry warnings
 * 
 * Widgets forbidden:
 * - Vulnerability counts
 * - Risk heatmaps
 * - Severity charts
 */
import { lazy, Suspense } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, AlertTriangle, CheckCircle2, Clock, FileText } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useReportStore } from "@/hooks/useReportStore";
import { EnhancedUpload } from "@/components/EnhancedUpload";
import { VerificationPanel } from "@/components/VerificationPanel";
import { ControlEvidenceViewer } from "@/components/ControlEvidenceViewer";

// Lazy load chart components
const ComplianceRadarChart = lazy(() =>
  import("@/components/charts/ComplianceRadarChart").then((m) => ({ default: m.ComplianceRadarChart }))
);

export function AuditCockpitPage() {
  const { report } = useReportStore();
  const navigate = useNavigate();

  // Calculate framework readiness
  const frameworks = report
    ? new Set(report.findings.flatMap((f) => f.compliance_frameworks_affected || []))
    : new Set<string>();

  // Calculate control states from report data
  const controlStatesMap = report?.control_states || {};
  const systemEvidence = report?.system_evidence || [];
  
  // Count control states
  const controlStates = {
    verified_machine: 0,
    verified_system: 0,
    attested_human: 0,
    missing_evidence: 0,
    expired_evidence: 0,
  };

  // Count from control_states mapping
  Object.values(controlStatesMap).forEach((state: string) => {
    if (state === "VERIFIED_MACHINE") controlStates.verified_machine++;
    else if (state === "VERIFIED_SYSTEM") controlStates.verified_system++;
    else if (state === "ATTESTED_HUMAN") controlStates.attested_human++;
    else if (state === "MISSING_EVIDENCE") controlStates.missing_evidence++;
    else if (state === "EXPIRED_EVIDENCE") controlStates.expired_evidence++;
  });

  // Also count from system evidence
  systemEvidence.forEach((ev: any) => {
    if (ev.evidence_present && !ev.expiry_detected) {
      controlStates.verified_system++;
    } else if (ev.expiry_detected) {
      controlStates.expired_evidence++;
    } else {
      controlStates.missing_evidence++;
    }
  });

  // Fallback: if no control_states, use findings as before
  if (Object.keys(controlStatesMap).length === 0 && systemEvidence.length === 0) {
    controlStates.verified_machine = report?.findings.filter((f) => f.control_pass_fail_status === "PASS").length || 0;
    controlStates.missing_evidence = report?.findings.filter((f) => f.control_pass_fail_status === "FAIL").length || 0;
  }

  const totalControls = Object.values(controlStates).reduce((a, b) => a + b, 0);
  const satisfiedControls = controlStates.verified_machine + controlStates.verified_system + controlStates.attested_human;
  const readinessPercent = totalControls > 0 ? Math.round((satisfiedControls / totalControls) * 100) : 0;

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-5xl mx-auto px-4 space-y-4"
      >
        <div>
          <p className="text-sm uppercase tracking-[0.4em] text-muted-foreground">Compliance Evidence Engine</p>
          <h1 className="text-4xl font-semibold text-foreground">Audit Readiness Dashboard</h1>
          <p className="text-base text-muted-foreground">
            View compliance control status, evidence gaps, and audit readiness across frameworks
          </p>
        </div>
      </motion.div>

      {/* Upload & Verify Section */}
      {!report && (
        <div className="max-w-5xl mx-auto px-4">
          <div className="grid gap-6 lg:grid-cols-2">
            <EnhancedUpload />
            <VerificationPanel />
          </div>
        </div>
      )}

      {/* Framework Readiness */}
      {report && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="max-w-5xl mx-auto px-4"
        >
          <Card>
            <CardHeader>
              <CardTitle>Framework Readiness</CardTitle>
              <CardDescription>
                Which frameworks are you preparing for, and what is your audit readiness?
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Overall Audit Readiness</span>
                  <span className="text-2xl font-semibold">{readinessPercent}%</span>
                </div>
                <div className="h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all"
                    style={{ width: `${readinessPercent}%` }}
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  {Array.from(frameworks).map((fw) => (
                    <Badge key={fw} variant="outline">
                      {fw}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Control Status Breakdown */}
      {report && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="max-w-5xl mx-auto px-4"
        >
          <Card>
            <CardHeader>
              <CardTitle>Control Status Breakdown</CardTitle>
              <CardDescription>
                Which controls are satisfied, and which lack evidence?
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-5">
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/15 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                    <p className="text-xs font-medium uppercase tracking-wider text-emerald-200">Machine Verified</p>
                  </div>
                  <p className="text-3xl font-bold text-emerald-300">{controlStates.verified_machine}</p>
                </div>
                <div className="rounded-xl border border-blue-500/30 bg-blue-500/15 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <ShieldCheck className="h-5 w-5 text-blue-400" />
                    <p className="text-xs font-medium uppercase tracking-wider text-blue-200">System Verified</p>
                  </div>
                  <p className="text-3xl font-bold text-blue-300">{controlStates.verified_system}</p>
                </div>
                <div className="rounded-xl border border-purple-500/30 bg-purple-500/15 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <FileText className="h-5 w-5 text-purple-400" />
                    <p className="text-xs font-medium uppercase tracking-wider text-purple-200">Human Attested</p>
                  </div>
                  <p className="text-3xl font-bold text-purple-300">{controlStates.attested_human}</p>
                </div>
                <div className="rounded-xl border border-red-500/30 bg-red-500/15 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                    <p className="text-xs font-medium uppercase tracking-wider text-red-200">Evidence Missing</p>
                  </div>
                  <p className="text-3xl font-bold text-red-300">{controlStates.missing_evidence}</p>
                </div>
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/15 p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Clock className="h-5 w-5 text-amber-400" />
                    <p className="text-xs font-medium uppercase tracking-wider text-amber-200">Evidence Expired</p>
                  </div>
                  <p className="text-3xl font-bold text-amber-300">{controlStates.expired_evidence}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Evidence Expiry Warnings */}
      {report && controlStates.expired_evidence > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="max-w-5xl mx-auto px-4"
        >
          <Card className="bg-amber-500/10 border-amber-500/20">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Clock className="h-5 w-5 text-amber-400" />
                <CardTitle>Evidence Expiry Warnings</CardTitle>
              </div>
              <CardDescription>
                Some evidence has expired and requires renewal to maintain compliance
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground">
                {controlStates.expired_evidence} control{controlStates.expired_evidence !== 1 ? "s" : ""} have 
                expired evidence. These controls will fail an audit until evidence is refreshed.
              </p>
              <Button
                variant="outline"
                className="mt-4"
                onClick={() => navigate("/controls-evidence")}
              >
                Review Expired Evidence
              </Button>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* What Will Fail an Audit Today */}
      {report && controlStates.missing_evidence > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="max-w-5xl mx-auto px-4"
        >
          <Card className="bg-red-500/10 border-red-500/20">
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                <CardTitle>What Will Fail an Audit Today</CardTitle>
              </div>
              <CardDescription>
                Controls that currently lack evidence and will fail an audit
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                {controlStates.missing_evidence} control{controlStates.missing_evidence !== 1 ? "s" : ""} 
                {" "}lack evidence. These controls must be addressed before an audit.
              </p>
              <Button
                variant="outline"
                onClick={() => navigate("/controls-evidence")}
              >
                View Missing Evidence
              </Button>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Control Evidence Viewer */}
      {report && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="max-w-5xl mx-auto px-4"
        >
          <ControlEvidenceViewer />
        </motion.div>
      )}

      {/* Compliance Framework Chart */}
      {report && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="max-w-5xl mx-auto px-4"
        >
          <Card>
            <CardHeader>
              <CardTitle>Framework Coverage</CardTitle>
              <CardDescription>
                Compliance readiness across supported frameworks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Suspense fallback={<div className="h-64 animate-pulse rounded-lg bg-muted" />}>
                <ComplianceRadarChart />
              </Suspense>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button
          variant="outline"
          onClick={() => navigate("/controls-evidence")}
        >
          View Controls & Evidence
        </Button>
        <Button
          onClick={() => navigate("/attestations")}
        >
          View Attestations
        </Button>
      </motion.div>
    </div>
  );
}


