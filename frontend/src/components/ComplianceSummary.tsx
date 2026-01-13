import { ShieldCheck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useReportStore } from "@/hooks/useReportStore";

export function ComplianceSummary() {
  const { report } = useReportStore();
  if (!report) return null;

  // Calculate compliance readiness metrics
  const totalControls = report.findings.length;
  const failedControls = report.findings.filter(
    (f) => f.control_pass_fail_status === "FAIL"
  ).length;
  const passedControls = totalControls - failedControls;
  const controlPassRate = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 100;
  
  // Collect frameworks
  const frameworks = new Set<string>();
  report.findings.forEach((f) => {
    (f.compliance_frameworks_affected || []).forEach((fw: string) => frameworks.add(fw));
  });
  
  // Extract scan statistics if available (v2.2.0+)
  const scanStats = (report as any).scan_statistics;
  
  const metrics = [
    { label: "Control Failures", value: failedControls },
    { label: "Controls Verified", value: passedControls },
    { label: "Audit Readiness", value: `${controlPassRate}%` },
    { label: "Frameworks Covered", value: frameworks.size },
    { label: "Evidence Gaps", value: report.findings.length },
    { label: "Audit Status", value: controlPassRate >= 80 ? "Audit Ready" : "Evidence Review Required" },
  ];
  
  // Add scan statistics if available
  if (scanStats) {
    metrics.push(
      { label: "Files Scanned", value: scanStats.files_scanned || "N/A" },
      { label: "Scan Duration", value: scanStats.scan_duration_seconds ? `${scanStats.scan_duration_seconds}s` : "N/A" },
      { label: "Workers Used", value: scanStats.workers_used || "N/A" }
    );
  }

  return (
    <Card>
      <CardContent className="grid gap-4 p-6 sm:grid-cols-3">
        {metrics.map((metric) => (
          <div key={metric.label} className="rounded-2xl border border-border/60 bg-muted/30 p-5">
            <p className="text-xs font-medium uppercase tracking-wider text-foreground/70">{metric.label}</p>
            <p className="mt-3 text-3xl font-bold text-foreground">{metric.value}</p>
          </div>
        ))}
        <div className="rounded-2xl border border-border/60 bg-gradient-to-br from-indigo-500/30 to-purple-500/20 p-5 text-foreground">
          <p className="text-xs font-medium uppercase tracking-wider text-foreground/70">Mode</p>
          <p className="mt-3 flex items-center gap-2 text-lg font-bold">
            <ShieldCheck className="h-5 w-5 text-emerald-400" /> Local + Hosted Demo
          </p>
          <p className="mt-2 text-sm text-foreground/80">
            Privacy-first agent with hosted verification attestation.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
