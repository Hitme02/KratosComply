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
    (f.compliance_frameworks_affected || []).forEach((fw) => frameworks.add(fw));
  });
  
  const metrics = [
    { label: "Control Violations", value: failedControls },
    { label: "Controls Passed", value: passedControls },
    { label: "Compliance Readiness", value: `${controlPassRate}%` },
    { label: "Frameworks Affected", value: frameworks.size },
    { label: "Evidence Gaps", value: report.findings.length },
    { label: "Audit Status", value: controlPassRate >= 80 ? "Ready" : "Review Required" },
  ];

  return (
    <Card>
      <CardContent className="grid gap-4 p-6 sm:grid-cols-3">
        {metrics.map((metric) => (
          <div key={metric.label} className="rounded-2xl border border-border/60 bg-muted/20 p-4">
            <p className="text-xs uppercase tracking-widest text-muted-foreground">{metric.label}</p>
            <p className="mt-2 text-2xl font-semibold text-foreground">{metric.value}</p>
          </div>
        ))}
        <div className="rounded-2xl border border-border/60 bg-gradient-to-br from-indigo-500/30 to-purple-500/20 p-4 text-foreground">
          <p className="text-xs uppercase tracking-[0.4em] text-muted-foreground">Mode</p>
          <p className="mt-2 flex items-center gap-2 text-lg font-semibold">
            <ShieldCheck className="h-5 w-5 text-emerald-400" /> Local + Hosted Demo
          </p>
          <p className="text-sm text-muted-foreground">
            Privacy-first agent with hosted verification attestation.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
