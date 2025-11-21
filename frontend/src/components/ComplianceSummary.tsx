import { ShieldCheck } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { useReportStore } from "@/hooks/useReportStore";

export function ComplianceSummary() {
  const { report } = useReportStore();
  if (!report) return null;

  const metrics = [
    { label: "Total Findings", value: report.findings.length },
    { label: "Risk Score", value: report.metrics.risk_score },
    { label: "Critical", value: report.metrics.critical },
    { label: "High", value: report.metrics.high },
    { label: "Medium", value: report.metrics.medium },
    { label: "Low", value: report.metrics.low },
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
