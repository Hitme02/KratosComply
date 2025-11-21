import { motion } from "framer-motion";
import { AlertTriangle, FileText } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useReportStore } from "@/hooks/useReportStore";
import { cn } from "@/lib/utils";

const severityStyles: Record<string, string> = {
  critical: "bg-red-500/20 text-red-200",
  high: "bg-orange-500/20 text-orange-200",
  medium: "bg-amber-400/20 text-amber-100",
  low: "bg-blue-500/20 text-blue-100",
};

export function ReportPreview() {
  const { report } = useReportStore();

  if (!report) {
    return (
      <Card className="h-full">
        <CardHeader>
          <CardTitle>No report loaded</CardTitle>
          <CardDescription>Upload an aegis report to see findings and compliance insights.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 rounded-2xl border border-dashed border-border/60 p-6 text-muted-foreground">
            <FileText className="h-8 w-8" />
            <p className="text-sm">Awaiting upload…</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="h-full">
      <CardHeader>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>{report.project.name}</CardTitle>
            <CardDescription className="flex flex-wrap gap-2 text-sm text-muted-foreground">
              <span>Path: {report.project.path}</span>
              <span>• Findings: {report.findings.length}</span>
              <span>• Risk score: {report.metrics.risk_score}</span>
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            {report.standards.map((standard) => (
              <Badge key={standard}>{standard}</Badge>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2">
          <MetricCard label="Merkle root" value={report.merkle_root} />
          <MetricCard label="Signature" value={`${report.agent_signature.slice(0, 24)}…`} />
        </div>
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold uppercase tracking-widest text-muted-foreground">
            <AlertTriangle className="h-4 w-4" /> Findings
          </div>
          <div className="space-y-3">
            {report.findings.slice(0, 6).map((finding) => (
              <motion.div
                key={finding.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className="rounded-xl border border-border/60 bg-muted/20 p-4"
              >
                <div className="flex items-center justify-between text-sm">
                  <p className="font-semibold text-foreground">{finding.file}</p>
                  <span className="text-xs text-muted-foreground">Line {finding.line ?? "-"}</span>
                </div>
                <p className="mt-1 text-sm text-muted-foreground">{finding.snippet}</p>
                <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                  <span className={cn("rounded-full px-2 py-0.5 font-semibold", severityStyles[finding.severity])}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <Badge variant="outline">ID: {finding.id}</Badge>
                  <Badge variant="outline">Confidence {Math.round(finding.confidence * 100)}%</Badge>
                </div>
              </motion.div>
            ))}
            {report.findings.length > 6 && (
              <p className="text-xs text-muted-foreground">+{report.findings.length - 6} more findings…</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border/60 bg-gradient-to-br from-white/5 to-white/0 p-4">
      <p className="text-xs uppercase tracking-widest text-muted-foreground">{label}</p>
      <p className="mt-2 text-lg font-semibold text-foreground break-all">{value}</p>
    </div>
  );
}
