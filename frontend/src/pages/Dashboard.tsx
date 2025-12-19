import { lazy, Suspense } from "react";

import { EnhancedUpload } from "@/components/EnhancedUpload";
import { ReportPreview } from "@/components/ReportPreview";
import { ComplianceSummary } from "@/components/ComplianceSummary";
import { VerificationPanel } from "@/components/VerificationPanel";
import { AttestationHistory } from "@/components/AttestationHistory";
import { useReportStore } from "@/hooks/useReportStore";
import { Button } from "@/components/ui/button";
import { ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

// Lazy load heavy chart components
const SeverityBarChart = lazy(() =>
  import("@/components/charts/SeverityBarChart").then((m) => ({ default: m.SeverityBarChart }))
);
const ComplianceRadarChart = lazy(() =>
  import("@/components/charts/ComplianceRadarChart").then((m) => ({ default: m.ComplianceRadarChart }))
);

export function Dashboard() {
  const { report } = useReportStore();

  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.4em] text-muted-foreground">Compliance Evidence Engine</p>
          <h1 className="text-4xl font-semibold text-foreground">KratosComply Audit Cockpit</h1>
          <p className="text-base text-muted-foreground">
            Upload compliance evidence reports, verify cryptographic signatures, and create legal-grade attestations
            for auditors, investors, and regulators.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button className="gap-2">
            <ShieldCheck className="h-4 w-4" /> Local Mode
          </Button>
          <Button variant="outline" className="border-dashed border-primary/40 text-primary">
            Hosted Demo Mode
          </Button>
        </div>
      </motion.div>

      <div className="grid gap-6 lg:grid-cols-2">
        <EnhancedUpload />
        <VerificationPanel />
      </div>

      {report && <ComplianceSummary />}

      <div className="grid gap-6 lg:grid-cols-2">
        <ReportPreview />
        <div className="space-y-6">
          <Suspense fallback={<div className="h-64 animate-pulse rounded-lg bg-muted" />}>
            <SeverityBarChart />
          </Suspense>
          <Suspense fallback={<div className="h-64 animate-pulse rounded-lg bg-muted" />}>
            <ComplianceRadarChart />
          </Suspense>
        </div>
      </div>

      <AttestationHistory condensed />
    </div>
  );
}
