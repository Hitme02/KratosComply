import { EnhancedUpload } from "@/components/EnhancedUpload";
import { ReportPreview } from "@/components/ReportPreview";
import { ComplianceSummary } from "@/components/ComplianceSummary";
import { SeverityBarChart } from "@/components/charts/SeverityBarChart";
import { ComplianceRadarChart } from "@/components/charts/ComplianceRadarChart";
import { VerificationPanel } from "@/components/VerificationPanel";
import { AttestationHistory } from "@/components/AttestationHistory";
import { useReportStore } from "@/hooks/useReportStore";
import { Button } from "@/components/ui/button";
import { ShieldCheck } from "lucide-react";
import { motion } from "framer-motion";

export function Dashboard() {
  const { report } = useReportStore();

  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col gap-4">
        <div>
          <p className="text-sm uppercase tracking-[0.4em] text-muted-foreground">Cybersecurity Compliance</p>
          <h1 className="text-4xl font-semibold text-foreground">KratosComply Control Tower</h1>
          <p className="text-base text-muted-foreground">
            Upload your Aegis report, verify every signature, and attest compliance for investor-ready confidence.
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
          <SeverityBarChart />
          <ComplianceRadarChart />
        </div>
      </div>

      <AttestationHistory condensed />
    </div>
  );
}
