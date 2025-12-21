import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { CheckCircle2, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Alert } from "@/components/ui/alert";
import { useReportStore } from "@/hooks/useReportStore";
import { attestReport, verifyReport } from "@/services/api";

export function VerificationPanel() {
  const {
    report,
    publicKeyHex,
    setPublicKeyHex,
    verification,
    setVerification,
    isVerifying,
    setIsVerifying,
    isAttesting,
    setIsAttesting,
    addAttestation,
    setUploadError,
  } = useReportStore();

  const canVerify = Boolean(report && publicKeyHex.trim().length >= 32);
  const canAttest = Boolean(canVerify && verification?.valid);

  const handleVerify = async () => {
    if (!report || !canVerify) {
      setUploadError("Provide a public key and upload a report first.");
      return;
    }
    setIsVerifying(true);
    try {
      const result = await verifyReport({ report, public_key_hex: publicKeyHex.trim() });
      setVerification(result);
    } catch (error) {
      console.error(error);
      setVerification({ valid: false, message: "Backend unreachable" });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleAttest = async () => {
    if (!report || !canAttest) return;
    setIsAttesting(true);
    try {
      const record = await attestReport({
        merkle_root: report.merkle_root,
        public_key_hex: publicKeyHex.trim(),
        metadata: { project: report.project.name },
      });
      addAttestation(record);
    } catch (error) {
      console.error(error);
    } finally {
      setIsAttesting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verification & Attestation</CardTitle>
        <CardDescription>Validate the signature + Merkle root, then record an attestation.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="space-y-2">
          <label className="text-sm font-semibold text-foreground/90">Public key (hex)</label>
          <Input
            placeholder="Paste the agent's public key"
            value={publicKeyHex}
            onChange={(event) => setPublicKeyHex(event.target.value)}
          />
        </div>
        <div className="flex flex-col gap-3 sm:flex-row">
          <Button onClick={handleVerify} disabled={!canVerify || isVerifying} className="flex-1">
            {isVerifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Verify report
          </Button>
          <Button
            variant="secondary"
            onClick={handleAttest}
            disabled={!canAttest || isAttesting}
            className="flex-1"
          >
            {isAttesting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />} Create attestation
          </Button>
        </div>

        {verification && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3"
          >
            {verification.valid ? (
              <Alert
                type="success"
                title="Report verified"
                description={verification.message}
                className="border-emerald-500/40 bg-emerald-500/10"
              />
            ) : (
              <Alert type="error" title="Verification failed" description={verification.message} />
            )}
            <div className="grid gap-3 md:grid-cols-2">
              <StatusCard
                title="Merkle root"
                value={report?.merkle_root ?? "--"}
                icon={verification.valid ? <ShieldCheck className="text-emerald-400" /> : <ShieldAlert className="text-red-400" />}
              />
              <StatusCard
                title="Signature"
                value={verification.valid ? "Valid" : "Invalid"}
                icon={verification.valid ? <CheckCircle2 className="text-emerald-400" /> : <ShieldAlert className="text-red-400" />}
              />
            </div>
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}

function StatusCard({ title, value, icon }: { title: string; value: string; icon: ReactNode }) {
  return (
    <div className="flex items-center gap-3 rounded-2xl border border-border/60 bg-muted/30 p-5">
      {icon}
      <div>
        <p className="text-xs font-medium uppercase tracking-wider text-foreground/70">{title}</p>
        <p className="text-base font-bold text-foreground">{value}</p>
      </div>
    </div>
  );
}
