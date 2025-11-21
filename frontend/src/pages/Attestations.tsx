import { AttestationHistory } from "@/components/AttestationHistory";
import { motion } from "framer-motion";

export function AttestationsPage() {
  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
        <p className="text-sm uppercase tracking-[0.4em] text-muted-foreground">Ledger</p>
        <h1 className="text-4xl font-semibold text-foreground">Attestation history</h1>
        <p className="text-base text-muted-foreground">
          Every attestation is signed and timestamped for downstream auditors. Filter and export as needed.
        </p>
      </motion.div>
      <AttestationHistory />
    </div>
  );
}
