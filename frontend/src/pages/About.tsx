import { motion } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";

const pillars = [
  {
    title: "Local Mode",
    description:
      "Run the Kratos agent offline with deterministic fixes, Merkle attestation, and zero network calls by default.",
  },
  {
    title: "Hosted Mode",
    description:
      "Use the FastAPI verifier to validate signatures and collect attestations in an auditable ledger.",
  },
  {
    title: "Privacy-first",
    description:
      "Your source never leaves your laptop; only hashes + signatures are shared when you explicitly attest.",
  },
];

export function AboutPage() {
  return (
    <div className="space-y-8">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
        <p className="text-sm uppercase tracking-[0.4em] text-muted-foreground">Mission</p>
        <h1 className="text-4xl font-semibold text-foreground">Cybersecurity compliance for startups</h1>
        <p className="text-base text-muted-foreground">
          KratosComply automates SOC2/ISO27001 readiness with reproducible evidence, safe remediations, and verifiable attestations.
        </p>
      </motion.div>
      <div className="grid gap-6 md:grid-cols-3">
        {pillars.map((pillar) => (
          <Card key={pillar.title} className="h-full">
            <CardContent className="space-y-3 p-6">
              <h3 className="text-lg font-semibold text-foreground">{pillar.title}</h3>
              <p className="text-sm text-muted-foreground">{pillar.description}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <Card>
        <CardContent className="space-y-4 p-6 text-sm text-muted-foreground">
          <p>
            <strong className="text-foreground">Two modes.</strong> Local Mode performs scans and sandboxed fixes entirely offline.
            Cloud Mode only uploads Merkle roots + signatures to the backend for verification.
          </p>
          <p>
            <strong className="text-foreground">No-code-upload guarantee.</strong> Reports never contain raw code snippets—only hashed evidence.
          </p>
          <p>
            <strong className="text-foreground">Deterministic outputs.</strong> Identical inputs yield identical hashes, enabling auditors to reproduce results.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
