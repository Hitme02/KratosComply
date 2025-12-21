/**
 * Architecture / How It Works Page
 * 
 * Purpose: Remove fear, explain privacy model, preempt audit questions
 * 
 * Sections:
 * - Offline-first architecture
 * - Multi-plane evidence model (Technical, System, Procedural)
 * - Cryptographic attestation flow
 * 
 * Tone: Explanatory, transparent, defensive (in a good way)
 */
import { motion } from "framer-motion";
import { Lock, Shield, FileText, CheckCircle2, ArrowRight } from "lucide-react";
import { useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function ArchitecturePage() {
  const navigate = useNavigate();

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-semibold">Architecture & How It Works</h1>
        <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
          Understanding KratosComply's privacy-preserving, compliance-first architecture
        </p>
      </motion.div>

      {/* Offline-First Architecture */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-5xl mx-auto px-4 space-y-8"
      >
        <div className="text-center space-y-2">
          <Lock className="h-12 w-12 text-primary mx-auto" />
          <h2 className="text-3xl font-semibold">Offline-First Architecture</h2>
          <p className="text-muted-foreground">
            Your source code, configs, and infrastructure data never leave your control
          </p>
        </div>

        <Card>
          <CardContent className="pt-6 space-y-4">
            <div className="space-y-3">
              <h3 className="text-xl font-semibold">Local Processing</h3>
              <p className="text-muted-foreground">
                The KratosComply agent runs entirely on your local machine or in your infrastructure. 
                All scanning, analysis, and report generation happens offline. No network calls are 
                made during the scanning process.
              </p>
            </div>

            <div className="space-y-3">
              <h3 className="text-xl font-semibold">No Data Exfiltration</h3>
              <p className="text-muted-foreground">
                The agent generates a compliance report with evidence hashes and cryptographic 
                signatures. Only this report (not your source code) is uploaded to the verification 
                backend. The report contains:
              </p>
              <ul className="list-disc list-inside space-y-2 text-muted-foreground ml-4">
                <li>Control violation findings (file paths, line numbers, snippets)</li>
                <li>Evidence hashes (SHA256 hashes of evidence, not the evidence itself)</li>
                <li>Merkle root (cryptographic proof of report integrity)</li>
                <li>Ed25519 signature (cryptographic proof of authenticity)</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="text-xl font-semibold">GitHub OAuth Mode (Ephemeral Workers)</h3>
              <p className="text-muted-foreground">
                When using GitHub OAuth mode, repositories are cloned into ephemeral workspaces 
                that are immediately destroyed after scanning. The workspace lifecycle:
              </p>
              <ol className="list-decimal list-inside space-y-2 text-muted-foreground ml-4">
                <li>Create temporary workspace</li>
                <li>Clone repository (with authentication)</li>
                <li>Run agent scan</li>
                <li>Generate signed attestation</li>
                <li>Destroy workspace (all code deleted)</li>
              </ol>
              <p className="text-muted-foreground mt-4">
                <strong>No source code is persisted.</strong> Only the signed compliance attestation 
                is returned, identical to offline mode.
              </p>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Multi-Plane Evidence Model */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="max-w-5xl mx-auto px-4 space-y-8"
      >
        <div className="text-center space-y-2">
          <Shield className="h-12 w-12 text-primary mx-auto" />
          <h2 className="text-3xl font-semibold">Multi-Plane Evidence Model</h2>
          <p className="text-muted-foreground">
            Compliance requires evidence across three planes: Technical, System, and Procedural
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/20 text-blue-400">
                  <CheckCircle2 className="h-6 w-6" />
                </div>
                <CardTitle>Technical Evidence</CardTitle>
              </div>
              <CardDescription>
                Machine-verifiable evidence from source code and configuration files
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                <strong>Verification Method:</strong> Machine (AST parsing, regex patterns)
              </p>
              <p className="text-sm text-muted-foreground">
                <strong>Examples:</strong>
              </p>
              <ul className="list-disc list-inside text-sm text-muted-foreground ml-2 space-y-1">
                <li>Hardcoded secrets in code</li>
                <li>Insecure ACLs in infrastructure code</li>
                <li>Consent handling mechanisms</li>
                <li>Data erasure functionality</li>
              </ul>
              <p className="text-sm text-muted-foreground mt-3">
                <strong>State:</strong> VERIFIED_MACHINE (when evidence present)
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-purple-500/20 text-purple-400">
                  <FileText className="h-6 w-6" />
                </div>
                <CardTitle>System Evidence</CardTitle>
              </div>
              <CardDescription>
                Configuration-based evidence (flags, settings, policies)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                <strong>Verification Method:</strong> Configuration detection
              </p>
              <p className="text-sm text-muted-foreground">
                <strong>Examples:</strong>
              </p>
              <ul className="list-disc list-inside text-sm text-muted-foreground ml-2 space-y-1">
                <li>Logging enabled flags</li>
                <li>Retention duration settings</li>
                <li>Encryption-at-rest configuration</li>
                <li>MFA enforcement settings</li>
              </ul>
              <p className="text-sm text-muted-foreground mt-3">
                <strong>State:</strong> VERIFIED_SYSTEM (when evidence present)
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20 text-amber-400">
                  <Shield className="h-6 w-6" />
                </div>
                <CardTitle>Procedural Evidence</CardTitle>
              </div>
              <CardDescription>
                Human-attested evidence (policies, SOPs, training records)
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-sm text-muted-foreground">
                <strong>Verification Method:</strong> Human attestation (cryptographically signed)
              </p>
              <p className="text-sm text-muted-foreground">
                <strong>Examples:</strong>
              </p>
              <ul className="list-disc list-inside text-sm text-muted-foreground ml-2 space-y-1">
                <li>Incident response procedures</li>
                <li>Access review policies</li>
                <li>Employee training records</li>
                <li>Vendor risk assessments</li>
              </ul>
              <p className="text-sm text-muted-foreground mt-3">
                <strong>State:</strong> ATTESTED_HUMAN (when signed attestation present)
              </p>
            </CardContent>
          </Card>
        </div>
      </motion.section>

      {/* Cryptographic Attestation Flow */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="max-w-5xl mx-auto px-4 space-y-8"
      >
        <div className="text-center space-y-2">
          <FileText className="h-12 w-12 text-primary mx-auto" />
          <h2 className="text-3xl font-semibold">Cryptographic Attestation Flow</h2>
          <p className="text-muted-foreground">
            How compliance evidence becomes a legal-grade attestation
          </p>
        </div>

        <Card>
          <CardContent className="pt-6 space-y-6">
            <div className="space-y-4">
              <div className="flex items-start gap-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-semibold flex-shrink-0">
                  1
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-2">Evidence Collection</h3>
                  <p className="text-muted-foreground">
                    The agent scans your codebase and collects evidence for each compliance control. 
                    Each piece of evidence is hashed using SHA256.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-semibold flex-shrink-0">
                  2
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-2">Merkle Tree Construction</h3>
                  <p className="text-muted-foreground">
                    All evidence hashes are organized into a Merkle tree. The Merkle root provides 
                    cryptographic proof that the report has not been tampered with.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-semibold flex-shrink-0">
                  3
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-2">Ed25519 Signing</h3>
                  <p className="text-muted-foreground">
                    The report (including Merkle root) is signed with an Ed25519 private key. 
                    This provides cryptographic proof of authenticity and non-repudiation.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-semibold flex-shrink-0">
                  4
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-2">Backend Verification</h3>
                  <p className="text-muted-foreground">
                    The signed report is uploaded to the verification backend, which:
                  </p>
                  <ul className="list-disc list-inside space-y-1 text-muted-foreground ml-4 mt-2">
                    <li>Verifies the Ed25519 signature</li>
                    <li>Recomputes the Merkle root to ensure integrity</li>
                    <li>Validates control mappings and evidence types</li>
                  </ul>
                </div>
              </div>

              <div className="flex items-start gap-4">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-primary font-semibold flex-shrink-0">
                  5
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold mb-2">Legal-Grade Attestation</h3>
                  <p className="text-muted-foreground">
                    Upon successful verification, a compliance attestation is recorded in the ledger. 
                    This attestation includes:
                  </p>
                  <ul className="list-disc list-inside space-y-1 text-muted-foreground ml-4 mt-2">
                    <li>Framework coverage (SOC2, ISO27001, GDPR, DPDP)</li>
                    <li>Control states (VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, MISSING_EVIDENCE)</li>
                    <li>Evidence hashes (cryptographic binding)</li>
                    <li>Human signer identities (hashed for privacy)</li>
                    <li>Verification timestamp</li>
                  </ul>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button
          variant="outline"
          onClick={() => navigate("/")}
        >
          ← Back
        </Button>
        <Button
          onClick={() => navigate("/compliance-coverage")}
        >
          View Compliance Coverage
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </motion.div>
    </div>
  );
}


