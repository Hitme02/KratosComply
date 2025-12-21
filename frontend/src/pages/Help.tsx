/**
 * Help Page - Single Source of Truth (Last Page)
 * 
 * This must be the most detailed page.
 * 
 * Must explain:
 * - Full system behavior
 * - Offline vs GitHub mode
 * - Evidence types
 * - What KratosComply does NOT do
 * - Privacy guarantees
 * - Auditor FAQ
 * - Legal positioning
 * 
 * If a user reads only this page, they should understand the entire system.
 */
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  HelpCircle,
  Shield,
  FileText,
  CheckCircle2,
  XCircle,
  ArrowLeft,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";

export function HelpPage() {
  const navigate = useNavigate();

  return (
    <div className="space-y-16 py-12 max-w-4xl mx-auto">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <HelpCircle className="h-16 w-16 text-primary mx-auto" />
        <h1 className="text-4xl font-semibold">Help & Documentation</h1>
        <p className="text-xl text-muted-foreground">
          Complete guide to KratosComply. Read this page to understand the entire system.
        </p>
      </motion.div>

      {/* System Behavior */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Full System Behavior</CardTitle>
            <CardDescription>
              How KratosComply works from start to finish
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <h3 className="font-semibold">1. Evidence Collection</h3>
              <p className="text-sm text-muted-foreground">
                The KratosComply agent scans your codebase locally (or in an ephemeral workspace for GitHub mode). 
                It collects evidence for compliance controls across three planes:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>Technical Evidence:</strong> Machine-verifiable evidence from source code (AST parsing, regex patterns)</li>
                <li><strong>System Evidence:</strong> Configuration-based evidence (flags, settings, policies)</li>
                <li><strong>Procedural Evidence:</strong> Human-attested evidence (policies, SOPs, training records)</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">2. Report Generation</h3>
              <p className="text-sm text-muted-foreground">
                The agent generates a compliance report containing:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li>Control violation findings (evidence gaps)</li>
                <li>Evidence hashes (SHA256 hashes of evidence, not the evidence itself)</li>
                <li>Merkle root (cryptographic proof of report integrity)</li>
                <li>Ed25519 signature (cryptographic proof of authenticity)</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">3. Verification & Attestation</h3>
              <p className="text-sm text-muted-foreground">
                The signed report is uploaded to the verification backend, which:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li>Verifies the Ed25519 signature</li>
                <li>Recomputes the Merkle root to ensure integrity</li>
                <li>Validates control mappings and evidence types</li>
                <li>Records a legal-grade compliance attestation in the ledger</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Offline vs GitHub Mode */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Offline vs GitHub Mode</CardTitle>
            <CardDescription>
              Understanding the differences and privacy implications
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="offline">
                <AccordionTrigger>Offline Docker Mode (Privacy-Maximum)</AccordionTrigger>
                <AccordionContent className="space-y-3">
                  <p className="text-sm text-muted-foreground">
                    <strong>What happens:</strong> You run the agent locally using Docker. All scanning, 
                    analysis, and report generation happens on your machine. Zero network calls during scanning.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>What stays local:</strong> 100% of your source code, configuration files, 
                    infrastructure code, and all scanning/analysis.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>What leaves:</strong> Only the signed compliance attestation report (after you 
                    explicitly upload it to the verification backend).
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>Best for:</strong> Organizations with strict data privacy requirements, 
                    air-gapped environments, regulated industries, sensitive codebases.
                  </p>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="github">
                <AccordionTrigger>GitHub OAuth Mode (Convenience)</AccordionTrigger>
                <AccordionContent className="space-y-3">
                  <p className="text-sm text-muted-foreground">
                    <strong>What happens:</strong> You authorize GitHub OAuth. The backend creates an 
                    ephemeral workspace, clones your repository, runs the agent scan, generates the 
                    attestation, and immediately destroys the workspace.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>What stays local:</strong> Your source code is cloned to a temporary workspace 
                    that is immediately destroyed after scanning. No code is persisted.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>What leaves:</strong> GitHub OAuth token (for repository access), signed 
                    compliance attestation (after scan completes). Source code is NEVER persisted.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    <strong>Best for:</strong> Teams that want convenience without sacrificing privacy. 
                    Output is identical to offline mode: signed compliance attestation only.
                  </p>
                  <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 mt-3">
                    <p className="text-xs text-muted-foreground">
                      <strong>Important:</strong> The ephemeral worker system ensures code is destroyed 
                      immediately after scanning. The workspace lifecycle is: create → clone → scan → 
                      generate attestation → destroy. No source code is ever persisted.
                    </p>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </CardContent>
        </Card>
      </motion.section>

      {/* Evidence Types */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Evidence Types</CardTitle>
            <CardDescription>
              Understanding the three planes of compliance evidence
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-blue-400" />
                  <h3 className="font-semibold">Technical Evidence</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Machine-verifiable evidence from source code. Examples: hardcoded secrets, insecure ACLs, 
                  consent handling code, data erasure functionality.
                </p>
                <p className="text-xs text-muted-foreground">
                  <strong>State:</strong> VERIFIED_MACHINE (when evidence present)
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-purple-400" />
                  <h3 className="font-semibold">System Evidence</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Configuration-based evidence. Examples: logging enabled flags, retention duration settings, 
                  encryption-at-rest configuration, MFA enforcement settings.
                </p>
                <p className="text-xs text-muted-foreground">
                  <strong>State:</strong> VERIFIED_SYSTEM (when evidence present)
                </p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-amber-400" />
                  <h3 className="font-semibold">Procedural Evidence</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Human-attested evidence. Examples: incident response procedures, access review policies, 
                  employee training records, vendor risk assessments.
                </p>
                <p className="text-xs text-muted-foreground">
                  <strong>State:</strong> ATTESTED_HUMAN (when signed attestation present)
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* What KratosComply Does NOT Do */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>What KratosComply Does NOT Do</CardTitle>
            <CardDescription>
              Important clarifications about system limitations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <XCircle className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold mb-1">Not a Security Scanner</h3>
                  <p className="text-sm text-muted-foreground">
                    KratosComply does NOT scan for CVEs, dependency vulnerabilities, or runtime exploits. 
                    We focus on compliance evidence, not security vulnerabilities.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <XCircle className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold mb-1">Not a SaaS Code Harvester</h3>
                  <p className="text-sm text-muted-foreground">
                    Your source code never leaves your control unless you explicitly upload evidence. 
                    GitHub OAuth mode uses ephemeral workers that destroy workspaces after scanning.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <XCircle className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold mb-1">Not a Continuous Monitoring Tool</h3>
                  <p className="text-sm text-muted-foreground">
                    We generate point-in-time compliance attestations. Evidence must be refreshed to 
                    maintain validity. We do not provide "continuous compliance" monitoring.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <XCircle className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold mb-1">Not a SIEM, SAST, or DAST Tool</h3>
                  <p className="text-sm text-muted-foreground">
                    We do NOT monitor network traffic, detect runtime attacks, or perform dynamic analysis. 
                    We are compliance infrastructure, not security tooling.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3">
                <XCircle className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
                <div>
                  <h3 className="font-semibold mb-1">Not a "Full Automation" Solution</h3>
                  <p className="text-sm text-muted-foreground">
                    Many compliance controls require human attestation. We clearly distinguish between 
                    machine-verified, system-verified, and human-attested evidence. We never claim 
                    "100% automated compliance."
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Privacy Guarantees */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Privacy Guarantees</CardTitle>
            <CardDescription>
              What data is collected, stored, and shared
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <h3 className="font-semibold">Offline Docker Mode</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>No data collection:</strong> The agent runs entirely offline. No network calls are made.</li>
                <li><strong>No data storage:</strong> Reports are generated locally. You choose when and if to upload.</li>
                <li><strong>No data sharing:</strong> Only the signed attestation (not source code) is uploaded if you choose to verify it.</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">GitHub OAuth Mode</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>Ephemeral workspaces:</strong> Code is cloned to temporary workspaces that are immediately destroyed.</li>
                <li><strong>No code persistence:</strong> Source code is NEVER stored or persisted. Only the signed attestation is returned.</li>
                <li><strong>OAuth token:</strong> GitHub OAuth token is used only for repository access during scanning. Token is not stored long-term.</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Backend Storage</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>Attestation records:</strong> Only compliance attestations (Merkle roots, signatures, metadata) are stored.</li>
                <li><strong>No source code:</strong> Source code is never stored in the backend.</li>
                <li><strong>Evidence hashes:</strong> Only SHA256 hashes of evidence are stored, not the evidence itself.</li>
                <li><strong>Human signer identities:</strong> Signer identities are hashed for privacy-preserving auditability.</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Auditor FAQ */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Auditor FAQ</CardTitle>
            <CardDescription>
              Common questions from auditors, investors, and regulators
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="q1">
                <AccordionTrigger>How do I verify an attestation?</AccordionTrigger>
                <AccordionContent className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Each attestation includes a Merkle root and Ed25519 signature. You can verify:
                  </p>
                  <ol className="list-decimal list-inside space-y-1 text-sm text-muted-foreground ml-4">
                    <li>The Ed25519 signature using the agent's public key</li>
                    <li>The Merkle root by recomputing it from evidence hashes</li>
                    <li>The attestation timestamp and framework coverage</li>
                  </ol>
                  <p className="text-sm text-muted-foreground mt-2">
                    Use the auditor verification endpoint: <code className="bg-muted px-2 py-1 rounded text-xs">POST /auditor/verify</code>
                  </p>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="q2">
                <AccordionTrigger>What evidence is included in an attestation?</AccordionTrigger>
                <AccordionContent>
                  <p className="text-sm text-muted-foreground">
                    Attestations include:
                  </p>
                  <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                    <li>Evidence hashes (SHA256 hashes of evidence, not the evidence itself)</li>
                    <li>Control states (VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, MISSING_EVIDENCE, EXPIRED_EVIDENCE)</li>
                    <li>Framework coverage (SOC2, ISO27001, GDPR, DPDP)</li>
                    <li>Merkle root (cryptographic proof of integrity)</li>
                    <li>Ed25519 signature (cryptographic proof of authenticity)</li>
                    <li>Human signer identities (hashed for privacy)</li>
                    <li>Verification timestamp</li>
                  </ul>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="q3">
                <AccordionTrigger>Can attestations be edited or modified?</AccordionTrigger>
                <AccordionContent>
                  <p className="text-sm text-muted-foreground">
                    <strong>No.</strong> Attestations are immutable. They are cryptographically sealed and cannot be edited or modified. 
                    To update compliance status, a new attestation must be generated. Historical attestations provide an audit trail 
                    of compliance over time.
                  </p>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="q4">
                <AccordionTrigger>How long is evidence valid?</AccordionTrigger>
                <AccordionContent>
                  <p className="text-sm text-muted-foreground">
                    Evidence validity depends on the control's expiry policy. Some controls require evidence to be refreshed 
                    every 90 days, others every 365 days. Expired evidence is clearly marked in the UI. Controls with expired 
                    evidence will fail an audit until evidence is refreshed.
                  </p>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="q5">
                <AccordionTrigger>What is the difference between machine-verified and human-attested evidence?</AccordionTrigger>
                <AccordionContent>
                  <p className="text-sm text-muted-foreground">
                    <strong>Machine-verified:</strong> Fully automated verification through AST parsing and regex patterns. 
                    Examples: hardcoded secrets, insecure ACLs, consent handling code.
                  </p>
                  <p className="text-sm text-muted-foreground mt-2">
                    <strong>Human-attested:</strong> Requires human declaration with cryptographic signature. Examples: 
                    incident response procedures, access review policies, training records. Human-attested evidence 
                    includes the signer's public key and Ed25519 signature.
                  </p>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </CardContent>
        </Card>
      </motion.section>

      {/* Legal Positioning */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
      >
        <Card>
          <CardHeader>
            <CardTitle>Legal Positioning</CardTitle>
            <CardDescription>
              How KratosComply fits into compliance and audit frameworks
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <h3 className="font-semibold">Compliance Operating System</h3>
              <p className="text-sm text-muted-foreground">
                KratosComply is a compliance operating system, not a security scanner. We generate 
                compliance evidence and legal-grade attestations suitable for:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>Auditors:</strong> SOC2, ISO27001, GDPR, DPDP Act compliance audits</li>
                <li><strong>Investors:</strong> Due diligence and compliance verification</li>
                <li><strong>Regulators:</strong> Regulatory compliance submissions</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Cryptographic Proof</h3>
              <p className="text-sm text-muted-foreground">
                Every attestation is cryptographically sealed with:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li>Merkle root (proof of integrity)</li>
                <li>Ed25519 signature (proof of authenticity and non-repudiation)</li>
                <li>Evidence hashes (cryptographic binding)</li>
                <li>Human signer identities (hashed for privacy)</li>
              </ul>
            </div>

            <div className="space-y-3">
              <h3 className="font-semibold">Audit Defensibility</h3>
              <p className="text-sm text-muted-foreground">
                KratosComply is designed for audit defensibility. Every claim is:
              </p>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li><strong>Traceable:</strong> Linked to specific compliance controls and evidence</li>
                <li><strong>Cryptographically bound:</strong> Evidence hashes and Merkle trees provide proof</li>
                <li><strong>Time-scoped:</strong> Timestamps and expiry policies ensure evidence freshness</li>
                <li><strong>Verifiable:</strong> Auditors can independently verify attestations</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </motion.section>

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.8 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button variant="outline" onClick={() => navigate("/attestations")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Attestations
        </Button>
      </motion.div>
    </div>
  );
}

