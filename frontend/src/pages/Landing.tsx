/**
 * Landing Page - Intent, Not Action
 * 
 * Purpose: Establish trust, explain philosophy, do NOT collect access or data
 * 
 * Must include:
 * - What KratosComply is (compliance OS)
 * - What it is not (scanner, SaaS code harvester)
 * - High-level flow: Scan locally → Generate attestation → Verify & present
 * 
 * Must NOT:
 * - Ask for GitHub access
 * - Show dashboards or findings
 * - Mention vulnerabilities or CVEs
 * 
 * Primary CTA: "Generate Compliance Attestation"
 */
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, FileText, Lock, CheckCircle2, ArrowRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import DecryptedText from "@/components/DecryptedText";
import Particles from "@/components/Particles";

export function LandingPage() {
  const navigate = useNavigate();

  return (
    <div className="relative min-h-screen space-y-16 py-12 overflow-hidden">
      {/* Particles Background */}
      <div className="fixed inset-0 z-0">
        <Particles
          particleCount={300}
          particleSpread={15}
          speed={0.15}
          particleColors={["#6366f1", "#8b5cf6", "#ec4899", "#3b82f6"]}
          moveParticlesOnHover={true}
          particleHoverFactor={2}
          alphaParticles={true}
          particleBaseSize={80}
          sizeRandomness={0.8}
          cameraDistance={25}
          disableRotation={false}
        />
      </div>

      {/* Hero Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative text-center space-y-8 py-20 z-20"
      >
        <div className="relative z-10">
          <DecryptedText
            text="KratosComply"
            speed={80}
            maxIterations={25}
            sequential={true}
            revealDirection="center"
            useOriginalCharsOnly={false}
            className="text-7xl md:text-8xl font-bold bg-gradient-to-r from-indigo-400 via-purple-400 to-pink-400 bg-clip-text text-transparent"
            encryptedClassName="text-7xl md:text-8xl font-bold text-muted-foreground/30"
            parentClassName="block"
            animateOn="view"
          />
        </div>
        
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="text-2xl text-muted-foreground max-w-3xl mx-auto relative z-10 font-light"
        >
          Compliance Operating System for Startups
        </motion.p>
        
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="text-lg text-muted-foreground/80 max-w-2xl mx-auto relative z-10"
        >
          Generate audit-ready compliance attestations with cryptographic verification.
          Your source code never leaves your control.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="relative z-10"
        >
          <Button
            size="lg"
            className="text-lg px-8 py-6 h-auto"
            onClick={() => navigate("/architecture")}
          >
            Generate Compliance Attestation
            <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
        </motion.div>
      </motion.div>

      {/* What KratosComply Is */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.9 }}
        className="max-w-5xl mx-auto px-4 space-y-8 relative z-20"
      >
        <div className="text-center space-y-3">
          <h2 className="text-4xl font-bold">What KratosComply Is</h2>
          <p className="text-lg text-foreground/80">
            A compliance operating system that generates legal-grade attestations
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-3">
          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <ShieldCheck className="h-10 w-10 text-primary" />
              <CardTitle className="text-xl">Compliance Evidence Engine</CardTitle>
              <CardDescription className="text-base leading-relaxed">
                Scans your codebase locally to identify evidence gaps for SOC2, ISO27001, GDPR, DPDP Act, HIPAA, PCI-DSS, and NIST CSF compliance. Detects secrets, infrastructure misconfigurations, container security issues, API vulnerabilities, database risks, and CI/CD pipeline problems.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <Lock className="h-10 w-10 text-primary" />
              <CardTitle className="text-xl">Cryptographic Attestation</CardTitle>
              <CardDescription className="text-base leading-relaxed">
                Generates cryptographically signed compliance statements suitable for auditors, investors, and regulators
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <FileText className="h-10 w-10 text-primary" />
              <CardTitle className="text-xl">Offline-First</CardTitle>
              <CardDescription className="text-base leading-relaxed">
                All scanning happens locally. Your source code, configs, and infrastructure data never leave your environment
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </motion.div>

      {/* What KratosComply Is NOT */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.1 }}
        className="max-w-5xl mx-auto px-4 space-y-8 relative z-20"
      >
        <div className="text-center space-y-3">
          <h2 className="text-4xl font-bold">What KratosComply Is NOT</h2>
          <p className="text-lg text-foreground/80">
            Important clarifications about what we do not do
          </p>
        </div>

        <Card className="bg-card/95 backdrop-blur-sm border-border/50">
          <CardContent className="pt-8 pb-8">
            <ul className="space-y-6">
              <li className="flex items-start gap-4">
                <CheckCircle2 className="h-6 w-6 text-foreground/40 mt-1 flex-shrink-0" />
                <span className="text-base leading-relaxed">
                  <strong className="text-foreground font-bold">Not a security scanner:</strong>{" "}
                  <span className="text-foreground/80">
                    We do not scan for CVEs, dependency vulnerabilities, or runtime exploits. We focus on compliance evidence.
                  </span>
                </span>
              </li>
              <li className="flex items-start gap-4">
                <CheckCircle2 className="h-6 w-6 text-foreground/40 mt-1 flex-shrink-0" />
                <span className="text-base leading-relaxed">
                  <strong className="text-foreground font-bold">Not a SaaS code harvester:</strong>{" "}
                  <span className="text-foreground/80">
                    Your source code never leaves your control unless you explicitly upload evidence. GitHub OAuth mode uses ephemeral workers that destroy workspaces after scanning.
                  </span>
                </span>
              </li>
              <li className="flex items-start gap-4">
                <CheckCircle2 className="h-6 w-6 text-foreground/40 mt-1 flex-shrink-0" />
                <span className="text-base leading-relaxed">
                  <strong className="text-foreground font-bold">Not a continuous monitoring tool:</strong>{" "}
                  <span className="text-foreground/80">
                    We generate point-in-time compliance attestations. Evidence must be refreshed to maintain validity.
                  </span>
                </span>
              </li>
              <li className="flex items-start gap-4">
                <CheckCircle2 className="h-6 w-6 text-foreground/40 mt-1 flex-shrink-0" />
                <span className="text-base leading-relaxed">
                  <strong className="text-foreground font-bold">Not a SIEM or SAST tool:</strong>{" "}
                  <span className="text-foreground/80">
                    We do not monitor network traffic, detect runtime attacks, or perform dynamic analysis.
                  </span>
                </span>
              </li>
            </ul>
          </CardContent>
        </Card>
      </motion.div>

      {/* High-Level Flow */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.3 }}
        className="max-w-5xl mx-auto px-4 space-y-8 relative z-20"
      >
        <div className="text-center space-y-3">
          <h2 className="text-4xl font-bold">How It Works</h2>
          <p className="text-lg text-foreground/80">
            Simple, privacy-preserving compliance attestation flow
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-3">
          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-lg font-bold">
                  1
                </div>
                <CardTitle className="text-xl">Scan Locally</CardTitle>
              </div>
              <CardDescription className="text-base leading-relaxed">
                Run the agent on your codebase. All processing happens offline. No network calls, no data exfiltration.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-white text-lg font-bold">
                  2
                </div>
                <CardTitle className="text-xl">Generate Attestation</CardTitle>
              </div>
              <CardDescription className="text-base leading-relaxed">
                The agent generates a cryptographically signed compliance report with evidence hashes and Merkle tree integrity.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="bg-card/95 backdrop-blur-sm border-border/50">
            <CardHeader className="space-y-4 pb-8">
              <div className="flex items-center gap-3 mb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-white font-bold">
                  3
                </div>
                <CardTitle>Verify & Present</CardTitle>
              </div>
              <CardDescription>
                Upload the attestation to verify signatures and create a legal-grade 
                compliance statement for auditors and regulators.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </motion.div>

      {/* Next Steps */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1.5 }}
        className="max-w-4xl mx-auto px-4 space-y-6 relative z-20 pb-20"
      >
        <div className="text-center space-y-4">
          <Button
            size="lg"
            variant="outline"
            className="text-lg px-8 py-6 h-auto"
            onClick={() => navigate("/architecture")}
          >
            Learn How It Works
            <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
          <p className="text-sm text-muted-foreground">
            Understand the architecture, privacy model, and compliance coverage before proceeding
          </p>
        </div>
      </motion.div>
    </div>
  );
}
