import { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Github, Container, ShieldCheck, Upload, FileCheck, BarChart3, ArrowRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getGitHubAuthUrl } from "@/services/api";
import DecryptedText from "@/components/DecryptedText";
import Particles from "@/components/Particles";
import TiltedCard from "@/components/TiltedCard";

const steps = [
  {
    number: 1,
    title: "Choose your mode",
    description: "Select Docker agent for offline scans or GitHub OAuth for cloud-based analysis",
    icon: ShieldCheck,
  },
  {
    number: 2,
    title: "Run the agent",
    description: "Docker: Scan your local repo. GitHub: Authorize and scan your repository automatically",
    icon: FileCheck,
  },
  {
    number: 3,
    title: "Get your report",
    description: "Docker: Upload the generated report. GitHub: Report appears automatically on the dashboard",
    icon: Upload,
  },
  {
    number: 4,
    title: "Review & attest",
    description: "View control violations, verify cryptographic signatures, create legal-grade attestations, and assess audit readiness",
    icon: BarChart3,
  },
];

export function LandingPage() {
  const navigate = useNavigate();
  const [selectedMode, setSelectedMode] = useState<"docker" | "github" | null>(null);

  const handleModeSelect = (mode: "docker" | "github") => {
    setSelectedMode(mode);
    if (mode === "github") {
      // Trigger GitHub OAuth flow
      window.location.href = getGitHubAuthUrl();
    } else {
      // Navigate to Docker instructions
      navigate("/docker-setup");
    }
  };

  return (
    <div className="relative min-h-screen space-y-12 py-12 overflow-hidden">
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

      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative text-center space-y-6 py-20 z-20"
      >
        <div className="relative">
          <DecryptedText
            text="KratosComply"
            speed={80}
            maxIterations={25}
            sequential={true}
            revealDirection="center"
            useOriginalCharsOnly={false}
            characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
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
          className="text-xl text-muted-foreground max-w-2xl mx-auto relative z-20"
        >
          Compliance evidence automation for startups. Generate audit-ready compliance reports with
          cryptographic verification for SOC2, ISO27001, GDPR, and DPDP Act compliance.
        </motion.p>
      </motion.div>

      {/* Step-by-step tiles */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4 max-w-7xl mx-auto px-4 relative z-20">
        {steps.map((step, idx) => (
          <motion.div
            key={step.number}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            className="h-[240px]"
          >
            <TiltedCard
              containerHeight="100%"
              containerWidth="100%"
              imageHeight="100%"
              imageWidth="100%"
              scaleOnHover={1.05}
              rotateAmplitude={12}
              showMobileWarning={false}
              showTooltip={false}
            >
              <Card className="h-full w-full bg-card/95 backdrop-blur-sm border border-border/50 hover:border-primary/50 transition-colors">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-white font-bold">
                      {step.number}
                    </div>
                    <step.icon className="h-6 w-6 text-primary" />
                  </div>
                  <CardTitle className="mt-4">{step.title}</CardTitle>
                  <CardDescription>{step.description}</CardDescription>
                </CardHeader>
              </Card>
            </TiltedCard>
          </motion.div>
        ))}
      </div>

      {/* Mode selection */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="max-w-4xl mx-auto px-4 space-y-6 relative z-20"
      >
        <div className="text-center space-y-2">
          <h2 className="text-3xl font-semibold">Choose your compliance mode</h2>
          <p className="text-muted-foreground">
            Select how you want to run the KratosComply agent
          </p>
        </div>

        <div className="grid gap-6 md:grid-cols-2">
          {/* Docker Mode */}
          <div className="h-[350px]">
            <TiltedCard
              containerHeight="100%"
              containerWidth="100%"
              imageHeight="100%"
              imageWidth="100%"
              scaleOnHover={1.05}
              rotateAmplitude={12}
              showMobileWarning={false}
              showTooltip={false}
            >
            <Card
              className={`h-full w-full cursor-pointer transition-all bg-card/95 backdrop-blur-sm ${
                selectedMode === "docker"
                  ? "border-primary ring-2 ring-primary/20"
                  : "border-border/50 hover:border-primary/50"
              }`}
              onClick={() => handleModeSelect("docker")}
            >
              <CardHeader>
                <div className="flex items-center gap-3 mb-2">
                  <Container className="h-8 w-8 text-primary" />
                  <CardTitle>Docker Agent (Offline)</CardTitle>
                </div>
                <CardDescription>
                  Run the agent locally in a Docker container. Perfect for air-gapped environments or when you need full control.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <ul className="text-sm text-muted-foreground space-y-2">
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> Scan local repositories
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> No cloud dependencies
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> Upload report manually
                  </li>
                </ul>
                <Button className="w-full mt-4" variant={selectedMode === "docker" ? "default" : "outline"}>
                  Use Docker Agent
                </Button>
              </CardContent>
            </Card>
          </TiltedCard>
          </div>

          {/* GitHub Mode */}
          <div className="h-[350px]">
            <TiltedCard
              containerHeight="100%"
              containerWidth="100%"
              imageHeight="100%"
              imageWidth="100%"
              scaleOnHover={1.05}
              rotateAmplitude={12}
              showMobileWarning={false}
              showTooltip={false}
            >
            <Card
              className={`h-full w-full cursor-pointer transition-all bg-card/95 backdrop-blur-sm ${
                selectedMode === "github"
                  ? "border-primary ring-2 ring-primary/20"
                  : "border-border/50 hover:border-primary/50"
              }`}
              onClick={() => handleModeSelect("github")}
            >
              <CardHeader>
                <div className="flex items-center gap-3 mb-2">
                  <Github className="h-8 w-8 text-primary" />
                  <CardTitle>GitHub OAuth (Cloud)</CardTitle>
                </div>
                <CardDescription>
                  Connect your GitHub repository. The agent scans automatically and reports appear instantly on your dashboard.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <ul className="text-sm text-muted-foreground space-y-2">
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> Automatic scanning
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> Real-time reports
                  </li>
                  <li className="flex items-center gap-2">
                    <ArrowRight className="h-4 w-4" /> No manual uploads
                  </li>
                </ul>
                <Button className="w-full mt-4" variant={selectedMode === "github" ? "default" : "outline"}>
                  Connect GitHub
                </Button>
              </CardContent>
            </Card>
          </TiltedCard>
          </div>
        </div>
      </motion.div>

      {/* Quick start info */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.7 }}
        className="max-w-4xl mx-auto px-4 relative z-20"
      >
        <Card className="bg-gradient-to-br from-indigo-500/10 to-purple-500/10 border-primary/20">
          <CardContent className="p-6">
            <div className="flex items-start gap-4">
              <ShieldCheck className="h-6 w-6 text-primary mt-1" />
              <div className="space-y-2">
                <h3 className="font-semibold text-lg">Privacy-first compliance</h3>
                <p className="text-sm text-muted-foreground">
                  KratosComply never stores your source code. We only process hashed evidence and signatures for compliance verification.
                  Your code stays on your infrastructure or GitHub—we only see what you explicitly share.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
