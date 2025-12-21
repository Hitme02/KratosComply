/**
 * Mode Selection Page (Critical Decision Point)
 * 
 * Two cards only:
 * - Offline Docker Mode (Privacy-Max)
 * - GitHub OAuth Mode (Convenience)
 * 
 * Each card must show:
 * - What data stays local
 * - What data leaves (if any)
 * - Who this mode is for
 * 
 * No default selection. User must consciously choose.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Container, Github, Lock, ArrowRight, ArrowLeft, CheckCircle2, AlertCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getGitHubAuthUrl } from "@/services/api";

export function ModeSelectionPage() {
  const navigate = useNavigate();
  const [selectedMode, setSelectedMode] = useState<"docker" | "github" | null>(null);

  const handleModeSelect = (mode: "docker" | "github") => {
    setSelectedMode(mode);
    if (mode === "github") {
      // Trigger GitHub OAuth flow
      window.location.href = getGitHubAuthUrl();
    } else {
      // Navigate to Docker setup
      navigate("/docker-setup");
    }
  };

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-semibold">Choose Your Compliance Mode</h1>
        <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
          Select how you want to run the KratosComply agent. This is a critical decision 
          that affects data privacy and workflow.
        </p>
      </motion.div>

      {/* Mode Selection Cards */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-5xl mx-auto px-4 space-y-8"
      >
        <div className="grid gap-6 md:grid-cols-2">
          {/* Docker Mode */}
          <Card
            className={`h-full cursor-pointer transition-all bg-card/95 backdrop-blur-sm ${
              selectedMode === "docker"
                ? "border-primary ring-2 ring-primary/20"
                : "border-border/50 hover:border-primary/50"
            }`}
            onClick={() => handleModeSelect("docker")}
          >
            <CardHeader>
              <div className="flex items-center gap-3 mb-2">
                <Container className="h-8 w-8 text-primary" />
                <CardTitle>Offline Docker Mode</CardTitle>
              </div>
              <CardDescription>
                Privacy-maximum mode. All processing happens locally with zero data exfiltration.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div>
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <Lock className="h-4 w-4 text-emerald-400" />
                    What Stays Local
                  </h3>
                  <ul className="space-y-1 text-sm text-muted-foreground ml-6">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>100% of your source code</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>All configuration files</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>Infrastructure code (Terraform, etc.)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>All scanning and analysis</span>
                    </li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-amber-400" />
                    What Leaves Your Control
                  </h3>
                  <ul className="space-y-1 text-sm text-muted-foreground ml-6">
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400">•</span>
                      <span>Only the signed compliance attestation report (after you explicitly upload it)</span>
                    </li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-2">Who This Mode Is For</h3>
                  <p className="text-sm text-muted-foreground">
                    Organizations with strict data privacy requirements, air-gapped environments, 
                    or those who want complete control over the scanning process. Perfect for 
                    regulated industries and sensitive codebases.
                  </p>
                </div>
              </div>

              <Button
                className="w-full mt-4"
                variant={selectedMode === "docker" ? "default" : "outline"}
                onClick={(e) => {
                  e.stopPropagation();
                  handleModeSelect("docker");
                }}
              >
                Use Offline Docker Mode
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>

          {/* GitHub Mode */}
          <Card
            className={`h-full cursor-pointer transition-all bg-card/95 backdrop-blur-sm ${
              selectedMode === "github"
                ? "border-primary ring-2 ring-primary/20"
                : "border-border/50 hover:border-primary/50"
            }`}
            onClick={() => handleModeSelect("github")}
          >
            <CardHeader>
              <div className="flex items-center gap-3 mb-2">
                <Github className="h-8 w-8 text-primary" />
                <CardTitle>GitHub OAuth Mode</CardTitle>
              </div>
              <CardDescription>
                Convenience mode with ephemeral workers. Code is never persisted.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div>
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <Lock className="h-4 w-4 text-emerald-400" />
                    What Stays Local
                  </h3>
                  <ul className="space-y-1 text-sm text-muted-foreground ml-6">
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>Your source code (cloned to ephemeral workspace, immediately destroyed)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                      <span>All scanning happens in temporary workspace</span>
                    </li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-amber-400" />
                    What Leaves Your Control
                  </h3>
                  <ul className="space-y-1 text-sm text-muted-foreground ml-6">
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400">•</span>
                      <span>GitHub OAuth token (for repository access)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-amber-400">•</span>
                      <span>Signed compliance attestation (after scan completes)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400">•</span>
                      <span className="line-through">Source code is NEVER persisted</span>
                    </li>
                  </ul>
                </div>

                <div>
                  <h3 className="font-semibold mb-2">Who This Mode Is For</h3>
                  <p className="text-sm text-muted-foreground">
                    Teams that want convenience without sacrificing privacy. The ephemeral worker 
                    system ensures code is destroyed immediately after scanning. Output is identical 
                    to offline mode: signed compliance attestation only.
                  </p>
                </div>
              </div>

              <Button
                className="w-full mt-4"
                variant={selectedMode === "github" ? "default" : "outline"}
                onClick={(e) => {
                  e.stopPropagation();
                  handleModeSelect("github");
                }}
              >
                Use GitHub OAuth Mode
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Important Notice */}
        <Card className="bg-amber-500/10 border-amber-500/20">
          <CardContent className="pt-6">
            <div className="flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-amber-400 mt-0.5 flex-shrink-0" />
              <div className="space-y-2">
                <h3 className="font-semibold">Important: No Default Selection</h3>
                <p className="text-sm text-muted-foreground">
                  You must consciously choose your mode. This decision affects data privacy and workflow. 
                  Both modes produce identical output (signed compliance attestation), but differ in 
                  convenience and data handling.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button
          variant="outline"
          onClick={() => navigate("/compliance-coverage")}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back
        </Button>
      </motion.div>
    </div>
  );
}


