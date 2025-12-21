/**
 * Controls & Evidence Page (Most Important Page)
 * 
 * This is where auditors live.
 * 
 * Layout:
 * - Left: Control list (by framework)
 * - Center: Control details
 * - Right: Evidence panel
 * 
 * For each control show:
 * - Control ID & description
 * - Verification method (Machine, System, Human)
 * - Current state (VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, MISSING, EXPIRED)
 * - Linked evidence hashes
 * - Evidence actions (Upload evidence, View hashed proof, Sign attestation if human)
 * 
 * Never auto-advance controls.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  CheckCircle2,
  XCircle,
  Clock,
  FileText,
  Shield,
  Upload,
  Eye,
  ArrowLeft,
  AlertCircle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useReportStore } from "@/hooks/useReportStore";
import { cn } from "@/lib/utils";

type ControlState = "VERIFIED_MACHINE" | "VERIFIED_SYSTEM" | "ATTESTED_HUMAN" | "MISSING_EVIDENCE" | "EXPIRED_EVIDENCE";
type VerificationMethod = "machine" | "system" | "human_attestation";

interface ControlDetail {
  control_id: string;
  framework: string;
  control_category: string;
  description: string;
  verification_method: VerificationMethod;
  state: ControlState;
  evidence_hash?: string;
  findings: Array<{
    id: string;
    file: string;
    line?: number;
    snippet: string;
    severity: string;
  }>;
  frameworks_affected: string[];
  auditor_explanation?: string;
}

const stateConfig: Record<ControlState, { icon: typeof CheckCircle2; color: string; label: string }> = {
  VERIFIED_MACHINE: { icon: CheckCircle2, color: "text-emerald-400", label: "Machine Verified" },
  VERIFIED_SYSTEM: { icon: Shield, color: "text-blue-400", label: "System Verified" },
  ATTESTED_HUMAN: { icon: FileText, color: "text-purple-400", label: "Human Attested" },
  MISSING_EVIDENCE: { icon: XCircle, color: "text-red-400", label: "Evidence Missing" },
  EXPIRED_EVIDENCE: { icon: Clock, color: "text-amber-400", label: "Evidence Expired" },
};

const verificationMethodConfig: Record<VerificationMethod, { label: string; description: string }> = {
  machine: {
    label: "Machine-Verified",
    description: "Fully automated verification through AST parsing and regex patterns",
  },
  system: {
    label: "System-Verified",
    description: "Configuration detection (flags, settings, policies)",
  },
  human_attestation: {
    label: "Human-Attested",
    description: "Requires human declaration with cryptographic signature",
  },
};

export function ControlsEvidencePage() {
  const { report } = useReportStore();
  const navigate = useNavigate();
  const [selectedControl, setSelectedControl] = useState<ControlDetail | null>(null);
  const [selectedFramework, setSelectedFramework] = useState<string>("all");

  if (!report) {
    return (
      <div className="space-y-6 py-12">
        <Card>
          <CardHeader>
            <CardTitle>Controls & Evidence</CardTitle>
            <CardDescription>
              Upload a compliance evidence report to view controls and evidence status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => navigate("/audit-cockpit")}>
              Go to Dashboard
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Group findings by control_id
  const controlsMap = new Map<string, ControlDetail>();
  const frameworks = new Set<string>();

  report.findings.forEach((finding) => {
    const controlId = finding.control_id || "UNKNOWN";
    const framework = finding.compliance_frameworks_affected?.[0] || "UNKNOWN";
    frameworks.add(framework);

    const key = `${controlId}-${framework}`;
    if (!controlsMap.has(key)) {
      let state: ControlState = "MISSING_EVIDENCE";
      if (finding.control_pass_fail_status === "PASS") {
        state = "VERIFIED_MACHINE"; // Simplified - would check evidence type
      }

      let verification_method: VerificationMethod = "machine";
      if (finding.control_category?.toLowerCase().includes("system") || 
          finding.control_category?.toLowerCase().includes("config")) {
        verification_method = "system";
      }

      controlsMap.set(key, {
        control_id: controlId,
        framework,
        control_category: finding.control_category || "Unknown",
        description: finding.auditor_explanation || "No description available",
        verification_method,
        state,
        evidence_hash: finding.evidence_hash,
        findings: [],
        frameworks_affected: finding.compliance_frameworks_affected || [],
        auditor_explanation: finding.auditor_explanation,
      });
    }

    const control = controlsMap.get(key)!;
    control.findings.push({
      id: finding.id,
      file: finding.file,
      line: finding.line || undefined,
      snippet: finding.snippet,
      severity: finding.severity,
    });
  });

  const controls = Array.from(controlsMap.values());
  const filteredControls =
    selectedFramework === "all"
      ? controls
      : controls.filter((c) => c.framework === selectedFramework);

  // Group by framework for left panel
  const controlsByFramework = new Map<string, ControlDetail[]>();
  filteredControls.forEach((control) => {
    if (!controlsByFramework.has(control.framework)) {
      controlsByFramework.set(control.framework, []);
    }
    controlsByFramework.get(control.framework)!.push(control);
  });

  // Select first control if none selected
  if (!selectedControl && filteredControls.length > 0) {
    setSelectedControl(filteredControls[0]);
  }

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-5xl mx-auto px-4 flex items-center justify-between"
      >
        <div>
          <h1 className="text-4xl font-semibold">Controls & Evidence</h1>
          <p className="text-muted-foreground mt-2">
            View compliance controls, evidence status, and verification methods. This is where auditors review compliance.
          </p>
        </div>
        <Button variant="outline" onClick={() => navigate("/audit-cockpit")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Dashboard
        </Button>
      </motion.div>

      {/* Framework Filter */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Tabs value={selectedFramework} onValueChange={setSelectedFramework}>
          <TabsList>
            <TabsTrigger value="all">All Frameworks</TabsTrigger>
            {Array.from(frameworks).map((fw) => (
              <TabsTrigger key={fw} value={fw}>
                {fw}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </motion.div>

      {/* Three-Column Layout */}
      <div className="max-w-7xl mx-auto px-4">
        <div className="grid gap-6 lg:grid-cols-12">
        {/* Left: Control List */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-3 space-y-4"
        >
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Controls by Framework</CardTitle>
              <CardDescription>{filteredControls.length} control{filteredControls.length !== 1 ? "s" : ""}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 max-h-[calc(100vh-300px)] overflow-y-auto">
              {Array.from(controlsByFramework.entries()).map(([framework, frameworkControls]) => (
                <div key={framework} className="space-y-2">
                  <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                    {framework}
                  </h3>
                  {frameworkControls.map((control) => {
                    const config = stateConfig[control.state];
                    const Icon = config.icon;
                    const isSelected = selectedControl?.control_id === control.control_id &&
                      selectedControl?.framework === control.framework;

                    return (
                      <button
                        key={`${control.control_id}-${control.framework}`}
                        onClick={() => setSelectedControl(control)}
                        className={cn(
                          "w-full text-left rounded-lg border p-3 transition-all",
                          isSelected
                            ? "border-primary bg-primary/10"
                            : "border-border/50 hover:border-primary/50 bg-card"
                        )}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant="outline" className="text-xs">
                                {control.control_id}
                              </Badge>
                              <Icon className={cn("h-4 w-4 flex-shrink-0", config.color)} />
                            </div>
                            <p className="text-xs text-muted-foreground truncate">
                              {control.control_category}
                            </p>
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>

        {/* Center: Control Details */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-6 space-y-4"
        >
          {selectedControl ? (
            <Card>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant="outline">{selectedControl.control_id}</Badge>
                      {selectedControl.frameworks_affected.map((fw) => (
                        <Badge key={fw} variant="secondary">{fw}</Badge>
                      ))}
                    </div>
                    <CardTitle>{selectedControl.control_category}</CardTitle>
                    <CardDescription className="mt-2">
                      {selectedControl.description}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Verification Method */}
                <div>
                  <h3 className="font-semibold mb-2">Verification Method</h3>
                  <div className="rounded-lg border border-border/50 bg-muted/20 p-4 transition-all duration-300 hover:border-primary/60 hover:shadow-lg hover:shadow-primary/10">
                    <div className="flex items-center gap-2 mb-2">
                      {selectedControl.verification_method === "machine" && (
                        <CheckCircle2 className="h-5 w-5 text-blue-400" />
                      )}
                      {selectedControl.verification_method === "system" && (
                        <Shield className="h-5 w-5 text-purple-400" />
                      )}
                      {selectedControl.verification_method === "human_attestation" && (
                        <FileText className="h-5 w-5 text-amber-400" />
                      )}
                      <span className="font-semibold">
                        {verificationMethodConfig[selectedControl.verification_method].label}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {verificationMethodConfig[selectedControl.verification_method].description}
                    </p>
                  </div>
                </div>

                {/* Current State */}
                <div>
                  <h3 className="font-semibold mb-2">Current State</h3>
                  <div className="rounded-lg border border-border/50 bg-muted/20 p-4 transition-all duration-300 hover:border-primary/60 hover:shadow-lg hover:shadow-primary/10">
                    <div className="flex items-center gap-2">
                      {(() => {
                        const config = stateConfig[selectedControl.state];
                        const Icon = config.icon;
                        return (
                          <>
                            <Icon className={cn("h-5 w-5", config.color)} />
                            <span className={cn("font-semibold", config.color)}>{config.label}</span>
                          </>
                        );
                      })()}
                    </div>
                    {selectedControl.state === "MISSING_EVIDENCE" && (
                      <p className="text-sm text-muted-foreground mt-2">
                        This control lacks evidence and will fail an audit. Evidence must be provided 
                        or attested to satisfy this control.
                      </p>
                    )}
                    {selectedControl.state === "EXPIRED_EVIDENCE" && (
                      <p className="text-sm text-muted-foreground mt-2">
                        Evidence for this control has expired. Evidence must be refreshed to maintain compliance.
                      </p>
                    )}
                  </div>
                </div>

                {/* Evidence Hash */}
                {selectedControl.evidence_hash && (
                  <div>
                    <h3 className="font-semibold mb-2">Evidence Hash</h3>
                    <div className="rounded-lg border border-border/50 bg-muted/20 p-4 transition-all duration-300 hover:border-primary/60 hover:shadow-lg hover:shadow-primary/10">
                      <code className="text-xs break-all">{selectedControl.evidence_hash}</code>
                    </div>
                  </div>
                )}

                {/* Findings */}
                {selectedControl.findings.length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-2">
                      Evidence Gaps ({selectedControl.findings.length})
                    </h3>
                    <div className="space-y-2">
                      {selectedControl.findings.map((finding) => (
                        <div
                          key={finding.id}
                          className="rounded-lg border border-border/50 bg-muted/20 p-4"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <p className="font-semibold text-sm">{finding.file}</p>
                              {finding.line && (
                                <p className="text-xs text-muted-foreground">Line {finding.line}</p>
                              )}
                            </div>
                            <Badge variant="outline">{finding.severity}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground font-mono bg-background/50 p-2 rounded mt-2">
                            {finding.snippet}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Auditor Explanation */}
                {selectedControl.auditor_explanation && (
                  <div>
                    <h3 className="font-semibold mb-2">Auditor Explanation</h3>
                    <div className="rounded-lg border border-border/50 bg-muted/20 p-4 transition-all duration-300 hover:border-primary/60 hover:shadow-lg hover:shadow-primary/10">
                      <p className="text-sm text-muted-foreground">
                        {selectedControl.auditor_explanation}
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="pt-6">
                <div className="text-center text-muted-foreground py-12">
                  <AlertCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Select a control from the list to view details</p>
                </div>
              </CardContent>
            </Card>
          )}
        </motion.div>

        {/* Right: Evidence Panel */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="lg:col-span-3 space-y-4"
        >
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Evidence Actions</CardTitle>
              <CardDescription>
                Upload evidence, view proofs, or sign attestations
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedControl && (
                <>
                  {selectedControl.verification_method === "human_attestation" && (
                    <Button className="w-full" variant="default">
                      <FileText className="mr-2 h-4 w-4" />
                      Sign Human Attestation
                    </Button>
                  )}
                  {selectedControl.verification_method !== "human_attestation" && (
                    <Button className="w-full" variant="outline">
                      <Upload className="mr-2 h-4 w-4" />
                      Upload Evidence
                    </Button>
                  )}
                  {selectedControl.evidence_hash && (
                    <Button className="w-full" variant="outline">
                      <Eye className="mr-2 h-4 w-4" />
                      View Hashed Proof
                    </Button>
                  )}
                  <div className="pt-4 border-t">
                    <p className="text-xs text-muted-foreground">
                      <strong>Control ID:</strong> {selectedControl.control_id}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      <strong>Framework:</strong> {selectedControl.framework}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">
                      <strong>State:</strong> {stateConfig[selectedControl.state].label}
                    </p>
                  </div>
                </>
              )}
              {!selectedControl && (
                <p className="text-sm text-muted-foreground text-center py-4">
                  Select a control to view evidence actions
                </p>
              )}
            </CardContent>
          </Card>
        </motion.div>
        </div>
      </div>
    </div>
  );
}

