/**
 * Compliance Coverage Page
 * 
 * Purpose: Answer "What frameworks do you support?"
 * 
 * Structure:
 * - Framework → Control categories → Control examples
 * - Explicit statement: What is machine-verified vs what requires human attestation
 * 
 * Must NOT:
 * - Claim "full automation"
 * - Use vague compliance percentages without context
 */
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Shield, CheckCircle2, AlertCircle, ArrowRight, ArrowLeft } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const frameworks = {
  SOC2: {
    name: "SOC 2",
    description: "Service Organization Control 2 - Trust Services Criteria",
    controls: [
      {
        id: "CC6.1",
        category: "Infrastructure Security",
        description: "Logical and physical access controls must be implemented and monitored",
        verification: "machine",
        example: "Public-read ACLs on storage resources",
      },
      {
        id: "CC6.2",
        category: "Secrets Management",
        description: "Credentials and secrets must be managed securely",
        verification: "machine",
        example: "Hardcoded secrets in source code",
      },
      {
        id: "CC7.2",
        category: "Logging",
        description: "System activities must be logged and monitored",
        verification: "system",
        example: "Logging enabled flags in configuration",
      },
    ],
  },
  ISO27001: {
    name: "ISO 27001",
    description: "Information Security Management System",
    controls: [
      {
        id: "A.9.2.1",
        category: "Access Control",
        description: "User access management procedures must be established",
        verification: "system",
        example: "MFA enforcement configuration",
      },
      {
        id: "A.10.1.1",
        category: "Encryption",
        description: "Cryptographic controls must be implemented",
        verification: "system",
        example: "Encryption-at-rest settings",
      },
    ],
  },
  DPDP: {
    name: "DPDP Act (India)",
    description: "Digital Personal Data Protection Act",
    controls: [
      {
        id: "Section-7",
        category: "Consent",
        description: "Consent must be obtained before processing personal data",
        verification: "machine",
        example: "Consent handling mechanisms in code",
      },
      {
        id: "Section-8",
        category: "Retention",
        description: "Data retention policies must be explicitly configured",
        verification: "system",
        example: "Retention duration settings",
      },
      {
        id: "Section-9",
        category: "Logging",
        description: "Access to personal data must be logged for audit purposes",
        verification: "system",
        example: "Access logging configuration",
      },
    ],
  },
  GDPR: {
    name: "GDPR (EU)",
    description: "General Data Protection Regulation",
    controls: [
      {
        id: "Article-5",
        category: "Retention",
        description: "Personal data must be retained only as long as necessary",
        verification: "system",
        example: "Data retention policies",
      },
      {
        id: "Article-6",
        category: "Consent",
        description: "Lawful basis for processing personal data must be established",
        verification: "machine",
        example: "Consent mechanisms in code",
      },
      {
        id: "Article-17",
        category: "Data Subject Rights",
        description: "Right to erasure (right to be forgotten) must be implemented",
        verification: "machine",
        example: "Data erasure functionality",
      },
      {
        id: "Article-20",
        category: "Data Subject Rights",
        description: "Data portability mechanisms must be implemented",
        verification: "machine",
        example: "Data export functionality",
      },
      {
        id: "Article-32",
        category: "Encryption",
        description: "Security of processing must include encryption",
        verification: "system",
        example: "Encryption configuration",
      },
    ],
  },
};

export function ComplianceCoveragePage() {
  const navigate = useNavigate();

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <h1 className="text-4xl font-semibold">Compliance Coverage</h1>
        <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
          Supported compliance frameworks and control verification methods
        </p>
      </motion.div>

      {/* Verification Methods Explanation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Card>
          <CardHeader>
            <CardTitle>Verification Methods</CardTitle>
            <CardDescription>
              Understanding how controls are verified and what requires human attestation
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-blue-400" />
                  <h3 className="font-semibold">Machine-Verified</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Fully automated verification through AST parsing and regex patterns. 
                  Examples: hardcoded secrets, insecure ACLs, consent handling code.
                </p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5 text-purple-400" />
                  <h3 className="font-semibold">System-Verified</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Configuration detection (flags, settings). Examples: logging enabled, 
                  retention duration, encryption settings, MFA configuration.
                </p>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-amber-400" />
                  <h3 className="font-semibold">Human-Attested</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Requires human declaration with cryptographic signature. Examples: 
                  incident response procedures, access review policies, training records.
                </p>
              </div>
            </div>
            <div className="pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                <strong className="text-foreground">Important:</strong> KratosComply does NOT claim 
                "full automation" for compliance. Many controls require human attestation. The system 
                clearly distinguishes between machine-verified, system-verified, and human-attested evidence.
              </p>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Framework Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Tabs defaultValue="SOC2" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="SOC2">SOC 2</TabsTrigger>
            <TabsTrigger value="ISO27001">ISO 27001</TabsTrigger>
            <TabsTrigger value="DPDP">DPDP Act</TabsTrigger>
            <TabsTrigger value="GDPR">GDPR</TabsTrigger>
          </TabsList>

          {Object.entries(frameworks).map(([key, framework]) => (
            <TabsContent key={key} value={key} className="space-y-4 mt-6">
              <Card>
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <Shield className="h-8 w-8 text-primary" />
                    <div>
                      <CardTitle>{framework.name}</CardTitle>
                      <CardDescription>{framework.description}</CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4">
                    {framework.controls.map((control) => (
                      <div
                        key={control.id}
                        className="rounded-lg border border-border/60 bg-muted/20 p-4 space-y-2 transition-all duration-300 hover:border-primary/60 hover:shadow-lg hover:shadow-primary/10"
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <Badge variant="outline">{control.id}</Badge>
                              <Badge
                                variant={
                                  control.verification === "machine"
                                    ? "default"
                                    : control.verification === "system"
                                    ? "secondary"
                                    : "outline"
                                }
                              >
                                {control.verification === "machine"
                                  ? "Machine-Verified"
                                  : control.verification === "system"
                                  ? "System-Verified"
                                  : "Human-Attested"}
                              </Badge>
                            </div>
                            <h3 className="font-semibold">{control.category}</h3>
                            <p className="text-sm text-muted-foreground">{control.description}</p>
                            <p className="text-xs text-muted-foreground mt-2">
                              <strong>Example:</strong> {control.example}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          ))}
        </Tabs>
      </motion.div>

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button
          variant="outline"
          onClick={() => navigate("/architecture")}
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back
        </Button>
        <Button
          onClick={() => navigate("/mode-selection")}
        >
          Choose Your Mode
          <ArrowRight className="ml-2 h-4 w-4" />
        </Button>
      </motion.div>
    </div>
  );
}

