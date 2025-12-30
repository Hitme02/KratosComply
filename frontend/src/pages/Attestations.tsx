/**
 * Attestations Page
 * 
 * Purpose: Legal proof timeline
 * 
 * Show:
 * - All generated attestations
 * - Time scope
 * - Framework coverage
 * - Merkle root
 * - Verification status
 * 
 * Allow:
 * - Download attestation
 * - Verify attestation
 * - Compare attestations (historical)
 * 
 * Do NOT:
 * - Edit attestations
 * - Mutate past evidence
 * 
 * Attestations are immutable.
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  FileText,
  Download,
  Clock,
  Shield,
  ArrowLeft,
  Eye,
  Hash,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/services/api";

interface AttestationRecord {
  id: number;
  merkle_root: string;
  public_key_hex: string;
  created_at: string;
  frameworks_covered: string[];
  control_coverage_percent: number | null;
  evidence_count?: number;
  human_signer_count?: number;
  control_count?: number;
}

export function AttestationsPage() {
  const navigate = useNavigate();
  const [attestations, setAttestations] = useState<AttestationRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAttestations();
  }, []);

  const loadAttestations = async () => {
    try {
      const data = await api.getAttestations();
      // Map the data to match our AttestationRecord interface
      const mapped = (data.attestations || []).map((att: any) => ({
        id: att.id || att.attest_id,
        merkle_root: att.merkle_root,
        public_key_hex: att.public_key_hex,
        created_at: att.created_at || att.timestamp,
        frameworks_covered: att.frameworks_covered || [],
        control_coverage_percent: att.control_coverage_percent ?? null,
        human_attestations: att.human_attestations || [],
      }));
      setAttestations(mapped);
    } catch (error) {
      console.error("Failed to load attestations:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const handleDownload = (attestation: AttestationRecord) => {
    // Create downloadable JSON
    const data = JSON.stringify(attestation, null, 2);
    const blob = new Blob([data], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `attestation-${attestation.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-16 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-5xl mx-auto px-4 flex items-center justify-between"
      >
        <div>
          <h1 className="text-4xl font-semibold">Compliance Attestations</h1>
          <p className="text-muted-foreground mt-2">
            Legal proof timeline. All attestations are immutable and cryptographically sealed.
          </p>
        </div>
        <Button variant="outline" onClick={() => navigate("/audit-cockpit")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Dashboard
        </Button>
      </motion.div>

      {/* Important Notice */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Card className="bg-blue-500/10 border-blue-500/20">
          <CardContent className="pt-6">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
              <div className="space-y-2">
                <h3 className="font-semibold">Attestations Are Immutable</h3>
                <p className="text-sm text-muted-foreground">
                  Compliance attestations are legal-grade statements that cannot be edited or mutated. 
                  Each attestation is cryptographically sealed with a Merkle root and Ed25519 signature. 
                  To update compliance status, generate a new attestation.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Attestations Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Card>
          <CardHeader>
            <CardTitle>Attestation History</CardTitle>
            <CardDescription>
              {attestations.length} attestation{attestations.length !== 1 ? "s" : ""} recorded
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="text-center py-12 text-muted-foreground">
                Loading attestations...
              </div>
            ) : attestations.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No attestations yet. Generate your first compliance attestation from the dashboard.</p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Frameworks</TableHead>
                    <TableHead>Coverage</TableHead>
                    <TableHead>Evidence</TableHead>
                    <TableHead>Merkle Root</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {attestations.map((attestation) => (
                    <TableRow key={attestation.id}>
                      <TableCell className="font-mono text-sm">#{attestation.id}</TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Clock className="h-4 w-4 text-muted-foreground" />
                          <span className="text-sm">{formatDate(attestation.created_at)}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {attestation.frameworks_covered.map((fw) => (
                            <Badge key={fw} variant="outline" className="text-xs">
                              {fw}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        {attestation.control_coverage_percent !== null ? (
                          <div className="flex items-center gap-2">
                            <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary transition-all"
                                style={{ width: `${attestation.control_coverage_percent}%` }}
                              />
                            </div>
                            <span className="text-sm font-semibold">
                              {attestation.control_coverage_percent}%
                            </span>
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">N/A</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="text-sm space-y-1">
                          {attestation.evidence_count !== undefined && (
                            <div className="flex items-center gap-1">
                              <Hash className="h-3 w-3 text-muted-foreground" />
                              <span>{attestation.evidence_count} evidence</span>
                            </div>
                          )}
                          {attestation.human_signer_count !== undefined && attestation.human_signer_count > 0 && (
                            <div className="flex items-center gap-1">
                              <FileText className="h-3 w-3 text-muted-foreground" />
                              <span>{attestation.human_signer_count} signer{attestation.human_signer_count !== 1 ? "s" : ""}</span>
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <code className="text-xs bg-muted px-2 py-1 rounded">
                          {attestation.merkle_root.slice(0, 16)}...
                        </code>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDownload(attestation)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => {
                              // Navigate to verification page or show modal
                              navigate(`/attestations/${attestation.id}`);
                            }}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Verification Info */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="max-w-5xl mx-auto px-4"
      >
        <Card>
          <CardHeader>
            <CardTitle>Attestation Verification</CardTitle>
            <CardDescription>
              How to verify an attestation for auditors, investors, and regulators
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <h3 className="font-semibold">Each attestation includes:</h3>
              <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                <li>
                  <strong>Merkle Root:</strong> Cryptographic proof that the report has not been tampered with
                </li>
                <li>
                  <strong>Ed25519 Signature:</strong> Cryptographic proof of authenticity (signed by agent private key)
                </li>
                <li>
                  <strong>Framework Coverage:</strong> Which compliance frameworks are covered (SOC2, ISO27001, GDPR, DPDP, HIPAA, PCI-DSS, NIST CSF)
                </li>
                <li>
                  <strong>Control States:</strong> Which controls are VERIFIED_MACHINE, VERIFIED_SYSTEM, ATTESTED_HUMAN, or MISSING_EVIDENCE
                </li>
                <li>
                  <strong>Evidence Hashes:</strong> SHA256 hashes of all evidence (cryptographic binding)
                </li>
                <li>
                  <strong>Human Signer Identities:</strong> Hashed identities of human signers (for privacy-preserving auditability)
                </li>
                <li>
                  <strong>Verification Timestamp:</strong> When the attestation was verified and recorded
                </li>
              </ul>
            </div>
            <div className="pt-4 border-t">
              <p className="text-sm text-muted-foreground">
                <strong>Note:</strong> Attestations are immutable. To update compliance status, generate a new attestation. 
                Historical attestations provide an audit trail of compliance over time.
              </p>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
