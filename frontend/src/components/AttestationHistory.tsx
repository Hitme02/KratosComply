import { useEffect } from "react";
import { Search } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { useReportStore } from "@/hooks/useReportStore";
import { fetchAttestations } from "@/services/api";

export function AttestationHistory({ condensed = false }: { condensed?: boolean }) {
  const { attestations, setAttestations } = useReportStore();

  useEffect(() => {
    fetchAttestations().then((records) => {
      if (records.length) setAttestations(records);
    });
  }, [setAttestations]);

  const visibleRecords = condensed ? attestations.slice(0, 5) : attestations;

  return (
    <Card>
      <CardHeader className="flex items-center justify-between gap-4">
        <div>
          <CardTitle>Attestation history</CardTitle>
          <p className="text-sm text-muted-foreground">Chronological ledger of recorded proofs.</p>
        </div>
        {!condensed && (
          <div className="relative w-full max-w-sm">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="Search merkle root" className="pl-9" />
          </div>
        )}
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>Merkle root</TableHead>
              <TableHead>Public key</TableHead>
              <TableHead>Timestamp</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleRecords.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">
                  No attestations yet. Create one after verifying a report.
                </TableCell>
              </TableRow>
            )}
            {visibleRecords.map((record) => (
              <TableRow key={record.attest_id}>
                <TableCell className="font-semibold">#{record.attest_id}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{record.merkle_root}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{record.public_key_hex}</TableCell>
                <TableCell>{new Date(record.timestamp).toLocaleString()}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!condensed && attestations.length > 5 && (
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="outline">Previous</Button>
            <Button variant="outline">Next</Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
