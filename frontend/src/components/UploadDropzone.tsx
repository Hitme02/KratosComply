import { useCallback, useRef, useState } from "react";
import { motion } from "framer-motion";
import { FileDown, UploadCloud } from "lucide-react";

import { useReportStore } from "@/hooks/useReportStore";
import type { Report } from "@/types/report";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function UploadDropzone() {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const { setReport, setUploadError, uploadError, reset } = useReportStore();
  const [hovered, setHovered] = useState(false);

  const parseFile = useCallback(async (file: File) => {
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as Report;
      setReport(parsed);
      setUploadError(undefined);
    } catch (error) {
      console.error(error);
      setReport(undefined);
      setUploadError("Unable to parse JSON. Please upload a valid aegis-report.json file.");
    }
  }, [setReport, setUploadError]);

  const handleFiles = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    reset();
    parseFile(files[0]);
  };

  return (
    <Card
      className="relative overflow-hidden"
      onDragOver={(e) => {
        e.preventDefault();
        setHovered(true);
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        setHovered(false);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setHovered(false);
        handleFiles(e.dataTransfer.files);
      }}
    >
      <CardHeader>
        <CardTitle>Upload Aegis Report</CardTitle>
        <CardDescription>
          Drag & drop your JSON report here or select it manually. We never upload files automatically.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <motion.div
          animate={{
            borderColor: hovered ? "rgba(129, 140, 248, 1)" : "rgba(255,255,255,0.08)",
            scale: hovered ? 1.01 : 1,
          }}
          className="flex flex-col items-center gap-4 rounded-2xl border-2 border-dashed border-border/80 bg-muted/20 px-6 py-10 text-center"
        >
          <UploadCloud className="h-10 w-10 text-primary" />
          <div>
            <p className="text-lg font-semibold">Drop your `aegis-report.json`</p>
            <p className="text-sm text-muted-foreground">
              We’ll parse it locally, preview the findings, and guide you through verification.
            </p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Button onClick={() => fileInputRef.current?.click()} className="flex items-center gap-2">
              <FileDown className="h-4 w-4" /> Choose JSON
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setReport(undefined);
                setUploadError(undefined);
              }}
            >
              Clear
            </Button>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json"
            className="hidden"
            onChange={(event) => handleFiles(event.target.files)}
          />
          {uploadError && <p className="text-sm text-red-400">{uploadError}</p>}
        </motion.div>
      </CardContent>
    </Card>
  );
}
