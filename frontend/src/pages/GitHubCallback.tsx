import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Loader2, CheckCircle2, AlertCircle, Github } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useReportStore } from "@/hooks/useReportStore";
import { fetchGitHubReport } from "@/services/api";

export function GitHubCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { setReport } = useReportStore();
  const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [repoInfo, setRepoInfo] = useState<{ owner: string; repo: string } | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");
    const state = searchParams.get("state");

    if (!code) {
      setStatus("error");
      setErrorMessage("No authorization code received from GitHub");
      return;
    }

    // Exchange code for token and fetch report
    fetchGitHubReport(code, state || "")
      .then((report) => {
        setReport(report);
        setStatus("success");
        // Extract repo info from report if available
        if (report.project?.path) {
          const parts = report.project.path.split("/");
          if (parts.length >= 2) {
            setRepoInfo({ owner: parts[parts.length - 2], repo: parts[parts.length - 1] });
          }
        }
      })
      .catch((err) => {
        console.error(err);
        setStatus("error");
        setErrorMessage(err.message || "Failed to fetch report from GitHub");
      });
  }, [searchParams, setReport]);

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center gap-4 p-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Connecting to GitHub and scanning repository...</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (status === "error") {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-400">
              <AlertCircle className="h-5 w-5" /> Authorization Failed
            </CardTitle>
            <CardDescription>{errorMessage}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button onClick={() => navigate("/")} className="w-full">
              Return to Landing
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-md"
      >
        <Card className="bg-gradient-to-br from-emerald-500/10 to-indigo-500/10 border-emerald-500/20">
          <CardHeader>
            <div className="flex items-center gap-3">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 200 }}
              >
                <CheckCircle2 className="h-8 w-8 text-emerald-400" />
              </motion.div>
              <div>
                <CardTitle>Scan Complete!</CardTitle>
                <CardDescription>
                  Your GitHub repository has been scanned and the report is ready
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {repoInfo && (
              <div className="flex items-center gap-2 rounded-lg bg-muted/40 p-3">
                <Github className="h-5 w-5" />
                <div>
                  <p className="text-sm font-semibold">{repoInfo.owner}/{repoInfo.repo}</p>
                  <p className="text-xs text-muted-foreground">Repository scanned</p>
                </div>
              </div>
            )}
            <Alert
              type="success"
              title="Report available"
              description="Navigate to the dashboard to view findings, verify signatures, and create attestations."
            />
            <Button onClick={() => navigate("/dashboard")} className="w-full gap-2">
              View Dashboard <CheckCircle2 className="h-4 w-4" />
            </Button>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
