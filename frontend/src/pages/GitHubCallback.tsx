import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Loader2, CheckCircle2, AlertCircle, Github, Lock, Globe } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { fetchGitHubRepos, type GitHubRepository } from "@/services/api";

export function GitHubCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<"loading" | "select" | "error">("loading");
  const [errorMessage, setErrorMessage] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [repositories, setRepositories] = useState<GitHubRepository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepository | null>(null);

  // Safety: Always show loading initially
  if (status === "loading" && !searchParams.get("code") && !searchParams.get("error")) {
    // If no params at all, might be a navigation issue
    console.warn("GitHubCallback: No code or error in URL params");
  }

  useEffect(() => {
    const code = searchParams.get("code");
    const error = searchParams.get("error");
    const errorDescription = searchParams.get("error_description");
    const state = searchParams.get("state");

    // Check if GitHub returned an error
    if (error) {
      setStatus("error");
      const message = errorDescription 
        ? `${error}: ${decodeURIComponent(errorDescription)}`
        : error === "access_denied"
        ? "Authorization was denied. Please try again and authorize the application."
        : `GitHub authorization error: ${error}`;
      setErrorMessage(message);
      return;
    }

    if (!code) {
      setStatus("error");
      setErrorMessage("No authorization code received from GitHub. Please try again.");
      return;
    }

    // Exchange code for token and fetch repositories
    fetchGitHubRepos(code, state || "")
      .then((response) => {
        console.log("GitHub repos response:", response);
        if (!response || !response.repositories) {
          throw new Error("Invalid response from server");
        }
        setUsername(response.username || "Unknown");
        setRepositories(response.repositories || []);
        setStatus("select");
      })
      .catch((err) => {
        console.error("GitHub callback error:", err);
        setStatus("error");
        // Extract error message from response
        let errorMsg = "Failed to fetch repositories from GitHub";
        
        if (err.code === "ERR_NETWORK" || err.message?.includes("Network Error")) {
          errorMsg = "Cannot connect to backend server. Please ensure the backend is running on http://localhost:8000";
        } else if (err.response?.data?.detail) {
          errorMsg = err.response.data.detail;
        } else if (err.response?.status === 500) {
          errorMsg = "Backend server error. Check backend logs for details.";
        } else if (err.response?.status) {
          errorMsg = `Server error (${err.response.status}): ${err.response.statusText || "Unknown error"}`;
        } else if (err.message) {
          errorMsg = err.message;
        }
        
        setErrorMessage(errorMsg);
      });
  }, [searchParams]);

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="flex flex-col items-center gap-4 p-8">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">Connecting to GitHub...</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (status === "select") {
    return (
      <div className="flex min-h-screen items-center justify-center px-4 py-12">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="w-full max-w-2xl"
        >
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <Github className="h-6 w-6 text-primary" />
                <div>
                  <CardTitle>Select Repository to Scan</CardTitle>
                  <CardDescription>
                    Choose a repository from {username}'s GitHub account
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert
                type="info"
                title="Demo Mode"
                description="Repository scanning is currently in demo mode. Selecting a repository will show a placeholder report. Actual scanning will be implemented in a future update."
              />

              <div className="space-y-2 max-h-96 overflow-y-auto">
                {repositories.map((repo) => (
                  <motion.div
                    key={repo.id}
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.99 }}
                  >
                    <Card
                      className={`cursor-pointer transition-all ${
                        selectedRepo?.id === repo.id
                          ? "border-primary ring-2 ring-primary/20"
                          : "hover:border-primary/50"
                      }`}
                      onClick={() => setSelectedRepo(repo)}
                    >
                      <CardContent className="p-4">
                        <div className="flex items-start gap-3">
                          {repo.private ? (
                            <Lock className="h-5 w-5 text-muted-foreground mt-0.5" />
                          ) : (
                            <Globe className="h-5 w-5 text-muted-foreground mt-0.5" />
                          )}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="font-semibold text-sm">{repo.full_name}</p>
                              {selectedRepo?.id === repo.id && (
                                <CheckCircle2 className="h-4 w-4 text-primary" />
                              )}
                            </div>
                            {repo.description && (
                              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                {repo.description}
                              </p>
                            )}
                            <p className="text-xs text-muted-foreground mt-1">
                              Updated {new Date(repo.updated_at).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </div>

              <div className="flex gap-3 pt-4">
                <Button
                  variant="outline"
                  onClick={() => navigate("/")}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button
                  onClick={() => {
                    if (selectedRepo) {
                      // For now, just show a message that scanning is not implemented
                      alert(
                        `Repository scanning for "${selectedRepo.full_name}" is not yet implemented.\n\n` +
                        `This is a demo. In production, this would:\n` +
                        `1. Clone the repository\n` +
                        `2. Run the Kratos agent scan\n` +
                        `3. Generate a compliance report\n` +
                        `4. Return the report with findings`
                      );
                      navigate("/dashboard");
                    }
                  }}
                  disabled={!selectedRepo}
                  className="flex-1"
                >
                  {selectedRepo ? `Scan ${selectedRepo.name}` : "Select a repository"}
                </Button>
              </div>
            </CardContent>
          </Card>
        </motion.div>
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

  // Fallback: Should never reach here, but just in case
  return (
    <div className="flex min-h-screen items-center justify-center">
      <Card className="w-full max-w-md">
        <CardContent className="flex flex-col items-center gap-4 p-8">
          <AlertCircle className="h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Unexpected state. Please try again.</p>
          <Button onClick={() => navigate("/")}>Return to Landing</Button>
        </CardContent>
      </Card>
    </div>
  );
}
