/**
 * GitHub OAuth Callback Page
 * 
 * Handles the OAuth callback from GitHub, exchanges code for token,
 * fetches repositories, and redirects to repository selection.
 */
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Loader2, AlertCircle, CheckCircle2 } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { fetchGitHubRepos, type GitHubReposResponse } from "@/services/api";

export function GitHubCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reposData, setReposData] = useState<GitHubReposResponse | null>(null);

  useEffect(() => {
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const errorParam = searchParams.get("error");

    if (errorParam) {
      setError(`GitHub OAuth error: ${errorParam}`);
      setLoading(false);
      return;
    }

    if (!code || !state) {
      setError("Missing OAuth code or state parameter");
      setLoading(false);
      return;
    }

    // Exchange code for token and fetch repositories
    const handleCallback = async () => {
      try {
        setLoading(true);
        const data = await fetchGitHubRepos(code, state);
        setReposData(data);
        
        // Store in sessionStorage for repository selection page
        sessionStorage.setItem("github_username", data.username);
        sessionStorage.setItem("github_repos", JSON.stringify(data.repositories));
        
        // Store access token if provided (for scanning)
        if (data.access_token) {
          sessionStorage.setItem("github_access_token", data.access_token);
        }
        
        // Redirect to repository selection
        navigate("/github/repositories", { replace: true });
      } catch (err: any) {
        console.error("GitHub callback error:", err);
        setError(err.response?.data?.detail || err.message || "Failed to authenticate with GitHub");
        setLoading(false);
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="text-center space-y-4"
        >
          <Loader2 className="h-12 w-12 mx-auto animate-spin text-primary" />
          <p className="text-muted-foreground">Authenticating with GitHub...</p>
        </motion.div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto py-12">
        <Card className="border-red-500/50 bg-red-500/10">
          <CardHeader>
            <div className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <CardTitle>Authentication Failed</CardTitle>
            </div>
            <CardDescription>{error}</CardDescription>
          </CardHeader>
          <CardContent>
            <Button onClick={() => navigate("/mode-selection")}>
              Back to Mode Selection
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null; // Will redirect before rendering
}
