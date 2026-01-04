/**
 * GitHub Repository Selection Page
 * 
 * Displays user's repositories and allows selection for scanning.
 */
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Github, Search, Loader2, ArrowRight, ArrowLeft, CheckCircle2, Lock, Globe } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import type { GitHubRepository } from "@/services/api";
import { useReportStore } from "@/hooks/useReportStore";
import { api } from "@/services/api";

export function GitHubRepositoriesPage() {
  const navigate = useNavigate();
  const { setReport } = useReportStore();
  const [repos, setRepos] = useState<GitHubRepository[]>([]);
  const [filteredRepos, setFilteredRepos] = useState<GitHubRepository[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<GitHubRepository | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [username, setUsername] = useState<string>("");

  useEffect(() => {
    // Load repositories from sessionStorage
    const storedRepos = sessionStorage.getItem("github_repos");
    const storedUsername = sessionStorage.getItem("github_username");

    if (!storedRepos || !storedUsername) {
      navigate("/mode-selection");
      return;
    }

    try {
      const reposData = JSON.parse(storedRepos) as GitHubRepository[];
      setRepos(reposData);
      setFilteredRepos(reposData);
      setUsername(storedUsername);
    } catch (err) {
      console.error("Failed to parse repositories:", err);
      navigate("/mode-selection");
    }
  }, [navigate]);

  useEffect(() => {
    // Filter repositories based on search query
    if (!searchQuery.trim()) {
      setFilteredRepos(repos);
      return;
    }

    const query = searchQuery.toLowerCase();
    const filtered = repos.filter(
      (repo) =>
        repo.name.toLowerCase().includes(query) ||
        repo.full_name.toLowerCase().includes(query) ||
        repo.description?.toLowerCase().includes(query)
    );
    setFilteredRepos(filtered);
  }, [searchQuery, repos]);

  const handleScanRepository = async (repo: GitHubRepository) => {
    if (scanning) return;

    setSelectedRepo(repo);
    setScanning(true);
    setError(null);

    try {
      // Get access token from sessionStorage
      const accessToken = sessionStorage.getItem("github_access_token");
      if (!accessToken) {
        throw new Error("GitHub access token not found. Please re-authenticate.");
      }
      
      // Trigger scan via backend
      const response = await api.scanRepository(
        `https://github.com/${repo.full_name}`,
        accessToken,
        repo.name
      );

      if (response.report) {
        setReport(response.report);
        navigate("/audit-cockpit");
      } else {
        throw new Error("No report returned from scan");
      }
    } catch (err: any) {
      console.error("Scan error:", err);
      setError(
        err.response?.data?.detail ||
          err.message ||
          "Failed to scan repository. Please try again."
      );
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-8 py-12">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center space-y-4"
      >
        <div className="flex items-center justify-center gap-3">
          <Github className="h-8 w-8 text-primary" />
          <h1 className="text-4xl font-semibold">Select Repository</h1>
        </div>
        <p className="text-xl text-muted-foreground">
          Choose a repository to scan for compliance evidence
        </p>
        {username && (
          <p className="text-sm text-muted-foreground">
            Authenticated as <strong>{username}</strong>
          </p>
        )}
      </motion.div>

      {/* Search */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="max-w-2xl mx-auto"
      >
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Search repositories..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </motion.div>

      {/* Error Message */}
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl mx-auto"
        >
          <Card className="border-red-500/50 bg-red-500/10">
            <CardContent className="pt-6">
              <p className="text-sm text-red-400">{error}</p>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Repository List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="max-w-4xl mx-auto space-y-4"
      >
        {filteredRepos.length === 0 ? (
          <Card>
            <CardContent className="pt-6 text-center text-muted-foreground">
              {searchQuery ? "No repositories match your search" : "No repositories found"}
            </CardContent>
          </Card>
        ) : (
          filteredRepos.map((repo) => (
            <Card
              key={repo.id}
              className={`cursor-pointer transition-all ${
                selectedRepo?.id === repo.id
                  ? "border-primary ring-2 ring-primary/20"
                  : "border-border/50 hover:border-primary/50"
              } ${scanning && selectedRepo?.id !== repo.id ? "opacity-50" : ""}`}
              onClick={() => !scanning && handleScanRepository(repo)}
            >
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      {repo.private ? (
                        <Lock className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Globe className="h-4 w-4 text-muted-foreground" />
                      )}
                      <CardTitle className="text-lg">{repo.name}</CardTitle>
                      {repo.private && (
                        <Badge variant="outline" className="text-xs">
                          Private
                        </Badge>
                      )}
                    </div>
                    <CardDescription className="line-clamp-2">
                      {repo.description || "No description"}
                    </CardDescription>
                  </div>
                  {scanning && selectedRepo?.id === repo.id && (
                    <Loader2 className="h-5 w-5 animate-spin text-primary" />
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className="text-sm text-muted-foreground">
                    <p>{repo.full_name}</p>
                    <p className="text-xs mt-1">
                      Updated {new Date(repo.updated_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Button
                    disabled={scanning}
                    onClick={(e) => {
                      e.stopPropagation();
                      handleScanRepository(repo);
                    }}
                  >
                    {scanning && selectedRepo?.id === repo.id ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        Scan Repository
                        <ArrowRight className="ml-2 h-4 w-4" />
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </motion.div>

      {/* Navigation */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="flex justify-center gap-4 pt-8"
      >
        <Button variant="outline" onClick={() => navigate("/mode-selection")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Mode Selection
        </Button>
      </motion.div>
    </div>
  );
}

