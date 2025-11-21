import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ThemeProvider } from "@/hooks/useTheme";

// Lazy load pages for code splitting
const LandingPage = lazy(() => import("@/pages/Landing").then((m) => ({ default: m.LandingPage })));
const Dashboard = lazy(() => import("@/pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const DockerSetupPage = lazy(() => import("@/pages/DockerSetup").then((m) => ({ default: m.DockerSetupPage })));
const GitHubCallbackPage = lazy(() => import("@/pages/GitHubCallback").then((m) => ({ default: m.GitHubCallbackPage })));
const AttestationsPage = lazy(() => import("@/pages/Attestations").then((m) => ({ default: m.AttestationsPage })));
const AboutPage = lazy(() => import("@/pages/About").then((m) => ({ default: m.AboutPage })));

function LoadingFallback() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="flex flex-col items-center gap-4">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <div className="min-h-screen bg-background text-foreground">
          <Navbar />
          <main className="mx-auto max-w-6xl px-4 py-10">
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route path="/" element={<LandingPage />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/docker-setup" element={<DockerSetupPage />} />
                <Route path="/github/callback" element={<GitHubCallbackPage />} />
                <Route path="/attestations" element={<AttestationsPage />} />
                <Route path="/about" element={<AboutPage />} />
              </Routes>
            </Suspense>
          </main>
        </div>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;
