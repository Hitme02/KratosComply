import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ThemeProvider } from "@/hooks/useTheme";
import { ErrorBoundary } from "@/components/ErrorBoundary";

// Lazy load pages for code splitting
// Strict top-down cognitive flow: Landing → Architecture → Compliance Coverage → Mode Selection → Dashboard → Controls & Evidence → Attestations → Help
const LandingPage = lazy(() => import("@/pages/Landing").then((m) => ({ default: m.LandingPage })));
const ArchitecturePage = lazy(() => import("@/pages/Architecture").then((m) => ({ default: m.ArchitecturePage })));
const ComplianceCoveragePage = lazy(() => import("@/pages/ComplianceCoverage").then((m) => ({ default: m.ComplianceCoveragePage })));
const ModeSelectionPage = lazy(() => import("@/pages/ModeSelection").then((m) => ({ default: m.ModeSelectionPage })));
const AuditCockpitPage = lazy(() => import("@/pages/AuditCockpit").then((m) => ({ default: m.AuditCockpitPage })));
const ControlsEvidencePage = lazy(() => import("@/pages/ControlsEvidence").then((m) => ({ default: m.ControlsEvidencePage })));
const AttestationsPage = lazy(() => import("@/pages/Attestations").then((m) => ({ default: m.AttestationsPage })));
const HelpPage = lazy(() => import("@/pages/Help").then((m) => ({ default: m.HelpPage })));
// Legacy pages (kept for compatibility) - Dashboard redirects to AuditCockpit
const DockerSetupPage = lazy(() => import("@/pages/DockerSetup").then((m) => ({ default: m.DockerSetupPage })));
const GitHubCallbackPage = lazy(() => import("@/pages/GitHubCallback").then((m) => ({ default: m.GitHubCallbackPage })));
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
        <ErrorBoundary>
          <div className="min-h-screen bg-background text-foreground">
            <Navbar />
            <main className="mx-auto max-w-6xl px-4 py-10">
              <Suspense fallback={<LoadingFallback />}>
                <Routes>
                {/* Strict top-down cognitive flow */}
                <Route path="/" element={<LandingPage />} />
                <Route path="/architecture" element={<ArchitecturePage />} />
                <Route path="/compliance-coverage" element={<ComplianceCoveragePage />} />
                <Route path="/mode-selection" element={<ModeSelectionPage />} />
                <Route path="/audit-cockpit" element={<AuditCockpitPage />} />
                <Route path="/controls-evidence" element={<ControlsEvidencePage />} />
                <Route path="/attestations" element={<AttestationsPage />} />
                <Route path="/help" element={<HelpPage />} />
                {/* Legacy routes (redirects) */}
                <Route path="/dashboard" element={<AuditCockpitPage />} />
                <Route path="/docker-setup" element={<DockerSetupPage />} />
                <Route path="/github/callback" element={<GitHubCallbackPage />} />
                <Route path="/about" element={<AboutPage />} />
                </Routes>
              </Suspense>
            </main>
          </div>
        </ErrorBoundary>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;
