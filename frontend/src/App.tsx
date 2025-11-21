import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ThemeProvider } from "@/hooks/useTheme";
import { LandingPage } from "@/pages/Landing";
import { Dashboard } from "@/pages/Dashboard";
import { DockerSetupPage } from "@/pages/DockerSetup";
import { GitHubCallbackPage } from "@/pages/GitHubCallback";
import { AttestationsPage } from "@/pages/Attestations";
import { AboutPage } from "@/pages/About";

function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <div className="min-h-screen bg-background text-foreground">
          <Navbar />
          <main className="mx-auto max-w-6xl px-4 py-10">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/docker-setup" element={<DockerSetupPage />} />
              <Route path="/github/callback" element={<GitHubCallbackPage />} />
              <Route path="/attestations" element={<AttestationsPage />} />
              <Route path="/about" element={<AboutPage />} />
            </Routes>
          </main>
        </div>
      </ThemeProvider>
    </BrowserRouter>
  );
}

export default App;
