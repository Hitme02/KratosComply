import { BrowserRouter, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ThemeProvider } from "@/hooks/useTheme";
import { Dashboard } from "@/pages/Dashboard";
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
              <Route path="/" element={<Dashboard />} />
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
