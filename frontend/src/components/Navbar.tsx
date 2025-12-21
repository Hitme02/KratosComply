/**
 * Navigation Bar - Strict Top-Down Cognitive Flow
 * 
 * Navigation order:
 * 1. Landing
 * 2. Architecture / How It Works
 * 3. Compliance Coverage
 * 4. Mode Selection
 * 5. Dashboard (Audit Cockpit)
 * 6. Evidence & Controls
 * 7. Attestations
 * 8. Help (Final authority page)
 * 
 * No skipping. No burying Help. Help is the last page.
 */
import { NavLink, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck } from "lucide-react";

import { ThemeToggle } from "@/components/ThemeToggle";
import { cn } from "@/lib/utils";

const links = [
  { to: "/", label: "Landing" },
  { to: "/architecture", label: "Architecture" },
  { to: "/compliance-coverage", label: "Coverage" },
  { to: "/mode-selection", label: "Mode Selection" },
  { to: "/audit-cockpit", label: "Audit Cockpit" },
  { to: "/controls-evidence", label: "Controls & Evidence" },
  { to: "/attestations", label: "Attestations" },
  { to: "/help", label: "Help" },
];

export function Navbar() {
  const location = useLocation();
  const isLanding = location.pathname === "/";

  // Hide navbar on landing page (cleaner experience)
  if (isLanding) {
    return null;
  }

  return (
    <header className="sticky top-0 z-50 border-b border-border/40 bg-background/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <NavLink to="/" className="flex items-center gap-3">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.25 }}
            className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white"
          >
            <ShieldCheck className="h-6 w-6" />
          </motion.div>
          <div>
            <p className="text-sm uppercase tracking-[0.3em] text-muted-foreground">Kratos</p>
            <p className="text-lg font-semibold text-foreground">Comply</p>
          </div>
        </NavLink>
        <nav className="hidden items-center gap-4 text-sm font-medium lg:flex">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                cn(
                  "transition-colors px-2 py-1 rounded-md",
                  isActive
                    ? "text-primary bg-primary/10"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
                )
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="flex items-center gap-4">
          <NavLink
            to="/help"
            className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors lg:hidden"
          >
            Help
          </NavLink>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
