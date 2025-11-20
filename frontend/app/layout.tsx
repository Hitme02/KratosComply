import "./globals.css";
import type { Metadata } from "next";
import { clsx } from "clsx";

export const metadata: Metadata = {
  title: "KratosComply Demo",
  description: "Privacy-first compliance automation demo",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={clsx("min-h-screen bg-slate-950 text-slate-100")}>{children}</body>
    </html>
  );
}
