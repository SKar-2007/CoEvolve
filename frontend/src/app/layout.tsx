"use client";

import { useState, useEffect } from "react";
import { usePathname } from "next/navigation";
import { api } from "@/lib/api";
import "./globals.css";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [backendUrl, setBackendUrl] = useState("");

  useEffect(() => {
    let mounted = true;
    api.checkConnection().then((r) => {
      if (mounted) {
        setBackendOk(r.ok);
        setBackendUrl(r.url);
      }
    });
    return () => { mounted = false; };
  }, []);

  const navLinks = [
    { href: "/", label: "Dashboard", icon: "space_dashboard" },
    { href: "/run-training", label: "Run Training", icon: "play_circle" },
    { href: "/episodes", label: "Episodes", icon: "history" },
    { href: "/rules", label: "Rules", icon: "policy" },
    { href: "/elo-ratings", label: "ELO Ratings", icon: "leaderboard" },
  ];

  const infraItems = [
    { label: "Frontend", value: "Vercel" },
    { label: "Backend", value: "Render" },
    { label: "LLM", value: "Groq" },
    { label: "DB", value: "Supabase" },
  ];

  return (
    <html lang="en" className="dark h-full antialiased">
      <head>
        <title>CoEvolve</title>
        <meta name="description" content="Autonomous security training system" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Space+Grotesk:wght@500;600;700&display=swap"
          rel="stylesheet"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0"
          rel="stylesheet"
        />
      </head>
      <body className="bg-surface text-on-surface font-body min-h-screen">
        {/* ─── Backend Offline Banner ─── */}
        {backendOk === false && (
          <div className="fixed inset-x-0 top-0 z-[100] flex items-center justify-center gap-space-sm bg-error/15 px-space-md py-space-sm text-sm text-error backdrop-blur-sm">
            <span className="material-symbols-outlined text-base">cloud_off</span>
            <span>Backend offline — {backendUrl}</span>
          </div>
        )}

        {/* ─── Sidebar ─── */}
        <aside className="fixed left-0 top-0 z-40 flex h-full w-[220px] flex-col border-r border-outline-variant/30 bg-surface-container-low">
          {/* Logo */}
          <div className="flex items-center gap-space-sm px-space-md pt-space-xl">
            <span className="font-headline text-xl font-bold tracking-tight">
              <span className="text-primary-container">co</span>
              <span className="text-tertiary">evolve</span>
            </span>
            <span className="rounded bg-primary-container/20 px-1.5 py-0.5 font-label text-[10px] font-medium text-primary-container">
              v2
            </span>
          </div>

          {/* Operations Section */}
          <nav className="mt-space-xl flex flex-1 flex-col gap-1 px-space-sm">
            <span className="mb-space-xs px-space-sm font-label text-[11px] font-medium uppercase tracking-widest text-outline">
              Operations
            </span>
            {navLinks.map((link) => {
              const active = pathname === link.href;
              return (
                <a
                  key={link.href}
                  href={link.href}
                  className={`flex items-center gap-space-sm rounded-lg px-space-sm py-2 text-sm font-medium transition-colors ${
                    active
                      ? "bg-primary-container text-on-primary-container"
                      : "text-on-surface/70 hover:bg-surface-container-high hover:text-on-surface"
                  }`}
                >
                  <span className="material-symbols-outlined text-[20px]">{link.icon}</span>
                  {link.label}
                </a>
              );
            })}
          </nav>

          {/* Infrastructure Info */}
          <div className="mx-space-sm mb-space-lg rounded-lg border border-outline-variant/20 bg-surface-container-lowest p-space-sm">
            <div className="mb-space-xs flex items-center justify-between">
              <span className="font-label text-[11px] font-medium uppercase tracking-widest text-outline">
                Infrastructure
              </span>
              <span className="flex items-center gap-1 font-label text-[10px] text-primary">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-primary animate-pulse-dot" />
                LIVE
              </span>
            </div>
            <div className="flex flex-col gap-1">
              {infraItems.map((item) => (
                <div key={item.label} className="flex items-center justify-between text-xs">
                  <span className="text-outline">{item.label}</span>
                  <span className="font-label font-medium text-on-surface/80">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* ─── Header ─── */}
        <header className="fixed left-[220px] right-0 top-0 z-30 flex h-16 items-center justify-between border-b border-outline-variant/30 bg-surface/85 px-space-lg backdrop-blur-xl">
          {/* Status Badges */}
          <div className="flex items-center gap-space-md">
            <StatusBadge label="SYSTEM" value="ACTIVE" ok />
            <StatusBadge label="ENGINE" value="GROQ-LLAMA3-70B" ok />
            <StatusBadge label="RUNTIME" value="SYNCHRONIZED" ok={backendOk !== false} />
          </div>

          {/* Deploy Button */}
          <button className="flex items-center gap-space-sm rounded-lg bg-primary-container px-space-md py-2 text-sm font-medium text-on-primary-container transition-colors hover:brightness-110">
            <span className="material-symbols-outlined text-[18px]">rocket_launch</span>
            Deploy Exploit Run
          </button>
        </header>

        {/* ─── Main Content ─── */}
        <main className="pl-[220px] pt-16 min-h-screen">
          {children}
        </main>
      </body>
    </html>
  );
}

function StatusBadge({
  label,
  value,
  ok,
}: {
  label: string;
  value: string;
  ok: boolean;
}) {
  return (
    <div className="flex items-center gap-space-xs rounded-md border border-outline-variant/20 bg-surface-container-low px-space-sm py-1">
      <span className="inline-block h-1.5 w-1.5 rounded-full bg-primary animate-pulse-dot" />
      <span className="font-label text-[11px] font-medium uppercase tracking-wider text-outline">
        {label}:
      </span>
      <span className="font-label text-[11px] font-medium text-on-surface">{value}</span>
    </div>
  );
}
