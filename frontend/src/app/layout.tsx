"use client";

import type { Metadata } from "next";
import "./globals.css";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}

function AppShell({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState<boolean | null>(null);
  const [apiUrl, setApiUrl] = useState("");

  useEffect(() => {
    api.checkConnection().then((r) => {
      setConnected(r.ok);
      setApiUrl(r.url);
    });
  }, []);

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Sidebar */}
      <nav className="w-full md:w-56 md:min-h-screen border-b md:border-b-0 md:border-r border-zinc-800 bg-zinc-950 p-3 md:p-4 flex md:flex-col gap-1 md:sticky md:top-0">
        <div className="text-lg font-bold mb-0 md:mb-6 mr-4 md:mr-0">
          <span className="text-red-500">co</span>
          <span className="text-amber-400">evolve</span>
        </div>
        <div className="flex md:flex-col gap-1 flex-1">
          {[
            { href: "/", label: "Dashboard", icon: "⬡" },
            { href: "/train", label: "Run Training", icon: "▶" },
            { href: "/episodes", label: "Episodes", icon: "☰" },
            { href: "/rules", label: "Rules", icon: "shield" },
            { href: "/elo", label: "Elo Ratings", icon: "⚡" },
          ].map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="px-3 py-2 rounded-md text-sm hover:bg-zinc-800 transition-colors text-zinc-300 hover:text-white"
            >
              {link.label}
            </a>
          ))}
        </div>
      </nav>

      {/* Main */}
      <div className="flex-1 flex flex-col min-h-screen">
        {/* Connection banner */}
        {connected === false && (
          <div className="bg-red-950 border-b border-red-900 px-4 py-2 text-sm text-red-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse-dot" />
            Backend offline — {apiUrl}
          </div>
        )}
        {connected === true && (
          <div className="bg-emerald-950 border-b border-emerald-900 px-4 py-2 text-sm text-emerald-300 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            Connected to {apiUrl}
          </div>
        )}
        <main className="flex-1 p-4 md:p-8 max-w-6xl">{children}</main>
      </div>
    </div>
  );
}
