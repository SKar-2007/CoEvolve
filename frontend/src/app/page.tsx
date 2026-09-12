"use client";

import { useEffect, useState } from "react";
import { api, Metrics } from "@/lib/api";

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.metrics().then(setMetrics).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="text-red-400 p-8">Failed to load: {error}</div>;
  if (!metrics) return <div className="text-[--muted] p-8">Loading...</div>;

  const securePct = (metrics.secure_rate * 100).toFixed(1);
  const atk = metrics.epo.attacker || 1500;
  const dev = metrics.epo.developer || 1500;

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-bold mb-6">
        <span className="text-brand-red">co</span>
        <span className="text-brand-yellow">evolve</span>
        <span className="text-[--muted] text-base ml-3">Dashboard</span>
      </h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <Card label="Episodes" value={String(metrics.total_episodes)} color="text-white" />
        <Card label="Secure Rate" value={`${securePct}%`} color="text-brand-green" />
        <Card label="Rules" value={String(metrics.rules_count)} color="text-brand-blue" />
        <Card label="ATK Rating" value={atk.toFixed(0)} color="text-brand-red" />
      </div>

      <div className="bg-[--surface] rounded-lg border border-[--border] p-6">
        <h2 className="text-sm font-semibold text-[--muted] mb-4">ELO RATINGS</h2>
        <div className="space-y-3">
          <EloBar label="ATK" value={atk} max={2500} color="bg-brand-red" />
          <EloBar label="DEV" value={dev} max={2500} color="bg-brand-yellow" />
        </div>
        <p className="text-xs text-[--muted] mt-3">
          {metrics.total_episodes} episodes played
        </p>
      </div>
    </div>
  );
}

function Card({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="bg-[--surface] rounded-lg border border-[--border] p-4">
      <div className="text-xs text-[--muted] mb-1">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function EloBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-3">
      <span className={`text-sm font-bold w-8 ${label === "ATK" ? "text-brand-red" : "text-brand-yellow"}`}>
        {label}
      </span>
      <div className="flex-1 h-4 bg-[--bg] rounded overflow-hidden">
        <div className={`h-full ${color} rounded`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-sm font-mono w-12 text-right">{value.toFixed(0)}</span>
    </div>
  );
}
