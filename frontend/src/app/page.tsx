"use client";

import { useEffect, useState } from "react";
import { api, Metrics } from "@/lib/api";

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.metrics().then(setMetrics).catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
        <div className="text-6xl">⚠</div>
        <h1 className="text-xl font-semibold text-zinc-200">Cannot reach backend</h1>
        <p className="text-zinc-500 text-sm max-w-md text-center">{error}</p>
        <p className="text-zinc-600 text-xs">Make sure the Render backend is deployed and the API URL is set.</p>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-[60vh]">
        <div className="flex items-center gap-3 text-zinc-500">
          <div className="w-5 h-5 border-2 border-zinc-600 border-t-zinc-300 rounded-full animate-spin" />
          Loading...
        </div>
      </div>
    );
  }

  const securePct = (metrics.secure_rate * 100).toFixed(1);
  const atk = metrics.epo.attacker || 1500;
  const dev = metrics.epo.developer || 1500;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-8">
        <span className="text-red-500">co</span>
        <span className="text-amber-400">evolve</span>
        <span className="text-zinc-600 text-base ml-3 font-normal">Dashboard</span>
      </h1>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Episodes" value={String(metrics.total_episodes)} />
        <StatCard label="Secure Rate" value={`${securePct}%`} accent={metrics.secure_rate > 0.5 ? "green" : "red"} />
        <StatCard label="Rules Distilled" value={String(metrics.rules_count)} accent="blue" />
        <StatCard label="Episodes Played" value={String(metrics.total_episodes)} />
      </div>

      {/* Elo chart */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
        <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-4">Elo Ratings</h2>
        <div className="space-y-4">
          <EloRow label="Attacker" value={atk} color="bg-red-500" textColor="text-red-400" />
          <EloRow label="Developer" value={dev} color="bg-amber-400" textColor="text-amber-400" />
        </div>
        <div className="mt-4 flex items-center gap-4 text-xs text-zinc-600">
          <span>Range: 1000–2500</span>
          <span>•</span>
          <span>K-factor: 32</span>
          <span>•</span>
          <span>{metrics.total_episodes} games played</span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, accent }: { label: string; value: string; accent?: string }) {
  const colorMap: Record<string, string> = {
    green: "text-emerald-400",
    red: "text-red-400",
    blue: "text-blue-400",
  };
  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5">
      <div className="text-xs text-zinc-500 mb-1">{label}</div>
      <div className={`text-3xl font-bold ${accent ? colorMap[accent] || "text-white" : "text-white"}`}>{value}</div>
    </div>
  );
}

function EloRow({ label, value, color, textColor }: { label: string; value: number; color: string; textColor: string }) {
  const pct = Math.max(0, Math.min(100, ((value - 1000) / 1500) * 100));
  return (
    <div className="flex items-center gap-4">
      <span className={`text-sm font-semibold w-20 ${textColor}`}>{label}</span>
      <div className="flex-1 h-6 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-700`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-sm font-mono text-zinc-300 w-12 text-right">{value.toFixed(0)}</span>
    </div>
  );
}
