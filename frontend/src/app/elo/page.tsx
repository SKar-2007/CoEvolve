"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function EloPage() {
  const [elo, setElo] = useState<{ attacker: number; developer: number } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.elo().then(setElo).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-[--muted] p-8">Loading...</div>;
  if (!elo) return <div className="text-[--muted] p-8">Failed to load</div>;

  const atk = elo.attacker;
  const dev = elo.developer;
  const total = atk + dev;
  const atkPct = total > 0 ? (atk / total) * 100 : 50;

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Elo Ratings</h1>

      <div className="bg-[--surface] rounded-lg border border-[--border] p-6 mb-6">
        <div className="flex justify-between text-sm mb-2">
          <span className="text-brand-red font-bold">Attacker</span>
          <span className="text-brand-yellow font-bold">Developer</span>
        </div>

        <div className="h-8 bg-[--bg] rounded-full overflow-hidden flex mb-4">
          <div
            className="h-full bg-brand-red transition-all duration-500"
            style={{ width: `${atkPct}%` }}
          />
          <div
            className="h-full bg-brand-yellow transition-all duration-500"
            style={{ width: `${100 - atkPct}%` }}
          />
        </div>

        <div className="grid grid-cols-2 gap-4 text-center">
          <div>
            <div className="text-3xl font-bold text-brand-red">{atk.toFixed(0)}</div>
            <div className="text-xs text-[--muted]">Attacker Rating</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-brand-yellow">{dev.toFixed(0)}</div>
            <div className="text-xs text-[--muted]">Developer Rating</div>
          </div>
        </div>
      </div>

      <div className="bg-[--surface] rounded-lg border border-[--border] p-4">
        <h2 className="text-sm font-semibold text-[--muted] mb-2">How it works</h2>
        <p className="text-xs text-[--muted] leading-relaxed">
          Attacker and Developer play a zero-sum game. If the Developer introduces a
          vulnerability (J=1), the Attacker gains rating and the Developer loses. If
          the patch is secure (J=0), the Developer gains. Ratings are clamped between
          1000-2500 with K=32.
        </p>
      </div>
    </div>
  );
}
