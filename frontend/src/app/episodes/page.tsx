"use client";

import { useEffect, useState } from "react";
import { api, Episode } from "@/lib/api";

export default function EpisodesPage() {
  const [episodes, setEpisodes] = useState<Episode[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.episodes(50).then(setEpisodes).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-[--muted] p-8">Loading...</div>;

  return (
    <div className="max-w-5xl">
      <h1 className="text-2xl font-bold mb-6">Episodes</h1>

      {episodes.length === 0 ? (
        <div className="text-[--muted]">No episodes yet. Run a training episode first.</div>
      ) : (
        <div className="bg-[--surface] rounded-lg border border-[--border] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[--border] text-[--muted] text-left">
                <th className="px-4 py-3 font-medium">ID</th>
                <th className="px-4 py-3 font-medium">Vuln</th>
                <th className="px-4 py-3 font-medium">Tier</th>
                <th className="px-4 py-3 font-medium">Outcome</th>
                <th className="px-4 py-3 font-medium">ATK</th>
                <th className="px-4 py-3 font-medium">DEV</th>
                <th className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {episodes.map((ep) => (
                <tr key={ep.episode_id} className="border-b border-[--border] last:border-0 hover:bg-[--bg]">
                  <td className="px-4 py-3 font-mono text-xs">{ep.episode_id.slice(0, 12)}</td>
                  <td className="px-4 py-3">
                    <span className="text-brand-red font-medium">{ep.vulnerability_class}</span>
                  </td>
                  <td className="px-4 py-3 text-[--muted]">T{ep.difficulty_tier}</td>
                  <td className="px-4 py-3">
                    <span className={`font-semibold ${ep.outcome === 1 ? "text-brand-red" : "text-brand-green"}`}>
                      {ep.outcome === 1 ? "VULN" : "SAFE"}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono">{ep.attacker_rating.toFixed(0)}</td>
                  <td className="px-4 py-3 font-mono">{ep.developer_rating.toFixed(0)}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${ep.status === "completed" ? "bg-brand-green/20 text-brand-green" : "bg-brand-red/20 text-brand-red"}`}>
                      {ep.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
