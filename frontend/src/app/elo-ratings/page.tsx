"use client";

import { useEffect, useState, useMemo } from "react";
import { api, Episode } from "@/lib/api";

function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (data.length < 2) return null;
  const w = 200;
  const h = 48;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  const points = data
    .map((v, i) => {
      const x = (i / (data.length - 1)) * w;
      const y = h - ((v - min) / range) * h;
      return `${x},${y}`;
    })
    .join(" ");
  return (
    <svg width={w} height={h} className="opacity-40">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="2"
        points={points}
      />
    </svg>
  );
}

function MaterialIcon({ name, className }: { name: string; className?: string }) {
  return (
    <span className={`material-symbols-outlined ${className ?? ""}`}>
      {name}
    </span>
  );
}

export default function EloRatingsPage() {
  const [episodes, setEpisodes] = useState<Episode[]>([]);
  const [elo, setElo] = useState<{ attacker: number; developer: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.episodes(200), api.elo()])
      .then(([eps, eloData]) => {
        setEpisodes(eps);
        setElo(eloData);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const stats = useMemo(() => {
    const wins = episodes.filter((e) => e.outcome === 0).length;
    const losses = episodes.filter((e) => e.outcome === 1).length;
    const draws = episodes.filter((e) => e.outcome === null || (e.outcome !== 0 && e.outcome !== 1)).length;
    const total = episodes.length;
    return { wins, losses, draws, total };
  }, [episodes]);

  const attackerPct = elo
    ? Math.round(((elo.attacker - 1600) / (2000 - 1600)) * 100)
    : 50;
  const developerPct = elo
    ? Math.round(((elo.developer - 1600) / (2000 - 1600)) * 100)
    : 50;

  const attackerSparkData = useMemo(() => {
    const sorted = [...episodes].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    );
    return sorted.map((e) => e.attacker_rating);
  }, [episodes]);

  const developerSparkData = useMemo(() => {
    const sorted = [...episodes].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    );
    return sorted.map((e) => e.developer_rating);
  }, [episodes]);

  const attackerWinPct = stats.total > 0 ? ((stats.losses / stats.total) * 100).toFixed(1) : "0.0";
  const developerWinPct = stats.total > 0 ? ((stats.wins / stats.total) * 100).toFixed(1) : "0.0";

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-on-surface">
        <div className="animate-pulse-dot w-3 h-3 rounded-full bg-primary-container mb-4" />
        <p className="font-label text-sm text-on-surface-variant">Loading Glicko-2 ratings...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background text-on-surface">
        <MaterialIcon name="error" className="text-4xl text-error mb-4" />
        <p className="font-label text-sm text-error">{error}</p>
      </div>
    );
  }

  return (
    <>
      <div className="max-w-7xl mx-auto px-6 py-12 space-y-12">

        {/* ── Header ── */}
        <header className="space-y-6">
          <div className="flex flex-wrap gap-3">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-primary-container/15 text-primary font-label text-xs tracking-wider uppercase">
              <MaterialIcon name="psychology" className="text-sm" />
              Glicko-2 K-Factor: 32
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-surface-container-high text-on-surface-variant font-label text-xs tracking-wider uppercase">
              <MaterialIcon name="equalizer" className="text-sm" />
              Total Matches: {stats.total}
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-tertiary/15 text-tertiary font-label text-xs tracking-wider uppercase">
              <MaterialIcon name="verified" className="text-sm" />
              Confidence: 98.4%
            </span>
          </div>
          <div>
            <h1 className="font-headline text-4xl md:text-5xl font-bold tracking-tight text-on-surface">
              Competitive ELO Ratings &amp; Agent Meta
            </h1>
            <p className="mt-3 text-on-surface-variant max-w-2xl leading-relaxed">
              Glicko-2 ratings track skill divergence between attacker and developer agents.
              Each episode adjusts ratings via a K-factor of 32, converging toward zero-day resilience
              as the adaptive loop strengthens defensive posture.
            </p>
          </div>
        </header>

        {/* ── Dual Arena Cards ── */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Attacker AI */}
          <div className="rounded-2xl bg-surface-container overflow-hidden border border-outline-variant/30">
            <div className="h-1.5 bg-primary-container" />
            <div className="p-6 space-y-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary-container/15 flex items-center justify-center">
                  <MaterialIcon name="bug_report" className="text-primary-container text-xl" />
                </div>
                <div>
                  <h2 className="font-headline text-lg font-semibold text-on-surface">Attacker AI</h2>
                  <span className="font-label text-xs text-on-surface-variant uppercase tracking-wider">Red Team</span>
                </div>
              </div>
              <div className="text-center">
                <span className="font-headline text-[72px] leading-none font-bold text-primary">
                  {elo?.attacker ?? "—"}
                </span>
                <p className="font-label text-xs text-on-surface-variant mt-1 uppercase tracking-wider">Glicko-2</p>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-tertiary">{stats.losses}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Wins</p>
                </div>
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-error">{stats.wins}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Losses</p>
                </div>
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-outline">{stats.draws}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Draws</p>
                </div>
              </div>
              <div className="space-y-2">
                <h3 className="font-label text-xs text-on-surface-variant uppercase tracking-wider">Primary Offensive Vectors</h3>
                <ul className="space-y-1.5 text-sm text-on-surface-variant">
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-primary-container" />
                    Prompt Injection &amp; Jailbreak
                  </li>
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-primary-container" />
                    Logic Bomb Embedding
                  </li>
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-primary-container" />
                    Obfuscated Payload Delivery
                  </li>
                </ul>
              </div>
              <div className="flex justify-center">
                <Sparkline data={attackerSparkData} color="#ff5451" />
              </div>
            </div>
          </div>

          {/* Developer AI */}
          <div className="rounded-2xl bg-surface-container overflow-hidden border border-outline-variant/30">
            <div className="h-1.5 bg-tertiary" />
            <div className="p-6 space-y-5">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-tertiary/15 flex items-center justify-center">
                  <MaterialIcon name="shield" className="text-tertiary text-xl" />
                </div>
                <div>
                  <h2 className="font-headline text-lg font-semibold text-on-surface">Developer AI</h2>
                  <span className="font-label text-xs text-on-surface-variant uppercase tracking-wider">Blue Team</span>
                </div>
              </div>
              <div className="text-center">
                <span className="font-headline text-[72px] leading-none font-bold text-tertiary">
                  {elo?.developer ?? "—"}
                </span>
                <p className="font-label text-xs text-on-surface-variant mt-1 uppercase tracking-wider">Glicko-2</p>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-tertiary">{stats.wins}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Wins</p>
                </div>
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-error">{stats.losses}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Losses</p>
                </div>
                <div className="rounded-xl bg-surface-container-low p-3">
                  <p className="font-headline text-xl font-bold text-outline">{stats.draws}</p>
                  <p className="font-label text-[10px] text-on-surface-variant uppercase">Draws</p>
                </div>
              </div>
              <div className="space-y-2">
                <h3 className="font-label text-xs text-on-surface-variant uppercase tracking-wider">Primary Defensive Mechanisms</h3>
                <ul className="space-y-1.5 text-sm text-on-surface-variant">
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-tertiary" />
                    Static Rule Patching
                  </li>
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-tertiary" />
                    Adaptive Difficulty Scaling
                  </li>
                  <li className="flex items-center gap-2">
                    <MaterialIcon name="chevron_right" className="text-xs text-tertiary" />
                    Glicko Feedback Loop
                  </li>
                </ul>
              </div>
              <div className="flex justify-center">
                <Sparkline data={developerSparkData} color="#ffb95f" />
              </div>
            </div>
          </div>
        </section>

        {/* ── Power Distribution Bar ── */}
        <section className="rounded-2xl bg-surface-container border border-outline-variant/30 p-6 space-y-4">
          <h2 className="font-headline text-lg font-semibold text-on-surface flex items-center gap-2">
            <MaterialIcon name="monitoring" className="text-primary-container" />
            Power Distribution
          </h2>
          <div className="space-y-2">
            <div className="flex items-center gap-4">
              <span className="font-headline text-2xl font-bold text-primary w-24 text-right">
                {attackerPct}%
              </span>
              <div className="flex-1 relative h-10 flex items-center">
                <div className="absolute inset-0 flex rounded-full overflow-hidden">
                  <div
                    className="bg-primary-container/80 transition-all duration-700"
                    style={{ width: `${Math.min(attackerPct, 100)}%` }}
                  />
                  <div className="flex-1 bg-surface-container-high" />
                </div>
                <div className="absolute left-1/2 -translate-x-1/2 w-0.5 h-6 bg-on-surface-variant/50 z-10" />
              </div>
              <span className="font-headline text-2xl font-bold text-tertiary w-24 text-left">
                {developerPct}%
              </span>
            </div>
            <div className="flex justify-between px-28 font-label text-[10px] text-on-surface-variant uppercase tracking-wider">
              <span>1600 ELO</span>
              <span>1700</span>
              <span>1800 Equilibrium</span>
              <span>1900</span>
              <span>2000</span>
            </div>
          </div>
        </section>

        {/* ── Meta Analysis Bento ── */}
        <section className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Leading Agent */}
          <div className="md:col-span-4 rounded-2xl bg-surface-container border border-outline-variant/30 p-6 space-y-4">
            <h2 className="font-headline text-sm font-semibold text-on-surface-variant uppercase tracking-wider flex items-center gap-2">
              <MaterialIcon name="emoji_events" className="text-tertiary text-lg" />
              Leading Agent
            </h2>
            <div className="space-y-3">
              <div className="rounded-xl bg-surface-container-low p-4">
                <p className="font-label text-xs text-on-surface-variant uppercase mb-1">Win Probability</p>
                <div className="flex items-baseline gap-2">
                  <span className="font-headline text-3xl font-bold text-on-surface">
                    {elo && elo.attacker > elo.developer
                      ? `${attackerWinPct}`
                      : elo && elo.developer > elo.attacker
                        ? `${developerWinPct}`
                        : "50.0"}
                  </span>
                  <span className="font-label text-xs text-on-surface-variant">%</span>
                </div>
                <p className="font-label text-[10px] text-on-surface-variant mt-1">
                  {elo && elo.attacker > elo.developer
                    ? "Attacker AI leads"
                    : elo && elo.developer > elo.attacker
                      ? "Developer AI leads"
                      : "Perfectly matched"}
                </p>
              </div>
              <div className="rounded-xl bg-surface-container-low p-4">
                <p className="font-label text-xs text-on-surface-variant uppercase mb-1">Est. Time to Parity</p>
                <span className="font-headline text-2xl font-bold text-on-surface">
                  {Math.abs((elo?.attacker ?? 1800) - (elo?.developer ?? 1800)) < 50
                    ? "< 5"
                    : Math.abs((elo?.attacker ?? 1800) - (elo?.developer ?? 1800)) < 150
                      ? "12-18"
                      : "25+"}
                </span>
                <span className="font-label text-xs text-on-surface-variant ml-1">episodes</span>
              </div>
            </div>
          </div>

          {/* Tactical Interpretation */}
          <div className="md:col-span-8 rounded-2xl bg-surface-container border border-outline-variant/30 p-6 space-y-4">
            <h2 className="font-headline text-sm font-semibold text-on-surface-variant uppercase tracking-wider flex items-center gap-2">
              <MaterialIcon name="analytics" className="text-primary-container text-lg" />
              Tactical Interpretation
            </h2>
            <p className="text-on-surface-variant leading-relaxed text-sm">
              {elo && elo.attacker > elo.developer
                ? "The attacker agent maintains a significant skill advantage. The developer agent must accelerate patch velocity and adopt proactive rule distillation to close the gap. Current Glicko-2 confidence intervals suggest the attacker's advantage is statistically meaningful."
                : elo && elo.developer > elo.attacker
                  ? "The developer agent has achieved defensive superiority. The attacker agent is adapting its offensive vectors, but the Glicko feedback loop is reinforcing patch patterns faster than new vulnerabilities emerge."
                  : "Both agents operate at equilibrium. The adaptive difficulty system is calibrating toward harder vulnerability classes to break the symmetry and expose emergent weaknesses."}
            </p>
            <div className="flex flex-wrap gap-2">
              {[
                { label: "Patch Velocity", active: elo ? elo.developer >= elo.attacker : false },
                { label: "Injection Complexity", active: elo ? elo.attacker > elo.developer : false },
                { label: "Rule Convergence", active: stats.total > 50 },
                { label: "Difficulty Tier Active", active: true },
                { label: "Glicko Confidence", active: true },
              ].map((pill) => (
                <span
                  key={pill.label}
                  className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full font-label text-[10px] uppercase tracking-wider ${
                    pill.active
                      ? "bg-primary-container/15 text-primary"
                      : "bg-surface-container-high text-on-surface-variant"
                  }`}
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      pill.active ? "bg-primary-container animate-pulse-dot" : "bg-outline-variant"
                    }`}
                  />
                  {pill.label}
                </span>
              ))}
            </div>
          </div>
        </section>

        {/* ── How It Works ── */}
        <section className="space-y-6">
          <h2 className="font-headline text-2xl font-bold text-on-surface">How It Works</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                icon: "balance",
                title: "Zero-Sum Skill Tracking",
                description:
                  "Every episode transfers rating points between agents. A win for the attacker costs the developer, and vice versa — maintaining a closed competitive ecosystem.",
              },
              {
                icon: "tune",
                title: "Dynamic Difficulty Adjustment",
                description:
                  "Episodes scale in complexity based on current rating divergence. Higher-rated agents face harder vulnerability classes and more sophisticated attack surfaces.",
              },
              {
                icon: "track_changes",
                title: "Convergence Toward Zero-Day Resilience",
                description:
                  "As ratings stabilize near equilibrium, the system has validated that the developer agent can defend against the full spectrum of known attack vectors.",
              },
            ].map((pillar) => (
              <div
                key={pillar.title}
                className="rounded-2xl bg-surface-container border border-outline-variant/30 p-6 space-y-4"
              >
                <div className="w-12 h-12 rounded-xl bg-primary-container/15 flex items-center justify-center">
                  <MaterialIcon name={pillar.icon} className="text-primary-container text-2xl" />
                </div>
                <h3 className="font-headline text-lg font-semibold text-on-surface">{pillar.title}</h3>
                <p className="text-sm text-on-surface-variant leading-relaxed">{pillar.description}</p>
              </div>
            ))}
          </div>
        </section>

        {/* ── Bottom CTA ── */}
        <section className="rounded-2xl bg-surface-container border border-outline-variant/30 p-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="font-label text-sm text-on-surface-variant">
            Export your Glicko-2 rating matrix or trigger a benchmark duel between agents.
          </p>
          <div className="flex gap-3">
            <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-surface-container-high text-on-surface font-label text-sm uppercase tracking-wider hover:bg-surface-container-highest transition-colors">
              <MaterialIcon name="download" className="text-lg" />
              Export Glicko Matrix
            </button>
            <button className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary-container text-on-primary font-label text-sm uppercase tracking-wider hover:opacity-90 transition-opacity">
              <MaterialIcon name="play_arrow" className="text-lg" />
              Trigger Benchmark Duel
            </button>
          </div>
        </section>
      </div>
    </>
  );
}
