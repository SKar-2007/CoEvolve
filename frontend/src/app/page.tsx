"use client";

import { useEffect, useState } from "react";
import { api, type Metrics } from "@/lib/api";

const PIPELINE_STEPS = [
  { num: "01", label: "ATTACK", icon: "shield", title: "Attacker Generates", desc: "Adversarial LLM probes for zero-day vulnerabilities using mutation-based fuzzing." },
  { num: "02", label: "DEFEND", icon: "code", title: "Developer Patches", desc: "Defensive LLM analyzes attack surface and synthesizes AST-level patches." },
  { num: "03", label: "VERIFY", icon: "check_circle", title: "Judge Verifies", desc: "Isolated judge agent validates patch correctness against ground truth." },
  { num: "04", label: "BALANCE", icon: "balance", title: "ELO Updates", desc: "Glicko-2 rating system updates agent skill ratings based on outcome." },
  { num: "05", label: "DISTILL", icon: "psychology", title: "Rules Distilled", desc: "Winning strategies distilled into reusable AST-mutation rules." },
];

const VULNERABILITY_CLASSES = [
  { name: "SQL Injection", rate: 87 },
  { name: "Cross-Site Scripting", rate: 93 },
  { name: "Remote Code Execution", rate: 74 },
  { name: "Server-Side Request Forgery", rate: 81 },
];

const INFRA_STACK = [
  { name: "Vercel", desc: "Edge-optimized deployment platform", icon: "public", status: "ACTIVE" },
  { name: "Render", desc: "Backend API & GPU workers", icon: "dns", status: "ACTIVE" },
  { name: "Groq", desc: "Ultra-low-latency LLM inference", icon: "speed", status: "ACTIVE" },
  { name: "Supabase", desc: "PostgreSQL + real-time subscriptions", icon: "storage", status: "ACTIVE" },
];

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .metrics()
      .then(setMetrics)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const eloGap = metrics
    ? Math.abs(metrics.epo.developer - metrics.epo.attacker)
    : 0;
  const securePct = metrics ? (metrics.secure_rate * 100).toFixed(1) : "0.0";
  const attackerPct = metrics
    ? ((metrics.epo.attacker / (metrics.epo.attacker + metrics.epo.developer)) * 100).toFixed(1)
    : "50.0";
  const developerPct = metrics
    ? ((metrics.epo.developer / (metrics.epo.attacker + metrics.epo.developer)) * 100).toFixed(1)
    : "50.0";

  return (
    <>
      {/* ─── Hero Header ─── */}
      <section className="bg-surface-container-low p-space-lg">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-lg">
          <div className="space-y-space-md">
            <div className="flex flex-wrap gap-space-sm">
              <span className="font-label text-xs uppercase px-2 py-0.5 rounded bg-surface-container-lowest text-secondary border border-outline-variant">
                LOOP ID: #8492 // DUAL-AGENT ACTIVE
              </span>
              <span className="font-label text-xs uppercase px-2 py-0.5 rounded bg-surface-container-lowest text-tertiary border border-outline-variant">
                EPOCH: 084 // GLICKO-2
              </span>
              <span className="font-label text-xs uppercase px-2 py-0.5 rounded bg-surface-container-lowest text-primary border border-outline-variant animate-pulse-dot">
                REAL-TIME ORCHESTRATION
              </span>
            </div>
            <h1 className="font-headline text-4xl lg:text-5xl font-bold uppercase tracking-tight">
              <span className="text-on-surface">CoEvolve</span>{" "}
              <span className="text-primary-container">Adversarial</span>{" "}
              <span className="text-tertiary">HUD</span>
            </h1>
            <p className="font-body text-secondary max-w-xl leading-relaxed">
              A dual-agent adversarial training loop where an Attacker AI and Developer AI continuously
              challenge and reinforce each other, producing battle-hardened security patches distilled
              into reproducible AST-mutation rules.
            </p>
          </div>

          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-space-md min-w-[260px]">
            <p className="font-label text-xs uppercase text-secondary mb-space-xs">CURRENT ARBITRATION</p>
            <p className="font-headline text-lg font-semibold text-on-surface">AST-MUTATION-V9 STABLE</p>
            <p className="font-label text-xs text-tertiary mt-space-xs">Delta Time: 142ms / round</p>
          </div>
        </div>
      </section>

      {/* ─── Stat Cards ─── */}
      <section className="p-space-lg">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-space-md">
          <StatCard
            label="EPISODES RUN"
            value={loading ? "—" : String(metrics?.total_episodes ?? 0)}
            badge="Live Pipeline"
            badgeColor="bg-secondary-container text-on-secondary-container"
          />
          <StatCard
            label="SECURE RATE"
            value={loading ? "—" : `${securePct}%`}
            progress={metrics?.secure_rate ?? 0}
          />
          <StatCard
            label="RULES LEARNED"
            value={loading ? "—" : String(metrics?.rules_count ?? 0)}
            badge="AST STORE"
            badgeColor="bg-tertiary-container text-on-tertiary-container"
          />
          <StatCard
            label="ELO GAP"
            value={loading ? "—" : String(eloGap.toFixed(0))}
            badge="DEV ADV"
            badgeColor="bg-primary-container text-on-primary-container"
          />
        </div>
      </section>

      {/* ─── Pipeline Diagram ─── */}
      <section className="px-space-lg pb-space-lg">
        <h2 className="font-label text-xs uppercase text-secondary mb-space-md">EXECUTION FLOW</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-space-md">
          {PIPELINE_STEPS.map((step, i) => (
            <div key={step.num} className="relative">
              <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-space-md h-full flex flex-col space-y-space-sm">
                <span className="font-label text-[10px] uppercase px-1.5 py-0.5 rounded bg-surface-container-highest text-secondary inline-block w-fit">
                  {step.num} // {step.label}
                </span>
                <span className="material-symbols-outlined text-2xl text-primary">{step.icon}</span>
                <h3 className="font-headline text-sm font-semibold text-on-surface">{step.title}</h3>
                <p className="font-body text-xs text-secondary leading-relaxed flex-1">{step.desc}</p>
                <div className="border-t border-outline-variant pt-space-xs mt-auto">
                  <p className="font-label text-[10px] uppercase text-tertiary">ROLE: {
                    step.label === "ATTACK" ? "adversary" :
                    step.label === "DEFEND" ? "defender" :
                    step.label === "VERIFY" ? "arbiter" :
                    step.label === "BALANCE" ? "rating-system" : "meta-learner"
                  }</p>
                </div>
              </div>
              {i < PIPELINE_STEPS.length - 1 && (
                <span className="hidden lg:block absolute top-1/2 -right-3 -translate-y-1/2 text-outline-variant material-symbols-outlined text-lg pointer-events-none">
                  arrow_forward
                </span>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* ─── ELO Head-to-Head + Attack Vectors ─── */}
      <section className="px-space-lg pb-space-lg grid grid-cols-1 lg:grid-cols-12 gap-space-md">
        {/* ELO Head-to-Head */}
        <div className="lg:col-span-7 bg-surface-container-lowest border border-outline-variant rounded-lg p-space-lg space-y-space-md">
          <h2 className="font-label text-xs uppercase text-secondary">ELO HEAD-TO-HEAD</h2>

          <div className="space-y-space-sm">
            <div className="flex items-center justify-between">
              <span className="font-label text-xs uppercase text-on-surface">ATTACKER AI</span>
              <span className="font-headline text-xl font-bold text-primary-container">
                {loading ? "—" : metrics?.epo.attacker ?? 0}
              </span>
            </div>
            <div className="w-full h-3 bg-surface-container-highest rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-container rounded-full transition-all duration-700"
                style={{ width: `${attackerPct}%` }}
              />
            </div>
            <p className="font-label text-[10px] text-secondary">{attackerPct}% dominance</p>
          </div>

          <div className="space-y-space-sm">
            <div className="flex items-center justify-between">
              <span className="font-label text-xs uppercase text-on-surface">DEVELOPER AI</span>
              <span className="font-headline text-xl font-bold text-tertiary">
                {loading ? "—" : metrics?.epo.developer ?? 0}
              </span>
            </div>
            <div className="w-full h-3 bg-surface-container-highest rounded-full overflow-hidden">
              <div
                className="h-full bg-tertiary rounded-full transition-all duration-700"
                style={{ width: `${developerPct}%` }}
              />
            </div>
            <p className="font-label text-[10px] text-secondary">{developerPct}% dominance</p>
          </div>

          <div className="bg-surface-container-low border border-outline-variant rounded p-space-sm mt-space-md">
            <p className="font-label text-[10px] uppercase text-secondary">
              META ANALYSIS — The rating gap between agents correlates with rule distillation yield.
              A smaller gap indicates balanced adversarial pressure and higher-quality rule extraction.
            </p>
          </div>
        </div>

        {/* Attack Vectors */}
        <div className="lg:col-span-5 bg-surface-container-lowest border border-outline-variant rounded-lg p-space-lg flex flex-col">
          <h2 className="font-label text-xs uppercase text-secondary mb-space-md">ATTACK VECTORS</h2>
          <div className="space-y-space-md flex-1">
            {VULNERABILITY_CLASSES.map((vc) => (
              <div key={vc.name}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-body text-sm text-on-surface">{vc.name}</span>
                  <span className="font-label text-xs text-primary">{vc.rate}%</span>
                </div>
                <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full transition-all duration-700"
                    style={{ width: `${vc.rate}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
          <button className="mt-space-md font-label text-xs uppercase text-tertiary hover:text-on-surface transition-colors self-start">
            VIEW ALL VECTOR LOGS →
          </button>
        </div>
      </section>

      {/* ─── Infrastructure Stack ─── */}
      <section className="px-space-lg pb-space-xl">
        <h2 className="font-label text-xs uppercase text-secondary mb-space-md">INFRASTRUCTURE STACK</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
          {INFRA_STACK.map((svc) => (
            <div key={svc.name} className="bg-surface-container-lowest border border-outline-variant rounded-lg p-space-md space-y-space-sm">
              <div className="flex items-center justify-between">
                <span className="material-symbols-outlined text-xl text-secondary">{svc.icon}</span>
                <span className="font-label text-[10px] uppercase px-1.5 py-0.5 rounded bg-secondary-container text-on-secondary-container">
                  {svc.status}
                </span>
              </div>
              <h3 className="font-headline text-sm font-semibold text-on-surface">{svc.name}</h3>
              <p className="font-body text-xs text-secondary">{svc.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function StatCard({
  label,
  value,
  badge,
  badgeColor,
  progress,
}: {
  label: string;
  value: string;
  badge?: string;
  badgeColor?: string;
  progress?: number;
}) {
  return (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-space-md space-y-space-sm">
      <p className="font-label text-[10px] uppercase text-secondary">{label}</p>
      <p className="font-headline text-2xl font-bold text-on-surface">{value}</p>
      {badge && (
        <span className={`font-label text-[10px] uppercase px-1.5 py-0.5 rounded ${badgeColor ?? "bg-surface-container-highest text-secondary"}`}>
          {badge}
        </span>
      )}
      {progress !== undefined && (
        <div className="w-full h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all duration-700"
            style={{ width: `${progress * 100}%` }}
          />
        </div>
      )}
    </div>
  );
}
