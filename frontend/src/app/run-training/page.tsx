"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, SSEEvent } from "@/lib/api";

/* ── mappings ──────────────────────────────────────────────────────────── */

const VULN_OPTIONS = [
  { label: "SQL Injection", value: "SQLi", cwe: "CWE-89" },
  { label: "Cross-Site Scripting", value: "XSS", cwe: "CWE-79" },
  { label: "Prototype Pollution", value: "Prototype Pollution", cwe: "CWE-1321" },
  { label: "Path Traversal", value: "Path Traversal", cwe: "CWE-22" },
  { label: "Insecure Deserialization", value: "Deserialization", cwe: "CWE-502" },
];

const LANG_OPTIONS = [
  { label: "TypeScript / Node.js", value: "javascript" },
  { label: "Python 3.12", value: "python" },
  { label: "Go 1.22", value: "go" },
  { label: "Rust", value: "rust" },
  { label: "Java 21", value: "java" },
];

const COMPLEXITY_TIERS = ["Standard", "Advanced", "Zero-Day"] as const;

type Tier = (typeof COMPLEXITY_TIERS)[number];

const TIER_MAP: Record<Tier, number> = {
  Standard: 1,
  Advanced: 2,
  "Zero-Day": 3,
};

/* ── agent definitions ─────────────────────────────────────────────────── */

const AGENTS = [
  {
    num: "01",
    role: "RED TEAM",
    title: "Attacker Agent",
    color: "bg-primary-container",
    colorText: "text-primary-container",
    icon: "shield",
    desc: "Generates adversarial payloads targeting the selected vulnerability class.",
    tactic: "Exploit Synthesis",
  },
  {
    num: "02",
    role: "BLUE TEAM",
    title: "Developer Agent",
    color: "bg-tertiary",
    colorText: "text-tertiary",
    icon: "code",
    desc: "Produces defensive patches and refactors code to neutralize exploits.",
    tactic: "Remediation Loop",
  },
  {
    num: "03",
    role: "JUDGE",
    title: "Judge Agent",
    color: "bg-secondary-container",
    colorText: "text-secondary",
    icon: "gavel",
    desc: "Evaluates attack severity and patch efficacy via mutation testing.",
    tactic: "Verdict Cascade",
  },
  {
    num: "04",
    role: "SYNTHESIS",
    title: "Rule Distiller",
    color: "bg-surface-variant",
    colorText: "text-on-surface-variant",
    icon: "psychology",
    desc: "Distills learned patterns into Semgrep-guardrail rules for long-term defense.",
    tactic: "Pattern Crystallisation",
  },
];

/* ── sequence steps ────────────────────────────────────────────────────── */

const SEQUENCE_STEPS = [
  { agent: "attacker", label: "Attacker Agent", dotColor: "bg-primary-container", desc: "Generating exploit payloads" },
  { agent: "developer", label: "Developer Agent", dotColor: "bg-tertiary", desc: "Producing defensive patch" },
  { agent: "judge", label: "Judge Agent", dotColor: "bg-secondary", desc: "Evaluating attack vs defence" },
  { agent: "distiller", label: "Rule Distiller", dotColor: "bg-on-surface-variant", desc: "Distilling Semgrep guardrail" },
] as const;

/* ── mock terminal lines (shown before stream) ─────────────────────────── */

const MOCK_TERMINAL = [
  { ts: "00:00.012", msg: "$ coevolve train --sandbox microvm" },
  { ts: "00:00.034", msg: "[boot] isolated firecracker microVM ready" },
  { ts: "00:00.071", msg: "[agent] red-team spawned — vuln=SQLi lang=javascript" },
  { ts: "00:01.220", msg: "[agent] exploit payload #1 synthesized (Union-based)" },
  { ts: "00:01.231", msg: "[agent] blue-team spawned — awaiting attack artifact" },
  { ts: "00:02.488", msg: "[agent] patch applied: parameterized query rewrite" },
  { ts: "00:02.502", msg: "[judge] mutation test suite executed (47 cases)" },
  { ts: "00:02.913", msg: "[judge] verdict: SECURE — boundary preserved" },
  { ts: "00:03.041", msg: "[rule] guardrail distilled → semgrep: sql-injection-v1" },
];

/* ── types ─────────────────────────────────────────────────────────────── */

interface TerminalEntry {
  ts: string;
  msg: string;
}

interface StepProgress {
  status: "pending" | "active" | "done" | "error";
  progress: number;
}

/* ── component ─────────────────────────────────────────────────────────── */

export default function RunTrainingPage() {
  /* form state */
  const [vuln, setVuln] = useState(VULN_OPTIONS[0].value);
  const [lang, setLang] = useState(LANG_OPTIONS[0].value);
  const [tier, setTier] = useState<Tier>("Standard");

  /* run state */
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<StepProgress[]>(
    SEQUENCE_STEPS.map(() => ({ status: "pending", progress: 0 }))
  );
  const [terminal, setTerminal] = useState<TerminalEntry[]>(MOCK_TERMINAL);
  const [result, setResult] = useState<{
    outcome: number;
    duration: number;
    elo: { attacker: number; developer: number };
  } | null>(null);
  const [ruleText, setRuleText] = useState<string | null>(null);

  const terminalRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  /* auto-scroll terminal */
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminal]);

  /* helper: append terminal line */
  const pushTerminal = useCallback((msg: string) => {
    const now = new Date();
    const ts = `${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}.${String(now.getMilliseconds()).padStart(3, "0")}`;
    setTerminal((prev) => [...prev, { ts, msg }]);
  }, []);

  /* start training */
  const handleStart = useCallback(() => {
    if (running) return;

    setRunning(true);
    setResult(null);
    setRuleText(null);
    setSteps(SEQUENCE_STEPS.map(() => ({ status: "pending", progress: 0 })));
    setTerminal(MOCK_TERMINAL);

    const vulnObj = VULN_OPTIONS.find((v) => v.value === vuln)!;
    pushTerminal(`$ coevolve train --vuln ${vulnObj.cwe} --lang ${lang} --tier ${TIER_MAP[tier]}`);

    cleanupRef.current = api.streamTraining(
      vuln,
      lang,
      (evt: SSEEvent) => {
        if (evt.type === "start") {
          pushTerminal("[boot] isolated firecracker microVM ready");
        }

        if (evt.type === "agent") {
          const agentIdx =
            evt.agent === "attacker"
              ? 0
              : evt.agent === "developer"
                ? 1
                : evt.agent === "judge"
                  ? 2
                  : 3;

          const isRunning = evt.status === "running";
          const isDone = evt.status === "done" || evt.status === "error";

          setSteps((prev) =>
            prev.map((s, i) =>
              i === agentIdx
                ? {
                    status: isDone ? (evt.status === "error" ? "error" : "done") : isRunning ? "active" : s.status,
                    progress: isDone ? 100 : isRunning ? 60 : s.progress,
                  }
                : s
            )
          );

          pushTerminal(
            `[agent] ${evt.agent ?? "?"} → ${evt.status ?? "?"} ${evt.message ? `— ${evt.message}` : ""}`
          );
        }

        if (evt.type === "complete") {
          const outcome = evt.outcome ?? 0;
          const duration = evt.duration_s ?? 0;
          const elo = { attacker: evt.elo?.[0] ?? 0, developer: evt.elo?.[1] ?? 0 };
          setResult({ outcome, duration, elo });
          if (evt.rule_distilled && evt.message) {
            setRuleText(evt.message);
          }

          setSteps((prev) =>
            prev.map((s) => ({ status: "done" as const, progress: 100 }))
          );

          pushTerminal("[done] episode complete");
          pushTerminal(
            `[result] verdict: ${outcome === 1 ? "SECURE" : "VULNERABLE"} — ${duration}s`
          );
          setRunning(false);
        }

        if (evt.type === "error") {
          pushTerminal(`[error] ${evt.message ?? "unknown error"}`);
          setRunning(false);
        }
      },
      () => {
        setRunning(false);
      },
      (err) => {
        pushTerminal(`[error] ${err}`);
        setRunning(false);
      }
    );
  }, [running, vuln, lang, tier, pushTerminal]);

  /* cleanup on unmount */
  useEffect(() => {
    return () => {
      cleanupRef.current?.();
    };
  }, []);

  /* ── render ─────────────────────────────────────────────────────────────── */

  const vulnLabel = VULN_OPTIONS.find((v) => v.value === vuln)?.label ?? vuln;
  const langLabel = LANG_OPTIONS.find((l) => l.value === lang)?.label ?? lang;

  return (
    <>
      {/* ════════════════ CONFIG FORM ════════════════ */}
        <section className="bg-surface-container rounded-2xl p-8 border border-outline-variant/20">
          <div className="flex items-center gap-3 mb-6">
            <span className="material-symbols-outlined text-primary-container text-xl">
              tune
            </span>
            <h2 className="font-headline text-lg font-semibold uppercase tracking-wide text-on-surface">
              Configuration
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {/* CWE Taxonomy */}
            <div className="flex flex-col gap-2">
              <label className="text-[11px] font-label uppercase tracking-widest text-outline">
                CWE Taxonomy
              </label>
              <select
                value={vuln}
                onChange={(e) => setVuln(e.target.value)}
                className="bg-surface-container-high text-on-surface border border-outline-variant/40 rounded-lg px-4 py-3 text-sm font-body focus:outline-none focus:ring-2 focus:ring-primary-container/60"
              >
                {VULN_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.cwe} — {o.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Target Stack */}
            <div className="flex flex-col gap-2">
              <label className="text-[11px] font-label uppercase tracking-widest text-outline">
                Target Stack
              </label>
              <select
                value={lang}
                onChange={(e) => setLang(e.target.value)}
                className="bg-surface-container-high text-on-surface border border-outline-variant/40 rounded-lg px-4 py-3 text-sm font-body focus:outline-none focus:ring-2 focus:ring-primary-container/60"
              >
                {LANG_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Complexity Tier */}
            <div className="flex flex-col gap-2">
              <label className="text-[11px] font-label uppercase tracking-widest text-outline">
                Complexity Tier
              </label>
              <div className="flex rounded-lg border border-outline-variant/40 overflow-hidden">
                {COMPLEXITY_TIERS.map((t) => (
                  <button
                    key={t}
                    onClick={() => setTier(t)}
                    className={`flex-1 px-3 py-3 text-xs font-label uppercase tracking-wider transition-colors ${
                      tier === t
                        ? "bg-primary-container text-on-primary-container font-semibold"
                        : "bg-surface-container-high text-on-surface-variant hover:bg-surface-container-highest"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Start Button */}
            <div className="flex flex-col justify-end">
              <button
                onClick={handleStart}
                disabled={running}
                className="flex items-center justify-center gap-2 bg-primary-container text-on-primary-container rounded-lg px-6 py-3 text-sm font-label uppercase tracking-wider font-semibold transition-all hover:brightness-110 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <span className="material-symbols-outlined text-lg">
                  {running ? "hourglass_top" : "play_arrow"}
                </span>
                {running ? "Running…" : "Start Training"}
              </button>
            </div>
          </div>

          {/* active config summary */}
          <div className="mt-6 flex flex-wrap gap-3">
            <span className="inline-flex items-center gap-1.5 bg-surface-container-high rounded-full px-3 py-1 text-[11px] font-label uppercase tracking-wider text-on-surface-variant">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-container" />
              {VULN_OPTIONS.find((v) => v.value === vuln)?.cwe}
            </span>
            <span className="inline-flex items-center gap-1.5 bg-surface-container-high rounded-full px-3 py-1 text-[11px] font-label uppercase tracking-wider text-on-surface-variant">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary" />
              {langLabel}
            </span>
            <span className="inline-flex items-center gap-1.5 bg-surface-container-high rounded-full px-3 py-1 text-[11px] font-label uppercase tracking-wider text-on-surface-variant">
              <span className="w-1.5 h-1.5 rounded-full bg-secondary" />
              Tier {TIER_MAP[tier]}
            </span>
          </div>
        </section>

        {/* ════════════════ MULTI-AGENT MESH ════════════════ */}
        <section>
          <div className="flex items-center gap-3 mb-6">
            <span className="material-symbols-outlined text-secondary text-xl">
              hub
            </span>
            <h2 className="font-headline text-lg font-semibold uppercase tracking-wide text-on-surface">
              Multi-Agent Mesh
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {AGENTS.map((a) => (
              <div
                key={a.num}
                className="bg-surface-container rounded-xl border border-outline-variant/20 p-5 flex flex-col justify-between hover:border-outline-variant/40 transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <span className={`w-10 h-10 ${a.color} rounded-lg flex items-center justify-center`}>
                      <span className="material-symbols-outlined text-on-surface text-lg">
                        {a.icon}
                      </span>
                    </span>
                    <span className="text-[10px] font-label text-outline tracking-wider">
                      {a.num}
                    </span>
                  </div>
                  <p className={`text-[11px] font-label uppercase tracking-widest ${a.colorText} mb-1`}>
                    {a.role}
                  </p>
                  <h3 className="font-headline text-sm font-semibold text-on-surface mb-2">
                    {a.title}
                  </h3>
                  <p className="text-xs text-on-surface-variant leading-relaxed">
                    {a.desc}
                  </p>
                </div>
                <div className="mt-4 pt-3 border-t border-outline-variant/20">
                  <p className="text-[10px] font-label uppercase tracking-widest text-outline">
                    Tactic
                  </p>
                  <p className="text-xs font-label text-on-surface-variant mt-0.5">
                    {a.tactic}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* ════════════════ LIVE PROGRESS ════════════════ */}
        <section>
          <div className="flex items-center gap-3 mb-6">
            <span className="material-symbols-outlined text-tertiary text-xl">
              monitoring
            </span>
            <h2 className="font-headline text-lg font-semibold uppercase tracking-wide text-on-surface">
              Live Progress
            </h2>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* left — sequence stream */}
            <div className="bg-surface-container rounded-xl border border-outline-variant/20 p-6">
              <h3 className="text-[11px] font-label uppercase tracking-widest text-outline mb-5">
                Live Sequence Stream
              </h3>

              <div className="space-y-5">
                {SEQUENCE_STEPS.map((step, i) => {
                  const s = steps[i];
                  return (
                    <div key={step.agent}>
                      <div className="flex items-center gap-3 mb-2">
                        <span className={`w-2.5 h-2.5 rounded-full ${step.dotColor} ${
                          s.status === "active" ? "animate-pulse" : ""
                        }`} />
                        <span className="text-sm font-label text-on-surface font-medium">
                          {step.label}
                        </span>
                        <span
                          className={`ml-auto text-[10px] font-label uppercase tracking-widest px-2 py-0.5 rounded-full ${
                            s.status === "done"
                              ? "bg-tertiary/20 text-tertiary"
                              : s.status === "active"
                                ? "bg-primary-container/20 text-primary-container"
                                : s.status === "error"
                                  ? "bg-error/20 text-error"
                                  : "bg-surface-container-high text-outline"
                          }`}
                        >
                          {s.status === "pending"
                            ? "queued"
                            : s.status === "done"
                              ? "complete"
                              : s.status}
                        </span>
                      </div>
                      <div className="h-1.5 bg-surface-container-high rounded-full overflow-hidden ml-6">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            s.status === "error"
                              ? "bg-error"
                              : s.status === "done"
                                ? "bg-tertiary"
                                : "bg-primary-container"
                          }`}
                          style={{ width: `${s.progress}%` }}
                        />
                      </div>
                      <p className="text-xs text-on-surface-variant ml-6 mt-1.5">
                        {step.desc}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* right — terminal console */}
            <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/20 flex flex-col">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-outline-variant/20">
                <span className="w-3 h-3 rounded-full bg-error/70" />
                <span className="w-3 h-3 rounded-full bg-tertiary/70" />
                <span className="w-3 h-3 rounded-full bg-primary-container/70" />
                <span className="ml-2 text-[10px] font-label uppercase tracking-widest text-outline">
                  Terminal Console
                </span>
                <span className="ml-auto material-symbols-outlined text-outline text-sm">
                  terminal
                </span>
              </div>
              <div
                ref={terminalRef}
                className="flex-1 overflow-y-auto p-4 font-label text-xs leading-relaxed text-on-surface-variant max-h-[340px]"
              >
                {terminal.map((entry, i) => (
                  <div key={i} className="flex gap-3">
                    <span className="text-outline select-none shrink-0">{entry.ts}</span>
                    <span
                      className={
                        entry.msg.startsWith("[error]")
                          ? "text-error"
                          : entry.msg.startsWith("[done]")
                            ? "text-tertiary"
                            : entry.msg.startsWith("$")
                              ? "text-primary-container"
                              : "text-on-surface-variant"
                      }
                    >
                      {entry.msg}
                    </span>
                  </div>
                ))}
                {running && (
                  <div className="flex gap-3 mt-1">
                    <span className="text-outline animate-pulse">█</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>

        {/* ════════════════ RESULT BANNERS ════════════════ */}
        {result && (
          <section>
            <div className="flex items-center gap-3 mb-6">
              <span className="material-symbols-outlined text-secondary text-xl">
                flag
              </span>
              <h2 className="font-headline text-lg font-semibold uppercase tracking-wide text-on-surface">
                Battle Outcome
              </h2>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* SECURE */}
              <div
                className={`rounded-xl border p-6 transition-all ${
                  result.outcome === 1
                    ? "bg-secondary-container/10 border-secondary-container/40"
                    : "bg-surface-container border-outline-variant/20 opacity-40"
                }`}
              >
                <div className="flex items-center gap-3 mb-3">
                  <span className="material-symbols-outlined text-secondary text-2xl">
                    verified_user
                  </span>
                  <h3 className="font-headline text-base font-semibold text-secondary">
                    SECURE
                  </h3>
                </div>
                <p className="text-on-surface font-headline text-sm mb-4">
                  Defensive Boundary Preserved
                </p>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Attacker ELO</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.elo.attacker}</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Developer ELO</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.elo.developer}</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Duration</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.duration}s</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Verdict</p>
                    <p className="text-secondary font-label text-sm mt-1 font-semibold">Defended</p>
                  </div>
                </div>
              </div>

              {/* VULNERABLE */}
              <div
                className={`rounded-xl border p-6 transition-all ${
                  result.outcome !== 1
                    ? "bg-error-container/10 border-error-container/40"
                    : "bg-surface-container border-outline-variant/20 opacity-40"
                }`}
              >
                <div className="flex items-center gap-3 mb-3">
                  <span className="material-symbols-outlined text-error text-2xl">
                    bug_report
                  </span>
                  <h3 className="font-headline text-base font-semibold text-error">
                    VULNERABLE
                  </h3>
                </div>
                <p className="text-on-surface font-headline text-sm mb-4">
                  Payload Evaded Detection
                </p>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Attacker ELO</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.elo.attacker}</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Developer ELO</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.elo.developer}</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Duration</p>
                    <p className="text-on-surface font-label text-sm mt-1">{result.duration}s</p>
                  </div>
                  <div className="bg-surface-container-lowest rounded-lg p-3">
                    <p className="text-[10px] font-label uppercase tracking-widest text-outline">Verdict</p>
                    <p className="text-error font-label text-sm mt-1 font-semibold">Breach</p>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ════════════════ DISTILLED GUARDRAIL ════════════════ */}
        {ruleText && (
          <section>
            <div className="flex items-center gap-3 mb-6">
              <span className="material-symbols-outlined text-on-surface-variant text-xl">
                policy
              </span>
              <h2 className="font-headline text-lg font-semibold uppercase tracking-wide text-on-surface">
                Distilled Guardrail
              </h2>
            </div>

            <div className="bg-surface-container-lowest rounded-xl border border-outline-variant/20 overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-outline-variant/20">
                <span className="material-symbols-outlined text-on-surface-variant text-sm">
                  code
                </span>
                <span className="text-[10px] font-label uppercase tracking-widest text-outline">
                  Semgrep Rule — {VULN_OPTIONS.find((v) => v.value === vuln)?.cwe}
                </span>
                <span className="ml-auto text-[10px] font-label text-tertiary">
                  AUTO-DISTILLED
                </span>
              </div>
              <pre className="p-5 overflow-x-auto">
                <code className="font-label text-xs text-on-surface-variant leading-relaxed whitespace-pre">
                  {ruleText}
                </code>
              </pre>
            </div>
          </section>
        )}
    </>
  );
}
