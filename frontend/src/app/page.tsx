"use client";

import { useEffect, useState, useCallback, useRef } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Metrics {
  total_episodes: number;
  secure_rate: number;
  /** Deprecated alias kept for old backends — prefer `elo`. */
  epo: { attacker: number; developer: number };
  elo?: { attacker: number; developer: number };
  rules_count: number;
}

interface Episode {
  episode_id: string;
  status: string;
  vulnerability_class: string | null;
  difficulty_tier: number | null;
  outcome: number | null;
  task_description: string | null;
  patch_text: string | null;
  judge_verdict: Record<string, unknown> | null;
  error: string | null;
  attacker_rating: number;
  developer_rating: number;
  prompt_version: number;
  created_at: string;
}

interface Rule {
  id: string;
  rule_text: string;
  vulnerability_class: string;
  source_pattern: string;
  recommended_fix: string;
  approved: boolean;
}

interface RuleDetail extends Rule {
  source_trace_id: string;
  prompt_version: number;
  created_at: string;
}

interface Prompt {
  id: string;
  version: number;
  base_prompt: string;
  rules: unknown[];
  commit_message: string;
  parent_version: number | null;
  created_at: string;
}

interface PromptDiff {
  from_version: number;
  to_version: number;
  added: string[];
  removed: string[];
}

interface Job {
  job_id: string;
  status: string;
  vulnerability_class: string;
  language: string;
  context_hint: string;
  max_retries: number;
  use_react: boolean;
  queue_position: number | null;
  created_at: number;
  started_at: number | null;
  completed_at: number | null;
  result: Record<string, unknown>;
  error: string;
}

interface Coverage {
  vulnerability_class: string;
  total_episodes: number;
  detected_count: number;
  secure_count: number;
  coverage_rate: number;
}

type Tab = "overview" | "episodes" | "rules" | "prompts" | "jobs" | "coverage";

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span
      style={{
        background: color,
        padding: "2px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        whiteSpace: "nowrap",
      }}
    >
      {label}
    </span>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section
      style={{
        background: "var(--surface)",
        border: "1px solid var(--border)",
        borderRadius: 8,
        padding: 24,
        marginBottom: 24,
      }}
    >
      <h2
        style={{
          fontSize: 14,
          color: "var(--text-dim)",
          textTransform: "uppercase",
          letterSpacing: 1,
          marginBottom: 16,
        }}
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

function Pre({ text, copy }: { text: string; copy?: string }) {
  const [copied, setCopied] = useState(false);
  const doCopy = async () => {
    try {
      await navigator.clipboard.writeText(copy ?? text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div style={{ position: "relative" }}>
      <pre
        style={{
          background: "var(--surface-2)",
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: 12,
          fontSize: 12,
          lineHeight: 1.5,
          overflow: "auto",
          maxHeight: 300,
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {text}
      </pre>
      <button
        onClick={doCopy}
        title="Copy to clipboard"
        style={{
          position: "absolute",
          top: 6,
          right: 6,
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: 4,
          padding: "2px 8px",
          fontSize: 11,
          cursor: "pointer",
          color: "var(--text-dim)",
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function Field({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 13, marginBottom: 6 }}>
      <span style={{ color: "var(--text-dim)", minWidth: 150, flexShrink: 0 }}>{k}</span>
      <span style={{ wordBreak: "break-word" }}>{v}</span>
    </div>
  );
}

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return iso;
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function fmtDur(sec: number | null | undefined): string {
  if (sec === null || sec === undefined) return "—";
  if (sec < 60) return `${sec.toFixed(1)}s`;
  return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`;
}

function fmtTs(epochSec: number | null | undefined): string {
  if (!epochSec) return "—";
  return new Date(epochSec * 1000).toLocaleString();
}

interface SastFinding {
  rule_id: string;
  file: string;
  line: number;
  severity: string;
  confidence: string;
  message: string;
}

interface Verdict {
  j?: number;
  trace_id?: string;
  episode_k?: number | null;
  structure?: string;
  sast?: { rules_matched?: SastFinding[]; total_matches?: number };
  dast?: {
    exploit_class?: string;
    payload?: string;
    success?: boolean;
    stdout?: string;
    stderr?: string;
    execution_time_ms?: number;
    evidence?: string[];
  };
  error?: string;
}

function VerdictTable({ verdict }: { verdict: Verdict }) {
  const findings = verdict.sast?.rules_matched ?? [];
  const dast = verdict.dast && Object.keys(verdict.dast).length > 0 ? verdict.dast : null;
  return (
    <div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, flexWrap: "wrap" }}>
        {verdict.j === 0 ? (
          <Badge label="SECURE" color="#4caf5030" />
        ) : verdict.j === 1 ? (
          <Badge label="VULNERABLE" color="#ff545130" />
        ) : (
          <Badge label="UNKNOWN" color="#8888a030" />
        )}
        {verdict.trace_id && (
          <code style={{ fontSize: 11, color: "var(--text-dim)" }}>trace {verdict.trace_id.slice(0, 8)}</code>
        )}
        {verdict.episode_k !== null && verdict.episode_k !== undefined && (
          <span style={{ fontSize: 11, color: "var(--text-dim)" }}>episode_k={verdict.episode_k}</span>
        )}
      </div>
      {verdict.structure && (
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 8 }}>{verdict.structure}</p>
      )}
      {verdict.error && (
        <p style={{ fontSize: 12, color: "var(--accent)", marginBottom: 8 }}>Judge error: {verdict.error}</p>
      )}
      <div style={{ fontSize: 13, fontWeight: 600, margin: "8px 0 4px" }}>
        SAST — {verdict.sast?.total_matches ?? findings.length} match(es)
      </div>
      {findings.length === 0 ? (
        <p style={{ fontSize: 12, color: "var(--text-dim)" }}>Clean — no patterns matched.</p>
      ) : (
        <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse", marginBottom: 8 }}>
          <thead>
            <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
              <th style={{ padding: "6px 4px", borderBottom: "1px solid var(--border)" }}>Rule</th>
              <th style={{ padding: "6px 4px", borderBottom: "1px solid var(--border)" }}>Severity</th>
              <th style={{ padding: "6px 4px", borderBottom: "1px solid var(--border)" }}>Location</th>
              <th style={{ padding: "6px 4px", borderBottom: "1px solid var(--border)" }}>Message</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f, i) => (
              <tr key={i} style={{ borderBottom: "1px solid var(--border)", verticalAlign: "top" }}>
                <td style={{ padding: "6px 4px", fontFamily: "monospace" }}>{f.rule_id}</td>
                <td style={{ padding: "6px 4px" }}>{f.severity}</td>
                <td style={{ padding: "6px 4px", fontFamily: "monospace" }}>
                  {f.file}:{f.line}
                </td>
                <td style={{ padding: "6px 4px" }}>{f.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ fontSize: 13, fontWeight: 600, margin: "8px 0 4px" }}>DAST replay</div>
      {!dast ? (
        <p style={{ fontSize: 12, color: "var(--text-dim)" }}>
          Not run — SAST was clean or the replay was inconclusive.
        </p>
      ) : (
        <>
          <Field k="Exploit class" v={<code style={{ fontSize: 12 }}>{dast.exploit_class}</code>} />
          <Field
            k="Result"
            v={
              dast.success ? (
                <Badge label="EXPLOITED" color="#ff545130" />
              ) : (
                <Badge label="BLOCKED" color="#4caf5030" />
              )
            }
          />
          {dast.execution_time_ms !== undefined && <Field k="Replay time" v={fmtDur(dast.execution_time_ms / 1000)} />}
          {dast.payload && (
            <>
              <div style={{ fontSize: 12, color: "var(--text-dim)", margin: "4px 0" }}>Payload</div>
              <Pre text={dast.payload} />
            </>
          )}
          {dast.evidence && dast.evidence.length > 0 && (
            <>
              <div style={{ fontSize: 12, color: "var(--text-dim)", margin: "4px 0" }}>Evidence</div>
              {dast.evidence.map((e, i) => (
                <p key={i} style={{ fontSize: 12, marginBottom: 2 }}>
                  • {e}
                </p>
              ))}
            </>
          )}
          {dast.stdout && (
            <>
              <div style={{ fontSize: 12, color: "var(--text-dim)", margin: "4px 0" }}>Stdout</div>
              <Pre text={dast.stdout} />
            </>
          )}
        </>
      )}
    </div>
  );
}

function BarChart({
  data,
  maxVal,
}: {
  data: { label: string; value: number; color: string }[];
  maxVal: number;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {data.map((d) => (
        <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ width: 140, fontSize: 13, color: "var(--text-dim)", textAlign: "right" }}>
            {d.label}
          </span>
          <div
            style={{
              flex: 1,
              height: 20,
              background: "var(--surface-2)",
              borderRadius: 4,
              overflow: "hidden",
            }}
          >
            <div
              style={{
                height: "100%",
                width: `${(d.value / maxVal) * 100}%`,
                background: d.color,
                borderRadius: 4,
                transition: "width 0.3s",
              }}
            />
          </div>
          <span style={{ width: 30, fontSize: 13, fontWeight: 600 }}>{d.value}</span>
        </div>
      ))}
    </div>
  );
}

function EloBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontSize: 13 }}>{label}</span>
        <span style={{ fontWeight: 700, color }}>{Math.round(value)}</span>
      </div>
      <div
        style={{
          height: 8,
          background: "var(--surface-2)",
          borderRadius: 4,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${((value - 1000) / 1500) * 100}%`,
            background: color,
            borderRadius: 4,
          }}
        />
      </div>
    </div>
  );
}

function outcomeBadge(outcome: number | null, status: string) {
  if (outcome === 0) return <Badge label="SECURE" color="#4caf5030" />;
  if (outcome === 1) return <Badge label="VULN" color="#ff545130" />;
  if (status === "failed") return <Badge label="FAILED" color="#8888a030" />;
  return <Badge label={status.toUpperCase()} color="#8888a030" />;
}

export default function Dashboard() {
  const [tab, setTab] = useState<Tab>("overview");
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [episodes, setEpisodes] = useState<Episode[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [coverage, setCoverage] = useState<Coverage[]>([]);
  const [promptCurrent, setPromptCurrent] = useState<Prompt | null>(null);
  const [promptHistory, setPromptHistory] = useState<Prompt[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const [expandedEp, setExpandedEp] = useState<string | null>(null);
  const [ruleDetail, setRuleDetail] = useState<Record<string, RuleDetail>>({});
  const [diffV1, setDiffV1] = useState("");
  const [diffV2, setDiffV2] = useState("");
  const [diff, setDiff] = useState<PromptDiff | null>(null);
  const [diffError, setDiffError] = useState("");
  const [jobForm, setJobForm] = useState({ vulnerability_class: "SQLi", language: "python", use_react: false });
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState<string>("");
  const [epQuery, setEpQuery] = useState("");
  const [epStatus, setEpStatus] = useState("all");
  const [epOutcome, setEpOutcome] = useState("all");
  const [epLimit, setEpLimit] = useState(100);
  const EP_PAGE = 100;
  // Pause auto-refresh while the user inspects details so the UI doesn't jump.
  const interactiveRef = useRef(false);
  interactiveRef.current =
    expandedEp !== null || Object.keys(ruleDetail).length > 0 || diff !== null || running;

  const fetchData = useCallback(async () => {
    try {
      const get = async (p: string) => {
        const r = await fetch(`${API}${p}`);
        if (!r.ok) return null;
        return r.json();
      };
      const [m, e, r, c, pc, ph, j] = await Promise.all([
        get("/metrics"),
        get(`/episodes?limit=${epLimit}`),
        get("/rules?limit=100"),
        get("/vulnerabilities/coverage"),
        get("/prompts/current"),
        get("/prompts/history?limit=50"),
        get("/training/jobs?limit=50"),
      ]);
      if (m) setMetrics(m);
      if (e) setEpisodes(e);
      if (r) setRules(r);
      if (c) setCoverage(c);
      setPromptCurrent(pc);
      if (ph) setPromptHistory(ph);
      if (j) setJobs(j);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [epLimit]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => {
      if (!interactiveRef.current && !document.hidden) fetchData();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const fetchRuleDetail = async (id: string) => {
    if (ruleDetail[id]) {
      const next = { ...ruleDetail };
      delete next[id];
      setRuleDetail(next);
      return;
    }
    try {
      const r = await fetch(`${API}/rules/${id}`);
      if (r.ok) setRuleDetail({ ...ruleDetail, [id]: await r.json() });
    } catch {
      /* ignore */
    }
  };

  const fetchDiff = async () => {
    setDiffError("");
    setDiff(null);
    try {
      const r = await fetch(`${API}/prompts/diff/${diffV1}/${diffV2}`);
      if (!r.ok) {
        setDiffError(`Versions not found (${r.status})`);
        return;
      }
      setDiff(await r.json());
    } catch {
      setDiffError("Backend unreachable");
    }
  };

  const enqueueJob = async () => {
    try {
      const r = await fetch(`${API}/training/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(jobForm),
      });
      if (r.ok) fetchData();
    } catch {
      /* ignore */
    }
  };

  const runTraining = async () => {
    setRunning(true);
    setLastRun("");
    try {
      const r = await fetch(`${API}/training/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = await r.json();
      setLastRun(
        `episode=${body.episode_id} status=${body.status} outcome=${body.judge_outcome} rule=${body.rule_distilled}`
      );
      fetchData();
    } catch {
      setLastRun("request failed");
    } finally {
      setRunning(false);
    }
  };

  const stopEpisode = async (id: string) => {
    try {
      await fetch(`${API}/episodes/${id}/stop`, { method: "POST" });
      fetchData();
    } catch {
      /* ignore */
    }
  };

  // Derived stats
  const vulnByClass: Record<string, { total: number; vuln: number }> = {};
  episodes.forEach((ep) => {
    const cls = ep.vulnerability_class || "Unknown";
    if (!vulnByClass[cls]) vulnByClass[cls] = { total: 0, vuln: 0 };
    vulnByClass[cls].total++;
    if (ep.outcome === 1) vulnByClass[cls].vuln++;
  });

  const classData = Object.entries(vulnByClass).map(([cls, d]) => ({
    label: cls,
    value: d.total,
    color: d.vuln > 0 ? "var(--accent)" : "var(--green)",
  }));

  const secureCount = episodes.filter((e) => e.outcome === 0).length;
  const vulnCount = episodes.filter((e) => e.outcome === 1).length;
  const maxClass = Math.max(...classData.map((d) => d.value), 1);

  const eloTimeline = [...episodes].reverse();

  const windowSize = 10;
  const rollingSecureRate: number[] = [];
  for (let i = 0; i < eloTimeline.length; i++) {
    const start = Math.max(0, i - windowSize + 1);
    const window = eloTimeline.slice(start, i + 1);
    const secure = window.filter((e) => e.outcome === 0).length;
    rollingSecureRate.push(secure / window.length);
  }

  const perClassPerf: Record<string, { secure: number; total: number }> = {};
  eloTimeline.forEach((ep) => {
    const cls = ep.vulnerability_class || "Unknown";
    if (!perClassPerf[cls]) perClassPerf[cls] = { secure: 0, total: 0 };
    perClassPerf[cls].total++;
    if (ep.outcome === 0) perClassPerf[cls].secure++;
  });

  // Prefer the canonical `elo` field; fall back to the deprecated `epo` alias.
  const eloR = (metrics?.elo ?? metrics?.epo) as { attacker: number; developer: number } | undefined;

  const filteredEpisodes = episodes.filter((ep) => {
    if (epStatus !== "all" && ep.status !== epStatus) return false;
    if (epOutcome === "secure" && ep.outcome !== 0) return false;
    if (epOutcome === "vuln" && ep.outcome !== 1) return false;
    if (epOutcome === "error" && !(ep.outcome === null || ep.outcome === undefined)) return false;
    if (epQuery) {
      const q = epQuery.toLowerCase();
      const hay = `${ep.episode_id} ${ep.vulnerability_class || ""} ${ep.task_description || ""} ${ep.error || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const tabs: { id: Tab; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "episodes", label: `Episodes (${episodes.length})` },
    { id: "rules", label: `Rules (${rules.length})` },
    { id: "prompts", label: "Prompts" },
    { id: "jobs", label: `Jobs (${jobs.length})` },
    { id: "coverage", label: "Coverage" },
  ];

  const fmtDate = (s: string) => {
    try {
      return new Date(s).toLocaleString();
    } catch {
      return s;
    }
  };

  return (
    <main style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 24px" }}>
      <header style={{ marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: 32, fontWeight: 700 }}>
            <span style={{ color: "var(--accent)" }}>Co</span>Evolve
          </h1>
          <p style={{ color: "var(--text-dim)", marginTop: 4 }}>Adversarial Security Training Platform</p>
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <button
            onClick={runTraining}
            disabled={running}
            style={{
              background: running ? "var(--surface-2)" : "var(--accent)",
              color: "#fff",
              border: "none",
              borderRadius: 6,
              padding: "8px 16px",
              fontSize: 13,
              fontWeight: 600,
              cursor: running ? "wait" : "pointer",
            }}
          >
            {running ? "Training…" : "Run training now"}
          </button>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: error ? "var(--accent)" : "var(--green)",
              }}
            />
            <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
              {loading ? "Connecting..." : error ? "Offline" : "Live"}
            </span>
          </div>
        </div>
      </header>

      {lastRun && (
        <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 16 }}>Last run: {lastRun}</p>
      )}

      {error && (
        <div
          style={{
            background: "#ff545120",
            border: "1px solid var(--accent)",
            padding: 16,
            borderRadius: 8,
            marginBottom: 24,
          }}
        >
          <p style={{ color: "var(--accent)" }}>Backend unreachable. Start the API on port 8000.</p>
        </div>
      )}

      <nav style={{ display: "flex", gap: 8, marginBottom: 24, flexWrap: "wrap" }}>
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              background: tab === t.id ? "var(--surface)" : "transparent",
              border: "1px solid var(--border)",
              borderBottom: tab === t.id ? "2px solid var(--accent)" : "1px solid var(--border)",
              borderRadius: "6px 6px 0 0",
              padding: "8px 16px",
              fontSize: 13,
              fontWeight: tab === t.id ? 700 : 400,
              cursor: "pointer",
              color: "var(--text)",
            }}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "overview" && (
        <>
          {metrics && (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 24 }}>
              {[
                { label: "Episodes", value: metrics.total_episodes, icon: "📊" },
                { label: "Secure Rate", value: `${(metrics.secure_rate * 100).toFixed(0)}%`, icon: "🛡️" },
                { label: "Rules", value: metrics.rules_count, icon: "📏" },
                { label: "Attacker ELO", value: Math.round(eloR!.attacker), icon: "⚔️" },
                { label: "Developer ELO", value: Math.round(eloR!.developer), icon: "🔧" },
              ].map((s) => (
                <div
                  key={s.label}
                  style={{
                    background: "var(--surface)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    padding: 20,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "var(--text-dim)", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>
                      {s.label}
                    </span>
                    <span style={{ fontSize: 16 }}>{s.icon}</span>
                  </div>
                  <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>{s.value}</div>
                </div>
              ))}
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>
            {metrics && (
              <Section title="ELO Ratings">
                <EloBar label="Attacker" value={eloR!.attacker} color="var(--accent)" />
                <EloBar label="Developer" value={eloR!.developer} color="var(--accent-2)" />
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontSize: 13, color: "var(--text-dim)" }}>Rating Gap</span>
                    <span style={{ fontSize: 13, fontWeight: 600 }}>
                      {(() => {
                        const gap = Math.round(eloR!.developer - eloR!.attacker);
                        const leader = gap >= 0 ? "Dev lead" : "Attacker lead";
                        return (
                          <span style={{ color: gap >= 0 ? "var(--green)" : "var(--accent)" }}>
                            {gap >= 0 ? "+" : ""}
                            {gap} pts ({leader})
                          </span>
                        );
                      })()}
                    </span>
                  </div>
                </div>
              </Section>
            )}
            <Section title="Episodes by Class">
              {classData.length > 0 ? (
                <BarChart data={classData} maxVal={maxClass} />
              ) : (
                <p style={{ color: "var(--text-dim)" }}>No data yet.</p>
              )}
            </Section>
          </div>

          <Section title="Security Outcomes">
            <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
              <div style={{ flex: 1 }}>
                <div
                  style={{
                    height: 32,
                    background: "var(--surface-2)",
                    borderRadius: 6,
                    overflow: "hidden",
                    display: "flex",
                  }}
                >
                  <div
                    style={{
                      width: `${(secureCount / Math.max(secureCount + vulnCount, 1)) * 100}%`,
                      background: "var(--green)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: 12,
                      fontWeight: 600,
                      color: "#fff",
                      minWidth: secureCount > 0 ? 40 : 0,
                    }}
                  >
                    {secureCount}
                  </div>
                  <div
                    style={{
                      width: `${(vulnCount / Math.max(secureCount + vulnCount, 1)) * 100}%`,
                      background: "var(--accent)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: 12,
                      fontWeight: 600,
                      color: "#fff",
                      minWidth: vulnCount > 0 ? 40 : 0,
                    }}
                  >
                    {vulnCount}
                  </div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 24 }}>
                <span style={{ fontSize: 13 }}>🟩 Secure ({secureCount})</span>
                <span style={{ fontSize: 13 }}>🟥 Vulnerable ({vulnCount})</span>
              </div>
            </div>
          </Section>

          {rollingSecureRate.length > 2 && (
            <Section title={`Convergence — Rolling Secure Rate (window=${windowSize})`}>
              <div style={{ position: "relative", height: 180, marginBottom: 16 }}>
                <div
                  style={{
                    position: "absolute",
                    left: 0,
                    right: 0,
                    top: "50%",
                    height: 1,
                    background: "var(--border)",
                    opacity: 0.5,
                  }}
                >
                  <span style={{ position: "absolute", right: 0, top: -8, fontSize: 10, color: "var(--text-dim)" }}>
                    50%
                  </span>
                </div>
                <svg
                  viewBox={`0 0 ${rollingSecureRate.length * 10} 100`}
                  style={{ width: "100%", height: "100%", position: "absolute" }}
                  preserveAspectRatio="none"
                >
                  <polyline
                    points={rollingSecureRate.map((r, i) => `${i * 10 + 5},${100 - r * 100}`).join(" ")}
                    fill="none"
                    stroke="var(--green)"
                    strokeWidth="2"
                    vectorEffect="non-scaling-stroke"
                  />
                </svg>
              </div>
            </Section>
          )}

          <Section title="Per-Class Performance">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
              {Object.entries(perClassPerf)
                .sort((a, b) => b[1].total - a[1].total)
                .map(([cls, d]) => (
                  <div
                    key={cls}
                    style={{
                      background: "var(--surface-2)",
                      border: "1px solid var(--border)",
                      borderRadius: 6,
                      padding: 14,
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>{cls}</span>
                      <span style={{ fontSize: 12, color: "var(--text-dim)" }}>{d.total} eps</span>
                    </div>
                    <span style={{ fontSize: 12, fontWeight: 600 }}>
                      {(d.secure / d.total * 100).toFixed(0)}% secure ({d.secure}/{d.total})
                    </span>
                  </div>
                ))}
            </div>
          </Section>

          {eloTimeline.length > 2 && (
            <Section title="ELO Progression">
              <div style={{ position: "relative", height: 200 }}>
                {[1200, 1400, 1600, 1800].map((v) => (
                  <div
                    key={v}
                    style={{
                      position: "absolute",
                      left: 0,
                      right: 0,
                      top: `${((v - 1000) / 1000) * 100}%`,
                      height: 1,
                      background: "var(--border)",
                      opacity: 0.3,
                    }}
                  >
                    <span style={{ position: "absolute", left: 0, top: -8, fontSize: 10, color: "var(--text-dim)" }}>
                      {v}
                    </span>
                  </div>
                ))}
                <svg
                  viewBox={`0 0 ${eloTimeline.length * 20} 200`}
                  style={{ width: "100%", height: "100%", position: "absolute" }}
                  preserveAspectRatio="none"
                >
                  <polyline
                    points={eloTimeline
                      .map((ep, i) => `${i * 20 + 10},${200 - ((ep.attacker_rating - 1000) / 1000) * 200}`)
                      .join(" ")}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth="2"
                    vectorEffect="non-scaling-stroke"
                  />
                  <polyline
                    points={eloTimeline
                      .map((ep, i) => `${i * 20 + 10},${200 - ((ep.developer_rating - 1000) / 1000) * 200}`)
                      .join(" ")}
                    fill="none"
                    stroke="var(--accent-2)"
                    strokeWidth="2"
                    vectorEffect="non-scaling-stroke"
                  />
                </svg>
              </div>
            </Section>
          )}
        </>
      )}

      {tab === "episodes" && (
        <Section title={`All Episodes (${filteredEpisodes.length}/${episodes.length}) — click a row for full detail`}>
          <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
            <input
              value={epQuery}
              onChange={(e) => setEpQuery(e.target.value)}
              placeholder="Search id, class, task, error…"
              style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", width: 240, fontSize: 13 }}
            />
            <select
              value={epStatus}
              onChange={(e) => setEpStatus(e.target.value)}
              style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", fontSize: 13 }}
            >
              <option value="all">All statuses</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="pending">Pending</option>
            </select>
            <select
              value={epOutcome}
              onChange={(e) => setEpOutcome(e.target.value)}
              style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", fontSize: 13 }}
            >
              <option value="all">All outcomes</option>
              <option value="secure">Secure</option>
              <option value="vuln">Vulnerable</option>
              <option value="error">Error/unknown</option>
            </select>
          </div>
          {episodes.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No episodes yet. Click “Run training now” above.</p>
          ) : filteredEpisodes.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No episodes match the current filters.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {filteredEpisodes.map((ep) => (
                <div
                  key={ep.episode_id}
                  style={{
                    background: "var(--surface-2)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: "12px 14px",
                  }}
                >
                  <div
                    onClick={() => setExpandedEp(expandedEp === ep.episode_id ? null : ep.episode_id)}
                    style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                      <Badge label={ep.vulnerability_class || "—"} color="#8888a030" />
                      <span style={{ fontSize: 12, color: "var(--text-dim)" }}>T{ep.difficulty_tier ?? "?"}</span>
                      <span style={{ fontSize: 12, fontFamily: "monospace" }}>{ep.episode_id}</span>
                      <span style={{ fontSize: 11, color: "var(--text-dim)" }} title={fmtDate(ep.created_at)}>
                        {timeAgo(ep.created_at)}
                      </span>
                    </div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                        {Math.round(ep.attacker_rating)} / {Math.round(ep.developer_rating)}
                      </span>
                      {outcomeBadge(ep.outcome, ep.status)}
                    </div>
                  </div>
                  {expandedEp === ep.episode_id && (
                    <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
                      <Field k="Status" v={ep.status} />
                      <Field k="Prompt version" v={`v${ep.prompt_version}`} />
                      <Field k="Task" v={ep.task_description || "—"} />
                      {ep.error && <Field k="Error" v={<span style={{ color: "var(--accent)" }}>{ep.error}</span>} />}
                      <div style={{ fontSize: 13, color: "var(--text-dim)", margin: "8px 0 4px" }}>Patch</div>
                      <Pre text={ep.patch_text || "(empty)"} />
                      <div style={{ fontSize: 13, color: "var(--text-dim)", margin: "8px 0 4px" }}>Judge verdict</div>
                      {ep.judge_verdict ? (
                        <VerdictTable verdict={ep.judge_verdict as Verdict} />
                      ) : (
                        <p style={{ fontSize: 12, color: "var(--text-dim)" }}>(none recorded)</p>
                      )}
                      {ep.status !== "completed" && ep.status !== "failed" && (
                        <button
                          onClick={() => stopEpisode(ep.episode_id)}
                          style={{
                            marginTop: 8,
                            background: "var(--accent)",
                            color: "#fff",
                            border: "none",
                            borderRadius: 6,
                            padding: "6px 14px",
                            fontSize: 12,
                            cursor: "pointer",
                          }}
                        >
                          Stop episode
                        </button>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {episodes.length >= epLimit && (
                <button
                  onClick={() => setEpLimit((n) => n + EP_PAGE)}
                  style={{ marginTop: 8, background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: "8px 16px", fontSize: 13, cursor: "pointer", color: "var(--text)" }}
                >
                  Load more ({episodes.length} loaded)
                </button>
              )}
            </div>
          )}
        </Section>
      )}

      {tab === "rules" && (
        <Section title={`Distilled Rules (${rules.length}) — click a row for full detail`}>
          {rules.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No rules distilled yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {rules.map((r) => (
                <div
                  key={r.id}
                  style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}
                >
                  <div
                    onClick={() => fetchRuleDetail(r.id)}
                    style={{ cursor: "pointer", display: "flex", justifyContent: "space-between", marginBottom: 6 }}
                  >
                    <Badge label={r.vulnerability_class} color="var(--accent-2)20" />
                    {r.approved && <Badge label="APPROVED" color="#4caf5030" />}
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "flex-start", justifyContent: "space-between" }}>
                    <p style={{ fontSize: 13, lineHeight: 1.5, flex: 1 }}>{r.rule_text}</p>
                    <button
                      onClick={async () => {
                        try {
                          await navigator.clipboard.writeText(r.rule_text);
                        } catch {
                          /* clipboard unavailable */
                        }
                      }}
                      title="Copy rule text"
                      style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 4, padding: "2px 8px", fontSize: 11, cursor: "pointer", color: "var(--text-dim)", flexShrink: 0 }}
                    >
                      Copy
                    </button>
                  </div>
                  {ruleDetail[r.id] && (
                    <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
                      <Field k="Source pattern" v={<code style={{ fontSize: 12 }}>{ruleDetail[r.id].source_pattern || "—"}</code>} />
                      <Field k="Recommended fix" v={ruleDetail[r.id].recommended_fix || "—"} />
                      <Field k="Source trace" v={<code style={{ fontSize: 12 }}>{ruleDetail[r.id].source_trace_id || "—"}</code>} />
                      <Field k="Prompt version" v={`v${ruleDetail[r.id].prompt_version}`} />
                      <Field k="Created" v={fmtDate(ruleDetail[r.id].created_at)} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {tab === "prompts" && (
        <>
          <Section title="Current Prompt">
            {promptCurrent ? (
              <>
                <Field k="Version" v={`v${promptCurrent.version}`} />
                <Field k="Commit" v={promptCurrent.commit_message || "—"} />
                <Field k="Parent" v={promptCurrent.parent_version !== null ? `v${promptCurrent.parent_version}` : "—"} />
                <Field k="Active rules" v={promptCurrent.rules.length} />
                <Field k="Created" v={fmtDate(promptCurrent.created_at)} />
                <div style={{ fontSize: 13, color: "var(--text-dim)", margin: "8px 0 4px" }}>Base prompt</div>
                <Pre text={promptCurrent.base_prompt} />
              </>
            ) : (
              <p style={{ color: "var(--text-dim)" }}>No prompt versions yet.</p>
            )}
          </Section>
          <Section title={`Version History (${promptHistory.length})`}>
            {promptHistory.length === 0 ? (
              <p style={{ color: "var(--text-dim)" }}>No history.</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {promptHistory.map((p) => (
                  <div key={p.id} style={{ display: "flex", gap: 12, fontSize: 13, alignItems: "center" }}>
                    <Badge label={`v${p.version}`} color="#8888a030" />
                    <span style={{ flex: 1 }}>{p.commit_message || "—"}</span>
                    <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{p.rules.length} rules</span>
                    <span style={{ color: "var(--text-dim)", fontSize: 12 }}>{fmtDate(p.created_at)}</span>
                  </div>
                ))}
              </div>
            )}
          </Section>
          <Section title="Diff Two Versions">
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <input
                value={diffV1}
                onChange={(e) => setDiffV1(e.target.value)}
                placeholder="from (e.g. 1)"
                style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", width: 140 }}
              />
              <input
                value={diffV2}
                onChange={(e) => setDiffV2(e.target.value)}
                placeholder="to (e.g. 2)"
                style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", width: 140 }}
              />
              <button
                onClick={fetchDiff}
                style={{ background: "var(--accent-2)", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", fontSize: 13, cursor: "pointer" }}
              >
                Diff
              </button>
            </div>
            {diffError && <p style={{ color: "var(--accent)", fontSize: 13 }}>{diffError}</p>}
            {diff && (
              <>
                <Field k="Added" v={`${diff.added.length} rule(s)`} />
                {diff.added.map((a, i) => (
                  <p key={`a${i}`} style={{ fontSize: 12, color: "var(--green)", marginBottom: 4 }}>+ {a}</p>
                ))}
                <Field k="Removed" v={`${diff.removed.length} rule(s)`} />
                {diff.removed.map((r, i) => (
                  <p key={`r${i}`} style={{ fontSize: 12, color: "var(--accent)", marginBottom: 4 }}>- {r}</p>
                ))}
              </>
            )}
          </Section>
        </>
      )}

      {tab === "jobs" && (
        <>
          <Section title="Enqueue Training Job (async)">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <input
                value={jobForm.vulnerability_class}
                onChange={(e) => setJobForm({ ...jobForm, vulnerability_class: e.target.value })}
                placeholder="vulnerability class"
                style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", width: 180 }}
              />
              <input
                value={jobForm.language}
                onChange={(e) => setJobForm({ ...jobForm, language: e.target.value })}
                placeholder="language"
                style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 8, color: "var(--text)", width: 120 }}
              />
              <label style={{ fontSize: 13, display: "flex", gap: 6, alignItems: "center" }}>
                <input
                  type="checkbox"
                  checked={jobForm.use_react}
                  onChange={(e) => setJobForm({ ...jobForm, use_react: e.target.checked })}
                />
                ReAct
              </label>
              <button
                onClick={enqueueJob}
                style={{ background: "var(--accent)", color: "#fff", border: "none", borderRadius: 6, padding: "8px 16px", fontSize: 13, cursor: "pointer" }}
              >
                Enqueue
              </button>
            </div>
            <p style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 8 }}>
              Jobs are processed by the background worker (<code>make worker</code>). Requires Redis in multi-process setups.
            </p>
          </Section>
          <Section title={`Training Jobs (${jobs.length})`}>
            {jobs.length === 0 ? (
              <p style={{ color: "var(--text-dim)" }}>No jobs yet.</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {jobs.map((j) => (
                  <div key={j.job_id} style={{ background: "var(--surface-2)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: 12, fontFamily: "monospace" }}>{j.job_id}</span>
                      <Badge
                        label={j.status.toUpperCase()}
                        color={j.status === "completed" ? "#4caf5030" : j.status === "failed" ? "#ff545130" : j.status === "running" ? "var(--accent-2)30" : "#8888a030"}
                      />
                    </div>
                    <Field k="Class / lang" v={`${j.vulnerability_class} / ${j.language}${j.use_react ? " (ReAct)" : ""}`} />
                    <Field k="Enqueued" v={fmtTs(j.created_at)} />
                    {j.queue_position !== null && j.status === "pending" && <Field k="Queue position" v={j.queue_position} />}
                    {j.started_at && (
                      <Field
                        k="Wait / run time"
                        v={`${fmtDur(j.started_at - j.created_at)} wait${j.completed_at ? ` / ${fmtDur(j.completed_at - j.started_at)} run` : ""}`}
                      />
                    )}
                    {j.error && <Field k="Error" v={<span style={{ color: "var(--accent)" }}>{j.error}</span>} />}
                    {Object.keys(j.result).length > 0 && (
                      <Pre text={JSON.stringify(j.result, null, 2)} />
                    )}
                  </div>
                ))}
              </div>
            )}
          </Section>
        </>
      )}

      {tab === "coverage" && (
        <Section title={`Vulnerability Coverage (${coverage.length} classes)`}>
          {coverage.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No coverage data yet — run training first.</p>
          ) : (
            <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "var(--text-dim)" }}>
                  <th style={{ padding: "8px 4px", borderBottom: "1px solid var(--border)" }}>Class</th>
                  <th style={{ padding: "8px 4px", borderBottom: "1px solid var(--border)" }}>Episodes</th>
                  <th style={{ padding: "8px 4px", borderBottom: "1px solid var(--border)" }}>Detected</th>
                  <th style={{ padding: "8px 4px", borderBottom: "1px solid var(--border)" }}>Secure</th>
                  <th style={{ padding: "8px 4px", borderBottom: "1px solid var(--border)" }}>Coverage</th>
                </tr>
              </thead>
              <tbody>
                {coverage.map((c) => (
                  <tr key={c.vulnerability_class} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "8px 4px" }}>{c.vulnerability_class}</td>
                    <td style={{ padding: "8px 4px" }}>{c.total_episodes}</td>
                    <td style={{ padding: "8px 4px" }}>{c.detected_count}</td>
                    <td style={{ padding: "8px 4px" }}>{c.secure_count}</td>
                    <td style={{ padding: "8px 4px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ flex: 1, minWidth: 60, height: 8, background: "var(--surface-2)", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${c.coverage_rate * 100}%`, background: c.coverage_rate >= 0.7 ? "var(--green)" : "var(--accent)", borderRadius: 4 }} />
                        </div>
                        <span style={{ fontWeight: 600 }}>{(c.coverage_rate * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>
      )}

      <footer style={{ textAlign: "center", padding: "24px 0", color: "var(--text-dim)", fontSize: 12 }}>
        CoEvolve — Adversarial Security Training Platform
      </footer>
    </main>
  );
}
