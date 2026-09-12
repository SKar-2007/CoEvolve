"use client";

import { useEffect, useState, useCallback } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Metrics {
  total_episodes: number;
  secure_rate: number;
  epo: { attacker: number; developer: number };
  rules_count: number;
}

interface Episode {
  episode_id: string;
  status: string;
  vulnerability_class: string | null;
  outcome: number | null;
  difficulty_tier: number | null;
  attacker_rating: number;
  developer_rating: number;
  judge_verdict: Record<string, unknown>;
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

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span
      style={{
        background: color,
        padding: "2px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
      }}
    >
      {label}
    </span>
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

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [episodes, setEpisodes] = useState<Episode[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [m, e, r] = await Promise.all([
        fetch(`${API}/metrics`).then((r) => r.json()),
        fetch(`${API}/episodes?limit=50`).then((r) => r.json()),
        fetch(`${API}/rules?limit=10`).then((r) => r.json()),
      ]);
      setMetrics(m);
      setEpisodes(e);
      setRules(r);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

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

  // ELO timeline (reverse to chronological)
  const eloTimeline = [...episodes].reverse();

  // Convergence analysis - rolling secure rate
  const windowSize = 10;
  const rollingSecureRate: number[] = [];
  for (let i = 0; i < eloTimeline.length; i++) {
    const start = Math.max(0, i - windowSize + 1);
    const window = eloTimeline.slice(start, i + 1);
    const secure = window.filter((e) => e.outcome === 0).length;
    rollingSecureRate.push(secure / window.length);
  }

  // Per-class performance
  const perClassPerf: Record<string, { secure: number; total: number; rates: number[] }> = {};
  eloTimeline.forEach((ep, i) => {
    const cls = ep.vulnerability_class || "Unknown";
    if (!perClassPerf[cls]) perClassPerf[cls] = { secure: 0, total: 0, rates: [] };
    perClassPerf[cls].total++;
    if (ep.outcome === 0) perClassPerf[cls].secure++;
    perClassPerf[cls].rates.push(perClassPerf[cls].secure / perClassPerf[cls].total);
  });

  return (
    <main style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 24px" }}>
      <header style={{ marginBottom: 40, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ fontSize: 32, fontWeight: 700 }}>
            <span style={{ color: "var(--accent)" }}>Co</span>Evolve
          </h1>
          <p style={{ color: "var(--text-dim)", marginTop: 4 }}>Adversarial Security Training Platform</p>
        </div>
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
      </header>

      {error && (
        <div
          style={{
            background: "#ff545120",
            border: "1px solid var(--accent)",
            padding: 16,
            borderRadius: 8,
            marginBottom: 32,
          }}
        >
          <p style={{ color: "var(--accent)" }}>Backend unreachable. Start the API on port 8000.</p>
        </div>
      )}

      {/* Stats Cards */}
      {metrics && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 32 }}>
          {[
            { label: "Episodes", value: metrics.total_episodes, icon: "📊" },
            { label: "Secure Rate", value: `${(metrics.secure_rate * 100).toFixed(0)}%`, icon: "🛡️" },
            { label: "Rules", value: metrics.rules_count, icon: "📏" },
            { label: "Attacker ELO", value: Math.round(metrics.epo.attacker), icon: "⚔️" },
            { label: "Developer ELO", value: Math.round(metrics.epo.developer), icon: "🔧" },
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

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 32 }}>
        {/* ELO Ratings */}
        {metrics && (
          <section
            style={{
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              padding: 24,
            }}
          >
            <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
              ELO Ratings
            </h2>
            <EloBar label="Attacker" value={metrics.epo.attacker} color="var(--accent)" />
            <EloBar label="Developer" value={metrics.epo.developer} color="var(--accent-2)" />
            <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
              <div style={{ display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontSize: 13, color: "var(--text-dim)" }}>Rating Gap</span>
                <span style={{ fontSize: 13, fontWeight: 600 }}>
                  {Math.round(metrics.epo.developer - metrics.epo.attacker)} pts (Dev lead)
                </span>
              </div>
            </div>
          </section>
        )}

        {/* Vuln Breakdown */}
        <section
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: 24,
          }}
        >
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
            Episodes by Class
          </h2>
          {classData.length > 0 ? (
            <BarChart data={classData} maxVal={maxClass} />
          ) : (
            <p style={{ color: "var(--text-dim)" }}>No data yet.</p>
          )}
        </section>
      </div>

      {/* Secure vs Vulnerable */}
      <section
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          padding: 24,
          marginBottom: 32,
        }}
      >
        <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
          Security Outcomes
        </h2>
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
                  width: `${((secureCount / Math.max(secureCount + vulnCount, 1)) * 100)}%`,
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
                  width: `${((vulnCount / Math.max(secureCount + vulnCount, 1)) * 100)}%`,
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
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 12, height: 12, borderRadius: 3, background: "var(--green)" }} />
              <span style={{ fontSize: 13 }}>Secure ({secureCount})</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 12, height: 12, borderRadius: 3, background: "var(--accent)" }} />
              <span style={{ fontSize: 13 }}>Vulnerable ({vulnCount})</span>
            </div>
          </div>
        </div>
      </section>

      {/* Convergence Analysis */}
      {rollingSecureRate.length > 2 && (
        <section
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: 24,
            marginBottom: 32,
          }}
        >
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
            Convergence Analysis — Rolling Secure Rate (window={windowSize})
          </h2>
          <div style={{ position: "relative", height: 180, marginBottom: 16 }}>
            {/* 50% line */}
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
            {/* Rolling rate line */}
            <svg
              viewBox={`0 0 ${rollingSecureRate.length * 10} 100`}
              style={{ width: "100%", height: "100%", position: "absolute" }}
              preserveAspectRatio="none"
            >
              <polyline
                points={rollingSecureRate
                  .map((r, i) => `${i * 10 + 5},${100 - r * 100}`)
                  .join(" ")}
                fill="none"
                stroke="var(--green)"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />
            </svg>
          </div>
          <div style={{ display: "flex", gap: 24, justifyContent: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 16, height: 2, background: "var(--green)" }} />
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                Rolling Secure Rate (last {rollingSecureRate.length > 0 ? (rollingSecureRate[rollingSecureRate.length - 1] * 100).toFixed(0) : "?"}%)
              </span>
            </div>
          </div>
        </section>
      )}

      {/* Per-Class Performance */}
      <section
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: 8,
          padding: 24,
          marginBottom: 32,
        }}
      >
        <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
          Per-Class Performance
        </h2>
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
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                    <div
                      style={{
                        width: `${d.secure / d.total * 100}%`,
                        height: 6,
                        background: "var(--green)",
                        borderRadius: 3,
                        minWidth: d.secure > 0 ? 4 : 0,
                      }}
                    />
                    <div
                      style={{
                        width: `${(d.total - d.secure) / d.total * 100}%`,
                        height: 6,
                        background: "var(--accent)",
                        borderRadius: 3,
                        minWidth: d.total - d.secure > 0 ? 4 : 0,
                      }}
                    />
                  </div>
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 600,
                      color: d.secure / d.total >= 0.7 ? "var(--green)" : "var(--accent)",
                    }}
                  >
                    {(d.secure / d.total * 100).toFixed(0)}%
                  </span>
                </div>
                <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-dim)" }}>
                  {d.secure} secure / {d.total - d.secure} vuln
                </div>
              </div>
            ))}
        </div>
      </section>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 24, marginBottom: 32 }}>
        {/* Episodes */}
        <section
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: 24,
          }}
        >
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
            Recent Episodes
          </h2>
          {episodes.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No episodes yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 400, overflow: "auto" }}>
              {episodes.slice(0, 20).map((ep) => (
                <div
                  key={ep.episode_id}
                  style={{
                    background: "var(--surface-2)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: "10px 14px",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <Badge
                      label={ep.vulnerability_class || "—"}
                      color={
                        ep.vulnerability_class === "SQLi"
                          ? "#ff545130"
                          : ep.vulnerability_class === "XSS"
                            ? "#ffb95f30"
                            : ep.vulnerability_class === "CommandInjection"
                              ? "#a855f730"
                              : "#8888a030"
                      }
                    />
                    <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                      T{ep.difficulty_tier || "?"}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                      {Math.round(ep.attacker_rating)} / {Math.round(ep.developer_rating)}
                    </span>
                    {ep.outcome === 0 ? (
                      <Badge label="SECURE" color="#4caf5030" />
                    ) : ep.outcome === 1 ? (
                      <Badge label="VULN" color="#ff545130" />
                    ) : (
                      <Badge label="ERR" color="#8888a030" />
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Rules */}
        <section
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: 24,
          }}
        >
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
            Distilled Rules ({rules.length})
          </h2>
          {rules.length === 0 ? (
            <p style={{ color: "var(--text-dim)" }}>No rules distilled yet.</p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 400, overflow: "auto" }}>
              {rules.map((r) => (
                <div
                  key={r.id}
                  style={{
                    background: "var(--surface-2)",
                    border: "1px solid var(--border)",
                    borderRadius: 6,
                    padding: 12,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <Badge label={r.vulnerability_class} color="var(--accent-2)20" />
                    {r.approved && <Badge label="APPROVED" color="#4caf5030" />}
                  </div>
                  <p style={{ fontSize: 12, lineHeight: 1.5, color: "var(--text)" }}>{r.rule_text}</p>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* ELO Timeline */}
      {eloTimeline.length > 2 && (
        <section
          style={{
            background: "var(--surface)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: 24,
            marginBottom: 32,
          }}
        >
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>
            ELO Progression
          </h2>
          <div style={{ position: "relative", height: 200 }}>
            {/* Grid lines */}
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
                <span style={{ position: "absolute", left: -30, top: -8, fontSize: 10, color: "var(--text-dim)" }}>
                  {v}
                </span>
              </div>
            ))}
            {/* SVG line chart */}
            <svg
              viewBox={`0 0 ${eloTimeline.length * 20} 200`}
              style={{ width: "100%", height: "100%", position: "absolute" }}
              preserveAspectRatio="none"
            >
              {/* Attacker line */}
              <polyline
                points={eloTimeline
                  .map(
                    (ep, i) =>
                      `${i * 20 + 10},${200 - ((ep.attacker_rating - 1000) / 1000) * 200}`
                  )
                  .join(" ")}
                fill="none"
                stroke="var(--accent)"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />
              {/* Developer line */}
              <polyline
                points={eloTimeline
                  .map(
                    (ep, i) =>
                      `${i * 20 + 10},${200 - ((ep.developer_rating - 1000) / 1000) * 200}`
                  )
                  .join(" ")}
                fill="none"
                stroke="var(--accent-2)"
                strokeWidth="2"
                vectorEffect="non-scaling-stroke"
              />
            </svg>
          </div>
          <div style={{ display: "flex", gap: 24, justifyContent: "center", marginTop: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 16, height: 2, background: "var(--accent)" }} />
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Attacker</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 16, height: 2, background: "var(--accent-2)" }} />
              <span style={{ fontSize: 12, color: "var(--text-dim)" }}>Developer</span>
            </div>
          </div>
        </section>
      )}

      <footer style={{ textAlign: "center", padding: "24px 0", color: "var(--text-dim)", fontSize: 12 }}>
        CoEvolve — Adversarial Security Training Platform
      </footer>
    </main>
  );
}
