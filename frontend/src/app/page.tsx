const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function fetchAPI<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

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
  attacker_rating: number;
  developer_rating: number;
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
    <span style={{ background: color, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>
      {label}
    </span>
  );
}

export default async function Home() {
  let metrics: Metrics | null = null;
  let episodes: Episode[] = [];
  let rules: Rule[] = [];
  let error = false;

  try {
    [metrics, episodes, rules] = await Promise.all([
      fetchAPI<Metrics>("/metrics"),
      fetchAPI<Episode[]>("/episodes?limit=10"),
      fetchAPI<Rule[]>("/rules?limit=5"),
    ]);
  } catch {
    error = true;
  }

  return (
    <main style={{ maxWidth: 1100, margin: "0 auto", padding: "40px 24px" }}>
      <header style={{ marginBottom: 40 }}>
        <h1 style={{ fontSize: 32, fontWeight: 700 }}>
          <span style={{ color: "var(--accent)" }}>Co</span>Evolve
        </h1>
        <p style={{ color: "var(--text-dim)", marginTop: 4 }}>Adversarial Security Training Platform</p>
      </header>

      {error && (
        <div style={{ background: "#ff545120", border: "1px solid var(--accent)", padding: 16, borderRadius: 8, marginBottom: 32 }}>
          <p style={{ color: "var(--accent)" }}>Backend unreachable. Start the API on port 8000.</p>
        </div>
      )}

      {/* Stats */}
      {metrics && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 40 }}>
          {[
            { label: "Episodes", value: metrics.total_episodes },
            { label: "Secure Rate", value: `${(metrics.secure_rate * 100).toFixed(0)}%` },
            { label: "Rules", value: metrics.rules_count },
            { label: "Attacker ELO", value: Math.round(metrics.epo.attacker) },
          ].map((s) => (
            <div key={s.label} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 20 }}>
              <div style={{ color: "var(--text-dim)", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>{s.label}</div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* ELO */}
      {metrics && (
        <section style={{ marginBottom: 40 }}>
          <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>ELO Ratings</h2>
          <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span>Attacker</span>
              <span style={{ fontWeight: 700, color: "var(--accent)" }}>{Math.round(metrics.epo.attacker)}</span>
            </div>
            <div style={{ height: 8, background: "var(--surface-2)", borderRadius: 4, overflow: "hidden", marginBottom: 16 }}>
              <div style={{ height: "100%", width: `${(metrics.epo.attacker / 2000) * 100}%`, background: "var(--accent)", borderRadius: 4 }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <span>Developer</span>
              <span style={{ fontWeight: 700, color: "var(--accent-2)" }}>{Math.round(metrics.epo.developer)}</span>
            </div>
            <div style={{ height: 8, background: "var(--surface-2)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${(metrics.epo.developer / 2000) * 100}%`, background: "var(--accent-2)", borderRadius: 4 }} />
            </div>
          </div>
        </section>
      )}

      {/* Episodes */}
      <section style={{ marginBottom: 40 }}>
        <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Recent Episodes</h2>
        {episodes.length === 0 ? (
          <p style={{ color: "var(--text-dim)" }}>No episodes yet.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {episodes.map((ep) => (
              <div key={ep.episode_id} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 16, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <span style={{ fontWeight: 600 }}>{ep.vulnerability_class || "—"}</span>
                  <span style={{ color: "var(--text-dim)", marginLeft: 12, fontSize: 13 }}>{ep.episode_id.slice(0, 8)}</span>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                    {new Date(ep.created_at).toLocaleDateString()}
                  </span>
                  {ep.outcome === 0 ? (
                    <Badge label="SECURE" color="#4caf5030" />
                  ) : ep.outcome === 1 ? (
                    <Badge label="VULN" color="#ff545130" />
                  ) : (
                    <Badge label="PENDING" color="#8888a030" />
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Rules */}
      <section>
        <h2 style={{ fontSize: 14, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>Distilled Rules</h2>
        {rules.length === 0 ? (
          <p style={{ color: "var(--text-dim)" }}>No rules distilled yet.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {rules.map((r) => (
              <div key={r.id} style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, padding: 16 }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <Badge label={r.vulnerability_class} color="var(--accent)20" />
                  {r.approved && <Badge label="APPROVED" color="#4caf5030" />}
                </div>
                <p style={{ fontSize: 14, lineHeight: 1.5 }}>{r.rule_text}</p>
                {r.source_pattern && (
                  <pre style={{ marginTop: 8, padding: 12, background: "var(--surface-2)", borderRadius: 4, fontSize: 12, overflow: "auto" }}>
                    {r.source_pattern}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}
