const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://coevolve.onrender.com";

export interface Episode {
  episode_id: string;
  status: string;
  vulnerability_class: string | null;
  difficulty_tier: number | null;
  outcome: number | null;
  task_description: string | null;
  patch_text: string | null;
  error: string | null;
  attacker_rating: number;
  developer_rating: number;
  prompt_version: number;
  created_at: string;
}

export interface Rule {
  id: string;
  rule_text: string;
  vulnerability_class: string;
  source_pattern: string;
  recommended_fix: string;
  approved: boolean;
  created_at: string;
}

export interface Metrics {
  total_episodes: number;
  secure_rate: number;
  epo: { attacker: number; developer: number };
  rules_count: number;
}

export interface SSEEvent {
  type: "start" | "agent" | "elo" | "complete" | "error";
  agent?: string;
  status?: string;
  message?: string;
  before?: Record<string, number>;
  after?: Record<string, number>;
  episode_id?: string;
  outcome?: number;
  rule_distilled?: boolean;
  duration_s?: number;
  vuln?: string;
  lang?: string;
  elo?: number[];
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Backend ${res.status}: ${body}`);
  }
  return res.json();
}

export const api = {
  health: () => apiFetch<{ status: string }>("/health"),
  metrics: () => apiFetch<Metrics>("/metrics"),
  episodes: (limit = 50) => apiFetch<Episode[]>(`/episodes?limit=${limit}`),
  episode: (id: string) => apiFetch<Episode>(`/episodes/${id}`),
  rules: (limit = 50) => apiFetch<Rule[]>(`/rules?limit=${limit}`),
  elo: () => apiFetch<{ attacker: number; developer: number }>("/elo"),
  runTraining: (req: { vulnerability_class?: string; language?: string }) =>
    apiFetch<{ episode_id: string; status: string; difficulty_tier: number; judge_outcome: number; judge_verdict: Record<string, unknown>; rule_distilled: boolean; rule_text: string | null; regression_passed: boolean; elo_before: Record<string, number>; elo_after: Record<string, number>; duration_s: number; error: string | null }>("/training/run", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  streamTraining: (
    vuln: string,
    lang: string,
    onEvent: (evt: SSEEvent) => void,
    onDone: () => void,
    onError: (err: string) => void
  ) => {
    const url = `${API_BASE}/training/stream?vulnerability_class=${encodeURIComponent(vuln)}&language=${encodeURIComponent(lang)}`;
    const es = new EventSource(url);
    const timeout = setTimeout(() => { es.close(); onError("Timed out"); }, 10000);
    es.onopen = () => clearTimeout(timeout);
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as SSEEvent;
        onEvent(data);
        if (data.type === "complete" || data.type === "error") { es.close(); clearTimeout(timeout); onDone(); }
      } catch {}
    };
    es.onerror = () => { es.close(); clearTimeout(timeout); onError("Cannot connect to backend"); };
    return () => { es.close(); clearTimeout(timeout); };
  },
  checkConnection: async (): Promise<{ ok: boolean; url: string }> => {
    try { await apiFetch("/health"); return { ok: true, url: API_BASE }; }
    catch { return { ok: false, url: API_BASE }; }
  },
};
