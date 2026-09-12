"use client";

import { useEffect, useState, useMemo } from "react";
import { api, type Episode } from "@/lib/api";

interface EpisodeDetail extends Episode {
  judge_verdict?: Record<string, unknown>;
  language?: string;
  elo_before?: { attacker: number; developer: number };
  elo_after?: { attacker: number; developer: number };
}

type VerdictFilter = "ALL" | "SECURE" | "VULNERABLE";

const CLASSES = [
  "SQL_INJECTION",
  "XSS",
  "CSRF",
  "PATH_TRAVERSAL",
  "COMMAND_INJECTION",
  "SSRF",
  "AUTH_BYPASS",
  "RACE_CONDITION",
] as const;

const TIERS = [
  { value: 1, label: "Tier 1 — Pattern Match" },
  { value: 2, label: "Tier 2 — Logic Bypass" },
  { value: 3, label: "Tier 3 — Multi-Stage" },
];

function isSecure(e: Episode): boolean {
  return e.outcome === 1;
}

function verdictBadge(e: Episode) {
  if (isSecure(e)) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-secondary/15 px-2.5 py-0.5 font-label-xs font-medium text-secondary">
        <span className="material-symbols-outlined text-sm">verified</span>
        SECURE
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-primary-container/15 px-2.5 py-0.5 font-label-xs font-medium text-primary-container">
      <span className="material-symbols-outlined text-sm">warning</span>
      VULNERABLE
    </span>
  );
}

function formatDuration(s: number | null | undefined): string {
  if (s == null) return "—";
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function CodeBlock({ code, label }: { code: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative rounded-lg bg-surface-container-lowest border border-outline-variant/30">
      {label && (
        <div className="flex items-center gap-2 border-b border-outline-variant/30 px-4 py-2">
          <span className="material-symbols-outlined text-sm text-tertiary">
            code
          </span>
          <span className="font-label-xs text-tertiary">{label}</span>
        </div>
      )}
      <div className="relative">
        <pre className="overflow-x-auto p-4 text-sm font-label text-on-surface-variant">
          <code>{code}</code>
        </pre>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
          className="absolute right-3 top-3 flex items-center gap-1 rounded-md bg-surface-container-high px-2 py-1 text-xs font-label text-tertiary transition-colors hover:text-on-surface"
        >
          <span className="material-symbols-outlined text-sm">
            {copied ? "check" : "content_copy"}
          </span>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

function TabBar({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: string; label: string; icon: string }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-outline-variant/30">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => onChange(t.id)}
          className={`flex items-center gap-1.5 whitespace-nowrap px-3 py-2 text-xs font-label transition-colors ${
            active === t.id
              ? "border-b-2 border-primary text-primary"
              : "text-tertiary hover:text-on-surface-variant"
          }`}
        >
          <span className="material-symbols-outlined text-sm">{t.icon}</span>
          {t.label}
        </button>
      ))}
    </div>
  );
}

const TABS = [
  { id: "attacker", label: "Attacker Vector", icon: "bug_report" },
  { id: "patch", label: "Dev Patch", icon: "build" },
  { id: "sast", label: "SAST Static", icon: "scan" },
  { id: "dast", label: "DAST Sandbox", icon: "science" },
  { id: "judge", label: "Judge Verdict", icon: "gavel" },
];

function EpisodeCard({ ep }: { ep: EpisodeDetail }) {
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState("attacker");

  const verdict = ep.judge_verdict ?? {};
  const sast = (verdict as Record<string, unknown>).sast as
    | { findings?: string[] }
    | undefined;
  const dast = (verdict as Record<string, unknown>).dast as
    | { exploit_result?: string }
    | undefined;

  return (
    <article className="rounded-xl bg-surface-container-low border border-outline-variant/20 transition-colors hover:border-outline-variant/40">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-4 p-4 text-left"
      >
        <div className="flex flex-1 flex-wrap items-center gap-2">
          {verdictBadge(ep)}
          <span className="rounded-md bg-surface-container-high px-2 py-0.5 font-label-xs text-on-surface-variant">
            {ep.vulnerability_class ?? "UNKNOWN"}
          </span>
          <span className="rounded-md bg-surface-container-high px-2 py-0.5 font-label-xs text-tertiary">
            Tier {ep.difficulty_tier ?? "?"}
          </span>
          {ep.language && (
            <span className="rounded-md bg-surface-container-high px-2 py-0.5 font-label-xs text-tertiary">
              {ep.language}
            </span>
          )}
          <span className="ml-auto font-label-xs text-tertiary">
            {ep.episode_id.slice(0, 12)}
          </span>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="font-label-xs text-tertiary">ELO Δ</div>
            <div className="flex gap-2 font-label-xs">
              <span className="text-primary-container">
                {ep.elo_before && ep.elo_after
                  ? `${(ep.elo_after.attacker - ep.elo_before.attacker) >= 0 ? "+" : ""}${(ep.elo_after.attacker - ep.elo_before.attacker).toFixed(1)}`
                  : "—"}
              </span>
              <span className="text-secondary">
                {ep.elo_before && ep.elo_after
                  ? `${(ep.elo_after.developer - ep.elo_before.developer) >= 0 ? "+" : ""}${(ep.elo_after.developer - ep.elo_before.developer).toFixed(1)}`
                  : "—"}
              </span>
            </div>
          </div>
          <span
            className={`material-symbols-outlined text-xl text-tertiary transition-transform ${expanded ? "rotate-180" : ""}`}
          >
            expand_more
          </span>
        </div>
      </button>

      {ep.task_description && (
        <div className="flex items-start gap-2 px-4 pb-3">
          <span className="material-symbols-outlined mt-0.5 text-sm text-tertiary">
            description
          </span>
          <p className="line-clamp-2 text-sm font-body text-on-surface-variant">
            {ep.task_description}
          </p>
        </div>
      )}

      {expanded && (
        <div className="border-t border-outline-variant/20">
          <div className="flex gap-0 lg:flex-row">
            <div className="min-w-0 flex-1">
              <TabBar
                tabs={TABS}
                active={activeTab}
                onChange={setActiveTab}
              />
              <div className="p-4">
                {activeTab === "attacker" && (
                  <div className="space-y-4">
                    <div>
                      <h4 className="mb-1 font-label-xs text-tertiary">
                        TASK DESCRIPTION
                      </h4>
                      <p className="text-sm font-body text-on-surface">
                        {ep.task_description ?? "No task description available."}
                      </p>
                    </div>
                    <div>
                      <h4 className="mb-1 font-label-xs text-tertiary">
                        EXPLOIT PAYLOAD
                      </h4>
                      <p className="text-sm font-body text-on-surface-variant">
                        {ep.error
                          ? `Error: ${ep.error}`
                          : "See patch tab for the fix that was applied."}
                      </p>
                    </div>
                  </div>
                )}

                {activeTab === "patch" && (
                  <div className="space-y-3">
                    {ep.patch_text ? (
                      <CodeBlock code={ep.patch_text} label="Developer Patch" />
                    ) : (
                      <p className="text-sm font-body text-tertiary italic">
                        No patch text available for this episode.
                      </p>
                    )}
                  </div>
                )}

                {activeTab === "sast" && (
                  <div className="space-y-3">
                    {sast?.findings && sast.findings.length > 0 ? (
                      <ul className="space-y-2">
                        {sast.findings.map((f, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 rounded-lg bg-surface-container-lowest p-3"
                          >
                            <span className="material-symbols-outlined mt-0.5 text-sm text-primary-container">
                              error
                            </span>
                            <span className="text-sm font-body text-on-surface-variant">
                              {f}
                            </span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm font-body text-tertiary italic">
                        No SAST findings recorded for this episode.
                      </p>
                    )}
                  </div>
                )}

                {activeTab === "dast" && (
                  <div className="space-y-3">
                    {dast?.exploit_result ? (
                      <div className="rounded-lg bg-surface-container-lowest p-3">
                        <div className="mb-1 flex items-center gap-1.5">
                          <span className="material-symbols-outlined text-sm text-secondary">
                            science
                          </span>
                          <span className="font-label-xs text-secondary">
                            Sandbox Result
                          </span>
                        </div>
                        <p className="whitespace-pre-wrap text-sm font-body text-on-surface-variant">
                          {dast.exploit_result}
                        </p>
                      </div>
                    ) : (
                      <p className="text-sm font-body text-tertiary italic">
                        No DAST sandbox results for this episode.
                      </p>
                    )}
                  </div>
                )}

                {activeTab === "judge" && (
                  <div className="space-y-3">
                    <div className="rounded-lg bg-surface-container-lowest p-3">
                      <h4 className="mb-1 font-label-xs text-tertiary">
                        FINAL OUTCOME
                      </h4>
                      <p className="text-sm font-body text-on-surface">
                        {isSecure(ep)
                          ? "The developer's patch successfully mitigated the vulnerability. The attacker's exploit did not succeed against the patched code."
                          : "The developer's patch was insufficient. The attacker's exploit succeeded, indicating the vulnerability remains exploitable."}
                      </p>
                    </div>
                    <div className="flex gap-4">
                      <div className="flex-1 rounded-lg bg-surface-container-lowest p-3 text-center">
                        <div className="font-label-xs text-tertiary">
                          Attacker Rating
                        </div>
                        <div className="mt-1 font-headline-sm text-primary-container">
                          {ep.attacker_rating.toFixed(1)}
                        </div>
                      </div>
                      <div className="flex-1 rounded-lg bg-surface-container-lowest p-3 text-center">
                        <div className="font-label-xs text-tertiary">
                          Developer Rating
                        </div>
                        <div className="mt-1 font-headline-sm text-secondary">
                          {ep.developer_rating.toFixed(1)}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <aside className="hidden w-64 flex-shrink-0 border-l border-outline-variant/20 p-4 lg:block">
              <h4 className="mb-3 font-label-xs text-tertiary">
                SANDBOX EXECUTION
              </h4>
              <div className="space-y-2">
                <div className="flex items-center gap-2 rounded-lg bg-surface-container-lowest p-2.5">
                  <span className="material-symbols-outlined text-sm text-tertiary">
                    dns
                  </span>
                  <div>
                    <div className="font-label-xs text-tertiary">Container</div>
                    <div className="font-label-xs text-on-surface-variant">
                      Ubuntu 22.04
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-surface-container-lowest p-2.5">
                  <span className="material-symbols-outlined text-sm text-tertiary">
                    memory
                  </span>
                  <div>
                    <div className="font-label-xs text-tertiary">Memory</div>
                    <div className="font-label-xs text-on-surface-variant">
                      512 MB
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-surface-container-lowest p-2.5">
                  <span className="material-symbols-outlined text-sm text-tertiary">
                    timer
                  </span>
                  <div>
                    <div className="font-label-xs text-tertiary">Timeout</div>
                    <div className="font-label-xs text-on-surface-variant">
                      30s
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-surface-container-lowest p-2.5">
                  <span className="material-symbols-outlined text-sm text-tertiary">
                    wifi_off
                  </span>
                  <div>
                    <div className="font-label-xs text-tertiary">Network</div>
                    <div className="font-label-xs text-on-surface-variant">
                      Isolated
                    </div>
                  </div>
                </div>
              </div>

              <h4 className="mb-3 mt-5 font-label-xs text-tertiary">
                AST VERIFICATION
              </h4>
              <div className="rounded-lg bg-surface-container-lowest p-3">
                <div className="flex items-end gap-1" style={{ height: 48 }}>
                  {[60, 45, 80, 55, 90, 40, 70, 65, 50, 75, 85, 35].map(
                    (h, i) => (
                      <div
                        key={i}
                        className="flex-1 rounded-t-sm bg-secondary/30"
                        style={{ height: `${h}%` }}
                      />
                    ),
                  )}
                </div>
                <p className="mt-2 text-center font-label-xs text-tertiary">
                  AST parse depth
                </p>
              </div>
            </aside>
          </div>
        </div>
      )}
    </article>
  );
}

const ITEMS_PER_PAGE = 10;

export default function EpisodesPage() {
  const [episodes, setEpisodes] = useState<EpisodeDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("ALL");
  const [classFilter, setClassFilter] = useState<string>("ALL");
  const [tierFilter, setTierFilter] = useState<string>("ALL");
  const [page, setPage] = useState(1);

  useEffect(() => {
    api
      .episodes(50)
      .then((data) => setEpisodes(data as EpisodeDetail[]))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    return episodes.filter((ep) => {
      if (verdictFilter === "SECURE" && !isSecure(ep)) return false;
      if (verdictFilter === "VULNERABLE" && isSecure(ep)) return false;
      if (classFilter !== "ALL" && ep.vulnerability_class !== classFilter)
        return false;
      if (tierFilter !== "ALL" && String(ep.difficulty_tier) !== tierFilter)
        return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          ep.episode_id.toLowerCase().includes(q) ||
          (ep.task_description?.toLowerCase().includes(q) ?? false) ||
          (ep.vulnerability_class?.toLowerCase().includes(q) ?? false)
        );
      }
      return true;
    });
  }, [episodes, verdictFilter, classFilter, tierFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / ITEMS_PER_PAGE));
  const paged = filtered.slice(
    (page - 1) * ITEMS_PER_PAGE,
    page * ITEMS_PER_PAGE,
  );

  const secureCount = episodes.filter(isSecure).length;
  const mitigationRate =
    episodes.length > 0
      ? ((secureCount / episodes.length) * 100).toFixed(1)
      : "0";

  return (
    <>
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <header className="mb-8">
          <h1 className="font-headline-lg text-on-surface">
            Training Episodes Archive
          </h1>
          <p className="mt-1 max-w-2xl text-sm font-body text-tertiary">
            Review completed training episodes: attacker exploits, developer
            patches, static/dynamic analysis results, and judge verdicts.
          </p>
          <div className="mt-4 flex gap-6">
            <div className="rounded-lg bg-surface-container-low p-3">
              <div className="font-label-xs text-tertiary">Total Duels</div>
              <div className="mt-0.5 font-headline-sm text-on-surface">
                {episodes.length}
              </div>
            </div>
            <div className="rounded-lg bg-surface-container-low p-3">
              <div className="font-label-xs text-tertiary">Mitigation Rate</div>
              <div className="mt-0.5 font-headline-sm text-secondary">
                {mitigationRate}%
              </div>
            </div>
            <div className="rounded-lg bg-surface-container-low p-3">
              <div className="font-label-xs text-tertiary">Secure</div>
              <div className="mt-0.5 font-headline-sm text-secondary">
                {secureCount}
              </div>
            </div>
            <div className="rounded-lg bg-surface-container-low p-3">
              <div className="font-label-xs text-tertiary">Vulnerable</div>
              <div className="mt-0.5 font-headline-sm text-primary-container">
                {episodes.length - secureCount}
              </div>
            </div>
          </div>
        </header>

        {/* Filter Bar */}
        <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <span className="material-symbols-outlined pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-tertiary">
              search
            </span>
            <input
              type="text"
              placeholder="Search episodes, classes, descriptions..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg bg-surface-container-low py-2 pl-10 pr-3 text-sm font-body text-on-surface placeholder-tertiary outline-none ring-1 ring-outline-variant/30 transition-shadow focus:ring-primary/50"
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <div className="flex rounded-lg bg-surface-container-low p-0.5 ring-1 ring-outline-variant/30">
              {(["ALL", "SECURE", "VULNERABLE"] as VerdictFilter[]).map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => {
                    setVerdictFilter(v);
                    setPage(1);
                  }}
                  className={`rounded-md px-3 py-1 text-xs font-label transition-colors ${
                    verdictFilter === v
                      ? v === "SECURE"
                        ? "bg-secondary/20 text-secondary"
                        : v === "VULNERABLE"
                          ? "bg-primary-container/20 text-primary-container"
                          : "bg-surface-container-high text-on-surface"
                      : "text-tertiary hover:text-on-surface-variant"
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>

            <select
              value={classFilter}
              onChange={(e) => {
                setClassFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-lg bg-surface-container-low px-3 py-1.5 text-xs font-label text-on-surface-variant ring-1 ring-outline-variant/30 outline-none focus:ring-primary/50"
            >
              <option value="ALL">All Classes</option>
              {CLASSES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>

            <select
              value={tierFilter}
              onChange={(e) => {
                setTierFilter(e.target.value);
                setPage(1);
              }}
              className="rounded-lg bg-surface-container-low px-3 py-1.5 text-xs font-label text-on-surface-variant ring-1 ring-outline-variant/30 outline-none focus:ring-primary/50"
            >
              <option value="ALL">All Tiers</option>
              {TIERS.map((t) => (
                <option key={t.value} value={String(t.value)}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Loading / Error */}
        {loading && (
          <div className="flex items-center justify-center gap-2 py-20 text-tertiary">
            <span className="material-symbols-outlined animate-spin text-xl">
              progress_activity
            </span>
            <span className="text-sm font-label">Loading episodes...</span>
          </div>
        )}

        {error && (
          <div className="rounded-lg bg-error-container/10 p-4 text-sm font-body text-error">
            <span className="material-symbols-outlined mr-1 text-sm align-middle">
              error
            </span>
            {error}
          </div>
        )}

        {/* Episode Cards */}
        {!loading && !error && (
          <div className="space-y-3">
            {paged.length === 0 && (
              <div className="py-20 text-center text-sm font-body text-tertiary">
                No episodes match your filters.
              </div>
            )}
            {paged.map((ep) => (
              <EpisodeCard key={ep.episode_id} ep={ep} />
            ))}
          </div>
        )}

        {/* Pagination */}
        {!loading && filtered.length > ITEMS_PER_PAGE && (
          <div className="mt-6 flex items-center justify-between">
            <span className="text-xs font-label text-tertiary">
              Showing {(page - 1) * ITEMS_PER_PAGE + 1}–
              {Math.min(page * ITEMS_PER_PAGE, filtered.length)} of{" "}
              {filtered.length}
            </span>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="flex items-center gap-1 rounded-lg bg-surface-container-low px-3 py-1.5 text-xs font-label text-on-surface-variant transition-colors hover:bg-surface-container-high disabled:opacity-40"
              >
                <span className="material-symbols-outlined text-sm">
                  chevron_left
                </span>
                Prev
              </button>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                className="flex items-center gap-1 rounded-lg bg-surface-container-low px-3 py-1.5 text-xs font-label text-on-surface-variant transition-colors hover:bg-surface-container-high disabled:opacity-40"
              >
                Next
                <span className="material-symbols-outlined text-sm">
                  chevron_right
                </span>
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
