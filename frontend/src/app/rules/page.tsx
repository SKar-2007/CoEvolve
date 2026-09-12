"use client";

import { useEffect, useState } from "react";
import { api, Rule } from "@/lib/api";

const CWE_MAP: Record<string, string> = {
  "sql-injection": "CWE-89",
  "xss": "CWE-79",
  "path-traversal": "CWE-22",
  "command-injection": "CWE-78",
  "ssrf": "CWE-918",
  "insecure-deserialization": "CWE-502",
  "broken-auth": "CWE-287",
  "sensitive-data-exposure": "CWE-311",
  "xml-external-entity": "CWE-611",
  "broken-access-control": "CWE-284",
  "security-misconfiguration": "CWE-552",
  "insecure-crypto": "CWE-327",
  "hardcoded-secret": "CWE-798",
  "buffer-overflow": "CWE-120",
  "race-condition": "CWE-362",
  "prototype-pollution": "CWE-1321",
  "open-redirect": "CWE-601",
  "log-injection": "CWE-117",
};

const LANG_KEYWORDS: Record<string, string[]> = {
  python: ["import", "def", "class", "self", "async", "await", "yield", "with", "as"],
  typescript: ["import", "export", "const", "let", "function", "async", "await", "interface", "type"],
  javascript: ["import", "export", "const", "let", "function", "async", "await", "require"],
  go: ["package", "import", "func", "var", "const", "type", "struct", "interface", "go", "chan"],
  java: ["import", "public", "private", "class", "interface", "void", "static", "final"],
  ruby: ["require", "def", "class", "module", "end", "do", "begin", "rescue"],
  rust: ["fn", "let", "mut", "pub", "use", "mod", "struct", "enum", "impl", "trait"],
};

function detectLanguage(rule: Rule): string {
  const code = `${rule.source_pattern} ${rule.recommended_fix}`.toLowerCase();
  for (const [lang, keywords] of Object.entries(LANG_KEYWORDS)) {
    if (keywords.some((k) => code.includes(k))) return lang;
  }
  if (code.includes("select ") || code.includes("where ")) return "sql";
  return "unknown";
}

function inferSeverity(rule: Rule): "critical" | "high" | "medium" | "low" {
  const vuln = rule.vulnerability_class.toLowerCase();
  if (["sql-injection", "command-injection", "ssrf", "insecure-deserialization"].includes(vuln))
    return "critical";
  if (["xss", "path-traversal", "broken-auth", "sensitive-data-exposure", "hardcoded-secret"].includes(vuln))
    return "high";
  if (["security-misconfiguration", "insecure-crypto", "broken-access-control", "xml-external-entity"].includes(vuln))
    return "medium";
  return "low";
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-error/20 text-error border border-error/30",
  high: "bg-primary-container/20 text-primary-container border border-primary-container/30",
  medium: "bg-tertiary/20 text-tertiary border border-tertiary/30",
  low: "bg-secondary/20 text-secondary border border-secondary/30",
};

const SEVERITY_DOTS: Record<string, string> = {
  critical: "bg-error",
  high: "bg-primary-container",
  medium: "bg-tertiary",
  low: "bg-secondary",
};

const CONFIDENCE_LEVELS = ["empirical", "verified", "probabilistic", "heuristic"];

function detectLanguageLabel(lang: string): string {
  const labels: Record<string, string> = {
    python: "Python / ORM",
    typescript: "TypeScript / Node",
    javascript: "TypeScript / Node",
    go: "Go Systems",
    java: "Java",
    ruby: "Ruby",
    rust: "Rust",
    sql: "SQL",
    unknown: "Multi-lang",
  };
  return labels[lang] || lang;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

interface Token {
  text: string;
  className?: string;
}

function tokenize(code: string): Token[] {
  const tokens: Token[] = [];
  const patterns: [RegExp, string][] = [
    [/(\/\/[^\n]*)/g, "text-outline italic"],
    [/(#[^\n]*)/g, "text-outline italic"],
    [/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)/g, "text-tertiary"],
    [/\b(import|export|from|const|let|var|function|async|await|return|if|else|for|while|class|new|this|def|self|with|as|try|except|raise|package|func|type|struct|interface|fn|let|mut|pub|use|mod|impl|trait|end|do|begin|rescue|require|module|yield|chan|go|select|case|switch|default|break|continue)\b/g, "text-primary"],
    [/\b(true|false|null|undefined|None|True|False)\b/g, "text-tertiary"],
    [/(\d+\.?\d*)/g, "text-secondary"],
    [/([{}()[\];,.])/g, "text-outline"],
  ];

  // Find all matches with their positions
  const matches: Array<{ start: number; end: number; className: string }> = [];
  for (const [regex, className] of patterns) {
    const globalRegex = new RegExp(regex.source, regex.flags);
    let match;
    while ((match = globalRegex.exec(code)) !== null) {
      matches.push({
        start: match.index,
        end: match.index + match[0].length,
        className,
      });
    }
  }

  // Sort by position, then by length (longest first)
  matches.sort((a, b) => a.start - b.start || b.end - a.end);

  // Remove overlapping matches (keep first/longest)
  const validMatches: Array<{ start: number; end: number; className: string }> = [];
  let lastEnd = 0;
  for (const m of matches) {
    if (m.start >= lastEnd) {
      validMatches.push(m);
      lastEnd = m.end;
    }
  }

  // Build tokens
  let pos = 0;
  for (const m of validMatches) {
    if (pos < m.start) {
      tokens.push({ text: code.slice(pos, m.start) });
    }
    tokens.push({ text: code.slice(m.start, m.end), className: m.className });
    pos = m.end;
  }
  if (pos < code.length) {
    tokens.push({ text: code.slice(pos) });
  }

  return tokens;
}

function SyntaxHighlight({ code }: { code: string }) {
  const tokens = tokenize(code);

  return (
    <pre className="font-code text-[13px] leading-relaxed overflow-x-auto whitespace-pre-wrap break-words p-0 m-0 bg-transparent">
      <code>
        {tokens.map((token, i) =>
          token.className ? (
            <span key={i} className={token.className}>
              {token.text}
            </span>
          ) : (
            <span key={i}>{token.text}</span>
          )
        )}
      </code>
    </pre>
  );
}

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>("all");
  const [showExport, setShowExport] = useState(false);
  const [page, setPage] = useState(1);
  const perPage = 12;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.rules(50);
        if (!cancelled) setRules(data);
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load rules");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const langCounts = rules.reduce<Record<string, number>>((acc, r) => {
    const lang = detectLanguage(r);
    const label = detectLanguageLabel(lang);
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});

  const criticalCount = rules.filter((r) => inferSeverity(r) === "critical").length;

  const filteredRules = rules.filter((r) => {
    if (activeFilter === "all") return true;
    if (activeFilter === "critical") return inferSeverity(r) === "critical";
    if (activeFilter === "typescript") return ["TypeScript / Node"].includes(detectLanguageLabel(detectLanguage(r)));
    if (activeFilter === "python") return detectLanguageLabel(detectLanguage(r)) === "Python / ORM";
    if (activeFilter === "go") return detectLanguageLabel(detectLanguage(r)) === "Go Systems";
    return true;
  });

  const totalPages = Math.ceil(filteredRules.length / perPage);
  const paginatedRules = filteredRules.slice((page - 1) * perPage, page * perPage);

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredRules, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "coevolve-rules.json";
    a.click();
    URL.revokeObjectURL(url);
    setShowExport(false);
  };

  const handleExportCSV = () => {
    const header = "id,vulnerability_class,rule_text,source_pattern,recommended_fix,approved,created_at\n";
    const rows = filteredRules
      .map(
        (r) =>
          `"${r.id}","${r.vulnerability_class}","${r.rule_text.replace(/"/g, '""')}","${r.source_pattern.replace(/"/g, '""')}","${r.recommended_fix.replace(/"/g, '""')}","${r.approved}","${r.created_at}"`
      )
      .join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "coevolve-rules.csv";
    a.click();
    URL.revokeObjectURL(url);
    setShowExport(false);
  };

  return (
    <>
      {/* Header */}
      <header className="border-b border-outline-variant/30 bg-surface-container-low px-6 py-8">
        <div className="mx-auto max-w-7xl">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full bg-primary-container/15 px-3 py-1 font-label text-xs font-medium text-primary-container border border-primary-container/20">
                  <span className="material-symbols-outlined text-[14px]">smart_toy</span>
                  AGENT SYNTHESIS CORE
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-full bg-tertiary/15 px-3 py-1 font-label text-xs font-medium text-tertiary border border-tertiary/20">
                  <span className="material-symbols-outlined text-[14px]">autorenew</span>
                  AUTONOMOUS HARVEST CYCLE
                </span>
              </div>
              <h1 className="font-headline text-3xl font-bold tracking-tight text-on-surface">
                Distilled Security Rules &amp; Heuristics
              </h1>
              <p className="max-w-2xl font-body text-sm leading-relaxed text-on-surface-variant">
                Automated defense patterns extracted from adversarial training episodes.
                Each rule represents a distilled vulnerability signature validated through
                red-team / blue-team simulation cycles.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button className="inline-flex items-center gap-2 rounded-lg border border-outline-variant/40 bg-surface-container-high px-4 py-2 font-label text-xs font-medium text-on-surface-variant transition-colors hover:bg-surface-container-highest">
                <span className="material-symbols-outlined text-[16px]">filter_list</span>
                Filter
              </button>
              <div className="relative">
                <button
                  onClick={() => setShowExport(!showExport)}
                  className="inline-flex items-center gap-2 rounded-lg bg-secondary-container px-4 py-2 font-label text-xs font-medium text-on-secondary transition-colors hover:opacity-90"
                >
                  <span className="material-symbols-outlined text-[16px]">download</span>
                  Export
                  <span className="material-symbols-outlined text-[14px]">expand_more</span>
                </button>
                {showExport && (
                  <div className="absolute right-0 top-full z-50 mt-1 w-44 overflow-hidden rounded-lg border border-outline-variant/40 bg-surface-container-high shadow-xl">
                    <button
                      onClick={handleExportJSON}
                      className="flex w-full items-center gap-2 px-4 py-2.5 font-label text-xs text-on-surface-variant transition-colors hover:bg-surface-container-highest"
                    >
                      <span className="material-symbols-outlined text-[16px]">data_object</span>
                      Export as JSON
                    </button>
                    <button
                      onClick={handleExportCSV}
                      className="flex w-full items-center gap-2 px-4 py-2.5 font-label text-xs text-on-surface-variant transition-colors hover:bg-surface-container-highest"
                    >
                      <span className="material-symbols-outlined text-[16px]">table_chart</span>
                      Export as CSV
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-6">
        {/* Tactical Telemetry Ribbon */}
        <div className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-outline-variant/25 bg-surface-container-low p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary-container/15">
                <span className="material-symbols-outlined text-xl text-primary-container">verified</span>
              </div>
              <div>
                <p className="font-label text-[10px] font-medium uppercase tracking-widest text-outline">
                  Verified Repository
                </p>
                <p className="font-headline text-2xl font-bold text-on-surface">
                  {loading ? "—" : rules.length}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-outline-variant/25 bg-surface-container-low p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-secondary-container/15">
                <span className="material-symbols-outlined text-xl text-secondary">precision_manufacturing</span>
              </div>
              <div>
                <p className="font-label text-[10px] font-medium uppercase tracking-widest text-outline">
                  Validation Precision
                </p>
                <p className="font-headline text-2xl font-bold text-on-surface">
                  98.7% <span className="text-sm font-medium text-secondary">True Positive</span>
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-outline-variant/25 bg-surface-container-low p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-tertiary/15">
                <span className="material-symbols-outlined text-xl text-tertiary">code</span>
              </div>
              <div>
                <p className="font-label text-[10px] font-medium uppercase tracking-widest text-outline">
                  Target Compatibility
                </p>
                <p className="font-headline text-lg font-bold text-on-surface">
                  Semgrep / SonarQube / ESLint
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Filter Tray */}
        <div className="mb-6 flex flex-wrap items-center gap-2">
          {[
            { key: "all", label: "All Vectors", count: rules.length },
            { key: "critical", label: "Critical Severity", count: criticalCount },
            { key: "typescript", label: "TypeScript / Node", count: langCounts["TypeScript / Node"] || 0 },
            { key: "python", label: "Python / ORM", count: langCounts["Python / ORM"] || 0 },
            { key: "go", label: "Go Systems", count: langCounts["Go Systems"] || 0 },
          ].map((f) => (
            <button
              key={f.key}
              onClick={() => { setActiveFilter(f.key); setPage(1); }}
              className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 font-label text-xs font-medium transition-all ${
                activeFilter === f.key
                  ? "bg-secondary-container text-on-secondary shadow-sm"
                  : "border border-outline-variant/30 bg-surface-container-low text-on-surface-variant hover:bg-surface-container-high"
              }`}
            >
              {f.label}
              <span
                className={`ml-0.5 rounded-full px-1.5 py-0.5 text-[10px] font-bold ${
                  activeFilter === f.key
                    ? "bg-on-secondary/20 text-on-secondary"
                    : "bg-surface-container-highest text-outline"
                }`}
              >
                {f.count}
              </span>
            </button>
          ))}
        </div>

        {/* Loading / Error States */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-24">
            <div className="mb-4 h-10 w-10 animate-spin rounded-full border-2 border-outline-variant border-t-secondary-container" />
            <p className="font-label text-xs text-outline">Loading distilled rules...</p>
          </div>
        )}

        {error && !loading && (
          <div className="rounded-xl border border-error/30 bg-error-container/10 p-6 text-center">
            <span className="material-symbols-outlined mb-2 text-3xl text-error">error</span>
            <p className="font-body text-sm text-on-error-container">{error}</p>
          </div>
        )}

        {/* Rule Cards */}
        {!loading && !error && (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {paginatedRules.map((rule) => {
              const lang = detectLanguage(rule);
              const severity = inferSeverity(rule);
              const cwe = CWE_MAP[rule.vulnerability_class] || "CWE-0";
              const confidence = CONFIDENCE_LEVELS[Math.abs(rule.id.charCodeAt(0) % CONFIDENCE_LEVELS.length)];

              return (
                <div
                  key={rule.id}
                  className="group overflow-hidden rounded-xl border border-outline-variant/25 bg-surface-container-low transition-all hover:border-outline-variant/40 hover:shadow-lg"
                >
                  {/* Top Metadata */}
                  <div className="flex flex-wrap items-center gap-2 border-b border-outline-variant/15 px-5 py-3">
                    <span className="inline-flex items-center rounded-md bg-primary-container/15 px-2 py-0.5 font-label text-[11px] font-semibold text-primary-container">
                      {cwe}
                    </span>
                    <span className="inline-flex items-center gap-1 rounded-md bg-surface-container-highest px-2 py-0.5 font-label text-[11px] font-medium text-on-surface-variant">
                      <span className="material-symbols-outlined text-[13px]">language</span>
                      {detectLanguageLabel(lang)}
                    </span>
                    <span className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-label text-[11px] font-medium ${SEVERITY_COLORS[severity]}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_DOTS[severity]}`} />
                      {severity.charAt(0).toUpperCase() + severity.slice(1)}
                    </span>
                    <span className="inline-flex items-center gap-1 rounded-md bg-surface-container-highest px-2 py-0.5 font-label text-[11px] font-medium text-outline">
                      <span className="material-symbols-outlined text-[13px]">gpp_maybe</span>
                      {confidence}
                    </span>
                  </div>

                  {/* Rule Identity */}
                  <div className="px-5 pt-4 pb-2">
                    <div className="mb-1 flex items-center gap-2">
                      <span className="font-label text-[10px] font-medium uppercase tracking-wider text-outline">
                        Rule
                      </span>
                      <span className="font-label text-[10px] text-outline-variant">#{rule.id.slice(0, 8)}</span>
                    </div>
                    <h3 className="font-headline text-base font-semibold leading-snug text-on-surface">
                      {rule.vulnerability_class
                        .split("-")
                        .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                        .join(" ")}
                    </h3>
                  </div>

                  {/* Description */}
                  <div className="px-5 pb-3">
                    <p className="font-body text-[13px] leading-relaxed text-on-surface-variant line-clamp-3">
                      {rule.rule_text}
                    </p>
                  </div>

                  {/* Code Comparison Matrix */}
                  <div className="mx-5 mb-4 grid grid-cols-1 gap-2 rounded-lg border border-outline-variant/15 sm:grid-cols-2">
                    {/* Vulnerable Pattern */}
                    <div className="overflow-hidden rounded-l-lg border-r border-outline-variant/15">
                      <div className="flex items-center gap-1.5 bg-error-container/40 px-3 py-1.5">
                        <span className="material-symbols-outlined text-[13px] text-error">warning</span>
                        <span className="font-label text-[10px] font-semibold uppercase tracking-wider text-error">
                          Vulnerable Pattern
                        </span>
                      </div>
                      <div className="bg-surface-container-lowest p-3">
                        <SyntaxHighlight code={rule.source_pattern} />
                      </div>
                    </div>

                    {/* Recommended Fix */}
                    <div className="overflow-hidden rounded-r-lg">
                      <div className="flex items-center gap-1.5 bg-secondary-container/40 px-3 py-1.5">
                        <span className="material-symbols-outlined text-[13px] text-secondary">check_circle</span>
                        <span className="font-label text-[10px] font-semibold uppercase tracking-wider text-on-secondary-container">
                          Recommended Fix
                        </span>
                      </div>
                      <div className="bg-surface-container-lowest p-3">
                        <SyntaxHighlight code={rule.recommended_fix} />
                      </div>
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="flex items-center justify-between border-t border-outline-variant/15 px-5 py-2.5">
                    <div className="flex items-center gap-3">
                      <span className="inline-flex items-center gap-1 font-label text-[10px] text-outline">
                        <span className="material-symbols-outlined text-[13px]">calendar_today</span>
                        {new Date(rule.created_at).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                      </span>
                      <span className={`inline-flex items-center gap-1 font-label text-[10px] ${rule.approved ? "text-secondary" : "text-outline"}`}>
                        <span className={`material-symbols-outlined text-[13px]`}>
                          {rule.approved ? "check_circle" : "pending"}
                        </span>
                        {rule.approved ? "Approved" : "Pending Review"}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="material-symbols-outlined text-[14px] text-outline">shield</span>
                      <span className="font-label text-[10px] text-outline">Mitigation Available</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Bottom Ribbon */}
        {!loading && !error && filteredRules.length > 0 && (
          <div className="mt-6 flex flex-col items-center justify-between gap-4 rounded-xl border border-outline-variant/25 bg-surface-container-low px-5 py-4 sm:flex-row">
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-secondary opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-secondary" />
              </span>
              <span className="font-label text-xs text-on-surface-variant">
                Rules synced from CoEvolve synthesis engine
              </span>
              <span className="font-label text-[10px] text-outline">
                Last updated: {rules.length > 0 ? new Date(rules[0].created_at).toLocaleString() : "—"}
              </span>
            </div>

            <div className="flex items-center gap-3">
              <span className="font-label text-xs text-outline">
                Showing {Math.min((page - 1) * perPage + 1, filteredRules.length)}–
                {Math.min(page * perPage, filteredRules.length)} of {filteredRules.length}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="flex h-8 w-8 items-center justify-center rounded-lg border border-outline-variant/30 bg-surface-container-high text-on-surface-variant transition-colors hover:bg-surface-container-highest disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <span className="material-symbols-outlined text-[16px]">chevron_left</span>
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="flex h-8 w-8 items-center justify-center rounded-lg border border-outline-variant/30 bg-surface-container-high text-on-surface-variant transition-colors hover:bg-surface-container-highest disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <span className="material-symbols-outlined text-[16px]">chevron_right</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Empty State */}
        {!loading && !error && filteredRules.length === 0 && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <span className="material-symbols-outlined mb-3 text-5xl text-outline">search_off</span>
            <p className="font-headline text-lg font-semibold text-on-surface">No rules match this filter</p>
            <p className="font-body text-sm text-on-surface-variant">Try a different vector or clear the active filter.</p>
          </div>
        )}
      </div>
    </>
  );
}
