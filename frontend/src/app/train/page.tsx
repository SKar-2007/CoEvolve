"use client";

import { useState } from "react";
import { api, SSEEvent } from "@/lib/api";

const VULNS = ["SQLi", "XSS", "PathTraversal", "CommandInjection", "SSRF", "Deserialization", "SSTI", "XXE", "OpenRedirect", "PrototypePollution"];
const LANGS = ["python", "javascript", "java"];

interface Step {
  agent: string;
  status: string;
  message: string;
}

export default function TrainPage() {
  const [vuln, setVuln] = useState("SQLi");
  const [lang, setLang] = useState("python");
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<Step[]>([]);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startTraining = () => {
    setRunning(true);
    setSteps([]);
    setResult(null);
    setError(null);

    api.streamTraining(
      vuln,
      lang,
      (evt: SSEEvent) => {
        if (evt.type === "agent" && evt.agent && evt.status && evt.message) {
          setSteps((prev) => [
            ...prev.filter((s) => s.agent !== evt.agent),
            { agent: evt.agent!, status: evt.status!, message: evt.message! },
          ]);
        }
        if (evt.type === "complete") {
          const outcome = evt.outcome === 1 ? "VULNERABLE" : "SECURE";
          const color = evt.outcome === 1 ? "text-brand-red" : "text-brand-green";
          setResult(
            `Episode ${evt.episode_id} — ${outcome}` +
            (evt.rule_distilled ? " — Rule distilled" : "") +
            ` (${evt.duration_s?.toFixed(1)}s)`
          );
        }
        if (evt.type === "error") {
          setError(evt.message || "Unknown error");
        }
      },
      () => setRunning(false),
      (msg) => {
        setError(msg);
        setRunning(false);
      }
    );
  };

  const agentColor: Record<string, string> = {
    attacker: "text-brand-red",
    developer: "text-brand-yellow",
    judge: "text-brand-blue",
    distiller: "text-brand-green",
  };

  const statusIcon: Record<string, string> = {
    done: "●",
    working: "◎",
    skip: "○",
  };

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold mb-6">Run Training</h1>

      <div className="bg-[--surface] rounded-lg border border-[--border] p-6 mb-6">
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="text-xs text-[--muted] block mb-1">Vulnerability Class</label>
            <select
              value={vuln}
              onChange={(e) => setVuln(e.target.value)}
              disabled={running}
              className="w-full bg-[--bg] border border-[--border] rounded px-3 py-2 text-sm"
            >
              {VULNS.map((v) => (
                <option key={v} value={v}>{v}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-[--muted] block mb-1">Language</label>
            <select
              value={lang}
              onChange={(e) => setLang(e.target.value)}
              disabled={running}
              className="w-full bg-[--bg] border border-[--border] rounded px-3 py-2 text-sm"
            >
              {LANGS.map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={startTraining}
          disabled={running}
          className="w-full bg-brand-blue text-white font-semibold py-2.5 rounded hover:opacity-90 disabled:opacity-40 transition"
        >
          {running ? "Running..." : "Start Training"}
        </button>
      </div>

      {steps.length > 0 && (
        <div className="bg-[--surface] rounded-lg border border-[--border] p-6 mb-6">
          <h2 className="text-sm font-semibold text-[--muted] mb-4">AGENT PROGRESS</h2>
          <div className="space-y-2">
            {steps.map((s, i) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className={agentColor[s.agent] || "text-[--muted]"}>
                  {statusIcon[s.status] || "·"}
                </span>
                <span className={`font-semibold w-24 ${agentColor[s.agent] || ""}`}>
                  {s.agent}
                </span>
                <span className="text-[--text]">{s.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {result && (
        <div className="bg-[--surface] rounded-lg border border-brand-green p-4 text-brand-green font-semibold">
          {result}
        </div>
      )}

      {error && (
        <div className="bg-[--surface] rounded-lg border border-brand-red p-4 text-brand-red">
          {error}
        </div>
      )}
    </div>
  );
}
