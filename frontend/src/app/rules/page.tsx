"use client";

import { useEffect, useState } from "react";
import { api, Rule } from "@/lib/api";

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.rules(50).then(setRules).catch(() => {}).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="text-[--muted] p-8">Loading...</div>;

  return (
    <div className="max-w-4xl">
      <h1 className="text-2xl font-bold mb-6">Security Rules</h1>

      {rules.length === 0 ? (
        <div className="text-[--muted]">No rules distilled yet. Run training to generate rules.</div>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => (
            <div key={rule.id} className="bg-[--surface] rounded-lg border border-[--border] p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-brand-red text-xs font-bold">{rule.vulnerability_class}</span>
                {rule.approved && (
                  <span className="text-xs bg-brand-green/20 text-brand-green px-2 py-0.5 rounded">approved</span>
                )}
              </div>
              <p className="text-sm mb-2">{rule.rule_text}</p>
              {rule.source_pattern && (
                <p className="text-xs text-[--muted]">Pattern: {rule.source_pattern}</p>
              )}
              {rule.recommended_fix && (
                <p className="text-xs text-brand-green mt-1">Fix: {rule.recommended_fix}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
