import sys, os, json, time
sys.path.insert(0, ".")
from dotenv import load_dotenv
load_dotenv(override=True)
os.environ.setdefault("SECRET_KEY", "test-secret")

from packages.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app, raise_server_exceptions=False)

print("=" * 65)
print("END-TO-END TRAINING RUN  -  Real LLM, Real DB")
print("=" * 65)
print()
print("Pipeline: Attacker generates exploit task")
print("       -> Developer writes code fix")
print("       -> Judge evaluates (SAST + DAST)")
print("       -> Rules distilled -> Elo updated")
print()
print("POST /training/run  (SQLi, python, login endpoint context)")
print("Running...")
print()

t0 = time.time()
r = client.post("/training/run", json={
    "vulnerability_class": "SQLi",
    "language": "python",
    "context_hint": "login endpoint using SQLite",
    "max_retries": 1,
    "use_react": False,
})
elapsed = time.time() - t0

print(f"HTTP Status : {r.status_code}")
print(f"Wall time   : {elapsed:.1f}s")
print()

if r.status_code == 200:
    d = r.json()
    outcome_label = {1: "SECURE (developer won)", 0: "VULNERABLE (attacker won)"}.get(d.get("judge_outcome"), "unknown")
    print(f"episode_id       : {d.get('episode_id')}")
    print(f"status           : {d.get('status')}")
    print(f"difficulty_tier  : {d.get('difficulty_tier')}")
    print(f"judge_outcome    : {d.get('judge_outcome')}  ->  {outcome_label}")
    print(f"rule_distilled   : {d.get('rule_distilled')}")
    if d.get("rule_text"):
        print(f"rule_text        : {d['rule_text'][:120]}")
    print(f"elo_before       : {d.get('elo_before')}")
    print(f"elo_after        : {d.get('elo_after')}")
    delta_atk = round((d.get("elo_after") or {}).get("attacker", 0) - (d.get("elo_before") or {}).get("attacker", 0), 2)
    delta_dev = round((d.get("elo_after") or {}).get("developer", 0) - (d.get("elo_before") or {}).get("developer", 0), 2)
    print(f"elo_delta        : attacker {delta_atk:+.1f}  developer {delta_dev:+.1f}")
    print(f"regression_pass  : {d.get('regression_passed')}")
    print(f"duration_s       : {d.get('duration_s', elapsed):.1f}s")
    verdict = d.get("judge_verdict") or {}
    if verdict:
        print()
        print("Judge verdict:")
        print(json.dumps(verdict, indent=4)[:600])
    if d.get("error"):
        print()
        print(f"error: {d['error']}")
else:
    print("Error response:")
    try:
        print(json.dumps(r.json(), indent=4))
    except Exception:
        print(r.text[:800])

print()
print("=" * 65)
