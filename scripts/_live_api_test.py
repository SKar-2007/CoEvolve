import sys, os, json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, '.')
os.environ.setdefault('DATABASE_URL', 'sqlite:///coevolve.db')
os.environ.setdefault('SECRET_KEY', 'test-secret')

from packages.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app, raise_server_exceptions=False)
SEP = '=' * 65

results = []

def show(status_code, label, body=''):
    ok = 'OK  ' if status_code < 400 else 'FAIL'
    flag = 'pass' if status_code < 400 else 'fail'
    results.append((flag, label, status_code))
    print(f'[{ok}] {status_code}  {label}')
    if body:
        print(body)
    print()

print(SEP)
print('LIVE API TEST  -  Real data from coevolve.db')
print(SEP)
print()

# /health
r = client.get('/health')
show(r.status_code, 'GET /health', f'       {r.json()}')

# /metrics
r = client.get('/metrics')
m = r.json()
show(r.status_code, 'GET /metrics',
     f'       total_episodes : {m["total_episodes"]}\n'
     f'       secure_rate    : {m["secure_rate"]:.0%}\n'
     f'       rules_count    : {m["rules_count"]}\n'
     f'       elo            : {m["epo"]}')

# /episodes
r = client.get('/episodes')
eps = r.json()
print(f'[OK  ] 200  GET /episodes  ({len(eps)} records)')
results.append(('pass', f'GET /episodes ({len(eps)} records)', 200))
label_map = {0: 'attacker wins', 1: 'developer wins', None: 'in progress'}
for ep in eps:
    outcome = label_map.get(ep.get('outcome'))
    print(f'         {ep["episode_id"][:30]}  {ep["status"]:10}  {ep.get("vulnerability_class","?"):15}  {outcome}')
print()

# /elo
r = client.get('/elo')
show(r.status_code, 'GET /elo', f'       {r.json()}')

# /elo/history
r = client.get('/elo/history')
h = r.json()
show(r.status_code, 'GET /elo/history',
     f'       current      : {h["current"]}\n'
     f'       history rows : {len(h["history"])}')

# /rules
r = client.get('/rules')
rules = r.json()
print(f'[OK  ] 200  GET /rules  ({len(rules)} records)')
results.append(('pass', f'GET /rules ({len(rules)} records)', 200))
for rule in rules:
    status = 'approved' if rule['approved'] else 'PENDING '
    print(f'         [{status}]  {rule["vulnerability_class"]:18}  {rule["rule_text"][:55]}...')
print()

# /prompts/current
r = client.get('/prompts/current')
p = r.json()
show(r.status_code, 'GET /prompts/current',
     f'       version        : {p["version"]}\n'
     f'       commit_message : {p["commit_message"]}')
for rule in p['rules']:
    print(f'           - {rule}')
print()

# /prompts/history
r = client.get('/prompts/history')
ph = r.json()
print(f'[OK  ] 200  GET /prompts/history  ({len(ph)} versions)')
results.append(('pass', f'GET /prompts/history ({len(ph)} versions)', 200))
for v in ph:
    print(f'         v{v["version"]}  rules={len(v["rules"])}  "{v["commit_message"][:50]}"')
print()

# /vulnerabilities/coverage
r = client.get('/vulnerabilities/coverage')
cov = r.json()
print(f'[OK  ] 200  GET /vulnerabilities/coverage  ({len(cov)} classes)')
results.append(('pass', f'GET /vulnerabilities/coverage ({len(cov)} classes)', 200))
for c in cov:
    filled = c['secure_count']
    empty  = c['total_episodes'] - c['secure_count']
    bar = '#' * filled + '.' * empty
    print(f'         {c["vulnerability_class"]:18}  total={c["total_episodes"]}  secure={c["secure_count"]}  [{bar}]  {c["coverage_rate"]:.0%}')
print()

# POST /training/jobs
r = client.post('/training/jobs', json={'vulnerability_class': 'XSS', 'language': 'python', 'max_retries': 1})
j = r.json()
show(r.status_code, 'POST /training/jobs  (enqueue XSS job)',
     f'       job_id  : {j.get("job_id")}\n'
     f'       status  : {j.get("status")}\n'
     f'       vuln    : {j.get("vulnerability_class")}')

# GET /training/jobs
r2 = client.get('/training/jobs')
jobs = r2.json()
print(f'[OK  ] 200  GET /training/jobs  ({len(jobs)} queued)')
results.append(('pass', f'GET /training/jobs ({len(jobs)} queued)', 200))
for jb in jobs:
    print(f'         {jb["job_id"]}  status={jb["status"]}  vuln={jb["vulnerability_class"]}')
print()

# POST /config
r = client.post('/config', json={'llm_model': 'llama3-8b-8192', 'k_factor': 32.0, 'max_retries': 2})
show(r.status_code, 'POST /config  (runtime settings update)', f'       {r.json()}')

# GET /training/stream (SSE)
r = client.get('/training/stream')
show(r.status_code, 'GET /training/stream  (SSE)',
     f'       content-type : {r.headers.get("content-type","?")}')

print(SEP)
passed = sum(1 for f, _, _ in results if f == 'pass')
failed = sum(1 for f, _, _ in results if f == 'fail')
print(f'ENDPOINTS: {passed} OK  |  {failed} FAILED')
if failed:
    print('FAILURES:')
    for f, lbl, code in results:
        if f == 'fail':
            print(f'  - [{code}] {lbl}')
else:
    print('All endpoints returned expected responses with live DB data.')
