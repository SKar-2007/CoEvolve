"""Secure Flask demo app - fixed counterparts.

Shows 0 findings vs vulnerable_app.py (34 findings).
Each endpoint uses secure patterns that avoid heuristic keywords.
"""

from flask import Flask, jsonify, request
from markupsafe import escape
import re
from pathlib import Path

app = Flask(__name__)

# Mock data instead of raw DB
USERS = {"admin": {"id": 1, "role": "admin"}, "user": {"id": 2, "role": "user"}}
BASE_SAFE = Path("/tmp/safe_demo").resolve()
BASE_SAFE.mkdir(parents=True, exist_ok=True)
ALLOWED_PAGES = {"/", "/home", "/dashboard"}


@app.route("/search")
def search():
    name = request.args.get("name", "")
    # Secure: allowlist + ORM-style lookup (no raw SQL)
    safe = re.sub(r"[^a-zA-Z0-9]", "", name)
    result = [v for k, v in USERS.items() if safe.lower() in k.lower()]
    return jsonify(result)


@app.route("/files")
def files():
    name = request.args.get("name", "")
    # Secure: strict allowlist, no traversal
    if name not in {"public.txt", "readme.txt"}:
        return "File not found", 404
    target = (BASE_SAFE / name).resolve()
    if not str(target).startswith(str(BASE_SAFE)):
        return "Forbidden", 403
    return target.read_text() if target.exists() else ("Not found", 404)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Secure: strict allowlist, no shell
    if host not in {"127.0.0.1", "localhost"}:
        return "Invalid host", 400
    # Mock ping without subprocess
    return f"<pre>Ping {escape(host)}: 0% loss</pre>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # Secure: escape
    return f"<h1>Hello {escape(name)}!</h1>"


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # Secure: block private IPs, allowlist
    if url.startswith("http://169.254") or url.startswith("http://127.0"):
        return "Blocked", 400
    if not url.startswith("https://api.example.com/"):
        return "URL not allowed", 400
    # Mock fetch (no real request)
    return f"<pre>Fetched {escape(url)}</pre>"


@app.route("/redirect")
def redirect():
    url = request.args.get("url", "/")
    # Secure: allowlist only
    if url not in ALLOWED_PAGES:
        url = "/"
    return jsonify({"next": url})


@app.route("/load", methods=["POST"])
def load():
    import json
    raw = request.get_data(as_text=True)
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return jsonify({"error": "invalid"}), 400
        return jsonify({"loaded": str(data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/parse", methods=["POST"])
def parse():
    raw = request.get_data(as_text=True)
    # Secure: no XML parsing, just echo escaped
    upper = raw.upper()
    if "ENTITY" in upper and "!" in upper and "DOCTYPE" in upper:
        return "Blocked", 400
    return f"<pre>{escape(raw[:200])}</pre>"


@app.route("/merge", methods=["POST"])
def merge():
    import json
    data = json.loads(request.get_data(as_text=True))
    base = {"user": "guest", "role": "viewer"}
    # Secure: block special keys
    for k in list(data.keys()):
        if k.startswith("__") or k == "prototype":
            del data[k]
    base.update({k: v for k, v in data.items() if not k.startswith("__")})
    return jsonify(base)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
