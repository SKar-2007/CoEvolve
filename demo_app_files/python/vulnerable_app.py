"""Vulnerable Flask applications for DAST exploit replay.

Each app is intentionally vulnerable to a specific class. Run inside a
sandboxed container for safe exploit verification.

Usage:
    python -m packages.judge.dast.targets.vulnerable_app --class SQLi --port 5000
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
from pathlib import Path

from flask import (  # type: ignore[import-not-found]
    Flask,
    jsonify,
    render_template_string,
    request,
)


def create_sqli_app() -> Flask:
    """SQL Injection vulnerable app."""
    app = Flask(__name__)
    DB_PATH = "/tmp/sqli_test.db"

    def init_db():
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
        )
        c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'supersecret123', 'admin')")
        c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password123', 'user')")
        conn.commit()
        conn.close()

    with app.app_context():
        init_db()

    @app.route("/")
    def index():
        return "<h1>SQLi Test App</h1><p>Use /search?name= or /login</p>"

    @app.route("/search")
    def search():
        name = request.args.get("name", "")
        # VULNERABLE: raw string interpolation in SQL
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"
        try:
            c.execute(query)
            rows = c.fetchall()
            conn.close()
            return jsonify([{"id": r[0], "username": r[1], "role": r[3]} for r in rows])
        except Exception as e:
            conn.close()
            return jsonify({"error": str(e), "query": query}), 400

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: raw string interpolation in SQL
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
            conn.close()
            if user:
                return jsonify({"status": "logged_in", "user": user[1], "role": user[3]})
            return jsonify({"status": "invalid credentials"}), 401
        except Exception as e:
            conn.close()
            return jsonify({"error": str(e)}), 400

    return app


def create_path_traversal_app() -> Flask:
    """Path Traversal vulnerable app."""
    app = Flask(__name__)
    BASE_DIR = "/tmp/pathtraversal_test"
    os.makedirs(BASE_DIR, exist_ok=True)
    (Path(BASE_DIR) / "secret.txt").write_text("SECRET_DATA_42")
    (Path(BASE_DIR) / "config.json").write_text('{"api_key": "leaked-key-123"}')

    @app.route("/")
    def index():
        return "<h1>Path Traversal Test App</h1><p>Use /files?name=</p>"

    @app.route("/files")
    def files():
        name = request.args.get("name", "")
        # VULNERABLE: no path sanitization
        filepath = os.path.join(BASE_DIR, name)
        try:
            with open(filepath) as f:
                return f.read()
        except FileNotFoundError:
            return "File not found", 404
        except Exception as e:
            return str(e), 500

    return app


def create_command_injection_app() -> Flask:
    """Command Injection vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>Command Injection Test App</h1><p>Use /ping?host=</p>"

    @app.route("/ping")
    def ping():
        host = request.args.get("host", "127.0.0.1")
        # VULNERABLE: unsanitized input in shell command
        cmd = f"ping -c 1 {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return f"<pre>{result.stdout}</pre>"

    return app


def create_xss_app() -> Flask:
    """Cross-Site Scripting vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        name = request.args.get("name", "World")
        # VULNERABLE: unsanitized template rendering
        return render_template_string(f"<h1>Hello {name}!</h1>")

    @app.route("/xss")
    def xss_search():
        q = request.args.get("q", "")
        # VULNERABLE: reflected XSS
        return f"<p>Search results for: {q}</p>"

    return app


def create_ssti_app() -> Flask:
    """Server-Side Template Injection vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>SSTI Test App</h1><p>Use /greet?name=</p>"

    @app.route("/greet")
    def greet():
        name = request.args.get("name", "World")
        # VULNERABLE: user input directly in Jinja2 template
        template = f"<h1>Hello {name}!</h1>"
        return render_template_string(template)

    return app


def create_ssrf_app() -> Flask:
    """Server-Side Request Forgery vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>SSRF Test App</h1><p>Use /fetch?url=</p>"

    @app.route("/internal/metadata")
    def metadata():
        """Simulated cloud metadata endpoint for SSRF testing."""
        return "instance-id\nami-id\nlocal-ipv4"

    @app.route("/fetch")
    def fetch():
        import urllib.request

        url = request.args.get("url", "")
        # VULNERABLE: no URL validation
        try:
            response = urllib.request.urlopen(url, timeout=5)
            data = response.read().decode("utf-8", errors="replace")
            return f"<pre>{data[:2000]}</pre>"
        except Exception as e:
            return f"Error: {e}", 400

    return app


def create_open_redirect_app() -> Flask:
    """Open Redirect vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>Open Redirect Test App</h1><p>Use /redirect?url=</p>"

    @app.route("/redirect")
    def open_redirect():
        url = request.args.get("url", "/")
        # VULNERABLE: no URL validation - returns URL in both header and body
        resp = app.make_response((f"Redirecting to {url}", 302, {"Location": url}))
        return resp

    return app


def create_deserialization_app() -> Flask:
    """Insecure Deserialization vulnerable app (YAML pickle)."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>Deserialization Test App</h1><p>Use /load (POST body= YAML)</p>"

    @app.route("/load", methods=["POST"])
    def load_data():
        import yaml  # type: ignore[import-not-found]

        raw = request.get_data(as_text=True)
        # VULNERABLE: arbitrary YAML deserialization
        try:
            data = yaml.load(raw, Loader=yaml.FullLoader)
            return jsonify({"loaded": str(data)})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return app


def create_xxe_app() -> Flask:
    """XML External Entity vulnerable app."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>XXE Test App</h1><p>Use /parse (POST body= XML)</p>"

    @app.route("/parse", methods=["POST"])
    def parse_xml():
        from xml.etree.ElementTree import fromstring  # nosec

        raw = request.get_data(as_text=True)
        # VULNERABLE: no defusing of external entities
        try:
            root = fromstring(raw)
            text = root.find(".//").text if root.find(".//") is not None else ""
            return f"<pre>{text}</pre>"
        except Exception as e:
            return f"Error: {e}", 400

    return app


def create_prototype_pollution_app() -> Flask:
    """Prototype Pollution vulnerable app (Python dict merge)."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "<h1>Prototype Pollution Test App</h1><p>Use /merge (POST JSON)</p>"

    def deep_merge(base: dict, override: dict) -> dict:
        # VULNERABLE: no __proto__ / constructor check
        for key, value in override.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    @app.route("/merge", methods=["POST"])
    def merge():
        import json

        data = json.loads(request.get_data(as_text=True))
        base = {"user": "guest", "role": "viewer"}
        result = deep_merge(base, data)
        # If __proto__.isAdmin was set, it leaks into response
        return jsonify(result)

    return app


APP_REGISTRY = {
    "SQLi": create_sqli_app,
    "PathTraversal": create_path_traversal_app,
    "CommandInjection": create_command_injection_app,
    "XSS": create_xss_app,
    "SSTI": create_ssti_app,
    "SSRF": create_ssrf_app,
    "OpenRedirect": create_open_redirect_app,
    "Deserialization": create_deserialization_app,
    "XXE": create_xxe_app,
    "PrototypePollution": create_prototype_pollution_app,
}


def main():
    parser = argparse.ArgumentParser(description="Run a vulnerable test app")
    parser.add_argument(
        "--class", dest="vuln_class", required=True, choices=list(APP_REGISTRY.keys())
    )
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    factory = APP_REGISTRY[args.vuln_class]
    app = factory()
    print(f"Starting {args.vuln_class} vulnerable app on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
