"""Vulnerable example: XSS via unescaped output."""

from flask import Flask, request

app = Flask(__name__)

@app.route("/greet")
def greet_vulnerable():
    """This endpoint is vulnerable to reflected XSS."""
    name = request.args.get("name", "World")
    
    # VULNERABLE: User input directly in HTML
    return f"<h1>Hello, {name}!</h1>"
