"""Fixed example: XSS prevention via auto-escaping."""

from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route("/greet")
def greet_secure():
    """This endpoint prevents XSS via escaping."""
    name = request.args.get("name", "World")
    
    # SECURE: Escape user input
    return f"<h1>Hello, {escape(name)}!</h1>"

@app.route("/greet-template")
def greet_secure_template():
    """This endpoint prevents XSS via template auto-escaping."""
    name = request.args.get("name", "World")
    
    # SECURE: Template auto-escaping
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
