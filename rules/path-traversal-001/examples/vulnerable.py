"""Vulnerable example: Path traversal via unsanitized input."""

import os
from flask import Flask, request, send_file

app = Flask(__name__)

UPLOAD_DIR = "/var/uploads"

@app.route("/download")
def download_vulnerable():
    """This endpoint is vulnerable to path traversal."""
    filename = request.args.get("file")
    
    # VULNERABLE: No path validation
    file_path = os.path.join(UPLOAD_DIR, filename)
    return send_file(file_path)
