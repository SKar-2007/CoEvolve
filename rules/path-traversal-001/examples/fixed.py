"""Fixed example: Path traversal prevention via validation."""

import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

UPLOAD_DIR = "/var/uploads"

def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """Check if the requested path is within the allowed directory."""
    base_real = os.path.realpath(base_dir)
    requested_real = os.path.realpath(os.path.join(base_dir, requested_path))
    return requested_real.startswith(base_real)

@app.route("/download")
def download_secure():
    """This endpoint prevents path traversal."""
    filename = request.args.get("file")
    
    if not filename:
        abort(400, "No filename provided")
    
    # SECURE: Validate path before use
    if not is_safe_path(UPLOAD_DIR, filename):
        abort(403, "Access denied")
    
    file_path = os.path.join(UPLOAD_DIR, filename)
    
    if not os.path.exists(file_path):
        abort(404, "File not found")
    
    return send_file(file_path)
