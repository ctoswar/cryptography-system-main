"""AC3 v2 Flask API — text and file encryption endpoints.

Endpoints:
    GET  /                 web UI
    POST /encrypt          {message} -> {ciphertext}
    POST /decrypt          {ciphertext} -> {plaintext}
    POST /encrypt-file     multipart 'file' -> downloadable .ac3
    POST /decrypt-file     multipart 'file' -> decrypted download
    GET  /health           liveness probe

Security posture:
    * No plaintext or ciphertext contents are ever logged.
    * Debug mode off by default; binds 127.0.0.1 only.
    * Uploads capped at 64 MB, text messages at MAX_TEXT_BYTES.
    * Per-IP rate limiting (AC3_RATE_LIMIT requests/minute, 0 disables).
    * CORS disabled unless AC3_ALLOWED_ORIGINS is set explicitly.
    * Security headers on every response: CSP (nonce), nosniff,
      frame-deny, no-referrer, no-store (responses carry secrets).
"""

import io
import logging
import os
import re
import secrets
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, g, jsonify, render_template, request, send_file

try:  # only needed when cross-origin use is explicitly enabled
    from flask_cors import CORS
except ImportError:  # pragma: no cover
    CORS = None

from ac3 import AC3Error, CMainController

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 64 * 1024 * 1024   # multipart body cap
MAX_TEXT_BYTES = 8 * 1024 * 1024      # single text message cap (CPU guard)
RATE_LIMIT_PER_MIN = int(os.getenv("AC3_RATE_LIMIT", "120"))

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("ac3.web")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            BASE_DIR / "project_logs.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)
    # Werkzeug request logging would echo paths only, but keep it quiet anyway.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    return logger


logger = configure_logging()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# CORS is OFF by default: the web UI is same-origin and needs none. A wildcard
# here would let any website in the victim's browser drive this local API.
_allowed_origins = [
    o.strip() for o in os.getenv("AC3_ALLOWED_ORIGINS", "").split(",") if o.strip()
]
if _allowed_origins:
    if CORS is None:
        raise RuntimeError(
            "AC3_ALLOWED_ORIGINS set but flask-cors is not installed."
        )
    CORS(app, resources={r"/*": {"origins": _allowed_origins}})

controller = CMainController()


# --------------------------------------------------------------------------
# rate limiting (per-process fixed window; local single-process deployment)
# --------------------------------------------------------------------------

_rate_lock = threading.Lock()
_rate_buckets: dict = {}


def _rate_limit_hit():
    """Return a (response, status) tuple when the caller exceeds the limit."""
    if RATE_LIMIT_PER_MIN <= 0 or app.config.get("TESTING"):
        return None
    now = time.monotonic()
    ip = request.remote_addr or "?"
    with _rate_lock:
        start, count = _rate_buckets.get(ip, (now, 0))
        if now - start >= 60.0:
            start, count = now, 0
        count += 1
        _rate_buckets[ip] = (start, count)
        if len(_rate_buckets) > 10_000:  # bound memory: drop stale buckets
            for k in [k for k, v in _rate_buckets.items() if now - v[0] >= 60.0]:
                del _rate_buckets[k]
    if count > RATE_LIMIT_PER_MIN:
        logger.warning("rate limit exceeded for %s", ip)
        return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429
    return None


@app.before_request
def _enforce_rate_limit():
    return _rate_limit_hit()


@app.after_request
def _security_headers(response):
    """Headers on every response (OWASP A05 security misconfiguration)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )
    # Bodies carry plaintext or ciphertext — never cache them.
    response.headers["Cache-Control"] = "no-store"
    nonce = getattr(g, "csp_nonce", None)
    if nonce:
        response.headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; "
            f"style-src 'nonce-{nonce}'; img-src 'self' data:; "
            f"connect-src 'self'; base-uri 'none'; form-action 'self'; "
            f"frame-ancestors 'none'"
        )
    else:
        # API/JSON responses: no scripts to allow at all.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
    server = response.headers.get("Server")
    if server and "werkzeug" in server.lower():
        del response.headers["Server"]  # don't advertise the stack
    return response


# --------------------------------------------------------------------------
# pages
# --------------------------------------------------------------------------

@app.get("/")
def index():
    g.csp_nonce = secrets.token_urlsafe(16)
    return render_template("index.html", csp_nonce=g.csp_nonce)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": 2})


def _check_json_content_type():
    # request.mimetype ignores parameters like '; charset=utf-8'.
    if request.mimetype != "application/json":
        return jsonify({"error": "Expected application/json"}), 415
    return None


def _safe_download_name(name: str, suffix: str = "") -> str:
    """Basename + control-char strip: never echo paths or escape codes."""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _CONTROL_CHARS.sub("", name).strip()
    if not name or name in {".", ".."}:
        name = "download.bin"
    return name + suffix


# --------------------------------------------------------------------------
# text endpoints
# --------------------------------------------------------------------------

@app.post("/encrypt")
def encrypt_message():
    wrong_type = _check_json_content_type()
    if wrong_type:
        return wrong_type
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body must be an object"}), 400
    message = data.get("message")
    if not isinstance(message, str) or message == "":
        return jsonify({"error": "Missing or empty 'message' parameter"}), 400
    if len(message.encode("utf-8")) > MAX_TEXT_BYTES:
        return (
            jsonify(
                {"error": f"Message exceeds {MAX_TEXT_BYTES // (1024 * 1024)} MB limit"}
            ),
            413,
        )
    try:
        token = controller.encrypt(message)
    except AC3Error as exc:
        logger.warning("encrypt failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    logger.info("encrypt: %d chars in, %d chars out", len(message), len(token))
    return jsonify({"ciphertext": token}), 200


@app.post("/decrypt")
def decrypt_message():
    wrong_type = _check_json_content_type()
    if wrong_type:
        return wrong_type
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body must be an object"}), 400
    token = data.get("ciphertext")
    if not isinstance(token, str) or token == "":
        return jsonify({"error": "Missing or empty 'ciphertext' parameter"}), 400
    if len(token) > MAX_TEXT_BYTES * 2:
        return jsonify({"error": "Ciphertext too large"}), 413
    try:
        message = controller.decrypt(token)
    except AC3Error as exc:
        # Integrity/envelope failures are expected outcomes, not server faults.
        logger.warning("decrypt rejected input: %s", exc.__class__.__name__)
        return jsonify({"error": str(exc)}), 400
    logger.info("decrypt: %d chars in, %d chars out", len(token), len(message))
    return jsonify({"plaintext": message}), 200


# --------------------------------------------------------------------------
# file endpoints
# --------------------------------------------------------------------------

def _read_upload():
    if "file" not in request.files:
        return None, (jsonify({"error": "Missing multipart 'file' field"}), 400)
    upload = request.files["file"]
    if not upload.filename:
        return None, (jsonify({"error": "No file selected"}), 400)
    payload = upload.read()
    if not payload:
        return None, (jsonify({"error": "Uploaded file is empty"}), 400)
    return (_safe_download_name(upload.filename), payload), None


@app.post("/encrypt-file")
def encrypt_file():
    parsed, error = _read_upload()
    if error:
        return error
    filename, payload = parsed
    try:
        blob = controller.encrypt_bytes(payload)
    except AC3Error as exc:
        return jsonify({"error": str(exc)}), 400
    logger.info("encrypt-file: %s (%d -> %d bytes)", filename, len(payload), len(blob))
    return send_file(
        io.BytesIO(blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=_safe_download_name(filename, ".ac3"),
    )


@app.post("/decrypt-file")
def decrypt_file():
    parsed, error = _read_upload()
    if error:
        return error
    filename, payload = parsed
    try:
        blob = controller.decrypt_bytes(payload)
    except AC3Error as exc:
        logger.warning("decrypt-file rejected: %s", exc.__class__.__name__)
        return jsonify({"error": str(exc)}), 400
    if filename.endswith(".ac3"):
        filename = filename[: -len(".ac3")]
    logger.info("decrypt-file: %s (%d -> %d bytes)", filename, len(payload), len(blob))
    return send_file(
        io.BytesIO(blob),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=_safe_download_name(filename),
    )


@app.errorhandler(413)
def too_large(_error):
    return (
        jsonify(
            {
                "error": f"Request exceeds the "
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit"
            }
        ),
        413,
    )


if __name__ == "__main__":
    debug = os.getenv("AC3_DEBUG", "").lower() in {"1", "true", "yes"}
    port = int(os.getenv("AC3_PORT", "8080"))
    if debug:
        logger.warning("AC3_DEBUG is on — never expose a debug server to a network")
    app.run(host="127.0.0.1", port=port, debug=debug)
