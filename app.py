"""AC3 v2 Flask API — text and file encryption endpoints.

Endpoints:
    GET  /                 web UI
    POST /encrypt          {message} -> {ciphertext}
    POST /decrypt          {ciphertext} -> {plaintext}
    POST /encrypt-file     multipart 'file' -> downloadable .ac3
    POST /decrypt-file     multipart 'file' -> decrypted download
    GET  /health           liveness probe

Security posture: no plaintext or ciphertext contents are ever logged,
debug mode is off by default, uploads are size-capped.
"""

import io
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

from ac3 import AC3Error, CMainController

BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 64 * 1024 * 1024  # 64 MB cap


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
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

controller = CMainController()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "version": 2})


@app.post("/encrypt")
def encrypt_message():
    if request.content_type != "application/json":
        return jsonify({"error": "Expected application/json"}), 415
    data = request.get_json(silent=True) or {}
    message = data.get("message")
    if not isinstance(message, str) or message == "":
        return jsonify({"error": "Missing or empty 'message' parameter"}), 400
    try:
        token = controller.encrypt(message)
    except AC3Error as exc:
        logger.warning("encrypt failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    logger.info("encrypt: %d chars in, %d chars out", len(message), len(token))
    return jsonify({"ciphertext": token}), 200


@app.post("/decrypt")
def decrypt_message():
    if request.content_type != "application/json":
        return jsonify({"error": "Expected application/json"}), 415
    data = request.get_json(silent=True) or {}
    token = data.get("ciphertext")
    if not isinstance(token, str) or token == "":
        return jsonify({"error": "Missing or empty 'ciphertext' parameter"}), 400
    try:
        message = controller.decrypt(token)
    except AC3Error as exc:
        # Integrity/envelope failures are expected outcomes, not server faults.
        logger.warning("decrypt rejected input: %s", exc.__class__.__name__)
        return jsonify({"error": str(exc)}), 400
    logger.info("decrypt: %d chars in, %d chars out", len(token), len(message))
    return jsonify({"plaintext": message}), 200


def _read_upload():
    if "file" not in request.files:
        return None, (jsonify({"error": "Missing multipart 'file' field"}), 400)
    upload = request.files["file"]
    if upload.filename == "":
        return None, (jsonify({"error": "No file selected"}), 400)
    payload = upload.read()
    if not payload:
        return None, (jsonify({"error": "Uploaded file is empty"}), 400)
    return (upload.filename, payload), None


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
        download_name=filename + ".ac3",
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
        download_name=filename or "decrypted.bin",
    )


@app.errorhandler(413)
def too_large(_error):
    return (
        jsonify(
            {
                "error": f"File exceeds the "
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit"
            }
        ),
        413,
    )


if __name__ == "__main__":
    import os

    debug = os.getenv("AC3_DEBUG", "").lower() in {"1", "true", "yes"}
    port = int(os.getenv("AC3_PORT", "8080"))
    app.run(host="127.0.0.1", port=port, debug=debug)
