from __future__ import annotations

import socket
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

from scanner import build_scan_request, scan_network


app = Flask(__name__)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/network-info")
def network_info():
    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "Unavailable"

    return jsonify({
        "hostname": hostname,
        "local_ip": local_ip,
        "recommended_target": local_ip
    })


@app.post("/api/scan")
def start_scan():
    payload = request.get_json(silent=True) or {}

    if payload.get("authorised") is not True:
        return jsonify({
            "error": (
                "You must confirm that you own or are authorised "
                "to scan the target."
            )
        }), 400

    target = str(payload.get("target", ""))
    profile = str(payload.get("profile", "common"))
    custom_ports = str(payload.get("custom_ports", ""))

    try:
        timeout = float(payload.get("timeout", 0.35))
    except (TypeError, ValueError):
        return jsonify({"error": "Timeout must be a number."}), 400

    try:
        scan_request = build_scan_request(
            target=target,
            profile=profile,
            custom_ports=custom_ports,
            timeout=timeout
        )

        results = scan_network(scan_request)
        results["scan_id"] = datetime.now(
            timezone.utc
        ).strftime("PP-%Y%m%d-%H%M%S")

        results["completed_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        return jsonify(results)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Unexpected scan failure")
        return jsonify({
            "error": "The scan could not be completed safely."
        }), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)