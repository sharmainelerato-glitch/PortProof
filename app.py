from __future__ import annotations

import os
import socket
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

from scanner import build_scan_request, scan_network


app = Flask(__name__)

DEMO_MODE = os.getenv(
    "PORTPROOF_DEMO_MODE",
    "false"
).lower() == "true"


def current_timestamp() -> tuple[str, str]:
    now = datetime.now(timezone.utc)

    scan_id = now.strftime("PP-%Y%m%d-%H%M%S")
    completed_at = now.isoformat()

    return scan_id, completed_at


def build_demo_results() -> dict:
    scan_id, completed_at = current_timestamp()

    findings = [
        {
            "host": "192.168.50.10",
            "port": 22,
            "service": "SSH",
            "severity": "low",
            "response_ms": 1.24,
            "explanation": (
                "Confirm that remote administration is authorised "
                "and hardened."
            ),
            "remediation": (
                "Restrict source addresses, require key "
                "authentication, and disable direct root login."
            ),
            "service_confidence": (
                "Inferred from the standard TCP port; "
                "validate the application."
            )
        },
        {
            "host": "192.168.50.10",
            "port": 80,
            "service": "HTTP",
            "severity": "medium",
            "response_ms": 1.76,
            "explanation": (
                "HTTP is unencrypted; confirm redirects or "
                "approved use."
            ),
            "remediation": (
                "Redirect to HTTPS or document the approved "
                "reason for unencrypted HTTP."
            ),
            "service_confidence": (
                "Inferred from the standard TCP port; "
                "validate the application."
            )
        },
        {
            "host": "192.168.50.10",
            "port": 445,
            "service": "SMB",
            "severity": "high",
            "response_ms": 0.93,
            "explanation": (
                "SMB exposure can enable lateral movement "
                "and file-share access."
            ),
            "remediation": (
                "Restrict SMB to trusted hosts, disable SMBv1, "
                "patch systems, and review share permissions."
            ),
            "service_confidence": (
                "Inferred from the standard TCP port; "
                "validate the application."
            )
        },
        {
            "host": "192.168.50.10",
            "port": 5432,
            "service": "PostgreSQL",
            "severity": "high",
            "response_ms": 1.08,
            "explanation": (
                "Restrict database access to approved "
                "application hosts."
            ),
            "remediation": (
                "Restrict database access to approved hosts "
                "and review pg_hba.conf rules."
            ),
            "service_confidence": (
                "Inferred from the standard TCP port; "
                "validate the application."
            )
        }
    ]

    return {
        "scan_id": scan_id,
        "completed_at": completed_at,
        "target": "192.168.50.10/32",
        "hosts_checked": 1,
        "ports_checked_per_host": 38,
        "total_connection_checks": 38,
        "hosts_with_open_ports": 1,
        "open_port_count": len(findings),
        "severity_counts": {
            "high": 2,
            "medium": 1,
            "low": 1,
            "informational": 0
        },
        "duration_seconds": 1.84,
        "hosts": [
            {
                "ip": "192.168.50.10",
                "hostname": "demo-workstation",
                "open_ports": findings
            }
        ],
        "findings": findings,
        "demo_mode": True
    }


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return response


@app.get("/")
def index():
    return render_template(
        "index.html",
        demo_mode=DEMO_MODE
    )


@app.get("/api/network-info")
def network_info():
    if DEMO_MODE:
        return jsonify({
            "hostname": "PORTPROOF-DEMO",
            "local_ip": "192.168.50.10",
            "recommended_target": "192.168.50.10",
            "demo_mode": True
        })

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        local_ip = "Unavailable"

    return jsonify({
        "hostname": hostname,
        "local_ip": local_ip,
        "recommended_target": local_ip,
        "demo_mode": False
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

    if DEMO_MODE:
        return jsonify(build_demo_results())

    target = str(payload.get("target", ""))
    profile = str(payload.get("profile", "common"))
    custom_ports = str(payload.get("custom_ports", ""))

    try:
        timeout = float(payload.get("timeout", 0.35))
    except (TypeError, ValueError):
        return jsonify({
            "error": "Timeout must be a number."
        }), 400

    try:
        scan_request = build_scan_request(
            target=target,
            profile=profile,
            custom_ports=custom_ports,
            timeout=timeout
        )

        results = scan_network(scan_request)
        scan_id, completed_at = current_timestamp()

        results["scan_id"] = scan_id
        results["completed_at"] = completed_at
        results["demo_mode"] = False

        return jsonify(results)

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except Exception:
        app.logger.exception("Unexpected scan failure")

        return jsonify({
            "error": "The scan could not be completed safely."
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5050"))
    host = "0.0.0.0" if DEMO_MODE else "127.0.0.1"

    app.run(
        host=host,
        port=port,
        debug=False
    )