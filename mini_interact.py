#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import socket
import requests
import json
import argparse

app = Flask(__name__)

interactions = []
MY_PUBLIC_IP = None

PRIVATE_PREFIXES = (
    "127.", "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "::1", "0.0.0.0",
)

INTERNAL_PATHS = ("/api/logs", "/api/poll", "/api/clear", "/favicon.ico")


def get_my_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def is_internal_request(ip):
    """Filter own IP and private ranges."""
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return True
    if MY_PUBLIC_IP and ip == MY_PUBLIC_IP:
        return True
    return False


def log_interaction(req):
    client_ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    if is_internal_request(client_ip):
        return

    # Skip internal API/dashboard requests
    if req.path in INTERNAL_PATHS:
        return

    hostname = reverse_dns(client_ip)

    entry = {
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": client_ip,
        "hostname": hostname or "N/A",
        "method": req.method,
        "path": req.full_path.rstrip("?"),
        "query": req.query_string.decode("utf-8", errors="replace"),
        "headers": dict(req.headers),
        "body": req.get_data(as_text=True),
        "user_agent": req.headers.get("User-Agent", "N/A"),
    }

    interactions.append(entry)
    print(f"\033[92m[+] {entry['time']} | {client_ip} ({hostname or 'N/A'}) | {req.method} {req.path}\033[0m")
    ua = entry["user_agent"]
    if ua != "N/A":
        print(f"    UA: {ua}")


def interactions_as_text():
    """Dump all interactions as plain text — for hhip canary polling."""
    if not interactions:
        return ""
    lines = []
    for e in interactions:
        lines.append(f"--- {e['time']} ---")
        lines.append(f"IP: {e['ip']} ({e['hostname']})")
        lines.append(f"{e['method']} {e['path']}")
        for k, v in e["headers"].items():
            lines.append(f"{k}: {v}")
        if e["body"]:
            lines.append(f"BODY: {e['body']}")
        lines.append("")
    return "\n".join(lines)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.before_request
def before():
    """Log every incoming request before routing."""
    log_interaction(request)


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def catch_all(path):
    """
    Smart root:
    - Browser (Accept: text/html) → serves dashboard
    - Script/curl (Accept: */*, no text/html) → returns plain text logs for canary polling
    """
    # Internal API routes handled by their own endpoints
    if request.path in INTERNAL_PATHS:
        return "", 404

    accept = request.headers.get("Accept", "")
    if "text/html" in accept:
        return render_dashboard()

    # Plain text dump — this is what hhip polls for canary detection
    return interactions_as_text(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/api/logs")
def api_logs():
    return jsonify(interactions)


@app.route("/api/poll")
def api_poll():
    """Explicit polling endpoint (alternative to root content negotiation)."""
    return interactions_as_text(), 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/api/clear", methods=["GET", "POST"])
def clear_logs():
    interactions.clear()
    return jsonify({"status": "cleared"})


# ─── Dashboard ────────────────────────────────────────────────────────────────

def render_dashboard():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Interact Dashboard</title>
        <meta charset="utf-8">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
                background: #0a0e14;
                color: #b3b1ad;
                font-size: 13px;
            }

            /* Header */
            .header {
                background: #0d1117;
                border-bottom: 1px solid #1a1f2e;
                padding: 12px 20px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                position: sticky;
                top: 0;
                z-index: 100;
            }
            .header-left {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            .logo {
                color: #ff6b35;
                font-weight: bold;
                font-size: 15px;
                letter-spacing: 1px;
            }
            .badge {
                background: #1a2332;
                color: #59c2ff;
                padding: 3px 10px;
                border-radius: 3px;
                font-size: 11px;
            }
            .badge.live {
                background: #1a2e1a;
                color: #7fd962;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .controls {
                display: flex;
                gap: 8px;
            }
            .btn {
                background: #1a2332;
                border: 1px solid #1f2937;
                color: #b3b1ad;
                padding: 6px 14px;
                border-radius: 4px;
                cursor: pointer;
                font-family: inherit;
                font-size: 12px;
                transition: all 0.15s;
            }
            .btn:hover { background: #243044; border-color: #374151; }
            .btn.danger { color: #f87171; }
            .btn.danger:hover { background: #2d1a1a; border-color: #7f1d1d; }

            /* Filter bar */
            .filter-bar {
                background: #0d1117;
                border-bottom: 1px solid #1a1f2e;
                padding: 8px 20px;
                display: flex;
                gap: 10px;
                align-items: center;
            }
            .filter-bar input {
                background: #1a2332;
                border: 1px solid #1f2937;
                color: #e6e1cf;
                padding: 5px 10px;
                border-radius: 4px;
                font-family: inherit;
                font-size: 12px;
                width: 300px;
            }
            .filter-bar input:focus { outline: none; border-color: #59c2ff; }
            .filter-bar .count { color: #636a76; font-size: 11px; }

            /* Interactions */
            .container { padding: 10px 20px; }
            .empty {
                text-align: center;
                padding: 60px 20px;
                color: #636a76;
            }
            .empty .icon { font-size: 28px; margin-bottom: 10px; opacity: 0.4; }

            .entry {
                background: #0d1117;
                border: 1px solid #1a1f2e;
                border-radius: 6px;
                margin-bottom: 8px;
                overflow: hidden;
                transition: border-color 0.15s;
            }
            .entry:hover { border-color: #2a3040; }
            .entry.new {
                border-left: 3px solid #7fd962;
                animation: fadeIn 0.3s ease;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-5px); }
                to { opacity: 1; transform: translateY(0); }
            }

            .entry-header {
                padding: 10px 14px;
                display: flex;
                align-items: center;
                gap: 10px;
                cursor: pointer;
                user-select: none;
            }
            .entry-header:hover { background: #111720; }

            .method {
                font-weight: bold;
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
                min-width: 50px;
                text-align: center;
            }
            .method.GET { background: #1a2e1a; color: #7fd962; }
            .method.POST { background: #2e2a1a; color: #e6b450; }
            .method.PUT { background: #1a2332; color: #59c2ff; }
            .method.DELETE { background: #2d1a1a; color: #f87171; }
            .method.HEAD { background: #1a2332; color: #b3b1ad; }
            .method.OPTIONS { background: #2a1a2e; color: #d2a6ff; }

            .entry-path { color: #e6e1cf; flex: 1; word-break: break-all; }
            .entry-ip { color: #59c2ff; font-size: 12px; }
            .entry-time { color: #636a76; font-size: 11px; min-width: 130px; text-align: right; }

            .entry-detail {
                display: none;
                padding: 0 14px 12px;
                border-top: 1px solid #1a1f2e;
            }
            .entry.open .entry-detail { display: block; }

            .detail-section {
                margin-top: 10px;
            }
            .detail-label {
                color: #636a76;
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 4px;
            }
            .detail-content {
                background: #070a0f;
                border: 1px solid #1a1f2e;
                border-radius: 4px;
                padding: 10px;
                overflow-x: auto;
                max-height: 300px;
                overflow-y: auto;
                white-space: pre-wrap;
                word-break: break-all;
                line-height: 1.5;
            }
            .hdr-key { color: #59c2ff; }
            .hdr-val { color: #e6e1cf; }
            .highlight { background: #3d2e00; color: #e6b450; padding: 1px 3px; border-radius: 2px; }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="header-left">
                <span class="logo">INTERACT</span>
                <span class="badge live" id="status">● LIVE</span>
                <span class="badge" id="countBadge">0 hits</span>
            </div>
            <div class="controls">
                <button class="btn" onclick="toggleAutoRefresh()" id="autoBtn">Auto: ON (3s)</button>
                <button class="btn" onclick="loadLogs()">Refresh</button>
                <button class="btn danger" onclick="clearLogs()">Clear</button>
            </div>
        </div>

        <div class="filter-bar">
            <input type="text" id="filter" placeholder="Filter by IP, path, header, body..." oninput="applyFilter()">
            <span class="count" id="filterCount"></span>
        </div>

        <div class="container" id="logs">
            <div class="empty">
                <div class="icon">⏳</div>
                Waiting for interactions...
            </div>
        </div>

        <script>
            let allData = [];
            let autoRefresh = true;
            let autoInterval = null;
            let lastCount = 0;
            let openEntries = new Set();

            function toggleAutoRefresh() {
                autoRefresh = !autoRefresh;
                document.getElementById("autoBtn").textContent = autoRefresh ? "Auto: ON (3s)" : "Auto: OFF";
                if (autoRefresh) startAutoRefresh();
                else stopAutoRefresh();
            }

            function startAutoRefresh() {
                if (autoInterval) return;
                autoInterval = setInterval(loadLogs, 3000);
            }

            function stopAutoRefresh() {
                if (autoInterval) { clearInterval(autoInterval); autoInterval = null; }
            }

            async function loadLogs() {
                try {
                    let res = await fetch('/api/logs', {headers: {'ngrok-skip-browser-warning': '1'}});
                    allData = await res.json();
                    document.getElementById("countBadge").textContent = allData.length + " hit" + (allData.length !== 1 ? "s" : "");
                    applyFilter();
                    lastCount = allData.length;
                } catch(e) {
                    document.getElementById("status").textContent = "● OFFLINE";
                    document.getElementById("status").classList.remove("live");
                }
            }

            function applyFilter() {
                let q = document.getElementById("filter").value.toLowerCase();
                let filtered = allData;
                if (q) {
                    filtered = allData.filter(e => {
                        let blob = JSON.stringify(e).toLowerCase();
                        return blob.includes(q);
                    });
                }
                renderEntries(filtered);
                document.getElementById("filterCount").textContent = q ? filtered.length + "/" + allData.length + " shown" : "";
            }

            function renderEntries(entries) {
                let container = document.getElementById("logs");
                if (!entries.length) {
                    container.innerHTML = '<div class="empty"><div class="icon">⏳</div>Waiting for interactions...</div>';
                    return;
                }

                let html = "";
                // Reverse: newest first
                for (let i = entries.length - 1; i >= 0; i--) {
                    let e = entries[i];
                    let idx = allData.indexOf(e);
                    let isNew = idx >= lastCount;
                    let isOpen = openEntries.has(idx);

                    html += '<div class="entry' + (isNew ? ' new' : '') + (isOpen ? ' open' : '') + '" data-idx="' + idx + '">';
                    html += '<div class="entry-header" onclick="toggleEntry(' + idx + ')">';
                    html += '<span class="method ' + e.method + '">' + e.method + '</span>';
                    html += '<span class="entry-path">' + escHtml(e.path) + '</span>';
                    html += '<span class="entry-ip">' + escHtml(e.ip) + '</span>';
                    html += '<span class="entry-time">' + e.time + '</span>';
                    html += '</div>';

                    html += '<div class="entry-detail">';

                    // Info
                    html += '<div class="detail-section">';
                    html += '<div class="detail-label">Info</div>';
                    html += '<div class="detail-content">';
                    html += '<span class="hdr-key">IP:</span> <span class="hdr-val">' + escHtml(e.ip) + '</span>\\n';
                    html += '<span class="hdr-key">Hostname:</span> <span class="hdr-val">' + escHtml(e.hostname) + '</span>\\n';
                    html += '<span class="hdr-key">User-Agent:</span> <span class="hdr-val">' + escHtml(e.user_agent) + '</span>';
                    if (e.query) html += '\\n<span class="hdr-key">Query:</span> <span class="hdr-val">' + escHtml(e.query) + '</span>';
                    html += '</div></div>';

                    // Headers
                    html += '<div class="detail-section">';
                    html += '<div class="detail-label">Headers</div>';
                    html += '<div class="detail-content">';
                    for (let k in e.headers) {
                        html += '<span class="hdr-key">' + escHtml(k) + ':</span> <span class="hdr-val">' + escHtml(e.headers[k]) + '</span>\\n';
                    }
                    html += '</div></div>';

                    // Body
                    if (e.body) {
                        html += '<div class="detail-section">';
                        html += '<div class="detail-label">Body</div>';
                        html += '<div class="detail-content">' + escHtml(e.body) + '</div>';
                        html += '</div>';
                    }

                    html += '</div></div>';
                }
                container.innerHTML = html;
            }

            function toggleEntry(idx) {
                if (openEntries.has(idx)) openEntries.delete(idx);
                else openEntries.add(idx);
                applyFilter();
            }

            function escHtml(s) {
                if (!s) return "";
                return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
            }

            async function clearLogs() {
                await fetch('/api/clear', {method:'POST', headers: {'ngrok-skip-browser-warning': '1'}});
                allData = [];
                lastCount = 0;
                openEntries.clear();
                applyFilter();
                document.getElementById("countBadge").textContent = "0 hits";
            }

            loadLogs();
            startAutoRefresh();
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mini Interactsh Dashboard")
    parser.add_argument("-p", "--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()

    MY_PUBLIC_IP = get_my_public_ip()
    print(f"\033[96m┌─ Interact Dashboard\033[0m")
    print(f"\033[96m├─ Listening on {args.host}:{args.port}\033[0m")
    print(f"\033[96m├─ Dashboard: http://localhost:{args.port}/\033[0m")
    print(f"\033[96m├─ Poll API:  http://localhost:{args.port}/api/poll\033[0m")
    if MY_PUBLIC_IP:
        print(f"\033[96m├─ Public IP:  {MY_PUBLIC_IP} (excluded)\033[0m")
    print(f"\033[93m├─ ngrok: ngrok http {args.port} --request-header-add 'ngrok-skip-browser-warning:1'\033[0m")
    print(f"\033[96m└─ Waiting for interactions...\033[0m")

    app.run(host=args.host, port=args.port)