"""
dashboard.py - Live metrics web dashboard.
Refreshes every 3 seconds. Shows banned IPs, global req/s,
top 10 source IPs, CPU/memory usage, effective mean/stddev, uptime.
Served at port 8080.
"""

import time
import threading
import psutil
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="3">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detector — Live Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        h1 {
            color: #58a6ff;
            margin-bottom: 5px;
            font-size: 1.5em;
        }
        .subtitle {
            color: #8b949e;
            font-size: 0.85em;
            margin-bottom: 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }
        .card h2 {
            color: #58a6ff;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.9em;
        }
        .metric .label { color: #8b949e; }
        .metric .value { color: #e6edf3; font-weight: bold; }
        .value.danger { color: #f85149; }
        .value.warning { color: #d29922; }
        .value.ok { color: #3fb950; }
        .banned-ip {
            background: #1f1117;
            border: 1px solid #f8514933;
            border-radius: 4px;
            padding: 8px;
            margin-bottom: 8px;
            font-size: 0.85em;
        }
        .banned-ip .ip { color: #f85149; font-weight: bold; }
        .banned-ip .detail { color: #8b949e; margin-top: 2px; }
        .top-ip {
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            font-size: 0.85em;
            border-bottom: 1px solid #21262d;
        }
        .top-ip:last-child { border-bottom: none; }
        .top-ip .rank { color: #8b949e; width: 24px; }
        .top-ip .ip { color: #58a6ff; flex: 1; }
        .top-ip .count { color: #3fb950; }
        .status-bar {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            font-size: 0.85em;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #3fb950;
            display: inline-block;
            margin-right: 6px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        .no-bans { color: #3fb950; font-size: 0.9em; text-align: center; padding: 16px; }
        .footer {
            color: #8b949e;
            font-size: 0.75em;
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>🛡️ HNG Anomaly Detector</h1>
    <p class="subtitle">Live Dashboard — Auto-refreshes every 3 seconds</p>

    <div class="status-bar">
        <span><span class="status-dot"></span> Detector Running</span>
        <span>Uptime: {{ uptime }}</span>
        <span>Last updated: {{ now }}</span>
    </div>

    <div class="grid">
        <!-- Traffic Stats -->
        <div class="card">
            <h2>📊 Traffic Stats</h2>
            <div class="metric">
                <span class="label">Global Req/60s</span>
                <span class="value {% if global_rate > 100 %}danger{% elif global_rate > 50 %}warning{% else %}ok{% endif %}">
                    {{ global_rate }}
                </span>
            </div>
            <div class="metric">
                <span class="label">Effective Mean</span>
                <span class="value">{{ mean }}</span>
            </div>
            <div class="metric">
                <span class="label">Effective StdDev</span>
                <span class="value">{{ stddev }}</span>
            </div>
            <div class="metric">
                <span class="label">Banned IPs</span>
                <span class="value {% if banned_count > 0 %}danger{% else %}ok{% endif %}">
                    {{ banned_count }}
                </span>
            </div>
        </div>

        <!-- System Stats -->
        <div class="card">
            <h2>💻 System Resources</h2>
            <div class="metric">
                <span class="label">CPU Usage</span>
                <span class="value {% if cpu > 80 %}danger{% elif cpu > 60 %}warning{% else %}ok{% endif %}">
                    {{ cpu }}%
                </span>
            </div>
            <div class="metric">
                <span class="label">Memory Usage</span>
                <span class="value {% if mem > 80 %}danger{% elif mem > 60 %}warning{% else %}ok{% endif %}">
                    {{ mem }}%
                </span>
            </div>
            <div class="metric">
                <span class="label">Memory Used</span>
                <span class="value">{{ mem_used }} MB</span>
            </div>
            <div class="metric">
                <span class="label">Memory Total</span>
                <span class="value">{{ mem_total }} MB</span>
            </div>
        </div>
    </div>

    <div class="grid">
        <!-- Banned IPs -->
        <div class="card">
            <h2>🚫 Banned IPs ({{ banned_count }})</h2>
            {% if banned_ips %}
                {% for ip, info in banned_ips.items() %}
                <div class="banned-ip">
                    <div class="ip">{{ ip }}</div>
                    <div class="detail">Condition: {{ info.condition }}</div>
                    <div class="detail">Rate: {{ info.rate }} req/60s</div>
                    <div class="detail">
                        Duration: {% if info.duration == -1 %}permanent{% else %}{{ info.duration }} min{% endif %}
                    </div>
                    <div class="detail">Ban #{{ info.count }}</div>
                </div>
                {% endfor %}
            {% else %}
                <div class="no-bans">✅ No IPs currently banned</div>
            {% endif %}
        </div>

        <!-- Top IPs -->
        <div class="card">
            <h2>🔝 Top 10 Source IPs</h2>
            {% for ip, count in top_ips %}
            <div class="top-ip">
                <span class="rank">{{ loop.index }}.</span>
                <span class="ip">{{ ip }}</span>
                <span class="count">{{ count }} reqs</span>
            </div>
            {% endfor %}
            {% if not top_ips %}
                <div style="color:#8b949e; font-size:0.9em; text-align:center; padding:16px;">
                    No traffic yet
                </div>
            {% endif %}
        </div>
    </div>

    <div class="footer">
        HNG Stage 3 — Anomaly Detection Engine | travispocr
    </div>
</body>
</html>
"""


class Dashboard:
    def __init__(self, config, state, baseline):
        self.config = config
        self.state = state
        self.baseline = baseline
        self.port = config["dashboard"]["port"]
        self.app = Flask(__name__)
        self._setup_routes()
        print(f"[dashboard] Dashboard initialized on port {self.port}")

    def _setup_routes(self):
        state = self.state
        baseline = self.baseline

        @self.app.route("/")
        def index():
            mean, stddev = baseline.get_baseline()
            mem = psutil.virtual_memory()
            uptime_seconds = int(time.time() - state.start_time)
            hours, rem = divmod(uptime_seconds, 3600)
            minutes, seconds = divmod(rem, 60)

            return render_template_string(
                DASHBOARD_HTML,
                global_rate=state.get_global_rate(),
                mean=f"{mean:.3f}",
                stddev=f"{stddev:.3f}",
                banned_count=len(state.banned_ips),
                banned_ips=dict(state.banned_ips),
                top_ips=state.get_top_ips(10),
                cpu=psutil.cpu_percent(interval=None),
                mem=mem.percent,
                mem_used=mem.used // (1024 * 1024),
                mem_total=mem.total // (1024 * 1024),
                uptime=f"{hours:02d}:{minutes:02d}:{seconds:02d}",
                now=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            )

        @self.app.route("/api/metrics")
        def metrics():
            mean, stddev = baseline.get_baseline()
            mem = psutil.virtual_memory()
            return jsonify({
                "global_rate": state.get_global_rate(),
                "mean": round(mean, 3),
                "stddev": round(stddev, 3),
                "banned_ips": list(state.banned_ips.keys()),
                "banned_count": len(state.banned_ips),
                "top_ips": state.get_top_ips(10),
                "cpu": psutil.cpu_percent(interval=None),
                "memory_percent": mem.percent,
                "uptime": int(time.time() - state.start_time),
            })

    def run(self, stop_event):
        """Run Flask dashboard in a thread."""
        print(f"[dashboard] Starting dashboard on port {self.port}")
        self.app.run(
            host="0.0.0.0",
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )