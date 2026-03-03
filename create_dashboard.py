#!/usr/bin/env python3
"""
Dashboard bootstrapper — run once to create the web UI.
Usage: python create_dashboard.py
"""
import os
BASE = os.path.dirname(os.path.abspath(__file__))
FILES = {}

# ─────────────────────────────────────────────────────────────────────────────
# DOCKERFILE  (build context = pentest/, copies both pentester/ and dashboard/)
# ─────────────────────────────────────────────────────────────────────────────
FILES["dashboard/Dockerfile"] = """\
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    nmap curl git perl libnet-ssleay-perl ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \\
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \\
    && chmod +x /opt/nikto/program/nikto.pl

# Install Python deps from both pentester and dashboard requirements
COPY pentester/requirements.txt /tmp/pentest_req.txt
COPY dashboard/requirements.txt /tmp/dash_req.txt
RUN pip install --no-cache-dir -r /tmp/pentest_req.txt -r /tmp/dash_req.txt sqlmap

# Copy pentester lib and dashboard app
COPY pentester/ /app/pentest_lib/
COPY dashboard/ /app/

EXPOSE 8080
CMD ["python", "app.py"]
"""

# ─────────────────────────────────────────────────────────────────────────────
FILES["dashboard/requirements.txt"] = """\
flask>=3.0.0
python-dotenv>=1.0.0
"""

# ─────────────────────────────────────────────────────────────────────────────
FILES["dashboard/app.py"] = '''\
"""
AutoPenTest Web Dashboard
Allows scanning any URL via browser, streams live logs,
displays AI-generated report inline.
"""
import os, sys, uuid, threading, json
from datetime import datetime
from flask import (Flask, render_template, request, redirect,
                   url_for, jsonify, Response, stream_with_context)

# Make pentester modules importable
sys.path.insert(0, "/app/pentest_lib")

from scanner_runner import run_scan_async, SCANS

app = Flask(__name__)
app.secret_key = os.urandom(24)

REPORT_DIR = os.environ.get("REPORT_DIR", "/reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    history = sorted(SCANS.values(),
                     key=lambda s: s["started_at"], reverse=True)
    return render_template("index.html", scans=history)


@app.route("/scan", methods=["POST"])
def start_scan():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("index"))
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    scan_id = str(uuid.uuid4())[:8]
    run_scan_async(scan_id, url, REPORT_DIR)
    return redirect(url_for("scan_view", scan_id=scan_id))


@app.route("/scan/<scan_id>")
def scan_view(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template("scan.html", scan=scan)


@app.route("/scan/<scan_id>/status")
def scan_status(scan_id):
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status":       scan["status"],
        "phase":        scan["phase"],
        "progress_pct": scan["progress_pct"],
        "log_count":    len(scan["logs"]),
        "has_report":   bool(scan.get("report_html")),
        "total_findings": scan.get("total_findings", 0),
        "risk_rating":  scan.get("risk_rating", ""),
        "error":        scan.get("error"),
    })


@app.route("/scan/<scan_id>/logs")
def scan_logs(scan_id):
    """Return logs from given offset."""
    scan = SCANS.get(scan_id)
    if not scan:
        return jsonify([])
    offset = int(request.args.get("offset", 0))
    return jsonify(scan["logs"][offset:])


@app.route("/scan/<scan_id>/report")
def scan_report(scan_id):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_html"):
        return "Report not ready yet", 404
    return scan["report_html"]


@app.route("/scan/<scan_id>/download/json")
def download_json(scan_id):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_json"):
        return "Not available", 404
    return Response(
        json.dumps(scan["report_json"], indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
    )


@app.route("/scan/<scan_id>/cancel", methods=["POST"])
def cancel_scan(scan_id):
    scan = SCANS.get(scan_id)
    if scan and scan["status"] == "running":
        scan["status"] = "cancelled"
        scan["phase"]  = "Cancelled by user"
    return redirect(url_for("scan_view", scan_id=scan_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
'''

# ─────────────────────────────────────────────────────────────────────────────
FILES["dashboard/scanner_runner.py"] = '''\
"""
Background scanner runner.
Runs all pentest modules in a thread, captures logs,
stores results + report in the SCANS global dict.
"""
import sys, io, threading, time, os
from datetime import datetime
from contextlib import redirect_stdout

# Make pentest_lib importable (Docker path)
if "/app/pentest_lib" not in sys.path:
    sys.path.insert(0, "/app/pentest_lib")

# Also support local dev
_local_lib = os.path.join(os.path.dirname(__file__), "..", "pentester")
if os.path.exists(_local_lib) and _local_lib not in sys.path:
    sys.path.insert(0, _local_lib)

SCANS: dict = {}


class _ScanLogger:
    """Thread-safe stdout redirector that appends to scan log list."""
    def __init__(self, scan_id: str):
        self._id = scan_id
        self._buf = ""

    def write(self, text: str):
        self._buf += text
        while "\\n" in self._buf:
            line, self._buf = self._buf.split("\\n", 1)
            line = line.strip()
            if line:
                # Strip ANSI colour codes
                import re
                line = re.sub(r"\\x1b\\[[0-9;]*m", "", line)
                SCANS[self._id]["logs"].append(line)

    def flush(self):
        pass


def _update(scan_id, **kwargs):
    SCANS[scan_id].update(kwargs)


def _run(scan_id: str, url: str, report_dir: str):
    scan = SCANS[scan_id]
    logger = _ScanLogger(scan_id)

    def log(msg):
        scan["logs"].append(msg)

    try:
        from config import TARGET_URL   # will be overridden below
        import config as _cfg
        _cfg.TARGET_URL = url

        # Also patch ZAP config
        zap_url = os.environ.get("ZAP_URL", "http://zap:8090")
        zap_key = os.environ.get("ZAP_KEY", "zapkey123")
        _cfg.ZAP_URL = zap_url
        _cfg.ZAP_KEY = zap_key

    except Exception:
        pass

    # ── Phase 1: Custom scanners ───────────────────────────────────────────
    _update(scan_id, phase="Phase 1: Custom Scanners", progress_pct=5)
    log("=" * 50)
    log("PHASE 1: Custom Python Scanners")
    log("=" * 50)

    custom_steps = [
        ("SQL Injection",     "scanners.sql_injection",   "SQLInjectionScanner"),
        ("XSS",               "scanners.xss_scanner",     "XSSScanner"),
        ("Authentication",    "scanners.auth_tester",     "AuthTester"),
        ("Path Traversal",    "scanners.dir_traversal",   "DirTraversalScanner"),
        ("Command Injection", "scanners.command_injection","CommandInjectionScanner"),
        ("IDOR",              "scanners.idor_scanner",    "IDORScanner"),
    ]

    all_findings = []
    total_steps  = len(custom_steps) + 4 + 1  # +4 tools, +1 AI
    step         = 0

    for name, module_path, class_name in custom_steps:
        if scan["status"] == "cancelled":
            return
        log(f"[*] Running {name} scanner...")
        try:
            import importlib
            mod = importlib.import_module(module_path)
            # Patch TARGET_URL inside scanner config
            import config as _cfg
            _cfg.TARGET_URL = url

            cls  = getattr(mod, class_name)
            with redirect_stdout(logger):
                findings = cls().run()
            all_findings.extend(findings)
            log(f"    → {len(findings)} finding(s)")
        except Exception as e:
            log(f"    [!] {name} error: {e}")

        step += 1
        _update(scan_id,
                phase=f"Phase 1: {name}",
                progress_pct=int(5 + (step / total_steps) * 40))

    # ── Phase 2: Real pentest tools ────────────────────────────────────────
    _update(scan_id, phase="Phase 2: Real Pentest Tools", progress_pct=45)
    log("")
    log("=" * 50)
    log("PHASE 2: Real Pentest Tools")
    log("=" * 50)

    tool_steps = [
        ("Nmap",      "scanners.nmap_scanner",   "NmapScanner"),
        ("Nikto",     "scanners.nikto_scanner",  "NiktoScanner"),
        ("SQLMap",    "scanners.sqlmap_scanner", "SQLMapScanner"),
        ("OWASP ZAP", "scanners.zap_scanner",    "ZAPScanner"),
    ]

    for name, module_path, class_name in tool_steps:
        if scan["status"] == "cancelled":
            return
        log(f"[*] Running {name}...")
        try:
            import importlib
            mod = importlib.import_module(module_path)
            import config as _cfg
            _cfg.TARGET_URL = url
            _cfg.ZAP_URL    = os.environ.get("ZAP_URL", "http://zap:8090")
            _cfg.ZAP_KEY    = os.environ.get("ZAP_KEY", "zapkey123")

            cls = getattr(mod, class_name)
            with redirect_stdout(logger):
                findings = cls().run()
            all_findings.extend(findings)
            log(f"    → {len(findings)} finding(s)")
        except Exception as e:
            log(f"    [!] {name} error: {e}")

        step += 1
        _update(scan_id,
                phase=f"Phase 2: {name}",
                progress_pct=int(45 + (step / total_steps) * 40))

    # ── AI Analysis ────────────────────────────────────────────────────────
    _update(scan_id, phase="AI Analysis", progress_pct=88)
    log("")
    log("[*] Running AI analysis...")
    try:
        import config as _cfg
        _cfg.OPENAI_KEY   = os.environ.get("OPENAI_API_KEY", "")
        _cfg.OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        from ai_analyzer import analyze
        with redirect_stdout(logger):
            analysis = analyze(all_findings)
        risk = analysis.get("risk_rating", "Unknown")
        log(f"    → Risk Rating: {risk}")
        log(f"    → {analysis.get('executive_summary','')[:120]}")
    except Exception as e:
        log(f"    [!] AI analysis error: {e}")
        analysis = {"risk_rating": "Unknown", "executive_summary": str(e),
                    "total_findings": len(all_findings),
                    "critical_count": 0, "high_count": 0,
                    "medium_count": 0, "low_count": 0,
                    "findings_analysis": [], "top_priorities": [],
                    "positive_findings": []}

    # ── Generate report ────────────────────────────────────────────────────
    _update(scan_id, phase="Generating Report", progress_pct=95)
    log("[*] Generating report...")
    try:
        import config as _cfg
        _cfg.TARGET_URL  = url
        _cfg.REPORT_DIR  = report_dir
        from report_generator import generate
        with redirect_stdout(logger):
            paths = generate(all_findings, analysis)

        with open(paths["html"], "r", encoding="utf-8") as f:
            report_html = f.read()

        import json as _json
        with open(paths["json"], "r") as f:
            report_json = _json.load(f)

        log(f"    → Report saved: {paths['html']}")

        _update(scan_id,
                status="complete",
                phase="Complete",
                progress_pct=100,
                total_findings=len(all_findings),
                risk_rating=analysis.get("risk_rating", "Unknown"),
                findings=all_findings,
                analysis=analysis,
                report_html=report_html,
                report_json=report_json,
                report_path=paths["html"],
                completed_at=datetime.utcnow().isoformat())
        log("[✓] Assessment complete!")

    except Exception as e:
        log(f"[!] Report error: {e}")
        _update(scan_id, status="error", error=str(e), phase="Error",
                progress_pct=100)


def run_scan_async(scan_id: str, url: str, report_dir: str):
    SCANS[scan_id] = {
        "id":             scan_id,
        "url":            url,
        "status":         "running",
        "phase":          "Starting...",
        "progress_pct":   0,
        "logs":           [],
        "findings":       [],
        "analysis":       {},
        "report_html":    None,
        "report_json":    None,
        "report_path":    None,
        "total_findings": 0,
        "risk_rating":    "",
        "error":          None,
        "started_at":     datetime.utcnow().isoformat(),
        "completed_at":   None,
    }
    t = threading.Thread(target=_run, args=(scan_id, url, report_dir), daemon=True)
    t.start()
'''

# ─────────────────────────────────────────────────────────────────────────────
# TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

FILES["dashboard/templates/base.html"] = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}AutoPenTest{% endblock %}</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    theme: { extend: { colors: {
      'cyber-green': '#00ff41',
      'cyber-blue':  '#00b4d8',
      'cyber-red':   '#ff003c',
    }}}
  }
</script>
<style>
  body { background: #0a0e17; color: #c9d1d9; font-family: 'Segoe UI', monospace; }
  .terminal { background: #0d1117; border: 1px solid #30363d; font-family: 'Courier New', monospace; }
  .glow-green { text-shadow: 0 0 10px #00ff41; }
  .glow-red   { text-shadow: 0 0 10px #ff003c; }
  .glow-blue  { text-shadow: 0 0 10px #00b4d8; }
  .badge-critical { background:#7f1d1d; color:#fca5a5; }
  .badge-high     { background:#7c2d12; color:#fdba74; }
  .badge-medium   { background:#713f12; color:#fde68a; }
  .badge-low      { background:#14532d; color:#86efac; }
  .badge-info     { background:#1e3a5f; color:#93c5fd; }
  @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:.3} }
  .pulse-dot { animation: pulse-dot 1.5s infinite; }
  ::-webkit-scrollbar { width:6px; }
  ::-webkit-scrollbar-track { background:#0d1117; }
  ::-webkit-scrollbar-thumb { background:#30363d; border-radius:3px; }
</style>
</head>
<body>
<nav class="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
  <a href="/" class="flex items-center gap-2">
    <span class="text-2xl">🔐</span>
    <span class="font-bold text-lg text-cyber-green glow-green">AutoPenTest</span>
    <span class="text-gray-500 text-sm ml-2">Web Security Scanner</span>
  </a>
  <div class="flex gap-4 text-sm text-gray-400">
    <a href="/" class="hover:text-white transition">Dashboard</a>
    <span class="text-gray-700">|</span>
    <span class="text-yellow-500">⚠ For authorized testing only</span>
  </div>
</nav>
<div class="max-w-6xl mx-auto px-4 py-8">
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

FILES["dashboard/templates/index.html"] = """\
{% extends "base.html" %}
{% block title %}AutoPenTest — Dashboard{% endblock %}
{% block content %}

<!-- Hero -->
<div class="text-center mb-10">
  <h1 class="text-4xl font-bold text-cyber-green glow-green mb-2">Automated Penetration Testing</h1>
  <p class="text-gray-400">Nmap · Nikto · SQLMap · OWASP ZAP · AI Analysis</p>
</div>

<!-- Scan Form -->
<div class="terminal rounded-xl p-8 mb-8 max-w-2xl mx-auto">
  <h2 class="text-cyber-blue font-bold text-lg mb-4 glow-blue">🎯 Start New Scan</h2>
  <form method="POST" action="/scan" id="scanForm">
    <div class="flex gap-3 mb-4">
      <input type="text" name="url" id="urlInput"
             placeholder="https://target-site.com"
             class="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white
                    placeholder-gray-600 focus:outline-none focus:border-cyber-blue focus:ring-1
                    focus:ring-cyber-blue transition"
             required>
      <button type="submit"
              class="bg-cyber-green text-black font-bold px-6 py-3 rounded-lg
                     hover:bg-green-400 transition flex items-center gap-2"
              id="scanBtn">
        <span>▶</span> Scan
      </button>
    </div>
    <label class="flex items-start gap-3 text-sm text-gray-400 cursor-pointer">
      <input type="checkbox" required class="mt-1 accent-cyber-green">
      <span>I confirm I have <strong class="text-white">written authorization</strong>
            to test this target. I accept all legal responsibility.</span>
    </label>
  </form>
  <div class="mt-4 flex flex-wrap gap-2">
    <span class="text-xs text-gray-600">Quick test targets:</span>
    <button onclick="setUrl('http://testphp.vulnweb.com')"
            class="text-xs bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded text-gray-300 transition">
      testphp.vulnweb.com
    </button>
    <button onclick="setUrl('http://localhost:5000')"
            class="text-xs bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded text-gray-300 transition">
      localhost:5000 (built-in)
    </button>
  </div>
</div>

<!-- Disclaimer -->
<div class="bg-yellow-900/20 border border-yellow-800 rounded-lg p-4 mb-8 max-w-2xl mx-auto">
  <p class="text-yellow-400 text-sm">
    ⚠️ <strong>Legal Notice:</strong> Only scan systems you own or have explicit written permission to test.
    Unauthorized scanning is illegal under the Computer Fraud and Abuse Act and similar laws worldwide.
  </p>
</div>

<!-- Scan History -->
{% if scans %}
<div class="terminal rounded-xl p-6">
  <h2 class="text-white font-bold text-lg mb-4">📋 Scan History</h2>
  <div class="overflow-x-auto">
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-gray-800 text-gray-400">
          <th class="text-left py-2 pr-4">ID</th>
          <th class="text-left py-2 pr-4">Target</th>
          <th class="text-left py-2 pr-4">Status</th>
          <th class="text-left py-2 pr-4">Risk</th>
          <th class="text-left py-2 pr-4">Findings</th>
          <th class="text-left py-2 pr-4">Started</th>
          <th class="text-left py-2">Actions</th>
        </tr>
      </thead>
      <tbody>
        {% for scan in scans %}
        <tr class="border-b border-gray-900 hover:bg-gray-900/50 transition">
          <td class="py-3 pr-4 font-mono text-cyber-blue">{{ scan.id }}</td>
          <td class="py-3 pr-4 text-white max-w-xs truncate">{{ scan.url }}</td>
          <td class="py-3 pr-4">
            {% if scan.status == 'complete' %}
              <span class="text-green-400">✓ Complete</span>
            {% elif scan.status == 'running' %}
              <span class="text-yellow-400 pulse-dot">⟳ Running</span>
            {% elif scan.status == 'error' %}
              <span class="text-red-400">✗ Error</span>
            {% elif scan.status == 'cancelled' %}
              <span class="text-gray-400">⊘ Cancelled</span>
            {% else %}
              <span class="text-gray-400">{{ scan.status }}</span>
            {% endif %}
          </td>
          <td class="py-3 pr-4">
            {% if scan.risk_rating %}
              {% set r = scan.risk_rating | lower %}
              <span class="px-2 py-1 rounded text-xs font-bold
                {% if r == 'critical' %}badge-critical
                {% elif r == 'high' %}badge-high
                {% elif r == 'medium' %}badge-medium
                {% else %}badge-low{% endif %}">
                {{ scan.risk_rating }}
              </span>
            {% else %}—{% endif %}
          </td>
          <td class="py-3 pr-4 text-white">{{ scan.total_findings or '—' }}</td>
          <td class="py-3 pr-4 text-gray-500 text-xs">{{ scan.started_at[:16] | replace('T',' ') }}</td>
          <td class="py-3">
            <div class="flex gap-2">
              <a href="/scan/{{ scan.id }}"
                 class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded text-gray-300 transition">
                View
              </a>
              {% if scan.report_html %}
              <a href="/scan/{{ scan.id }}/report"
                 class="text-xs bg-blue-900 hover:bg-blue-800 px-3 py-1 rounded text-blue-300 transition"
                 target="_blank">
                Report
              </a>
              {% endif %}
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% else %}
<div class="terminal rounded-xl p-12 text-center text-gray-600">
  <div class="text-5xl mb-3">🔍</div>
  <p>No scans yet. Enter a target URL above to begin.</p>
</div>
{% endif %}

<script>
  function setUrl(url) {
    document.getElementById('urlInput').value = url;
  }
  document.getElementById('scanForm').addEventListener('submit', function() {
    document.getElementById('scanBtn').textContent = '⟳ Starting...';
    document.getElementById('scanBtn').disabled = true;
  });
</script>
{% endblock %}
"""

FILES["dashboard/templates/scan.html"] = """\
{% extends "base.html" %}
{% block title %}Scan {{ scan.id }} — AutoPenTest{% endblock %}
{% block content %}

<!-- Header -->
<div class="flex items-center justify-between mb-6">
  <div>
    <a href="/" class="text-gray-500 hover:text-white text-sm transition">← Dashboard</a>
    <h1 class="text-2xl font-bold text-white mt-1">
      Scan <span class="text-cyber-blue font-mono">{{ scan.id }}</span>
    </h1>
    <p class="text-gray-400 text-sm mt-1">🎯 {{ scan.url }}</p>
  </div>
  <div class="flex gap-3">
    {% if scan.status == 'running' %}
    <form method="POST" action="/scan/{{ scan.id }}/cancel">
      <button class="bg-red-900 hover:bg-red-800 text-red-300 px-4 py-2 rounded text-sm transition">
        ⊘ Cancel
      </button>
    </form>
    {% endif %}
    {% if scan.report_html %}
    <a href="/scan/{{ scan.id }}/report" target="_blank"
       class="bg-cyber-blue/20 hover:bg-cyber-blue/30 text-cyber-blue px-4 py-2 rounded text-sm transition">
      📄 Full Report
    </a>
    <a href="/scan/{{ scan.id }}/download/json"
       class="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded text-sm transition">
      ⬇ JSON
    </a>
    {% endif %}
  </div>
</div>

<!-- Status Card -->
<div class="terminal rounded-xl p-6 mb-6" id="statusCard">
  <div class="flex items-center justify-between mb-3">
    <div class="flex items-center gap-3">
      <span id="statusIcon" class="text-2xl">
        {% if scan.status == 'complete' %}✅
        {% elif scan.status == 'error' %}❌
        {% elif scan.status == 'cancelled' %}⊘
        {% else %}⟳{% endif %}
      </span>
      <div>
        <div class="font-bold text-white" id="phaseText">{{ scan.phase }}</div>
        <div class="text-sm text-gray-400">
          Started: {{ scan.started_at[:16] | replace('T',' ') }} UTC
          {% if scan.completed_at %}
            · Finished: {{ scan.completed_at[:16] | replace('T',' ') }} UTC
          {% endif %}
        </div>
      </div>
    </div>
    <div id="riskBadge" class="text-right">
      {% if scan.risk_rating %}
        {% set r = scan.risk_rating | lower %}
        <span class="px-4 py-2 rounded-lg text-sm font-bold
          {% if r == 'critical' %}badge-critical
          {% elif r == 'high' %}badge-high
          {% elif r == 'medium' %}badge-medium
          {% else %}badge-low{% endif %}">
          {{ scan.risk_rating }} RISK
        </span>
      {% endif %}
    </div>
  </div>
  <!-- Progress bar -->
  <div class="bg-gray-800 rounded-full h-2">
    <div id="progressBar"
         class="bg-cyber-green h-2 rounded-full transition-all duration-500"
         style="width: {{ scan.progress_pct }}%"></div>
  </div>
  <div class="text-xs text-gray-500 mt-1 text-right" id="progressPct">{{ scan.progress_pct }}%</div>
</div>

<!-- Stats (shown when complete) -->
<div id="statsRow" class="grid grid-cols-4 gap-4 mb-6
     {{ 'hidden' if not scan.total_findings else '' }}">
  <div class="terminal rounded-xl p-4 text-center border-t-2 border-red-700">
    <div class="text-3xl font-bold text-red-400" id="statCritical">
      {{ scan.analysis.critical_count if scan.analysis else 0 }}
    </div>
    <div class="text-xs text-gray-500 mt-1">CRITICAL</div>
  </div>
  <div class="terminal rounded-xl p-4 text-center border-t-2 border-orange-700">
    <div class="text-3xl font-bold text-orange-400" id="statHigh">
      {{ scan.analysis.high_count if scan.analysis else 0 }}
    </div>
    <div class="text-xs text-gray-500 mt-1">HIGH</div>
  </div>
  <div class="terminal rounded-xl p-4 text-center border-t-2 border-yellow-700">
    <div class="text-3xl font-bold text-yellow-400" id="statMedium">
      {{ scan.analysis.medium_count if scan.analysis else 0 }}
    </div>
    <div class="text-xs text-gray-500 mt-1">MEDIUM</div>
  </div>
  <div class="terminal rounded-xl p-4 text-center border-t-2 border-green-700">
    <div class="text-3xl font-bold text-green-400" id="statLow">
      {{ scan.analysis.low_count if scan.analysis else 0 }}
    </div>
    <div class="text-xs text-gray-500 mt-1">LOW</div>
  </div>
</div>

<!-- Two-column: logs + report summary -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

  <!-- Live Log Terminal -->
  <div class="terminal rounded-xl p-4">
    <div class="flex items-center gap-2 mb-3">
      <div class="w-3 h-3 rounded-full bg-red-500"></div>
      <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
      <div class="w-3 h-3 rounded-full bg-green-500"></div>
      <span class="text-gray-500 text-xs ml-2">scan.log</span>
      {% if scan.status == 'running' %}
      <span class="ml-auto text-xs text-yellow-400 pulse-dot">● LIVE</span>
      {% endif %}
    </div>
    <div id="logBox"
         class="h-96 overflow-y-auto text-xs text-green-400 leading-relaxed space-y-0.5"
         style="font-family: 'Courier New', monospace">
      {% for line in scan.logs %}
      <div class="{% if '[!]' in line %}text-red-400{% elif '[*]' in line %}text-cyber-blue
                  {% elif '[✓]' in line or '→' in line %}text-green-400
                  {% elif '===' in line %}text-yellow-400 font-bold
                  {% else %}text-gray-400{% endif %}">{{ line }}</div>
      {% endfor %}
    </div>
  </div>

  <!-- AI Summary / Findings -->
  <div class="terminal rounded-xl p-4">
    <h3 class="text-white font-bold mb-3">🤖 AI Analysis Summary</h3>
    {% if scan.analysis and scan.analysis.executive_summary %}
    <p class="text-gray-300 text-sm mb-4 leading-relaxed">
      {{ scan.analysis.executive_summary }}
    </p>
    {% if scan.analysis.top_priorities %}
    <h4 class="text-cyber-blue text-sm font-bold mb-2">⚡ Top Priorities</h4>
    <ul class="space-y-2 mb-4">
      {% for p in scan.analysis.top_priorities %}
      <li class="text-sm text-gray-300 bg-blue-900/20 border border-blue-900 rounded px-3 py-2">
        {{ p }}
      </li>
      {% endfor %}
    </ul>
    {% endif %}
    {% if scan.analysis.findings_analysis %}
    <h4 class="text-cyber-blue text-sm font-bold mb-2">🔍 Vulnerabilities Found</h4>
    <div class="space-y-2 max-h-52 overflow-y-auto">
      {% for fa in scan.analysis.findings_analysis %}
      <div class="bg-gray-900 rounded px-3 py-2 text-xs">
        <div class="flex justify-between items-center">
          <span class="text-white font-semibold">{{ fa.type }}</span>
          <span class="{% if fa.cvss_score >= 9 %}text-red-400
                       {% elif fa.cvss_score >= 7 %}text-orange-400
                       {% elif fa.cvss_score >= 4 %}text-yellow-400
                       {% else %}text-green-400{% endif %} font-mono">
            CVSS {{ fa.cvss_score }}
          </span>
        </div>
        <p class="text-gray-400 mt-1">{{ fa.attack_scenario[:100] }}...</p>
      </div>
      {% endfor %}
    </div>
    {% endif %}
    <div class="mt-4">
      <a href="/scan/{{ scan.id }}/report" target="_blank"
         class="w-full block text-center bg-cyber-green text-black font-bold py-2 rounded
                hover:bg-green-400 transition text-sm">
        📊 View Full Report
      </a>
    </div>
    {% elif scan.status == 'running' %}
    <div class="flex flex-col items-center justify-center h-64 text-gray-600">
      <div class="text-5xl mb-3 pulse-dot">🔍</div>
      <p>Scanning in progress...</p>
      <p class="text-xs mt-2" id="phaseHint">{{ scan.phase }}</p>
    </div>
    {% else %}
    <div class="flex flex-col items-center justify-center h-64 text-gray-600">
      <div class="text-5xl mb-3">⏳</div>
      <p>Waiting for scan to complete...</p>
    </div>
    {% endif %}
  </div>

</div>

<script>
const scanId    = "{{ scan.id }}";
const initStatus = "{{ scan.status }}";
let logOffset   = {{ scan.logs | length }};
let pollTimer   = null;

function severityColor(s) {
  const m = {'CRITICAL':'text-red-400','HIGH':'text-orange-400',
             'MEDIUM':'text-yellow-400','LOW':'text-green-400'};
  return m[s] || 'text-gray-400';
}

function logClass(line) {
  if (line.includes('[!]'))  return 'text-red-400';
  if (line.includes('[*]'))  return 'text-cyber-blue';
  if (line.includes('[✓]') || line.includes('→')) return 'text-green-400';
  if (line.includes('===')) return 'text-yellow-400 font-bold';
  return 'text-gray-400';
}

async function fetchLogs() {
  try {
    const r = await fetch(`/scan/${scanId}/logs?offset=${logOffset}`);
    const lines = await r.json();
    if (lines.length > 0) {
      const box = document.getElementById('logBox');
      lines.forEach(line => {
        const d = document.createElement('div');
        d.className = logClass(line);
        d.textContent = line;
        box.appendChild(d);
      });
      logOffset += lines.length;
      box.scrollTop = box.scrollHeight;
    }
  } catch(e) {}
}

async function fetchStatus() {
  try {
    const r  = await fetch(`/scan/${scanId}/status`);
    const st = await r.json();

    // Update progress bar
    document.getElementById('progressBar').style.width = st.progress_pct + '%';
    document.getElementById('progressPct').textContent = st.progress_pct + '%';
    document.getElementById('phaseText').textContent   = st.phase;

    // Update risk badge
    if (st.risk_rating) {
      const cls = {'Critical':'badge-critical','High':'badge-high',
                   'Medium':'badge-medium','Low':'badge-low'}[st.risk_rating] || 'badge-low';
      document.getElementById('riskBadge').innerHTML =
        `<span class="px-4 py-2 rounded-lg text-sm font-bold ${cls}">${st.risk_rating} RISK</span>`;
    }

    if (st.status !== 'running') {
      clearInterval(pollTimer);
      document.getElementById('statusIcon').textContent =
        st.status === 'complete' ? '✅' : st.status === 'error' ? '❌' : '⊘';

      if (st.has_report) {
        setTimeout(() => location.reload(), 1000);
      }
    }
  } catch(e) {}
}

if (initStatus === 'running') {
  pollTimer = setInterval(async () => {
    await fetchLogs();
    await fetchStatus();
  }, 2000);
}

// Auto-scroll log on load
window.addEventListener('load', () => {
  const box = document.getElementById('logBox');
  box.scrollTop = box.scrollHeight;
});
</script>
{% endblock %}
"""

# ─────────────────────────────────────────────────────────────────────────────
# UPDATE docker-compose.yml content (appended to FILES for reference)
# ─────────────────────────────────────────────────────────────────────────────
DOCKER_COMPOSE = """\
version: '3.9'

services:

  webapp:
    build:
      context: ./webapp
      dockerfile: Dockerfile
    container_name: vulnapp
    ports:
      - "5000:5000"
    environment:
      - DB_PATH=/tmp/webapp.db
      - FLASK_ENV=development
    networks:
      - pentest-net
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/')"]
      interval: 10s
      timeout: 5s
      retries: 8

  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    container_name: zap
    command: >
      zap.sh -daemon
      -host 0.0.0.0 -port 8090
      -config api.addrs.addr.name=.*
      -config api.addrs.addr.regex=true
      -config api.key=zapkey123
      -config scanner.threadPerHost=5
    ports:
      - "8090:8090"
    networks:
      - pentest-net
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8090/JSON/core/view/version/?apikey=zapkey123"]
      interval: 15s
      timeout: 10s
      retries: 10
      start_period: 30s

  dashboard:
    build:
      context: .
      dockerfile: dashboard/Dockerfile
    container_name: pentest_dashboard
    ports:
      - "8080:8080"
    environment:
      - ZAP_URL=http://zap:8090
      - ZAP_KEY=zapkey123
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o-mini}
      - REPORT_DIR=/reports
    volumes:
      - ./reports:/reports
    networks:
      - pentest-net
    depends_on:
      - zap

networks:
  pentest-net:
    driver: bridge
"""


def main():
    import textwrap

    # Write dashboard files
    created = 0
    for rel_path, content in FILES.items():
        abs_path = os.path.join(BASE, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✓  {rel_path}")
        created += 1

    # Overwrite docker-compose.yml to add dashboard service
    compose_path = os.path.join(BASE, "docker-compose.yml")
    with open(compose_path, "w", encoding="utf-8") as f:
        f.write(DOCKER_COMPOSE)
    print(f"  ✓  docker-compose.yml (updated)")

    print(f"\n✅  Created {created} files + updated docker-compose.yml")
    print("\nNext steps:")
    print("  docker-compose up --build")
    print("  Open http://localhost:8080  ← Web dashboard")
    print("  Enter any URL and click Scan!")


if __name__ == "__main__":
    main()
