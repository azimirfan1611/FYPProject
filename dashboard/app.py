"""
AutoPenTest Web Dashboard — Enterprise Edition
Phase 1: Security hardened — JWT auth, SSRF protection, rate limiting,
         XSS-safe log rendering, race-condition-safe SCANS access.
"""
import os, sys, uuid, json, ipaddress, secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps
from collections import defaultdict, deque
import threading

from flask import (Flask, render_template, request, redirect,
                   url_for, jsonify, Response, session, flash)

try:
    from flask_socketio import SocketIO, join_room, emit
    _SOCKETIO = True
except ImportError:
    socketio = None
    _SOCKETIO = False

sys.path.insert(0, "/app/pentest_lib")
_local = os.path.join(os.path.dirname(__file__), "..", "pentester")
if os.path.exists(_local) and _local not in sys.path:
    sys.path.insert(0, _local)

from scanner_runner import run_scan_async, SCANS, SCANS_LOCK, evict_old_scans

import logging as _logging
_log_handler = _logging.StreamHandler()
_log_handler.setFormatter(_logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'))
_logging.basicConfig(handlers=[_log_handler], level=_logging.INFO, force=True)
logger = _logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
if _SOCKETIO:
    from flask_socketio import SocketIO, join_room, emit
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
except ImportError:
    pass
app.config["WTF_CSRF_ENABLED"] = True

REPORT_DIR   = os.environ.get("REPORT_DIR", "/reports")
JWT_SECRET   = os.environ.get("JWT_SECRET",  secrets.token_hex(32))
JWT_EXPIRY_H = int(os.environ.get("JWT_EXPIRY_HOURS", "24"))
ADMIN_USER   = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS   = os.environ.get("ADMIN_PASS", "changeme123!")
ADMIN_ROLE = os.environ.get("ADMIN_ROLE", "admin")  # admin | analyst | viewer
_USER_ROLES = {ADMIN_USER: ADMIN_ROLE}
os.makedirs(REPORT_DIR, exist_ok=True)

# Start background scheduler
try:
    from scheduler import start as _start_scheduler
    _start_scheduler()
except Exception:
    pass

# ── Rate limiting (in-process) ─────────────────────────────────────────────
_rate_lock = threading.Lock()
_req_times  = defaultdict(lambda: deque())
RATE_LIMIT  = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))
SCAN_LIMIT  = int(os.environ.get("SCAN_LIMIT_PER_MIN", "3"))

def _check_rate(ip: str, bucket: str, limit: int) -> bool:
    key = f"{bucket}:{ip}"
    now = datetime.utcnow().timestamp()
    with _rate_lock:
        dq = _req_times[key]
        while dq and dq[0] < now - 60:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

# ── Account lockout ────────────────────────────────────────────────────────
_lockout_lock = threading.Lock()
_failed_attempts: dict = {}  # username -> (count, first_attempt_time)
LOCKOUT_ATTEMPTS = int(os.environ.get("LOCKOUT_ATTEMPTS", "5"))
LOCKOUT_MINUTES  = int(os.environ.get("LOCKOUT_MINUTES", "30"))

def _is_locked_out(username: str) -> bool:
    with _lockout_lock:
        entry = _failed_attempts.get(username)
        if not entry:
            return False
        count, first_time = entry
        if count >= LOCKOUT_ATTEMPTS:
            elapsed = (datetime.utcnow() - first_time).total_seconds() / 60
            if elapsed < LOCKOUT_MINUTES:
                return True
            else:
                del _failed_attempts[username]
        return False

def _record_failed(username: str):
    with _lockout_lock:
        entry = _failed_attempts.get(username)
        if entry:
            count, first_time = entry
            _failed_attempts[username] = (count + 1, first_time)
        else:
            _failed_attempts[username] = (1, datetime.utcnow())

def _clear_failed(username: str):
    with _lockout_lock:
        _failed_attempts.pop(username, None)

# ── SSRF Protection ────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
_BLOCKED_HOSTS = frozenset({
    "169.254.169.254", "metadata.google.internal",
    "metadata", "localhost", "0.0.0.0",
})

def _is_safe_url(url: str) -> tuple:
    """Return (is_safe: bool, reason: str)."""
    try:
        p = urlparse(url)
    except Exception:
        return False, "Invalid URL"
    if p.scheme not in ("http", "https"):
        return False, f"Scheme '{p.scheme}' not allowed"
    host = (p.hostname or "").lower().strip(".")
    if not host:
        return False, "Missing hostname"
    if host in _BLOCKED_HOSTS:
        return False, f"Host '{host}' is blocked"
    try:
        addr = ipaddress.ip_address(host)
        for net in _PRIVATE_NETS:
            if addr in net:
                return False, f"Private IP range blocked: {host}"
    except ValueError:
        pass  # hostname — DNS resolves at scan time
    if "169.254.169.254" in (p.path or ""):
        return False, "Metadata endpoint blocked"
    return True, ""

# ── JWT Auth ───────────────────────────────────────────────────────────────
try:
    import jwt as pyjwt
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

_token_blacklist: set = set()
_blacklist_lock = threading.Lock()

def _make_token(username: str) -> str:
    if not _JWT_AVAILABLE:
        return f"simple:{username}"
    payload = {"sub": username,
               "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_H),
               "iat": datetime.utcnow()}
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _verify_token(token: str):
    if not token:
        return None
    with _blacklist_lock:
        if token in _token_blacklist:
            return None
    if not _JWT_AVAILABLE:
        return token.replace("simple:", "") if token.startswith("simple:") else None
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token") or request.headers.get("X-Auth-Token")
        if not _verify_token(token):
            if request.is_json:
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = session.get("token") or request.headers.get("X-Auth-Token")
            username = _verify_token(token)
            if not username:
                return jsonify({"error": "authentication required"}), 401
            role = _USER_ROLES.get(username, "viewer")
            if role not in allowed_roles:
                if request.is_json:
                    return jsonify({"error": "insufficient privileges"}), 403
                flash("Insufficient privileges to perform this action.", "error")
                return redirect(url_for("index"))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ── Auth Routes ────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if not _check_rate(ip, "login", 10):
            error = "Too many login attempts. Please wait."
        else:
            u = request.form.get("username", "")
            p = request.form.get("password", "")
            if _is_locked_out(u):
                error = f"Account locked. Try again in {LOCKOUT_MINUTES} minutes."
            else:
                u_ok = secrets.compare_digest(u.encode(), ADMIN_USER.encode())
                p_ok = secrets.compare_digest(p.encode(), ADMIN_PASS.encode())
                logger.info(f"Login attempt: user={u} ip={ip} success={u_ok and p_ok}")
                if u_ok and p_ok:
                    session["token"] = _make_token(u)
                    _clear_failed(u)
                    return redirect(url_for("index"))
                error = "Invalid credentials"
                _record_failed(u)
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    token = session.get("token")
    if token:
        with _blacklist_lock:
            _token_blacklist.add(token)
    session.clear()
    return redirect(url_for("login_page"))

# ── Dashboard Routes ───────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    evict_old_scans()
    page     = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    with SCANS_LOCK:
        all_scans = sorted(SCANS.values(), key=lambda s: s["started_at"], reverse=True)
    total   = len(all_scans)
    start   = (page - 1) * per_page
    history = all_scans[start:start + per_page]
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("index.html", scans=history,
                           page=page, total_pages=total_pages, total=total)

@app.route("/scan", methods=["POST"])
@login_required
@role_required("admin", "analyst")
def start_scan():
    ip = request.remote_addr or "unknown"
    if not _check_rate(ip, "scan", SCAN_LIMIT):
        flash("Rate limit: max 3 scans per minute.", "error")
        return redirect(url_for("index"))
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("index"))
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    safe, reason = _is_safe_url(url)
    if not safe:
        flash(f"URL rejected: {reason}", "error")
        return redirect(url_for("index"))
    scan_id = str(uuid.uuid4())[:8]
    run_scan_async(scan_id, url, REPORT_DIR)
    return redirect(url_for("scan_view", scan_id=scan_id))

@app.route("/scan/<scan_id>")
@login_required
def scan_view(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template("scan.html", scan=scan)

def _calc_eta(scan: dict) -> int:
    """Rough ETA in seconds based on progress."""
    pct = scan.get("progress_pct", 0)
    if pct <= 0 or scan["status"] != "running":
        return 0
    started = scan.get("started_at", "")
    try:
        elapsed = (datetime.utcnow() - datetime.fromisoformat(started)).total_seconds()
        if pct > 0:
            total_est = elapsed / (pct / 100)
            return max(0, int(total_est - elapsed))
    except Exception:
        pass
    return 0


@app.route("/scan/<scan_id>/status")
@login_required
def scan_status(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status":         scan["status"],
        "phase":          scan["phase"],
        "progress_pct":   scan["progress_pct"],
        "log_count":      len(scan["logs"]),
        "has_report":     bool(scan.get("report_html")),
        "total_findings": scan.get("total_findings", 0),
        "risk_rating":    scan.get("risk_rating", ""),
        "error":          scan.get("error"),
        "eta_seconds":    _calc_eta(scan),
    })

@app.route("/scan/<scan_id>/logs")
@login_required
def scan_logs(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan:
        return jsonify([])
    offset = int(request.args.get("offset", 0))
    return jsonify(scan["logs"][offset:])

@app.route("/scan/<scan_id>/report")
@login_required
def scan_report(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_html"):
        return "Report not ready yet", 404
    return scan["report_html"]

@app.route("/scan/<scan_id>/download/json")
@login_required
def download_json(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_json"):
        return "Not available", 404
    return Response(
        json.dumps(scan["report_json"], indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.json"}
    )

@app.route("/scan/<scan_id>/download/sarif")
@login_required
def download_sarif(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan or not scan.get("findings"):
        return "Not available", 404
    try:
        from sarif_generator import generate_sarif
        sarif = generate_sarif(scan["findings"], scan["url"])
        return Response(
            json.dumps(sarif, indent=2),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.sarif"}
        )
    except Exception as e:
        return f"SARIF error: {e}", 500

@app.route("/scan/<scan_id>/download/pdf")
@login_required
def download_pdf(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if not scan or not scan.get("report_html"):
        return "Report not ready", 404
    try:
        from weasyprint import HTML as WP
        pdf = WP(string=scan["report_html"]).write_pdf()
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f"attachment; filename=report_{scan_id}.pdf"})
    except ImportError:
        return "PDF requires weasyprint (not installed)", 501
    except Exception as e:
        return f"PDF error: {e}", 500

@app.route("/scan/<scan_id>/cancel", methods=["POST"])
@login_required
@role_required("admin", "analyst")
def cancel_scan(scan_id):
    with SCANS_LOCK:
        scan = SCANS.get(scan_id)
    if scan and scan["status"] == "running":
        scan["status"] = "cancelled"
        scan["phase"]  = "Cancelled by user"
    return redirect(url_for("scan_view", scan_id=scan_id))

@app.route("/trends")
@login_required
def trends():
    with SCANS_LOCK:
        completed = [s for s in SCANS.values() if s["status"] == "complete"]
    completed.sort(key=lambda s: s["started_at"])
    return render_template("trends.html", scans=completed)


@app.route("/news")
@login_required
def news():
    try:
        from threat_feed import get_all
        force = request.args.get("refresh") == "1"
        data  = get_all(force=force)
    except Exception as e:
        data = {
            "news": [{"source": "Error", "title": str(e), "url": "#",
                      "summary": "", "date": "", "tags": [], "cves": []}],
            "cisa_kev": [], "nvd_recent": [],
            "updated_at": "unavailable",
            "severity_colors": {},
        }
    return render_template("news.html", **data)

# ── REST API (CI/CD integration) ───────────────────────────────────────────
@app.route("/api/scans")
@login_required
def api_scans():
    with SCANS_LOCK:
        scans = list(SCANS.values())
    return jsonify([{
        "id": s["id"], "url": s["url"], "status": s["status"],
        "risk_rating": s.get("risk_rating"), "total_findings": s.get("total_findings", 0),
        "started_at": s["started_at"], "completed_at": s.get("completed_at"),
    } for s in scans])

@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    """CI/CD endpoint: POST JSON {url, api_key} or X-Auth-Token header."""
    data    = request.get_json(silent=True) or {}
    api_key = data.get("api_key") or request.headers.get("X-Auth-Token")
    if not _verify_token(api_key):
        return jsonify({"error": "authentication required"}), 401
    ip = request.remote_addr or "unknown"
    if not _check_rate(ip, "scan", SCAN_LIMIT):
        return jsonify({"error": "rate limit exceeded"}), 429
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": f"URL rejected: {reason}"}), 400
    scan_id = str(uuid.uuid4())[:8]
    run_scan_async(scan_id, url, REPORT_DIR)
    return jsonify({"scan_id": scan_id, "status": "started",
                    "poll_url": f"/scan/{scan_id}/status"})

@app.route("/api/token", methods=["POST"])
def api_get_token():
    """Get JWT token for API use."""
    data = request.get_json(silent=True) or {}
    u = data.get("username", "")
    p = data.get("password", "")
    if (secrets.compare_digest(u.encode(), ADMIN_USER.encode()) and
            secrets.compare_digest(p.encode(), ADMIN_PASS.encode())):
        return jsonify({"token": _make_token(u)})
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/compare/<scan_id1>/<scan_id2>")
@login_required
def compare_scans(scan_id1, scan_id2):
    with SCANS_LOCK:
        s1 = SCANS.get(scan_id1)
        s2 = SCANS.get(scan_id2)
    if not s1 or not s2:
        return "One or both scans not found", 404

    def _finding_key(f):
        return f"{f.get('type','').lower()}|{f.get('endpoint','').lower()}"

    f1_keys = {_finding_key(f) for f in (s1.get("findings") or [])}
    f2_keys = {_finding_key(f) for f in (s2.get("findings") or [])}
    new_findings   = [f for f in (s2.get("findings") or []) if _finding_key(f) not in f1_keys]
    fixed_findings = [f for f in (s1.get("findings") or []) if _finding_key(f) not in f2_keys]
    common_findings = [f for f in (s2.get("findings") or []) if _finding_key(f) in f1_keys]

    return render_template("compare.html",
        scan1=s1, scan2=s2,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        common_findings=common_findings,
    )


# ── Scheduler Routes ───────────────────────────────────────────────────────
@app.route("/schedules")
@login_required
def schedules_page():
    try:
        from scheduler import list_schedules
        scheds = list_schedules()
    except Exception:
        scheds = []
    return render_template("schedules.html", schedules=scheds,
                           scheduler_available=True)

@app.route("/schedules/add", methods=["POST"])
@login_required
@role_required("admin")
def add_schedule_route():
    url      = request.form.get("url", "").strip()
    cron     = request.form.get("cron", "").strip()
    sched_id = str(uuid.uuid4())[:8]
    if url and cron:
        try:
            from scheduler import add_schedule
            add_schedule(sched_id, url, cron, REPORT_DIR)
            flash(f"Schedule {sched_id} created.", "success")
        except Exception as e:
            flash(f"Failed: {e}", "error")
    return redirect(url_for("schedules_page"))

@app.route("/schedules/<sched_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_schedule(sched_id):
    try:
        from scheduler import remove_schedule
        remove_schedule(sched_id)
        flash(f"Schedule {sched_id} deleted.", "success")
    except Exception as e:
        flash(f"Failed: {e}", "error")
    return redirect(url_for("schedules_page"))


if _SOCKETIO and socketio:
    @socketio.on("subscribe_scan")
    def on_subscribe(data):
        scan_id = data.get("scan_id", "")
        join_room(f"scan_{scan_id}")


if __name__ == "__main__":
    if _SOCKETIO and socketio:
        socketio.run(app, host="0.0.0.0", port=8080, debug=False, allow_unsafe_werkzeug=True)
    else:
        app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
