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
import pytz

from flask import (Flask, render_template, request, redirect,
                   url_for, jsonify, Response, session, flash)

from timezone_utils import (get_user_timezone, utc_to_local, format_scan_time, 
                           format_scan_duration, get_timezone_offset, COMMON_TIMEZONES)

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

# AI Chatbot integration
try:
    from ai_chatbot import get_chatbot
    from chat_context import get_chat_context
    _CHATBOT_AVAILABLE = True
except ImportError:
    _CHATBOT_AVAILABLE = False

import logging as _logging
_log_handler = _logging.StreamHandler()
_log_handler.setFormatter(_logging.Formatter('{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'))
_logging.basicConfig(handlers=[_log_handler], level=_logging.INFO, force=True)
logger = _logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["WTF_CSRF_ENABLED"] = False
app.config["WTF_CSRF_CHECK_DEFAULT"] = False

try:
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
except ImportError:
    app.config["WTF_CSRF_ENABLED"] = False
    # Define a dummy csrf object for decorators
    class _DummyCSRF:
        def exempt(self, f):
            return f
    csrf = _DummyCSRF()

if _SOCKETIO:
    from flask_socketio import SocketIO, join_room, emit
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Add context processor for authentication status
@app.context_processor
def inject_authenticated():
    """Make is_authenticated and utilities available in all templates"""
    from ai_chatbot import get_chatbot
    chatbot = get_chatbot()
    
    # Get user's timezone from session or browser
    user_tz = get_user_timezone(session)
    
    return {
        'is_authenticated': bool(session.get('token')),
        'cron_to_readable': chatbot.cron_to_readable if chatbot else lambda x: x,
        'user_timezone': user_tz,
        'timezone_offset': get_timezone_offset(user_tz),
    }

# Register Jinja filters for timezone conversion
@app.template_filter('to_local_time')
def jinja_to_local_time(utc_str, format_style='full'):
    """Jinja filter: Convert UTC time to local time"""
    user_tz = get_user_timezone(session)
    return format_scan_time(utc_str, user_tz, format_style)

@app.template_filter('scan_duration')
def jinja_scan_duration(started_str, completed_str=None):
    """Jinja filter: Format scan duration"""
    user_tz = get_user_timezone(session)
    return format_scan_duration(started_str, completed_str, user_tz)

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
    # ALLOW 127.0.0.1 for validation lab scanning
    # ipaddress.ip_network("127.0.0.0/8"),  # ← DISABLED for lab testing
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]
_BLOCKED_HOSTS = frozenset({
    "169.254.169.254", "metadata.google.internal",
    "metadata", "0.0.0.0",
    # ALLOW localhost for lab testing
    # "localhost",  # ← DISABLED for lab testing
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
                    # Set timezone to Singapore by default (most users are in Asia)
                    if 'timezone' not in session:
                        session['timezone'] = 'Asia/Singapore'
                    session.modified = True
                    _clear_failed(u)
                    return redirect(url_for("index"))
                error = "Invalid credentials"
                _record_failed(u)
    return render_template("login.html", error=error, is_authenticated=False)

@app.route("/api/set-timezone", methods=["POST"])
@login_required
def set_timezone():
    """Set user's timezone from browser detection"""
    data = request.get_json() or {}
    timezone = data.get('timezone', 'Asia/Singapore')
    
    # Validate timezone
    try:
        pytz.timezone(timezone)
        session['timezone'] = timezone
        session.modified = True  # Ensure session is saved
        logger.info(f"Timezone set for user: {timezone}")
        return jsonify({"success": True, "timezone": timezone})
    except Exception as e:
        logger.warning(f"Invalid timezone: {timezone} - {e}")
        return jsonify({"error": "Invalid timezone"}), 400

@app.route("/logout")
def logout():
    token = session.get("token")
    if token:
        with _blacklist_lock:
            _token_blacklist.add(token)
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/debug/chatbox")
def debug_chatbox():
    """Debug page for chatbox issues"""
    return render_template("chatbox_debug.html", is_authenticated=bool(session.get('token')))

# ── Dashboard Routes ───────────────────────────────────────────────────────
@app.route("/landing")
def landing():
    """Original premium SaaS landing page"""
    return render_template("landing-original.html", is_authenticated=False)

@app.route("/")
def homepage():
    """Homepage - redirect to landing or dashboard based on auth"""
    if session.get("token"):
        return redirect(url_for("index"))
    return redirect(url_for("landing"))

@app.route("/dashboard")
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
        scan["completed_at"] = datetime.utcnow().isoformat()
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

# ── Task/Scan Access for Chatbox ───────────────────────────────────────────
@app.route("/api/tasks")
@login_required
def api_tasks():
    """Get all security scan tasks (optimized for AI chatbox)"""
    limit = request.args.get("limit", 50, type=int)
    status_filter = request.args.get("status", None)
    
    with SCANS_LOCK:
        scans = list(SCANS.values())
    
    # Filter by status if provided
    if status_filter:
        scans = [s for s in scans if s["status"] == status_filter]
    
    # Sort by most recent first
    scans.sort(key=lambda s: s["started_at"], reverse=True)
    scans = scans[:limit]
    
    return jsonify({
        "tasks": [{
            "id": s["id"],
            "url": s["url"],
            "status": s["status"],
            "phase": s.get("phase", ""),
            "progress_pct": s.get("progress_pct", 0),
            "risk_rating": s.get("risk_rating", ""),
            "total_findings": s.get("total_findings", 0),
            "started_at": s["started_at"],
            "completed_at": s.get("completed_at"),
            "critical_count": len([f for f in s.get("findings", []) if f.get("severity", "").upper() == "CRITICAL"]),
            "high_count": len([f for f in s.get("findings", []) if f.get("severity", "").upper() == "HIGH"]),
        } for s in scans],
        "total_count": len(list(SCANS.values()))
    })

@app.route("/api/tasks/<task_id>")
@login_required
def api_task_details(task_id):
    """Get detailed information about a specific task"""
    with SCANS_LOCK:
        scan = SCANS.get(task_id)
    
    if not scan:
        return jsonify({"error": "Task not found"}), 404
    
    # Group findings by severity
    findings_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for finding in scan.get("findings", []):
        severity = finding.get("severity", "INFO").upper()
        if severity in findings_by_severity:
            findings_by_severity[severity].append({
                "title": finding.get("title"),
                "description": finding.get("description"),
                "endpoint": finding.get("endpoint"),
                "scanner": finding.get("scanner")
            })
    
    return jsonify({
        "id": scan["id"],
        "url": scan["url"],
        "status": scan["status"],
        "phase": scan.get("phase", ""),
        "progress_pct": scan.get("progress_pct", 0),
        "risk_rating": scan.get("risk_rating", ""),
        "total_findings": scan.get("total_findings", 0),
        "started_at": scan["started_at"],
        "completed_at": scan.get("completed_at"),
        "findings_by_severity": findings_by_severity,
        "summary": {
            "critical": len(findings_by_severity["CRITICAL"]),
            "high": len(findings_by_severity["HIGH"]),
            "medium": len(findings_by_severity["MEDIUM"]),
            "low": len(findings_by_severity["LOW"]),
            "info": len(findings_by_severity["INFO"])
        }
    })


# ── Chatbox Scan Control API ───────────────────────────────────────────────
@app.route("/api/scan-now", methods=["POST"])
@login_required
@csrf.exempt
def api_scan_now():
    """Start a security scan immediately from chatbox"""
    if not _CHATBOT_AVAILABLE:
        return jsonify({"error": "Scan not available", "status": "error"}), 503
    
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    
    if not url:
        return jsonify({
            "error": "URL is required",
            "status": "error",
            "message": "Please provide a valid URL to scan"
        }), 400
    
    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    # Validate URL
    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({
            "error": f"URL rejected: {reason}",
            "status": "error",
            "message": f"Cannot scan this URL: {reason}"
        }), 400
    
    # Rate limit scan requests
    ip = request.remote_addr or "unknown"
    if not _check_rate(ip, "scan", SCAN_LIMIT):
        return jsonify({
            "error": "Rate limit exceeded",
            "status": "error",
            "message": "You can only start 3 scans per minute. Please wait before starting another."
        }), 429
    
    # Start the scan
    try:
        scan_id = str(uuid.uuid4())[:8]
        run_scan_async(scan_id, url, REPORT_DIR)
        
        logger.info(f"Scan initiated via chatbox: {scan_id} for {url}")
        
        return jsonify({
            "status": "success",
            "message": f"✓ Scan started successfully!",
            "scan_id": scan_id,
            "url": url,
            "scan_url": f"/scan/{scan_id}",
            "details": f"Scanning {url}\nScan ID: {scan_id}\nYou can check progress on the dashboard or ask me for updates!"
        }), 201
    
    except Exception as e:
        logger.error(f"Failed to start scan via chatbox: {e}")
        return jsonify({
            "error": str(e),
            "status": "error",
            "message": f"Failed to start scan: {str(e)}"
        }), 500

@app.route("/api/schedule-scan", methods=["POST"])
@login_required
@csrf.exempt
def api_schedule_scan():
    """Schedule a security scan for later"""
    if not _CHATBOT_AVAILABLE:
        return jsonify({"error": "Scheduling not available", "status": "error"}), 503
    
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    cron = (data.get("cron") or "").strip()
    schedule_text = (data.get("schedule") or "").strip()  # Human-readable format
    
    if not url:
        return jsonify({
            "error": "URL is required",
            "status": "error",
            "message": "Please provide a URL to schedule"
        }), 400
    
    # Convert human-readable format to cron if provided
    if schedule_text and not cron:
        try:
            chatbot = get_chatbot()
            cron = chatbot.parse_schedule_format(schedule_text)
        except:
            pass
    
    if not cron:
        return jsonify({
            "error": "Schedule pattern is required",
            "status": "error",
            "message": "Please provide a schedule (e.g., 'daily', '8 am monday', 'hourly')"
        }), 400
    
    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    # Validate URL
    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({
            "error": f"URL rejected: {reason}",
            "status": "error",
            "message": f"Cannot schedule scan: {reason}"
        }), 400
    
    # Schedule the scan
    try:
        from scheduler import add_schedule
        sched_id = str(uuid.uuid4())[:8]
        add_schedule(sched_id, url, cron, REPORT_DIR)
        
        logger.info(f"Scan scheduled via chatbox: {sched_id} for {url} at {cron}")
        
        return jsonify({
            "status": "success",
            "message": f"✓ Scan scheduled successfully!",
            "schedule_id": sched_id,
            "url": url,
            "cron": cron,
            "details": f"Scheduled scan of {url}\nTime: {schedule_text}\nScans will run automatically on this schedule."
        }), 201
    
    except Exception as e:
        logger.error(f"Failed to schedule scan via chatbox: {e}")
        return jsonify({
            "error": str(e),
            "status": "error",
            "message": f"Failed to schedule scan: {str(e)}"
        }), 500

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
            from ai_chatbot import get_chatbot
            chatbot = get_chatbot()
            cron_expr = chatbot.parse_schedule_format(cron)
            logger.info(f"[schedules] User input: '{cron}' → Parsed cron: '{cron_expr}'")
            # Store both original user input and cron expression
            success = add_schedule(sched_id, url, cron_expr, REPORT_DIR, original_format=cron)
            if success:
                flash(f"Schedule {sched_id} created: {url} at {cron}", "success")
            else:
                flash(f"Failed to add schedule (invalid cron format)", "error")
        except Exception as e:
            logger.error(f"[schedules] Error: {e}")
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

@app.route("/debug/scheduler")
@login_required
@role_required("admin")
def debug_scheduler():
    """Debug scheduler status"""
    try:
        from scheduler import get_scheduler_status
        status = get_scheduler_status()
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI Chatbot API ────────────────────────────────────────────────────────
@app.route("/api/chat", methods=["POST"])
@login_required
@csrf.exempt
def chat_api():
    """AI cybersecurity chatbot endpoint"""
    if not _CHATBOT_AVAILABLE:
        return jsonify({"error": "Chatbot not available", "response": "AI chatbot is not configured."}), 503
    
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()
    include_context = data.get("include_context", True)
    
    if not user_message:
        return jsonify({"error": "Empty message", "response": "Please enter a question."}), 400
    
    # Rate limit chat requests (10 per minute per user)
    ip = request.remote_addr or "unknown"
    if not _check_rate(ip, "chat", 10):
        return jsonify({
            "error": "rate_limit",
            "response": "Chat rate limit exceeded. Please wait a moment."
        }), 429
    
    # Get chatbot and context
    chatbot = get_chatbot()
    context_mgr = get_chat_context(REPORT_DIR)
    
    # Load scan context if requested
    scan_context = None
    if include_context:
        scan_context = context_mgr.get_latest_scan_context()
        
        # Also include current tasks/scans summary
        with SCANS_LOCK:
            all_scans = list(SCANS.values())
        
        running_scans = [s for s in all_scans if s["status"] == "running"]
        completed_scans = [s for s in all_scans if s["status"] == "complete"]
        
        tasks_summary = f"\nCURRENT TASKS:\n"
        tasks_summary += f"- Total Scans: {len(all_scans)}\n"
        tasks_summary += f"- Running: {len(running_scans)}\n"
        tasks_summary += f"- Completed: {len(completed_scans)}\n"
        
        if running_scans:
            tasks_summary += f"\nRUNNING SCANS:\n"
            for scan in running_scans[:5]:  # Show top 5
                tasks_summary += f"  • {scan['id']}: {scan['url']} ({scan.get('phase', 'unknown')})\n"
        
        if scan_context:
            scan_context = tasks_summary + "\n" + scan_context
        else:
            scan_context = tasks_summary
    
    # Get user ID from session (for conversation history)
    user_id = session.get("token", "default")[:16]  # Use token prefix as user ID
    
    # Get response from chatbot
    result = chatbot.chat(user_message, user_id=user_id, scan_context=scan_context)
    
    response_data = {
        "response": result["response"],
        "error": result.get("error"),
        "sources": result.get("sources", []),
        "is_cached": result.get("is_cached", False),
        "rate_limit_remaining": 10,
        "scan_intent": result.get("scan_intent", {})
    }
    
    if result.get("error"):
        return jsonify(response_data), 500
    
    return jsonify(response_data)

@app.route("/api/chat/clear", methods=["POST"])
@login_required
@csrf.exempt
def chat_clear():
    """Clear chat history for current user"""
    if not _CHATBOT_AVAILABLE:
        return jsonify({"error": "Chatbot not available"}), 503
    
    chatbot = get_chatbot()
    user_id = session.get("token", "default")[:16]
    chatbot.clear_history(user_id)
    
    return jsonify({"status": "cleared"})

@app.route("/api/chat/status")
@login_required
@csrf.exempt
def chat_status():
    """Get chatbot status"""
    if not _CHATBOT_AVAILABLE:
        return jsonify({"available": False, "reason": "Anthropic SDK not installed"}), 503
    
    chatbot = get_chatbot()
    status = chatbot.get_summary()
    return jsonify(status)


# ── Scan Result Viewing ────────────────────────────────────────────────────
@app.route("/scan/<scan_id>")
@login_required
def view_scan(scan_id):
    """View scan results"""
    with SCANS_LOCK:
       if scan_id not in SCANS:
           flash("Scan not found", "error")
           return redirect(url_for("dashboard"))
        
       scan = dict(SCANS[scan_id])
    
    # Get findings count
    findings = scan.get("findings", {})
    vuln_count = sum(len(v) for v in findings.values())
    
    return render_template("scan_view.html", scan_id=scan_id, scan=scan, vuln_count=vuln_count)


@app.route("/report")
@login_required
def view_report():
    """View scan report"""
    scan_id = request.args.get("scan_id", "").strip()
    
    if not scan_id:
        flash("No scan ID provided", "error")
        return redirect(url_for("dashboard"))
    
    with SCANS_LOCK:
        if scan_id not in SCANS:
            flash("Scan report not found", "error")
            return redirect(url_for("dashboard"))
        
        scan = dict(SCANS[scan_id])
    
    # Check if scan is complete
    if scan.get("status") != "complete":
        flash("Scan is still in progress. Report will be available when complete.", "info")
        return redirect(url_for("dashboard"))
    
    # Get findings
    findings = scan.get("findings", {})
    
    return render_template("report.html", scan_id=scan_id, scan=scan, findings=findings)


@app.route("/compare")
@login_required
def compare_schedules():
    """Compare schedule results over time"""
    schedule_id = request.args.get("schedule_id", "").strip()
    
    if not schedule_id:
       flash("No schedule ID provided", "error")
       return redirect(url_for("schedules_page"))
    
    # For now, redirect to schedules page
    # TODO: Implement comparison view
    flash("Comparison feature coming soon", "info")
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
