"""
HARDENED Flask Web Application - remediation demo for FYPProject.

This is a patched, security-conscious rewrite of ../webapp/app.py.
Every route mirrors the original vulnerable app so the same AutoPenTest
scanner can be pointed at it to demonstrate a "no vulnerability detected"
(or near-zero findings) result. See ../REMEDIATION.md for a full
vulnerability-by-vulnerability writeup of each fix applied here.

Run standalone for a demo:
    pip install -r requirements.txt
    python app.py
Then scan http://127.0.0.1:5001 instead of the vulnerable app on :5000.
"""
import ipaddress
import os
import re
import secrets
import subprocess
import time
from urllib.parse import urlparse

from flask import Flask, request, session, redirect, url_for, render_template, jsonify, g, abort
from werkzeug.security import check_password_hash

from database import get_db, init_db

app = Flask(__name__)
# FIXED: strong, random secret key (was a hardcoded weak string).
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FORCE_HTTPS", "0") == "1",
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
ALLOWED_FILES_DIR = os.path.realpath(os.path.join(app.root_path, "static"))
API_KEY = os.environ.get("API_KEY", "secret-key-12345")

# ── Helpers ───────────────────────────────────────────────────────────────────
@app.before_request
def open_db():
    g.db = get_db()


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.after_request
def set_security_headers(response):
    # FIXED: add standard hardening headers (missing in the vulnerable app).
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers.pop("Access-Control-Allow-Origin", None)
    return response


def get_csrf_token():
    # FIXED: session-bound CSRF token used by all state-changing forms.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def check_csrf():
    token = request.form.get("csrf_token", "")
    if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
        abort(400, description="Invalid or missing CSRF token")


app.jinja_env.globals["csrf_token"] = get_csrf_token


# ── Home ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html", user=session.get("username"), role=session.get("role"))


# ── Login  (FIXED: parameterized query, hashed password check, lockout) ──────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        row = g.db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if row and row["locked_until"] and time.time() < row["locked_until"]:
            error = "Account temporarily locked. Try again later."
        elif row and check_password_hash(row["password_hash"], password):
            g.db.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (row["id"],)
            )
            g.db.commit()
            session.clear()
            session["username"] = row["username"]
            session["role"] = row["role"]
            session["user_id"] = row["id"]
            return redirect(url_for("dashboard"))
        else:
            if row:
                attempts = row["failed_attempts"] + 1
                locked_until = time.time() + LOCKOUT_SECONDS if attempts >= MAX_LOGIN_ATTEMPTS else None
                g.db.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                    (attempts, locked_until, row["id"]),
                )
                g.db.commit()
            # FIXED: generic error message, no query/exception detail leaked.
            error = "Invalid credentials"
    return render_template("login.html", error=error)


# ── Logout ────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    users = g.db.execute("SELECT id, username, role FROM users").fetchall()
    return render_template("dashboard.html", user=session["username"], role=session["role"], users=users)


# ── Search  (FIXED: parameterized query + auto-escaped output) ───────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        results = g.db.execute(
            "SELECT id, username, email FROM users WHERE username LIKE ?", (f"%{q}%",)
        ).fetchall()
    # FIXED: q is rendered through Jinja's default auto-escaping (no |safe).
    return render_template("search.html", q=q, results=results)


# ── Profile  (FIXED: ownership check, no password field exposed) ────────────
@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "username" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "admin" and session.get("user_id") != user_id:
        abort(403)
    user = g.db.execute(
        "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", target=user, current_user=session.get("username"))


# ── Comments  (FIXED: CSRF token + auto-escaped output) ──────────────────────
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        check_csrf()
        author = request.form.get("author", "anonymous")[:80]
        body = request.form.get("body", "")[:1000]
        g.db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        g.db.commit()
        return redirect(url_for("comments"))
    rows = g.db.execute("SELECT * FROM comments ORDER BY created DESC").fetchall()
    return render_template("comments.html", comments=rows)


# ── Ping Utility  (FIXED: strict input validation, no shell=True) ────────────
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def _is_safe_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = ""
    if host:
        if not _is_safe_host(host):
            output = "Invalid host: only hostnames or IP addresses are allowed."
        else:
            try:
                result = subprocess.run(
                    ["ping", "-c", "2", host],  # FIXED: list args, shell=False
                    capture_output=True, text=True, timeout=10,
                )
                output = result.stdout + result.stderr
            except Exception:
                output = "Unable to reach host."
    return render_template("ping.html", host=host, output=output)


# ── File Viewer  (FIXED: canonical path check, whitelist directory) ──────────
@app.route("/files")
def files():
    filename = request.args.get("file", "")
    content = ""
    error = ""
    if filename:
        candidate = os.path.realpath(os.path.join(ALLOWED_FILES_DIR, filename))
        if not candidate.startswith(ALLOWED_FILES_DIR + os.sep):
            error = "Access denied: path outside of allowed directory."
        else:
            try:
                with open(candidate, "r") as f:
                    content = f.read()
            except Exception:
                error = "File not found."
    return render_template("files.html", filename=filename, content=content, error=error)


# ── Admin Panel  (FIXED: role re-verified from DB, no plaintext passwords) ───
@app.route("/admin")
def admin():
    if "user_id" not in session:
        return redirect(url_for("login"))
    row = g.db.execute("SELECT role FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if not row or row["role"] != "admin":
        return "Access denied", 403
    users = g.db.execute("SELECT id, username, role, email FROM users").fetchall()
    return render_template("admin.html", users=users)


# ── API: user info  (FIXED: requires auth, restricted CORS) ──────────────────
@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    if session.get("role") != "admin" and session.get("user_id") != user_id:
        return jsonify({"error": "forbidden"}), 403
    row = g.db.execute(
        "SELECT id, username, email, role FROM users WHERE id=?", (user_id,)
    ).fetchone()
    return jsonify(dict(row) if row else {})


# ── API data  (FIXED: requires auth, no wildcard CORS, no secret leaked) ────
@app.route("/api/data")
def api_data():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"data": "sensitive"})


# ── Template renderer  (FIXED: user input never passed to render_template) ──
@app.route("/render", methods=["GET", "POST"])
def render():
    if request.method == "POST":
        template_str = request.form.get("template", "")
        # FIXED: never render arbitrary user-supplied template strings.
        # Echo back the escaped input instead of evaluating it as a template.
        return render_template("render_result.html", template_input=template_str)
    return render_template("render_form.html")


# ── XML parser  (FIXED: DTD/external entities disabled) ─────────────────────
@app.route("/xml-parse", methods=["POST"])
def xml_parse():
    try:
        try:
            from defusedxml import ElementTree as SafeET  # type: ignore
            root = SafeET.fromstring(request.data)
        except ImportError:
            # Fallback: reject any input containing a DOCTYPE/ENTITY declaration.
            raw = request.data.decode("utf-8", errors="replace")
            if re.search(r"<!DOCTYPE|<!ENTITY", raw, re.IGNORECASE):
                return jsonify({"error": "DOCTYPE/ENTITY declarations are not allowed"}), 400
            import xml.etree.ElementTree as ET
            root = ET.fromstring(request.data)
        return jsonify({"parsed": True, "root": root.tag})
    except Exception:
        return jsonify({"error": "invalid XML"}), 400


@app.route("/xml-form")
def xml_form():
    return render_template("xml_form.html")


# ── LDAP search  (FIXED: input escaped per RFC 4515) ─────────────────────────
def _ldap_escape(value):
    escapes = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}
    return "".join(escapes.get(ch, ch) for ch in value)


@app.route("/ldap-search")
def ldap_search():
    search_term = request.args.get("search", "")
    ldap_filter = f"(uid={_ldap_escape(search_term)})"
    return jsonify({"filter": ldap_filter, "results": []})


# ── Redirect  (FIXED: only relative, same-site paths are allowed) ───────────
@app.route("/redirect")
def redirect_page():
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)
    if parsed.netloc or parsed.scheme or not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"
    return redirect(next_url)


# ── Password reset  (FIXED: unpredictable, expiring, server-verified token) ─
_reset_tokens = {}


@app.route("/reset-password/<token>")
def reset_password(token):
    entry = _reset_tokens.get(token)
    if not entry or time.time() > entry["expires"]:
        return jsonify({"status": "invalid or expired token"}), 400
    return jsonify({"status": "valid", "user_id": entry["user_id"]})


# ── API key auth  (FIXED: constant-time comparison) ──────────────────────────
@app.route("/api-with-key")
def api_with_key():
    api_key = request.headers.get("X-API-Key", "")
    if secrets.compare_digest(api_key, API_KEY):
        return jsonify({"authorized": True, "data": "premium content"})
    return jsonify({"error": "unauthorized"}), 401


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)), debug=False)
