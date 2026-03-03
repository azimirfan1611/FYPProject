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
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
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
                f"SELECT id, username, email FROM users WHERE username LIKE '%{q}%'"
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
