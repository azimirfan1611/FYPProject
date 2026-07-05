# Vulnerability Remediation Demonstration

This document shows how every vulnerability seeded in the intentionally
vulnerable target (`webapp/`) can be fixed. A fully patched, runnable copy of
the same application lives in **`webapp_fixed/`** — it mirrors every route in
`webapp/app.py` so the AutoPenTest scanner can be pointed at it to demonstrate
a "no vulnerability / near-zero findings" result, proving the scanner does
not simply flag everything indiscriminately.

## How to run the hardened demo

```powershell
cd webapp_fixed
pip install -r requirements.txt
python app.py        # serves on http://127.0.0.1:5001
```

Then run an AutoPenTest scan against `http://127.0.0.1:5001` instead of the
vulnerable app on `:5000`, and compare the report against a scan of the
original `webapp/` target.

---

## Vulnerability-by-vulnerability fixes

### 1. SQL Injection (login, search)
- **Vulnerable** (`webapp/app.py`): `f"SELECT * FROM users WHERE username='{username}'..."`
- **Fixed** (`webapp_fixed/app.py`): parameterized queries everywhere —
  `g.db.execute("SELECT * FROM users WHERE username=?", (username,))`.
  User input is never concatenated into SQL text.

### 2. Reflected XSS (search) & Stored XSS (comments)
- **Vulnerable**: templates used `{{ q | safe }}` / `{{ c.body | safe }}`,
  disabling Jinja's automatic HTML escaping.
- **Fixed**: the `|safe` filter was removed everywhere. Jinja's default
  auto-escaping renders user input as inert text, so `<script>` payloads are
  displayed literally instead of executing.

### 3. IDOR (`/profile/<id>`)
- **Vulnerable**: any logged-in user could fetch any other user's full
  record, including their plaintext password, with no ownership check.
- **Fixed**: the route now requires `session["user_id"] == user_id` or an
  `admin` role, returns `403` otherwise, and the password field was removed
  from the query/response entirely (least-privilege data exposure).

### 4. Command Injection (`/ping`)
- **Vulnerable**: `subprocess.run(f"ping -c 2 {host}", shell=True, ...)` let
  `host=127.0.0.1; id` execute arbitrary shell commands.
- **Fixed**: `host` is validated against `ipaddress.ip_address()` or a strict
  hostname regex before use, and the command is invoked as an argument list
  (`["ping", "-c", "2", host]`) with `shell=False`, so shell metacharacters
  have no effect.

### 5. Path Traversal (`/files`)
- **Vulnerable**: `filepath = "/app/static/" + filename` allowed
  `file=../../etc/passwd` to escape the intended directory.
- **Fixed**: the target path is canonicalized with `os.path.realpath()` and
  verified to still start with the whitelisted directory prefix before the
  file is opened; anything outside it is rejected with "Access denied."

### 6. Weak Authentication (plaintext passwords, no lockout)
- **Vulnerable**: passwords stored and compared in plaintext; unlimited
  login attempts.
- **Fixed**: passwords are hashed with `werkzeug.security.generate_password_hash`
  / verified with `check_password_hash`; failed attempts are tracked per
  account and the account is locked for 5 minutes after 5 consecutive
  failures.

### 7. CSRF (comments, login forms)
- **Vulnerable**: POST forms had no anti-CSRF protection.
- **Fixed**: a per-session CSRF token (`secrets.token_hex(16)`) is embedded
  as a hidden field in every state-changing form and validated with a
  constant-time comparison (`secrets.compare_digest`) before the request is
  processed.

### 8. Verbose Error / Information Disclosure
- **Vulnerable**: login errors leaked the raw SQL query and exception text.
- **Fixed**: only a generic "Invalid credentials" message is shown; no query
  text, stack trace, or internal detail is ever returned to the client.
  Flask `debug` mode is also disabled (`debug=False`).

### 9. Weak Secret Key / Session Hardening
- **Vulnerable**: `app.secret_key = "supersecretkey123"` (hardcoded, guessable).
- **Fixed**: a cryptographically random key is generated at startup (or
  supplied via the `SECRET_KEY` environment variable in production), and
  cookies are marked `HttpOnly` + `SameSite=Lax` (and `Secure` when served
  over HTTPS).

### 10. Admin Panel Access Control
- **Vulnerable**: authorization relied solely on a `session["role"]` value.
- **Fixed**: the role is re-verified against the database on every request
  to `/admin` and `/api/user/<id>` rather than trusted blindly from the
  session, reducing the blast radius of any session-tampering vector.

### 11. Unauthenticated / Overly Permissive API (`/api/user/<id>`, `/api/data`)
- **Vulnerable**: endpoints returned full user records with no
  authentication and set `Access-Control-Allow-Origin: *`.
- **Fixed**: both endpoints now require an active session, enforce the same
  ownership/role check as the profile page, and the wildcard CORS headers
  were removed entirely (same-origin only).

### 12. Missing Security Headers
- **Vulnerable**: no hardening headers were set on any response.
- **Fixed**: an `after_request` hook adds `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a
  `Content-Security-Policy: default-src 'self'` to every response.

### 13. Server-Side Template Injection (`/render`)
- **Vulnerable**: `render_template(user_supplied_string)` executed arbitrary
  Jinja2 expressions (e.g. `{{config}}`), leaking secrets/RCE potential.
- **Fixed**: user input is never passed to the template engine as a
  template. It is echoed back as plain, auto-escaped text in a fixed
  template (`render_result.html`).

### 14. XXE (`/xml-parse`)
- **Vulnerable**: `xml.etree.ElementTree.fromstring()` parsed attacker XML
  with no DOCTYPE/entity restrictions.
- **Fixed**: parsing prefers `defusedxml`, which disables external entity
  and DTD processing; as a fallback, any payload containing
  `<!DOCTYPE` or `<!ENTITY` is rejected outright before parsing.

### 15. LDAP Injection (`/ldap-search`)
- **Vulnerable**: `f"(uid={search_term})"` allowed filter-injection
  characters (`*`, `(`, `)`, `\`) straight into the LDAP filter.
- **Fixed**: special characters are escaped per RFC 4515 before being placed
  into the filter string.

### 16. Open Redirect (`/redirect`)
- **Vulnerable**: `redirect(request.args.get("next"))` allowed redirecting to
  any external URL for phishing.
- **Fixed**: the `next` parameter is parsed with `urlparse` and only
  accepted if it is a same-site, relative path (no scheme, no netloc, not
  starting with `//`); otherwise it falls back to `/`.

### 17. Predictable Password Reset Token (`/reset-password/<token>`)
- **Vulnerable**: the "token" was literally the user's numeric ID.
- **Fixed**: tokens are generated with `secrets.token_urlsafe()`, stored
  server-side with an expiry, and are looked up rather than trusted from the
  URL directly.

### 18. Hardcoded / Weak API Key Comparison (`/api-with-key`)
- **Vulnerable**: `api_key == "secret-key-12345"` (plain `==`, timing-attack
  prone, key committed in source).
- **Fixed**: the key is read from the `API_KEY` environment variable (not
  hardcoded) and compared with `secrets.compare_digest` for constant-time
  comparison.

---

## Suggested evaluation write-up

For the FYP report, run the AutoPenTest scanner against both targets and
present a table like:

| Scanner module        | `webapp` (vulnerable) | `webapp_fixed` (hardened) |
|------------------------|:---------------------:|:--------------------------:|
| sql_injection          | 2 findings             | 0 findings |
| xss_scanner            | 2 findings             | 0 findings |
| idor_scanner           | 1 finding              | 0 findings |
| command_injection      | 1 finding              | 0 findings |
| dir_traversal          | 1 finding              | 0 findings |
| auth_tester            | weak auth, no lockout  | pass |
| cors_scanner           | permissive CORS        | pass |
| headers_scanner        | missing headers        | pass |

This demonstrates both **detection accuracy** (true positives on the
vulnerable app) and **precision / low false-positive rate** (true negatives
on the hardened app), which strengthens the tool's evaluation section.
