# 🔐 AutoPenTest – Automated Web Application Penetration Testing

> **⚠️ Educational Use Only** — This project contains intentional vulnerabilities.
> Never deploy the web application to a production or public-facing environment.

## Overview

| Component   | Description                                                                     |
|-------------|---------------------------------------------------------------------------------|
| `webapp/`   | Intentionally vulnerable Flask web app (SQL injection, XSS, etc.)              |
| `pentester/`| Automated scanner — standard sequential mode OR Shannon 4-phase AI orchestrator |
| `reports/`  | Auto-generated HTML, JSON & Markdown pentest reports                            |

---

## 🤖 Shannon AI Penetration Testing Mode

Inspired by the [Shannon AI pentesting framework](https://github.com/KeygraphHQ/shannon),
this project now supports a **4-phase autonomous orchestrator** that emulates a human
penetration tester's methodology:

```
Phase 1 — Reconnaissance
  └─ Nmap, Nikto, HTTP headers, SSL/TLS, DNS, WAF detection
  └─ White-box source code analysis (static vulnerability patterns)

Phase 2 — Vulnerability Analysis (parallel)
  ├─ SQL Injection          ├─ XSS               ├─ Authentication
  ├─ SSRF (new)             ├─ Path Traversal     ├─ Command Injection
  ├─ IDOR                   ├─ API Security        └─ CORS

Phase 3 — Exploitation  ──  "No Exploit, No Report"
  └─ Each hypothesis is validated; unconfirmed findings are discarded.
  └─ Every confirmed finding gets a copy-paste Proof-of-Concept.

Phase 4 — Reporting
  └─ HTML + JSON + Markdown report with PoCs and Shannon metrics.
  └─ Workspace checkpointing: interrupted runs can be resumed.
```

### Shannon Key Features

| Feature | Description |
|---------|-------------|
| **4-phase architecture** | Recon → Analysis (parallel) → Exploitation → Reporting |
| **White-box analysis** | Scans your source code for vulnerable patterns |
| **SSRF detection** | Tests for Server-Side Request Forgery (OWASP A10) |
| **Parallel pipelines** | Runs all vulnerability types concurrently |
| **No Exploit, No Report** | Only confirmed vulnerabilities reach the report |
| **Proof-of-Concepts** | Copy-paste PoC for every confirmed finding |
| **Workspace checkpoints** | Resume interrupted scans without re-running phases |
| **Anthropic Claude** | Claude AI analysis alongside OpenAI fallback |

---

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
| SSRF                 | URL-accepting endpoints | HIGH      |
| Verbose Errors       | `/login`                | MEDIUM    |
| No CSRF Tokens       | `/comments`             | MEDIUM    |

## Quick Start

### 1. Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- Python 3.11+ (for local dev only)
- _(Optional)_ Anthropic API key (`ANTHROPIC_API_KEY`) **or** OpenAI API key for AI analysis

### 2. Clone / setup
```bash
cd pentest
cp pentester/.env.example pentester/.env
# Edit pentester/.env:
#   Set ANTHROPIC_API_KEY  (recommended for Shannon mode)
#   Set OPENAI_API_KEY     (alternative AI provider)
#   Set SHANNON_MODE=true  to use Shannon 4-phase orchestrator
```

### 3. Run with Docker Compose
```bash
docker-compose up --build
```

- **Web App** available at: http://localhost:5000
- **Pentest** runs automatically once the webapp is healthy
- **Reports** saved to `./reports/` (standard) or `./audit-logs/` (Shannon mode)

### 4. View the Report
Open `reports/report_<timestamp>.html` in your browser.

---

## Shannon Mode Usage

### Enable Shannon mode
```bash
# Option A: environment variable
SHANNON_MODE=true python main.py

# Option B: command-line flag
python main.py --shannon

# Option C: set in .env
echo "SHANNON_MODE=true" >> pentester/.env
docker-compose up --build
```

### White-box analysis (recommended)
```bash
# Clone the target app under repos/
git clone https://github.com/your-org/your-app.git repos/your-app

# Point Shannon at it
REPO_PATH=./repos/your-app python main.py --shannon
```

### Workspace resume
```bash
# Start a named workspace
WORKSPACE_NAME=my-audit python main.py --shannon

# Resume the same workspace (skips completed phases)
WORKSPACE_NAME=my-audit python main.py --shannon

# List all workspaces
python main.py --workspaces
```

### Output structure (Shannon mode)
```
audit-logs/{hostname}_{sessionId}/
├── workspace.json                          # Phase state & metrics
├── agents/                                 # Per-agent logs
└── deliverables/
    ├── report_<ts>_<id>.html               # Visual HTML report
    ├── report_<ts>_<id>.json               # Machine-readable JSON
    └── comprehensive_security_assessment_report.md  # Shannon-style markdown
```

---

## Manual Pentest Only (no Docker)
```bash
# Terminal 1 – start the webapp
cd webapp
pip install -r requirements.txt
python app.py

# Terminal 2 – run the pentester (standard mode)
cd pentester
pip install -r requirements.txt
cp .env.example .env   # set TARGET_URL=http://localhost:5000
python main.py

# Terminal 2 – run Shannon mode
python main.py --shannon
```

## AI Integration

| Provider | Key Variable | Notes |
|----------|-------------|-------|
| Anthropic Claude | `ANTHROPIC_API_KEY` | Preferred; `claude-sonnet-4-6` default |
| OpenAI | `OPENAI_API_KEY` | Fallback; `gpt-4o-mini` default |
| Rule-based | _(none)_ | Always-available offline fallback |

## Scanner Modules

| Module                    | Tests                                              |
|---------------------------|----------------------------------------------------|
| `sql_injection.py`        | SQLi payloads on login & search                    |
| `xss_scanner.py`          | Reflected & stored XSS                             |
| `auth_tester.py`          | Credential brute force, session fixation, debug    |
| `dir_traversal.py`        | Path traversal on file viewer                      |
| `command_injection.py`    | OS command injection on ping utility               |
| `idor_scanner.py`         | Profile IDOR, unauthenticated API access           |
| **`ssrf_scanner.py`** ✨  | SSRF via URL-accepting parameters (Shannon)        |
| **`source_analyzer.py`** ✨| White-box static code analysis (Shannon)          |

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
│   ├── main.py             # Orchestrator (standard + --shannon + --workspaces)
│   ├── config.py           # Config & payloads
│   ├── ai_analyzer.py      # Claude / OpenAI / rule-based analysis
│   ├── report_generator.py # HTML, JSON reports (with PoC panel)
│   ├── shannon_orchestrator.py  # 4-phase Shannon workflow ✨
│   ├── workspace.py             # Checkpoint/resume system ✨
│   ├── requirements.txt
│   ├── Dockerfile
│   └── scanners/
│       ├── sql_injection.py
│       ├── xss_scanner.py
│       ├── auth_tester.py
│       ├── dir_traversal.py
│       ├── command_injection.py
│       ├── idor_scanner.py
│       ├── ssrf_scanner.py      # SSRF detection ✨
│       └── source_analyzer.py   # White-box analysis ✨
├── reports/                # Standard mode output
├── audit-logs/             # Shannon mode output (workspaces)
├── repos/                  # Place target app repos here for white-box scan
├── docker-compose.yml
└── README.md
```
