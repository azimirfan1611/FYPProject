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
