#!/usr/bin/env python3
"""
AutoPenTest Enterprise — Setup Script
Creates remaining directory-dependent files:
  - .github/workflows/pentest.yml (CI/CD integration)
  - .env (root environment template)
  - pentester/.env (pentester environment)
  
Run: python setup_enterprise.py
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))


def write(path: str, content: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  ✓ {os.path.relpath(path, BASE)}")


print("AutoPenTest Enterprise Setup")
print("=" * 40)

# ── .github/workflows/pentest.yml ─────────────────────────────────────────
write(os.path.join(BASE, ".github", "workflows", "pentest.yml"), """\
name: AutoPenTest Security Scan

on:
  push:
    branches: [main, master, staging]
  pull_request:
    branches: [main, master]
  workflow_dispatch:
    inputs:
      target_url:
        description: 'Target URL to scan'
        required: true
        default: 'http://localhost:5000'

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install requests python-dotenv openai jinja2

      - name: Start target application
        run: |
          docker compose up -d webapp
          for i in $(seq 1 30); do
            curl -sf http://localhost:5000/ > /dev/null 2>&1 && break
            sleep 5
          done

      - name: Run AutoPenTest scan
        id: pentest
        env:
          TARGET_URL: ${{ github.event.inputs.target_url || 'http://localhost:5000' }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          REPORT_DIR: ./reports
        run: |
          cd pentester && pip install -r requirements.txt && python main.py
        continue-on-error: true

      - name: Check quality gate
        run: |
          python << 'EOF'
          import glob, json, sys, os
          files = sorted(glob.glob("reports/report_*.json"))
          if not files:
              print("No report found"); sys.exit(1)
          with open(files[-1]) as f:
              data = json.load(f)
          analysis = data.get("analysis", {})
          critical = analysis.get("critical_count", 0)
          risk     = analysis.get("risk_rating", "Unknown")
          total    = analysis.get("total_findings", 0)
          print(f"Risk: {risk} | Total: {total} | Critical: {critical}")
          with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as out:
              out.write(f"risk_rating={risk}\\n")
              out.write(f"critical_count={critical}\\n")
              out.write(f"total_findings={total}\\n")
          if critical > 0:
              print(f"QUALITY GATE FAILED: {critical} critical findings!")
              sys.exit(1)
          print("Quality gate passed.")
          EOF

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        continue-on-error: true
        with:
          sarif_file: reports/

      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pentest-reports-${{ github.run_number }}
          path: reports/
          retention-days: 30
""")

# ── Root .env template ─────────────────────────────────────────────────────
env_path = os.path.join(BASE, ".env")
if not os.path.exists(env_path):
    import secrets
    zap_key = secrets.token_hex(16)
    jwt_sec = secrets.token_hex(32)
    write(env_path, f"""\
# AutoPenTest Enterprise — Environment Configuration
# Copy this file to .env and fill in your values.

# ZAP API key (auto-generated — change if needed)
ZAP_KEY={zap_key}

# Dashboard authentication
ADMIN_USER=admin
ADMIN_PASS=changeme123!

# JWT signing secret (auto-generated)
JWT_SECRET={jwt_sec}

# OpenAI (optional — enables AI analysis)
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini

# Threat intelligence (optional)
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=

# Rate limiting
RATE_LIMIT_PER_MIN=60
SCAN_LIMIT_PER_MIN=3

# Target for standalone pentester
TARGET_URL=http://webapp:5000
REPORT_DIR=/reports
""")
    print(f"  ✓ .env (generated with random keys)")
else:
    print(f"  – .env already exists, skipping")

# ── pentester/requirements.txt update ─────────────────────────────────────
req_path = os.path.join(BASE, "pentester", "requirements.txt")
if os.path.exists(req_path):
    with open(req_path, "r") as f:
        existing = f.read()
    additions = []
    for dep in ["weasyprint>=60.0", "requests>=2.31.0"]:
        pkg = dep.split(">=")[0].split("==")[0]
        if pkg not in existing:
            additions.append(dep)
    if additions:
        with open(req_path, "a") as f:
            f.write("\n" + "\n".join(additions) + "\n")
        print(f"  ✓ pentester/requirements.txt (added: {', '.join(additions)})")

print("")
print("Setup complete! Next steps:")
print("  1. Edit .env and set ADMIN_PASS and optionally OPENAI_API_KEY")
print("  2. docker compose up --build")
print("  3. Open http://localhost:8080 and log in")
print("  4. Enter a target URL and click Scan")
