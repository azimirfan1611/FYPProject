# AutoPenTest Project Parameters Reference

## Overview
This document lists all configuration parameters for the AutoPenTest project, including authentication, AI integration, security scanning, and infrastructure settings.

---

## 1. AUTHENTICATION PARAMETERS

### ADMIN_USER
- **Type:** String
- **Default:** `admin`
- **Purpose:** Dashboard admin username
- **Location:** `docker-compose.yml` (line 125)
- **Security:** Not sensitive (username only)
- **Example:** `export ADMIN_USER=admin`

### ADMIN_PASS
- **Type:** String (Password)
- **Default:** `changeme123!`
- **Purpose:** Dashboard admin password
- **Location:** `docker-compose.yml` (line 126)
- **Security:** ⚠️ **CRITICAL - CHANGE IN PRODUCTION**
- **Example:** `export ADMIN_PASS=MySecurePassword123!`
- **Requirements:** 
  - Minimum 8 characters
  - Use strong password

### JWT_SECRET
- **Type:** String (Cryptographic Key)
- **Default:** Auto-generated (32 bytes, hex format)
- **Purpose:** JWT token signing key for session management
- **Location:** `docker-compose.yml` (line 127)
- **Security:** 🔐 **KEEP SECRET - Never commit**
- **Generation:**
  ```powershell
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- **Example:** `export JWT_SECRET=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6`

---

## 2. AI CHATBOT PARAMETERS

### OPENAI_API_KEY
- **Type:** String (API Key)
- **Default:** Empty (not configured)
- **Purpose:** Enable OpenAI GPT models for chatbox
- **Cost:** FREE tier available ($5 credits for new accounts)
- **Status:** ✅ **Recommended for testing**
- **Location:** `docker-compose.yml` (line 121)
- **Security:** 🔐 **KEEP SECRET - Don't commit**
- **Get Key:**
  1. Visit: https://platform.openai.com/account/api-keys
  2. Sign up with email/GitHub
  3. Create new secret key
  4. Copy key (starts with `sk-proj-`)
- **Example:** `export OPENAI_API_KEY=sk-proj-abc123xyz789def...`
- **Priority:** Falls back to Claude if configured, otherwise primary

### OPENAI_MODEL
- **Type:** String (Model identifier)
- **Default:** `gpt-4o-mini`
- **Purpose:** Specifies which OpenAI model to use
- **Location:** `docker-compose.yml` (line 122)
- **Options:**
  - `gpt-4o-mini` (recommended, free-tier friendly)
  - `gpt-4-turbo` (faster, cheaper)
  - `gpt-3.5-turbo` (legacy, cost-effective)
- **Example:** `export OPENAI_MODEL=gpt-4o-mini`

### ANTHROPIC_API_KEY
- **Type:** String (API Key)
- **Default:** Empty (not configured)
- **Purpose:** Enable Claude for chatbox (higher quality)
- **Cost:** Paid subscription required
- **Status:** 💎 **Premium option - better responses**
- **Location:** `docker-compose.yml` (line 123)
- **Security:** 🔐 **KEEP SECRET - Don't commit**
- **Get Key:**
  1. Visit: https://console.anthropic.com/
  2. Create account
  3. Add payment method
  4. Navigate to: https://console.anthropic.com/keys
  5. Create new API key
  6. Copy key (starts with `sk-ant-`)
- **Example:** `export ANTHROPIC_API_KEY=sk-ant-abc123xyz789def...`
- **Priority:** If configured, used before OpenAI

---

## 3. ZAP SCANNER PARAMETERS

### ZAP_URL
- **Type:** String (URL)
- **Default:** `http://zap:8090`
- **Purpose:** OWASP ZAP service address
- **Location:** `docker-compose.yml` (lines 116, 89)
- **Network:** Internal (not exposed to host)
- **Port:** 8090
- **Example:** `export ZAP_URL=http://zap:8090`
- **Note:** 'zap' hostname resolves to ZAP container via Docker network

### ZAP_KEY
- **Type:** String (API Key)
- **Default:** `autopentest_changeme_key` (⚠️ INSECURE)
- **Purpose:** OWASP ZAP API authentication key
- **Location:** `docker-compose.yml` (lines 3, 38, 41, 90, 117)
- **Security:** ⚠️ **CRITICAL - CHANGE IN PRODUCTION**
- **Generation:**
  ```powershell
  python -c "import secrets; print(secrets.token_hex(16))"
  ```
- **Example:** `export ZAP_KEY=3f2e5c1b9a4d8e7f6c2a5b1d9e3f8c5a`
- **Length:** 32 characters (16 bytes, hex)

---

## 4. RATE LIMITING PARAMETERS

### RATE_LIMIT_PER_MIN
- **Type:** Integer
- **Default:** `60`
- **Purpose:** Global HTTP request rate limit
- **Location:** `docker-compose.yml` (line 130)
- **Unit:** Requests per minute
- **Scope:** Per IP address
- **Example:** `export RATE_LIMIT_PER_MIN=100`
- **Recommended:**
  - Local testing: 300
  - Production: 60-120
  - Public API: 30-60

### SCAN_LIMIT_PER_MIN
- **Type:** Integer
- **Default:** `3`
- **Purpose:** Security scan execution rate limit
- **Location:** `docker-compose.yml` (line 131)
- **Unit:** Scans per minute
- **Scope:** Per IP address
- **Example:** `export SCAN_LIMIT_PER_MIN=1`
- **Recommended:**
  - Local testing: 10
  - Production: 1-3
  - Note:** Scans are resource-intensive

---

## 5. OPTIONAL SECURITY INTELLIGENCE PARAMETERS

### SHODAN_API_KEY
- **Type:** String (API Key)
- **Default:** Empty (not configured)
- **Purpose:** IP and domain reconnaissance
- **Location:** `docker-compose.yml` (line 128)
- **Cost:** Free tier available (limited queries)
- **Get Key:** https://www.shodan.io/account/api-keys
- **Example:** `export SHODAN_API_KEY=your_shodan_key`
- **Status:** Optional (not required)

### VIRUSTOTAL_API_KEY
- **Type:** String (API Key)
- **Default:** Empty (not configured)
- **Purpose:** Malware and indicator scanning
- **Location:** `docker-compose.yml` (line 129)
- **Cost:** Free tier available (4 requests/minute)
- **Get Key:** https://www.virustotal.com/gui/my-apikey
- **Example:** `export VIRUSTOTAL_API_KEY=your_vt_key`
- **Status:** Optional (not required)

---

## 6. INFRASTRUCTURE PARAMETERS

### TARGET_URL
- **Type:** String (URL)
- **Default:** `http://webapp:5000`
- **Purpose:** Target web application for security scanning
- **Location:** `docker-compose.yml` (line 88)
- **Example:** `export TARGET_URL=http://webapp:5000`
- **Note:** 'webapp' hostname resolves to vulnerable app container

### REPORT_DIR
- **Type:** String (File path)
- **Default:** `/reports`
- **Purpose:** Storage directory for scan reports
- **Location:** `docker-compose.yml` (lines 96, 124)
- **Format:** JSON reports named `report_<timestamp>.json`
- **Volume:** Shared between Docker containers
- **Example:** `export REPORT_DIR=/reports`

### SHANNON_MODE
- **Type:** Boolean (true/false)
- **Default:** `true`
- **Purpose:** Enable enhanced scanning features
- **Location:** `docker-compose.yml` (line 97)
- **Example:** `export SHANNON_MODE=true`

---

## 7. DISABLED/OPTIONAL PARAMETERS

### MSF_HOST (Commented out)
- **Type:** String (Hostname)
- **Default:** `msf` (disabled)
- **Purpose:** Metasploit Framework server
- **Status:** 🔴 Currently disabled
- **Location:** `docker-compose.yml` (lines 91, 118)

### MSF_PORT (Commented out)
- **Type:** Integer (Port)
- **Default:** `55553` (disabled)
- **Purpose:** Metasploit RPC port
- **Status:** 🔴 Currently disabled

### MSF_PASS (Commented out)
- **Type:** String (Password)
- **Default:** `msfrpc_pass` (disabled)
- **Purpose:** Metasploit Framework password
- **Status:** 🔴 Currently disabled

---

## QUICK SETUP GUIDE

### Option 1: Environment Variables (Recommended)

**Windows PowerShell:**
```powershell
# Generate secure keys
$zap_key = python -c "import secrets; print(secrets.token_hex(16))"

# Set environment variables
$env:ADMIN_USER = "admin"
$env:ADMIN_PASS = "MySecurePassword123!"
$env:OPENAI_API_KEY = "sk-proj-your-key-here"
$env:ZAP_KEY = $zap_key

# Restart container
docker-compose restart dashboard
```

### Option 2: .env File (Recommended for persistence)

**Create `.env` file in project root:**
```
# Authentication
ADMIN_USER=admin
ADMIN_PASS=MySecurePassword123!
JWT_SECRET=auto-generated-at-startup

# AI Chatbot (get free key from https://platform.openai.com)
OPENAI_API_KEY=sk-proj-your-key-here
OPENAI_MODEL=gpt-4o-mini

# Security Scanning
ZAP_KEY=3f2e5c1b9a4d8e7f6c2a5b1d9e3f8c5a

# Rate Limiting
RATE_LIMIT_PER_MIN=60
SCAN_LIMIT_PER_MIN=3

# Optional Intelligence
# SHODAN_API_KEY=your_shodan_key
# VIRUSTOTAL_API_KEY=your_vt_key
```

**Then:**
```powershell
docker-compose up -d
```

### Option 3: Edit docker-compose.yml directly
Edit lines 115-131 to set custom values permanently.

---

## SECURITY CHECKLIST

### ⚠️ MUST CHANGE FOR PRODUCTION:
- [ ] `ADMIN_PASS` - Change from default
- [ ] `ZAP_KEY` - Generate new secure key
- [ ] `JWT_SECRET` - Generate new key
- [ ] Remove defaults from docker-compose.yml

### 🔐 NEVER COMMIT TO GIT:
- [ ] `OPENAI_API_KEY`
- [ ] `ANTHROPIC_API_KEY`
- [ ] `JWT_SECRET` (if custom)
- [ ] `ZAP_KEY` (if custom)
- [ ] `ADMIN_PASS` (if custom)
- [ ] `.env` file

### ✅ BEST PRACTICES:
- [ ] Use `.env` file for sensitive data
- [ ] Add `.env` to `.gitignore`
- [ ] Use strong passwords (12+ chars, mixed case, symbols)
- [ ] Rotate API keys regularly
- [ ] Use different passwords for different environments
- [ ] Keep `.env` backups in secure location

---

## TESTING PARAMETERS

### Verify Configuration:
```powershell
# Show all environment variables
docker-compose exec dashboard env | Sort-Object

# Check specific variable
docker exec pentest_dashboard printenv OPENAI_API_KEY
```

### Test Authentication:
```powershell
curl -X POST http://localhost:8080/login `
  -d "username=admin&password=YourPassword" `
  -H "Content-Type: application/x-www-form-urlencoded"
```

### Test Chatbox:
```powershell
curl -X POST http://localhost:8080/api/chat `
  -H "Content-Type: application/json" `
  -H "Cookie: session=your_cookie" `
  -d '{"message":"What is XSS?"}'
```

---

## TROUBLESHOOTING

### Issue: "No API key configured"
**Solution:** Set OPENAI_API_KEY or ANTHROPIC_API_KEY and restart

### Issue: "Login failed"
**Solution:** Verify ADMIN_USER and ADMIN_PASS are correct

### Issue: "Rate limit exceeded"
**Solution:** Increase RATE_LIMIT_PER_MIN or wait 1 minute

### Issue: "ZAP connection failed"
**Solution:** Verify ZAP_URL and ZAP_KEY are correct

---

## References

- [docker-compose.yml](./docker-compose.yml) - Full configuration
- [app.py](./dashboard/app.py) - Flask application
- [ai_chatbot.py](./dashboard/ai_chatbot.py) - AI integration
- [AI_CHATBOX_SETUP.md](./AI_CHATBOX_SETUP.md) - Chatbox setup guide
