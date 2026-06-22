# Chatbox Scan Control - Quick Reference

## 🚀 Start a Scan

**Ask the chatbox:**
```
"Scan https://example.com"
"Check my app at http://localhost:3000"
"Audit https://api.example.com for vulnerabilities"
```

**Chatbot will:**
1. Extract the URL
2. Validate it
3. Start the scan
4. Give you the scan ID

**Response example:**
```
✓ Scan started successfully!
🔍 Scan ID: a1b2c3d4
📍 Target: https://example.com
You can check progress on the dashboard or ask me for updates!
```

---

## 📅 Schedule Recurring Scans

**Ask the chatbox:**
```
"Schedule daily scans of https://example.com"
"Monitor api.example.com every hour"
"Set up weekly security tests"
```

**Chatbot will:**
1. Extract the URL
2. Suggest scheduling options
3. Wait for your confirmation
4. Create the schedule

**Response example:**
```
📅 I'll set up monitoring for https://example.com
Suggested schedules:
• 0 * * * * (every hour)
• 0 0 * * * (daily at midnight)
• 0 0 * * 0 (weekly on Sunday)
Which would you prefer?
```

---

## 📊 Available Cron Patterns

| Pattern | Description |
|---------|-------------|
| `0 * * * *` | Every hour |
| `0 0 * * *` | Daily (midnight) |
| `0 0 * * 0` | Weekly (Sunday midnight) |
| `0 0 * * 1-5` | Every weekday |
| `0 9 * * *` | Daily at 9 AM |
| `0 17 * * *` | Daily at 5 PM |
| `0 9,17 * * *` | Daily at 9 AM & 5 PM |
| `*/30 * * * *` | Every 30 minutes |
| `0 0 1 * *` | Monthly (1st day) |

---

## 🔍 Check Scan Status

**Ask the chatbox:**
```
"What scans are running?"
"Show me the latest scan"
"Status of scan a1b2c3d4"
"How's my scan progressing?"
```

---

## ✅ Supported URL Formats

| Format | Example | Works? |
|--------|---------|--------|
| Full HTTPS | `https://example.com` | ✅ Yes |
| Full HTTP | `http://example.com` | ✅ Yes |
| Domain only | `example.com` | ✅ Yes |
| With port | `https://example.com:8443` | ✅ Yes |
| With path | `https://example.com/app` | ✅ Yes |
| Localhost | `http://localhost:3000` | ✅ Yes |
| IP address | `http://192.168.1.100` | ✅ Yes |

---

## ⚠️ Limitations

- **Rate limit:** 3 scans per minute
- **Chat limit:** 10 messages per minute
- **URL validation:** Must be accessible
- **One URL at a time:** Process URLs individually

---

## 🔑 Required for Scheduling

**To schedule scans, you need:**
1. Valid URL
2. Cron pattern
3. Admin or Analyst role

---

## 📱 Example Conversation

```
You: Scan https://myapp.com

Chatbot: ✓ Scan started successfully!
🔍 Scan ID: xyz123abc
📍 Target: https://myapp.com
You can check progress on the dashboard or ask me for updates!

You: Schedule daily scans please

Chatbot: 📅 I'll set up daily monitoring
When would you like scans to run?
• 0 0 * * * (daily at midnight)

You: Daily at midnight works

Chatbot: ✓ Scan scheduled!
📅 Schedule ID: sch456def
📍 Target: https://myapp.com
Pattern: 0 0 * * * (daily at midnight)
Scans will run automatically!
```

---

## 🛠️ API Usage

### Start Scan via API
```bash
curl -X POST http://localhost:8080/api/scan-now \
  -H "X-Auth-Token: token" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Schedule Scan via API
```bash
curl -X POST http://localhost:8080/api/schedule-scan \
  -H "X-Auth-Token: token" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "cron": "0 0 * * *"
  }'
```

---

## ✨ Pro Tips

💡 Use simple, natural language  
💡 One URL per request  
💡 Save scan IDs for reference  
💡 Schedule off-peak times  
💡 Monitor dashboard for details  
💡 Ask for help: "What can you do?"  

---

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| "URL rejected" | Check URL is valid and accessible |
| "Rate limit" | Wait 1 minute before next scan |
| "Scan not visible" | Refresh dashboard page |
| "Can't schedule" | Confirm you have admin/analyst role |

---

## 📖 Full Documentation

For complete details, see: `CHATBOX_SCAN_CONTROL.md`

---

**Your chatbox is now your security command center!** 🚀
