# Quick Start: AI Chatbox Task Access

## Installation (Already Done!)

Your AI chatbox has been enhanced to access all security scan tasks. No additional installation needed!

## Quick Test (5 minutes)

### 1. Start Your Dashboard
```bash
# Make sure you're in the project directory
cd C:\playrepo\FYPProject

# Start the dashboard
docker-compose up -d dashboard
```

### 2. Login
- Open: http://localhost:8080
- Username: admin
- Password: changeme123!

### 3. Run a Test Scan
- Click "New Scan"
- Enter a URL: `http://localhost:9000` (or any test target)
- Click "Start Scan"

### 4. Try the Chatbox
- Look for the chat icon in the bottom-right corner
- Click to open the chatbox
- Try these questions:

```
"What scans are running?"
"Show me the latest vulnerabilities"
"What's the status of my scans?"
"How many critical vulnerabilities were found?"
"What should I fix first?"
```

## That's It! 🎉

The chatbox now automatically:
✅ Detects when you're asking about tasks
✅ Fetches current scan information
✅ Provides AI-powered insights
✅ Gives real-time security status

## New Commands Available

### For Dashboard Users
```
/api/tasks                    # See all scans
/api/tasks/scan123           # See details of specific scan
/api/chat                    # Chat with AI about tasks
```

### For Developers
```python
# Python example
import requests

token = "your_jwt_token"
response = requests.get(
    "http://localhost:8080/api/tasks",
    headers={"X-Auth-Token": token}
)
scans = response.json()["tasks"]
```

```bash
# Bash example
curl -H "X-Auth-Token: $TOKEN" \
  http://localhost:8080/api/tasks?limit=10
```

## Example Responses

### Ask About Running Scans
**You:** "What tasks are currently running?"

**Chatbot:** "I see 1 scan currently running:

- scan_abc123: http://vulnerable-app.local (Exploitation phase, 65% complete)

The scan started about 10 minutes ago and should complete in approximately 15 more minutes. So far, 8 vulnerabilities have been detected, including 1 critical SQL injection issue."

### Ask About Vulnerabilities
**You:** "What vulnerabilities were found?"

**Chatbot:** "The latest scan found 12 vulnerabilities:

**CRITICAL (1):**
- SQL Injection in /api/users - User input not validated

**HIGH (3):**
- Cross-Site Scripting (XSS) in search
- Weak authentication on admin panel
- Insecure API endpoints

**MEDIUM (5):**
- Missing security headers
- Outdated dependencies
- Debug info exposed
- Weak cookie settings
- Default credentials

**LOW (3):**
- Information disclosure
- Banner grabbing enabled
- Unnecessary services

I recommend prioritizing the SQL Injection fix immediately."

## Key Features

🎯 **Smart Detection** - Chatbox automatically knows when you're asking about tasks
🔍 **Real-time Data** - Always gets current scan information
🤖 **AI Insights** - Provides security expert analysis
📊 **Rich Context** - Shows severity, endpoints, recommendations
⚡ **Fast Response** - No manual dashboard navigation needed
🔐 **Secure** - Only for authenticated users

## Common Questions

**Q: Can I manage tasks from the chatbox?**
A: Currently, the chatbox is read-only (viewing only). You can still manage tasks from the main dashboard.

**Q: How often is scan data updated?**
A: The chatbox queries live data each time you send a message, so it's always current.

**Q: What if I have no scans running?**
A: The chatbox will tell you about completed scans and previous vulnerabilities found.

**Q: Is my data private?**
A: Yes! Only authenticated users can access scan data through the API.

## Next Steps

1. **Read the Full Guide:** `CHATBOX_TASK_ACCESS.md`
2. **Review Implementation:** `CHATBOX_TASK_ACCESS_IMPLEMENTATION.md`
3. **Run Test Script:** `python test_chatbox_tasks.py`
4. **Schedule Regular Scans:** Set up automated scanning
5. **Monitor via Chat:** Get daily security briefings

## API Documentation

### GET /api/tasks
Returns all security scans with summary info.
```bash
curl -H "X-Auth-Token: token" http://localhost:8080/api/tasks
```

### GET /api/tasks/{id}
Returns detailed information about a specific scan.
```bash
curl -H "X-Auth-Token: token" http://localhost:8080/api/tasks/scan123
```

### POST /api/chat
Chat with AI about security tasks.
```bash
curl -X POST -H "X-Auth-Token: token" \
  -d '{"message":"What tasks are running?"}' \
  http://localhost:8080/api/chat
```

## Troubleshooting

**"I don't see task info in chat"**
→ Make sure a scan has run before asking. Try running a quick scan first.

**"API returns 401"**
→ Your session may have expired. Re-login to the dashboard.

**"Chatbox not responding"**
→ Check browser console (F12) for errors. Restart dashboard if needed.

## Files Added/Modified

### Modified Files
- `dashboard/app.py` - Added task API endpoints and chat context
- `dashboard/ai_chatbot.py` - Updated AI system prompt
- `dashboard/static/js/chatbox.js` - Enhanced task query detection

### New Files
- `CHATBOX_TASK_ACCESS.md` - Full user guide
- `CHATBOX_TASK_ACCESS_IMPLEMENTATION.md` - Technical details
- `test_chatbox_tasks.py` - Validation test script

## Support

Having issues? Try:
1. Running `test_chatbox_tasks.py` to diagnose
2. Checking `CHATBOX_TASK_ACCESS.md` FAQ section
3. Reviewing dashboard logs: `docker-compose logs dashboard`

---

**Congratulations!** Your AI chatbox now has intelligent access to all security tasks on your website. 🚀

For detailed guides and examples, see the documentation files included in the project.
