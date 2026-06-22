# AI Chatbox Scan Control Guide

Your AI chatbox can now **start security scans immediately** and **schedule automated scanning** by simply providing URLs in chat messages!

## Quick Start

### 1. Start a Scan via Chat

Just ask the chatbox to scan a URL:

```
You: "Scan https://example.com for vulnerabilities"
Chatbot: "✓ Scan started successfully! 
🔍 Scan ID: a1b2c3d4
📍 Target: https://example.com
You can check progress on the dashboard or ask me for updates!"
```

### 2. Schedule Automated Scans

Ask the chatbox to schedule recurring scans:

```
You: "Schedule daily scans of https://api.example.com"
Chatbot: "📅 Would you like me to schedule a scan of https://api.example.com?
Suggested schedules:
• 0 * * * * (every hour)
• 0 0 * * * (daily)
• 0 0 * * 0 (weekly)"
```

## How It Works

### Automatic URL Detection
The chatbox automatically:
1. **Detects URLs** in your messages
2. **Identifies your intent** (scan vs schedule)
3. **Initiates actions** with a single message
4. **Confirms execution** with scan details

### URL Format Support
The chatbox accepts URLs in these formats:
- Full URLs: `https://example.com`
- Short URLs: `example.com` (auto-adds `http://`)
- Multiple URLs: Scans the first one (others ignored)

### Intent Detection

The chatbox recognizes these patterns:

**Immediate Scan:**
- "Scan https://..."
- "Check https://..."
- "Audit https://..."
- "Test https://..."
- "Penetrate https://..."

**Schedule Scan:**
- "Schedule https://..."
- "Monitor https://..."
- "Schedule recurring scans"
- "Daily scans of..."
- "Weekly monitoring of..."

## Example Conversations

### Example 1: Quick Scan

```
You: "I want to scan my new API at api.myapp.local"
Chatbot: "✓ Scan started successfully!
🔍 Scan ID: f7e8d9c0
📍 Target: http://api.myapp.local
You can check progress on the dashboard or ask me for updates!
Estimated time: 20-40 minutes depending on target complexity"
```

### Example 2: Immediate Vulnerability Check

```
You: "Quickly check https://example.com for SQL injection"
Chatbot: "✓ Scan started successfully!
🔍 Scan ID: b3a4c5d6
📍 Target: https://example.com
I'll focus on SQL injection vulnerabilities during this scan.
You can ask me for progress updates: 'How's the scan going?'"
```

### Example 3: Schedule Daily Monitoring

```
You: "Can you set up a daily scan for monitoring.example.com?"
Chatbot: "📅 I'll set up daily monitoring of monitoring.example.com
Suggested schedules:
• 0 * * * * (every hour)
• 0 0 * * * (daily at midnight)
• 0 0 * * 0 (weekly on Sunday)
Which would you prefer?"

You: "Daily at midnight"
Chatbot: "✓ Scan scheduled successfully!
📅 Schedule ID: s9h8g7f6
📍 Target: monitoring.example.com
Pattern: 0 0 * * * (daily at midnight)
Scans will run automatically on this schedule."
```

### Example 4: Multiple Requests

```
You: "Can you scan https://web.example.com and schedule https://api.example.com daily?"
Chatbot: "✓ Scan started immediately for https://web.example.com
🔍 Scan ID: x1y2z3w4
📅 Would you like to schedule https://api.example.com?
I can set up daily scans if you'd like!"
```

## New API Endpoints

### POST /api/scan-now
**Start an immediate security scan**

```bash
curl -X POST http://localhost:8080/api/scan-now \
  -H "X-Auth-Token: your_token" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "status": "success",
  "message": "✓ Scan started successfully!",
  "scan_id": "a1b2c3d4",
  "url": "https://example.com",
  "scan_url": "/scan/a1b2c3d4",
  "details": "Scanning https://example.com..."
}
```

**Parameters:**
- `url` (required): Target URL to scan

**Status Codes:**
- `201` - Scan started successfully
- `400` - Missing or invalid URL
- `429` - Rate limit exceeded (3 scans/minute)
- `500` - Server error

### POST /api/schedule-scan
**Schedule recurring security scans**

```bash
curl -X POST http://localhost:8080/api/schedule-scan \
  -H "X-Auth-Token: your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "cron": "0 0 * * *"
  }'
```

**Response:**
```json
{
  "status": "success",
  "message": "✓ Scan scheduled successfully!",
  "schedule_id": "s1h2g3f4",
  "url": "https://example.com",
  "cron": "0 0 * * *",
  "details": "Scheduled scan of https://example.com..."
}
```

**Parameters:**
- `url` (required): Target URL to scan
- `cron` (required): Cron pattern for scheduling

**Cron Pattern Examples:**
- `0 * * * *` - Every hour
- `0 0 * * *` - Every day at midnight
- `0 0 * * 0` - Every Sunday at midnight
- `0 0 * * 1-5` - Every weekday at midnight
- `0 9,17 * * *` - Every day at 9 AM and 5 PM
- `*/30 * * * *` - Every 30 minutes

**Status Codes:**
- `201` - Schedule created successfully
- `400` - Missing URL or cron pattern
- `500` - Server error

## Chatbot Capabilities

The chatbot can now:

✅ **Extract URLs** from any message automatically
✅ **Detect scan intent** (immediate vs scheduled)
✅ **Start scans** via /api/scan-now endpoint
✅ **Schedule scans** via /api/schedule-scan endpoint
✅ **Confirm actions** with detailed feedback
✅ **Suggest cron patterns** for scheduling
✅ **Provide scan IDs** for tracking

## Features & Benefits

🚀 **Instant Scanning** - Start scans without leaving the chat
📅 **Automated Monitoring** - Set up recurring scans easily
🔍 **Natural Language** - Just say what you want
📊 **Real-time Feedback** - Get scan IDs and status immediately
🎯 **Context Aware** - AI understands your security needs
⏱️ **Time Saving** - No need to navigate dashboards

## Security & Limits

**Rate Limiting:**
- 3 scans can be started per minute
- 10 chat messages per minute

**URL Validation:**
- URLs must be valid and accessible
- Private/internal networks are allowed
- Invalid URLs are rejected with explanation

**Authentication:**
- All endpoints require login
- Token must be valid and not expired
- Respects user permissions

**URL Whitelist/Blacklist:**
- System validates URL safety
- Localhost and private IPs allowed
- Dangerous URLs rejected

## Supported URL Types

The chatbox can scan:
- ✅ Web applications: `https://example.com`
- ✅ APIs: `https://api.example.com/v1`
- ✅ Subdomains: `https://app.example.com`
- ✅ Ports: `https://example.com:8443`
- ✅ Local development: `http://localhost:3000`
- ✅ Internal networks: `http://192.168.1.100`

## Troubleshooting

### "Scan failed - URL rejected"
**Issue:** URL validation failed
**Solution:** Check if URL is accessible and valid

### "Rate limit exceeded"
**Issue:** Too many scans in short time
**Solution:** Wait 1 minute before starting another scan

### "Scheduling not available"
**Issue:** Scheduler module not loaded
**Solution:** Check system logs, restart dashboard

### "Scan started but not visible"
**Issue:** Scan not showing on dashboard
**Solution:** 
- Refresh dashboard page
- Check scan is in running state
- Wait for scan to progress past 0%

### Cron pattern not accepted
**Issue:** Invalid cron pattern
**Solution:** Use standard cron format (5 fields: minute hour day month weekday)

## Usage Tips

💡 **Keep URLs Simple** - Single URLs work best; provide one at a time
💡 **Use Full URLs** - Include protocol for clarity (http:// or https://)
💡 **Ask Naturally** - Use words like "scan", "check", "monitor"
💡 **Schedule Off-Peak** - Schedule scans during low-traffic times
💡 **Track with IDs** - Save scan IDs for reference
💡 **Check Progress** - Ask "How's the scan?" during execution

## Integration with Dashboard

When you start a scan via chatbox:
1. Scan appears immediately on dashboard
2. Progress updates in real-time
3. Scan ID links to full report
4. Can monitor from both chat and dashboard
5. Results accessible via API

## Example Prompts

Try these with your chatbox:

```
"Scan my application at https://app.example.com"
"Check https://api.example.com for vulnerabilities"
"Set up daily monitoring of my server"
"Schedule hourly scans of http://localhost:3000"
"Audit https://admin.example.com for security issues"
"I need to test my new API at api.test.local"
"Can you monitor https://staging.example.com weekly?"
"Start a security scan of our new app"
"Schedule automated tests for api.myapp.com"
"Scan this URL: https://example.com/app"
```

## Command Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `scan` | Start immediate scan | "Scan https://example.com" |
| `check` | Verify vulnerabilities | "Check my app for XSS" |
| `audit` | Security audit | "Audit https://api.example.com" |
| `schedule` | Set up recurring scans | "Schedule daily scans" |
| `monitor` | Ongoing monitoring | "Monitor production server" |
| `test` | Security testing | "Test for SQL injection" |

## API Integration

### JavaScript Example
```javascript
// Start a scan
const response = await fetch('/api/scan-now', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Auth-Token': 'your_token'
  },
  body: JSON.stringify({
    url: 'https://example.com'
  })
});

const result = await response.json();
console.log('Scan ID:', result.scan_id);
```

### Python Example
```python
import requests

# Start a scan
response = requests.post(
    'http://localhost:8080/api/scan-now',
    json={'url': 'https://example.com'},
    headers={'X-Auth-Token': 'your_token'}
)

scan_data = response.json()
print(f"Scan started: {scan_data['scan_id']}")
```

## Next Steps

1. **Try it now:** Open chatbox and ask to scan a URL
2. **Monitor progress:** Check dashboard for scan status
3. **Review results:** Ask chatbot for vulnerability summary
4. **Schedule scans:** Set up automated monitoring
5. **Integrate:** Use APIs for custom workflows

## Support

For issues or questions:
1. Check this guide for common scenarios
2. Review API response messages
3. Check dashboard logs
4. Verify network connectivity

---

**Your AI chatbox is now your security command center!** 🔐
