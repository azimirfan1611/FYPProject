# AI Chatbox Task Access Guide

Your AI chatbox can now access and provide insights about all security scan tasks running on your website.

## New Features

### 1. Automatic Task Detection
The chatbox automatically detects when you're asking about tasks/scans and provides relevant information. Just ask naturally:

- "What scans are running?"
- "Show me the latest vulnerability findings"
- "What's the status of my current scans?"
- "How many critical vulnerabilities were found?"
- "List all completed scans"

### 2. New API Endpoints

#### Get All Tasks
```
GET /api/tasks?limit=50&status=running
```
Returns a list of all security scan tasks with:
- Task ID and URL
- Current status and phase
- Progress percentage
- Risk rating
- Finding counts (critical, high, medium, low, info)
- Start/completion times

**Example Response:**
```json
{
  "tasks": [
    {
      "id": "scan123",
      "url": "https://example.com",
      "status": "running",
      "phase": "Exploitation",
      "progress_pct": 65,
      "risk_rating": "HIGH",
      "total_findings": 12,
      "critical_count": 2,
      "high_count": 4,
      "started_at": "2024-01-15T10:30:00"
    }
  ],
  "total_count": 45
}
```

#### Get Task Details
```
GET /api/tasks/{task_id}
```
Returns detailed information about a specific task:
- Full vulnerability list grouped by severity
- Detailed finding descriptions
- Affected endpoints
- Scanner information

**Example Response:**
```json
{
  "id": "scan123",
  "url": "https://example.com",
  "status": "complete",
  "risk_rating": "HIGH",
  "total_findings": 12,
  "findings_by_severity": {
    "CRITICAL": [
      {
        "title": "SQL Injection",
        "description": "User input is directly concatenated...",
        "endpoint": "/api/users",
        "scanner": "sqlmap"
      }
    ],
    "HIGH": [...],
    "MEDIUM": [...]
  },
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1,
    "info": 0
  }
}
```

### 3. Enhanced Chatbot Context

The chatbot now automatically receives:
- Summary of all running and completed scans
- Latest vulnerability findings
- Risk ratings and severity counts
- Phase information for ongoing scans

This allows it to provide context-aware responses about your security posture.

## Usage Examples

### Example 1: Check Running Scans
**You:** "What tasks are currently running?"

**AI:** "I see 3 scans currently running:
- scan_001: https://api.example.com (Exploitation phase, 45% complete)
- scan_002: https://app.example.com (Analysis phase, 60% complete)  
- scan_003: https://admin.example.com (Recon phase, 20% complete)

The scan of api.example.com is progressing through the exploitation phase and should complete in about 15 minutes."

### Example 2: Vulnerability Summary
**You:** "Show me the vulnerabilities from the latest scan"

**AI:** "The latest scan of https://example.com found 8 vulnerabilities:

**CRITICAL (1):**
- SQL Injection in /api/users endpoint - User input is not sanitized...

**HIGH (2):**
- XSS vulnerability in search field - Reflected cross-site scripting...
- Weak password requirements - No complexity validation...

**MEDIUM (4):**
- Missing security headers
- Outdated dependencies
- Insecure cookie settings
- Debug endpoints exposed

I recommend prioritizing the SQL Injection fix immediately."

### Example 3: Track Specific Scan
**You:** "What's the status of scan scan_abc?"

**AI:** "Scan scan_abc targeting https://shop.example.com:
- Status: Running
- Phase: Exploitation (Phase 3 of 4)
- Progress: 72% complete
- Started: 2024-01-15 at 10:30 AM
- Estimated completion: 30 minutes

So far, 15 vulnerabilities have been detected:
- 1 CRITICAL
- 3 HIGH
- 7 MEDIUM
- 4 LOW

The critical finding is a SQL Injection in the product search endpoint."

## How It Works

1. **Automatic Detection**: The chatbox detects task-related keywords in your message
2. **API Query**: It fetches current task information from `/api/tasks` endpoint
3. **Context Enhancement**: Task data is included in the AI's context
4. **Smart Response**: The AI provides insights based on actual scan data
5. **Task Links**: In the chat, you can ask for specific task IDs to get detailed reports

## Benefits

✅ **Real-time Insights**: Get immediate summaries of running scans
✅ **No Manual Checking**: Ask the chatbox instead of navigating the dashboard
✅ **Natural Language**: Ask questions naturally, get security-aware responses
✅ **Trend Analysis**: Understand vulnerability patterns across scans
✅ **Risk Assessment**: Understand which vulnerabilities need immediate attention
✅ **Historical Context**: Reference previous scans for comparison

## Supported Queries

The chatbox can help with:
- Current scan status and progress
- Vulnerability findings and severity
- Risk ratings and recommendations
- Task history and trends
- Comparative analysis between scans
- Security best practices for found vulnerabilities
- Remediation guidance
- Compliance implications

## Rate Limiting

- Chat requests: 10 per minute
- Task API calls: Included in chat requests
- No additional rate limits for task queries

## Security & Permissions

- Only authenticated users can access task information
- Permissions follow your dashboard role (admin/analyst/viewer)
- All task data is encrypted in transit
- Chat history is stored server-side and associated with your session

## Troubleshooting

**"Chatbot not responding to task queries"**
- Ensure you have an active scan running or completed scans in history
- Check that you're logged in to the dashboard
- Refresh the page and try again

**"No findings displayed"**
- The scan may still be in progress (Recon/Analysis phases)
- Wait for the scan to reach the Exploitation or Reporting phase
- Try again after 5-10 minutes

**"Task information is stale"**
- The chatbox updates automatically from live scan data
- Refresh your page to get the latest updates
- Each chat request fetches fresh data

## Tips

💡 Be specific with scan IDs when you want details about particular scans
💡 Ask about "critical" or "high" vulnerabilities to focus on urgent issues
💡 Request "recommendations" to get mitigation strategies from the AI
💡 Use "compare" to analyze differences between two scans
💡 Ask for "trend analysis" across multiple scans to see improvements

## Example Prompts for the Chatbox

```
"What are the top 5 most critical vulnerabilities across all scans?"
"Give me a summary of all running scans"
"What did the scan of example.com find?"
"How many SQL injection issues have we found this week?"
"What's the risk rating for the latest scan?"
"Show me all scans with critical vulnerabilities"
"Recommend the top 3 things I should fix"
"Are we more secure than last week?"
"What phase is scan_xyz in?"
"List all completed scans from today"
```

## API Usage (for developers)

If you want to integrate task access in your own applications:

### JavaScript Example
```javascript
// Fetch all tasks
const response = await fetch('/api/tasks?limit=50');
const data = await response.json();
console.log(data.tasks);  // Array of scan objects

// Fetch specific task details
const taskResponse = await fetch('/api/tasks/scan123');
const taskData = await taskResponse.json();
console.log(taskData.findings_by_severity);  // Grouped vulnerabilities
```

### Python Example
```python
import requests

# Get all tasks
response = requests.get('http://localhost:8080/api/tasks', 
                       headers={'X-Auth-Token': 'your_token'})
tasks = response.json()['tasks']

# Get task details
task_response = requests.get(f'http://localhost:8080/api/tasks/{task_id}',
                            headers={'X-Auth-Token': 'your_token'})
task_data = task_response.json()
```

## Next Steps

- Try asking the chatbox about your current scans
- Use task IDs to get detailed vulnerability reports
- Set up scheduled scans and monitor them via chat
- Create custom reports by asking the chatbox specific questions
- Share insights with your team via the chat history

Enjoy enhanced security monitoring with your AI-powered chatbox!
