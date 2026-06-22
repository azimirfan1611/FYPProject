# AI Chatbox Task Access Integration - Implementation Summary

**Date:** 2024
**Project:** FYPProject (AutoPenTest Dashboard)
**Feature:** Enhanced AI Chatbox with Security Scan Task Access

## Overview

Your AI chatbox has been enhanced with the ability to access and provide insights about all security scanning tasks running on your website. Users can now ask natural language questions about scan status, vulnerabilities, and security findings.

## Changes Made

### 1. Backend API Endpoints (dashboard/app.py)

#### New Endpoint: GET /api/tasks
**Location:** Line ~510 in dashboard/app.py

**Purpose:** Returns a list of all security scan tasks with summary information.

**Features:**
- Supports `limit` parameter to control results (default: 50)
- Supports `status` filter (running, complete, cancelled, etc.)
- Returns tasks sorted by most recent first
- Includes vulnerability counts by severity
- Includes progress and phase information

**Response Structure:**
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
      "started_at": "2024-01-15T10:30:00",
      "completed_at": null
    }
  ],
  "total_count": 45
}
```

#### New Endpoint: GET /api/tasks/<task_id>
**Location:** Line ~550 in dashboard/app.py

**Purpose:** Returns detailed information about a specific security scan task.

**Features:**
- Returns all findings grouped by severity
- Provides detailed vulnerability descriptions
- Shows affected endpoints and scanners used
- Includes comprehensive statistics

**Response Structure:**
```json
{
  "id": "scan123",
  "url": "https://example.com",
  "status": "complete",
  "risk_rating": "HIGH",
  "total_findings": 12,
  "findings_by_severity": {
    "CRITICAL": [...],
    "HIGH": [...],
    "MEDIUM": [...],
    "LOW": [...],
    "INFO": [...]
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

### 2. Enhanced Chat API (dashboard/app.py)

**Location:** Line ~660-680 in dashboard/app.py

**Changes:**
- Chat API now collects task context before sending to chatbot
- Includes running and completed scans summary in context
- Shows top 5 running scans with their phase information
- Task information is automatically included when user enables context

**New Context Fields:**
- Total number of scans
- Number of running vs completed scans
- List of active scans with phases
- All findings from latest scan

### 3. Updated Chatbot System Prompt (dashboard/ai_chatbot.py)

**Location:** Line ~28-42 in dashboard/ai_chatbot.py

**Changes:**
- Enhanced system prompt with task access capabilities
- Informed AI about available endpoints
- Documented how to respond to task-related queries
- Added capabilities list for task operations

**New Capabilities:**
- Access and summarize security scan results
- Answer questions about ongoing/completed assessments
- Provide insights into risk ratings and severity
- Help understand security findings
- Recommend actions based on scan results
- Track security scan progress

### 4. Enhanced Chatbox Frontend (dashboard/static/js/chatbox.js)

**Location:** Line ~68-141 in chatbox.js

**Changes:**
- Added automatic task query detection
- Fetches task information when relevant keywords detected
- Detects task-related keywords: task, scan, running, status, progress, findings, vulnerab
- Passes task context to API
- Enhanced error handling for task queries

**New Features:**
- Auto-detects when user is asking about tasks
- Queries /api/tasks endpoint automatically
- Includes task context in chat request
- Provides seamless task information access

## Files Modified

1. **dashboard/app.py** (2 changes)
   - Added new endpoints for task access
   - Enhanced chat API with task context

2. **dashboard/ai_chatbot.py** (1 change)
   - Updated system prompt with task capabilities

3. **dashboard/static/js/chatbox.js** (1 change)
   - Added task query detection and context passing

## New Files Created

1. **CHATBOX_TASK_ACCESS.md**
   - Comprehensive user guide for the new feature
   - Usage examples and tips
   - API documentation
   - Troubleshooting guide

2. **test_chatbox_tasks.py**
   - Test script to validate new endpoints
   - Tests authentication
   - Tests task fetching
   - Tests chatbot integration

## How It Works

### User Workflow

1. User opens chatbox and asks about tasks
   ```
   "What scans are running?"
   "Show me vulnerabilities"
   "What's the status of my scans?"
   ```

2. Frontend detects task keywords and fetches /api/tasks

3. Task data is included in chat context

4. AI responds with insights based on actual scan data

5. User gets real-time, context-aware security information

### Data Flow

```
User Message
    ↓
[Frontend detects keywords]
    ↓
[Fetch /api/tasks if relevant]
    ↓
[POST /api/chat with task context]
    ↓
[Backend builds enhanced context]
    ↓
[AI generates response using task data]
    ↓
[Response displayed in chatbox]
```

## Features & Benefits

### For End Users
✅ **Natural Language Queries** - Ask about scans in plain English
✅ **Real-time Insights** - Get immediate security status
✅ **No Dashboard Navigation** - Access info directly from chatbox
✅ **Context Awareness** - AI understands vulnerability context
✅ **Quick Summaries** - Get executive summaries of findings
✅ **Risk Assessment** - Understand security implications

### For Developers
✅ **REST API** - Standard JSON endpoints for integration
✅ **Authenticated** - Uses existing JWT/token system
✅ **Scalable** - Handles many tasks efficiently
✅ **Extensible** - Easy to add more task-related features
✅ **Well-Documented** - Clear API documentation

## Usage Examples

### Query All Tasks
```bash
curl -H "X-Auth-Token: your_token" \
  http://localhost:8080/api/tasks?limit=10&status=running
```

### Query Specific Task
```bash
curl -H "X-Auth-Token: your_token" \
  http://localhost:8080/api/tasks/scan123
```

### Chat with Task Context
```bash
curl -X POST -H "X-Auth-Token: your_token" \
  -H "Content-Type: application/json" \
  -d '{"message":"What scans are running?","include_context":true}' \
  http://localhost:8080/api/chat
```

## Testing

### Manual Testing
1. Start the dashboard: `docker-compose up dashboard`
2. Login with admin/changeme123!
3. Run at least one security scan
4. Open the AI Chatbox (bottom-right corner)
5. Ask about your scans

### Automated Testing
Run the provided test script:
```bash
python test_chatbox_tasks.py
```

This will verify:
- Authentication works
- Task endpoints return valid data
- Task details are accessible
- Chatbot integrates with task data

## Security Considerations

✅ **Authentication Required** - Only logged-in users can access tasks
✅ **Rate Limiting** - 10 chat requests/minute per user
✅ **Permission Checks** - Respects existing dashboard role system
✅ **Data Validation** - All inputs validated before processing
✅ **Secure Context** - Task context only included when requested
✅ **XSS Protection** - AI responses properly HTML-escaped

## Performance Optimizations

- **Caching**: Scan data loaded from memory (SCANS dict)
- **Limiting**: Response limited to most recent scans
- **Filtering**: Optional status filters reduce payload
- **Threading**: Safe concurrent access with locks
- **Efficiency**: Only fetches task data when relevant

## Future Enhancements

Potential additions:
- [ ] Task comparison ("Compare scan1 and scan2")
- [ ] Trend analysis ("Are we improving?")
- [ ] Custom alerts ("Notify if critical found")
- [ ] Report generation ("Generate PDF report")
- [ ] Vulnerability tracking ("Show all SQL injections across scans")
- [ ] Remediation tracking ("Which issues are fixed?")
- [ ] Compliance reporting ("GDPR/PCI compliance status")
- [ ] Integration with ticketing systems

## Known Limitations

- Task context only includes summary, not full details
- Limited to 50 most recent tasks by default
- Cannot modify tasks through chatbox (read-only access)
- Task history limited to current session scans
- Real-time updates require page refresh for frontend

## Troubleshooting

### Chatbox doesn't show task info
- Ensure you're logged in
- Verify at least one scan exists
- Check that include_context is enabled
- Refresh page and try again

### API returns 401
- Your session token may have expired
- Re-login to the dashboard
- Verify X-Auth-Token header is correct

### No vulnerabilities displayed
- Scan may still be in early phases
- Wait for scan to reach Exploitation phase
- Check scan details directly on dashboard

## Documentation

See the following files for more information:
- **CHATBOX_TASK_ACCESS.md** - User guide and examples
- **AI_CHATBOX_SETUP.md** - Original setup instructions
- **test_chatbox_tasks.py** - Test script with examples

## Deployment

No additional deployment steps required. The changes are:
1. Pure Python backend additions (no new dependencies)
2. Pure JavaScript frontend additions (no new libraries)
3. Backward compatible with existing code

Simply restart the dashboard container:
```bash
docker-compose restart dashboard
```

## Verification Checklist

- [x] Backend endpoints working correctly
- [x] Chat API integrates task context
- [x] Chatbot system prompt updated
- [x] Frontend JavaScript working
- [x] Authentication required for all endpoints
- [x] Rate limiting applied
- [x] Error handling in place
- [x] Documentation complete
- [x] Test script provided
- [x] Backward compatible

## Support

For issues or questions:
1. Check CHATBOX_TASK_ACCESS.md for common issues
2. Run test_chatbox_tasks.py to diagnose problems
3. Check dashboard logs: `docker-compose logs dashboard`
4. Review the implementation in dashboard/app.py

---

**Summary:** Your AI chatbox can now intelligently access and provide insights about all security tasks on your website, making security monitoring more accessible and efficient.
