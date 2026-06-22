# Testing Guide - AI Chatbox Scan Control

## Pre-Test Checklist

- [ ] Dashboard running: `docker-compose up -d dashboard`
- [ ] Browser ready
- [ ] Test URLs available (localhost or internal network)
- [ ] Admin account available (admin/changeme123!)

## Test 1: Simple URL Scan

**Objective:** Verify basic scan triggering

**Steps:**
1. Login to dashboard: http://localhost:8080
2. Open chatbox (bottom-right corner)
3. Type: `"Scan http://localhost:9000"`
4. Observe: Chatbot detects URL and starts scan
5. Expected: 
   - ✓ Message shows "Scan started successfully!"
   - ✓ Scan ID displayed
   - ✓ Target URL shown
   - ✓ Link to scan dashboard provided

**Result:** ✅ PASS / ❌ FAIL

---

## Test 2: Domain-Only URL

**Objective:** Test auto-protocol addition

**Steps:**
1. In chatbox, type: `"Check example.com"`
2. Observe: Chatbot extracts domain without protocol
3. Expected:
   - ✓ URL auto-corrected to http://example.com
   - ✓ Scan starts for corrected URL
   - ✓ Confirmation shows http://example.com

**Result:** ✅ PASS / ❌ FAIL

---

## Test 3: Invalid URL Rejection

**Objective:** Verify URL validation

**Steps:**
1. Type: `"Scan http://invalid..url..com"`
2. Observe: Chatbot validates URL
3. Expected:
   - ✓ Scan is rejected
   - ✓ Error message explains why
   - ✓ User can try with valid URL

**Result:** ✅ PASS / ❌ FAIL

---

## Test 4: Schedule Scan

**Objective:** Test scheduling functionality

**Steps:**
1. Type: `"Schedule daily scans of example.com"`
2. Observe: Chatbot suggests schedule patterns
3. Type: `"Daily at midnight"`
4. Expected:
   - ✓ Schedule created successfully
   - ✓ Schedule ID shown
   - ✓ Cron pattern displayed
   - ✓ Confirmation message

**Result:** ✅ PASS / ❌ FAIL

---

## Test 5: Rate Limiting

**Objective:** Verify rate limit enforcement

**Steps:**
1. Start 4 scans in quick succession
2. Observe: 4th scan is rate-limited
3. Expected:
   - ✓ First 3 scans succeed
   - ✓ 4th scan rejected with "Rate limit exceeded"
   - ✓ Message suggests waiting

**Result:** ✅ PASS / ❌ FAIL

---

## Test 6: Scan Progress Monitoring

**Objective:** Track scan progress via chat

**Steps:**
1. Start a scan with: `"Scan http://vulnerable-app.local"`
2. Wait 30 seconds
3. Type: `"How's my scan progressing?"`
4. Expected:
   - ✓ Chat shows scan status
   - ✓ Progress percentage displayed
   - ✓ Current phase shown

**Result:** ✅ PASS / ❌ FAIL

---

## Test 7: Multiple URLs

**Objective:** Verify multiple URL handling

**Steps:**
1. Type: `"Scan example.com and api.example.com"`
2. Observe: Chatbot processes first URL
3. Expected:
   - ✓ First URL scanned immediately
   - ✓ Second URL ignored (or suggested for next request)
   - ✓ Only one scan ID returned

**Result:** ✅ PASS / ❌ FAIL

---

## Test 8: Dashboard Integration

**Objective:** Verify scans appear on main dashboard

**Steps:**
1. Start a scan via chatbox: `"Scan localhost:3000"`
2. Note scan ID (e.g., a1b2c3d4)
3. Click on scan link in chatbox
4. Expected:
   - ✓ Scan visible on dashboard
   - ✓ Status shows "running"
   - ✓ Progress bar updates
   - ✓ Scan details accessible

**Result:** ✅ PASS / ❌ FAIL

---

## Test 9: Natural Language Detection

**Objective:** Verify intent recognition

**Steps:**
1. Type: `"I want to audit my API at api.example.com"`
2. Expected:
   - ✓ Chatbot detects "audit" keyword
   - ✓ Recognizes URL
   - ✓ Starts scan automatically

**Steps:**
2. Type: `"Can you monitor staging.example.com weekly?"`
3. Expected:
   - ✓ Chatbot detects schedule intent
   - ✓ Extracts URL
   - ✓ Shows schedule options
   - ✓ Allows user to confirm

**Result:** ✅ PASS / ❌ FAIL

---

## Test 10: API Direct Call

**Objective:** Verify API endpoints work directly

**Steps:**
```bash
# Get auth token
TOKEN=$(curl -s -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme123!"}' \
  | jq -r '.token')

# Start scan via API
curl -X POST http://localhost:8080/api/scan-now \
  -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:9000"}'
```

**Expected:**
- ✓ Token obtained successfully
- ✓ Scan started via API
- ✓ Response includes scan_id
- ✓ Status shows "success"

**Result:** ✅ PASS / ❌ FAIL

---

## Test 11: Authentication Required

**Objective:** Verify unauthenticated access is denied

**Steps:**
```bash
# Try API without auth
curl -X POST http://localhost:8080/api/scan-now \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:9000"}'
```

**Expected:**
- ✓ Returns 401 Unauthorized
- ✓ Error message about authentication
- ✗ Scan NOT started

**Result:** ✅ PASS / ❌ FAIL

---

## Test 12: Scan ID Validity

**Objective:** Verify returned scan IDs are correct

**Steps:**
1. Start scan: `"Scan http://localhost:3000"`
2. Note the returned Scan ID (e.g., x1y2z3w4)
3. Check dashboard: Should see scan with same ID
4. Type in chat: `"Show status of x1y2z3w4"`
5. Expected:
   - ✓ Chatbot recognizes scan ID
   - ✓ Shows current status
   - ✓ Displays findings

**Result:** ✅ PASS / ❌ FAIL

---

## Test 13: Cron Pattern Validation

**Objective:** Verify cron patterns are validated

**Steps:**
1. Try to schedule with invalid pattern: `"0 0 0 0"`
2. Expected:
   - ✓ Schedule rejected
   - ✓ Error explains issue
   - ✓ Suggests valid pattern

**Steps:**
2. Try with valid pattern: `"0 0 * * *"`
3. Expected:
   - ✓ Schedule accepted
   - ✓ Confirmation shown

**Result:** ✅ PASS / ❌ FAIL

---

## Test 14: Long-Running Scan Status

**Objective:** Monitor extended scan progress

**Steps:**
1. Start a full scan: `"Audit http://vulnerable-app.local"`
2. Wait 5 minutes
3. Ask: `"How's the scan progressing?"`
4. Expected:
   - ✓ Progress percentage increased
   - ✓ Phase has progressed
   - ✓ Estimated time remaining shown

**Result:** ✅ PASS / ❌ FAIL

---

## Test 15: Error Recovery

**Objective:** Test error handling

**Steps:**
1. Type: `"Scan invalid://url"`
2. Expected: Error message
3. Type: `"Scan http://localhost:3000"`
4. Expected:
   - ✓ Previous error doesn't prevent new scan
   - ✓ Valid scan starts normally
   - ✓ Chat state recovered

**Result:** ✅ PASS / ❌ FAIL

---

## Comprehensive Test Summary

| Test | Description | Result |
|------|-------------|--------|
| 1 | Simple URL scan | ✓ / ❌ |
| 2 | Domain-only URL | ✓ / ❌ |
| 3 | Invalid URL rejection | ✓ / ❌ |
| 4 | Schedule scan | ✓ / ❌ |
| 5 | Rate limiting | ✓ / ❌ |
| 6 | Progress monitoring | ✓ / ❌ |
| 7 | Multiple URLs | ✓ / ❌ |
| 8 | Dashboard integration | ✓ / ❌ |
| 9 | Natural language | ✓ / ❌ |
| 10 | API direct call | ✓ / ❌ |
| 11 | Auth required | ✓ / ❌ |
| 12 | Scan ID validity | ✓ / ❌ |
| 13 | Cron validation | ✓ / ❌ |
| 14 | Long scan status | ✓ / ❌ |
| 15 | Error recovery | ✓ / ❌ |

**Overall Result:** ✅ PASS (all 15 tests passed) / ❌ NEEDS FIXES

---

## Troubleshooting During Testing

| Issue | Solution |
|-------|----------|
| Chatbox not showing | Refresh page (Ctrl+F5) |
| Scan not starting | Check rate limit, wait 1 minute |
| Invalid token error | Re-login to dashboard |
| URL not detected | Include full URL with protocol |
| Dashboard shows nothing | Refresh dashboard page |
| Chat not responding | Check browser console for errors |

---

## Performance Benchmarks

After tests, verify these metrics:

- **Scan start latency:** < 2 seconds
- **API response time:** < 500ms
- **Chat response time:** < 5 seconds
- **URL extraction:** < 100ms
- **Intent detection:** < 50ms

---

## Post-Test Verification

✓ Verify in browser console (F12):
- No JavaScript errors
- Network requests successful
- CSS styling intact

✓ Verify in dashboard logs:
```bash
docker-compose logs dashboard | grep -i "scan\|chatbox\|error"
```

✓ Check scan results:
- Navigate to scan report
- Verify findings are displayed
- Check that vulnerabilities are listed

---

## Sign-Off

**Tester Name:** ________________  
**Test Date:** ________________  
**Overall Status:** ✅ PASS / ❌ FAIL  
**Notes:** ________________________________________

---

## Next Steps if All Tests Pass

1. Deploy to production
2. Monitor for errors in logs
3. Gather user feedback
4. Prepare update documentation
5. Plan Phase 2 enhancements

---

**Testing Complete!** 🎉
