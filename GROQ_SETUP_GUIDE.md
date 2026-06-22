# 🚀 Groq Setup Guide (Free AI - No Payment!)

## ✅ Current Status

Your chatbot code is now updated to support **Groq** (completely FREE).

| What | Status |
|------|--------|
| Chatbot code | ✅ Updated for Groq |
| Dependencies | ✅ Added to requirements.txt |
| .env file | ✅ Ready for your key |
| OpenAI key | ✅ Already set (backup) |

---

## 🚀 **Step 1: Get Free Groq API Key (2 minutes)**

### Visit Groq Console:
https://console.groq.com

### Sign Up:
1. Click **"Sign Up"**
2. Use **email** or **GitHub** (your choice)
3. Verify your email
4. Complete profile

### Create API Key:
1. Click **"API Keys"** in the sidebar
2. Click **"Create API Key"**
3. **Copy the entire key** (starts with `gsk_`)
4. Save it somewhere safe!

---

## 📝 **Step 2: Add Your Groq Key to .env**

### Open File:
`C:\playrepo\FYPProject\.env`

### Find This Line:
```
GROQ_API_KEY=
```

### Replace With:
```
GROQ_API_KEY=gsk_YOUR_KEY_HERE
```

**Example (DO NOT USE):**
```
GROQ_API_KEY=gsk_abc123def456ghi789jklmnop
```

### Save the File

---

## 🔄 **Step 3: Rebuild & Restart Dashboard**

Run this command:

```powershell
cd C:\playrepo\FYPProject
docker-compose up -d --build
```

Wait 10-15 seconds for startup.

---

## 🧪 **Step 4: Test Your ChatBox**

1. Open browser: **http://localhost:8080**
2. Login:
   - Username: `admin`
   - Password: `changeme123!`
3. Find **Chat** section
4. Ask a question:
   - "What is SQL injection?"
   - "How do I prevent XSS?"
   - "Explain CSRF protection"

### Expected Result:
✅ You see a real AI response from Groq (usually in 1-2 seconds)

---

## ✨ **Why Groq is Great**

| Feature | Value |
|---------|-------|
| **Cost** | 💰 Completely FREE |
| **API Calls** | Unlimited |
| **Speed** | ⚡ Very fast (1-2 sec) |
| **Quality** | ⭐ Excellent |
| **Setup** | 🚀 2 minutes |
| **Model** | mixtral-8x7b-32768 |

**Best part:** Groq is actually FASTER than OpenAI and it's completely FREE! 🎉

---

## 🔍 **What If It Doesn't Work?**

### Issue: "AI chatbot not available"
**Fix:** 
1. Did you add your Groq key to `.env`?
2. Check: `GROQ_API_KEY=gsk_...` (should have value)
3. Restart: `docker-compose restart pentest_dashboard`
4. Wait 10 seconds

### Issue: "Error 500" when chatting
**Fix:**
1. Check logs: `docker logs pentest_dashboard 2>&1 | grep -i "error\|groq"`
2. Verify Groq key is correct
3. Restart: `docker-compose restart pentest_dashboard`

### Issue: "Rate limit exceeded"
**Fix:** Groq free tier allows many requests. Usually not an issue.

### Issue: Nothing happens when you click "Send"
**Fix:**
1. Open browser console (F12)
2. Check for errors
3. Check Docker logs: `docker logs pentest_dashboard`

---

## 💡 **Security Reminder**

✅ **DO:**
- Keep your Groq key in `.env`
- Keep `.env` in `.gitignore` (already done ✓)
- Don't share your key

❌ **DO NOT:**
- Share Groq key with anyone
- Commit `.env` to Git
- Put key in code or documentation

---

## 📊 **Groq Model Details**

Your chatbot uses: **mixtral-8x7b-32768**

| Property | Value |
|----------|-------|
| Model Name | Mixtral 8x7B |
| Context Window | 32,768 tokens |
| Speed | Very fast |
| Quality | Excellent |
| Cost | FREE |

This is a powerful open-source model that's completely FREE on Groq!

---

## 🎯 **What's Next?**

1. ✅ Add Groq key to `.env`
2. ✅ Restart Docker: `docker-compose up -d --build`
3. ✅ Test chatbox at http://localhost:8080
4. ✅ Ask it security questions!

---

## 📞 **Troubleshooting Commands**

### Check if Groq is initialized:
```powershell
docker logs pentest_dashboard | grep -i "groq\|OK"
```

### View .env file:
```powershell
Get-Content C:\playrepo\FYPProject\.env | Select-String GROQ
```

### Restart everything:
```powershell
cd C:\playrepo\FYPProject
docker-compose down
docker-compose up -d --build
Start-Sleep -Seconds 10
```

### Check if dashboard is running:
```powershell
docker ps | Select-String "pentest_dashboard"
```

---

## ✅ **Success Indicators**

When working correctly, you'll see:

**In logs:**
```
[OK] Groq API initialized (FREE)
```

**In chatbox:**
- Questions get answered in 1-2 seconds
- Responses are from Groq (real AI)
- No "Error 500" messages

**In your .env:**
```
GROQ_API_KEY=gsk_abc123...xyz
```

---

## 🎉 **That's It!**

You now have a completely FREE AI chatbox using Groq! No payment needed, no rate limits issues, super fast responses.

**Enjoy your secure, free AI assistant!** 🚀
