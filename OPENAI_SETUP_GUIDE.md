# 🤖 OpenAI Setup Guide for ChatBox

## ✅ Status: Ready for Your API Key

Your dashboard is now running and ready for OpenAI integration. Follow these steps:

---

## 🚀 **Step 1: Get Your Free OpenAI API Key**

### Visit this link:
https://platform.openai.com/account/api-keys

### Sign Up (if needed):
- Click "Sign up"
- Use email or GitHub account
- Verify your account

### Add Free $5 Credits:
1. Go to: https://platform.openai.com/account/billing/overview
2. Click "Add to prepaid balance"
3. Add $5 or more (lasts ~1 month of testing)
4. Add credit/debit card (or prepaid card)

### Create API Key:
1. Go back to: https://platform.openai.com/account/api-keys
2. Click **"+ Create new secret key"**
3. **Copy the entire key** (it looks like: `sk-proj-abc123...xyz`)
4. ⚠️ **IMPORTANT:** Save it somewhere safe! You won't see it again.

---

## 📝 **Step 2: Add Your Key to .env**

### Open your .env file:
`C:\playrepo\FYPProject\.env`

### Find this section:
```
OPENAI_API_KEY=
```

### Replace with your key:
```
OPENAI_API_KEY=sk-proj-YOUR_ACTUAL_KEY_HERE
```

**Example (DO NOT USE THIS):**
```
OPENAI_API_KEY=sk-proj-abc123def456ghi789jklmnop
```

---

## 🔄 **Step 3: Restart Dashboard**

Run this command:

```powershell
cd C:\playrepo\FYPProject
docker-compose restart pentest_dashboard
```

Wait ~10 seconds for restart.

---

## 🧪 **Step 4: Test the ChatBox**

1. Open browser: **http://localhost:8080**
2. Login with:
   - Username: `admin`
   - Password: `changeme123!`
3. Find the **Chat** section
4. Ask a question like:
   - "What is SQL injection?"
   - "How do I prevent XSS?"
   - "Explain CSRF protection"

### Expected Results:
- ✅ You see a response from OpenAI
- ✅ Chat history appears below
- ❌ If you see "Error 500" → Key is missing or wrong

---

## 🐛 **Troubleshooting**

### Problem: "AI chatbot not available"
**Solution:** API key is missing or empty in `.env`
- Check: `OPENAI_API_KEY=` (should have a value after =)
- Make sure there are no spaces at the beginning
- Restart: `docker-compose restart pentest_dashboard`

### Problem: "Error 500" in chatbox
**Solution:** API key is invalid
- Check if key starts with `sk-proj-`
- Check OpenAI console to verify key exists
- Make sure you copied the entire key (no missing characters)
- Restart dashboard

### Problem: "Rate limit exceeded"
**Solution:** You're out of free credits
- Go to: https://platform.openai.com/account/billing/usage
- Check your usage
- Add more credits if needed

### Problem: "Invalid API key"
**Solution:** Your key may have expired or been revoked
- Go to: https://platform.openai.com/account/api-keys
- Delete the old key
- Create a new key
- Update `.env` with new key
- Restart dashboard

---

## 📊 **Free Tier Details**

| Feature | OpenAI Free Tier |
|---------|-----------------|
| Cost | $5 free credits (then paid) |
| Model | `gpt-4o-mini` (affordable) |
| Speed | Fast (~2-5 sec per response) |
| Quality | Excellent |
| Setup | 5 minutes |
| Restart needed | Yes |

**Pricing:** After $5, typically $0.01-0.05 per message depending on length.

---

## 🔐 **Security Reminders**

✅ **DO:**
- Keep API key in `.env` only
- Rotate keys every 90 days
- Keep `.env` in `.gitignore`
- Monitor usage at: https://platform.openai.com/account/billing/usage

❌ **DO NOT:**
- Share API key with anyone
- Commit `.env` to Git
- Put key in code or documentation
- Use in production without rate limiting

---

## ✨ **What to Ask the ChatBox**

Your chatbox is trained on cybersecurity topics:

**Good questions:**
- "What is SQL injection and how do I prevent it?"
- "Explain XSS vulnerabilities"
- "How do I implement CSRF protection?"
- "What's the difference between IDOR and privilege escalation?"
- "Best practices for authentication"
- "How to secure APIs"
- "OWASP Top 10 explanation"

**It will also understand:**
- Code examples
- Vulnerability descriptions
- Security best practices
- Compliance questions (NIST, ISO 27001, CIS)
- Threat modeling

---

## 📞 **Need Help?**

1. Check the logs:
   ```powershell
   docker logs pentest_dashboard
   ```

2. Check if OpenAI service is up:
   ```powershell
   docker exec pentest_dashboard curl -s https://api.openai.com/v1/models -H "Authorization: Bearer YOUR_KEY" | Select-String -Pattern "gpt"
   ```

3. Verify key in .env:
   ```powershell
   Get-Content C:\playrepo\FYPProject\.env | Select-String "OPENAI"
   ```

---

## 🎯 **Summary**

1. ✅ Get free API key from OpenAI (5 min)
2. ✅ Add key to `.env` file
3. ✅ Restart dashboard
4. ✅ Test in browser at http://localhost:8080
5. ✅ Start chatting!

**Status:** Ready to go! Just add your key and restart.
