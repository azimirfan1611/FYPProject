# AI Chatbox Setup Guide

The AutoPenTest dashboard includes an AI-powered cybersecurity chatbox that provides real-time security guidance. It supports both **OpenAI (Free)** and **Anthropic Claude**.

## Quick Start with FREE OpenAI

### 1. Get Your Free OpenAI API Key
- Go to: https://platform.openai.com/signup
- Sign up with email or GitHub
- Navigate to: https://platform.openai.com/account/api-keys
- Click "Create new secret key"
- Copy your key (starts with `sk-`)
- OpenAI provides $5 free credits for new accounts

### 2. Set the Environment Variable
**Windows PowerShell:**
```powershell
$env:OPENAI_API_KEY = "sk-your-key-here"
docker-compose restart dashboard
```

**Linux/Mac:**
```bash
export OPENAI_API_KEY="sk-your-key-here"
docker-compose restart dashboard
```

**Or create `.env` file in project root:**
```
OPENAI_API_KEY=sk-your-key-here
```

### 3. Test the Chatbox
- Login at: http://localhost:8080 (admin/changeme123!)
- Look for the chat icon in the bottom-right corner
- Ask: "What is SQL injection?"
- You should get a cybersecurity-focused response!

---

## Alternative: Anthropic Claude (Paid)

Claude offers better responses but requires a paid subscription.

### 1. Get Your Anthropic API Key
- Go to: https://console.anthropic.com/
- Create an account and add payment method
- Navigate to: https://console.anthropic.com/keys
- Create new key
- Copy your key (starts with `sk-ant-`)

### 2. Set the Environment Variable
**Windows PowerShell:**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-your-key-here"
docker-compose restart dashboard
```

---

## How to Use the Chatbox

Once configured:

1. **Login** to the dashboard at http://localhost:8080
2. **Click the chat icon** in the bottom-right corner
3. **Ask cybersecurity questions** such as:
   - "What is XSS and how do I prevent it?"
   - "Explain SQL injection vulnerabilities"
   - "What is CSRF protection?"
   - "How should I fix the vulnerabilities in my scan results?"

## Features

✓ **Cybersecurity Expert**: Trained to answer security questions comprehensively
✓ **Context Awareness**: References your scan results if available
✓ **Conversation History**: Remembers previous messages in the chat
✓ **Rate Limiting**: 10 requests per minute (configurable)
✓ **Multi-Provider Support**: Works with OpenAI or Claude

## Pricing Comparison

| Provider | Cost | Free Tier | Model Quality |
|----------|------|-----------|---------------|
| **OpenAI** | $0.0005/1K tokens | $5 free credits | gpt-4o-mini (Good) |
| **Anthropic Claude** | $0.003/1K tokens | None | claude-3.5-sonnet (Better) |

### Estimated Usage
- Average cybersecurity question: ~150 tokens
- $5 OpenAI credit = ~33,000 tokens = ~220 questions
- At moderate use (5 questions/day) = ~45 days free

---

## Troubleshooting

**"No API key configured"**
- You haven't set OPENAI_API_KEY or ANTHROPIC_API_KEY
- See "Set the Environment Variable" section above

**"Invalid API key"**
- Check your key is correct (copy from website again)
- Ensure no extra spaces or quotes

**"Rate limit exceeded"**
- You've hit 10 requests/minute limit
- Wait a minute before sending another message
- Contact support to increase limit

**Chatbox icon not showing**
- Refresh the page (Ctrl+Shift+R)
- Check browser console for JavaScript errors
- Ensure you're logged in

---

## Getting Help

1. Check logs: `docker-compose logs dashboard`
2. Test API directly:
   ```bash
   curl -H "Authorization: Bearer sk-your-key" \
     https://api.openai.com/v1/models
   ```

3. Verify environment variable:
   ```powershell
   $env:OPENAI_API_KEY  # Should show your key
   ```
