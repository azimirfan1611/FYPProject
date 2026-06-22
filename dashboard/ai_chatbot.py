"""
AI Cybersecurity Chatbot Integration
Provides real-time security assistance using Groq, Anthropic Claude, or OpenAI
"""
import os
import json
import re
from datetime import datetime
from collections import defaultdict, deque

try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# System prompt for platform assistant
CYBERSECURITY_SYSTEM_PROMPT = """You are the assistant for this platform. Help users navigate the system, answer questions based on available data, summarize information, generate reports, and perform authorized actions. Never access or modify data without appropriate permissions.

CAPABILITIES:
- Access and summarize security scan results
- Answer questions about ongoing or completed vulnerability assessments
- Provide insights into risk ratings and vulnerability severity
- Help users understand security findings
- Recommend actions based on scan results
- Track security scan progress and status

SCAN CONTROL CAPABILITIES:
- Start immediate scans when user provides a URL (use /api/scan-now endpoint)
- Schedule recurring scans using simple formats:
  * "daily" - every day at midnight
  * "8 am daily" - every day at 8 AM
  * "2 pm Monday" - every Monday at 2 PM
  * "10:30 am" - every day at 10:30 AM
  * "hourly" - every hour
  * Supported days: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday
- Monitor scan progress and provide updates
- Extract URLs from user messages automatically

When users ask about:
- "What tasks are running?" - Query the /api/tasks endpoint for current scans
- "Show me the latest scan" - Retrieve details from /api/tasks endpoint
- "What vulnerabilities were found?" - Summarize findings from scan results
- "Status of [scan_id]" - Provide detailed status from /api/tasks/<task_id>
- "Scan [URL]" or "Check [URL]" - Extract URL and call /api/scan-now endpoint
- "Schedule [URL]" or "Monitor [URL]" - Extract URL and call /api/schedule-scan endpoint with cron pattern

URL EXTRACTION RULES:
- Extract all URLs from messages (http://, https://, or domains)
- Ask user to confirm if URL extraction is ambiguous
- Suggest appropriate cron patterns for scheduling (hourly: "0 * * * *", daily: "0 0 * * *", weekly: "0 0 * * 0")

Always provide context-aware responses based on actual scan data when available."""


class CybersecurityChatbot:
    """AI-powered cybersecurity assistant using Groq, Claude, or OpenAI"""
    
    def __init__(self):
        self.client = None
        self.provider = None  # "groq", "claude", "openai", or "demo"
        self.conversations = defaultdict(lambda: deque(maxlen=20))  # Keep last 20 messages per user
        self.max_context_messages = 10
        self.model = None
        
        # Try Groq first (FREE!)
        if HAS_GROQ:
            api_key = os.environ.get("GROQ_API_KEY", "")
            if api_key and api_key.strip():
                try:
                    self.client = Groq(api_key=api_key)
                    self.provider = "groq"
                    self.model = "llama-3.3-70b-versatile"  # Free model (mixtral was decommissioned)
                    print("[OK] Groq API initialized (FREE)")
                except Exception as e:
                    print(f"[WARN] Groq initialization failed: {e}")
                    self.client = None
        
        # Try OpenAI if Groq failed
        if not self.client and HAS_OPENAI:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if api_key and api_key.strip():
                try:
                    self.client = OpenAI(api_key=api_key)
                    self.provider = "openai"
                    self.model = "gpt-4o-mini"
                    print("[OK] OpenAI API initialized")
                except Exception as e:
                    print(f"[WARN] OpenAI initialization failed: {e}")
                    self.client = None
        
        # Try Claude if OpenAI failed
        if not self.client and HAS_ANTHROPIC:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key and api_key.strip():
                try:
                    self.client = Anthropic(api_key=api_key)
                    self.provider = "claude"
                    self.model = "claude-3-sonnet-20240229"
                    print("[OK] Anthropic Claude initialized")
                except Exception as e:
                    print(f"[WARN] Anthropic initialization failed: {e}")
                    self.client = None
        
        # Enable demo mode if no real APIs available
        if not self.client and os.environ.get("DEMO_MODE") == "true":
            self.provider = "demo"
            self.model = "demo (no API quota)"
            print("[OK] Demo mode enabled for responses")
    
    def is_available(self) -> bool:
        """Check if AI is available (either client is configured or mock mode is enabled)"""
        return self.client is not None or os.environ.get("DEMO_MODE") == "true"
    
    def add_message_to_history(self, user_id: str, role: str, content: str):
        """Store message in conversation history"""
        self.conversations[user_id].append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def get_conversation_context(self, user_id: str) -> list:
        """Get last N messages for Claude context"""
        messages = list(self.conversations[user_id])
        # Keep only last max_context_messages to avoid token explosion
        if len(messages) > self.max_context_messages:
            messages = messages[-self.max_context_messages:]
        # Convert to Claude format
        return [{"role": m["role"], "content": m["content"]} for m in messages]
    
    def extract_urls(self, message: str) -> list:
        """Extract URLs from message"""
        # Pattern to match URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, message)
        
        # Also match domains without protocol
        domain_pattern = r'\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b'
        domains = re.findall(domain_pattern, message, re.IGNORECASE)
        
        # Add http:// to domains
        all_urls = urls + [f"http://{d}" for d in domains if f"http://{d}" not in urls and f"https://{d}" not in urls]
        
        return list(set(all_urls))
    
    def parse_schedule_format(self, text: str) -> str:
        """
        Convert human-readable schedule format to cron pattern
        Examples:
            "8 am daily" → "0 8 * * *"
            "8 am Monday" → "0 8 * * 1"
            "9:30 pm weekly" → "30 21 * * 0"
            "daily at 2 pm" → "0 14 * * *"
            "every Monday 10 am" → "0 10 * * 1"
            "hourly" → "0 * * * *"
        """
        import re
        text_lower = text.lower().strip()
        
        hour = 0
        minute = 0
        
        # Pattern: number followed by optional colon and 2 digits, then optional am/pm
        time_pattern = r'(\d{1,2}):?(\d{2})?\s*(am|pm)?'
        time_match = re.search(time_pattern, text_lower)
        
        if time_match:
            hour = int(time_match.group(1))
            minute = int(time_match.group(2)) if time_match.group(2) else 0
            
            # Handle 12-hour to 24-hour conversion
            meridiem = time_match.group(3)
            if meridiem == 'pm' and hour != 12:
                hour += 12
            elif meridiem == 'am' and hour == 12:
                hour = 0
        
        # Build cron expression
        if 'hourly' in text_lower:
            return f"{minute} * * * *"
        elif 'monday' in text_lower or 'mon' in text_lower:
            return f"{minute} {hour} * * 1"
        elif 'tuesday' in text_lower or 'tue' in text_lower:
            return f"{minute} {hour} * * 2"
        elif 'wednesday' in text_lower or 'wed' in text_lower:
            return f"{minute} {hour} * * 3"
        elif 'thursday' in text_lower or 'thu' in text_lower:
            return f"{minute} {hour} * * 4"
        elif 'friday' in text_lower or 'fri' in text_lower:
            return f"{minute} {hour} * * 5"
        elif 'saturday' in text_lower or 'sat' in text_lower:
            return f"{minute} {hour} * * 6"
        elif 'sunday' in text_lower or 'sun' in text_lower:
            return f"{minute} {hour} * * 0"
        elif 'weekly' in text_lower:
            return f"{minute} {hour} * * 0"  # Default to Sunday
        else:
            # Default to daily
            return f"{minute} {hour} * * *"
    
    def cron_to_readable(self, cron_expr: str) -> str:
        """
        Convert cron format back to human-readable schedule
        Examples:
            "0 8 * * *" → "8:00 am daily"
            "0 8 * * 1" → "8:00 am Monday"
            "30 21 * * 0" → "9:30 pm Sunday"
        """
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return cron_expr
        
        minute, hour, _, _, day_of_week = parts
        
        try:
            minute = int(minute)
            hour = int(hour)
            day_of_week = int(day_of_week)
        except:
            return cron_expr
        
        # Convert to 12-hour format
        am_pm = "am" if hour < 12 else "pm"
        display_hour = hour % 12
        if display_hour == 0:
            display_hour = 12
        
        time_str = f"{display_hour}:{minute:02d} {am_pm}"
        
        # Map day of week
        days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
        
        if day_of_week == 0 and hour == 0 and minute == 0:
            return f"{time_str} weekly"
        elif day_of_week < 7:
            return f"{time_str} {days[day_of_week]}"
        else:
            return f"{time_str} daily"

        """Detect if user wants to scan or schedule"""
        message_lower = message.lower()
        
        # Immediate scan keywords
        scan_keywords = ['scan ', 'check ', 'audit ', 'test ', 'penetrate ', 'test it', 'scan it']
        # Schedule keywords
        schedule_keywords = ['schedule ', 'monitor ', 'recurring ', 'hourly', 'daily', 'weekly', 'regular ']
        
        scan_intent = any(keyword in message_lower for keyword in scan_keywords)
        schedule_intent = any(keyword in message_lower for keyword in schedule_keywords)
        
        urls = self.extract_urls(message)
        
        return {
            "has_urls": len(urls) > 0,
            "urls": urls,
            "scan": scan_intent,
            "schedule": schedule_intent
        }
    
    def chat(self, user_message: str, user_id: str = "default", scan_context: str = None) -> dict:
        """
        Process user message and get AI response
        
        Args:
            user_message: User's question
            user_id: Unique user identifier (for multi-user support)
            scan_context: Optional context from current scan results
            
        Returns:
            {
                "response": str,
                "error": str or None,
                "sources": list,
                "is_cached": bool
            }
        """
        if not self.is_available():
            return {
                "response": "[!] AI chatbot not available. Set OPENAI_API_KEY (free) or ANTHROPIC_API_KEY",
                "error": "No API key configured",
                "sources": [],
                "is_cached": False
            }
        
        try:
            # Add user message to history
            self.add_message_to_history(user_id, "user", user_message)
            
            # Detect scan intent and URLs
            scan_intent = self.detect_scan_intent(user_message)
            
            # Build system prompt with scan context
            system_prompt = CYBERSECURITY_SYSTEM_PROMPT
            if scan_context:
                system_prompt += f"\n\nCURRENT SCAN CONTEXT:\n{scan_context}"
            
            # Get conversation history
            messages = self.get_conversation_context(user_id)
            
            response_text = None
            
            # Try Groq (FREE!) - Groq uses same format as OpenAI
            if self.provider == "groq":
                # Groq requires system prompt in messages array (like OpenAI)
                groq_messages = [{"role": "system", "content": system_prompt}] + messages
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=1024,
                    messages=groq_messages
                )
                response_text = response.choices[0].message.content
            
            # Try Claude
            elif self.provider == "claude":
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=1024,
                    system=system_prompt,
                    messages=messages
                )
                response_text = response.content[0].text
            
            # Try OpenAI
            elif self.provider == "openai":
                # OpenAI requires system prompt in messages array
                openai_messages = [{"role": "system", "content": system_prompt}] + messages
                response = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=1024,
                    messages=openai_messages
                )
                response_text = response.choices[0].message.content
            
            # Use demo mode (no API calls needed)
            elif self.provider == "demo":
                response_text = self._generate_demo_response(user_message)
            
            # Add assistant response to history
            if response_text:
                self.add_message_to_history(user_id, "assistant", response_text)
            
            return {
                "response": response_text or "No response",
                "error": None,
                "sources": [
                    {
                        "type": self.provider,
                        "model": self.model,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                ],
                "is_cached": False,
                "scan_intent": scan_intent
            }
        
        except Exception as e:
            error_msg = str(e)
            return {
                "response": f"[!] Error: {error_msg}",
                "error": error_msg,
                "sources": [],
                "is_cached": False,
                "scan_intent": {"has_urls": False, "urls": [], "scan": False, "schedule": False}
            }
    
    def _generate_demo_response(self, message: str) -> str:
        """Generate demo security response without API calls"""
        message_lower = message.lower()
        
        if "sql injection" in message_lower:
            return """SQL Injection is a critical vulnerability where attackers insert malicious SQL code into input fields to manipulate database queries. 

Prevention methods:
1. Use parameterized queries/prepared statements
2. Input validation and sanitization
3. Least privilege database access
4. Web Application Firewalls (WAF)
5. Regular security testing

Example secure code uses placeholders: `SELECT * FROM users WHERE id = ?` with bound parameters."""
        
        elif "xss" in message_lower or "cross-site script" in message_lower:
            return """Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages. There are three types:
- Stored XSS: Malicious code saved in database
- Reflected XSS: Code reflected immediately in responses
- DOM-based XSS: Client-side vulnerability

Prevention:
1. HTML entity encoding
2. Content Security Policy (CSP) headers
3. Input validation and output encoding
4. HTTPOnly cookie flags
5. Regular security audits"""
        
        elif "csrf" in message_lower or "cross-site request" in message_lower:
            return """Cross-Site Request Forgery (CSRF) tricks users into performing unwanted actions. It occurs when:
1. User logs into legitimate site
2. User visits malicious site without logging out
3. Malicious site makes requests as the authenticated user

Protection:
1. CSRF tokens (unique per session)
2. SameSite cookie attributes
3. Referer/Origin header validation
4. Re-authentication for sensitive actions
5. Clear logout mechanisms"""
        
        elif "authentication" in message_lower or "login" in message_lower:
            return """Strong Authentication Best Practices:
1. Use bcrypt/scrypt/Argon2 for password hashing
2. Enforce strong password requirements
3. Implement MFA (multi-factor authentication)
4. Secure session management
5. Rate limiting on login attempts
6. Account lockout mechanisms
7. Secure password reset flows
8. Never store plaintext passwords"""
        
        else:
            return """As a cybersecurity expert, I can help with topics like:
- SQL Injection prevention
- XSS (Cross-Site Scripting) mitigation
- CSRF (Cross-Site Request Forgery) protection
- Authentication and authorization
- Security best practices
- Vulnerability assessment
- Secure coding principles

Ask me about any of these topics or describe your security concern."""
    
    def clear_history(self, user_id: str = "default"):
        """Clear conversation history for user"""
        if user_id in self.conversations:
            self.conversations[user_id].clear()
    
    def get_summary(self, user_id: str = "default") -> dict:
        """Get chatbot status and conversation summary"""
        return {
            "available": self.is_available(),
            "model": self.model,
            "conversation_count": len(self.conversations[user_id]),
            "max_context": self.max_context_messages
        }


# Global instance
_chatbot_instance = None

def get_chatbot() -> CybersecurityChatbot:
    """Get or create chatbot instance"""
    global _chatbot_instance
    if _chatbot_instance is None:
        _chatbot_instance = CybersecurityChatbot()
    return _chatbot_instance
