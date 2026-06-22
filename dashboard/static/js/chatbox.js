/**
 * AI Security Chatbox Frontend
 * Handles UI interactions and API communication
 */

class SecurityChatbot {
    constructor() {
        console.log('SecurityChatbot initializing...');
        
        // Check if required elements exist
        const requiredElements = [
            'chat-messages', 'chat-input', 'chat-send-btn', 'chat-loading',
            'chat-status', 'chat-clear-btn', 'chat-info-btn', 'chat-toggle-btn',
            'chat-sidebar', 'chat-launcher'
        ];
        
        const missingElements = requiredElements.filter(id => !document.getElementById(id));
        if (missingElements.length > 0) {
            console.error('Missing elements:', missingElements);
            return;
        }
        
        this.messagesContainer = document.getElementById('chat-messages');
        this.inputField = document.getElementById('chat-input');
        this.sendBtn = document.getElementById('chat-send-btn');
        this.loadingDiv = document.getElementById('chat-loading');
        this.statusDiv = document.getElementById('chat-status');
        this.clearBtn = document.getElementById('chat-clear-btn');
        this.infoBtn = document.getElementById('chat-info-btn');
        this.toggleBtn = document.getElementById('chat-toggle-btn');
        this.sidebar = document.getElementById('chat-sidebar');
        this.launcher = document.getElementById('chat-launcher');
        this.promptChips = document.querySelectorAll('.chat-chip');
        this.dragState = {
            active: false,
            moved: false,
            startX: 0,
            startY: 0,
            startLeft: 0,
            startTop: 0,
            pointerId: null
        };
        
        this.messageHistory = [];
        this.isLoading = false;
        this.rateLimitRemaining = 10;
        
        this.initEventListeners();
        this.loadChatHistory();
        console.log('SecurityChatbot initialized successfully');
    }
    
    initEventListeners() {
        this.sendBtn.addEventListener('click', () => this.sendMessage());
        this.inputField.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });
        this.clearBtn.addEventListener('click', () => this.clearChat());
        this.infoBtn.addEventListener('click', () => this.showInfo());
        this.toggleBtn.addEventListener('click', () => this.toggleSidebar());
        this.launcher.addEventListener('click', (e) => {
            if (this.dragState.moved) {
                e.preventDefault();
                this.dragState.moved = false;
                return;
            }
            this.openSidebar();
        });
        this.launcher.addEventListener('pointerdown', (e) => this.startLauncherDrag(e));
        window.addEventListener('pointermove', (e) => this.handleLauncherDrag(e));
        window.addEventListener('pointerup', (e) => this.endLauncherDrag(e));
        this.promptChips.forEach((chip) => {
            chip.addEventListener('click', () => {
                this.inputField.value = chip.dataset.prompt || '';
                this.inputField.focus();
                this.autoResizeInput();
            });
        });
    }
    
    async sendMessage() {
        const message = this.inputField.value.trim();
        
        if (!message) {
            this.setStatus('Please enter a message', 'error');
            return;
        }
        
        if (this.isLoading) {
            this.setStatus('Waiting for previous response...', 'error');
            return;
        }
        
        // Check rate limit
        if (this.rateLimitRemaining <= 0) {
            this.setStatus('Rate limit exceeded. Please wait a moment.', 'error');
            return;
        }
        
        // Add user message to UI
        this.addMessageToUI('user', message);
        this.inputField.value = '';
        this.inputField.style.height = 'auto';
        
        this.isLoading = true;
        this.sendBtn.disabled = true;
        this.showLoading(true);
        this.setStatus('Analyzing your question...');
        
        try {
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
            
            // Check if user is asking about tasks
            const taskKeywords = ['task', 'scan', 'running', 'status', 'progress', 'findings', 'vulnerab'];
            const isTaskQuery = taskKeywords.some(keyword => message.toLowerCase().includes(keyword));
            
            // Fetch task information if relevant
            let taskContext = null;
            if (isTaskQuery) {
                try {
                    const tasksResponse = await fetch('/api/tasks?limit=10', {
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrfToken
                        }
                    });
                    if (tasksResponse.ok) {
                        taskContext = await tasksResponse.json();
                    }
                } catch (e) {
                    console.warn('Could not fetch task context:', e);
                }
            }
            
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    message: message,
                    include_context: true,
                    task_context: taskContext
                })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.error) {
                this.addMessageToUI('assistant', `❌ Error: ${data.error}`);
                this.setStatus(`Error: ${data.error}`, 'error');
            } else {
                this.addMessageToUI('assistant', data.response);
                this.setStatus('Ready to help!', 'success');
                this.rateLimitRemaining = data.rate_limit_remaining || 10;
                
                // Handle scan intent if present (DISABLED - scan feature removed)
                // if (data.scan_intent && data.scan_intent.has_urls) {
                //     await this.handleScanIntent(data.scan_intent, message, csrfToken);
                // }
            }
            
            this.messageHistory.push({ role: 'user', content: message });
            this.messageHistory.push({ role: 'assistant', content: data.response });
            this.saveChatHistory();
            
        } catch (error) {
            console.error('Chat error:', error);
            this.addMessageToUI('assistant', `❌ Communication error: ${error.message}\n\nPlease check the console for details.`);
            this.setStatus(`Error: ${error.message}`, 'error');
        } finally {
            this.isLoading = false;
            this.sendBtn.disabled = false;
            this.showLoading(false);
        }
    }
    
    async handleScanIntent(scanIntent, message, csrfToken) {
        // Handle scan or schedule requests from user
        if (!scanIntent.urls || scanIntent.urls.length === 0) {
            return;
        }
        
        const firstUrl = scanIntent.urls[0];
        
        // Check if user wants to schedule
        if (scanIntent.schedule) {
            // Suggest scheduling
            const cronOptions = ['0 * * * * (every hour)', '0 0 * * * (daily)', '0 0 * * 0 (weekly)'];
            this.addMessageToUI('system', 
                `📅 Would you like me to schedule a scan of ${firstUrl}?\n\n` +
                `Suggested schedules:\n` +
                cronOptions.map(c => `• ${c}`).join('\n')
            );
            return;
        }
        
        // If user explicitly asked to scan
        if (scanIntent.scan) {
            try {
                this.setStatus('Starting scan...');
                const scanResponse = await fetch('/api/scan-now', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrfToken
                    },
                    body: JSON.stringify({ url: firstUrl })
                });
                
                const scanData = await scanResponse.json();
                
                if (scanResponse.ok) {
                    this.addMessageToUI('system', 
                        `✅ ${scanData.message}\n\n` +
                        `🔍 Scan ID: ${scanData.scan_id}\n` +
                        `📍 Target: ${scanData.url}\n\n` +
                        `You can check progress on the dashboard or ask me for updates!`
                    );
                    this.setStatus('Scan started!', 'success');
                } else {
                    this.addMessageToUI('assistant', 
                        `⚠️ Failed to start scan: ${scanData.message || scanData.error}`
                    );
                    this.setStatus(`Scan error: ${scanData.error}`, 'error');
                }
            } catch (error) {
                console.error('Scan error:', error);
                this.addMessageToUI('assistant', 
                    `❌ Failed to start scan: ${error.message}`
                );
            }
        }
    }
    
    addMessageToUI(role, content) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${role}`;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        
        // Convert markdown-like formatting to HTML
        let htmlContent = this.escapeHtml(content);
        htmlContent = htmlContent
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/__(.*?)__/g, '<strong>$1</strong>')
            .replace(/\n/g, '<br>');

        contentDiv.innerHTML = htmlContent;

        const metaDiv = document.createElement('div');
        metaDiv.className = 'message-meta';
        metaDiv.textContent = `${role === 'user' ? 'You' : role === 'assistant' ? 'AI' : 'System'} • ${this.getTimestamp()}`;

        if (role !== 'system') {
            const avatarDiv = document.createElement('div');
            avatarDiv.className = 'message-avatar';
            avatarDiv.textContent = role === 'user' ? 'You' : 'AI';
            messageDiv.appendChild(avatarDiv);
        }

        contentDiv.appendChild(metaDiv);
        messageDiv.appendChild(contentDiv);
        this.messagesContainer.appendChild(messageDiv);
        
        // Auto scroll to bottom
        this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
    }
    
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }
    
    showLoading(show) {
        this.loadingDiv.style.display = show ? 'flex' : 'none';
    }
    
    setStatus(message, type = 'info') {
        this.statusDiv.textContent = message;
        this.statusDiv.className = 'chat-status' + (type ? ` ${type}` : '');
        
        // Auto clear status after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                this.statusDiv.textContent = '';
            }, 5000);
        }
    }
    
    clearChat() {
        if (confirm('Clear all chat history? This cannot be undone.')) {
            // Get CSRF token from meta tag
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
            
            // Clear locally
            this.messagesContainer.innerHTML = `
                <div class="chat-message system">
                    <div class="message-avatar">AI</div>
                    <div class="message-content">
                        <strong>Chat cleared!</strong> [CLEARED]
                        <p>Start a new conversation with your AI security advisor.</p>
                        <div class="message-meta">System • ${this.getTimestamp()}</div>
                    </div>
                </div>
            `;
            this.messageHistory = [];
            this.saveChatHistory();
            this.setStatus('Chat history cleared', 'success');
            
            // Clear on server
            fetch('/api/chat/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                }
            }).catch(err => console.error('Error clearing server history:', err));
        }
    }
    
    showInfo() {
        const info = `
            <strong>Platform Assistant Info</strong>
            <p>Helps users navigate the system, summarize data, generate reports, and perform authorized actions.</p>
            <p><strong>Capabilities:</strong></p>
            <ul>
                <li>System navigation guidance</li>
                <li>Data summaries and report drafts</li>
                <li>Authorized workflow actions</li>
                <li>Context-aware answers from available data</li>
            </ul>
            <p>Access is limited to what the user is permitted to see or change.</p>
        `;
        alert(info);
    }
    
    toggleSidebar() {
        if (this.sidebar.classList.contains('is-open')) {
            this.closeSidebar();
        } else {
            this.openSidebar();
        }
    }

    openSidebar() {
        this.sidebar.classList.add('is-open');
        this.launcher.classList.add('is-open');
        this.inputField.focus();
    }

    closeSidebar() {
        this.sidebar.classList.remove('is-open');
        this.launcher.classList.remove('is-open');
    }

    startLauncherDrag(e) {
        if (e.button !== 0) {
            return;
        }

        const rect = this.launcher.getBoundingClientRect();
        this.dragState.active = true;
        this.dragState.moved = false;
        this.dragState.startX = e.clientX;
        this.dragState.startY = e.clientY;
        this.dragState.startLeft = rect.left;
        this.dragState.startTop = rect.top;
        this.dragState.pointerId = e.pointerId;

        this.launcher.classList.add('is-dragging');
        this.launcher.setPointerCapture(e.pointerId);
    }

    handleLauncherDrag(e) {
        if (!this.dragState.active || this.dragState.pointerId !== e.pointerId) {
            return;
        }

        const dx = e.clientX - this.dragState.startX;
        const dy = e.clientY - this.dragState.startY;

        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
            this.dragState.moved = true;
        }

        if (!this.dragState.moved) {
            return;
        }

        const nextLeft = this.clamp(
            this.dragState.startLeft + dx,
            8,
            window.innerWidth - this.launcher.offsetWidth - 8
        );
        const nextTop = this.clamp(
            this.dragState.startTop + dy,
            8,
            window.innerHeight - this.launcher.offsetHeight - 8
        );

        this.launcher.style.left = nextLeft + 'px';
        this.launcher.style.top = nextTop + 'px';
        this.launcher.style.right = 'auto';
        this.launcher.style.bottom = 'auto';
    }

    endLauncherDrag(e) {
        if (!this.dragState.active || this.dragState.pointerId !== e.pointerId) {
            return;
        }

        this.dragState.active = false;
        this.launcher.classList.remove('is-dragging');

        if (this.launcher.hasPointerCapture(e.pointerId)) {
            this.launcher.releasePointerCapture(e.pointerId);
        }

        if (this.dragState.moved) {
            this.saveLauncherPosition();
            e.preventDefault();
        }
    }

    clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    saveLauncherPosition() {
        try {
            const rect = this.launcher.getBoundingClientRect();
            localStorage.setItem('chatLauncherPosition', JSON.stringify({
                left: rect.left,
                top: rect.top
            }));
        } catch (e) {
            console.warn('Could not save launcher position:', e);
        }
    }

    loadLauncherPosition() {
        try {
            const saved = localStorage.getItem('chatLauncherPosition');
            if (!saved) {
                return;
            }

            const position = JSON.parse(saved);
            if (typeof position.left !== 'number' || typeof position.top !== 'number') {
                return;
            }

            this.launcher.style.left = position.left + 'px';
            this.launcher.style.top = position.top + 'px';
            this.launcher.style.right = 'auto';
            this.launcher.style.bottom = 'auto';
        } catch (e) {
            console.warn('Could not load launcher position:', e);
        }
    }
    
    saveChatHistory() {
        try {
            localStorage.setItem('chatHistory', JSON.stringify(this.messageHistory));
        } catch (e) {
            console.warn('Could not save chat history:', e);
        }
    }
    
    loadChatHistory() {
        try {
            const saved = localStorage.getItem('chatHistory');
            if (saved) {
                this.messageHistory = JSON.parse(saved);
                // Load messages into UI (limit to last 10)
                const recentMessages = this.messageHistory.slice(-10);
                this.messagesContainer.innerHTML = '';
                recentMessages.forEach(msg => {
                    this.addMessageToUI(msg.role, msg.content);
                });
            }
        } catch (e) {
            console.warn('Could not load chat history:', e);
        }
    }
    
    // Auto-resize textarea
    autoResizeTextarea() {
        this.inputField.addEventListener('input', (e) => {
            this.autoResizeInput(e.target);
        });
    }

    autoResizeInput(target = this.inputField) {
        target.style.height = 'auto';
        target.style.height = Math.min(target.scrollHeight, 120) + 'px';
    }

    getTimestamp() {
        const now = new Date();
        return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOMContentLoaded fired');
    try {
        const chatbot = new SecurityChatbot();
        if (chatbot.launcher) {
            chatbot.autoResizeTextarea();
            chatbot.loadLauncherPosition();
            chatbot.closeSidebar();
            console.log('Chatbot setup complete');
        } else {
            console.error('Chatbot launcher not found');
        }
    } catch (error) {
        console.error('Error initializing chatbot:', error);
    }
    
    // Shake animation on error
    window.showChatError = (message) => {
        const sidebar = document.getElementById('chat-sidebar');
        if (sidebar) {
            sidebar.style.animation = 'shake 0.5s';
            setTimeout(() => {
                sidebar.style.animation = '';
            }, 500);
        }
    };
});

// Shake animation keyframes
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-10px); }
        75% { transform: translateX(10px); }
    }
`;
document.head.appendChild(style);
