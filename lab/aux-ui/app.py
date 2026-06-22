from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/health')
def health():
    return 'OK', 200

@app.route('/dom-xss')
def dom_xss():
    """Vulnerable endpoint with reflected DOM XSS"""
    user_input = request.args.get('name', '')
    html = f"""
    <html>
    <body>
    <h1>DOM XSS Vulnerable Page</h1>
    <p>Hello: <span id="output"></span></p>
    <script>
    document.getElementById('output').innerHTML = '{user_input}';
    </script>
    </body>
    </html>
    """
    return html

@app.route('/stored-xss', methods=['GET', 'POST'])
def stored_xss():
    """Simulates stored XSS vulnerability"""
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        # Simulate storing to DB without sanitization
        html = f"""
        <html>
        <body>
        <h1>Comments</h1>
        <div class="comment">{comment}</div>
        <form method="post">
        <textarea name="comment" placeholder="Add comment"></textarea>
        <button type="submit">Post</button>
        </form>
        </body>
        </html>
        """
        return html
    return '''
    <html>
    <body>
    <h1>Stored XSS Test</h1>
    <form method="post">
    <textarea name="comment" placeholder="Add comment"></textarea>
    <button type="submit">Post</button>
    </form>
    </body>
    </html>
    '''

@app.route('/ssti')
def ssti():
    """Server-Side Template Injection vulnerability"""
    template = request.args.get('template', 'Hello World')
    try:
        return render_template_string(template)
    except:
        return 'Template Error', 500

@app.route('/xxe', methods=['POST'])
def xxe():
    """XML External Entity injection vulnerability"""
    try:
        import xml.etree.ElementTree as ET
        xml_data = request.data
        root = ET.fromstring(xml_data)
        return f'Parsed: {ET.tostring(root).decode()}', 200
    except Exception as e:
        return f'Error: {str(e)}', 400

@app.route('/xxe-form')
def xxe_form():
    """XXE test form"""
    return '''
    <html>
    <body>
    <h1>XXE Test</h1>
    <form method="post" action="/xxe">
    <textarea name="xml" placeholder="Enter XML"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root></textarea>
    <button type="submit">Parse XML</button>
    </form>
    </body>
    </html>
    '''

@app.route('/ldap-search')
def ldap_search():
    """LDAP Injection vulnerability (simulated)"""
    search_term = request.args.get('search', '')
    # Vulnerable: directly concatenating user input into LDAP filter
    ldap_filter = f"(uid={search_term})"
    return f'LDAP Filter: {ldap_filter}', 200

@app.route('/http-smuggling')
def http_smuggling():
    """HTTP Request Smuggling endpoint"""
    return '''
    <html>
    <body>
    <h1>HTTP Smuggling Test</h1>
    <p>This endpoint accepts chunked transfer encoding for smuggling detection</p>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
