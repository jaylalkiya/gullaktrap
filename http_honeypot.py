"""
HTTP Honeypot Module for Freak-Pot
Simulates a vulnerable web server to capture HTTP-based attacks
Enhanced with custom HTML file support and configurable banners
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from netutil import apply_bind_policy, ensure_free
from threading import Thread
import os

class HTTPHoneypotHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, log_callback=None, html_content=None, server_banner=None, **kwargs):
        self.log_callback = log_callback
        self.html_content = html_content
        self.server_banner = server_banner or "Apache/2.4.41 (Ubuntu)"
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to prevent default logging"""
        pass
    
    def log_attack(self, attack_type, details):
        """Log attack attempts"""
        if self.log_callback:
            self.log_callback('http', attack_type, details)
    
    def do_GET(self):
        """Handle GET requests"""
        client_ip = self.client_address[0]
        path = self.path
        headers = dict(self.headers)
        
        # Log the request
        self.log_attack('GET Request', f"From {client_ip} - Path: {path}")
        
        # Check for common attack patterns
        attack_patterns = [
            ('SQL Injection', ['union', 'select', 'drop', 'insert', '1=1', "' or '", 'concat', 'exec', '--']),
            ('XSS Attempt', ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'onclick=']),
            ('Path Traversal', ['../', '..\\', '/etc/passwd', '/windows/', 'c:\\', 'boot.ini']),
            ('Command Injection', ['|', ';', '&&', '||', '`', '$(', 'wget', 'curl']),
            ('File Inclusion', ['php://input', 'file://', 'data://', 'expect://']),
        ]
        
        for attack_name, patterns in attack_patterns:
            if any(pattern in path.lower() for pattern in patterns):
                self.log_attack(attack_name, f"Detected in {path} from {client_ip}")
        
        # Check User-Agent for scanning tools
        user_agent = headers.get('User-Agent', '').lower()
        scanning_tools = {
            'nikto': 'Nikto Scanner',
            'nmap': 'Nmap NSE',
            'sqlmap': 'SQLMap',
            'burp': 'Burp Suite',
            'metasploit': 'Metasploit',
            'acunetix': 'Acunetix',
            'nessus': 'Nessus',
            'qualys': 'Qualys',
            'openvas': 'OpenVAS'
        }
        
        for tool, name in scanning_tools.items():
            if tool in user_agent:
                self.log_attack('Scanner Detected', f"{name} from {client_ip}")
        
        # Send response with custom HTML
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', self.server_banner)
        self.send_header('X-Powered-By', 'PHP/7.4.3')
        self.end_headers()
        
        # Use custom HTML if provided, otherwise default
        html = self.html_content if self.html_content else self._default_html()
        self.wfile.write(html.encode())
    
    def do_POST(self):
        """Handle POST requests"""
        client_ip = self.client_address[0]
        path = self.path
        
        # Read POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        # Log the POST request with data
        self.log_attack('POST Request', f"From {client_ip} - Path: {path} - Data: {post_data[:200]}")
        
        # Check for credential theft attempts
        if 'username' in post_data.lower() or 'password' in post_data.lower() or 'user' in post_data.lower():
            self.log_attack('Credential Theft', f"Login attempt from {client_ip}: {post_data}")
        
        # Check for file upload attempts
        if 'filename' in post_data.lower() or 'content-disposition' in str(self.headers).lower():
            self.log_attack('File Upload Attempt', f"From {client_ip}")
        
        # Send fake error response
        self.send_response(401)
        self.send_header('Content-type', 'text/html')
        self.send_header('Server', self.server_banner)
        self.end_headers()
        
        html = "<html><body><h1>Authentication Failed</h1><p>Invalid credentials</p></body></html>"
        self.wfile.write(html.encode())
    
    def do_PUT(self):
        """Handle PUT requests (file upload attempts)"""
        client_ip = self.client_address[0]
        self.log_attack('PUT Request', f"File upload attempt from {client_ip} - Path: {self.path}")
        self.send_error(405, "Method Not Allowed")
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        client_ip = self.client_address[0]
        self.log_attack('DELETE Request', f"Delete attempt from {client_ip} - Path: {self.path}")
        self.send_error(405, "Method Not Allowed")
    
    def _default_html(self):
        """Default HTML if no custom file provided"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Login</title>
            <style>
                body { font-family: Arial; background: #f0f0f0; padding: 50px; }
                .login-box { background: white; padding: 30px; border-radius: 5px; max-width: 400px; margin: auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; }
                input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
                button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; width: 100%; }
                button:hover { background: #0056b3; }
                .info { color: #666; font-size: 12px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h1>🔐 Admin Panel</h1>
                <form action="/login" method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <div class="info">
                    <p><strong>Server Info:</strong></p>
                    <p>OS: Ubuntu 20.04 LTS</p>
                    <p>Web Server: Apache/2.4.41</p>
                    <p>Database: MySQL 8.0.23</p>
                    <p>PHP Version: 7.4.3</p>
                </div>
            </div>
        </body>
        </html>
        """


class _ExclusiveHTTPServer(HTTPServer):
    """HTTPServer that refuses to share a port with another listener.

    The stock class sets allow_reuse_address = 1, which on Windows means a
    busy port binds anyway and the sensor goes deaf. Binding policy is
    delegated to netutil so all three sensors behave identically.
    """
    allow_reuse_address = False

    def server_bind(self):
        apply_bind_policy(self.socket)
        HTTPServer.server_bind(self)


class HTTPHoneypot:
    # Vulnerable banner suggestions
    BANNER_SUGGESTIONS = [
        "Apache/2.4.41 (Ubuntu)",
        "Apache/2.2.15 (CentOS)",  # Old version
        "Microsoft-IIS/7.5",  # Windows Server 2008 R2
        "Microsoft-IIS/6.0",  # Very old, vulnerable
        "nginx/1.10.3",  # Older version
        "Apache/2.0.52 (Red Hat)",  # Very old
        "Microsoft-IIS/5.0",  # Windows 2000 - ancient
        "lighttpd/1.4.28",  # Old version
        "Apache/2.4.7 (Ubuntu)",  # Known vulnerabilities
        "nginx/1.4.0 (Ubuntu)",  # Older with known issues
        "Apache-Coyote/1.1",  # Tomcat default
        "WebSphere Application Server/7.0",  # Dated
    ]
    
    def __init__(self, port=8080, log_callback=None, html_file=None, server_banner=None):
        self.port = port
        self.log_callback = log_callback
        self.html_file = html_file
        self.server_banner = server_banner or self.BANNER_SUGGESTIONS[0]
        self.html_content = self._load_html_file()
        self.server = None
        self.thread = None
        self.running = False
    
    def _load_html_file(self):
        """Load HTML content from file if specified"""
        if self.html_file and os.path.exists(self.html_file):
            try:
                with open(self.html_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if self.log_callback:
                        self.log_callback('http', 'HTML Loaded', f"Custom HTML loaded from {self.html_file}")
                    return content
            except Exception as e:
                if self.log_callback:
                    self.log_callback('http', 'HTML Load Error', f"Failed to load {self.html_file}: {str(e)}")
                return None
        return None
    
    def handler_factory(self, *args, **kwargs):
        """Factory to pass configuration to handler"""
        return HTTPHoneypotHandler(
            *args, 
            log_callback=self.log_callback,
            html_content=self.html_content,
            server_banner=self.server_banner,
            **kwargs
        )
    
    def start(self):
        """Start the HTTP honeypot server"""
        try:
            ensure_free(self.port, 'http')
            self.server = _ExclusiveHTTPServer(('0.0.0.0', self.port),
                                              self.handler_factory)
            self.thread = Thread(target=self._run_server)
            self.thread.daemon = True
            self.running = True
            self.thread.start()
            
            if self.log_callback:
                banner_info = f"Banner: {self.server_banner}"
                html_info = f"HTML: {'Custom file' if self.html_content else 'Default'}"
                self.log_callback('http', 'Server Started', f"HTTP Honeypot on port {self.port} | {banner_info} | {html_info}")
        except Exception as e:
            if self.log_callback:
                self.log_callback('http', 'Error', f"Failed to start: {str(e)}")
            raise
    
    def _run_server(self):
        """Run the server in a thread"""
        try:
            self.server.serve_forever()
        except Exception as e:
            if self.log_callback:
                self.log_callback('http', 'Error', str(e))
    
    def stop(self):
        """Stop the HTTP honeypot server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()   # release the port for a restart
            self.running = False
            if self.log_callback:
                self.log_callback('http', 'Server Stopped', f"HTTP Honeypot on port {self.port} stopped")


if __name__ == '__main__':
    # Test the honeypot
    def test_log(protocol, event_type, details):
        print(f"[{protocol}] {event_type}: {details}")
    
    # Test with custom banner
    honeypot = HTTPHoneypot(
        port=8080, 
        log_callback=test_log,
        server_banner="Apache/2.2.15 (CentOS)"  # Old vulnerable version
    )
    honeypot.start()
    
    print("HTTP Honeypot running on port 8080")
    print(f"Server Banner: {honeypot.server_banner}")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        honeypot.stop()
        print("\nStopped")