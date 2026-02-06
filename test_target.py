"""Simple intentionally vulnerable web app for testing Reaper."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.49")  # Info disclosure
            self.send_header("X-Powered-By", "PHP/7.4.3")  # Info disclosure
            self.end_headers()
            self.wfile.write(b"""<html><head><title>Test App</title></head><body>
            <h1>Test Application</h1>
            <a href="/search?q=test">Search</a>
            <a href="/users?id=1">Users</a>
            <a href="/admin">Admin Panel</a>
            <a href="/api/data">API</a>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Login</button>
            </form>
            <form action="/search" method="GET">
                <input type="text" name="q" />
                <button type="submit">Search</button>
            </form>
            <!-- TODO: remove debug endpoint /debug -->
            </body></html>""")

        elif parsed.path == "/search":
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # XSS vulnerability - reflects input without sanitization
            self.wfile.write(f"<html><body><h1>Search results for: {q}</h1><p>No results found.</p></body></html>".encode())

        elif parsed.path == "/users":
            uid = params.get("id", ["1"])[0]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            # SQL injection simulation - returns error on special chars
            if "'" in uid or '"' in uid or "OR" in uid.upper():
                self.wfile.write(json.dumps({"error": "sqlite3.OperationalError: unrecognized token: " + uid, "query": f"SELECT * FROM users WHERE id = {uid}"}).encode())
            else:
                self.wfile.write(json.dumps({"id": uid, "name": "John Doe", "email": "john@test.com"}).encode())

        elif parsed.path == "/admin":
            self.send_response(200)  # No auth required - broken access control
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Admin Panel</h1><p>Welcome, admin!</p></body></html>")

        elif parsed.path == "/api/data":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")  # CORS misconfiguration
            self.end_headers()
            self.wfile.write(json.dumps({"data": [{"secret_key": "sk-12345"}, {"api_token": "tok_abc"}]}).encode())

        elif parsed.path == "/debug":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Debug Info</h1><pre>DB_PASSWORD=admin123\nSECRET_KEY=supersecret</pre></body></html>")

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        if parsed.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "session=abc123; Path=/")  # Missing Secure, HttpOnly, SameSite
            self.end_headers()
            self.wfile.write(json.dumps({"status": "Login attempted", "body_received": body}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS, TRACE")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(f"TRACE {self.path} HTTP/1.1\r\n".encode())

    def do_PUT(self): self.do_POST()
    def do_DELETE(self): self.do_GET()
    def do_PATCH(self): self.do_POST()

    def log_message(self, format, *args):
        pass  # Suppress request logging

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8888), VulnHandler)
    print("Vulnerable test server running on http://localhost:8888")
    server.serve_forever()
