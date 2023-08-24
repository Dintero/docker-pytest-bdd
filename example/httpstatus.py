from http.server import HTTPServer, BaseHTTPRequestHandler

class HttpStatus(BaseHTTPRequestHandler):
    def handle_response(self):
        self.send_response(int(self.path.split("/")[1]))
        self.end_headers()

    def do_GET(self):
        self.handle_response()

    def do_POST(self):
        self.handle_response()

if __name__ == "__main__":
    addr = "0.0.0.0"
    port = 80
    server_address = (addr, port)
    httpd = HTTPServer(server_address, HttpStatus)
    print(f"Starting httpd server on {addr}:{port}")
    httpd.serve_forever()
