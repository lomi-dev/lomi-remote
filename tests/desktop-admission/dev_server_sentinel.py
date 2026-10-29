"""Owned hostile-origin sentinel. Aggregate request counts only; no request logs."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
count = 0


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<!doctype html><title>Unapproved development frontend</title>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Server(HTTPServer):
    def get_request(self):
        stream, address = super().get_request()
        global count
        count += 1
        temporary = root / "dev-server-requests.tmp"
        temporary.write_text(json.dumps(count))
        temporary.replace(root / "dev-server-requests.json")
        stream.settimeout(.5)
        return stream, address


with Server(("127.0.0.1", 1420), Handler) as server:
    (root / "dev-server-requests.json").write_text("0")
    (root / "dev-server-ready").write_text("ready")
    server.serve_forever(poll_interval=.05)
