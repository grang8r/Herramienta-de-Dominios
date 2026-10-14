from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from urllib.parse import urlsplit
import json
import os

HOST = os.environ.get("UA_HOST", "0.0.0.0")
PORT = int(os.environ.get("UA_PORT", "8080"))
LOG_FILE = os.environ.get("UA_LOG_FILE", "data/user_agents.jsonl")
os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)

class UAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": self.client_address[0],
            "method": self.command,
            "path": urlsplit(self.path).path,
            "user_agent": self.headers.get("User-Agent", "(no enviado)")
        }
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(json.dumps(event, ensure_ascii=False), flush=True)
        body = b"Peticion recibida correctamente.\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    print(f"Servidor UA escuchando en {HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), UAHandler).serve_forever()
