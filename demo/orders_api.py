# SPDX-FileCopyrightText: 2026 Gal Diskin
# SPDX-License-Identifier: MIT
"""Fake Acme Orders API for the demo. Shows which credential each request carries."""

import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

GREEN, RED, YELLOW, BOLD, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
ORDERS = {
    "1042": {"id": 1042, "customer": "J. Rivera", "item": "Noise-cancelling headphones", "total_usd": 249.0,
             "status": "delivered", "delivered_on": "2026-09-19", "refund_window_days": 30, "opened": False},
    "1043": {"id": 1043, "customer": "M. Chen", "item": "Espresso machine", "total_usd": 689.0,
             "status": "delivered", "delivered_on": "2026-07-02", "refund_window_days": 30, "opened": True},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def reply(self, status, payload):
        body = (json.dumps(payload) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        auth = self.headers.get("Authorization", "")
        key = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        stamp = time.strftime("%H:%M:%S")
        if not key:
            print(f"{DIM}[{stamp}]{RESET} {self.command} {self.path}  {RED}no API key -> 401{RESET}", flush=True)
            return self.reply(401, {"error": "missing API key"})
        if key.startswith("openshell:resolve:"):
            print(f"{DIM}[{stamp}]{RESET} {self.command} {self.path}  {YELLOW}placeholder, not a key -> 401{RESET}", flush=True)
            return self.reply(401, {"error": "invalid API key"})
        print(f"{DIM}[{stamp}]{RESET} {self.command} {self.path}  key={BOLD}{key}{RESET}  {GREEN}authorized{RESET}", flush=True)
        order_id = self.path.rstrip("/").rsplit("/", 1)[-1]
        if self.path.startswith("/v1/orders/") and order_id in ORDERS:
            return self.reply(200, ORDERS[order_id])
        return self.reply(404, {"error": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
    print(f"{BOLD}Acme Orders API{RESET} on 127.0.0.1:{port}, waiting for the refund agent...", flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
