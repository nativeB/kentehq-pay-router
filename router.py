"""Paystack allows one webhook URL per account. This fans each event out to every app.

Each app verifies Paystack's x-paystack-signature itself (HMAC-SHA512 of the raw body with the
secret key) and ignores references it doesn't own; this service forwards the raw body and
signature unchanged. It also verifies the signature first (PAYSTACK_SECRET_KEY) so forged or junk
requests are dropped here instead of being multiplied across every app. It answers Paystack 200 once every target has
accepted; if any target fails it answers 500 so Paystack retries (apps are idempotent).
"""
import hashlib, hmac, os, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGETS = [t.strip() for t in os.environ.get("TARGETS", "").split(",") if t.strip()]
MAX_BODY = 1_000_000
SECRETS = [k.strip().encode() for k in os.environ.get("PAYSTACK_SECRET_KEY", "").split(",") if k.strip()]
if not SECRETS:
    raise SystemExit("PAYSTACK_SECRET_KEY is required (comma-separate test and live keys)")


def signed(body: bytes, sig: str) -> bool:
    return any(hmac.compare_digest(hmac.new(k, body, hashlib.sha512).hexdigest(), sig) for k in SECRETS)

class Handler(BaseHTTPRequestHandler):
    timeout = 10  # drop slow or idle clients
    server_version = "pay"
    sys_version = ""

    def _reply(self, code, text):
        self.send_response(code); self.send_header("Content-Type", "text/plain"); self.end_headers(); self.wfile.write(text.encode())

    def do_GET(self):
        self._reply(200, "ok") if self.path == "/health" else self._reply(404, "not found")

    def do_POST(self):
        if self.path != "/paystack":
            return self._reply(404, "not found")
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._reply(400, "bad body")
        body = self.rfile.read(n)
        sig = self.headers.get("x-paystack-signature", "")
        if not sig or not signed(body, sig):
            print("rejected unsigned or forged request", flush=True)
            return self._reply(401, "bad signature")
        failed = []
        for url in TARGETS:
            req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "x-paystack-signature": sig})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    if r.status >= 500: failed.append(url)
            except urllib.error.HTTPError as e:
                if e.code >= 500: failed.append(url)  # 4xx = the app rejected/ignored it; don't retry forever
            except Exception:
                failed.append(url)
        print(f"event forwarded to {len(TARGETS)} targets, failed={len(failed)}", flush=True)
        self._reply(500 if failed else 200, "retry" if failed else "ok")

    def log_message(self, *a): pass

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
