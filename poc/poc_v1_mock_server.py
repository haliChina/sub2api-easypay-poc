"""Mock sub2api for testing the PoC script's auth/error handling."""
import json, sys, hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qsl, urlencode

PKEY, HOST = "REAL_MERCHANT_KEY", "site.example.com"
SCENARIO = sys.argv[2] if len(sys.argv) > 2 else "ok"


def sign(params):
    d = {k: v for k, v in params.items() if k not in ("sign", "sign_type") and v != ""}
    return hashlib.md5(("&".join(f"{k}={d[k]}" for k in sorted(d)) + PKEY).encode()).hexdigest()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if "/payment/webhook/easypay" in self.path:
            return self._send(200, {"code": 0, "message": "success"})
        return self._send(404, {"code": 404, "message": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        p = urlparse(self.path).path

        if p.endswith("/auth/login"):
            if SCENARIO == "captcha":
                return self._send(400, {"code": 400, "message": "captcha verification failed",
                                        "reason": "TURNSTILE_FAILED"})
            if SCENARIO == "ratelimit":
                return self._send(429, {"code": 429, "message": "too many requests"})
            if SCENARIO == "server":
                return self._send(500, {"code": 500, "message": "internal error"})
            if body.get("password") != "correct-horse":
                return self._send(401, {"code": 401, "message": "invalid email or password",
                                        "reason": "INVALID_CREDENTIALS"})
            if SCENARIO == "2fa":
                return self._send(200, {"code": 0, "data": {"requires_2fa": True,
                                    "temp_token": "TMP123",
                                    "user_email_masked": "a***@example.com"}})
            return self._send(200, {"code": 0, "data": {
                "access_token": "JWT.OK", "token_type": "Bearer",
                "user": {"email": body.get("email")}}})

        if p.endswith("/auth/login/2fa"):
            if body.get("totp_code") == "123456":
                return self._send(200, {"code": 0, "data": {"access_token": "JWT.2FA"}})
            return self._send(401, {"code": 401, "message": "invalid totp code"})

        if p.endswith("/payment/orders"):
            if self.headers.get("Authorization") not in ("Bearer JWT.OK", "Bearer JWT.2FA"):
                return self._send(401, {"code": 401, "message": "unauthorized"})
            u = urlparse(body.get("return_url", ""))
            q = dict(parse_qsl(u.query, keep_blank_values=True))
            if SCENARIO == "patched":       # simulate a fixed deployment
                q = {}
            q["order_id"] = "99"
            q["out_trade_no"] = "OT123"
            q["status"] = "success"
            ret = u._replace(query=urlencode(sorted(q.items()))).geturl()
            params = {"pid": "1000", "type": "alipay", "out_trade_no": "OT123",
                      "notify_url": "https://" + HOST + "/api/v1/payment/webhook/easypay",
                      "return_url": ret, "name": "balance recharge", "money": "650.00"}
            params["sign"] = sign(params)
            return self._send(200, {"code": 0, "data": {
                "order_id": 99, "out_trade_no": "OT123",
                "pay_url": "https://pay.example.com/submit.php?" + urlencode(params) + "&sign_type=MD5"}})

        if p.endswith("/orders/verify"):
            return self._send(200, {"code": 0, "data": {"status": "paid", "balance": 999.99}})

        return self._send(404, {"code": 404, "message": "not found"})


HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()