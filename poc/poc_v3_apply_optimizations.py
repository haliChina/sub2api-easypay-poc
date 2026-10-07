#!/usr/bin/env python3
"""Apply surgical fixes to sub2api_easypay_poc_v2.py. Aborts if a pattern is
missing or already patched, so a silent no-op is impossible."""
import sys

P = "/var/minis/shared/sub2api-7881/sub2api_easypay_poc_v2.py"
s = open(P, encoding="utf-8").read()
applied, aborted = [], []


def sub(old, new, label, count=1):
    global s
    if new in s and old not in s:
        applied.append(label + " (已应用)")
        return
    n = s.count(old)
    if n != count:
        aborted.append(f"{label}: 期望 {count} 处, 实际 {n} 处")
        return
    s = s.replace(old, new, count)
    applied.append(label)


HELPER = '''
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

'''
sub("class ApiError(Exception):",
    HELPER + "\nclass ApiError(Exception):", "注入 Go 语义解析辅助函数")
sub("pairs = urllib.parse.parse_qsl(split.query, keep_blank_values=True)",
    "pairs = parse_qsl_go(split.query)", "FIX1 build_forged_callback 用 Go 语义解析")
sub('q = dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True))',
    'q = dict(parse_qsl_go(p.query))', "FIX1 emulator 规范化用 Go 语义解析")
sub("pairs = urllib.parse.parse_qsl(raw_body, keep_blank_values=True)",
    "pairs = parse_qsl_go(raw_body)", "FIX1 emulator 验签用 Go 语义解析")

sub("""    params, sign, sign_type = {}, None, "MD5"
    for k, v in pairs:
        if k == "sign":
            sign = v
        elif k == "sign_type":
            sign_type = v or "MD5"
        else:
            params[k] = v""",
    """    # Go 的 values.Get(k) 取第一个; 逐条覆盖会取最后一个, 参数重复时会对不上
    params = {}
    sign = values_get(pairs, "sign")
    sign_type = values_get(pairs, "sign_type") or "MD5"
    for k, v in pairs:
        if k in ("sign", "sign_type"):
            continue
        if k not in params:
            params[k] = v""",
    "FIX2 build_forged_callback 重复参数取第一个")

sub("""            params = {}
            for k, v in pairs:
                params[k] = v  # values.Get(k) 取第一个""",
    """            params = {}
            for k, v in pairs:
                if k not in params:      # Go 的 values.Get(k) 取第一个
                    params[k] = v""",
    "FIX2 emulator 验签重复参数取第一个")

sub("""    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body""",
    """    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        _raise_if_gateway(e.code, body)
        return e.code, dict(e.headers or {}), body""",
    "FIX3 5xx 网关响应转成可操作错误")

sub("class Sub2ApiClient:",
    '''GATEWAY_HINTS = {
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


class Sub2ApiClient:''',
    "FIX3 注入网关层诊断")

sub("""    if isinstance(data, dict) and data.get("requires_2fa"):
        raise ApiError("该账户启用了 2FA, 请换用未开启 2FA 的测试账户。")""",
    """    if isinstance(data, dict) and data.get("requires_2fa"):
        temp = data.get("temp_token") or ""
        masked = data.get("user_email_masked") or email
        ui.warn(f"该账户启用了两步验证 ({masked})")
        code = (args.totp or ui.ask("请输入 6 位验证码", default="")).strip()
        if not re.fullmatch(r"\\d{6}", code):
            raise ApiError("2FA 验证码格式不对（应为 6 位数字）。")
        data = client.login_2fa(temp, code)
        ui.ok("两步验证通过")""",
    "FIX4 支持 2FA 登录而不是直接放弃")

sub("""    def login(self, email, password):""",
    """    def login_2fa(self, temp_token, totp_code):
        return self._call("POST", "/api/v1/auth/login/2fa", auth=False,
                          json_body={"temp_token": temp_token, "totp_code": totp_code})

    def login(self, email, password):""",
    "FIX4 新增 login_2fa 方法")

sub('''                raise ApiError("目标启用了人机验证(turnstile/captcha), 自动注册不可行。"
                               "请手工注册后用 --email/--password 登录模式。") from e''',
    '''                raise ApiError(
                    "目标启用了人机验证(turnstile/captcha)。本工具不会去绕过它；"
                    "请手工登录后改用浏览器 Cookie。", reason="captcha") from e''',
    "FIX5 captcha 提示更明确")

open(P, "w", encoding="utf-8").write(s)

print("已应用：")
for a in applied:
    print("  +", a)
if aborted:
    print("\n未应用（模式没匹配上，已中止）：")
    for a in aborted:
        print("  !", a)
    sys.exit(1)
print("\n写回成功")