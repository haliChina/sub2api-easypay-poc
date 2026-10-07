"""
Sub2API fleet scanner — 找出开了易支付 popup 且未打补丁的实例。
两阶段:
  phase1: 存活 + 版本探测 (免鉴权, 快)
  phase2: 注册(tempmail 自动取码) + checkout-info 看有没有 easypay
用法:
  python3 scan_fleet.py phase1 <urls.json> [--limit N]
  python3 scan_fleet.py phase2 <urls.json> [--limit N] [--concurrency 6]
输出 TSV 到 /var/minis/shared/sub2api-7881/scan_report.tsv
"""
import json, re, ssl, sys, time, urllib.request, urllib.error, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import poc_v3_attack_chain as poc
import poc_v2_auto_register as reg

UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/148 Mobile Safari/537.36"

def _get(url, timeout=12, hdrs=None, method="GET", data=None):
    h = {"User-Agent": UA}
    if hdrs: h.update(hdrs)
    req = urllib.request.Request(url, headers=h, method=method,
                                 data=data.encode() if data else None)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read()

def probe_liveness(url, timeout=12):
    """返回 (alive, version, note)"""
    try:
        st, body = _get(url, timeout)
    except urllib.error.HTTPError as e:
        # 401/404 也算 alive(有服务在跑)
        return True, None, f"http_{e.code}"
    except Exception as e:
        return False, None, type(e).__name__
    text = body.decode("utf-8", "replace")[:4000]
    # 版本号常见于前端 build id / meta
    ver = None
    m = re.search(r'v0\.\d+\.\d+', text)
    if m: ver = m.group(0)
    m2 = re.search(r'"version"\s*:\s*"[^"]+"', text)
    if m2: ver = m2.group(0).split('"')[-1]
    return True, ver, "ok"

def probe_payment(url, timeout=20, email_provider="tempmail", preferred=None):
    """注册 + 看 checkout-info。任何异常都吞掉, 绝不让单站挂掉整轮扫描。"""
    try:
        return _probe_payment(url, timeout, email_provider, preferred)
    except Exception as e:
        return {"url": url, "register": None, "methods": None, "easypay": None,
                "global_max": None, "email": None,
                "note": f"crash:{type(e).__name__}:{str(e)[:80]}"}


def _probe_payment(url, timeout=20, email_provider="tempmail", preferred=None):
    """注册 + 看 checkout-info。返回 dict"""
    out = {"url": url, "register": None, "methods": None,
           "easypay": None, "global_max": None, "note": ""}
    c = poc.Sub2ApiClient(url, timeout=timeout)
    # 1) 拿一个临时邮箱
    try:
        email = reg.generate_mailbox(email_provider, preferred=preferred)
    except Exception as e:
        out["note"] = f"mailbox_crash:{type(e).__name__}"
        return out
    out["email"] = email
    if not email:
        out["note"] = f"no_mailbox({email_provider})"
        return out
    pw = reg.rand_password()
    try:
        body = {"email": email, "password": pw}
        data = c._call("POST", "/api/v1/auth/register", auth=False, json_body=body)
        out["register"] = "ok"
    except poc.ApiError as e:
        msg = str(e)
        if "suffix" in msg.lower() or "not allowed" in msg.lower():
            # 目标有邮件后缀白名单 -> 换 emailmux (能生成 @gmail.com / @outlook.com)
            m = re.search(r"allowed suffixes:\s*(.+)", msg)
            allowed = [x.strip() for x in (m.group(1).split(",") if m else [])]
            out["note"] = f"suffix_whitelist[{','.join(allowed)[:60]}]"
            if email_provider != "emailmux":
                out2 = probe_payment(url, timeout, email_provider="emailmux",
                                     preferred=allowed)
                out2["note"] = (out["note"] + f"[tried={email}] -> "
                                + str(out2.get("note", "")))[:200]
                return out2
            return out
        if "verif" in msg.lower():
            # 需要邮箱验证码
            try:
                c._call("POST", "/api/v1/auth/send-verify-code", auth=False,
                        json_body={"email": email})
            except poc.ApiError as e2:
                msg2 = str(e2)
                if "captcha" in msg2.lower():
                    out["note"] = "captcha"; return out
                if "suffix" in msg2.lower() or "not allowed" in msg2.lower():
                    # 白名单在发码这一步才暴露 -> 同样切 emailmux
                    m2 = re.search(r"allowed suffixes:\s*(.+)", msg2)
                    allowed2 = [x.strip() for x in (m2.group(1).split(",") if m2 else [])]
                    out["note"] = f"suffix_whitelist[{','.join(allowed2)[:60]}]"
                    if email_provider != "emailmux":
                        out2 = probe_payment(url, timeout, email_provider="emailmux",
                                             preferred=allowed2)
                        out2["note"] = out["note"] + " -> " + str(out2.get("note", ""))
                        return out2
                    return out
                out["note"] = f"send_code_fail:{msg2[:70]}"; return out
            code = reg.fetch_verify_code(email, provider=email_provider,
                                         timeout=75, ui=None)
            if not code:
                out["note"] = "code_timeout"; return out
            try:
                data = c._call("POST", "/api/v1/auth/register", auth=False,
                               json_body={"email": email, "password": pw,
                                          "verify_code": code})
                out["register"] = "ok"
            except poc.ApiError as e2:
                out["note"] = f"reg_fail:{e2}"; return out
        else:
            out["note"] = f"reg_fail:{msg[:60]}"; return out
    tok = data.get("access_token") if isinstance(data, dict) else None
    if not tok:
        out["note"] = "no_token"; return out
    c.token = tok
    try:
        info = c._call("GET", "/api/v1/payment/checkout-info")
        out["methods"] = list(info.get("methods", {}).keys())
        out["easypay"] = "easypay" in out["methods"] or "easyPay" in info.get("methods", {})
        out["global_max"] = info.get("global_max")
    except poc.ApiError as e:
        out["note"] = f"checkout:{e}"
    return out

def main():
    phase = sys.argv[1]
    urls = json.load(open(sys.argv[2]))
    args = sys.argv[3:]
    limit = int([a for a in args if a.startswith("--limit")][0].split("=")[1]) if any(a.startswith("--limit") for a in args) else 99999
    conc = int([a for a in args if a.startswith("--concurrency")][0].split("=")[1]) if any(a.startswith("--concurrency") for a in args) else 6
    urls = urls[:limit]
    # 断点续扫: 跳过报告里已有的
    import os
    rep = "/var/minis/shared/sub2api-7881/scan_report.tsv"
    done_urls = set()
    if os.path.isfile(rep):
        with open(rep, encoding="utf-8", errors="replace") as fp:
            for line in fp:
                parts = line.split("\t")
                # 只把本阶段的记录当成"已处理":
                #   phase1 行形如  url	True/False	ver	note
                #   phase2 行形如  url	reg=...
                if phase == "phase1":
                    if len(parts) > 1 and parts[1] in ("True", "False"):
                        done_urls.add(parts[0].strip())
                else:
                    if len(parts) > 1 and parts[1].startswith("reg="):
                        done_urls.add(parts[0].strip())
    before = len(urls)
    urls = [u for u in urls if u not in done_urls]
    print(f"phase={phase} targets={before} pending={len(urls)} concurrency={conc}")
    if not urls:
        print("没有待扫目标"); return
    rows = []
    with ThreadPoolExecutor(max_workers=conc) as ex:
        if phase == "phase1":
            futs = {ex.submit(probe_liveness, u): u for u in urls}
            for f in as_completed(futs):
                u = futs[f]
                alive, ver, note = f.result()
                rows.append((u, alive, ver, note))
        else:
            futs = {ex.submit(probe_payment, u): u for u in urls}
            done = 0
            for f in as_completed(futs):
                try:
                    r = f.result()
                except Exception as e:
                    r = {"url": futs[f], "register": None, "methods": None,
                         "easypay": None, "global_max": None, "email": None,
                         "note": f"future_crash:{type(e).__name__}"}
                done += 1
                rows.append(r)
                if done % 5 == 0:
                    print(f"  [{done}/{len(urls)}]", flush=True)
    path = "/var/minis/shared/sub2api-7881/scan_report.tsv"
    with open(path, "a", encoding="utf-8") as fp:
        if phase == "phase1":
            for u, alive, ver, note in rows:
                fp.write(f"{u}\t{alive}\t{ver or ''}\t{note}\n")
        else:
            for r in rows:
                fp.write(f"{r['url']}\treg={r['register']}\tmethods={r['methods']}"
                         f"\teasypay={r['easypay']}\tmax={r['global_max']}\t{r['note']}\n")
    print("report ->", path)

if __name__ == "__main__":
    main()
