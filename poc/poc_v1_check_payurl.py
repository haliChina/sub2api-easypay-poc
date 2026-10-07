#!/usr/bin/env python3
"""
Diagnostic: run the PoC's transform against a REAL pay_url and report the first
differing byte between the create-time base string and the callback base string.

usage: python3 check_payurl.py '<full submit.php URL>'
"""
import sys
from urllib.parse import urlparse, parse_qsl

PAY = sys.argv[1]

q = dict(parse_qsl(urlparse(PAY).query, keep_blank_values=True))
signed_return = q.get("return_url", "")

print("pay_url 参数：")
for k in sorted(q):
    v = q[k]
    if k == "return_url":
        v = v + "   <-- 走私对应在这个值里"
    print(f"  {k:14} = {v}")

suffix = "&trade_status=TRADE_SUCCESS"
if not signed_return.endswith(suffix):
    print("\n[!] return_url 结尾不是 &trade_status=TRADE_SUCCESS")
    print("    说明这台部署的 CanonicalizeReturnURL 已经把用户 query 剥掉了（① 号补丁已打）")
    sys.exit(1)

prefix = signed_return[: -len(suffix)]
cb = {k: v for k, v in q.items() if k not in ("sign", "sign_type")}
cb["return_url"] = prefix
cb_signed = dict(cb, trade_status="TRADE_SUCCESS")


def base(d):
    d = {k: v for k, v in d.items() if k not in ("sign", "sign_type") and v != ""}
    return "&".join(f"{k}={d[k]}" for k in sorted(d))


s1, s2 = base(q), base(cb_signed)
print("\n下单 基础串:\n  " + s1 + "<PKEY>")
print("\n回调 基础串:\n  " + s2 + "<PKEY>")
print("\n逐字节相同: " + str(s1 == s2))
if s1 != s2:
    i = next((i for i in range(min(len(s1), len(s2))) if s1[i] != s2[i]), min(len(s1), len(s2)))
    print(f"\n第一个不同的位置 offset={i}")
    print(f"  下单: ...{s1[max(0,i-70):i+70]}...")
    print(f"  回调: ...{s2[max(0,i-70):i+70]}...")

print("\n本伪造里带上的『下单专有字段』（真实异步通知里不会有）：")
extra = sorted(set(cb_signed) - {"pid", "trade_no", "out_trade_no", "type",
                                 "name", "money", "trade_status", "param",
                                 "sign", "sign_type"})
print("  " + (", ".join(extra) if extra else "无"))
if extra:
    print("\n  若这台部署打过 ② 号白名单补丁，日志里会是：unexpected notify param: " + extra[0])
    print("  客户端同样是 400 verify failed —— 和『签名不匹配』长得一模一样。")