# 修复方案 · issue #7881

> 目标读者：sub2api 维护者与运维
> 结论先行：**漏洞成立**，根因是 `easyPaySign` 拼接签名串时不转义参数值。

> ## ✅ 官方已在 v0.2.14 修复
> [v0.2.14](https://github.com/Wei-Shaw/sub2api/releases/tag/v0.2.14)（2026-10-07 发布）
> 已同时采纳本文的**方案 A**（剥离 return_url query）和**方案 B**（回调参数白名单）。
> **升级到 v0.2.14+ 即可。** 实测验证见 [PATCH_VERIFICATION.md](PATCH_VERIFICATION.md)。
>
> 下面保留方案说明，供维护者理解修复原理，以及评估未被采纳的**方案 C**。

---

## 1. 漏洞根因

`internal/payment/provider/easypay.go` 的 `easyPaySign`（约 :580 / :594）按
`k=v&k=v` 拼接待签名字符串，**参数值未经 URL 转义**：

```go
base := ""
for k, v := range sortedKeys {
    if base != "" { base += "&" }
    base += k + "=" + v      // ← v 直接拼进去
}
```

而 `VerifyNotification`（约 :371）用 `url.ParseQuery` 解析回调后**重新计算签名，无字段白名单**。

于是同一个字节串存在**两种合法切分**，两种切分算出的签名完全相同：

```
# 攻击者构造的 return_url（ smuggle 一个 &key=value ）
https://site/payment/result?trade_status=TRADE_SUCCESS

# 服务端 buildPaymentReturnURL 用 url.Values.Encode() 重排后（key 排序）
...?out_trade_no=XXX&order_id=XXX&resume_token=XXX&return_url=https%3A%2F%2Fsite%2Fpayment%2Fresult%3Ftrade_status%3DTRADE_SUCCESS&status=XXX

# VerifyNotification 用 ParseQuery 解析 —— 同一个 trade_status 出现两次：
#   1) 作为顶层参数
#   2) 被截断后残留在 return_url 值里
# 而 sign 对这两种切分都成立
```

**关键点**：`trade_status` 必然排在最后，因为 `url.Values.Encode()` 按 key 排序，
`return_url < status < trade_status < type`。攻击者不需要预测顺序——排序是确定性的。

---

## 2. 攻击前提

必须**同时**满足：

| # | 条件 | 说明 |
|---|---|---|
| 1 | 易支付实例为 **popup 模式** | 浏览器跳转 `submit.php?...&sign=...`，签名暴露在 URL 里 |
| 2 | 前端提交 `return_url` | 官方前端 `paymentFlow.ts:143` **总是**提交，所以普遍满足 |
| 3 | 未加回调字段白名单 | main 分支至今未修 |

任一不满足则不可利用。非 popup（扫码 / mapi）模式下签名不下发给客户端，攻击链断在第一步。

实测 930 个公开实例：**0 个**配置为 popup+易支付，因此当前威胁面主要在自建/小众部署。

---

## 3. 修复方案

### 方案 A：剥离用户 query（最小改动，强烈建议先上）

`payment_resume_service.go` 的 `CanonicalizeReturnURL`（约 :235）校验了 scheme/host/path，
但**保留了 RawQuery**。让它丢弃即可：

```go
func CanonicalizeReturnURL(raw string) (string, error) {
    parsed, err := url.Parse(raw)
    if err != nil {
        return "", err
    }
    if parsed.Scheme != "https" && parsed.Scheme != "http" {
        return "", errors.New("invalid scheme")
    }
    if parsed.Host == "" {
        return "", errors.New("missing host")
    }
    // ↓↓↓ 新增：服务端自己拼 query，用户带的 query 一律丢弃
    parsed.RawQuery = ""
    parsed.Fragment = ""
    return parsed.String(), nil
}
```

> 这一行直接切断走私通道：注入的 `trade_status` 永远进不了签名串。

### 方案 B：回调参数白名单（纵深防御，建议同时上）

`VerifyNotification` 解析出 `params` 后，只接受易支付回调的**已知字段**：

```go
// 易支付规范回调字段（来源：彩虹易支付 V2 接口文档）
var allowedNotifyFields = map[string]bool{
    "pid": true, "trade_no": true, "out_trade_no": true,
    "name": true, "money": true, "trade_status": true,
    "type": true, "notify_url": true, "return_url": true,
    "sitename": true, "sign": true, "sign_type": true,
}
```

对 `params` 里出现但不在白名单的 key → 直接拒绝。这样即使将来出现第二个注入点，
也不会有未知字段进入验签流程。

> 注意：`return_url` 在**回调**里出现是正常的（部分易支付实现会回传），所以它在白名单里。
> 白名单治的是「未知字段」，不是 `return_url` 本身。

### 方案 C：入账后异步复核（可选，最稳）

当前逻辑是「验签通过 → 直接加余额」。改为加余额后异步向上游 `api.php` 查单确认。
上游不认这笔单时回滚。这是唯一能兜住「签名机制本身被绕过」的方案，但改动最大。

### 方案 D：升级前的临时缓解

把易支付实例切到 **非 popup 模式**（扫码 / mapi）。签名不再暴露给客户端，
PoC 的第一步「从 `pay_url` 取签名」就断了。缺点是用户体验有变化。

---

## 4. 为什么不能只做转义

看起来最干净的修法是给 `easyPaySign` 的参数值加 `url.QueryEscape`。**但不能单方面改**：

- 易支付上游（彩虹易支付等）用的是**不转义版**签名算法。
- 你改了 `easyPaySign` → 你发给上游的请求签名变了 → **上游全部验签失败**，
  所有走易支付的订单直接挂掉。

所以值转义这条路在兼容性上是死的。**必须靠方案 A / B 在语义层堵**。

---

## 5. 修复优先级

### 现状（2026-10-07 起）

```
✅ 已完成   升级到 v0.2.14 —— 官方已采纳方案 A + B
```

### 如果仍停留在 v0.2.13 及更早版本

```
立即（今天）  升级到 v0.2.14                    ← 首选
    或         方案 A  —— 一行，切断走私通道
本周          方案 B  —— 纵深防御，防同类问题
下次发布      方案 D  —— 配合 A 作为回滚预案
有余力        方案 C  —— 上游复核，彻底闭环
```

> **不推荐**自己打补丁再升级 —— 直接升到 v0.2.14 更省事，且能拿到上游测试覆盖。

---

## 6. 验证方法

本仓库 `poc/poc_v4_menu.py` 的**离线自检**（路径 3）内置三个场景，可用于验证补丁：

```bash
cd poc
python3 poc_v4_menu.py        # 选 3 → 离线自检
```

期望输出：

| 场景 | 服务端状态 | 期望判定 |
|---|---|---|
| A | 未修复 | `VULNERABLE` |
| B | 已加回调白名单（方案 B） | `NOT_VULNERABLE` |
| C | 已剥离 return_url query（方案 A） | `NOT_VULNERABLE` |

**打完补丁后跑一遍，三个场景都应该是 `NOT_VULNERABLE`。**

真实源码端到端自检（路径 4）会编译真实的 `easypay.go` 起服务并跑完整攻击链，
包含两个反向对照：

```bash
python3 poc_v4_menu.py        # 选 4 → 真实源码自检
```

- 反向对照 1：垃圾签名必须被拒
- 反向对照 2：干净 `return_url` 的同样伪造必须被拒

两个对照都通过 → 证明「通过确实是因为走私，而不是因为验签形同虚设」。
