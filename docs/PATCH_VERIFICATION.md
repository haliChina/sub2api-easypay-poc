# 修复验证 · v0.2.14

> **结论：v0.2.14 已修复 issue #7881。** 本文档记录**实测**过程，非推测。
> 验证方式：用真实 v0.2.14 源码替换 pocserver 的 `easypay.go`，同一份 PoC 打两次。

---

## 1. 一句话结论

```
v0.2.13 (b8dece90)  →  VULNERABLE       伪造回调被接受，余额 +10.00
v0.2.14            →  NOT_VULNERABLE   HTTP 400 verify failed
```

**release note 与我的修复建议完全一致**（`return_url` 剥离 query + 回调白名单），
维护者两条都采纳了。

---

## 2. 上游声明

[v0.2.14 Release](https://github.com/Wei-Shaw/sub2api/releases/tag/v0.2.14) ·
发布于 `2026-10-07T02:02:43Z`：

> 修复 EasyPay 下单签名可被重放为支付成功回调、无需商户密钥即可伪造到账的安全漏洞：
> **return_url 不再保留客户端查询参数，回调验签拒绝非标准通知参数**（#7881）

同版本还修了 #7850（默认管理员邮箱可猜测）。

---

## 3. 代码核对（不只信 release note）

### 修复点 1 · `CanonicalizeReturnURL` 剥离用户 query

`backend/internal/service/payment_resume_service.go:235`

```go
func CanonicalizeReturnURL(raw string, srcHost string, srcURL string) (string, error) {
	...
	parsed.Fragment = ""
	parsed.RawQuery = ""      // ← 新增：用户 query 一律丢弃
```

→ **对应我的「方案 A」**。走私通道直接切断。

### 修复点 2 · `VerifyNotification` 加回调参数白名单

`backend/internal/payment/provider/easypay.go:369`

```go
params := make(map[string]string)
for k := range values {
	if !easyPayNotifyAllowedParams[k] {
		return nil, fmt.Errorf("unexpected notify param: %s", k)
	}
	params[k] = values.Get(k)
}
```

→ **对应我的「方案 B」**。未知字段不再进入验签流程。

> 附带修了一个真 bug：`params[k] = v` 循环覆盖 → `values.Get(k)` 取第一个。
> 重复参数时语义不同。

---

## 4. 实测：同一份 PoC 跑两个版本

**方法**：把真实 `easypay.go` 换进 `go-poc/cmd/pocserver`，用**完全相同**的
PoC 脚本、相同金额、相同攻击构造打两次。这是关键的对照——变量只有源码版本。

### v0.2.13（未修复）

```
[3] 解析支付 URL, 构造伪造回调
[+] 已从 pay_url 提取下单签名: <sign>
[4] 发送伪造支付成功回调
[*] webhook 响应: HTTP 200 {"code":0,...,"message":"success"}
[+] 订单 sub2_TEST1001 状态=PAID, 余额增加 10.00
判定结果: VULNERABLE
```

服务端：
```
[webhook] ACCEPTED order=sub2_TEST1001 status=success amount=10.00 credited=true balance=10.00
```

### v0.2.14（已修复）

```
[3] 解析支付 URL, 构造伪造回调
[+] 已从 pay_url 提取下单签名: 9e7b028d6f9409547d8906c53ffe9824
[*] return_url 截断: ...o=sub2_TEST1001&resume_token=RESUME.JWT.token&status=success
[4] 发送伪造支付成功回调
[*] webhook 响应: HTTP 400 body='verify failed'
判定结果: NOT_VULNERABLE
```

注意 `return_url 截断` 那一行——**v0.2.14 下 `trade_status` 已不在 `return_url` 里**，
`build_forged_callback` 是在截断后手工追加的（模拟攻击者强行拼接）。
服务端白名单直接把它拒了。

---

## 5. 这解释了一个观察

之前对某个真实目标测试时，PoC 稳定返回 HTTP 400。当时的判断是
「这台部署打了 ② 号白名单补丁」——**现在得到确认**，而且这台部署的
二进制已经带上 v0.2.14。

**外部可观测差异**：

| 版本 | webhook 响应 | 服务端日志 |
|---|---|---|
| 未修 | `HTTP 200 {"code":0}` | 无异常 |
| 已修 | `HTTP 400 verify failed` | `unexpected notify param: trade_status` |

> 排查建议：`docker logs <container> | grep 'unexpected notify param'`
> 出现这行 = 已修复；出现 `invalid signature` = 未修复但签名不同（另一个问题）。

---

## 6. 修复效果评价

| 维度 | 评价 |
|---|---|
| **彻底性** | ✅ 两条建议全采纳，A + B 都在 |
| **兼容性** | ✅ 没有动 `easyPaySign` 的签名算法，上游易支付不受影响 |
| **纵深防御** | ✅ 两层独立机制，单点失效不会被打穿 |
| **附带修复** | ✅ 重复参数取值语义修正 |
| **残留风险** | ⚠️ 见下 |

### ⚠️ 残留建议（我的方案 C 未被采纳）

当前逻辑仍是「验签通过 → 直接加余额」，**没有向上游 `api.php` 复核**。
这意味着：一旦签名机制本身再出问题（新的注入点、或上游换了签名算法），
系统仍会直接入账。

如果预算允许，建议后续补上异步复核。这是唯一能兜住「签名层被绕过」的机制，
A + B 只能堵住**已知的**注入点。

---

## 7. 给运维的升级建议

```bash
# Docker
docker pull weishaw/sub2api:0.2.14        # 或 ghcr.io/wei-shaw/sub2api:0.2.14

# 一键安装
curl -sSL https://raw.githubusercontent.com/Wei-Shaw/sub2api/main/deploy/install.sh | sudo bash
```

**升级前注意 #7850 的破坏性变更**（与本漏洞无关，但同版本）：

- `AUTO_SETUP` 全新安装时，`ADMIN_PASSWORD` 少于 8 字节或超过 72 字节 → **安装失败**
- `ADMIN_EMAIL` 不是合法可登录邮箱 → **安装失败**
- 未设置 `ADMIN_EMAIL` 时，管理员邮箱**不再是** `admin@sub2api.local`，
  改为 `admin-<随机串>@sub2api.local`，**从首次启动日志里取**

> 已有管理员 / 已有用户的部署不受影响，不会因此阻断启动。

**升级后建议**：在后台改掉管理员邮箱与密码（如果还在用旧默认值）。

---

## 8. 复现本文档的验证

```bash
# 1. 拿 v0.2.14 源码
curl -sL https://codeload.github.com/Wei-Shaw/sub2api/tar.gz/refs/tags/v0.2.14 | tar xz

# 2. 换进 pocserver
cd sub2api-easypay-poc/go-poc
cp ../sub2api-0.2.14/backend/internal/payment/provider/easypay.go \
   internal/payment/provider/easypay.go
GOTOOLCHAIN=local go build -o /tmp/poc214 ./cmd/pocserver

# 3. 打
/tmp/poc214 8901 &
cd ../poc
python3 poc_v3_attack_chain.py --target http://127.0.0.1:8901 \
  --email tester@example.com --password correct-horse --amount 10 --yes --plain
```

期望：`判定结果: NOT_VULNERABLE` / `HTTP 400 verify failed`
