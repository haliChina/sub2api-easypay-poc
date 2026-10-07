# sub2api #7881 验证报告 — 易支付签名复用 / return_url 参数走私

**结论：漏洞真实存在，报告者的 PoC 成立。评论区「回调参数变了签名就对不上」的反驳不成立。**

验证对象：`Wei-Shaw/sub2api` @ `b8dece90`（2026-10-02，v0.2.13），main 分支**未修复**。
验证日期：2026-10-06。

---

## 1. 为什么评论区那套反驳是错的

他们的论证是：

> 下单和回调的参数集合根本不一样，回调里多了 `trade_status`、`trade_no` 等字段，参数一变，签名就对不上。

这个论证隐含一个前提：**下单签名的基础串由哪些参数构成，攻击者无法影响**。代码里这个前提不成立。

`easyPaySign`（`easypay.go:580`）拼接时**不做任何转义**：

```go
_, _ = buf.WriteString(k + "=" + params[k])   // easypay.go:594
```

一个参数的值里可以藏 `&key=value`。于是同一个字节串存在两种合法切分，签名对两种都成立。
评论区只考虑了「参数集合不同」，没考虑「参数集合相同但边界不同」。

`VerifyNotification`（`easypay.go:371`）把回调 query 原样收进 params 后重算签名，**没有字段白名单**，所以第二种切分畅通无阻。

---

## 2. 走私路径（四步，全部在 main 上核实）

| 步骤 | 位置 | 事实 |
|---|---|---|
| 注入源 | `payment_resume_service.go:235` | `CanonicalizeReturnURL` 只校验 scheme/host/path，`:247` 只清 `Fragment`，**`RawQuery` 原样保留** |
| 走私装配 | `payment_resume_service.go:276` | `buildPaymentReturnURL` 用 `query.Encode()`（`:302`）**按 key 排序**重编码，注入的 `trade_status` 必然排在**最后** |
| 排序巧合 | `easyPaySign` | key 排序中 `return_url` < `trade_status` < `type`，所以注入对紧贴在 `&type=` 之前——正是切分点 |
| 签名暴露 | `easypay.go:138` | popup 模式 `createRedirectPayment` 把 `sign` 直接放进返回给付款人的 `submit.php` URL |

服务端重建后的 `return_url`（Go 标准库实测输出）：

```
https://HOST/payment/result?order_id=99&out_trade_no=ORDER&resume_token=T&status=success&trade_status=TRADE_SUCCESS
```

攻击者把 `return_url` 截到 `...status=success` 为止，把 `trade_status=TRADE_SUCCESS` 提升为顶层参数。两条基础串：

```
下单:   ...&return_url=<完整含走私对>&type=alipay<PKEY>
回调:   ...&return_url=<截断>&trade_status=TRADE_SUCCESS&type=alipay<PKEY>
```

**逐字节相同。**

注意：走私对前面必须是 `&` 而不是 `?`。攻击者必须用服务端重建后的完整 URL，不能用原始注入串 —— 这一点报告者的 PoC 做对了（他直接构造了终态），而我第一版用原始 `?trade_status=` 是错的，差一个字节，签名对不上。

---

## 3. 入账链路无阻碍

`confirmPayment`（`payment_fulfillment.go:112`）只比对金额与订单状态：

- 金额：攻击者用**自己的**订单，`money` 天然等于 `PayAmount` ✓
- 状态：自己的未付订单就是 pending ✓
- provider key / pid 元数据校验：都是攻击者从自己 pay_url 里读到的值 ✓
- `toPaid` → 账户余额入账 ✓

所以是**零成本给自己充值**，且每下一单就有一个新签名，**轮换 `pkey` 完全无效**——攻击者每次都现取现用。

---

## 4. 复现结果（真实源码，未经修改）

把 `easypay.go` 原样放进最小模块用 go1.23 编译运行：

```
=== RUN   TestSmuggleCreateSignatureIntoForgedCallback
    sign      : 143612572d7b0d5b176c571df4470e50  (server-computed with pkey, attacker does NOT know pkey)
    create  base string: money=650.00&name=balance recharge&notify_url=...&out_trade_no=sub2_ATTACKER_ORDER_0001&pid=1000&return_url=https://site.example.com/payment/result?order_id=99&out_trade_no=...&resume_token=RESUME_TOKEN&status=success&trade_status=TRADE_SUCCESS&type=alipay<pkey>
    verify  base string: money=650.00&name=balance recharge&notify_url=...&out_trade_no=sub2_ATTACKER_ORDER_0001&pid=1000&return_url=https://site.example.com/payment/result?order_id=99&out_trade_no=...&resume_token=RESUME_TOKEN&status=success&trade_status=TRADE_SUCCESS&type=alipay<pkey>
    ACCEPTED: order=sub2_ATTACKER_ORDER_0001 trade_no="" status=success amount=650.00
    BUG REPRODUCED: forged callback accepted, no merchant key required
--- PASS
=== RUN   TestSmuggleNegativeControl     (干净 return_url -> invalid signature)  --- PASS
=== RUN   TestSmuggleRealNotifyStillWorks (真实回调照常通过)                      --- PASS
=== RUN   TestSmuggleServerReorder        (注入对排序在最后)                      --- PASS
ok  github.com/Wei-Shaw/sub2api/internal/payment/provider
```

两个对照组的意义：控制组证明「干净 `return_url` 的同样伪造会被拒」，所以上面的通过确实是走私造成的，不是 `VerifyNotification` 漏字段；真实回调组证明不是「什么都能过」。

---

## 5. 攻击前提（缺一不可）

1. 易支付实例 `paymentMode = popup`（`submit.php`）。mapi 模式签名不暴露给付款人，此法不适用。
2. 用户提交了 `return_url`。官方前端**总是**提交 `origin + /payment/result`（`paymentFlow.ts:143`），所以实际上普遍满足。
3. 实例未配置 `cid` **不是**前提——`cid`/`device` 都是独立顶层参数，攻击者照抄即可。

---

## 6. 修复评估

报告者给的 ①② 是对的，② 的白名单尤其重要——它按**整类**拼接走私设防，不依赖已知注入点：

- ① `CanonicalizeReturnURL` 剥离 `RawQuery`（用户 query 本无合法用途）
- ② `VerifyNotification` 加字段白名单，多一个键就拒（真实易支付异步通知只有固定字段）
- ③④（异步上游复核、后台手动查验）是纵深防御，建议做但不阻塞修复

**补一条报告没提的**：`easyPaySign` 本身不转义是这类走私的**根因**。只堵 `return_url` 只能堵住这一个注入点；只要将来任何一个被签名的字段的值来自用户且不转义，同类走私就会重新出现。建议 `easyPaySign` 对值做 `url.QueryEscape`——但要注意这会**破坏与易支付上游的签名兼容性**（上游用的是不转义版本），所以不能单方面改，只能靠白名单兜。这是修复方案里最需要权衡的地方。

---

## 7. 产物

| 文件 | 用途 |
|---|---|
| `easypay_smuggle_poc_test.go` | 丢进 `backend/internal/payment/provider/`，`go test -run TestSmuggle -v` |
| `easypay_smuggle_poc.py` | 打你自己部署的端到端脚本，自带登录，默认 dry-run，`--send` 才真发 |
| `model_check.py` | 纯 Python 复现基础串碰撞，用于交叉验证 |
| `mock_server.py` | 模拟 sub2api 的本地服务，用来验证脚本各条错误分支 |
| `sub2api-mini/` | 最小 Go 模块（真实源码 + 测试），无需 go1.27 工具链 |

## 8. 脚本的登录与错误处理（已实测）

登录是 **email 不是用户名**（`auth_handler.go:78` `binding:"required,email"`）。

```bash
export SUB2API_PASSWORD='...'          # 用环境变量，别写命令行
python3 easypay_smuggle_poc.py --base https://站点 --email you@example.com
```

密码没给时会 `getpass` 交互输入（不回显）。以下分支都用 `mock_server.py` 实跑过：

| 情况 | 脚本行为 |
|---|---|
| 正常登录 | 取 `data.access_token`，继续 |
| 密码/邮箱错 | 提示「确认是邮箱不是用户名」 |
| 两步验证 | 提示掩码邮箱，`getpass` 收 6 位码 → `POST /auth/login/2fa` |
| 2FA 码错 | 明确报错并给出可能原因 |
| 人机验证 | **不尝试绕过**，给出 `--cookie` 两条正路 |
| 限流 429 | 提示 sub2api 的 20 次/分钟限制 |
| 服务端 500 | 区分「站点配置问题」与 PoC 无关 |
| 已打补丁的部署 | 检测到 `trade_status` 不在末尾，明确说明该版本已修 |
| 非 popup 实例 | 检测到 `pay_url` 不是 `submit.php`，说明本 PoC 不适用 |

**人机验证这条是刻意的**：脚本只做检测和引导，不做验证码破解或反检测规避。