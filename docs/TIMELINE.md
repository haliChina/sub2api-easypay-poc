# 迭代时间线

记录从静态分析到最终交付的过程，包括每个版本解决了什么、踩了哪些坑。

---

## v1 — 静态分析 + 三重验证

**目标**：证明漏洞成立，不依赖任何 mock。

| 产物 | 作用 | 结果 |
|---|---|---|
| `poc_v1_go_test.go` | 对**未修改**的真实 `easypay.go` 跑单测 | 4/4 PASS |
| `poc_v1_model_check.py` | 四个 Go 函数的纯 Python 模型 | `byte-identical: True` |
| `poc_v1_e2e.py` | 端到端 HTTP 利用脚本 | 见 v2 |

**关键发现**：`easyPaySign`（`easypay.go:580/594`）拼接 `k=v&k=v` **不转义**，
参数值里能藏 `&key=value`；`VerifyNotification`（`easypay.go:371`）**无字段白名单**。

**踩的坑**：

- `go.mod` 要求 go 1.27，PRoot 里 apk 的 go 1.23 会触发 40MB 工具链下载，10 分钟没完
  → **解法**：把 `easypay.go` + 依赖原样拷进最小模块，`GOTOOLCHAIN=local` + go 1.23 编译。
  **跑真实源码，不重写函数。**
- `git clone` 走 HTTPS 在 PRoot 会 RPC failed → 用 `codeload.github.com/.../tar.gz`
- PoC 测试断言写 `?trade_status=` 但实际应该是 `&trade_status=`（走私对前缀必须是 `&`）
  → **教训**：攻击者必须用**服务端重建后的完整 return_url**，不能用原始注入串

---

## v2 — 真实验签服务端（补上最大的验证缺口）

**转折点**：用户直接指出——

> 「你这个代码自己都没跑通过过」

**完全正确。** v1 的 e2e 只在**我自己写的 mock** 上测过，而那个 mock 的 webhook
**根本不验签、无条件返回 success**。这是循环论证：
**mock 只能验证「我的脚本符合我对被测系统的理解」，不能验证「被测系统真的这么跑」**。

**解法**：`go-poc/cmd/pocserver` —— 起一个**用真实被测代码**的最小服务。
`NewEasyPay` / `CreatePayment` / `VerifyNotification` 都是导出方法，直接从原仓库拷。

**必须配反向对照**（否则「攻击成功」无法归因）：

- 垃圾签名 → 必须 400
- 干净 `return_url` 的同样伪造 → 必须被拒

```
$ ./run_e2e.sh
[webhook] ACCEPTED order=sub2_TEST1001 status=success amount=10.00 credited=true
[5] HTTP 200 credited:true
[6] PAID
```

**教训**（最通用的一条）：
> 「写了类 + 测试全绿」≠「功能可用」。交付前必须验证产出物**真的被消费**。

---

## v3 — 参考脚本优化

基于**叶白**提供的 974 行参考脚本（`reference/reference_easypay_poc_original.py`）。

**参考脚本的优点**：TUI + `--selftest` 三场景（漏洞 / 白名单修复 / query 剥离修复），
且 emulator **真的验签**（不像我第一版 mock 无条件 success）。

**我补的 5 项**：

| # | 内容 | 说明 |
|---|---|---|
| 1 | `--selftest-real` | 编译真实 `easypay.go` 跑端到端，含两个反向对照 |
| 2 | **Go 语义修正** | 见下方「踩坑」 |
| 3 | 2FA 支持 | 原脚本遇 2FA 直接抛「请换用未开 2FA 的账户」 |
| 4 | 网关层诊断 | 502/503/504 + HTML 时给出「请求没到后端」的可操作提示 |
| 5 | captcha 提示 | 明确「不会绕过」 |

### 踩坑 1：Python `urlencode` 不排序，Go `url.Values.Encode()` 排序

写 Go 行为模型时必须手动 `sorted()`，否则会得出**「攻击不成立」的错误结论**。

### 踩坑 2：`parse_qsl` 默认在 `;` 处切分，Go 1.17+ `url.ParseQuery` 不会

且 `values.Get(k)` 取**第一个**，而原代码 `params[k]=v` 循环覆盖取**最后一个**。
两处都是真行为差异，参数重复时会对不上。

---

## v4 — 统一菜单 + 批量扫描

**目标**：把三条线合并成带交互菜单的单文件入口。

**没有复制代码，是 import 复用**——v3 提供攻击链，自动注册模块提供注册流程，
菜单层只做编排。以后任一模块改了菜单自动跟上。

### 合并时抓到的 5 个真 bug（都是自己写错的）

| # | Bug | 根因 |
|---|---|---|
| 1 | `reg.UI` / `reg.Sub2ApiClient` 不存在 | auto-register 是 `import poc` 后用 `poc.UI` 的，我没 from 进来 |
| 2 | `reg.load_records` 不存在 | 我之前加它的 `file_edit` 失败了却没复查，后面直接引用 |
| 3 | `login_2fa(temp, code)` 传空串 | 真实流程 login 返回 `requires_2fa` + `temp_token`（code 仍为 0，不抛异常） |
| 4 | `send_verify_code` 加了两遍 | 第二个生效 |
| 5 | `reg.main_loop` 是幻想的 | auto-register 只有 `main()`，里面混着 argparse |

> **教训**：符号存在性检查要用 `^(def\|class) X\b\|^X\s*=` 严格匹配，
> `rg 'X'` 会被 docstring 里的字样骗过（我第一轮检查就假阳性了）。
> **补丁失败后必须复检落点。**

### 最隐蔽的一个：符号链接导致类身份分裂

```
sub2api_easypay_poc.py -> sub2api_easypay_poc_v2.py   (符号链接)
```

Python 把同一个文件加载成**两个模块**，`ApiError` 变成**两个不同的类**。
结果：v2 客户端抛 `..._v2.ApiError`，但 auto-register 的 `except poc.ApiError`
捕获的是符号链接那一份的类 → **捕获失败，异常穿透**。

已删符号链接，统一引用真实模块名，并加 `assert reg.poc is poc` 防复发。

---

## 邮件验证码自动化

实测目标（域名已脱敏，见 `evidence/README.md`）需要邮箱验证码才能注册。

### 坑 1：本地随机的 gmail 收不到信

脚本原本本地随机生成 `@gmail.com`——那是**真实信箱**，tempmail/emailmux 根本收不到。
**邮箱必须由邮件服务自己生成。**

### 坑 2：两种服务的规则完全不同

| 服务 | 规则 |
|---|---|
| `tempmail.cn` | 前缀**随便拼**，不需要申请（`12@tempmail.cn`） |
| `emailmux.com` | **必须** `POST /generate-email`，否则拿到的地址不受它控制 |

### 坑 3：emailmux 的签名算法

抓包里的签名与时间戳绑定，早就过期。它的前端 `/static/index.js` 里是**明文常量**：

```js
const SECRET = 'yjd683c@47';
sig = CryptoJS.MD5(SECRET + email + Date.now()).toString();
```

### 坑 4：取到了错的那个 6 位数字

邮件正文 `Hello 571622,` 里的用户名也是 6 位，关键词在前就命中了它。

**解法**：先剥 HTML 标签 → 剔掉邮箱本地部分 → **取最后一次命中**而非第一次。

### 坑 5：tempmail 返回的是 `{"mails":[...]}` 不是裸数组

### 坑 6：emailmux 429 限流 / 按权重随机给域名

请求 `domains:["gmail"]` 也可能返回 `outlook`。加校验重试 + 指数退避（3.8 秒命中 gmail）。

---

## 批量扫描结果

930 个存活公开实例，**0 个**配置为 popup+易支付。

| 通道 | 站点数 |
|---|---|
| 无支付 | 70 |
| alipay | 13 |
| alipay + wxpay | 7 |
| stripe | 2 |
| USDT | 3 |
| **easypay** | **0** |

**结论**：漏洞前提条件很窄（popup 模式 + 前端提交 return_url + 未打补丁），
当前威胁面主要在自建/小众部署。

### 扫描器踩的坑

- **`RemoteDisconnected` 未捕获**杀了整轮扫描（跑 135/910 崩掉）
  → 给 `probe_payment` 包兜底，任何异常都不许中断
- **断点续扫按 URL 去重**，但 phase1/phase2 记录同格式 → 误判全部已扫
  → 改成分阶段判别（phase1 行第二列是 `True/False`，phase2 行第二列以 `reg=` 开头）
- **`generate_mailbox` 返回 `None` 没检查**，把 `None` 当邮箱发出去
  → 报了个误导性的 `RegisterRequest.Email required`

---

## 环境备忘

| 坑 | 规避 |
|---|---|
| `go run` 残留进程占端口 | 新进程 bind 失败**静默退出**，连到旧服务报 404。端口改 `argv[1]`，自检用 `socket.bind(('127.0.0.1',0))` |
| `go build ... \| head -5` 吞错误 | 管道退出码取的是 `head` 的 |
| `go run` 必须在 module 根内 | `go run go-poc/cmd/x` 报 "not in std" |
| Android 进程数上限 16 | 后台进程攒多了 shell 不执行 |
| BusyBox ash 无 brace expansion | `mkdir -p a/{b,c}` 创建一个字面量目录 |
| CJK 双宽但 `len()` 算 1 | `east_asian_width(c) in "WF"` 算显示宽度；`str.center()` 按字符数算，双重坑 |
