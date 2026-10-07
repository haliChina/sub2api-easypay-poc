# sub2api-easypay-poc

> Sub2API ([Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api)) 易支付回调**签名复用**漏洞复现工具
> Issue: [#7881](https://github.com/Wei-Shaw/sub2api/issues/7881) · 基于 `b8dece90` (v0.2.13)

**漏洞成立。** 攻击者可在**不持有商户密钥**的前提下伪造支付成功回调，给自己的账户充值。

---

## ✅ 已修复 · 升级到 v0.2.14 即可

[官方 v0.2.14](https://github.com/Wei-Shaw/sub2api/releases/tag/v0.2.14)（2026-10-07 发布）
已同时采纳本文的**方案 A**（剥离 `return_url` query）和**方案 B**（回调参数白名单）。

**实测验证**（同一份 PoC、相同攻击构造、只换源码版本）：

| 版本 | 结果 |
|---|---|
| v0.2.13 (`b8dece90`) | 🔴 `VULNERABLE` — HTTP 200，余额 +10.00 |
| v0.2.14 | 🟢 `NOT_VULNERABLE` — HTTP 400 `verify failed` |

📖 验证过程与代码核对见 **[docs/PATCH_VERIFICATION.md](docs/PATCH_VERIFICATION.md)**

<details>
<summary>如果你仍在 v0.2.13 及更早版本</summary>

```bash
docker pull weishaw/sub2api:0.2.14
# 或
curl -sSL https://raw.githubusercontent.com/Wei-Shaw/sub2api/main/deploy/install.sh | sudo bash
```

**同版本还有一处破坏性变更**（#7850，与本漏洞无关）：全新 `AUTO_SETUP` 安装时
`ADMIN_PASSWORD` 少于 8 字节或超过 72 字节、或 `ADMIN_EMAIL` 非法会**直接失败**；
未设置 `ADMIN_EMAIL` 时管理员邮箱不再是 `admin@sub2api.local`，
从**首次启动日志**取。已有部署不受影响。

</details>

---

## ⚠️ 法律声明

本工具仅供安全研究与防御自查。

- **仅限**用于你自己部署的实例，或已获得**书面授权**的目标
- 对未授权目标使用造成的后果由使用者自行承担
- 仓库中不含任何真实目标清单或账号凭据

---

## 漏洞原理

`easyPaySign` 拼接签名串时**不转义参数值**（`easypay.go:594`），
`VerifyNotification`（`easypay.go:371`）解析回调后重算签名时**无字段白名单**。

因此同一个字节串存在两种合法切分，且两种切分签名相同：

```
# 攻击者提交的 return_url（smuggle 一个 &key=value）
https://site/payment/result?trade_status=TRADE_SUCCESS

# 服务端重排后 —— trade_status 出现在两个位置：
#   1) 顶层参数
#   2) 被截断后残留在 return_url 值里
# 而 sign 对这两种切分都成立
```

**攻击前提**（三者同时满足才可利用）：
1. 易支付实例为 **popup 模式**（签名暴露在 `submit.php` URL 里）
2. 前端提交 `return_url`（官方前端**总是**提交，普遍满足）
3. 未加回调字段白名单

📖 完整分析见 **[docs/VERDICT.md](docs/VERDICT.md)**

---

## 快速开始

```bash
git clone https://github.com/haliChina/sub2api-easypay-poc.git
cd sub2api-easypay-poc/poc
python3 poc_v4_menu.py
```

```
╔══════════════════════════════════════════════════════════════════╗
║            sub2api 易支付回调伪造 PoC  ·  issue #7881            ║
║               ⚠  仅限授权测试 · 禁止用于未授权系统               ║
╟──────────────────────────────────────────────────────────────────╢
║  1)  复现漏洞  — 已有账号 → 直接攻击                             ║
║  2)  自动注册+攻击  — 新账号 → 注册并攻击                        ║
║  3)  离线自检  — 本地模拟服务端，验证 PoC 逻辑                   ║
║  4)  真实源码自检  — 用真实 easypay.go 编译服务跑端到端          ║
║  5)  查看已保存账号                                              ║
║  6)  退出                                                        ║
╚══════════════════════════════════════════════════════════════════╝
```

**依赖：Python 3.8+ 纯标准库。** 路径 4 需要 Go（用于编译真实源码）。
装 `rich` 会有更好的终端输出，非必需。

---

## 目录结构

```
sub2api-easypay-poc/
├── poc/                        # PoC 各版本演进
│   ├── poc_v1_e2e.py           # v1 端到端脚本（最早版本）
│   ├── poc_v1_model_check.py   # v1 纯函数模型校验
│   ├── poc_v1_mock_server.py   # v1 mock 服务端
│   ├── poc_v1_go_test.go       # v1 Go 单测（4/4 PASS）
│   ├── poc_v1_check_payurl.py  # v1 支付 URL 诊断
│   ├── poc_v1_run_e2e.sh       # v1 一键端到端
│   ├── poc_v2_auto_register.py # v2 自动注册 + 邮箱验证码（基于叶白脚本）
│   ├── poc_v3_attack_chain.py  # v3 优化后攻击链（主力）
│   ├── poc_v3_apply_optimizations.py
│   ├── poc_v4_menu.py          # v4 统一交互菜单（推荐入口）
│   └── poc_scan_fleet.py       # 批量站点扫描器
│
├── reference/                  # 参考脚本（原样保留）
│   ├── reference_easypay_poc_original.py      # 叶白
│   └── reference_auto_register_by_yebai.py    # 叶白（自动注册）
│
├── go-poc/                     # 最小 Go 模块 · v0.2.13（未修复）
├── go-poc-patched/             # 最小 Go 模块 · v0.2.14（已修复）—— 离线复现修复效果
│   ├── cmd/pocserver/main.go   # 真实验签服务端
│   └── internal/payment/       # 从上游原样拷贝
│
├── docs/
│   ├── PATCH_VERIFICATION.md   # ⭐ v0.2.14 修复实测
│   ├── REMEDIATION.md          # 修复方案
│   ├── VERDICT.md              # 完整验证报告
│   └── TIMELINE.md             # 迭代过程
│
└── evidence/                   # 真实验签日志片段
```

**版本演进**：v1（静态分析 + Go 单测 + 纯函数模型）→ v2（真实源码 e2e + 自动注册）
→ v3（参考脚本优化）→ v4（统一菜单 + 批量扫描）

📖 完整迭代记录与踩坑见 **[docs/TIMELINE.md](docs/TIMELINE.md)**

---

## 🔧 修复方案

**一句话**：根因是 `easyPaySign` 不转义。官方已在 v0.2.14 修好，**升级即可**。

| 优先级 | 方案 | 改动 | 状态 |
|---|---|---|---|
| 🔴 立即 | **升级到 v0.2.14** | `docker pull` | ✅ **已发布** |
| — | `CanonicalizeReturnURL` 加 `parsed.RawQuery = ""` | 一行 | ✅ 已采纳 |
| — | `VerifyNotification` 加回调字段白名单 | ~15 行 | ✅ 已采纳 |
| 🟢 可选 | 入账后异步向上游 `api.php` 复核 | 较大 | ⚠️ 尚未 |

> ⚠️ **不要**给签名参数值加转义——会破坏与易支付上游的签名兼容性，导致**所有订单失败**。
> 好消息：官方也没这么做，兼容性保住了。

📖 原理、代码位置、权衡、未采纳项的风险见 **[docs/REMEDIATION.md](docs/REMEDIATION.md)**

---

## 验证补丁是否生效

打完补丁后跑离线自检，三个场景应全部 `NOT_VULNERABLE`：

```bash
cd poc && python3 poc_v4_menu.py    # 选 3
```

真实源码端到端自检（选 4）包含两个**反向对照**——证明「攻击成功确实是因为走私，
而不是因为验签形同虚设」：

- 反向对照 1：垃圾签名必须被拒
- 反向对照 2：干净 `return_url` 的同样伪造必须被拒

---

## 致谢与来源

- **漏洞报告**：[issue #7881](https://github.com/Wei-Shaw/sub2api/issues/7881)
- **自动注册模块**：[`reference/reference_auto_register_by_yebai.py`](reference/reference_auto_register_by_yebai.py)
  —— 来自 **叶白**，本仓库在其基础上扩展了邮件验证码自动获取
- **攻击链参考**：[`reference/reference_easypay_poc_original.py`](reference/reference_easypay_poc_original.py)
  —— 来自 **叶白**，本仓库修复了其中的 Go 语义差异并补充了真实源码自检
- **v1 基线**：[`poc/poc_v1_e2e.py`](poc/poc_v1_e2e.py) —— 本仓库最早版本

`reference/` 下两个脚本**原样保留，一字未改**，用于对照与溯源。

---

## License

MIT
