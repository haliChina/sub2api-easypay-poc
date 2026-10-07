# ⚠️ 这个目录的单测**预期失败**

这里放的是 **v0.2.14 的官方 `easypay.go`**（已修复 issue #7881）。
`easypay_smuggle_poc_test.go` 是针对**未修复**版本写的漏洞复现测试，
所以在这里跑会**故意失败**——这是正确的表现，不是回归。

```bash
cd go-poc-patched && GOTOOLCHAIN=local go test ./internal/payment/provider/
```

期望输出：

```
--- FAIL: TestSmuggleCreateSignatureIntoForgedCallback
    VULNERABLE PATH NOT REPRODUCED — VerifyNotification rejected it:
    unexpected notify param: notify_url
FAIL
```

**看到这行 = 修复生效。** `unexpected notify param` 来自 v0.2.14 新增的
`easyPayNotifyAllowedParams` 白名单。

对照：同样的测试在 `../go-poc/`（v0.2.13 未修复）里是 **4/4 PASS**。

| 目录 | 源码版本 | 单测结果 |
|---|---|---|
| `go-poc/` | v0.2.13（未修复） | ✅ 4/4 PASS |
| `go-poc-patched/` | v0.2.14（已修复） | ❌ 预期失败（白名单拦截） |
