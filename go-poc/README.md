# go-poc · v0.2.13（未修复）

最小 Go 模块，让 **未修改**的上游 `easypay.go` 能在本地编译并提供真实验签服务。

## 版权

`internal/payment/` 下的 5 个 `.go` 文件是
[Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) **v0.2.13** 的
**逐字节原样拷贝**（sha256 校验，本仓库未作任何修改）。

**协议：LGPL-3.0**。版权归 Wei-Shaw 及其贡献者所有。
本仓库与上游无隶属或合作关系。详见仓库根目录的 [NOTICE](../NOTICE)。

`go.mod` 声明 `github.com/Wei-Shaw/sub2api` 作为 module path，
**仅用于让上游源码在其原有 import 路径下原样编译**，
不代表本仓库是该 module 的分发方。

## 本仓库原创部分

- `cmd/pocserver/main.go` —— pocserver 桩服务（唯一非上游文件）
- `internal/payment/provider/easypay_smuggle_poc_test.go` —— 漏洞复现单测

## 用法

```bash
GOTOOLCHAIN=local go build -o /tmp/poc213 ./cmd/pocserver
/tmp/poc213 8900 &
```

预期单测结果 **4/4 PASS**（漏洞存在）：
```bash
GOTOOLCHAIN=local go test ./internal/payment/provider/
```

对照修复版见 `../go-poc-patched/`（单测**预期失败**）。
