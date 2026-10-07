# go-poc-patched · v0.2.14（已修复）版

与 `../go-poc/` 完全相同，唯一区别是 `internal/payment/provider/easypay.go`
换成了 **v0.2.14 的官方版本**（issue #7881 的修复补丁）。

用于**离线复现**修复前后的对比：

```bash
# 未修复
cd go-poc && GOTOOLCHAIN=local go build -o /tmp/pv213 ./cmd/pocserver
/tmp/pv213 8902 &
cd ../poc && python3 poc_v3_attack_chain.py --target http://127.0.0.1:8902 \
  --email tester@example.com --password correct-horse --amount 10 --yes --plain
# → 判定结果: VULNERABLE

# 已修复
cd ../go-poc-patched && GOTOOLCHAIN=local go build -o /tmp/pv214 ./cmd/pocserver
/tmp/pv214 8903 &
cd ../poc && python3 poc_v3_attack_chain.py --target http://127.0.0.1:8903 \
  --email tester@example.com --password correct-horse --amount 10 --yes --plain
# → 判定结果: NOT_VULNERABLE  (HTTP 400 verify failed)
```

**唯一变量是源码版本**，PoC 脚本、金额、攻击构造完全相同。
