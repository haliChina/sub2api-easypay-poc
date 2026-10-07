// Command pocserver is a minimal stand-in for sub2api's payment endpoints.
// Order creation and webhook verification use the REAL provider.EasyPay code —
// only auth and the database layer are stubbed.
//
// It exists so a PoC client can be exercised end-to-end against real signature
// verification, instead of against a hand-written reimplementation of the
// signing algorithm (which would only prove the client matches the author's
// own model of the server).
package main

import (
	"context"
	"os"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/Wei-Shaw/sub2api/internal/payment/provider"
)

const (
	pkey      = "REAL_MERCHANT_KEY"
	notifyURL = "https://api.mdkj.lol/api/v1/payment/webhook/easypay"
	resultURL = "https://mdkj.lol/payment/result"
	password  = "correct-horse"
)

type order struct {
	ID          int64
	OutTradeNo  string
	Amount      float64
	PayAmount   float64
	Status      string
	PaymentType string
}

type state struct {
	mu      sync.Mutex
	balance float64
	orders  map[int64]*order
	byNo    map[string]*order
	nextID  int64
	counter int
}

func newState() *state {
	return &state{orders: map[int64]*order{}, byNo: map[string]*order{}, nextID: 63040}
}

func (s *state) newOrder(no string, amt float64, t string) *order {
	o := &order{ID: s.nextID, OutTradeNo: no, Amount: amt, PayAmount: amt,
		Status: "PENDING", PaymentType: t}
	s.orders[o.ID] = o
	s.byNo[no] = o
	s.nextID++
	return o
}

func reply(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(obj)
}

func ok(data any) map[string]any {
	return map[string]any{"code": 0, "message": "success", "data": data}
}

func authed(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer JWT.OK" }

// serviceLayerReturnURL replays what CanonicalizeReturnURL + buildPaymentReturnURL
// do in internal/service/payment_resume_service.go: the user query survives,
// then order_id/out_trade_no/resume_token/status are Set() and Encode() re-sorts.
func serviceLayerReturnURL(userRaw, orderID, outTradeNo, resumeToken string) (string, error) {
	p, err := url.Parse(userRaw)
	if err != nil || !p.IsAbs() || p.Host == "" {
		return "", fmt.Errorf("return_url must be an absolute http/https URL")
	}
	p.Fragment = ""
	if p.Path != "/payment/result" {
		return "", fmt.Errorf("return_url must target the canonical payment result page")
	}
	q := p.Query()
	q.Set("order_id", orderID)
	q.Set("out_trade_no", outTradeNo)
	if resumeToken != "" {
		q.Set("resume_token", resumeToken)
	}
	q.Set("status", "success")
	p.RawQuery = q.Encode()
	return p.String(), nil
}

func main() {
	addr := "127.0.0.1:8900"
	if len(os.Args) > 1 && os.Args[1] != "" {
		addr = "127.0.0.1:" + os.Args[1]
	}
	e, err := provider.NewEasyPay("poc", map[string]string{
		"pid": "A1786553412729", "pkey": pkey, "apiBase": "https://pay.vv22rei.me",
		"notifyUrl": notifyURL, "returnUrl": resultURL, "paymentMode": "popup",
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	st := newState()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct{ Email, Password string }
		_ = json.Unmarshal(b, &in)
		if in.Password != password {
			reply(w, 401, map[string]any{"code": 401, "message": "invalid email or password",
				"reason": "INVALID_CREDENTIALS"})
			return
		}
		reply(w, 200, ok(map[string]any{"access_token": "JWT.OK", "token_type": "Bearer",
			"user": map[string]any{"email": in.Email}}))
	})

	mux.HandleFunc("/api/v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct {
			Email, Password, VerifyCode, InvitationCode string
		}
		_ = json.Unmarshal(b, &in)
		if in.Password == "" || len(in.Password) < 8 {
			reply(w, 400, map[string]any{"code": 400, "message": "password too short"})
			return
		}
		if in.Email == "" {
			reply(w, 400, map[string]any{"code": 400, "message": "email is required"})
			return
		}
		fmt.Printf("[register] %s password=%s verify_code=%q\n", in.Email, in.Password, in.VerifyCode)
		reply(w, 200, ok(map[string]any{"access_token": "JWT.OK", "token_type": "Bearer",
			"user": map[string]any{"email": in.Email}}))
	})

	mux.HandleFunc("/api/v1/auth/send-verify-code", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct{ Email string }
		_ = json.Unmarshal(b, &in)
		fmt.Printf("[send-verify-code] %s\n", in.Email)
		reply(w, 200, ok(map[string]any{"message": "verification code sent",
			"expires_in": 600, "interval": 60}))
	})

	mux.HandleFunc("/api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			reply(w, 401, map[string]any{"code": 401, "message": "unauthorized"})
			return
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		reply(w, 200, ok(map[string]any{"email": "tester@example.com", "balance": st.balance}))
	})

	mux.HandleFunc("/api/v1/payment/checkout-info", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, ok(map[string]any{
			"methods":    map[string]any{"alipay": map[string]any{}, "wxpay": map[string]any{}},
			"plans":      []any{},
			"global_min": 1.0, "global_max": 10000.0,
		}))
	})

	mux.HandleFunc("/api/v1/payment/orders", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			reply(w, 401, map[string]any{"code": 401, "message": "unauthorized"})
			return
		}
		b, _ := io.ReadAll(r.Body)
		var in struct {
			Amount      float64 `json:"amount"`
			PaymentType string  `json:"payment_type"`
			ReturnURL   string  `json:"return_url"`
			IsMobile    *bool   `json:"is_mobile"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			reply(w, 400, map[string]any{"code": 400, "message": err.Error()})
			return
		}
		mobile := false
		if in.IsMobile != nil {
			mobile = *in.IsMobile
		}
		st.mu.Lock()
		st.counter++
		out := "sub2_TEST" + strconv.Itoa(1000+st.counter)
		o := st.newOrder(out, in.Amount, in.PaymentType)
		st.mu.Unlock()

		providerReturn, err := serviceLayerReturnURL(in.ReturnURL,
			strconv.FormatInt(o.ID, 10), out, "RESUME.JWT.token")
		if err != nil {
			reply(w, 400, map[string]any{"code": 400, "message": err.Error(),
				"reason": "INVALID_RETURN_URL"})
			return
		}
		money := fmt.Sprintf("%.2f", in.Amount)
		resp, err := e.CreatePayment(ctx, payment.CreatePaymentRequest{
			OrderID: out, Amount: money, PaymentType: in.PaymentType,
			Subject: "Sub2API " + money + " CNY", NotifyURL: notifyURL,
			ReturnURL: providerReturn, IsMobile: mobile, ClientIP: "203.0.113.7",
		})
		if err != nil {
			reply(w, 500, map[string]any{"code": 500, "message": err.Error()})
			return
		}
		reply(w, 200, ok(map[string]any{"order_id": o.ID, "out_trade_no": out,
			"amount": in.Amount, "pay_amount": money, "status": "PENDING",
			"payment_type": in.PaymentType, "payment_mode": "popup", "pay_url": resp.PayURL}))
	})

	mux.HandleFunc("/api/v1/payment/orders/my", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		items := []map[string]any{}
		for _, o := range st.orders {
			items = append(items, map[string]any{"id": o.ID, "out_trade_no": o.OutTradeNo,
				"status": o.Status, "amount": o.Amount})
		}
		reply(w, 200, ok(map[string]any{"items": items, "total": len(items),
			"page": 1, "page_size": 50, "pages": 1}))
	})

	mux.HandleFunc("/api/v1/payment/orders/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			reply(w, 401, map[string]any{"code": 401, "message": "unauthorized"})
			return
		}
		var id int64
		for _, seg := range strings.Split(r.URL.Path, "/") {
			if seg != "" && seg != "orders" && seg != "cancel" {
				id, _ = strconv.ParseInt(seg, 10, 64)
			}
		}
		st.mu.Lock()
		if o, ok := st.orders[id]; ok {
			o.Status = "CANCELLED"
		}
		st.mu.Unlock()
		reply(w, 200, ok(map[string]any{}))
	})

	// Mirrors PaymentWebhookHandler.handleNotify: GET takes the raw query string,
	// POST takes the body, then the provider verifies it. On success we apply the
	// same amount/status checks confirmPayment does before crediting.
	mux.HandleFunc("/api/v1/payment/webhook/easypay", func(w http.ResponseWriter, r *http.Request) {
		var raw string
		if r.Method == http.MethodGet {
			raw = r.URL.RawQuery
		} else {
			b, _ := io.ReadAll(r.Body)
			raw = string(b)
		}
		fmt.Printf("\n[webhook] %s raw=%s\n", r.Method, raw)

		n, err := e.VerifyNotification(ctx, raw, nil)
		if err != nil {
			fmt.Printf("[webhook] VERIFY FAILED: %v\n", err)
			w.WriteHeader(400)
			_, _ = io.WriteString(w, "verify failed")
			return
		}
		st.mu.Lock()
		o := st.byNo[n.OrderID]
		credited := false
		if o != nil && n.Status == "success" && n.Amount == o.PayAmount && o.Status != "PAID" {
			o.Status = "PAID"
			st.balance += o.Amount
			credited = true
		}
		bal := st.balance
		st.mu.Unlock()
		fmt.Printf("[webhook] ACCEPTED order=%s status=%s amount=%.2f credited=%v balance=%.2f\n",
			n.OrderID, n.Status, n.Amount, credited, bal)
		reply(w, 200, ok(map[string]any{"credited": credited, "order": n.OrderID,
			"amount": n.Amount, "balance": bal}))
	})

	mux.HandleFunc("/api/v1/payment/public/orders/verify", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var in struct{ OutTradeNo string }
		_ = json.Unmarshal(b, &in)
		st.mu.Lock()
		defer st.mu.Unlock()
		o := st.byNo[in.OutTradeNo]
		if o == nil {
			reply(w, 200, ok(map[string]any{"out_trade_no": in.OutTradeNo}))
			return
		}
		reply(w, 200, ok(map[string]any{"out_trade_no": o.OutTradeNo, "status": o.Status,
			"paid": o.Status == "PAID", "balance": st.balance}))
	})

	log.Printf("pocserver (REAL easypay.go) listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}