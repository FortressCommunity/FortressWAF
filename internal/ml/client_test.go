package ml

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeMLEngine mimics ml-engine/api/app.py closely enough to catch a contract
// drift: it validates the request the way pydantic does and returns the exact
// InspectResponse shape the real handler produces.
func fakeMLEngine(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"status":"healthy"}`)
			return
		case "/v1/inspect":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// pydantic InspectRequest requires source_ip and rejects anything
			// that is not a Dict[str, str] for query_params.
			if req["source_ip"] == nil || req["source_ip"] == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(w, `{"detail":[{"msg":"field required","loc":["body","source_ip"]}]}`)
				return
			}
			if qp, ok := req["query_params"].(map[string]any); ok {
				for _, v := range qp {
					if _, isStr := v.(string); !isStr {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusUnprocessableEntity)
						io.WriteString(w, `{"detail":[{"msg":"str type expected","loc":["body","query_params"]}]}`)
						return
					}
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			io.WriteString(w, `{"anomaly_score":0.93,"is_anomaly":true,`+
				`"attack_type":"sql-injection","attack_confidence":0.88,`+
				`"bot_score":0.12,"risk_score":87,"fingerprint":"sha256:abc",`+
				`"model_version":"2.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestInspect_ContractMatchesEngine(t *testing.T) {
	srv := fakeMLEngine(t, http.StatusOK)
	defer srv.Close()

	c := NewClient(srv.URL, 5, 2, "allow")
	req := &InspectRequest{
		Method:      "GET",
		Path:        "/search",
		SourceIP:    "192.168.1.10",
		UserAgent:   "Mozilla/5.0",
		QueryParams: map[string]string{"q": "1' OR '1'='1"},
		Headers:     map[string]string{"user-agent": "Mozilla/5.0"},
	}

	res, err := c.Inspect(t.Context(), req)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if res.AnomalyScore != 0.93 {
		t.Errorf("anomaly_score = %v, want 0.93", res.AnomalyScore)
	}
	if !res.IsAnomaly {
		t.Error("is_anomaly should be true for a malicious payload")
	}
	if res.AttackType != "sql-injection" {
		t.Errorf("attack_type = %q, want sql-injection", res.AttackType)
	}
	if res.AttackConfidence != 0.88 {
		t.Errorf("attack_confidence = %v, want 0.88", res.AttackConfidence)
	}
	if res.RiskScore != 87 {
		t.Errorf("risk_score = %v, want 87", res.RiskScore)
	}
	if res.ModelVersion != "2.0.0" {
		t.Errorf("model_version = %q", res.ModelVersion)
	}
}

// The old client sent real_ip and map[string][]string; pydantic answers 422.
func TestInspect_RejectsOldContractShape(t *testing.T) {
	srv := fakeMLEngine(t, http.StatusOK)
	defer srv.Close()

	c := NewClient(srv.URL, 5, 2, "allow")
	bad := map[string]any{
		"method": "GET", "path": "/search",
		"real_ip": "192.168.1.10", // wrong key: schema wants source_ip
	}
	body, _ := json.Marshal(bad)
	httpReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/inspect", strings.NewReader(string(body)))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("old contract should be rejected with 422, got %d", resp.StatusCode)
	}
}

func TestInspect_RequestFromHTTPFlattensQuery(t *testing.T) {
	srv := fakeMLEngine(t, http.StatusOK)
	defer srv.Close()

	raw := httptest.NewRequest(http.MethodGet, "/search?q=1&q=2&sort=asc", nil)
	raw.Header.Set("User-Agent", "Mozilla/5.0")
	raw.Header.Set("X-Forwarded-For", "10.0.0.5, 10.0.0.99")
	raw.RemoteAddr = "192.168.1.10:54321"

	req := InspectRequestFromHTTP(raw)
	if req.SourceIP != "10.0.0.5" {
		t.Errorf("source_ip = %q, want the first X-Forwarded-For hop", req.SourceIP)
	}
	if got := req.QueryParams["q"]; got != "1,2" {
		t.Errorf("query_params[q] = %q, want \"1,2\"", got)
	}
	if req.UserAgent != "Mozilla/5.0" {
		t.Errorf("user_agent = %q", req.UserAgent)
	}

	// The built request must be accepted by the engine.
	c := NewClient(srv.URL, 5, 2, "allow")
	if _, err := c.Inspect(t.Context(), req); err != nil {
		t.Fatalf("inspect of built request: %v", err)
	}
}

func TestInspect_FailsOpenWhenEngineDown(t *testing.T) {
	s := fakeMLEngine(t, http.StatusOK)
	s.Close() // gone on purpose

	c := NewClient(s.URL, 1, 0, "allow")
	res, err := c.Inspect(t.Context(), &InspectRequest{SourceIP: "1.1.1.1"})
	if err == nil {
		t.Fatal("expected an error when the engine is unreachable")
	}
	if res == nil {
		t.Fatal("expected a fallback result, not nil")
	}
	if res.IsAnomaly {
		t.Error("failing open must not report an anomaly")
	}
}

func TestInspect_FailsBlockedWhenConfigured(t *testing.T) {
	s := fakeMLEngine(t, http.StatusOK)
	s.Close()

	c := NewClient(s.URL, 1, 0, "block")
	res, _ := c.Inspect(t.Context(), &InspectRequest{SourceIP: "1.1.1.1"})
	if res == nil || !res.IsAnomaly {
		t.Error("fallback_mode=block should report an anomaly")
	}
}

func TestHealthCheck(t *testing.T) {
	srv := fakeMLEngine(t, http.StatusOK)
	defer srv.Close()

	c := NewClient(srv.URL, 5, 2, "allow")
	if err := c.HealthCheck(t.Context()); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}

	dead := fakeMLEngine(t, http.StatusOK)
	deadClient := NewClient(dead.URL, 5, 2, "allow")
	dead.Close()
	if err := deadClient.HealthCheck(t.Context()); err == nil {
		t.Error("healthcheck against a dead engine should fail")
	}
}

func TestClient_CircuitBreakerOpensOnFailures(t *testing.T) {
	srv := fakeMLEngine(t, http.StatusInternalServerError)
	defer srv.Close()

	c := NewClient(srv.URL, 1, 0, "allow")
	for i := 0; i < 6; i++ {
		if _, err := c.Inspect(t.Context(), &InspectRequest{SourceIP: "1.1.1.1"}); err == nil {
			t.Fatal("expected errors from a 500-returning engine")
		}
	}
	if c.isAvailable() {
		t.Error("circuit breaker should be open after repeated failures")
	}
}

func TestClassify(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"attack_type":"xss","confidence":0.91,"model_version":"2.0.0"}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5, 2, "allow")
	res, err := c.Classify(t.Context(), map[string]any{"payload": "<script>alert(1)</script>"})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if res.AttackType != "xss" || res.Confidence != 0.91 {
		t.Errorf("unexpected classify result: %+v", res)
	}
}

func TestBotScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"bot_score":0.77,"is_bot":true,"bot_type":"scraper"}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5, 2, "allow")
	res, err := c.BotScore(t.Context(), map[string]any{"user_agent": "scrapy"})
	if err != nil {
		t.Fatalf("bot score: %v", err)
	}
	if !res.IsBot || res.BotType != "scraper" {
		t.Errorf("unexpected bot result: %+v", res)
	}
}

var _ = url.QueryEscape
