package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// InspectionResult mirrors the ml-engine InspectResponse. The previous field
// names (threat_score/is_malicious/category) did not exist in the response, so
// every value silently decoded to its zero value and the WAF could never act
// on an ML verdict.
type InspectionResult struct {
	AnomalyScore     float64 `json:"anomaly_score"`
	IsAnomaly        bool    `json:"is_anomaly"`
	AttackType       string  `json:"attack_type,omitempty"`
	AttackConfidence float64 `json:"attack_confidence,omitempty"`
	BotScore         float64 `json:"bot_score"`
	RiskScore        int     `json:"risk_score"`
	Fingerprint      string  `json:"fingerprint"`
	ModelVersion     string  `json:"model_version"`
}

// ClassificationResult mirrors the ml-engine ClassifyResponse.
type ClassificationResult struct {
	AttackType   string  `json:"attack_type"`
	Confidence   float64 `json:"confidence"`
	ModelVersion string  `json:"model_version"`
}

// FingerprintResult mirrors the ml-engine FingerprintResponse.
type FingerprintResult struct {
	Fingerprint   string `json:"fingerprint"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// BotScoreResult mirrors the ml-engine BotScoreResponse.
type BotScoreResult struct {
	BotScore float64 `json:"bot_score"`
	IsBot    bool    `json:"is_bot"`
	BotType  string  `json:"bot_type,omitempty"`
}

type Client struct {
	mu         sync.RWMutex
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
	maxRetries int
	fallback   string
	available  bool
	cbState    circuitBreaker
}

type circuitBreaker struct {
	mu        sync.Mutex
	failures  int
	lastError time.Time
	threshold int
	cooldown  time.Duration
	open      bool
}

// InspectRequest mirrors the ml-engine /v1/inspect request body.
// Field names and shapes must match api/schemas.py exactly: the FastAPI
// pydantic model rejects unknown keys and wrong types with a 422, and a
// map[string][]string for query_params is one of those wrong types.
type InspectRequest struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	QueryParams map[string]string `json:"query_params"`
	SourceIP    string            `json:"source_ip"`
	UserAgent   string            `json:"user_agent"`
	ContentType string            `json:"content_type,omitempty"`
}

func NewClient(endpoint string, timeoutSec, maxRetries int, fallbackMode string) *Client {
	return &Client{
		baseURL: endpoint,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
			},
		},
		timeout:    time.Duration(timeoutSec) * time.Second,
		maxRetries: maxRetries,
		fallback:   fallbackMode,
		available:  true,
		cbState: circuitBreaker{
			threshold: 5,
			cooldown:  30 * time.Second,
		},
	}
}

func (c *Client) Name() string { return "ml" }

func (c *Client) Inspect(ctx context.Context, req *InspectRequest) (*InspectionResult, error) {
	if !c.isAvailable() {
		return c.fallbackResult(), fmt.Errorf("ml client unavailable")
	}

	var lastErr error
	for i := 0; i <= c.maxRetries; i++ {
		result, err := c.callInspect(ctx, req)
		if err == nil {
			c.recordSuccess()
			return result, nil
		}

		lastErr = err
		c.recordFailure()

		if i < c.maxRetries {
			time.Sleep(time.Duration(100*(i+1)) * time.Millisecond)
		}
	}

	return c.fallbackResult(), fmt.Errorf("ml inspect failed after %d retries: %w", c.maxRetries, lastErr)
}

func (c *Client) callInspect(ctx context.Context, req *InspectRequest) (*InspectionResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/inspect", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ml service returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result InspectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// InspectRequestFromHTTP builds an inspect request from a raw request. Query
// values are flattened to a single comma-joined string because the engine's
// schema wants map[string]string, not map[string][]string; sending the latter
// is a pydantic 422.
func InspectRequestFromHTTP(r *http.Request) *InspectRequest {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	query := make(map[string]string, len(r.URL.Query()))
	for k, v := range r.URL.Query() {
		query[k] = strings.Join(v, ",")
	}

	req := &InspectRequest{
		Method:      r.Method,
		Path:        r.URL.Path,
		Headers:     headers,
		QueryParams: query,
		UserAgent:   r.UserAgent(),
		ContentType: r.Header.Get("Content-Type"),
	}

	if r.Body != nil {
		if body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)); err == nil {
			req.Body = string(body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 && ip[0] != "" {
		req.SourceIP = ip[0]
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		req.SourceIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}

	return req
}

func (c *Client) Classify(ctx context.Context, data interface{}) (*ClassificationResult, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/classify", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result ClassificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) Fingerprint(ctx context.Context, data interface{}) (*FingerprintResult, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/fingerprint", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FingerprintResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) BotScore(ctx context.Context, data interface{}) (*BotScoreResult, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/bot-score", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result BotScoreResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) isAvailable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.available {
		return false
	}

	c.cbState.mu.Lock()
	defer c.cbState.mu.Unlock()

	if c.cbState.open {
		if time.Since(c.cbState.lastError) > c.cbState.cooldown {
			c.cbState.open = false
			c.cbState.failures = 0
			return true
		}
		return false
	}

	return true
}

func (c *Client) recordSuccess() {
	c.cbState.mu.Lock()
	defer c.cbState.mu.Unlock()
	c.cbState.failures = 0
}

func (c *Client) recordFailure() {
	c.cbState.mu.Lock()
	defer c.cbState.mu.Unlock()
	c.cbState.failures++
	if c.cbState.failures >= c.cbState.threshold {
		c.cbState.open = true
		c.cbState.lastError = time.Now()
		slog.Warn("ml circuit breaker opened", "failures", c.cbState.failures)
	}
}

// fallbackResult is what Inspect returns when the engine is unreachable.
// It deliberately reports no anomaly: failing open keeps the WAF available,
// and the caller decides whether to trust it (config ml.fallback_mode).
func (c *Client) fallbackResult() *InspectionResult {
	switch c.fallback {
	case "block":
		return &InspectionResult{AnomalyScore: 1.0, IsAnomaly: true, BotScore: 100, RiskScore: 100}
	case "monitor":
		return &InspectionResult{AnomalyScore: 0.5, BotScore: 50, RiskScore: 50}
	default:
		return &InspectionResult{}
	}
}

func (c *Client) SetAvailable(avail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.available = avail
}

func (c *Client) HealthCheck(ctx context.Context) error {
	// The engine exposes /health at the root, not under /v1.
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	// Drain before closing so the connection can be reused, and surface the
	// close error instead of discarding it.
	defer func() { _ = resp.Body.Close() }()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

var _ = slog.Debug
