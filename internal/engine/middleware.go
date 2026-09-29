package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type CAPTCHAVerifier struct {
	enabled  bool
	provider string
	secret   string
	siteKey  string
	score    float64
	client   *http.Client
}

func NewCAPTCHAVerifier(provider, secret, siteKey string, score float64) *CAPTCHAVerifier {
	return &CAPTCHAVerifier{
		enabled:  true,
		provider: provider,
		secret:   secret,
		siteKey:  siteKey,
		score:    score,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (cv *CAPTCHAVerifier) Name() string { return "captcha" }

func (cv *CAPTCHAVerifier) Inspect(ctx *RequestContext) (*Decision, error) {
	if !cv.enabled {
		return nil, nil
	}
	token := ctx.Request.Header.Get("X-CAPTCHA-Token")
	if token == "" {
		token = ctx.Request.Header.Get("X-Recaptcha-Token")
	}
	if token == "" {
		return nil, nil
	}
	ok, score, err := cv.verify(token)
	if err != nil {
		return nil, fmt.Errorf("captcha verify: %w", err)
	}
	if !ok {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CAPTCHA001",
			RuleName: "CAPTCHA Verification Failed",
			Severity: "low",
			Score:    30,
			Evidence: fmt.Sprintf("CAPTCHA score %f below threshold %f", score, cv.score),
		}, nil
	}
	return nil, nil
}

func (cv *CAPTCHAVerifier) verify(token string) (bool, float64, error) {
	switch cv.provider {
	case "recaptcha":
		return cv.verifyRecaptcha(token)
	case "hcaptcha":
		return cv.verifyHCaptcha(token)
	default:
		return false, 0, fmt.Errorf("unsupported captcha provider: %s", cv.provider)
	}
}

func (cv *CAPTCHAVerifier) verifyRecaptcha(token string) (bool, float64, error) {
	data := url.Values{
		"secret":   {cv.secret},
		"response": {token},
	}
	resp, err := cv.client.PostForm("https://www.google.com/recaptcha/api/siteverify", data)
	if err != nil {
		return false, 0, fmt.Errorf("recaptcha verify: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0, fmt.Errorf("recaptcha decode: %w", err)
	}
	return result.Success && result.Score >= cv.score, result.Score, nil
}

func (cv *CAPTCHAVerifier) verifyHCaptcha(token string) (bool, float64, error) {
	data := url.Values{
		"secret":   {cv.secret},
		"response": {token},
	}
	resp, err := cv.client.PostForm("https://hcaptcha.com/siteverify", data)
	if err != nil {
		return false, 0, fmt.Errorf("hcaptcha verify: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, 0, fmt.Errorf("hcaptcha decode: %w", err)
	}
	return result.Success && result.Score >= cv.score, result.Score, nil
}

// ResponseWriter buffers the origin response so it can be inspected before any
// byte reaches the client. Deferring the write is what makes leak-blocking
// possible: once a body has been streamed, a leak can no longer be stopped.
//
// It buffers up to bufCap bytes. If the body is larger, the buffered prefix is
// flushed and the remainder streamed through unchanged -- a multi-megabyte
// download must not be held in memory, and secrets worth catching appear in the
// first buffer anyway.
type ResponseWriter struct {
	http.ResponseWriter
	StatusCode  int
	Body        []byte
	InspectBody bool

	bufCap     int
	headerDone bool   // headers committed to the client
	flushed    bool   // buffered prefix already written
	blocked    bool   // caller discarded the response in favour of a block page
	pending    []byte // bytes received after the buffer filled, not yet written
}

// NewResponseWriter wraps w. When inspectBody is true, up to bufCap bytes of
// the response are buffered until Commit or Discard is called.
func NewResponseWriter(w http.ResponseWriter, inspectBody bool, bufCap int) *ResponseWriter {
	if bufCap <= 0 {
		bufCap = 1 << 20 // 1 MiB
	}
	return &ResponseWriter{
		ResponseWriter: w,
		StatusCode:     http.StatusOK,
		InspectBody:    inspectBody,
		bufCap:         bufCap,
	}
}

func (rw *ResponseWriter) WriteHeader(code int) {
	rw.StatusCode = code
	// Headers are held back until Commit; writing them now would commit the
	// status before the body has been inspected.
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if rw.blocked {
		return len(b), nil
	}
	if !rw.InspectBody {
		return rw.ResponseWriter.Write(b)
	}
	if len(rw.Body) < rw.bufCap {
		room := rw.bufCap - len(rw.Body)
		if room >= len(b) {
			rw.Body = append(rw.Body, b...)
			return len(b), nil
		}
		rw.Body = append(rw.Body, b[:room]...)
		rw.pending = append(rw.pending, b[room:]...)
		// Buffer is full: flush the prefix and stream the rest. Only the first
		// bufCap bytes are inspected from here on.
		rw.commitHeaders()
		if _, err := rw.ResponseWriter.Write(rw.Body); err != nil {
			return len(b), err
		}
		rw.flushed = true
		if len(rw.pending) > 0 {
			n, err := rw.ResponseWriter.Write(rw.pending)
			rw.pending = nil
			// Report the full input as written so the caller does not treat a
			// successful flush as a short write.
			_ = n
			return len(b), err
		}
		return len(b), nil
	}
	rw.commitHeaders()
	return rw.ResponseWriter.Write(b)
}

func (rw *ResponseWriter) commitHeaders() {
	if rw.headerDone {
		return
	}
	rw.headerDone = true
	rw.ResponseWriter.WriteHeader(rw.StatusCode)
}

// Flush commits whatever has been buffered and forwards to the wrapped writer.
// Streaming responses (SSE, chunked) use this; once flushed, later bytes are no
// longer inspected but are still forwarded.
func (rw *ResponseWriter) Flush() {
	if rw.blocked {
		return
	}
	rw.commitHeaders()
	if len(rw.Body) > 0 && !rw.flushed {
		_, _ = rw.ResponseWriter.Write(rw.Body)
		rw.flushed = true
	}
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Commit writes the buffered response through to the client. Call it when
// inspection found nothing to block.
func (rw *ResponseWriter) Commit() {
	if rw.blocked {
		return
	}
	rw.commitHeaders()
	if !rw.flushed {
		_, _ = rw.ResponseWriter.Write(rw.Body)
		rw.flushed = true
	}
}

// Discard drops the buffered origin response and marks the writer blocked so
// the caller can safely write its own reply to the underlying writer without
// the buffered body leaking through. Origin-set entity headers (Content-Length,
// Content-Type, Content-Encoding, ...) are cleared first: the replacement reply
// has a different length, and leaving the origin's Content-Length in place makes
// the client's framing mismatch. Returns the underlying writer.
func (rw *ResponseWriter) Discard() http.ResponseWriter {
	rw.blocked = true
	rw.Body = nil
	rw.pending = nil
	h := rw.Header()
	for _, k := range []string{
		"Content-Length", "Content-Type", "Content-Encoding",
		"Content-Range", "Content-Disposition", "ETag", "Last-Modified",
		"Cache-Control", "Set-Cookie", "Transfer-Encoding",
	} {
		h.Del(k)
	}
	return rw.ResponseWriter
}

// NewResponseInspector preserves the original constructor name used by
// cmd/proxy. It returns a response-body leak inspector that detects but does
// not block (monitor mode) with a 1 MiB scan window; call
// NewResponseLeakInspector directly to enable blocking or a custom window.
func NewResponseInspector() *ResponseLeakInspector {
	return NewResponseLeakInspector(true, false, 1<<20)
}

type SOAPValidator struct {
	enabled      bool
	strictSchema bool
	maxDepth     int
}

func NewSOAPValidator(strictSchema bool, maxDepth int) *SOAPValidator {
	if maxDepth <= 0 {
		maxDepth = 10
	}
	return &SOAPValidator{enabled: true, strictSchema: strictSchema, maxDepth: maxDepth}
}

func (sv *SOAPValidator) Name() string { return "soap" }

func (sv *SOAPValidator) Inspect(ctx *RequestContext) (*Decision, error) {
	if !sv.enabled {
		return nil, nil
	}
	if ctx.ContentType != "text/xml" && ctx.ContentType != "application/soap+xml" {
		return nil, nil
	}
	depth := 0
	openTags := 0
	for _, b := range ctx.Body {
		if b == '<' {
			openTags++
			depth++
			if depth > sv.maxDepth {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "SOAP001",
					RuleName: "SOAP/XML Depth Exceeded",
					Severity: "medium",
					Score:    50,
					Evidence: fmt.Sprintf("XML nesting depth exceeded max of %d", sv.maxDepth),
				}, nil
			}
		}
		if b == '>' {
			openTags--
			if openTags < 0 {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "SOAP002",
					RuleName: "Malformed XML",
					Severity: "medium",
					Score:    50,
					Evidence: "unexpected closing tag",
				}, nil
			}
		}
	}
	return nil, nil
}

type GRPCInspector struct {
	enabled    bool
	maxMsgSize int
	rateLimit  int
	counters   map[string]*grpcCounter
	mu         sync.Mutex
}

type grpcCounter struct {
	count     int
	resetTime time.Time
}

func NewGRPCInspector(maxMsgSize, rateLimit int) *GRPCInspector {
	if maxMsgSize <= 0 {
		maxMsgSize = 4 * 1024 * 1024
	}
	if rateLimit <= 0 {
		rateLimit = 100
	}
	return &GRPCInspector{
		enabled:    true,
		maxMsgSize: maxMsgSize,
		rateLimit:  rateLimit,
		counters:   make(map[string]*grpcCounter),
	}
}

func (gi *GRPCInspector) Name() string { return "grpc" }

func (gi *GRPCInspector) Inspect(ctx *RequestContext) (*Decision, error) {
	if !gi.enabled {
		return nil, nil
	}
	if !strings.HasPrefix(ctx.ContentType, "application/grpc") {
		return nil, nil
	}

	service := ctx.Path
	gi.mu.Lock()
	defer gi.mu.Unlock()

	now := time.Now()
	counter, exists := gi.counters[service]
	if !exists || now.Sub(counter.resetTime) > time.Minute {
		gi.counters[service] = &grpcCounter{count: 1, resetTime: now}
		return nil, nil
	}

	counter.count++
	if counter.count > gi.rateLimit {
		return &Decision{
			Action:   ActionRateLimit,
			RuleID:   "GRPC001",
			RuleName: "gRPC Rate Limit",
			Severity: "medium",
			Score:    60,
			Evidence: fmt.Sprintf("gRPC %s exceeded rate limit of %d req/min", service, gi.rateLimit),
		}, nil
	}

	if ctx.Request != nil && ctx.Request.ContentLength > int64(gi.maxMsgSize) {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "GRPC002",
			RuleName: "gRPC Message Too Large",
			Severity: "medium",
			Score:    40,
			Evidence: fmt.Sprintf("gRPC message size %d exceeds max %d", ctx.Request.ContentLength, gi.maxMsgSize),
		}, nil
	}

	return nil, nil
}
