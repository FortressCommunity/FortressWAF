package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Action represents the enforcement action to take for a request.
type Action string

const (
	ActionBlock     Action = "block"      // BlockAction blocks the request immediately.
	ActionAllow     Action = "allow"      // ActionAllow permits the request to proceed.
	ActionChallenge Action = "challenge"  // ActionChallenge requires browser challenge verification.
	ActionMonitor   Action = "monitor"    // ActionMonitor logs the event without blocking.
	ActionRateLimit Action = "rate_limit" // ActionRateLimit applies rate limiting to the request.
)

// Decision is the result of inspecting a request, containing the action, rule match details, and score.
type Decision struct {
	Action          Action  `json:"action"`
	RuleID          string  `json:"rule_id"`
	RuleName        string  `json:"rule_name"`
	Severity        string  `json:"severity"`
	Score           float64 `json:"score"`
	Evidence        string  `json:"evidence"`
	Blocked         bool    `json:"blocked"`
	ConfidenceScore float64 `json:"confidence_score,omitempty"`
	Explainability  string  `json:"explainability,omitempty"`
	InspectorName   string  `json:"inspector_name,omitempty"`
}

// RequestContext holds all request-derived data and inspection state for a single request.
type RequestContext struct {
	mu             sync.RWMutex
	Request        *http.Request
	Response       *http.Response
	Site           string
	RealIP         string
	UserAgent      string
	Path           string
	Method         string
	Headers        map[string]string
	Cookies        map[string]string
	QueryParams    map[string][]string
	FormParams     map[string][]string
	Body           []byte
	ContentType    string
	SessionID      string
	UserID         string
	APIKey         string
	Country        string
	ASN            uint
	BotScore       float64
	ThreatScore    float64
	Decisions      []Decision
	IsBot          bool
	IsKnownAttack  bool
	StartedAt      time.Time
	RequestID      string
	Context        context.Context
	Host           string
	TLSVersion     string
	TLSCipherSuite string
	JA3Hash        string
}

// ResponseContext holds response-level information for post-response inspection.
type ResponseContext struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Request    *RequestContext
}

// queryValues parses a raw query string, tolerating characters Go's strict
// parser rejects. It splits on '&' only, decodes each key and value with
// QueryUnescape, and skips malformed pairs rather than failing the whole
// query.
func queryValues(rawQuery string) url.Values {
	values := make(url.Values)
	if rawQuery == "" {
		return values
	}

	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}

		key, value, found := strings.Cut(pair, "=")
		if !found {
			value = ""
		}

		k, err := url.QueryUnescape(key)
		if err != nil {
			continue
		}
		v, err := url.QueryUnescape(value)
		if err != nil {
			continue
		}
		values.Add(k, v)
	}

	return values
}

// NewRequestContext resolves the client address without the Engine's
// trusted-proxy list; use Engine.ClientIP when the allow list has been
// configured. Client-supplied forwarded headers are never honoured here.
func NewRequestContext(r *http.Request) *RequestContext {
	realIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		realIP = r.RemoteAddr
	}

	ctx := &RequestContext{
		Request:     r,
		Context:     r.Context(),
		RealIP:      realIP,
		UserAgent:   r.UserAgent(),
		Path:        r.URL.Path,
		Method:      r.Method,
		Host:        r.Host,
		Headers:     make(map[string]string),
		Cookies:     make(map[string]string),
		QueryParams: make(map[string][]string),
		FormParams:  make(map[string][]string),
		StartedAt:   time.Now(),
		RequestID:   fmt.Sprintf("%x", time.Now().UnixNano()),
	}

	for k, v := range r.Header {
		ctx.Headers[k] = v[0]
	}

	for _, c := range r.Cookies() {
		ctx.Cookies[c.Name] = c.Value
	}

	// Go's url.Query rejects the entire query string when a raw ';' appears
	// in it ("invalid semicolon separator"), returning no parameters at all.
	// That would let any payload containing a bare semicolon -- ";id",
	// "1;DROP TABLE users" -- sail past every inspector. Fall back to a
	// lenient split on '&' that treats ';' as ordinary data.
	qp := queryValues(r.URL.RawQuery)
	for k, v := range qp {
		ctx.QueryParams[k] = v
	}

	ctx.ContentType = r.Header.Get("Content-Type")

	// Read request body so inspectors can inspect it
	if r.Body != nil {
		const maxBodySize = 10 << 20 // 10MB
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
		if err == nil {
			if len(body) > maxBodySize {
				ctx.Body = body[:maxBodySize]
			} else {
				ctx.Body = body
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	return ctx
}

type Inspector interface {
	Name() string
	Inspect(ctx *RequestContext) (*Decision, error)
}

type Engine struct {
	mu           sync.RWMutex
	inspectors   []Inspector
	bot          Inspector
	ddos         Inspector
	sqli         Inspector
	xss          Inspector
	apiProtect   Inspector
	rce          Inspector
	protocol     Inspector
	upload       Inspector
	credential   Inspector
	jwt          Inspector
	oauth        Inspector
	graphql      Inspector
	mtls         Inspector
	websocket    Inspector
	captcha      Inspector
	soap         Inspector
	grpc         Inspector
	respInspect  Inspector
	ja3          Inspector
	behavioral   Inspector
	wasm         Inspector
	desync       Inspector
	adaptive     Inspector
	ebpf         Inspector
	parser       Inspector
	devMode      bool
	shadowMode   bool
	learningMode bool
	perfMgmt     *PerformanceManager
	learner      *LearningEngine
	confScorer   *ConfidenceScorer
	proxies      trustedProxy
}

// EngineConfig configures which inspectors the Engine should use.
type EngineConfig struct {
	DevMode              bool
	ShadowMode           bool
	LearningMode         bool
	MaxRegexDuration     int64
	MaxWASMDuration      int64
	PerformanceIsolation bool

	Bot         Inspector
	DDoS        Inspector
	SQLI        Inspector
	XSS         Inspector
	APIProtect  Inspector
	RCE         Inspector
	Protocol    Inspector
	Upload      Inspector
	Credential  Inspector
	JWT         Inspector
	OAuth       Inspector
	GraphQL     Inspector
	MTLS        Inspector
	WebSocket   Inspector
	CAPTCHA     Inspector
	SOAP        Inspector
	GRPC        Inspector
	RespInspect Inspector
	JA3         Inspector
	Behavioral  Inspector
	WASM        Inspector
	Desync      Inspector
	Adaptive    Inspector
	EBPF        Inspector
	Parser      Inspector
}

func New(cfg EngineConfig) *Engine {
	e := &Engine{
		devMode:      cfg.DevMode,
		shadowMode:   cfg.ShadowMode,
		learningMode: cfg.LearningMode,
		bot:          cfg.Bot,
		ddos:         cfg.DDoS,
		sqli:         cfg.SQLI,
		xss:          cfg.XSS,
		apiProtect:   cfg.APIProtect,
		rce:          cfg.RCE,
		protocol:     cfg.Protocol,
		upload:       cfg.Upload,
		credential:   cfg.Credential,
		jwt:          cfg.JWT,
		oauth:        cfg.OAuth,
		graphql:      cfg.GraphQL,
		mtls:         cfg.MTLS,
		websocket:    cfg.WebSocket,
		captcha:      cfg.CAPTCHA,
		soap:         cfg.SOAP,
		grpc:         cfg.GRPC,
		respInspect:  cfg.RespInspect,
		ja3:          cfg.JA3,
		behavioral:   cfg.Behavioral,
		wasm:         cfg.WASM,
		desync:       cfg.Desync,
		adaptive:     cfg.Adaptive,
		ebpf:         cfg.EBPF,
		parser:       cfg.Parser,
	}

	if cfg.PerformanceIsolation {
		e.perfMgmt = NewPerformanceManager(
			cfg.MaxRegexDuration,
			cfg.MaxWASMDuration,
		)
	}

	e.confScorer = NewConfidenceScorer()
	e.learner = NewLearningEngine()

	e.inspectors = []Inspector{
		cfg.Parser,
		cfg.Desync,
		cfg.JA3,
		cfg.Behavioral,
		cfg.Adaptive,
		cfg.WASM,
		cfg.CAPTCHA,
		cfg.JWT,
		cfg.OAuth,
		cfg.MTLS,
		cfg.GraphQL,
		cfg.GRPC,
		cfg.SOAP,
		cfg.Bot,
		cfg.DDoS,
		cfg.SQLI,
		cfg.XSS,
		cfg.APIProtect,
		cfg.RCE,
		cfg.Protocol,
		cfg.Upload,
		cfg.Credential,
		cfg.WebSocket,
		cfg.RespInspect,
		cfg.EBPF,
	}

	return e
}

func (e *Engine) Inspect(ctx *RequestContext) (*Decision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.devMode {
		slog.Debug("inspecting request",
			"method", ctx.Method,
			"path", ctx.Path,
			"ip", ctx.RealIP,
			"ua", ctx.UserAgent,
		)
	}

	for _, inspector := range e.inspectors {
		if inspector == nil {
			continue
		}

		var dec *Decision
		var err error

		if e.perfMgmt != nil {
			dec, err = e.perfMgmt.Inspect(inspector, ctx)
		} else {
			dec, err = inspector.Inspect(ctx)
		}

		if err != nil {
			slog.Error("inspector error",
				"inspector", inspector.Name(),
				"error", err,
				"request_id", ctx.RequestID,
			)
			continue
		}

		if dec == nil {
			continue
		}

		dec.InspectorName = inspector.Name()

		if e.confScorer != nil {
			e.confScorer.ScoreDecision(dec)
		}

		if e.learningMode && e.learner != nil {
			e.learner.Record(inspector.Name(), ctx, dec)
		}

		e.enrichExplainability(ctx, dec)

		ctx.mu.Lock()
		ctx.Decisions = append(ctx.Decisions, *dec)
		ctx.ThreatScore += dec.Score
		if dec.Action == ActionBlock {
			ctx.IsKnownAttack = true
			ctx.BotScore = dec.Score
		}
		ctx.mu.Unlock()

		if e.devMode {
			slog.Debug("inspection decision",
				"inspector", inspector.Name(),
				"action", dec.Action,
				"rule_id", dec.RuleID,
				"score", dec.Score,
				"evidence", dec.Evidence,
				"request_id", ctx.RequestID,
			)
		}

		if dec.Action == ActionBlock {
			if e.shadowMode {
				dec.Action = ActionMonitor
				dec.Blocked = false
				slog.Info("shadow mode: would have blocked",
					"rule_id", dec.RuleID,
					"score", dec.Score,
					"request_id", ctx.RequestID,
				)
				continue
			}
			return dec, nil
		}
	}

	return e.finalDecision(ctx), nil
}

func (e *Engine) enrichExplainability(ctx *RequestContext, dec *Decision) {
	if dec.Explainability != "" {
		return
	}
	switch {
	case dec.Action == ActionBlock && dec.Score >= 90:
		dec.Explainability = "Critical threat detected with high confidence. Immediate blocking required."
	case dec.Action == ActionBlock:
		dec.Explainability = "Request matched blocking rule pattern with sufficient certainty."
	case dec.Action == ActionChallenge:
		dec.Explainability = "Request exhibits suspicious characteristics requiring additional verification."
	case dec.Action == ActionMonitor:
		dec.Explainability = "Request flagged for observation. No action taken."
	case dec.Action == ActionRateLimit:
		dec.Explainability = "Request rate exceeds configured threshold for this endpoint."
	default:
		dec.Explainability = "No actionable threat detected."
	}
	if e.learningMode && e.learner != nil && dec.Action == ActionAllow {
		bsl := e.learner.Baseline(ctx.Path)
		if bsl != nil {
			dec.Explainability = fmt.Sprintf("Request matches learned baseline for %s (mean=%.2f, std=%.2f)",
				ctx.Path, bsl.meanRate, bsl.stdDev)
		}
	}
}

func (e *Engine) finalDecision(ctx *RequestContext) *Decision {
	ctx.mu.RLock()
	score := ctx.ThreatScore
	ctx.mu.RUnlock()

	if score >= 90 {
		return &Decision{Action: ActionBlock, Score: score, Evidence: "cumulative threat score exceeded threshold"}
	}
	if score >= 50 {
		return &Decision{Action: ActionChallenge, Score: score, Evidence: "elevated threat score requires challenge"}
	}

	ctx.mu.RLock()
	for _, d := range ctx.Decisions {
		if d.Action == ActionRateLimit {
			ctx.mu.RUnlock()
			return &Decision{Action: ActionRateLimit, Score: score, Evidence: "rate limit exceeded"}
		}
	}
	ctx.mu.RUnlock()

	return &Decision{Action: ActionAllow, Score: 0}
}

func (e *Engine) InspectRequest(r *http.Request) (*Decision, error) {
	ctx := e.ContextFromRequest(r)

	if e.devMode {
		slog.Debug("request context created",
			"request_id", ctx.RequestID,
			"real_ip", ctx.RealIP,
		)
	}

	return e.Inspect(ctx)
}

func (e *Engine) InspectContext(ctx context.Context, r *http.Request) (*Decision, error) {
	rc := e.ContextFromRequest(r)
	rc.Context = ctx
	return e.Inspect(rc)
}

func (e *Engine) UpdateInspector(name string, inspector Inspector) {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch name {
	case "bot":
		e.bot = inspector
	case "ddos":
		e.ddos = inspector
	case "sqli":
		e.sqli = inspector
	case "xss":
		e.xss = inspector
	case "api_protect":
		e.apiProtect = inspector
	case "rce":
		e.rce = inspector
	case "protocol":
		e.protocol = inspector
	case "upload":
		e.upload = inspector
	case "credential":
		e.credential = inspector
	case "jwt":
		e.jwt = inspector
	case "oauth":
		e.oauth = inspector
	case "graphql":
		e.graphql = inspector
	case "mtls":
		e.mtls = inspector
	case "websocket":
		e.websocket = inspector
	case "captcha":
		e.captcha = inspector
	case "soap":
		e.soap = inspector
	case "grpc":
		e.grpc = inspector
	case "response_inspect":
		e.respInspect = inspector
	case "ja3":
		e.ja3 = inspector
	case "behavioral":
		e.behavioral = inspector
	case "wasm":
		e.wasm = inspector
	case "desync":
		e.desync = inspector
	case "adaptive":
		e.adaptive = inspector
	case "ebpf":
		e.ebpf = inspector
	case "parser_hardener":
		e.parser = inspector
	}

	for i, ins := range e.inspectors {
		if ins != nil && ins.Name() == name {
			e.inspectors[i] = inspector
			return
		}
	}
}

func (e *Engine) Inspectors() []Inspector {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]Inspector, len(e.inspectors))
	copy(result, e.inspectors)
	return result
}

// ContextFromRequest builds a RequestContext using the Engine's trusted-proxy
// configuration, so deployments behind a reverse proxy still see the real
// client while edge deployments ignore spoofed forwarded headers.
func (e *Engine) ContextFromRequest(r *http.Request) *RequestContext {
	ctx := NewRequestContext(r)
	ctx.RealIP = e.ClientIP(r)
	return ctx
}

// SetTrustedProxies configures which peer CIDRs may set forwarding headers.
// Invalid CIDRs are returned so the caller can surface the misconfiguration.
func (e *Engine) SetTrustedProxies(cidrs []string) []string {
	e.proxies.SetTrustedProxies(cidrs)
	return ParseTrustedProxies(cidrs)
}
