package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Response body inspection: detect secrets and sensitive data leaving the
// origin. This is the "data leakage" half of a WAF's job -- the request side
// catches attackers coming in, this side catches the application leaking
// credentials, keys, and personal data out.
//
// Scope is deliberately narrow and precise. Every rule here matches a value
// with a distinctive, low-false-positive shape (a key prefix, a fixed-length
// hash, a PEM header). Prose that merely contains the word "password" must not
// match; the tests assert exactly that.

// leakRule is a single response-body detection rule.
type leakRule struct {
	ID       string
	Name     string
	Severity string
	Score    float64
	Regex    *regexp.Regexp
	// Redact replaces the matched substring in evidence so the WAF's own logs
	// and dashboard never store the leaked secret. Nil means "mask the whole
	// match".
	Redact func(match string) string
}

// maskTail keeps at most the last 4 characters of a value so an operator can
// correlate an incident without the log itself becoming a credential store.
func maskTail(match string) string {
	if len(match) <= 4 {
		return "****"
	}
	return "****" + match[len(match)-4:]
}

// responseLeakRules is the compiled ruleset. Kept package-level so the regexes
// are compiled once, not per request.
var responseLeakRules = []leakRule{
	{
		ID:       "LEAK-001",
		Name:     "Private key material in response",
		Severity: "critical",
		Score:    95,
		Regex:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		ID:       "LEAK-002",
		Name:     "AWS access key ID in response",
		Severity: "critical",
		Score:    90,
		Regex:    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Redact:   maskTail,
	},
	{
		ID:       "LEAK-003",
		Name:     "JSON Web Token in response",
		Severity: "high",
		Score:    80,
		// header.payload.signature, each base64url; requires the eyJ prefix of a
		// base64url-encoded JSON object so ordinary dotted identifiers don't match.
		Regex:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		Redact: maskTail,
	},
	{
		ID:       "LEAK-004",
		Name:     "Generic API key or secret token in response",
		Severity: "high",
		Score:    75,
		// Known provider prefixes with a long high-entropy body.
		Regex:  regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b`),
		Redact: maskTail,
	},
	{
		ID:       "LEAK-005",
		Name:     "Database connection string with credentials",
		Severity: "critical",
		Score:    85,
		// scheme://user:password@host -- the colon-separated password is the tell.
		Regex:  regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:[^\s:/@]+@[^\s/]+`),
		Redact: maskTail,
	},
	{
		ID:       "LEAK-006",
		Name:     "Password hash in response (bcrypt/argon2)",
		Severity: "high",
		Score:    80,
		Regex:    regexp.MustCompile(`\$(?:2[aby]|argon2(?:id|i|d))\$[0-9]{2}\$[A-Za-z0-9./+]{20,}`),
		Redact:   func(string) string { return "$2b$…" },
	},
	{
		ID:       "LEAK-007",
		Name:     "Stack trace or internal path disclosure",
		Severity: "medium",
		Score:    40,
		Regex:    regexp.MustCompile(`(?m)(?:goroutine \d+ \[|Traceback \(most recent call last\)|at (?:java|org|com)\.[A-Za-z0-9_.]+\(|panic: runtime error)`),
	},
	{
		ID:       "LEAK-008",
		Name:     "Cloud metadata credential in response",
		Severity: "critical",
		Score:    90,
		Regex:    regexp.MustCompile(`(?i)"?(?:AccessKeyId|SecretAccessKey|SessionToken)"?\s*[:=]\s*"?[A-Za-z0-9/+=]{16,}`),
		Redact:   maskTail,
	},
}

// ResponseLeakInspector scans a response body for leaked secrets. Unlike the
// request Inspector interface (which sees only the inbound request), it runs
// after the origin responds, against a bounded copy of the response body that
// the caller captured.
type ResponseLeakInspector struct {
	enabled bool
	block   bool
	maxScan int
	mu      sync.Mutex
	scanned uint64
	flagged uint64
}

// NewResponseLeakInspector builds the inspector. maxScanBytes caps how much of
// a response body is scanned so a huge download cannot turn inspection into a
// memory or CPU sink; zero means the default (1 MiB). When block is false the
// inspector reports leaks but does not take the response down -- a hit is a
// monitor-level event, which is the safe default for a content scanner.
func NewResponseLeakInspector(enabled, block bool, maxScanBytes int) *ResponseLeakInspector {
	if maxScanBytes <= 0 {
		maxScanBytes = 1 << 20
	}
	return &ResponseLeakInspector{enabled: enabled, block: block, maxScan: maxScanBytes}
}

// InspectResponse scans body and returns the first (highest-scoring) leak
// found, or nil when the response is clean or inspection is disabled. The
// returned Decision carries redacted evidence only.
func (r *ResponseLeakInspector) InspectResponse(contentType string, statusCode int, body []byte) *Decision {
	if !r.enabled || len(body) == 0 {
		return nil
	}
	// Only text-shaped bodies can carry the patterns above. Binary downloads
	// (images, archives) are skipped rather than decoded at cost.
	if !isTextualResponse(contentType) {
		return nil
	}

	scan := body
	if len(scan) > r.maxScan {
		scan = scan[:r.maxScan]
	}
	text := string(scan)

	r.mu.Lock()
	r.scanned++
	r.mu.Unlock()

	var best *Decision
	for _, rule := range responseLeakRules {
		loc := rule.Regex.FindStringIndex(text)
		if loc == nil {
			continue
		}
		match := text[loc[0]:loc[1]]
		evidence := match
		if rule.Redact != nil {
			evidence = rule.Redact(match)
		} else if len(evidence) > 40 {
			evidence = evidence[:40] + "…"
		}

		action := ActionMonitor
		if r.block {
			action = ActionBlock
		}
		dec := &Decision{
			Action:        action,
			RuleID:        rule.ID,
			RuleName:      rule.Name,
			Severity:      rule.Severity,
			Score:         rule.Score,
			Blocked:       r.block,
			Evidence:      fmt.Sprintf("response body leak [%s]: %s", rule.Name, evidence),
			InspectorName: "response_inspect",
		}
		if best == nil || dec.Score > best.Score {
			best = dec
		}
	}

	if best != nil {
		r.mu.Lock()
		r.flagged++
		r.mu.Unlock()
	}
	return best
}

// Stats reports how many response bodies were scanned and how many were
// flagged, for the /inspectors and metrics endpoints.
func (r *ResponseLeakInspector) Stats() (scanned, flagged uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scanned, r.flagged
}

// Enabled reports whether response body inspection is turned on, so callers
// can skip the buffering wrapper entirely when it is not.
func (r *ResponseLeakInspector) Enabled() bool { return r != nil && r.enabled }

// Name implements the Inspector interface so the existing registration path
// (EngineConfig.RespInspect) keeps working. Request-phase inspection is a
// no-op: leak detection is inherently a response-phase concern.
func (r *ResponseLeakInspector) Name() string { return "response_inspect" }

// Inspect satisfies the Inspector interface. It intentionally does nothing --
// see InspectResponse for the real work.
func (r *ResponseLeakInspector) Inspect(ctx *RequestContext) (*Decision, error) {
	return nil, nil
}

// isTextualResponse reports whether a Content-Type is worth scanning. JSON,
// XML, HTML, plain text, and JavaScript can all carry the secrets above.
func isTextualResponse(contentType string) bool {
	if contentType == "" {
		return true // unknown; scan conservatively
	}
	ct := strings.ToLower(contentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/json",
		"application/xml",
		"text/xml",
		"application/javascript",
		"application/x-javascript",
		"text/javascript",
		"application/x-pem-file",
		"application/x-www-form-urlencoded":
		return true
	}
	return strings.HasPrefix(ct, "text/")
}
