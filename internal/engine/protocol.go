package engine

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

type ProtocolAnomaly struct {
	mu            sync.RWMutex
	devMode       bool
	malformedRE   *regexp.Regexp
	verbTampering []string
}

func NewProtocolAnomaly(devMode bool) *ProtocolAnomaly {
	return &ProtocolAnomaly{
		devMode:     devMode,
		malformedRE: regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`),
		// Only genuinely dangerous or unexpected verbs are flagged. GET, HEAD,
		// POST, PUT, PATCH, DELETE, and OPTIONS are ordinary HTTP: browsers send
		// OPTIONS as a CORS preflight and HEAD for metadata on every page load,
		// and REST APIs use PUT/PATCH/DELETE as a matter of course. Blocking
		// those broke normal browsing (a phone opening a web app tripped the
		// OPTIONS preflight before it did anything). TRACE and TRACK echo the
		// request back (XST), CONNECT opens a tunnel, and the WebDAV verbs below
		// have no business reaching a typical web app.
		verbTampering: []string{
			"CONNECT", "TRACE", "TRACK",
			"PROPFIND", "PROPPATCH", "MKCOL",
			"MOVE", "COPY", "LOCK", "UNLOCK",
			"BIND", "REBIND", "UNBIND",
			"ACL", "REPORT", "VERSION-CONTROL", "CHECKIN",
			"CHECKOUT", "UNCHECKOUT", "MERGE", "BASELINE-CONTROL",
			"MKCALENDAR", "MKREDIRECTREF", "UPDATEREDIRECTREF",
		},
	}
}

func (p *ProtocolAnomaly) Name() string { return "protocol_anomaly" }

func (p *ProtocolAnomaly) Inspect(ctx *RequestContext) (*Decision, error) {
	if dec := p.detectMalformedRequest(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectRequestSmuggling(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectWebSocketAnomaly(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectVerbTampering(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectResponseHeaderInjection(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectCookieSecurity(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (p *ProtocolAnomaly) detectMalformedRequest(ctx *RequestContext) *Decision {
	if ctx.Method == "" {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "PROT001",
			RuleName: "Missing HTTP Method",
			Severity: "high",
			Score:    70,
			Evidence: "http request missing method",
		}
	}

	for k, v := range ctx.Headers {
		if p.malformedRE.MatchString(k) || p.malformedRE.MatchString(v) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT002",
				RuleName: "Malformed HTTP Header",
				Severity: "high",
				Score:    75,
				Evidence: fmt.Sprintf("malformed header: %s", k),
			}
		}
	}

	if len(ctx.Headers) > 100 {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "PROT003",
			RuleName: "Excessive Headers",
			Severity: "medium",
			Score:    40,
			Evidence: fmt.Sprintf("too many headers: %d", len(ctx.Headers)),
		}
	}

	totalHeaderSize := 0
	for k, v := range ctx.Headers {
		totalHeaderSize += len(k) + len(v)
	}
	if totalHeaderSize > 32000 {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "PROT004",
			RuleName: "Header Size Exceeded",
			Severity: "high",
			Score:    65,
			Evidence: fmt.Sprintf("total header size: %d bytes", totalHeaderSize),
		}
	}

	return nil
}

func (p *ProtocolAnomaly) detectRequestSmuggling(ctx *RequestContext) *Decision {
	contentLength := ctx.Headers["Content-Length"]
	transferEncoding := ctx.Headers["Transfer-Encoding"]

	if contentLength != "" && transferEncoding != "" {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "PROT005",
			RuleName: "Request Smuggling (CL.TE)",
			Severity: "critical",
			Score:    90,
			Evidence: "both content-length and transfer-encoding headers present",
		}
	}

	if strings.Contains(strings.ToLower(transferEncoding), "chunked") {
		if strings.Count(transferEncoding, ",") > 0 {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT006",
				RuleName: "Request Smuggling (TE.TE)",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("obfuscated transfer-encoding: %s", transferEncoding),
			}
		}

		if strings.Contains(strings.ToLower(transferEncoding), "identity") {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT007",
				RuleName: "Transfer-Encoding Obfuscation",
				Severity: "high",
				Score:    80,
				Evidence: "transfer-encoding contains identity",
			}
		}
	}

	return nil
}

func (p *ProtocolAnomaly) detectWebSocketAnomaly(ctx *RequestContext) *Decision {
	upgrade := ctx.Headers["Upgrade"]
	connection := ctx.Headers["Connection"]

	if strings.ToLower(upgrade) == "websocket" {
		wsVersion := ctx.Headers["Sec-WebSocket-Version"]
		wsKey := ctx.Headers["Sec-WebSocket-Key"]

		if wsVersion == "" || wsKey == "" {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT008",
				RuleName: "Malformed WebSocket Request",
				Severity: "high",
				Score:    70,
				Evidence: "websocket upgrade missing required headers",
			}
		}

		if !strings.Contains(strings.ToLower(connection), "upgrade") {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT009",
				RuleName: "WebSocket Connection Header Missing",
				Severity: "high",
				Score:    65,
				Evidence: "websocket upgrade without connection: upgrade",
			}
		}
	}

	return nil
}

func (p *ProtocolAnomaly) detectVerbTampering(ctx *RequestContext) *Decision {
	method := strings.ToUpper(ctx.Method)

	for _, verb := range p.verbTampering {
		if method == verb {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT010",
				RuleName: "HTTP Verb Tampering",
				Severity: "high",
				Score:    70,
				Evidence: fmt.Sprintf("suspicious HTTP method: %s", method),
			}
		}
	}

	return nil
}

func (p *ProtocolAnomaly) detectResponseHeaderInjection(ctx *RequestContext) *Decision {
	for _, v := range ctx.QueryParams {
		for _, val := range v {
			if strings.Contains(val, "\r\n") || strings.Contains(val, "\n") {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "PROT011",
					RuleName: "Response Header Injection",
					Severity: "critical",
					Score:    85,
					Evidence: "header injection payload detected",
				}
			}
		}
	}

	for _, v := range ctx.Cookies {
		if strings.Contains(v, "\r\n") || strings.Contains(v, "\n") {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT012",
				RuleName: "Cookie Injection",
				Severity: "high",
				Score:    80,
				Evidence: "cookie header injection detected",
			}
		}
	}

	return nil
}

func (p *ProtocolAnomaly) detectCookieSecurity(ctx *RequestContext) *Decision {
	const maxCookieSize = 4096
	for k, v := range ctx.Cookies {
		if len(k)+len(v) > maxCookieSize {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "PROT013",
				RuleName: "Oversized Cookie",
				Severity: "medium",
				Score:    40,
				Evidence: fmt.Sprintf("cookie %s size exceeds limit", k),
			}
		}
	}

	const maxCookieCount = 50
	if len(ctx.Cookies) > maxCookieCount {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "PROT014",
			RuleName: "Excessive Cookies",
			Severity: "medium",
			Score:    35,
			Evidence: fmt.Sprintf("too many cookies: %d", len(ctx.Cookies)),
		}
	}

	return nil
}

func (p *ProtocolAnomaly) SanitizeHeaders(r *http.Request) {
	r.Header.Del("X-Forwarded-For")
}
