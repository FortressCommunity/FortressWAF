package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type APIProtection struct {
	mu              sync.RWMutex
	devMode         bool
	graphQLPatterns []*regexp.Regexp
	sensitivePaths  []*regexp.Regexp
	openAPISpecs    map[string]interface{}
	shadowAPIPaths  map[string]int
	maxQueryDepth   int
}

func NewAPIProtection(devMode bool) *APIProtection {
	p := &APIProtection{
		devMode:        devMode,
		maxQueryDepth:  10,
		openAPISpecs:   make(map[string]interface{}),
		shadowAPIPaths: make(map[string]int),
	}

	p.graphQLPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)query\s+\w+\s*\{`),
		regexp.MustCompile(`(?i)mutation\s+\w+\s*\{`),
		regexp.MustCompile(`(?i)subscription\s+\w+\s*\{`),
		regexp.MustCompile(`(?i)__schema\s*\{`),
		regexp.MustCompile(`(?i)__type\s*\{`),
		regexp.MustCompile(`(?i)introspection`),
		regexp.MustCompile(`(?i)__typename`),
	}

	p.sensitivePaths = []*regexp.Regexp{
		regexp.MustCompile(`(?i)/api/v?\d*/?$`),
		regexp.MustCompile(`(?i)/swagger|/docs|/openapi|/api-docs`),
		regexp.MustCompile(`(?i)/graphql`),
		regexp.MustCompile(`(?i)/grpc`),
		regexp.MustCompile(`(?i)/.env|/config|/debug|/admin`),
		// /health is intentionally left out: it is the standard uptime
		// probe that load balancers and the WAF itself use, so blocking it on
		// the protected site breaks health checks. /actuator, /info and
		// /metrics still expose internals worth hiding.
		regexp.MustCompile(`(?i)/actuator|/info|/metrics`),
		regexp.MustCompile(`(?i)/wp-admin|/administrator|/backup`),
		regexp.MustCompile(`(?i)/\.git|/\.svn|/\.hg`),
		regexp.MustCompile(`(?i)/\*|/\.\*`),
	}

	return p
}

func (p *APIProtection) Name() string { return "api_protection" }

func (p *APIProtection) Inspect(ctx *RequestContext) (*Decision, error) {
	if dec := p.detectOWASPTop10(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectGraphQLAbuse(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectGRPCAttack(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectOpenAPIAbuse(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectShadowAPI(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (p *APIProtection) detectOWASPTop10(ctx *RequestContext) *Decision {
	if ctx.Method == "OPTIONS" && ctx.Path == "/" {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "API001",
			RuleName: "API Discovery Attempt",
			Severity: "medium",
			Score:    30,
			Evidence: fmt.Sprintf("OPTIONS / from %s", ctx.RealIP),
		}
	}

	for _, pattern := range p.sensitivePaths {
		if pattern.MatchString(ctx.Path) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "API002",
				RuleName: "Sensitive API Path Access",
				Severity: "high",
				Score:    70,
				Evidence: fmt.Sprintf("sensitive path access: %s", ctx.Path),
			}
		}
	}

	if ctx.Headers["Content-Type"] == "application/xml" ||
		strings.Contains(ctx.Headers["Content-Type"], "application/xml") {
		if ctx.Body != nil && strings.Contains(string(ctx.Body), "<") {
			bodyStr := string(ctx.Body)
			if strings.Contains(bodyStr, "<!ENTITY") || strings.Contains(bodyStr, "<!DOCTYPE") {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "API003",
					RuleName: "XXE Injection",
					Severity: "critical",
					Score:    90,
					Evidence: "XML external entity injection detected",
				}
			}
		}
	}

	if ctx.Headers["Content-Length"] == "0" && ctx.Method == "POST" && strings.Contains(ctx.Path, "/api/") {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "API004",
			RuleName: "Empty POST to API",
			Severity: "low",
			Score:    10,
			Evidence: fmt.Sprintf("empty POST body to %s", ctx.Path),
		}
	}

	return nil
}

func (p *APIProtection) detectGraphQLAbuse(ctx *RequestContext) *Decision {
	if !strings.Contains(ctx.Path, "graphql") && !strings.Contains(ctx.Path, "gql") && !strings.Contains(ctx.Path, "gql") {
		return nil
	}

	bodyStr := ""
	if ctx.Body != nil {
		bodyStr = string(ctx.Body)
	}

	for k, v := range ctx.QueryParams {
		bodyStr += k + "=" + strings.Join(v, "") + " "
	}

	if strings.Contains(bodyStr, "__schema") || strings.Contains(bodyStr, "__type") ||
		strings.Contains(bodyStr, "introspection") {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "API005",
			RuleName: "GraphQL Introspection Blocked",
			Severity: "high",
			Score:    70,
			Evidence: "graphql introspection query blocked",
		}
	}

	if strings.Contains(bodyStr, "__typename") {
		hasDepth := strings.Count(bodyStr, "{") > p.maxQueryDepth
		if hasDepth {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "API006",
				RuleName: "GraphQL Query Depth Exceeded",
				Severity: "high",
				Score:    65,
				Evidence: fmt.Sprintf("graphql query depth exceeds limit of %d", p.maxQueryDepth),
			}
		}
	}

	for _, pattern := range p.graphQLPatterns {
		if pattern.MatchString(bodyStr) {
			return &Decision{
				Action:   ActionMonitor,
				RuleID:   "API007",
				RuleName: "GraphQL Query Detected",
				Severity: "low",
				Score:    5,
				Evidence: "graphql query detected",
			}
		}
	}

	return nil
}

func (p *APIProtection) detectGRPCAttack(ctx *RequestContext) *Decision {
	if ctx.Headers["Content-Type"] == "application/grpc" ||
		strings.HasPrefix(ctx.Headers["Content-Type"], "application/grpc") {
		contentType := ctx.Headers["Content-Type"]
		if strings.Contains(contentType, "proto") {
			return &Decision{
				Action:   ActionMonitor,
				RuleID:   "API008",
				RuleName: "gRPC Request",
				Severity: "low",
				Score:    5,
				Evidence: "gRPC request detected",
			}
		}
	}

	return nil
}

func (p *APIProtection) detectOpenAPIAbuse(ctx *RequestContext) *Decision {
	path := ctx.Path

	if strings.HasSuffix(path, "/") || strings.HasSuffix(path, "?") {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "API009",
			RuleName: "OpenAPI Schema Violation",
			Severity: "low",
			Score:    5,
			Evidence: fmt.Sprintf("path format violation: %s", path),
		}
	}

	return nil
}

func (p *APIProtection) detectShadowAPI(ctx *RequestContext) *Decision {
	path := ctx.Path

	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/v2/") {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(parts) >= 2 {
			endpoint := parts[0] + "/" + parts[1]

			p.mu.Lock()
			p.shadowAPIPaths[endpoint]++
			count := p.shadowAPIPaths[endpoint]
			p.mu.Unlock()

			if count < 2 {
				firstSeen := count == 1
				if firstSeen {
					return &Decision{
						Action:   ActionMonitor,
						RuleID:   "API010",
						RuleName: "Unknown API Endpoint",
						Severity: "low",
						Score:    10,
						Evidence: fmt.Sprintf("unknown API endpoint accessed: %s", endpoint),
					}
				}
			}
		}
	}

	return nil
}

func (p *APIProtection) LoadOpenAPISpec(spec map[string]interface{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.openAPISpecs = spec
}
