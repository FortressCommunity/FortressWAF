package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type ParserHardener struct {
	mu               sync.RWMutex
	devMode          bool
	overlongRE       *regexp.Regexp
	normalizationRE  *regexp.Regexp
	unicodeControlRE *regexp.Regexp
	http10RE         *regexp.Regexp
	http2PrefaceRE   *regexp.Regexp
}

func NewParserHardener(devMode bool) *ParserHardener {
	return &ParserHardener{
		devMode: devMode,
		overlongRE: regexp.MustCompile(
			`[\xC0-\xC1]` +
				`|[\xF5-\xFF]` +
				`|[\xF0-\xF4][\x80-\xBF]{0,3}` +
				`|[\xE0-\xEF][\x80-\xBF]{0,2}` +
				`|[\xC2-\xDF][\x80-\xBF]` +
				`|[\x80-\xBF]`,
		),
		normalizationRE: regexp.MustCompile(
			// Encoded space (%20), tab, #, ? and ; are normal in URLs and were
			// blocked here, which broke benign paths such as
			// /products/sony%20wh-1000xm5. Only control characters and null
			// bytes remain; dot-segment traversal is handled below.
			`(?i)(?:%00|%0d|%0a|%08)` +
				`|(?:\.\./)` +
				`|(?://+)` +
				`|(?:/\./)` +
				`|(?:/\.$)` +
				`|(?:\\\.\\)`,
		),
		unicodeControlRE: regexp.MustCompile(
			`[\x{200B}\x{200C}\x{200D}\x{FEFF}\x{00AD}]` +
				`|[\x{2028}\x{2029}]` +
				`|[\x{FFF0}-\x{FFFD}]`,
		),
		http10RE:       regexp.MustCompile(`(?i)^HTTP/1\.0\s`),
		http2PrefaceRE: regexp.MustCompile(`^PRI \* HTTP/2\.0`),
	}
}

func (p *ParserHardener) Name() string { return "parser_hardener" }

func (p *ParserHardener) Inspect(ctx *RequestContext) (*Decision, error) {
	if ctx.Request == nil {
		return nil, nil
	}

	if dec := p.detectNormalizationBypass(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectUnicodeAttack(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectParserDifferential(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectHTTPDowngrade(ctx); dec != nil {
		return dec, nil
	}

	if dec := p.detectChunkedAbuse(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (p *ParserHardener) detectNormalizationBypass(ctx *RequestContext) *Decision {
	path := ctx.Path

	if p.normalizationRE.MatchString(path) {
		return &Decision{
			Action:          ActionBlock,
			RuleID:          "PARSER_001",
			RuleName:        "Normalization Bypass Attempt",
			Severity:        "high",
			Score:           75,
			ConfidenceScore: 0.95,
			Evidence:        fmt.Sprintf("suspicious path normalization pattern in %q", path),
		}
	}

	for k, v := range ctx.Headers {
		if strings.Contains(k, "%") || strings.Contains(v, "%") {
			decoded, err := p.decodePathValue(v)
			if err == nil && decoded != v {
				if strings.Contains(decoded, "../") || strings.Contains(decoded, "..\\") {
					return &Decision{
						Action:          ActionBlock,
						RuleID:          "PARSER_002",
						RuleName:        "Double-Encoded Path Traversal",
						Severity:        "critical",
						Score:           90,
						ConfidenceScore: 0.98,
						Evidence:        fmt.Sprintf("double-encoded path traversal in header %s: %q -> %q", k, v, decoded),
					}
				}
			}
		}
	}

	return nil
}

func (p *ParserHardener) detectUnicodeAttack(ctx *RequestContext) *Decision {
	targets := []string{
		ctx.Path,
		ctx.Method,
		ctx.RealIP,
	}

	for k, v := range ctx.Headers {
		targets = append(targets, k, v)
	}

	for _, t := range targets {
		if !utf8.ValidString(t) {
			return &Decision{
				Action:          ActionBlock,
				RuleID:          "PARSER_010",
				RuleName:        "Invalid UTF-8 in Request",
				Severity:        "high",
				Score:           70,
				ConfidenceScore: 0.90,
				Evidence:        fmt.Sprintf("invalid UTF-8 sequence detected in request data"),
			}
		}

		for _, r := range t {
			if r > unicode.MaxASCII && (unicode.Is(unicode.C, r) || r == '\uFFFD') {
				if p.unicodeControlRE.MatchString(string(r)) {
					return &Decision{
						Action:          ActionBlock,
						RuleID:          "PARSER_011",
						RuleName:        "Unicode Control Character",
						Severity:        "high",
						Score:           75,
						ConfidenceScore: 0.92,
						Evidence:        fmt.Sprintf("unicode control character U+%04X in request", r),
					}
				}
			}
		}

		if p.overlongRE.MatchString(t) {
			return &Decision{
				Action:          ActionBlock,
				RuleID:          "PARSER_012",
				RuleName:        "Overlong UTF-8 Encoding",
				Severity:        "critical",
				Score:           85,
				ConfidenceScore: 0.95,
				Evidence:        fmt.Sprintf("overlong UTF-8 encoding detected (parser differential attack)"),
			}
		}
	}

	return nil
}

func (p *ParserHardener) detectParserDifferential(ctx *RequestContext) *Decision {
	ct := ctx.Request.Header.Get("Content-Type")

	if strings.Contains(strings.ToLower(ct), "multipart/form-data") {
		boundary := extractBoundary(ct)
		if boundary != "" && (strings.Contains(boundary, `\`) || strings.HasPrefix(boundary, " ")) {
			return &Decision{
				Action:          ActionBlock,
				RuleID:          "PARSER_020",
				RuleName:        "Multipart Boundary Parser Differential",
				Severity:        "high",
				Score:           80,
				ConfidenceScore: 0.93,
				Evidence:        fmt.Sprintf("suspicious multipart boundary: %q", boundary),
			}
		}
	}

	transferEncodings := ctx.Request.Header.Values("Transfer-Encoding")
	if len(transferEncodings) > 1 {
		return &Decision{
			Action:          ActionBlock,
			RuleID:          "PARSER_021",
			RuleName:        "Multiple Transfer-Encoding (Parser Differential)",
			Severity:        "critical",
			Score:           95,
			ConfidenceScore: 0.97,
			Evidence:        fmt.Sprintf("multiple TE headers: %v", transferEncodings),
		}
	}

	return nil
}

func (p *ParserHardener) detectHTTPDowngrade(ctx *RequestContext) *Decision {
	if ctx.Request.Proto == "HTTP/1.0" {
		host := ctx.Request.Header.Get("Host")
		contentLength := ctx.Request.Header.Get("Content-Length")

		if ctx.Method == "POST" && contentLength == "" && ctx.Body != nil && len(ctx.Body) > 0 {
			return &Decision{
				Action:          ActionBlock,
				RuleID:          "PARSER_030",
				RuleName:        "HTTP/1.0 Downgrade Attack",
				Severity:        "high",
				Score:           70,
				ConfidenceScore: 0.85,
				Evidence:        fmt.Sprintf("HTTP/1.0 POST with body but no Content-Length (request smuggling)"),
			}
		}

		if host == "" {
			return &Decision{
				Action:          ActionMonitor,
				RuleID:          "PARSER_031",
				RuleName:        "HTTP/1.0 No Host Header",
				Severity:        "low",
				Score:           20,
				ConfidenceScore: 0.60,
				Evidence:        fmt.Sprintf("HTTP/1.0 request missing Host header"),
			}
		}
	}

	if ctx.Method == "PRI" {
		if p.http2PrefaceRE.MatchString(string(ctx.Headers["PRI"])) {
			return &Decision{
				Action:          ActionBlock,
				RuleID:          "PARSER_032",
				RuleName:        "HTTP/2 Preface in HTTP/1.1",
				Severity:        "critical",
				Score:           95,
				ConfidenceScore: 0.99,
				Evidence:        fmt.Sprintf("HTTP/2 connection preface sent on HTTP/1.1 connection"),
			}
		}
	}

	return nil
}

func (p *ParserHardener) detectChunkedAbuse(ctx *RequestContext) *Decision {
	te := ctx.Request.Header.Get("Transfer-Encoding")
	if !strings.Contains(strings.ToLower(te), "chunked") {
		return nil
	}

	bodyLen := len(ctx.Body)
	if bodyLen == 0 {
		return nil
	}

	bodyStr := string(ctx.Body)

	chunkExtRE := regexp.MustCompile(`(?i)[a-z0-9]+\s*;\s*[a-z_]+\s*=\s*[^;\r\n]+`)
	if matches := chunkExtRE.FindAllString(bodyStr, -1); len(matches) > 3 {
		return &Decision{
			Action:          ActionMonitor,
			RuleID:          "PARSER_040",
			RuleName:        "Excessive Chunk Extensions",
			Severity:        "medium",
			Score:           40,
			ConfidenceScore: 0.70,
			Evidence:        fmt.Sprintf("excessive chunk extensions (%d) in chunked body", len(matches)),
		}
	}

	if strings.Contains(bodyStr, "0\r\n\r\n") && strings.Count(bodyStr, "0\r\n\r\n") > 1 {
		return &Decision{
			Action:          ActionBlock,
			RuleID:          "PARSER_041",
			RuleName:        "Chunked Trailer Confusion",
			Severity:        "high",
			Score:           75,
			ConfidenceScore: 0.90,
			Evidence:        fmt.Sprintf("multiple chunk terminator markers in chunked body"),
		}
	}

	return nil
}

func (p *ParserHardener) decodePathValue(v string) (string, error) {
	if !strings.Contains(v, "%") {
		return v, nil
	}
	var builder strings.Builder
	builder.Grow(len(v))
	for i := 0; i < len(v); i++ {
		if v[i] == '%' && i+2 < len(v) {
			hex := v[i+1 : i+3]
			var b byte
			n, err := fmt.Sscanf(hex, "%02x", &b)
			if err != nil || n != 1 {
				builder.WriteByte(v[i])
				continue
			}
			builder.WriteByte(b)
			i += 2
		} else {
			builder.WriteByte(v[i])
		}
	}
	result := builder.String()
	if strings.Contains(result, "%") {
		return p.decodePathValue(result)
	}
	return result, nil
}

func extractBoundary(ct string) string {
	if !strings.Contains(strings.ToLower(ct), "boundary=") {
		return ""
	}
	parts := strings.Split(ct, "boundary=")
	if len(parts) < 2 {
		return ""
	}
	b := strings.TrimSpace(parts[1])
	if idx := strings.IndexAny(b, "; \t\r\n"); idx > 0 {
		b = b[:idx]
	}
	b = strings.Trim(b, "\"")
	return b
}
