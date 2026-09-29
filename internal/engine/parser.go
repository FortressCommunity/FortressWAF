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
	normalizationRE  *regexp.Regexp
	unicodeControlRE *regexp.Regexp
	http10RE         *regexp.Regexp
	http2PrefaceRE   *regexp.Regexp
}

// hasOverlongUTF8 reports whether s contains a raw overlong or otherwise
// invalid UTF-8 byte sequence. It inspects the underlying bytes, not runes:
// s may be a string that failed utf8.ValidString, and a rune-range regexp
// cannot express byte-level rules in Go. The scan flags the four shapes an
// overlong encoder produces:
//
//	C0/C1 lead            -- overlong two-byte form
//	F5-FF lead            -- beyond U+10FFFF
//	E0 80-9F, F0 80-8F    -- overlong three- and four-byte forms
//	bare 80-BF            -- continuation byte with no lead
func hasOverlongUTF8(s string) bool {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == 0xC0 || b[i] == 0xC1:
			return true
		case b[i] >= 0xF5:
			return true
		case b[i] == 0xE0 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x9F:
			return true
		case b[i] == 0xF0 && i+1 < len(b) && b[i+1] >= 0x80 && b[i+1] <= 0x8F:
			return true
		case b[i] >= 0x80 && b[i] <= 0xBF:
			// A continuation byte is only invalid when it is not preceded by a
			// valid lead byte in 0xC2-0xF4.
			if i == 0 || !(b[i-1] >= 0xC2 && b[i-1] <= 0xF4) {
				return true
			}
		}
	}
	return false
}

func NewParserHardener(devMode bool) *ParserHardener {
	return &ParserHardener{
		devMode: devMode,
		// Overlong / invalid UTF-8 (the parser-differential trick) is caught by
		// the utf8.ValidString check in detectUnicodeAttack (PARSER_010) and
		// the byte scan in hasOverlongUTF8 (PARSER_012). A byte-class regexp
		// cannot express this: Go reads "[\xC2-\xDF]" as a *rune* range, so the
		// old pattern matched valid accented letters and blocked ordinary text.
		normalizationRE: regexp.MustCompile(
			// Encoded space (%20), tab, #, ? and ; are normal in URLs and were
			// blocked here, which broke benign paths such as
			// /products/sony%20wh-1000xm5. Only control characters and null
			// bytes remain; dot-segment traversal is handled below.
			`(?i)(?:%00|%0d|%0a|%08)` +
				`|(?:\.\./)` +
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
	if dec := p.detectTraversalInPath(ctx.Path, "path"); dec != nil {
		return dec
	}

	for k, v := range ctx.QueryParams {
		for _, val := range v {
			if dec := p.detectTraversalInPath(val, "query:"+k); dec != nil {
				return dec
			}
		}
	}

	for k, v := range ctx.FormParams {
		for _, val := range v {
			if dec := p.detectTraversalInPath(val, "form:"+k); dec != nil {
				return dec
			}
		}
	}

	for k, v := range ctx.Headers {
		if dec := p.detectTraversalInPath(v, "header:"+k); dec != nil {
			return dec
		}
	}

	return nil
}

// detectTraversalInPath decodes percent escapes (to a bounded depth) and
// reports a path-traversal attempt. It replaces the pattern-only check, which
// looked at headers but not at query or form values -- so the encoded
// traversal corpus was only caught incidentally by an over-broad SQLi rule.
func (p *ParserHardener) detectTraversalInPath(raw, source string) *Decision {
	if raw == "" {
		return nil
	}

	// The raw form: a literal "../" or "..\" segment, or the "....//" trick
	// (which a normalizer collapses back to "../").
	if p.normalizationRE.MatchString(raw) {
		return &Decision{
			Action:          ActionBlock,
			RuleID:          "PARSER_001",
			RuleName:        "Normalization Bypass Attempt",
			Severity:        "high",
			Score:           75,
			ConfidenceScore: 0.95,
			Evidence:        fmt.Sprintf("suspicious path normalization pattern in %s", source),
		}
	}

	if !strings.Contains(raw, "%") {
		return nil
	}

	decoded, err := p.decodePathValue(raw)
	if err != nil || decoded == raw {
		return nil
	}
	// Normalize the "....//" and "..//" collapsing tricks before the check.
	collapsed := collapseDotSegments(decoded)
	if strings.Contains(decoded, "../") || strings.Contains(decoded, "..\\") ||
		strings.Contains(collapsed, "../") || strings.Contains(collapsed, "..\\") {
		return &Decision{
			Action:          ActionBlock,
			RuleID:          "PARSER_002",
			RuleName:        "Encoded Path Traversal",
			Severity:        "critical",
			Score:           90,
			ConfidenceScore: 0.98,
			Evidence:        fmt.Sprintf("encoded path traversal in %s: %q -> %q", source, raw, decoded),
		}
	}

	return nil
}

// collapseDotSegments removes repeated slashes and the "....//" family so a
// payload that hides traversal behind collapsed separators is still caught.
func collapseDotSegments(s string) string {
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	for strings.Contains(s, `\\`) {
		s = strings.ReplaceAll(s, `\\`, `\`)
	}
	return s
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

		if hasOverlongUTF8(t) {
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

// decodePathValue decodes percent-escapes, at most twice, so a
// double-encoded traversal (%252e%252e = ..) is still seen. The previous
// version recursed whenever the decoded result still contained a "%", which
// never terminated for an input like "%25" (decodes to "%", which still
// contains "%"): it overflowed the stack and crashed the proxy -- a remote
// denial of service reachable from any header or path containing a percent
// sign that was not a valid escape. The loop is now bounded.
func (p *ParserHardener) decodePathValue(v string) (string, error) {
	// Decode repeatedly so multi-encoded traversal (..%25252f = "../", encoded
	// three deep) is still seen, but with a hard pass limit: the old version
	// recursed until the result stopped changing, which never terminated for an
	// input like "%25" (decodes to "%") and crashed the proxy with a stack
	// overflow. Each pass must make progress or the loop stops, so an ordinary
	// value with a stray "%" cannot loop.
	const maxPasses = 6
	result := v
	for pass := 0; pass < maxPasses; pass++ {
		if !strings.Contains(result, "%") {
			break
		}
		decoded, changed := percentDecodeOnce(result)
		if !changed {
			break
		}
		result = decoded
	}
	return result, nil
}

// percentDecodeOnce decodes every valid %XX escape in s exactly once and
// reports whether anything changed. An invalid escape (a bare "%", "%zz", a
// trailing "%A") is left as-is, so an ordinary value containing "%" cannot
// loop or be mangled.
func percentDecodeOnce(s string) (string, bool) {
	var builder strings.Builder
	builder.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			builder.WriteByte(hexByte(s[i+1], s[i+2]))
			i += 2
			changed = true
			continue
		}
		builder.WriteByte(s[i])
	}
	return builder.String(), changed
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexByte(hi, lo byte) byte {
	return hexVal(hi)<<4 | hexVal(lo)
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
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
