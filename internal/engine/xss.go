package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type XSSEngine struct {
	mu            sync.RWMutex
	devMode       bool
	htmlTags      []*regexp.Regexp
	eventHandlers []*regexp.Regexp
	jsProtocols   []*regexp.Regexp
	polyglot      []*regexp.Regexp
	svgPatterns   []*regexp.Regexp
	cssInjection  []*regexp.Regexp
	encodedXSS    *regexp.Regexp
	jsSinks       []*regexp.Regexp
	entityNumRE   *regexp.Regexp
	octalEscapeRE *regexp.Regexp
	hexEscapeRE   *regexp.Regexp
	reflectedXSS  *regexp.Regexp
	customCSP     string
}

func NewXSSEngine(devMode bool) *XSSEngine {
	e := &XSSEngine{
		devMode: devMode,
	}

	e.compilePatterns()
	e.setupCSP()

	return e
}

func (e *XSSEngine) Name() string { return "xss" }

func (e *XSSEngine) compilePatterns() {
	e.htmlTags = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:<script[^>]*>[^<]*</script>)`),
		regexp.MustCompile(`(?i)(?:<iframe[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<object[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<embed[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<applet[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<meta[^>]*http-equiv[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<link[^>]*href[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<base[^>]*href[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<form[^>]*action[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<img[^>]*onerror[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<body[^>]*onload[^>]*>)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*/svg>)`),
		regexp.MustCompile(`(?i)(?:<math[^>]*>)`),
	}

	e.eventHandlers = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:onabort|onautocomplete|onautocompleteerror|onblur|oncancel|oncanplay|oncanplaythrough|onchange|onclick|onclose|oncontextmenu|oncuechange|ondblclick|ondrag|ondragend|ondragenter|ondragleave|ondragover|ondragstart|ondrop|ondurationchange|onemptied|onended|onerror|onfocus|onfocusin|onfocusout|ongotpointercapture|oninput|oninvalid|onkeydown|onkeypress|onkeyup|onload|onloadeddata|onloadedmetadata|onloadstart|onlostpointercapture|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onpause|onplay|onplaying|onpointercancel|onpointerdown|onpointerenter|onpointerleave|onpointermove|onpointerout|onpointerover|onpointerup|onprogress|onratechange|onreset|onresize|onscroll|onseeked|onseeking|onselect|onselectionchange|onselectstart|onshow|onstalled|onsubmit|onsuspend|ontimeupdate|ontoggle|onvolumechange|onwaiting|onwheel)`),
		regexp.MustCompile(`(?i)(?:onmouseenter|onmouseleave|onpointerrawupdate|onbeforeinput|onbeforetoggle|oncontentvisibilityautostatechange)`),
		// SVG/animation events: <marquee onstart=...>, <svg><discard onbegin=...>
		regexp.MustCompile(`(?i)(?:onstart|onbegin|onend|onfinish|onanimationstart|onanimationend|onanimationiteration|onanimationcancel|ontransitionrun|ontransitionstart|ontransitionend|ontransitioncancel|onscrollend|onbeforematch|onsecuritypolicyviolation)`),
		regexp.MustCompile(`(?i)(?:onpageshow|onpagehide|onpopstate|onhashchange|onbeforeunload|onunload)`),
	}

	e.jsProtocols = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:javascript\s*:)`),
		regexp.MustCompile(`(?i)(?:vbscript\s*:)`),
		regexp.MustCompile(`(?i)(?:data\s*:\s*(?:text/html|application/xhtml))`),
		regexp.MustCompile(`(?i)(?:livescript\s*:)`),
		regexp.MustCompile(`(?i)(?:mocha\s*:)`)}

	e.polyglot = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:jaVasCript:[\s\S]*?[<\"'])`),
		regexp.MustCompile(`(?i)(?:\\x22.*onerror\\x3d)`),
		regexp.MustCompile(`(?i)(?:\\x3Cscript\\x3E)`),
	}

	e.svgPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:<svg[^>]*>[\s\S]*?<script)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*onload)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*>[\s\S]*?<animate)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*>[\s\S]*?<set)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*>[\s\S]*?<use)`),
		regexp.MustCompile(`(?i)(?:<svg[^>]*>[\s\S]*?<desc>)`),
	}

	e.cssInjection = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:expression\s*\()`),
		regexp.MustCompile(`(?i)(?:-moz-binding)`),
		regexp.MustCompile(`(?i)(?:behavior\s*:)`),
		regexp.MustCompile(`(?i)(?:@import\s+url)`),
		regexp.MustCompile(`(?i)(?:url\s*\(\s*['"]?\s*javascript:)`),
		regexp.MustCompile(`(?i)(?:position\s*:\s*fixed)`),
	}

	// The trailing ';' is optional: evasion payloads often omit it
	// (&#0000106&#0000097...), and browsers still decode them.
	e.entityNumRE = regexp.MustCompile(`&#[xX]?[0-9a-fA-F]{2,8};?`)
	// CSS-style backslash escapes: \0075 is hex 0x75 = 'u'. \xNN is the
	// JS/Java form.
	e.octalEscapeRE = regexp.MustCompile(`\\[0-9a-fA-F]{2,4}`)
	e.hexEscapeRE = regexp.MustCompile(`\\x[0-9a-fA-F]{1,4}`)

	e.encodedXSS = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;).*(?:script|alert|prompt|confirm|onerror|onload)`)

	// JS sinks: an XSS payload eventually calls something, so a bare sink
	// call inside a request value is a strong signal on its own. This is what
	// catches <marquee onstart=alert(1)> or <BR SIZE="&{alert('XSS')}">.
	e.jsSinks = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:alert|prompt|confirm|eval|atob|setTimeout|setInterval|execScript|Function)\s*\(`),
		regexp.MustCompile(`(?i)(?:document\.(?:cookie|write|writeln|location)|location\.(?:href|assign|replace)|window\.(?:location|open|eval)|self\.(?:location|eval))`),
		regexp.MustCompile(`(?i)(?:String\.fromCharCode|fromCharCode\s*\(|unescape\s*\(|decodeURIComponent\s*\()`),
	}
}

func (e *XSSEngine) setupCSP() {
	e.customCSP = "default-src 'self'; " +
		"script-src 'self' 'strict-dynamic' 'nonce-{nonce}' 'unsafe-inline' http: https:; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"require-trusted-types-for 'script';"
}

func (e *XSSEngine) Inspect(ctx *RequestContext) (*Decision, error) {
	targets := e.extractTargets(ctx)

	for _, target := range targets {
		if dec := e.inspectValue(target.value, target.source); dec != nil {
			return dec, nil
		}
	}

	return nil, nil
}

type xssTarget struct {
	value  string
	source string
}

func (e *XSSEngine) extractTargets(ctx *RequestContext) []xssTarget {
	var targets []xssTarget
	for k, v := range ctx.QueryParams {
		for _, val := range v {
			targets = append(targets, xssTarget{value: val, source: fmt.Sprintf("query:%s", k)})
		}
	}
	for k, v := range ctx.FormParams {
		for _, val := range v {
			targets = append(targets, xssTarget{value: val, source: fmt.Sprintf("form:%s", k)})
		}
	}
	if ctx.Body != nil {
		targets = append(targets, xssTarget{value: string(ctx.Body), source: "body"})
	}
	for k, v := range ctx.Headers {
		lower := strings.ToLower(k)
		if lower == "referer" || lower == "origin" || lower == "x-forwarded-for" {
			targets = append(targets, xssTarget{value: v, source: fmt.Sprintf("header:%s", k)})
		}
	}
	for k, v := range ctx.Cookies {
		targets = append(targets, xssTarget{value: v, source: fmt.Sprintf("cookie:%s", k)})
	}
	return targets
}

func (e *XSSEngine) inspectValue(value, source string) *Decision {
	if value == "" {
		return nil
	}

	// Token-splitting evasion inserts spaces inside a keyword ("jav ascript:",
	// "one rror=..."). Matching the whitespace-stripped variant closes that.
	squeezed := strings.Join(strings.Fields(value), "")

	// Fully-encoded payloads (&#106;&#97;... or \006A\0061...) hide every
	// literal token the rules look for, so decode before matching too.
	decoded := e.decodeEntities(value)

	for _, pattern := range e.htmlTags {
		if pattern.MatchString(value) || pattern.MatchString(decoded) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS001",
				RuleName: "HTML Tag Injection",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("HTML tag injection in %s: %s", source, pattern.String()),
			}
		}
	}

	for _, pattern := range e.eventHandlers {
		if pattern.MatchString(value) || pattern.MatchString(squeezed) || pattern.MatchString(decoded) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS002",
				RuleName: "Event Handler Injection",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("event handler injection in %s", source),
			}
		}
	}

	for _, pattern := range e.jsProtocols {
		if pattern.MatchString(value) || pattern.MatchString(squeezed) || pattern.MatchString(decoded) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS003",
				RuleName: "JavaScript Protocol",
				Severity: "critical",
				Score:    85,
				Evidence: fmt.Sprintf("javascript protocol detected in %s", source),
			}
		}
	}

	for _, pattern := range e.polyglot {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS004",
				RuleName: "Polyglot XSS Payload",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("polyglot XSS payload in %s", source),
			}
		}
	}

	for _, pattern := range e.svgPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS005",
				RuleName: "SVG Injection",
				Severity: "critical",
				Score:    85,
				Evidence: fmt.Sprintf("SVG injection in %s", source),
			}
		}
	}

	for _, pattern := range e.cssInjection {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS006",
				RuleName: "CSS Injection",
				Severity: "high",
				Score:    75,
				Evidence: fmt.Sprintf("CSS injection in %s", source),
			}
		}
	}

	for _, pattern := range e.jsSinks {
		if pattern.MatchString(value) || pattern.MatchString(squeezed) || pattern.MatchString(decoded) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS009",
				RuleName: "JavaScript Sink",
				Severity: "critical",
				Score:    85,
				Evidence: fmt.Sprintf("javascript sink in %s", source),
			}
		}
	}

	if e.encodedXSS.MatchString(value) {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "XSS007",
			RuleName: "Encoded XSS",
			Severity: "high",
			Score:    75,
			Evidence: fmt.Sprintf("encoded XSS pattern in %s", source),
		}
	}

	return nil
}

func (e *XSSEngine) GenerateCSP(nonce string) string {
	return strings.ReplaceAll(e.customCSP, "{nonce}", nonce)
}

func (e *XSSEngine) ScanResponse(body []byte) *Decision {
	if len(body) == 0 {
		return nil
	}

	bodyStr := string(body)

	for _, pattern := range e.htmlTags {
		if pattern.MatchString(bodyStr) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "XSS008",
				RuleName: "Reflected XSS",
				Severity: "critical",
				Score:    95,
				Evidence: "reflected XSS detected in response body",
			}
		}
	}

	return nil
}

// decodeEntities resolves numeric HTML entities and backslash octal/hex
// escapes to their characters. Fully-encoded payloads hide the literal tokens
// the sink rules search for; decoding them restores the match. Anything that
// is not a valid escape is left untouched.
func (e *XSSEngine) decodeEntities(value string) string {
	decoded := e.entityNumRE.ReplaceAllStringFunc(value, func(m string) string {
		// The trailing ';' is optional, so strip it only when present.
		body := m[2:]
		if strings.HasSuffix(body, ";") {
			body = body[:len(body)-1]
		}
		base := 10
		if len(body) > 1 && (body[0] == 'x' || body[0] == 'X') {
			body, base = body[1:], 16
		}
		code, err := strconv.ParseInt(body, base, 32)
		if err != nil || code <= 0 || code > 0x10FFFF {
			return m
		}
		return string(rune(code))
	})

	for _, re := range []*regexp.Regexp{e.octalEscapeRE, e.hexEscapeRE} {
		decoded = re.ReplaceAllStringFunc(decoded, func(m string) string {
			body := m[1:]
			if strings.HasPrefix(body, "x") || strings.HasPrefix(body, "X") {
				body = body[1:]
			}
			code, err := strconv.ParseInt(body, 16, 32)
			if err != nil || code <= 0 || code > 0x10FFFF {
				return m
			}
			return string(rune(code))
		})
	}

	return decoded
}
