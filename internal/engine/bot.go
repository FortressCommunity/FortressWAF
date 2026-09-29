package engine

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BotOptions tunes the repeat-offender auto-ban. Zero fields use the defaults;
// AutoBanAfter < 0 disables the counter and its ban entirely.
type BotOptions struct {
	AutoBanAfter    int           // bot-like requests per IP within the window
	AutoBanWindow   time.Duration // sliding window for the count
	AutoBanDuration time.Duration // ban length once the count is reached
}

type BotDetector struct {
	mu               sync.RWMutex
	devMode          bool
	goodBots         map[string]*regexp.Regexp
	badBots          []*regexp.Regexp
	headlessPatterns []*regexp.Regexp
	honeypotFields   []string

	autoBanAfter    int
	autoBanWindow   time.Duration
	autoBanDuration time.Duration
	botHits         map[string]*SlidingWindowCounter
	lastCleanup     time.Time
}

func NewBotDetector(devMode bool) *BotDetector {
	return NewBotDetectorWithOptions(devMode, BotOptions{})
}

func NewBotDetectorWithOptions(devMode bool, opts BotOptions) *BotDetector {
	if opts.AutoBanAfter == 0 {
		opts.AutoBanAfter = 5
	}
	if opts.AutoBanWindow <= 0 {
		opts.AutoBanWindow = time.Minute
	}
	if opts.AutoBanDuration == 0 {
		opts.AutoBanDuration = 10 * time.Minute
	}

	d := &BotDetector{
		devMode:         devMode,
		autoBanAfter:    opts.AutoBanAfter,
		autoBanWindow:   opts.AutoBanWindow,
		autoBanDuration: opts.AutoBanDuration,
		botHits:         make(map[string]*SlidingWindowCounter),
		lastCleanup:     time.Now(),
		goodBots: map[string]*regexp.Regexp{
			"googlebot":    regexp.MustCompile(`(?i)googlebot|google(?:-mobile|bot|adsense|structured-data|cloud-platform)`),
			"bingbot":      regexp.MustCompile(`(?i)bingbot|msnbot|bingpreview`),
			"yandexbot":    regexp.MustCompile(`(?i)yandexbot|yandeximages|yandexmetrika|yandexwebmaster`),
			"slurp":        regexp.MustCompile(`(?i)yahoo!\s+slurp|yahooseeker`),
			"baiduspider":  regexp.MustCompile(`(?i)baiduspider|baidugame`),
			"duckduckbot":  regexp.MustCompile(`(?i)duckduckbot`),
			"facebookbot":  regexp.MustCompile(`(?i)facebookexternalhit|facebookcatalog|facebot`),
			"twitterbot":   regexp.MustCompile(`(?i)twitterbot`),
			"linkedinbot":  regexp.MustCompile(`(?i)linkedinbot`),
			"slackbot":     regexp.MustCompile(`(?i)slackbot|slack-link-expand`),
			"discordbot":   regexp.MustCompile(`(?i)discordbot`),
			"telegrambot":  regexp.MustCompile(`(?i)telegrambot`),
			"applebot":     regexp.MustCompile(`(?i)applebot`),
			"semrushbot":   regexp.MustCompile(`(?i)semrushbot`),
			"ahrefsbot":    regexp.MustCompile(`(?i)ahrefsbot`),
			"majestic":     regexp.MustCompile(`(?i)majestic-seo`),
			"pinterest":    regexp.MustCompile(`(?i)pinterest`),
			"cloudflare":   regexp.MustCompile(`(?i)cloudflare`),
			"adidxbot":     regexp.MustCompile(`(?i)adidxbot`),
			"apple-pubsub": regexp.MustCompile(`(?i)apple-pubsub`),
			"zgrab":        regexp.MustCompile(`(?i)zgrab`),
		},
		honeypotFields: []string{
			// Only genuinely decoy field names belong here. A real contact or
			// signup form legitimately has "email", "phone", "address", and
			// "website" fields, so treating those as honeypots blocked ordinary
			// form submissions. Honeypot fields are instead conventionally
			// hidden and given a name no human form would use.
			"hp_", "honeypot", "botfield", "bot_field",
			"nocomment", "leaveblank", "dontfill", "do_not_fill",
			"trapfield", "trap_field", "hidden_field_for_bots",
		},
	}

	d.headlessPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)headless`),
		regexp.MustCompile(`(?i)puppeteer`),
		regexp.MustCompile(`(?i)playwright`),
		regexp.MustCompile(`(?i)selenium`),
		regexp.MustCompile(`(?i)phantomjs`),
		regexp.MustCompile(`(?i)htmlunit`),
		regexp.MustCompile(`(?i)phantom`),
		regexp.MustCompile(`(?i)chromium-headless`),
	}

	d.badBots = d.compileBadBotPatterns()

	return d
}

func (d *BotDetector) compileBadBotPatterns() []*regexp.Regexp {
	// Only genuine attack tooling belongs here. The previous list also matched
	// ordinary clients -- the bare word "java" matched "JavaScript" in real
	// browser UAs, and axios/okhttp/fetch/got/Postman are what legitimate mobile
	// apps and API consumers use -- so those were blocked as bots. Each pattern
	// is now anchored to a distinctive product token.
	patterns := []string{
		`(?i)\bmasscan\b`, `(?i)\bnmap\b`, `(?i)\bnessus\b`, `(?i)\bopenvas\b`,
		`(?i)\bnikto\b`, `(?i)\bsqlmap\b`, `(?i)\bdirbuster\b`, `(?i)\bgobuster\b`,
		`(?i)\bwpscan\b`, `(?i)\bjoomscan\b`, `(?i)\bdroopescan\b`,
		`(?i)\bacunetix\b`, `(?i)\bnetsparker\b`, `(?i)\bappscan\b`, `(?i)\bw3af\b`,
		`(?i)\bburpsuite\b`, `(?i)\bzap\b`, `(?i)\bparos\b`, `(?i)\bwebinspect\b`,
		`(?i)\bzgrab\b`, `(?i)\bzmap\b`, `(?i)\bmassdns\b`,
		`(?i)\bhydra\b`, `(?i)\bwfuzz\b`, `(?i)\bferoxbuster\b`, `(?i)\bffuf\b`,
		`(?i)\bnuclei\b`, `(?i)\bcommix\b`, `(?i)\bxray\b`, `(?i)\bwhatweb\b`,
	}
	// Note: "curl", "wget", "python-requests", and similar tools are NOT bad
	// bots. They are heavily used for legitimate automation, health checks, and
	// manual calls (the exhibition script itself uses curl); blocking them broke
	// ordinary traffic. Their requests are still inspected for attacks by every
	// other detector.

	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		result = append(result, regexp.MustCompile(p))
	}
	return result
}

func (d *BotDetector) Name() string { return "bot_detector" }

func (d *BotDetector) Inspect(ctx *RequestContext) (*Decision, error) {
	ua := ctx.UserAgent
	if ua == "" {
		// A request with no User-Agent is not a browser. Challenge it (rather
		// than silently monitor) and count it: a client that keeps doing this
		// is a scraper or a probe, and repeated offences auto-ban the address.
		return d.botlike(ctx, ActionChallenge, "BOT001", "Missing User-Agent", "medium", 30,
			"request has no user-agent header"), nil
	}

	for name, pattern := range d.goodBots {
		if pattern.MatchString(ua) {
			verified := d.verifyGoodBot(ctx)
			if !verified {
				return &Decision{
					Action:   ActionChallenge,
					RuleID:   "BOT002",
					RuleName: "Unverified Good Bot",
					Severity: "medium",
					Score:    25,
					Evidence: fmt.Sprintf("unverified good bot: %s", name),
				}, nil
			}
			ctx.IsBot = true
			if d.devMode {
				slog.Debug("verified good bot", "bot", name, "ip", ctx.RealIP)
			}
			return nil, nil
		}
	}

	for _, pattern := range d.headlessPatterns {
		if pattern.MatchString(ua) {
			return d.botlike(ctx, ActionBlock, "BOT003", "Headless Browser Detected", "high", 70,
				fmt.Sprintf("headless browser pattern detected: %s", ua)), nil
		}
	}

	for _, pattern := range d.badBots {
		if pattern.MatchString(ua) {
			return d.botlike(ctx, ActionBlock, "BOT004", "Bad Bot Detected", "high", 80,
				fmt.Sprintf("bad bot signature matched: %s", pattern.String())), nil
		}
	}

	if dec := d.detectHoneypot(ctx); dec != nil {
		return d.botlikeDecision(ctx, dec), nil
	}

	if dec := d.detectBrowserFeatures(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (d *BotDetector) verifyGoodBot(ctx *RequestContext) bool {
	ip := net.ParseIP(ctx.RealIP)
	if ip == nil {
		return false
	}

	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return false
	}

	name := strings.ToLower(names[0])
	for botName := range d.goodBots {
		if strings.Contains(name, botName) {
			return true
		}
	}

	if d.devMode {
		slog.Debug("good bot rDNS verification failed",
			"ip", ctx.RealIP,
			"ptr", name,
			"ua", ctx.UserAgent,
		)
	}

	return false
}

// botlike builds a bot decision and records one hit against the source address.
// Once an address reaches the repeat-offender threshold within the window, the
// decision asks the caller to ban it. Auto-ban is off when autoBanAfter < 0.
func (d *BotDetector) botlike(ctx *RequestContext, action Action, ruleID, name, severity string, score float64, evidence string) *Decision {
	return d.botlikeDecision(ctx, &Decision{
		Action:   action,
		RuleID:   ruleID,
		RuleName: name,
		Severity: severity,
		Score:    score,
		Evidence: evidence,
	})
}

// botlikeDecision attaches the repeat-offender count and ban request to an
// already-built bot decision.
func (d *BotDetector) botlikeDecision(ctx *RequestContext, dec *Decision) *Decision {
	if dec == nil || d.autoBanAfter < 0 || ctx.RealIP == "" {
		return dec
	}
	count := d.recordBotHit(ctx.RealIP)
	if count >= d.autoBanAfter && d.autoBanDuration > 0 {
		dec.BanRequest = true
		dec.BanDuration = d.autoBanDuration
		dec.Evidence = fmt.Sprintf("%s (bot-like request %d/%d in window)", dec.Evidence, count, d.autoBanAfter)
	}
	return dec
}

// recordBotHit increments the sliding count for an address and returns the new
// count. Entries are pruned lazily so the map cannot grow without bound.
func (d *BotDetector) recordBotHit(ip string) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if now.Sub(d.lastCleanup) > 5*time.Minute {
		for k, c := range d.botHits {
			if c.lastSeen().Before(now.Add(-2 * d.autoBanWindow)) {
				delete(d.botHits, k)
			}
		}
		d.lastCleanup = now
	}

	c, ok := d.botHits[ip]
	if !ok {
		c = &SlidingWindowCounter{window: d.autoBanWindow, maxCount: d.autoBanAfter + 1}
		d.botHits[ip] = c
	}
	c.record(now)
	return c.count()
}

func (d *BotDetector) detectHoneypot(ctx *RequestContext) *Decision {
	for k := range ctx.FormParams {
		lower := strings.ToLower(k)
		for _, field := range d.honeypotFields {
			if strings.HasPrefix(lower, field) || strings.Contains(lower, field) {
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "BOT005",
					RuleName: "Honeypot Field Triggered",
					Severity: "high",
					Score:    75,
					Evidence: fmt.Sprintf("honeypot field detected: %s", k),
				}
			}
		}
	}

	return nil
}

func (d *BotDetector) detectBrowserFeatures(ctx *RequestContext) *Decision {
	acceptLang := ctx.Headers["Accept-Language"]
	if acceptLang == "" {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "BOT006",
			RuleName: "Missing Accept-Language",
			Severity: "low",
			Score:    15,
			Evidence: "no accept-language header from supposedly browser request",
		}
	}

	accept := ctx.Headers["Accept"]
	if accept == "" {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "BOT007",
			RuleName: "Missing Accept Header",
			Severity: "low",
			Score:    10,
			Evidence: "no accept header from supposedly browser request",
		}
	}

	return nil
}

func (d *BotDetector) GenerateJSChallenge(ctx *RequestContext) string {
	return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Challenge</title>
<script>
(function(){
	var challenge = "` + ctx.RequestID + `";
	var result = "";
	var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
	for(var i=0;i<32;i++){result+=chars.charAt(Math.floor(Math.random()*chars.length));}
	document.cookie = "challenge="+result+":"+challenge+";path=/;max-age=300";
	window.location.reload();
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=?noscript=1"></noscript>
</head><body>Checking your browser...</body></html>`
}
