package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type ChallengeLevel int

const (
	ChallengeNone    ChallengeLevel = 0
	ChallengeJS      ChallengeLevel = 1
	ChallengeCAPTCHA ChallengeLevel = 2
	ChallengeTarpit  ChallengeLevel = 3
	ChallengeBlock   ChallengeLevel = 4
)

type AdaptiveChallenge struct {
	mu           sync.RWMutex
	devMode      bool
	jsScriptPath string
	tarpitDelay  time.Duration
	captchaScore float64
	challengeTTL time.Duration

	ipScores    map[string]*challengeState
	challenges  map[string]*issuedChallenge
	cleanupTick *time.Ticker
}

type challengeState struct {
	score      float64
	lastSeen   time.Time
	level      ChallengeLevel
	requestCnt int
}

type issuedChallenge struct {
	token     string
	ip        string
	level     ChallengeLevel
	expiresAt time.Time
	solved    bool
}

func NewAdaptiveChallenge(devMode bool, jsScriptPath string, tarpitDelayMs int, captchaScore float64, challengeTTL int) *AdaptiveChallenge {
	ac := &AdaptiveChallenge{
		devMode:      devMode,
		jsScriptPath: jsScriptPath,
		tarpitDelay:  time.Duration(tarpitDelayMs) * time.Millisecond,
		captchaScore: captchaScore,
		challengeTTL: time.Duration(challengeTTL) * time.Second,
		ipScores:     make(map[string]*challengeState),
		challenges:   make(map[string]*issuedChallenge),
		cleanupTick:  time.NewTicker(1 * time.Minute),
	}
	go ac.cleanupLoop()
	return ac
}

func (ac *AdaptiveChallenge) Name() string { return "adaptive" }

func (ac *AdaptiveChallenge) Inspect(ctx *RequestContext) (*Decision, error) {
	ip := ctx.RealIP
	if ip == "" {
		return nil, nil
	}

	token := ctx.Request.Header.Get("X-Challenge-Token")
	if token != "" {
		ac.mu.Lock()
		if c, ok := ac.challenges[token]; ok && !c.solved {
			c.solved = true
			delete(ac.challenges, token)

			ac.mu.Unlock()
			return &Decision{
				Action:   ActionAllow,
				RuleID:   "ADAPT_000",
				RuleName: "Challenge Solved",
				Severity: "info",
				Score:    0,
				Evidence: fmt.Sprintf("challenge solved for IP %s via token %s", ip, token),
			}, nil
		}
		ac.mu.Unlock()
	}

	state := ac.getOrCreateState(ip)
	state.requestCnt++

	if state.level >= ChallengeBlock {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "ADAPT_004",
			RuleName: "Adaptive Block",
			Severity: "critical",
			Score:    95,
			Evidence: fmt.Sprintf("IP %s blocked after adaptive escalation (score=%.1f)", ip, state.score),
		}, nil
	}

	existingScore := ctx.ThreatScore
	if existingScore <= 0 {
		existingScore = state.score
	}

	state.score = existingScore
	state.lastSeen = time.Now()

	level := ac.determineLevel(state)

	if level > state.level {
		state.level = level
	}

	switch state.level {
	case ChallengeJS:
		ct := ac.issueChallenge(ip, ChallengeJS)
		ac.mu.Lock()
		ac.challenges[ct] = &issuedChallenge{
			token:     ct,
			ip:        ip,
			level:     ChallengeJS,
			expiresAt: time.Now().Add(ac.challengeTTL),
		}
		ac.mu.Unlock()

		ctx.Response = nil
		return &Decision{
			Action:   ActionChallenge,
			RuleID:   "ADAPT_001",
			RuleName: "JS Challenge",
			Severity: "medium",
			Score:    30,
			Evidence: fmt.Sprintf("JS challenge issued for IP %s (score=%.1f)", ip, state.score),
		}, nil

	case ChallengeCAPTCHA:
		ct := ac.issueChallenge(ip, ChallengeCAPTCHA)
		ac.mu.Lock()
		ac.challenges[ct] = &issuedChallenge{
			token:     ct,
			ip:        ip,
			level:     ChallengeCAPTCHA,
			expiresAt: time.Now().Add(ac.challengeTTL),
		}
		ac.mu.Unlock()

		return &Decision{
			Action:   ActionChallenge,
			RuleID:   "ADAPT_002",
			RuleName: "CAPTCHA Challenge",
			Severity: "high",
			Score:    60,
			Evidence: fmt.Sprintf("CAPTCHA challenge issued for IP %s (score=%.1f)", ip, state.score),
		}, nil

	case ChallengeTarpit:
		delay := ac.tarpitDelay
		time.Sleep(delay)

		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "ADAPT_003",
			RuleName: "Tarpit Applied",
			Severity: "high",
			Score:    80,
			Evidence: fmt.Sprintf("tarpit delay of %v applied to IP %s (score=%.1f)", delay, ip, state.score),
		}, nil

	case ChallengeBlock:
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "ADAPT_004",
			RuleName: "Adaptive Block",
			Severity: "critical",
			Score:    95,
			Evidence: fmt.Sprintf("IP %s blocked after adaptive escalation (score=%.1f)", ip, state.score),
		}, nil
	}

	return nil, nil
}

func (ac *AdaptiveChallenge) determineLevel(state *challengeState) ChallengeLevel {
	score := state.score

	switch {
	case score >= 90:
		return ChallengeBlock
	case score >= 70:
		return ChallengeTarpit
	case score >= 50:
		return ChallengeCAPTCHA
	case score >= 20:
		return ChallengeJS
	default:
		return ChallengeNone
	}
}

func (ac *AdaptiveChallenge) getOrCreateState(ip string) *challengeState {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	state, ok := ac.ipScores[ip]
	if !ok {
		state = &challengeState{}
		ac.ipScores[ip] = state
	}
	return state
}

func (ac *AdaptiveChallenge) issueChallenge(ip string, level ChallengeLevel) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	h := sha256.Sum256(append(buf, []byte(ip)...))
	token := hex.EncodeToString(h[:16])
	return token
}

func (ac *AdaptiveChallenge) cleanupLoop() {
	for range ac.cleanupTick.C {
		ac.mu.Lock()
		now := time.Now()

		for token, c := range ac.challenges {
			if now.After(c.expiresAt) {
				delete(ac.challenges, token)
			}
		}

		for ip, state := range ac.ipScores {
			if now.After(state.lastSeen.Add(ac.challengeTTL * 2)) {
				delete(ac.ipScores, ip)
			}
		}
		ac.mu.Unlock()
	}
}

func (ac *AdaptiveChallenge) RecordEvent(ip string, score float64) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	state, ok := ac.ipScores[ip]
	if !ok {
		state = &challengeState{score: score, lastSeen: time.Now()}
		ac.ipScores[ip] = state
		return
	}

	state.score = score
	state.lastSeen = time.Now()
}

func JSChallengePage(path string) []byte {
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	challengeToken := hex.EncodeToString(tokenBytes)

	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;background:#1a1a2e;font-family:system-ui,monospace;color:#e0e0e0}
.card{text-align:center;padding:3rem;border:3px solid #e94560;background:#16213e;max-width:480px;width:90%%}
.card h2{color:#e94560;margin-bottom:1rem;font-size:1.5rem}
.spinner{width:40px;height:40px;border:4px solid #333;border-top:4px solid #e94560;border-radius:50%%;animation:spin 1s linear infinite;margin:1.5rem auto}
@keyframes spin{to{transform:rotate(360deg)}}
.card p{color:#aaa;font-size:0.9rem;line-height:1.5}
.card .footer{margin-top:1.5rem;font-size:0.8rem;color:#666}
</style>
</head>
<body>
<div class="card">
<h2>Security Verification</h2>
<div class="spinner"></div>
<p>Please wait while we verify your browser environment.</p>
<p id="status">Initializing...</p>
<div class="footer">FortressWAF &bull; Adaptive Challenge</div>
</div>
<form id="cf" action="/__challenge" method="POST" style="display:none">
<input type="hidden" name="challenge_token" value="%s">
<input type="hidden" name="original_path" value="%s">
</form>
<script>
(function(){
var results = [];
var checks = 0;
var required = 4;
var elapsed = Date.now() - (new Date()).getTimezoneOffset()*60000;
var start = Date.now();
var ua = navigator.userAgent.toLowerCase();
var pf = navigator.platform.toLowerCase();

results.push(ua.length > 10 ? 1 : 0);
results.push(pf.length > 0 ? 1 : 0);

var img = new Image();
var imgChecked = false;
img.onload = img.onerror = function(){ if(!imgChecked){ imgChecked=true; results.push(1); checks++; } };
setTimeout(function(){ if(!imgChecked){ imgChecked=true; results.push(0); checks++; } }, 500);

var canvas = document.createElement('canvas');
canvas.width = 200; canvas.height = 50;
var ctx = canvas.getContext('2d');
ctx.fillText('fortress', 10, 30);
var imgData = canvas.toDataURL();
results.push(imgData.length > 100 ? 1 : 0);

var cpuCores = (navigator.hardwareConcurrency || 1) > 1 ? 1 : 0;
results.push(cpuCores);

var webdriver = navigator.webdriver ? 0 : 1;
results.push(webdriver);

var pluginsLen = navigator.plugins.length > 0 ? 1 : 0;
results.push(pluginsLen);

checks += required;
var score = results.reduce(function(a,b){return a+b},0);
var maxScore = results.length;

function submitForm(){
document.getElementById('status').textContent = 'Verification complete. Redirecting...';
setTimeout(function(){
document.getElementById('cf').submit();
}, 500);
}

var waitTime = Math.max(1500, (Date.now() - start));
if(score >= maxScore * 0.6 && waitTime >= 1500){
document.getElementById('status').textContent = 'Browser verification passed.';
submitForm();
} else {
document.getElementById('status').textContent = 'Additional checks required...';
setTimeout(function(){ document.getElementById('status').textContent = 'Verifying...'; }, 2000);
setTimeout(submitForm, 3000);
}
})();
</script>
<noscript>
<div style="text-align:center;padding:2rem">
<p>JavaScript is required to pass the security check.</p>
<p><a href="/">Reload page</a></p>
</div>
</noscript>
</body>
</html>`, challengeToken, path))
}

func (ac *AdaptiveChallenge) Close() {
	ac.cleanupTick.Stop()
}

func init() {
	if slog.Default() == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(nil, nil)))
	}
}
