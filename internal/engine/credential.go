package engine

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

type CredentialProtection struct {
	mu              sync.RWMutex
	devMode         bool
	loginAttempts   map[string]*loginTracker
	passwordSpray   map[string]*sprayTracker
	bruteForce      map[string]*bruteForceTracker
	leakedCreds     map[string]bool
	hibpEnabled     bool
	lockoutDuration time.Duration
	// window is how long a burst of auth attempts stays "current". A new
	// attempt after a longer quiet period starts the count over.
	window time.Duration
	// loginPaths are the paths treated as authentication endpoints. Brute
	// force only ever counts requests to these (or POSTs carrying a
	// password); ordinary page and asset requests are never counted.
	loginPaths  []string
	maxAttempts int
}

type loginTracker struct {
	attempts  int
	firstSeen time.Time
	lastSeen  time.Time
	locked    bool
	lockoutAt time.Time
}

type sprayTracker struct {
	usernames map[string]int
	count     int
	lastSeen  time.Time
}

type bruteForceTracker struct {
	attempts  int
	backoff   time.Duration
	nextTry   time.Time
	firstSeen time.Time
}

func NewCredentialProtection(devMode bool, maxAttempts int, windowSec, blockDurationSec int, loginPaths []string) *CredentialProtection {
	paths := loginPaths
	if len(paths) == 0 {
		paths = []string{"/login", "/signin", "/auth", "/api/login"}
	}
	normalized := make([]string, 0, len(paths))
	for _, p := range paths {
		normalized = append(normalized, normalizeLoginPath(p))
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if blockDurationSec <= 0 {
		blockDurationSec = 3600
	}
	if windowSec <= 0 {
		windowSec = 300
	}
	return &CredentialProtection{
		devMode:         devMode,
		loginAttempts:   make(map[string]*loginTracker),
		passwordSpray:   make(map[string]*sprayTracker),
		bruteForce:      make(map[string]*bruteForceTracker),
		leakedCreds:     make(map[string]bool),
		hibpEnabled:     false,
		lockoutDuration: time.Duration(blockDurationSec) * time.Second,
		window:          time.Duration(windowSec) * time.Second,
		loginPaths:      normalized,
		maxAttempts:     maxAttempts,
	}
}

func normalizeLoginPath(path string) string {
	return strings.TrimSuffix(strings.ToLower(path), "/")
}

// isAuthAttempt reports whether ctx is an authentication attempt, which is all
// brute-force protection is meant to count. The previous implementation
// counted every request from an address and then rate-limited the whole
// address, so an ordinary browser - which fetches HTML, CSS and JS within the
// same second - was blocked by CRED006 on its third request.
func (c *CredentialProtection) isAuthAttempt(ctx *RequestContext) bool {
	if ctx.Method != "POST" {
		return false
	}
	if _, ok := ctx.FormParams["password"]; ok {
		return true
	}
	if _, ok := ctx.QueryParams["password"]; ok {
		return true
	}
	path := normalizeLoginPath(ctx.Path)
	for _, p := range c.loginPaths {
		if path == p {
			return true
		}
	}
	return false
}

func (c *CredentialProtection) Name() string { return "credential_protection" }

func (c *CredentialProtection) Inspect(ctx *RequestContext) (*Decision, error) {
	if dec := c.detectCredentialStuffing(ctx); dec != nil {
		return dec, nil
	}

	if dec := c.detectPasswordSpray(ctx); dec != nil {
		return dec, nil
	}

	if dec := c.detectBruteForce(ctx); dec != nil {
		return dec, nil
	}

	if dec := c.detectLeakedCredential(ctx); dec != nil {
		return dec, nil
	}

	if dec := c.validateJWT(ctx); dec != nil {
		return dec, nil
	}

	if dec := c.detectOAuthAbuse(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (c *CredentialProtection) detectCredentialStuffing(ctx *RequestContext) *Decision {
	if ctx.Method != "POST" {
		return nil
	}

	username := ctx.FormParams["username"]
	password := ctx.FormParams["password"]

	if len(username) == 0 || len(password) == 0 {
		username = ctx.QueryParams["username"]
		password = ctx.QueryParams["password"]
	}

	if len(username) == 0 || len(password) == 0 {
		return nil
	}

	userHash := fmt.Sprintf("%x", sha256.Sum256([]byte(username[0])))

	c.mu.Lock()
	defer c.mu.Unlock()

	tracker, exists := c.loginAttempts[userHash]
	if !exists {
		c.loginAttempts[userHash] = &loginTracker{
			attempts:  1,
			firstSeen: time.Now(),
			lastSeen:  time.Now(),
		}
		return nil
	}

	tracker.attempts++
	tracker.lastSeen = time.Now()

	if tracker.locked {
		if time.Since(tracker.lockoutAt) < c.lockoutDuration {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "CRED001",
				RuleName: "Account Locked",
				Severity: "high",
				Score:    80,
				Evidence: fmt.Sprintf("account locked until %v", tracker.lockoutAt.Add(c.lockoutDuration)),
			}
		}
		tracker.locked = false
		tracker.attempts = 0
		return nil
	}

	if tracker.attempts > c.maxAttempts*3 {
		tracker.locked = true
		tracker.lockoutAt = time.Now()
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED002",
			RuleName: "Credential Stuffing Detected",
			Severity: "critical",
			Score:    90,
			Evidence: fmt.Sprintf("credential stuffing: %d attempts for user hash %s", tracker.attempts, userHash[:8]),
		}
	}

	if tracker.attempts > c.maxAttempts {
		return &Decision{
			Action:   ActionRateLimit,
			RuleID:   "CRED003",
			RuleName: "Excessive Login Attempts",
			Severity: "medium",
			Score:    50,
			Evidence: fmt.Sprintf("%d login attempts for user", tracker.attempts),
		}
	}

	return nil
}

func (c *CredentialProtection) detectPasswordSpray(ctx *RequestContext) *Decision {
	password := ctx.FormParams["password"]
	if len(password) == 0 {
		password = ctx.QueryParams["password"]
	}
	if len(password) == 0 {
		return nil
	}

	passHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password[0])))[:16]

	c.mu.Lock()
	defer c.mu.Unlock()

	tracker, exists := c.passwordSpray[passHash]
	if !exists {
		c.passwordSpray[passHash] = &sprayTracker{
			usernames: make(map[string]int),
			count:     1,
			lastSeen:  time.Now(),
		}
		return nil
	}

	tracker.count++
	tracker.lastSeen = time.Now()

	uniqueUsernames := len(tracker.usernames)
	if uniqueUsernames >= 10 && tracker.count >= 50 {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED004",
			RuleName: "Password Spray Attack",
			Severity: "critical",
			Score:    90,
			Evidence: fmt.Sprintf("password spray detected: %d attempts across %d users", tracker.count, uniqueUsernames),
		}
	}

	if tracker.count >= 20 && uniqueUsernames >= 5 {
		return &Decision{
			Action:   ActionRateLimit,
			RuleID:   "CRED005",
			RuleName: "Potential Password Spray",
			Severity: "high",
			Score:    65,
			Evidence: fmt.Sprintf("potential password spray: %d attempts", tracker.count),
		}
	}

	return nil
}

func (c *CredentialProtection) detectBruteForce(ctx *RequestContext) *Decision {
	if !c.isAuthAttempt(ctx) {
		return nil
	}

	ip := ctx.RealIP
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	tracker, exists := c.bruteForce[ip]
	if !exists {
		c.bruteForce[ip] = &bruteForceTracker{
			attempts:  1,
			backoff:   1 * time.Second,
			nextTry:   now,
			firstSeen: now,
		}
		return nil
	}

	// A quiet period longer than the configured window starts a fresh burst,
	// so a user who mistyped a password earlier is not still locked out for
	// something they did hours ago.
	if now.Sub(tracker.firstSeen) > c.window {
		tracker.attempts = 1
		tracker.backoff = 1 * time.Second
		tracker.nextTry = now
		tracker.firstSeen = now
		return nil
	}

	tracker.attempts++

	if now.Before(tracker.nextTry) {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED006",
			RuleName: "Brute Force Blocked",
			Severity: "high",
			Score:    80,
			Evidence: fmt.Sprintf("brute force blocked for %s, backoff: %v", ip, tracker.backoff),
		}
	}

	switch {
	case tracker.attempts > 20:
		tracker.backoff = 30 * time.Minute
	case tracker.attempts > 10:
		tracker.backoff = 5 * time.Minute
	case tracker.attempts > 5:
		tracker.backoff = 30 * time.Second
	default:
		tracker.backoff = 1 * time.Second
	}

	tracker.nextTry = now.Add(tracker.backoff)

	return nil
}

func (c *CredentialProtection) detectLeakedCredential(ctx *RequestContext) *Decision {
	password := ctx.FormParams["password"]
	if len(password) == 0 {
		password = ctx.QueryParams["password"]
	}
	if len(password) == 0 {
		return nil
	}

	passHash := fmt.Sprintf("%X", sha256.Sum256([]byte(password[0])))

	if c.hibpEnabled {
		if c.leakedCreds[passHash] {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "CRED007",
				RuleName: "Leaked Credential",
				Severity: "critical",
				Score:    95,
				Evidence: "password matches known leaked credential database",
			}
		}
	}

	return nil
}

func (c *CredentialProtection) validateJWT(ctx *RequestContext) *Decision {
	authHeader := ctx.Headers["Authorization"]
	if authHeader == "" {
		return nil
	}

	if !strings.HasPrefix(strings.ToUpper(authHeader), "BEARER ") {
		return nil
	}

	token := authHeader[7:]
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED008",
			RuleName: "Malformed JWT",
			Severity: "high",
			Score:    70,
			Evidence: "jwt token does not have 3 parts",
		}
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED009",
			RuleName: "Invalid JWT Header Encoding",
			Severity: "high",
			Score:    65,
			Evidence: "invalid base64 encoding in jwt header",
		}
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil
	}

	if strings.EqualFold(header.Alg, "none") {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED010",
			RuleName: "JWT alg:none Attack",
			Severity: "critical",
			Score:    95,
			Evidence: "jwt with alg:none detected",
		}
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var payload struct {
		Exp int64 `json:"exp"`
		Nbf int64 `json:"nbf"`
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil
	}

	now := time.Now().Unix()
	if payload.Exp > 0 && now > payload.Exp {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "CRED013",
			RuleName: "Expired JWT",
			Severity: "medium",
			Score:    40,
			Evidence: "jwt token has expired",
		}
	}

	return nil
}

func (c *CredentialProtection) detectOAuthAbuse(ctx *RequestContext) *Decision {
	authHeader := ctx.Headers["Authorization"]
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token := authHeader[7:]
		if strings.Count(token, ".") == 2 {
			return nil
		}
	}

	stateParam := ctx.QueryParams["state"]
	if len(stateParam) > 0 {
		if len(stateParam[0]) > 2048 {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "CRED013",
				RuleName: "OAuth State Overflow",
				Severity: "medium",
				Score:    40,
				Evidence: "oauth state parameter exceeds maximum size",
			}
		}
	}

	return nil
}
