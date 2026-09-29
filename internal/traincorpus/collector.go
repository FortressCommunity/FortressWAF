// Package traincorpus accumulates high-confidence attack samples from the live
// request path into the ML engine's training data. Only blocks the engine is
// sure about are collected -- a rule match on a known attack family with a high
// score -- so the corpus stays clean. Everything lower-confidence is dropped,
// because training on uncertain data is worse than not training.
package traincorpus

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Sample is one collected attack, before it is written to a corpus file.
type Sample struct {
	RuleID     string
	Category   string // corpus subdirectory, e.g. "sql-injection"
	Payload    string
	Source     string // where in the request it was found
	ActorIP    string
	Score      float64
	ObservedAt time.Time
}

// Collector decides what is worth keeping and writes it to the corpus.
type Collector struct {
	mu      sync.Mutex
	dir     string
	seen    map[string]struct{}
	written int
	dropped int

	// trustedRules maps a rule-id prefix to the corpus category it belongs to.
	// A block only qualifies when its rule is in this map -- a named,
	// high-confidence attack family -- not an accumulated-score guess.
	trustedRules map[string]string
}

// ruleCategory maps rule-id prefixes to corpus categories. Only these rules
// produce training data.
var ruleCategory = map[string]string{
	"SQLI0":    "sql-injection",
	"XSS0":     "xss",
	"RCE0":     "rce",
	"CMD":      "command-injection",
	"SSTI":     "ssti",
	"LDAP":     "ldap-injection",
	"XXE":      "xxe",
	"DESER":    "deserialization",
	"WEBSHELL": "webshell",
	"PARSER_0": "path-traversal",
}

// NewCollector builds a collector writing under dir (the ml-engine data dir).
// A nil/empty dir disables collection.
func NewCollector(dir string) *Collector {
	return &Collector{
		dir:          dir,
		seen:         make(map[string]struct{}),
		trustedRules: ruleCategory,
	}
}

// Enabled reports whether collection is active.
func (c *Collector) Enabled() bool { return c != nil && c.dir != "" }

// Consider records a sample if it qualifies. It returns true when the sample
// was written. disqualifyReason is for logging.
func (c *Collector) Consider(s Sample) (kept bool, reason string) {
	if !c.Enabled() {
		return false, "collector disabled"
	}

	category, ok := c.categoryFor(s.RuleID)
	if !ok {
		return false, "rule is not a high-confidence attack family"
	}
	// A high-confidence block must also carry a high score; a low-score match
	// on a trusted rule is treated as uncertain and dropped.
	if s.Score < 70 {
		return false, "score below confidence floor"
	}
	payload := sanitizePayload(s.Payload)
	if payload == "" {
		return false, "empty payload after cleaning"
	}
	if isNoise(payload) {
		return false, "payload is noise, not an attack signature"
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := category + "\x00" + payload
	if _, dup := c.seen[key]; dup {
		return false, "duplicate"
	}
	c.seen[key] = struct{}{}

	path := filepath.Join(c.dir, category, "payloads.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		c.dropped++
		return false, fmt.Sprintf("mkdir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		c.dropped++
		return false, fmt.Sprintf("open: %v", err)
	}
	defer f.Close()

	line := fmt.Sprintf("%s\t# from %s at %s rule=%s\n", payload, s.ActorIP, s.ObservedAt.UTC().Format(time.RFC3339), s.RuleID)
	if _, err := f.WriteString(line); err != nil {
		c.dropped++
		return false, fmt.Sprintf("write: %v", err)
	}
	c.written++
	return true, "collected"
}

// Stats reports collection counters.
func (c *Collector) Stats() (written, dropped, unique int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written, c.dropped, len(c.seen)
}

func (c *Collector) categoryFor(ruleID string) (string, bool) {
	for prefix, cat := range c.trustedRules {
		if strings.HasPrefix(ruleID, prefix) {
			return cat, true
		}
	}
	return "", false
}

var whitespaceRE = regexp.MustCompile(`\s+`)

// sanitizePayload trims a payload to a single line and drops anything that
// would corrupt the corpus file (embedded newlines, NUL bytes, escaped tabs).
func sanitizePayload(p string) string {
	p = strings.ReplaceAll(p, "\x00", "")
	p = strings.ReplaceAll(p, "\r", " ")
	p = strings.ReplaceAll(p, "\n", " ")
	p = strings.ReplaceAll(p, "\t", " ")
	p = whitespaceRE.ReplaceAllString(p, " ")
	p = strings.TrimSpace(p)
	if len(p) > 2048 {
		p = p[:2048]
	}
	return p
}

// isNoise rejects lines that would poison the corpus. A payload must look like
// an attack, not prose that happened to contain a keyword: "please select the
// blue option" mentions "select" but has no SQL structure, while
// "1' OR '1'='1" and "<script>alert(1)</script>" do. A sample qualifies when it
// carries attack punctuation together with a keyword, or a structural signature
// on its own (quotes around a comparison, an HTML tag, a template expression).
func isNoise(p string) bool {
	if len(p) < 4 {
		return true
	}
	hasPunct := strings.ContainsAny(p, "'\"<>(){};=|&\\/`$%")
	hasKeyword := hasAttackKeyword(p)
	// Markup or template structure is an attack on its own.
	if structuralSignatureRE.MatchString(p) {
		return false
	}
	// Otherwise require both a keyword and punctuation, and not a sentence of
	// mostly plain words.
	if hasPunct && hasKeyword {
		return false
	}
	return true
}

// structuralSignatureRE matches shapes that are almost never prose: an HTML
// tag, a template expression, a command substitution, an LDAP filter, or a
// quote-wrapped comparison.
var structuralSignatureRE = regexp.MustCompile(`(?i)<\s*/?\s*[a-z][^>]*>|\{\{|\$\{|\$\(|\(\)|\[\[|@@|\|\||&&|'\s*(?:or|and)\s|"\s*(?:or|and)\s|=\s*'|'\s*=|--\s*$|#\s*$|\bunion\b\s+\bselect\b|\bselect\b[^;]*\bfrom\b|\.\./|%2e%2e`)

var attackKeywordRE = regexp.MustCompile(`(?i)\b(select|union|insert|update|delete|drop|exec|eval|system|script|alert|onerror|onload|jndi|ldap|xxe|entity|template|ssti|deserial|pickle|bash|cmd|powershell|passwd)\b`)

func hasAttackKeyword(p string) bool {
	return attackKeywordRE.MatchString(p)
}

// LoadCategory reads every payload currently in a category's corpus file,
// skipping comments, so callers can report corpus size.
func LoadCategory(dir, category string) ([]string, error) {
	f, err := os.Open(filepath.Join(dir, category, "payloads.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip the trailing " # from ..." annotation the collector adds.
		if i := strings.Index(line, "\t#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
