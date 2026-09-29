package engine

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

type TokenType int

const (
	TokenKeyword TokenType = iota
	TokenOperator
	TokenString
	TokenNumber
	TokenIdentifier
	TokenComment
	TokenPunctuation
	TokenFunction
	TokenUnknown
)

type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

type SQLInjectionEngine struct {
	mu         sync.RWMutex
	devMode    bool
	dialects   []string
	patterns   []*regexp.Regexp
	encodingRE *regexp.Regexp
	commentRE  *regexp.Regexp
	hexRE      *regexp.Regexp
	unicodeRE  *regexp.Regexp
	nullByteRE *regexp.Regexp
	base64RE   *regexp.Regexp
}

func NewSQLInjectionEngine(devMode bool) *SQLInjectionEngine {
	e := &SQLInjectionEngine{
		devMode: devMode,
		dialects: []string{
			"mysql", "postgresql", "mssql", "oracle", "sqlite",
			"mariadb", "db2", "informix", "sybase", "access",
			"firebird", "teradata", "hana", "redshift", "snowflake",
		},
	}

	e.encodingRE = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)`)
	e.commentRE = regexp.MustCompile(`(?is)(?:/\*.*?\*|--.*?$|#.*?$|--\s)`)
	e.hexRE = regexp.MustCompile(`(?i)(?:0x[0-9a-f]+|x'[0-9a-f]+'|unhex\(|hex\(|char\()`)
	e.unicodeRE = regexp.MustCompile(`(?i)(?:\\u[0-9a-f]{4}|%u[0-9a-f]{4}|nchar|n'|unicode\()`)
	e.nullByteRE = regexp.MustCompile(`\x00`)
	e.base64RE = regexp.MustCompile(`(?i)(?:base64_decode|base64_encode|from_base64|to_base64)`)

	e.compilePatterns()

	return e
}

func (e *SQLInjectionEngine) Name() string { return "sqli" }

func (e *SQLInjectionEngine) compilePatterns() {
	rawPatterns := []struct {
		id   string
		re   string
		desc string
		sev  string
	}{
		{"SQLI001", `(?i)(?:\b(?:union|union\s+all)\s+select\b)`, "UNION SELECT", "critical"},
		{"SQLI002", `(?i)(?:select\s+.*?\bfrom\b.*?\bwhere\b)`, "SELECT FROM WHERE", "high"},
		// SQLI003: DML/DDL keywords on their own are ordinary English
		// ("delete my account", "insert coin", "update your profile"), so the
		// pattern requires the keyword to be followed by SQL structure.
		{"SQLI003", `(?i)(?:\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b|\b(?:drop|truncate)\s+(?:table|database|schema|index|view)\b|\balter\s+(?:table|database|schema)\b|\bcreate\s+(?:table|database|schema|index|view|user)\b|\breplace\s+into\b)`, "DML/DDL with SQL context", "critical"},
		{"SQLI004", `(?i)(?:\b(?:exec|execute|exec_sp|xp_cmdshell|sp_executesql)\b)`, "Procedure Execution", "critical"},
		{"SQLI005", `(?i)(?:'.*\b(?:or|and)\b.*['\"])`, "SQL tautology", "high"},
		{"SQLI006", `(?i)(?:'.*\s*=\s*'.*--|'.*=\s*'.*#)`, "SQL comment injection", "high"},
		{"SQLI007", `(?i)(?:sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(`, "Time-based blind", "critical"},
		{"SQLI008", `(?i)(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1)`, "Boolean-based", "high"},
		{"SQLI009", `(?i)(?:';.*--|';.*#|'\)\s*;?\s*--)`, "SQL quote injection", "critical"},
		{"SQLI010", `(?i)(?:pg_sleep|waitfor|delay|sleep|benchmark|if)\s*\(`, "Time-based functions", "critical"},
		{"SQLI011", `(?i)(?:\b(?:information_schema|mysql\.|pg_catalog|sys\.|sqlite_master)\b)`, "Schema enumeration", "high"},
		{"SQLI012", `(?i)(?:@@version|version\(\)|@@servername|db_name\(\))`, "DB version probing", "medium"},
		{"SQLI013", `(?i)(?:into\s+(?:outfile|dumpfile|load_file)\b)`, "File operations", "critical"},
		{"SQLI014", `(?i)(?:conv|char|nchar|hex|unhex|ord|ascii)\s*\(`, "String functions injection", "high"},
		{"SQLI015", `(?i)(?:admin'|'admin|\bor\b.*\badmin\b|\badmin\b.*\bor\b)`, "Admin bypass", "high"},
	}

	for _, p := range rawPatterns {
		e.patterns = append(e.patterns, regexp.MustCompile(p.re))
	}
}

func (e *SQLInjectionEngine) Inspect(ctx *RequestContext) (*Decision, error) {
	targets := e.extractTargets(ctx)

	for _, target := range targets {
		if dec := e.inspectValue(target.value, target.source); dec != nil {
			return dec, nil
		}
	}

	return nil, nil
}

type targetValue struct {
	value  string
	source string
}

func (e *SQLInjectionEngine) extractTargets(ctx *RequestContext) []targetValue {
	var targets []targetValue

	for k, v := range ctx.QueryParams {
		for _, val := range v {
			targets = append(targets, targetValue{value: val, source: fmt.Sprintf("query:%s", k)})
		}
	}

	for k, v := range ctx.FormParams {
		for _, val := range v {
			targets = append(targets, targetValue{value: val, source: fmt.Sprintf("form:%s", k)})
		}
	}

	if ctx.Body != nil {
		targets = append(targets, targetValue{value: string(ctx.Body), source: "body"})
	}

	for k, v := range ctx.Headers {
		targets = append(targets, targetValue{value: v, source: fmt.Sprintf("header:%s", k)})
	}

	for k, v := range ctx.Cookies {
		targets = append(targets, targetValue{value: v, source: fmt.Sprintf("cookie:%s", k)})
	}

	return targets
}

func (e *SQLInjectionEngine) inspectValue(value, source string) *Decision {
	if value == "" {
		return nil
	}

	original := value

	if dec := e.detectEncodingBypass(value, source); dec != nil {
		return dec
	}

	value = e.normalizeInput(value)

	tokens := e.tokenize(value)
	if dec := e.analyzeTokens(tokens, value, source); dec != nil {
		return dec
	}

	// Pattern matching also runs against the unnormalized input: comment
	// stripping is what makes "; DROP TABLE x--" legible to the tokenizer, but
	// it also deletes the "--" that SQLI009 keys on, so a payload can be
	// normalized straight past every rule.
	for _, pattern := range e.patterns {
		if pattern.MatchString(value) || pattern.MatchString(original) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "SQLI016",
				RuleName: "SQL Pattern Match",
				Severity: "high",
				Score:    75,
				Evidence: fmt.Sprintf("SQL injection pattern matched in %s: %q", source, original[:min(len(original), 200)]),
			}
		}
	}

	return nil
}

// sqlKeywordInContext reports whether the keyword at tokens[i] is followed by
// SQL structure, which is what distinguishes "drop table users" from
// "drop-off location". Lookahead is bounded and skips nothing but comments,
// since the tokenizer already dropped whitespace.
func sqlKeywordInContext(tokens []Token, i int) bool {
	// next returns the value of the j-th token after i that is not a comment.
	next := func(offset int) (string, bool) {
		for j := i + 1; j < len(tokens) && offset > 0; j++ {
			if tokens[j].Type == TokenComment {
				continue
			}
			offset--
			return strings.ToUpper(tokens[j].Value), true
		}
		return "", false
	}

	switch strings.ToUpper(tokens[i].Value) {
	case "SELECT":
		// SELECT ... FROM, or SELECT * which is already caught by SQLI001/002.
		for j := i + 1; j < len(tokens) && j <= i+10; j++ {
			if tokens[j].Type == TokenComment {
				continue
			}
			if tokens[j].Type == TokenKeyword && strings.ToUpper(tokens[j].Value) == "FROM" {
				return true
			}
		}
		return false
	case "UNION":
		v, ok := next(1)
		return ok && (v == "SELECT" || v == "ALL")
	case "DROP", "TRUNCATE", "ALTER", "CREATE":
		v, ok := next(1)
		if !ok {
			return false
		}
		return v == "TABLE" || v == "DATABASE" || v == "SCHEMA" || v == "INDEX" || v == "VIEW" || v == "USER"
	case "EXEC", "EXECUTE":
		// EXEC followed by an identifier or a call, e.g. exec(@cmd).
		v, ok := next(1)
		return ok && (v == "(" || v != ";")
	}
	return true
}

func (e *SQLInjectionEngine) detectEncodingBypass(value, source string) *Decision {
	if e.nullByteRE.MatchString(value) {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "SQLI017",
			RuleName: "Null Byte Injection",
			Severity: "high",
			Score:    70,
			Evidence: fmt.Sprintf("null byte detected in %s", source),
		}
	}

	if dec := e.detectDoubleEncoding(value, source); dec != nil {
		return dec
	}

	if e.hexRE.MatchString(value) {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "SQLI019",
			RuleName: "Hex Encoding",
			Severity: "medium",
			Score:    40,
			Evidence: fmt.Sprintf("hex encoding detected in %s", source),
		}
	}

	if e.base64RE.MatchString(value) {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "SQLI020",
			RuleName: "Base64 Encoding",
			Severity: "medium",
			Score:    35,
			Evidence: fmt.Sprintf("base64 function detected in %s", source),
		}
	}

	return nil
}

// detectDoubleEncoding flags a value that decodes a second time into a SQL
// metacharacter. A single extra decode is applied; if it introduces a quote,
// comment, semicolon, or comparison operator that was not already there, the
// payload is trying to slip a metacharacter past a decoder that only runs once.
//
// This replaces a raw %25XX regex that blocked any value containing "%25"
// followed by two hex-ish characters -- a referring URL, a promo cookie, a page
// slug -- with no SQL context. Only a character that actually matters to SQL
// counts, so "%2520" (a space) passes while "%2527" (a quote) is caught.
func (e *SQLInjectionEngine) detectDoubleEncoding(value, source string) *Decision {
	// After a single decode (which the query/form parser already applied), a
	// double-encoded payload still carries escapes: "1%2527..." reaches us as
	// "1%27...". Decode once more and test the result for a real SQL pattern.
	// Blocking on the presence of a metacharacter alone is wrong -- a normal
	// URL-encoded value (a JSON cookie, a referring URL) yields quotes and
	// slashes on a single decode -- so the decoded text must actually look like
	// SQL before this fires.
	if !strings.Contains(value, "%") {
		return nil
	}
	decoded, changed := percentDecodeOnce(value)
	if !changed || decoded == value {
		return nil
	}
	// The decoded text must introduce a SQL metacharacter the original did not
	// have, and must match a SQL pattern once normalized.
	if !introducesMetaChar(value, decoded) {
		return nil
	}
	normalized := e.normalizeInput(decoded)
	for _, pattern := range e.patterns {
		if pattern.MatchString(decoded) || pattern.MatchString(normalized) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "SQLI018",
				RuleName: "Double Encoding",
				Severity: "high",
				Score:    75,
				Evidence: fmt.Sprintf("double encoding hides SQL in %s", source),
			}
		}
	}
	if dec := e.analyzeTokens(e.tokenize(normalized), decoded, source); dec != nil && dec.Action == ActionBlock {
		dec.RuleID = "SQLI018"
		dec.RuleName = "Double Encoding"
		return dec
	}
	return nil
}

// introducesMetaChar reports whether decoding added a SQL metacharacter that
// was not present in the original text.
func introducesMetaChar(original, decoded string) bool {
	for i := 0; i < len(decoded); i++ {
		if sqlMetaByte(decoded[i]) && strings.IndexByte(original, decoded[i]) < 0 {
			return true
		}
	}
	return false
}

// sqlMetaByte reports whether a decoded byte is a character that only appears
// in SQL attack payloads -- a string quote, a statement terminator, or the raw
// material of a comment. Common URL characters (/ - = ( ) *) are excluded on
// purpose: a referring URL decodes "%2F" to "/" on every request, and treating
// that as double-encoded SQLi blocked ordinary traffic.
func sqlMetaByte(c byte) bool {
	switch c {
	case '\'', '"', ';', '#', '\x00', '\n', '\r':
		return true
	}
	return false
}

func (e *SQLInjectionEngine) normalizeInput(input string) string {
	result := e.commentRE.ReplaceAllString(input, " ")
	result = e.encodingRE.ReplaceAllString(result, "X")
	return result
}

func (e *SQLInjectionEngine) tokenize(input string) []Token {
	var tokens []Token
	i := 0
	runes := []rune(input)

	for i < len(runes) {
		ch := runes[i]

		if unicode.IsSpace(ch) {
			i++
			continue
		}

		if ch == '\'' || ch == '"' {
			start := i
			i++
			for i < len(runes) && runes[i] != ch {
				if runes[i] == '\\' {
					i++
				}
				i++
			}
			if i < len(runes) {
				i++
			}
			tokens = append(tokens, Token{Type: TokenString, Value: string(runes[start:i]), Pos: start})
			continue
		}

		if ch == '/' && i+1 < len(runes) && runes[i+1] == '*' {
			end := i + 2
			for end+1 < len(runes) && !(runes[end] == '*' && runes[end+1] == '/') {
				end++
			}
			if end+1 < len(runes) {
				end += 2
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: string(runes[i:end]), Pos: i})
			i = end
			continue
		}

		if ch == '-' && i+1 < len(runes) && runes[i+1] == '-' {
			end := i + 2
			for end < len(runes) && runes[end] != '\n' {
				end++
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: string(runes[i:end]), Pos: i})
			i = end
			continue
		}

		if ch == '#' && i+1 < len(runes) {
			end := i + 1
			for end < len(runes) && runes[end] != '\n' {
				end++
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: string(runes[i:end]), Pos: i})
			i = end
			continue
		}

		if unicode.IsDigit(ch) || (ch == '.' && i+1 < len(runes) && unicode.IsDigit(runes[i+1])) {
			start := i
			for i < len(runes) && (unicode.IsDigit(runes[i]) || runes[i] == '.') {
				i++
			}
			tokens = append(tokens, Token{Type: TokenNumber, Value: string(runes[start:i]), Pos: start})
			continue
		}

		if unicode.IsLetter(ch) || ch == '_' {
			start := i
			for i < len(runes) && (unicode.IsLetter(runes[i]) || unicode.IsDigit(runes[i]) || runes[i] == '_') {
				i++
			}
			word := string(runes[start:i])
			upper := strings.ToUpper(word)
			keywords := map[string]bool{
				"SELECT": true, "UNION": true, "FROM": true, "WHERE": true,
				"INSERT": true, "UPDATE": true, "DELETE": true, "DROP": true,
				"CREATE": true, "ALTER": true, "TABLE": true, "INTO": true,
				"VALUES": true, "SET": true, "AND": true, "OR": true,
				"NOT": true, "NULL": true, "LIKE": true, "BETWEEN": true,
				"IN": true, "EXISTS": true, "HAVING": true, "GROUP": true,
				"ORDER": true, "BY": true, "LIMIT": true, "OFFSET": true,
				"JOIN": true, "LEFT": true, "RIGHT": true, "INNER": true,
				"OUTER": true, "ON": true, "AS": true, "CASE": true,
				"WHEN": true, "THEN": true, "ELSE": true, "END": true,
				"EXEC": true, "EXECUTE": true, "SLEEP": true, "BENCHMARK": true,
				"PG_SLEEP": true, "WAITFOR": true, "DELAY": true,
			}
			if keywords[upper] {
				tokens = append(tokens, Token{Type: TokenKeyword, Value: word, Pos: start})
			} else if i < len(runes) && runes[i] == '(' {
				tokens = append(tokens, Token{Type: TokenFunction, Value: word, Pos: start})
			} else {
				tokens = append(tokens, Token{Type: TokenIdentifier, Value: word, Pos: start})
			}
			continue
		}

		if strings.ContainsRune("=<>!+-*/%&|^~", ch) {
			start := i
			if i+1 < len(runes) && strings.ContainsRune("=<>", runes[i+1]) {
				i++
			}
			i++
			tokens = append(tokens, Token{Type: TokenOperator, Value: string(runes[start:i]), Pos: start})
			continue
		}

		if strings.ContainsRune("()[]{};,", ch) {
			tokens = append(tokens, Token{Type: TokenPunctuation, Value: string(ch), Pos: i})
			i++
			continue
		}

		tokens = append(tokens, Token{Type: TokenUnknown, Value: string(ch), Pos: i})
		i++
	}

	return tokens
}

func (e *SQLInjectionEngine) analyzeTokens(tokens []Token, original, source string) *Decision {
	keywordCount := 0
	stringCount := 0
	operatorCount := 0
	hasSemicolon := false

	// Token positions of keywords and semicolons. Stacked queries chain
	// statements ("; SELECT ..."), so a real payload has a keyword right next
	// to a semicolon. Ordinary text is full of both without them being
	// adjacent — every browser User-Agent contains "like" and ";" — so
	// counting keywords alone would block all browser traffic.
	var keywordPos, semicolonPos []int

	for idx, t := range tokens {
		switch t.Type {
		case TokenKeyword:
			keywordCount++
			keywordPos = append(keywordPos, idx)
			upper := strings.ToUpper(t.Value)
			if upper == "UNION" || upper == "SELECT" || upper == "DROP" ||
				upper == "EXEC" || upper == "EXECUTE" {
				// "union square", "drop-off", "select your size" are ordinary
				// text. Only block when the keyword sits in SQL context.
				if !sqlKeywordInContext(tokens, idx) {
					continue
				}
				return &Decision{
					Action:   ActionBlock,
					RuleID:   "SQLI021",
					RuleName: "SQL Keyword Injection",
					Severity: "critical",
					Score:    90,
					Evidence: fmt.Sprintf("dangerous SQL keyword %q in SQL context in %s", t.Value, source),
				}
			}
		case TokenString:
			stringCount++
		case TokenOperator:
			operatorCount++
		case TokenPunctuation:
			if t.Value == ";" {
				hasSemicolon = true
				semicolonPos = append(semicolonPos, idx)
			}
		}
	}

	if hasSemicolon && keywordCount > 0 && keywordNextToSemicolon(keywordPos, semicolonPos) {
		return &Decision{
			Action:   ActionBlock,
			RuleID:   "SQLI022",
			RuleName: "SQL Statement Chaining",
			Severity: "critical",
			Score:    85,
			Evidence: fmt.Sprintf("SQL statement chaining detected in %s", source),
		}
	}

	if keywordCount >= 2 && stringCount >= 1 {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "SQLI023",
			RuleName: "SQL-like Injection Pattern",
			Severity: "high",
			Score:    60,
			Evidence: fmt.Sprintf("SQL-like token pattern in %s: %d keywords, %d strings", source, keywordCount, stringCount),
		}
	}

	return nil
}

// keywordNextToSemicolon reports whether any keyword sits within two tokens of
// any semicolon, leaving room for a comment or filler token between them. That
// is the shape of a stacked query ("; DROP TABLE x", "1;DELETE FROM u"), as
// opposed to prose where the keyword and the semicolon are unrelated
// ("(X11; Linux x86_64) ... (KHTML, like Gecko)").
func keywordNextToSemicolon(keywordPos, semicolonPos []int) bool {
	for _, k := range keywordPos {
		for _, s := range semicolonPos {
			if d := k - s; d <= 2 && d >= -2 {
				return true
			}
		}
	}
	return false
}
