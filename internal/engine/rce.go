package engine

import (
	"fmt"
	"log/slog"
	"regexp"
	"sync"
)

type RCEInjection struct {
	mu            sync.RWMutex
	devMode       bool
	shellPatterns []*regexp.Regexp
	sstiPatterns  []*regexp.Regexp
	elPatterns    []*regexp.Regexp
	deserPatterns []*regexp.Regexp
	log4jPatterns []*regexp.Regexp
	fileInclusion []*regexp.Regexp
}

func NewRCEInjection(devMode bool) *RCEInjection {
	r := &RCEInjection{devMode: devMode}
	r.compilePatterns()
	return r
}

func (r *RCEInjection) Name() string { return "rce" }

func (r *RCEInjection) compilePatterns() {
	r.shellPatterns = []*regexp.Regexp{
		// Destructive/privilege commands after a shell metacharacter. Without
		// rm here, "; rm -rf /" sails through the engine.
		regexp.MustCompile(`(?i)(?:;\s*(?:id|whoami|pwd|ls|cat|nc|ncat|bash|sh|zsh|cmd|powershell|wget|curl|python|python3|perl|ruby|php|rm|mv|cp|dd|mkfs|chmod|chown|kill|killall|shutdown|reboot|useradd|userdel|passwd|crontab|history)\b)`),
		regexp.MustCompile(`(?i)(?:\|\s*(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell|wget|curl)\b)`),
		regexp.MustCompile("(?i)(?:`[^`]*?(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell|wget|curl)[^`]*?`)"),
		regexp.MustCompile(`(?i)(?:\$\([^)]*?(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell)[^)]*?\))`),
		regexp.MustCompile(`(?i)(?:\b(?:exec|passthru|shell_exec|system|proc_open|popen|pcntl_exec|eval|assert|create_function|call_user_func|array_map|preg_replace)\s*\()`),
		regexp.MustCompile(`(?i)(?:cmd\.exe|command\.com|%COMSPEC%)`),
		regexp.MustCompile(`(?i)(?:\|\||&&)\s*(?:id|whoami|pwd|dir|type|more|find)`),
		regexp.MustCompile(`(?i)(?:;\s*(?:echo|print|cat|type|dir)\s+[\w/\\:.~-]+)`),
		regexp.MustCompile(`(?i)(?:\$\(<\([\w\s/\\.-]+\)\))`),
		// Shell input/output redirection. Bound to a shell metacharacter or a
		// command name, otherwise "a<b and c>d" or "<header>" trips it.
		regexp.MustCompile(`(?i)(?:[;|&]\s*[\w.-]*\s*[<>]\s*[\w/\\.-]+)`),
		regexp.MustCompile(`(?i)(?:\b(?:cat|more|less|head|tail|sort|uniq|wc|tee|dd|read|exec)\s+[<>]\s*[\w/\\.-]+)`),
	}

	r.sstiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:{{[\s\S]*?(?:config|self|request|app|g|class|base|subclasses|import|open|popen|os|system|eval|exec|mro|__builtins__)[\s\S]*?}})`),
		regexp.MustCompile(`(?i)(?:{%[\s\S]*?(?:config|self|request|app|g|class|base|subclasses|import|open|popen|os|system|eval|exec)[\s\S]*?%})`),
		regexp.MustCompile(`(?i)(?:\$\{[\s\S]*?(?:class|forName|getRuntime|exec|invoke|newInstance|getMethod|access|process)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:#{[\s\S]*?(?:exec|system|eval|import|os|subprocess|open|read)[\s\S]*?})`),
		regexp.MustCompile(`(?i)(?:<%=?[\s\S]*?(?:exec|system|eval|Runtime|Process|cmd)[\s\S]*?%>)`),
		regexp.MustCompile(`(?i)(?:\${{[\s\S]*?(?:exec|system|eval|import|os|subprocess)[\s\S]*?}})`),
	}

	r.elPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\$\{[\s\S]*?(?:T\(|jndi|ldap|rmi|iiop|corba)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{[\s\S]*?(?:Runtime|ProcessBuilder|getRuntime|exec|forName|getMethod|invoke|newInstance)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{[\s\S]*?(?:application|session|request|pageContext|facesContext)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:%\{[\s\S]*?(?:exec|system|eval|java\.lang|Runtime)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{[\s\S]*?(?:@org\.apache|@java\.lang|@javax\.script)[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\#\{[\s\S]*?(?:exec|system|eval|java\.lang|Runtime)[\s\S]*?\})`),
	}

	r.deserPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:rO0|aced0005|H4sI|BAMARQ)`),
		regexp.MustCompile(`(?i)(?:\b(?:ObjectInputStream|readObject|unserialize|unserialize|deserialize|deserialize|pickle|loads)\b)`),
		regexp.MustCompile(`(?i)(?:\bysoserial\b|\bgadget\b|\bcommons-collections\b|\bcommons-collections4\b|\bC3P0\b|\bjavassist\b|\bjython\b|\brome\b|\bspring\b|\bhibernate\b)`),
		// The raw Java-serialization magic (AC ED 00 05) is covered in its hex
		// and base64 forms by "aced0005" / "rO0" above. A byte-class regexp for
		// the literal bytes does not work in Go (a rune-class like \xac matches
		// U+00AC, not the byte 0xAC), so it was removed rather than left as a
		// pattern that looks like it detects something but never matches.
		regexp.MustCompile(`(?i)(?:#002|#003)`),
		regexp.MustCompile(`(?i)(?:O:[0-9]+:"[^"]+":[0-9]+:\{)`),
		regexp.MustCompile(`(?i)(?:a:[0-9]+:\{i:[0-9]+;s:[0-9]+:")`),
		regexp.MustCompile(`(?i)(?:%00\*|%00[0-9a-f]{2}|\\\\x00)`),
		regexp.MustCompile(`(?i)(?:Dcs\.run|System\.Runtime|Microsoft\.CodeAnalysis)`),
	}

	r.log4jPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:\$\{jndi:ldap://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:rmi://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:dns://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:iiop://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:corba://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:nis://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:nds://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{jndi:[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:\$\{(?:lower|upper|env|sys|log4j|ctx|date|bundle):[\s\S]*?\})`),
	}

	r.fileInclusion = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:file://[\s\S]*?\})`),
		regexp.MustCompile(`(?i)(?:php://(?:input|filter|memory|temp|expect)\})`),
		regexp.MustCompile(`(?i)(?:\.\./\.\./|\.\.\\\.\.\\)`),
		regexp.MustCompile(`(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|/etc/hostname|/proc/self|/proc/environ)`),
		regexp.MustCompile(`(?i)(?:/windows/win\.ini|/boot\.ini|/autoexec\.bat|/windows/system32)`),
		regexp.MustCompile(`(?i)(?:include\(|include_once\(|require\(|require_once\(|fopen\(|file_get_contents\(|readfile\(|file\(|parse_ini_file\(|show_source\(|highlight_file\(\))`),
		regexp.MustCompile(`(?i)(?:data://|expect://|zip://|compress.zlib://|compress.bzip2://|phar://)`),
	}
}

func (r *RCEInjection) Inspect(ctx *RequestContext) (*Decision, error) {
	targets := r.extractTargets(ctx)

	for _, target := range targets {
		if dec := r.inspectValue(target.value, target.source); dec != nil {
			return dec, nil
		}
	}

	return nil, nil
}

type rceTarget struct {
	value  string
	source string
}

func (r *RCEInjection) extractTargets(ctx *RequestContext) []rceTarget {
	var targets []rceTarget
	for k, v := range ctx.QueryParams {
		for _, val := range v {
			targets = append(targets, rceTarget{value: val, source: fmt.Sprintf("query:%s", k)})
		}
	}
	for k, v := range ctx.FormParams {
		for _, val := range v {
			targets = append(targets, rceTarget{value: val, source: fmt.Sprintf("form:%s", k)})
		}
	}
	if ctx.Body != nil {
		targets = append(targets, rceTarget{value: string(ctx.Body), source: "body"})
	}
	for k, v := range ctx.Headers {
		targets = append(targets, rceTarget{value: v, source: fmt.Sprintf("header:%s", k)})
	}
	for k, v := range ctx.Cookies {
		targets = append(targets, rceTarget{value: v, source: fmt.Sprintf("cookie:%s", k)})
	}
	return targets
}

func (r *RCEInjection) inspectValue(value, source string) *Decision {
	if value == "" {
		return nil
	}

	for _, pattern := range r.shellPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE001",
				RuleName: "OS Command Injection",
				Severity: "critical",
				Score:    95,
				Evidence: fmt.Sprintf("shell metacharacter injection in %s", source),
			}
		}
	}

	for _, pattern := range r.sstiPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE002",
				RuleName: "SSTI Detected",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("SSTI pattern in %s", source),
			}
		}
	}

	for _, pattern := range r.elPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE003",
				RuleName: "EL Injection",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("EL injection pattern in %s", source),
			}
		}
	}

	for _, pattern := range r.deserPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE004",
				RuleName: "Deserialization Attack",
				Severity: "critical",
				Score:    95,
				Evidence: fmt.Sprintf("deserialization gadget chain in %s", source),
			}
		}
	}

	for _, pattern := range r.log4jPatterns {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE005",
				RuleName: "Log4Shell/JNDI Injection",
				Severity: "critical",
				Score:    100,
				Evidence: fmt.Sprintf("Log4Shell JNDI injection in %s", source),
			}
		}
	}

	for _, pattern := range r.fileInclusion {
		if pattern.MatchString(value) {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "RCE006",
				RuleName: "File Inclusion",
				Severity: "critical",
				Score:    85,
				Evidence: fmt.Sprintf("file inclusion detected in %s", source),
			}
		}
	}

	return nil
}

var _ = slog.Debug
