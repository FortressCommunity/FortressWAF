// Package uaparse turns a User-Agent string into a short, human-readable
// browser/OS/device summary for the request log. It is deliberately a small
// heuristic parser, not a full UA database: the console needs "Chrome 120 on
// Android" or "curl", which a bounded set of ordered patterns answers reliably
// and without a dependency.
package uaparse

import (
	"regexp"
	"strings"
)

// Info is the parsed summary of one User-Agent.
type Info struct {
	Browser string `json:"browser"` // e.g. "Chrome 120", "curl", "sqlmap"
	OS      string `json:"os"`      // e.g. "Android 14", "Windows 10"
	Device  string `json:"device"`  // desktop | mobile | tablet | bot | tool
	Raw     string `json:"raw"`
}

type rule struct {
	name string
	re   *regexp.Regexp
}

// Ordered so a more specific token wins: a Chrome-on-Android UA mentions
// Safari and AppleWebKit, so Chrome is tested first.
var browserRules = []rule{
	{"Edg", regexp.MustCompile(`(?i)Edg(?:e|A|iOS)?/([0-9]+)`)},
	{"OPR", regexp.MustCompile(`(?i)OPR/([0-9]+)`)},
	{"SamsungBrowser", regexp.MustCompile(`(?i)SamsungBrowser/([0-9]+)`)},
	{"Chrome", regexp.MustCompile(`(?i)Chrome/([0-9]+)`)},
	{"Firefox", regexp.MustCompile(`(?i)Firefox/([0-9]+)`)},
	{"Safari", regexp.MustCompile(`(?i)Version/([0-9]+)[^ ]*(?: [^ ]+)*? Safari`)},
	{"curl", regexp.MustCompile(`(?i)\bcurl/([0-9]+)`)},
	{"Wget", regexp.MustCompile(`(?i)\bWget/([0-9]+)`)},
	{"python-requests", regexp.MustCompile(`(?i)python-requests/([0-9]+)`)},
	{"Go-http-client", regexp.MustCompile(`(?i)Go-http-client/([0-9]+)`)},
	{"okhttp", regexp.MustCompile(`(?i)okhttp/([0-9]+)`)},
	{"axios", regexp.MustCompile(`(?i)\baxios/([0-9]+)`)},
	{"Postman", regexp.MustCompile(`(?i)PostmanRuntime/([0-9]+)`)},
}

// Attack tooling, checked first so the console labels it clearly.
var botRules = []rule{
	{"sqlmap", regexp.MustCompile(`(?i)sqlmap`)},
	{"Nikto", regexp.MustCompile(`(?i)nikto`)},
	{"Nmap", regexp.MustCompile(`(?i)nmap`)},
	{"masscan", regexp.MustCompile(`(?i)masscan`)},
	{"gobuster", regexp.MustCompile(`(?i)gobuster`)},
	{"dirbuster", regexp.MustCompile(`(?i)dirbuster`)},
	{"wpscan", regexp.MustCompile(`(?i)wpscan`)},
	{"Fuzz Faster U Fool", regexp.MustCompile(`(?i)\bffuf\b`)},
	{"Nuclei", regexp.MustCompile(`(?i)nuclei`)},
	{"Hydra", regexp.MustCompile(`(?i)\bhydra\b`)},
	{"Acunetix", regexp.MustCompile(`(?i)acunetix`)},
	{"Burp Suite", regexp.MustCompile(`(?i)burp(?:suite)?`)},
}

// Search/spider bots worth naming, but not attacks.
var spiderRules = []rule{
	{"Googlebot", regexp.MustCompile(`(?i)googlebot`)},
	{"Bingbot", regexp.MustCompile(`(?i)bingbot`)},
	{"DuckDuckBot", regexp.MustCompile(`(?i)duckduckbot`)},
	{"YandexBot", regexp.MustCompile(`(?i)yandexbot`)},
	{"Baiduspider", regexp.MustCompile(`(?i)baiduspider`)},
	{"FacebookBot", regexp.MustCompile(`(?i)facebookexternalhit`)},
	{"Twitterbot", regexp.MustCompile(`(?i)twitterbot`)},
}

var osRules = []rule{
	{"Android", regexp.MustCompile(`(?i)Android[ /]([0-9]+(?:\.[0-9]+)?)`)},
	{"iOS", regexp.MustCompile(`(?i)(?:iPhone OS|CPU OS)[ /]([0-9_]+)`)},
	{"Windows", regexp.MustCompile(`(?i)Windows NT ([0-9]+\.[0-9]+)`)},
	{"macOS", regexp.MustCompile(`(?i)Mac OS X ([0-9_]+)`)},
	{"Linux", regexp.MustCompile(`(?i)Linux`)},
	{"Chrome OS", regexp.MustCompile(`(?i)CrOS`)},
}

// Parse returns the browser/OS/device summary for a UA string.
func Parse(ua string) Info {
	info := Info{Raw: ua}
	ua = strings.TrimSpace(ua)
	if ua == "" {
		info.Browser = "unknown"
		info.Device = "unknown"
		return info
	}

	for _, r := range botRules {
		if r.re.MatchString(ua) {
			info.Browser = r.name
			info.Device = "bot"
			info.OS = matchOS(ua)
			return info
		}
	}
	for _, r := range spiderRules {
		if r.re.MatchString(ua) {
			info.Browser = r.name
			info.Device = "bot"
			info.OS = matchOS(ua)
			return info
		}
	}

	for _, r := range browserRules {
		if m := r.re.FindStringSubmatch(ua); m != nil {
			if len(m) > 1 && m[1] != "" {
				info.Browser = r.name + " " + cleanVersion(m[1])
			} else {
				info.Browser = r.name
			}
			break
		}
	}
	if info.Browser == "" {
		info.Browser = "other"
	}

	info.OS = matchOS(ua)
	info.Device = matchDevice(ua, info.Browser)
	return info
}

func matchOS(ua string) string {
	for _, r := range osRules {
		if m := r.re.FindStringSubmatch(ua); m != nil {
			if len(m) > 1 && m[1] != "" {
				return r.name + " " + strings.ReplaceAll(m[1], "_", ".")
			}
			return r.name
		}
	}
	return ""
}

func matchDevice(ua string, browser string) string {
	if strings.Contains(strings.ToLower(browser), "curl") ||
		strings.Contains(strings.ToLower(browser), "wget") ||
		strings.Contains(strings.ToLower(browser), "go-http") ||
		strings.Contains(strings.ToLower(browser), "python") ||
		strings.Contains(strings.ToLower(browser), "okhttp") ||
		strings.Contains(strings.ToLower(browser), "axios") ||
		strings.Contains(strings.ToLower(browser), "postman") {
		return "tool"
	}
	if regexp.MustCompile(`(?i)iPad|Tablet`).MatchString(ua) {
		return "tablet"
	}
	if regexp.MustCompile(`(?i)Mobile|iPhone|Android`).MatchString(ua) {
		return "mobile"
	}
	return "desktop"
}

func cleanVersion(v string) string {
	v = strings.ReplaceAll(v, "_", ".")
	if i := strings.IndexAny(v, ". "); i > 0 {
		return v[:i]
	}
	return v
}
