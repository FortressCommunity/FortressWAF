package uaparse

import "testing"

func TestParseRealBrowsers(t *testing.T) {
	cases := []struct {
		ua      string
		browser string
		device  string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Chrome 120", "desktop"},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", "Chrome 120", "mobile"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", "Safari 17", "mobile"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15", "Safari 17", "desktop"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox 121", "desktop"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91", "Edg 120", "desktop"},
		{"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1", "Safari 17", "tablet"},
	}
	for _, c := range cases {
		info := Parse(c.ua)
		if info.Browser != c.browser {
			t.Errorf("browser(%q) = %q, want %q", c.ua, info.Browser, c.browser)
		}
		if info.Device != c.device {
			t.Errorf("device(%q) = %q, want %q", c.ua, info.Device, c.device)
		}
	}
}

func TestParseToolsAndBots(t *testing.T) {
	cases := []struct {
		ua     string
		want   string
		device string
	}{
		{"curl/8.0.1", "curl 8", "tool"},
		{"python-requests/2.31.0", "python-requests 2", "tool"},
		{"sqlmap/1.7#stable (https://sqlmap.org)", "sqlmap", "bot"},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot", "bot"},
		{"", "unknown", "unknown"},
	}
	for _, c := range cases {
		info := Parse(c.ua)
		if info.Browser != c.want {
			t.Errorf("browser(%q) = %q, want %q", c.ua, info.Browser, c.want)
		}
		if info.Device != c.device {
			t.Errorf("device(%q) = %q, want %q", c.ua, info.Device, c.device)
		}
	}
}

func TestParseOS(t *testing.T) {
	info := Parse("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	if info.OS != "Android 14" {
		t.Errorf("OS = %q, want %q", info.OS, "Android 14")
	}
}
