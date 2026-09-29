//! User-Agent parsing into a browser/OS/device summary.
//!
//! Port of `internal/uaparse/parse.go`. Rule sets and their order are preserved
//! exactly (bot rules, then spiders, then browsers, then OS/device).

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Info {
    pub browser: String,
    pub os: String,
    pub device: String,
    pub raw: String,
}

struct Rule {
    name: &'static str,
    re: Regex,
}

fn rules(specs: &[(&'static str, &str)]) -> Vec<Rule> {
    specs
        .iter()
        .map(|(name, re)| Rule {
            name,
            re: Regex::new(re).expect("valid ua rule"),
        })
        .collect()
}

static BROWSER_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    rules(&[
        ("Edg", r"(?i)Edg(?:e|A|iOS)?/([0-9]+)"),
        ("OPR", r"(?i)OPR/([0-9]+)"),
        ("SamsungBrowser", r"(?i)SamsungBrowser/([0-9]+)"),
        ("Chrome", r"(?i)Chrome/([0-9]+)"),
        ("Firefox", r"(?i)Firefox/([0-9]+)"),
        ("Safari", r"(?i)Version/([0-9]+)[^ ]*(?: [^ ]+)*? Safari"),
        ("curl", r"(?i)\bcurl/([0-9]+)"),
        ("Wget", r"(?i)\bWget/([0-9]+)"),
        ("python-requests", r"(?i)python-requests/([0-9]+)"),
        ("Go-http-client", r"(?i)Go-http-client/([0-9]+)"),
        ("okhttp", r"(?i)okhttp/([0-9]+)"),
        ("axios", r"(?i)\baxios/([0-9]+)"),
        ("Postman", r"(?i)PostmanRuntime/([0-9]+)"),
    ])
});

static BOT_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    rules(&[
        ("sqlmap", r"(?i)sqlmap"),
        ("Nikto", r"(?i)nikto"),
        ("Nmap", r"(?i)nmap"),
        ("masscan", r"(?i)masscan"),
        ("gobuster", r"(?i)gobuster"),
        ("dirbuster", r"(?i)dirbuster"),
        ("wpscan", r"(?i)wpscan"),
        ("Fuzz Faster U Fool", r"(?i)\bffuf\b"),
        ("Nuclei", r"(?i)nuclei"),
        ("Hydra", r"(?i)\bhydra\b"),
        ("Acunetix", r"(?i)acunetix"),
        ("Burp Suite", r"(?i)burp(?:suite)?"),
    ])
});

static SPIDER_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    rules(&[
        ("Googlebot", r"(?i)googlebot"),
        ("Bingbot", r"(?i)bingbot"),
        ("DuckDuckBot", r"(?i)duckduckbot"),
        ("YandexBot", r"(?i)yandexbot"),
        ("Baiduspider", r"(?i)baiduspider"),
        ("FacebookBot", r"(?i)facebookexternalhit"),
        ("Twitterbot", r"(?i)twitterbot"),
    ])
});

static OS_RULES: Lazy<Vec<Rule>> = Lazy::new(|| {
    rules(&[
        ("Android", r"(?i)Android[ /]([0-9]+(?:\.[0-9]+)?)"),
        ("iOS", r"(?i)(?:iPhone OS|CPU OS)[ /]([0-9_]+)"),
        ("Windows", r"(?i)Windows NT ([0-9]+\.[0-9]+)"),
        ("macOS", r"(?i)Mac OS X ([0-9_]+)"),
        ("Linux", r"(?i)Linux"),
        ("Chrome OS", r"(?i)CrOS"),
    ])
});

static DEVICE_TABLET_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)iPad|Tablet").unwrap());
static DEVICE_MOBILE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)Mobile|iPhone|Android").unwrap());

/// Port of `Parse`.
pub fn parse(ua: &str) -> Info {
    let mut info = Info {
        raw: ua.to_string(),
        ..Default::default()
    };
    let ua = ua.trim();
    if ua.is_empty() {
        info.browser = "unknown".to_string();
        info.device = "unknown".to_string();
        return info;
    }

    for r in BOT_RULES.iter() {
        if r.re.is_match(ua) {
            info.browser = r.name.to_string();
            info.device = "bot".to_string();
            info.os = match_os(ua);
            return info;
        }
    }
    for r in SPIDER_RULES.iter() {
        if r.re.is_match(ua) {
            info.browser = r.name.to_string();
            info.device = "bot".to_string();
            info.os = match_os(ua);
            return info;
        }
    }

    for r in BROWSER_RULES.iter() {
        if let Some(m) = r.re.captures(ua) {
            let version = m.get(1).map(|g| g.as_str()).unwrap_or("");
            if !version.is_empty() {
                info.browser = format!("{} {}", r.name, clean_version(version));
            } else {
                info.browser = r.name.to_string();
            }
            break;
        }
    }
    if info.browser.is_empty() {
        info.browser = "other".to_string();
    }

    info.os = match_os(ua);
    info.device = match_device(ua, &info.browser);
    info
}

fn match_os(ua: &str) -> String {
    for r in OS_RULES.iter() {
        if let Some(m) = r.re.captures(ua) {
            let ver = m.get(1).map(|g| g.as_str()).unwrap_or("");
            if !ver.is_empty() {
                return format!("{} {}", r.name, ver.replace('_', "."));
            }
            return r.name.to_string();
        }
    }
    String::new()
}

fn match_device(ua: &str, browser: &str) -> String {
    let lower = browser.to_lowercase();
    for tool in [
        "curl", "wget", "go-http", "python", "okhttp", "axios", "postman",
    ] {
        if lower.contains(tool) {
            return "tool".to_string();
        }
    }
    if DEVICE_TABLET_RE.is_match(ua) {
        return "tablet".to_string();
    }
    if DEVICE_MOBILE_RE.is_match(ua) {
        return "mobile".to_string();
    }
    "desktop".to_string()
}

fn clean_version(v: &str) -> String {
    let v = v.replace('_', ".");
    if let Some(i) = v.find(['.', ' ']) {
        if i > 0 {
            return v[..i].to_string();
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_on_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
        let i = parse(ua);
        assert_eq!(i.browser, "Chrome 120");
        assert_eq!(i.os, "Android 14");
        assert_eq!(i.device, "mobile");
    }

    #[test]
    fn curl_is_tool() {
        let i = parse("curl/8.0.1");
        assert_eq!(i.browser, "curl 8");
        assert_eq!(i.device, "tool");
    }

    #[test]
    fn sqlmap_is_bot() {
        let i = parse("sqlmap/1.7#stable (http://sqlmap.org)");
        assert_eq!(i.browser, "sqlmap");
        assert_eq!(i.device, "bot");
    }

    #[test]
    fn empty_ua_unknown() {
        let i = parse("  ");
        assert_eq!(i.browser, "unknown");
        assert_eq!(i.device, "unknown");
    }

    #[test]
    fn safari_version() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.0 Safari/605.1.15";
        let i = parse(ua);
        assert_eq!(i.browser, "Safari 17");
        assert_eq!(i.os, "macOS 10.15.7");
        assert_eq!(i.device, "desktop");
    }
}
