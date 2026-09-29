# Bot Management

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

> **Status: Experimental** — Pattern-based bot detection is implemented. Fingerprinting, CAPTCHA, and JS challenge integration are documented as reference design and on the roadmap.

FortressWAF provides bot detection capabilities to distinguish between legitimate human users, good bots, and malicious automated traffic.

## Bot Detection Overview

| Bot Type | Detection Method | Action |
|----------|------------------|--------|
| Human | Fingerprint + behavioral | Allow |
| Good Bot (Google, Bing) | IP allowlist + UA verification | Allow |
| Bad Bot (Scanner, Crawler) | Pattern matching + ML | Block/Challenge |
| Sophisticated Bot | ML + behavioral analysis | Challenge/Block |
| Headless Browser | JavaScript challenges | Challenge |

## Detection Methods

### 1. Device Fingerprinting

FortressWAF collects and analyzes device fingerprints to identify bots:

#### Fingerprint Components

```yaml
bot_detection:
  fingerprint:
    enabled: true
    collection_methods:
      - canvas
      - webgl
      - fonts
      - screen
      - timezone
      - language
      - platform
      - plugins
      - vendor
    storage:
      backend: redis
      ttl: 24h
    fingerprint_hashing: sha256
```

#### Fingerprint Collection Code

```javascript
// Client-side fingerprint collection
const fingerprint = {
  canvas: collectCanvasFingerprint(),
  webgl: collectWebGLFingerprint(),
  webgl_vendor: collectWebGLVendor(),
  fonts: collectFontFingerprint(),
  screen: {
    width: screen.width,
    height: screen.height,
    colorDepth: screen.colorDepth,
    pixelRatio: window.devicePixelRatio
  },
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  language: navigator.language,
  platform: navigator.platform,
  hardware_concurrency: navigator.hardwareConcurrency,
  device_memory: navigator.deviceMemory,
  touch_support: navigator.maxTouchPoints > 0,
  webdriver: navigator.webdriver
};

async function collectCanvasFingerprint() {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  canvas.width = 200;
  canvas.height = 50;

  ctx.textBaseline = 'top';
  ctx.font = '14px Arial';
  ctx.fillStyle = '#f60';
  ctx.fillRect(125, 1, 62, 20);
  ctx.fillStyle = '#069';
  ctx.fillText('FortressWAF', 2, 15);
  ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
  ctx.fillText('Fingerprint', 4, 17);

  return canvas.toDataURL();
}

async function collectWebGLFingerprint() {
  const canvas = document.createElement('canvas');
  const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

  if (!gl) return null;

  const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
  return {
    vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null,
    renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : null
  };
}
```

### 2. Headless Browser Detection

Detect browsers running in headless mode:

```yaml
bot_detection:
  headless:
    enabled: true
    detection_methods:
      - webdriver_property
      - chrome_app
      - permissions_api
      - plugins_array
      - languages_length
      - webgl_vendor
      - timing_attacks
      - automation_variable
```

#### Detection Rules

```yaml
name: Detect Headless Browser
description: Block requests from headless browsers
priority: 15
condition:
  any:
    - request.fingerprint.webdriver: equals true
    - request.fingerprint.chrome_app: exists
    - request.fingerprint.permissions: equals "denied"
    - request.fingerprint.automation: equals true
action:
  type: challenge
  challenge_type: javascript
```

### 3. Good Bot Allowlisting

Known good bots (search engines, monitoring) are automatically allowed:

```yaml
bot_detection:
  good_bots:
    enabled: true
    verification:
      method: reverse_dns  # "reverse_dns", "asn", "both"
      allowlisted:
        - name: Googlebot
          ua_contains: "Googlebot"
          asns: [15169]
          domains: ["*.googlebot.com"]
        - name: Bingbot
          ua_contains: "Bingbot"
          asns: [8075]
          domains: ["*.bing.com"]
        - name: Yandexbot
          ua_contains: "YandexBot"
          asns: [13238]
          domains: ["*.yandex.com"]
        - name: Baiduspider
          ua_contains: "Baiduspider"
          asns: [55967]
          domains: ["*.baidu.com"]
        - name: Applebot
          ua_contains: "Applebot"
          asns: [618]
          domains: ["*.apple.com"]
        - name: Twitterbot
          ua_contains: "Twitterbot"
          asns: [13414]
          domains: ["*.twitter.com"]
        - name: Facebookexternalhit
          ua_contains: "facebookexternalhit"
          asns: [32934]
          domains: ["*.facebook.com"]
```

### 4. Behavioral Analysis

```yaml
bot_detection:
  behavioral:
    enabled: true
    analysis:
      mouse_movement:
        enabled: true
        min_movements: 5
        max_time: 5s
      keyboard_input:
        enabled: true
        min_keystrokes: 3
      scroll_behavior:
        enabled: true
        expected_scroll_depth: 0.3
      click_patterns:
        enabled: true
        suspicious_click_speed: 100ms
```

### 5. JavaScript Challenges

Present JavaScript challenges to detect bots:

```yaml
bot_detection:
  challenges:
    enabled: true
    types:
      - javascript
      - cookie
      - captcha
    javascript:
      challenge_code: |
        (function() {
          // Browser feature detection
          const features = {
            canvas: !!document.createElement('canvas').getContext,
            webgl: !!window.WebGLRenderingContext,
            webgl2: !!window.WebGL2RenderingContext,
            workers: !!window.Worker,
            notification: !!window.Notification,
            performance: !!window.performance,
            touch: 'ontouchstart' in window,
            serviceWorker: 'serviceWorker' in navigator
          };

          // Timing attack detection
          const start = performance.now();
          for (let i = 0; i < 1000; i++) {
            Math.sqrt(i);
          }
          const duration = performance.now() - start;

          // Send proof
          const proof = btoa(JSON.stringify({
            features,
            duration,
            timestamp: Date.now()
          }));

          document.cookie = `fw_challenge=${proof}; path=/; SameSite=Strict`;
        })();
      cookie_name: fw_challenge
      cookie_ttl: 3600
```

### 6. CAPTCHA Integration

```yaml
bot_detection:
  captcha:
    enabled: true
    provider: google  # "google", "hcaptcha", "turnstile"
    site_key: "6Lc_..."
    secret_key: "6Lc_..."
    threshold: 0.7  # Bot score threshold for CAPTCHA challenge
    theme: light
    size: normal
    expires_in: 300  # seconds
```

#### CAPTCHA Challenge Flow

```
Request → Bot Detection → Score > Threshold → CAPTCHA Challenge
                                    ↓
                               Score < Threshold → Allow Request
                                    ↓
                              CAPTCHA Failed → Block
                                    ↓
                             CAPTCHA Passed → Allow + Mark Session
```

## Bot Score Calculation

Bot score is calculated using multiple signals:

```python
def calculate_bot_score(request, fingerprint, session) -> float:
    scores = {}

    # 1. Fingerprint Score (40% weight)
    scores['fingerprint'] = calculate_fingerprint_score(fingerprint)

    # 2. Behavioral Score (25% weight)
    scores['behavioral'] = calculate_behavioral_score(session)

    # 3. Request Pattern Score (20% weight)
    scores['pattern'] = calculate_pattern_score(request, session)

    # 4. ML Model Score (15% weight)
    scores['ml'] = ml_bot_model.predict_proba([features])[0]

    # Weighted average
    weights = {
        'fingerprint': 0.40,
        'behavioral': 0.25,
        'pattern': 0.20,
        'ml': 0.15
    }

    final_score = sum(scores[k] * weights[k] for k in weights)
    return final_score

def calculate_fingerprint_score(fp) -> float:
    """Higher score = more likely bot"""
    score = 0.0

    # Webdriver detected
    if fp.get('webdriver'):
        score += 0.5

    # Missing common features
    if not fp.get('canvas'):
        score += 0.2
    if not fp.get('webgl'):
        score += 0.1

    # Unusual platform
    if fp.get('platform') in ['HeadlessChrome', 'PhantomJS']:
        score += 0.4

    # Missing plugins (real browsers usually have plugins)
    if len(fp.get('plugins', [])) == 0:
        score += 0.15

    # Automation variables
    if fp.get('automation'):
        score += 0.5

    return min(score, 1.0)
```

## Bot Categories and Actions

| Category | Score Range | Action | Description |
|----------|-------------|--------|-------------|
| Confirmed Human | 0.0 - 0.2 | Allow | Verified human user |
| Likely Human | 0.2 - 0.4 | Allow | Most signals indicate human |
| Unknown | 0.4 - 0.6 | Monitor | Uncertain, track closely |
| Likely Bot | 0.6 - 0.8 | Challenge | Challenge with CAPTCHA |
| Confirmed Bot | 0.8 - 1.0 | Block | Block immediately |

## Bot Management Actions

### Tarpit Mode

Slow down bots to waste their resources:

```yaml
bot_detection:
  tarpit:
    enabled: true
    delay_ms: 5000  # Add 5 second delay
    progressive: true  # Increase delay with each request
    max_delay_ms: 30000
```

### Honeypot Fields

Create invisible trap fields:

```yaml
bot_detection:
  honeypot:
    enabled: true
    fields:
      - name: email_address
        type: hidden
        css: "display:none;visibility:hidden;"
        trap_value: ""
      - name: website_url
        type: text
        css: "position:absolute;left:-9999px;"
        trap_patterns: ["http://", "https://"]
```

### Bot Challenge Rules

```yaml
name: Challenge Suspicious Bots
description: Challenge requests with bot score > 0.5
priority: 50
condition:
  bot.score: "> 0.5"
  bot.score: "< 0.8"
action:
  type: challenge
  challenge_type: captcha
  challenge_timeout: 60s
  challenge_fail_action: block

name: Block Confirmed Bots
description: Block requests with bot score > 0.8
priority: 40
condition:
  bot.score: "> 0.8"
action:
  type: block
  status: 403
  body: "Automated access detected and blocked"
  headers:
    X-Bot-Reason: "automated-access-detected"
```

## Session Bot Tracking

```yaml
session:
  bot_tracking:
    enabled: true
    track_attempts: true
    failed_challenges_threshold: 3
    challenge_timeout: 15m
    bot_decay_rate: 0.1  # Score decreases over time if no bot behavior
```

## Bot Detection Configuration

### Complete Configuration Example

```yaml
bot_detection:
  # Enable bot detection
  enabled: true

  # Device fingerprinting
  fingerprint:
    enabled: true
    collection_methods:
      - canvas
      - webgl
      - webgl_vendor
      - fonts
      - screen
      - timezone
      - language
      - platform
      - hardware_concurrency
      - device_memory
    cache_ttl: 24h

  # Headless browser detection
  headless:
    enabled: true
    detection_methods:
      - webdriver
      - chrome_app
      - permissions
      - automation_variable
      - languages_length

  # Behavioral analysis
  behavioral:
    enabled: true
    mouse_movement:
      enabled: true
      min_samples: 5
      max_time_ms: 5000
    keyboard:
      enabled: true
      min_keystrokes: 3
    scroll:
      enabled: true
      expected_depth: 0.3
    click:
      enabled: true
      max_speed_ms: 100

  # Good bot allowlisting
  good_bots:
    enabled: true
    verification:
      method: reverse_dns
      require_match: true
    bots:
      - googlebot
      - bingbot
      - yandexbot
      - baiduspider
      - applebot
      - twitterbot

  # Challenge configuration
  challenges:
    enabled: true
    javascript:
      enabled: true
      cookie_name: fw_js_challenge
      ttl: 3600
    cookie:
      enabled: true
      cookie_name: fw_cookie_challenge
      ttl: 7200
    captcha:
      enabled: true
      provider: google
      site_key: "${GOOGLE_RECAPTCHA_SITE_KEY}"
      secret_key: "${GOOGLE_RECAPTCHA_SECRET_KEY}"
      threshold: 0.7

  # Tarpit mode
  tarpit:
    enabled: false
    delay_ms: 5000
    progressive: false
    max_delay_ms: 30000

  # Honeypot fields
  honeypot:
    enabled: true
    fields:
      - name: __fw_email
        type: hidden
      - name: __fw_website
        type: hidden

  # Scoring thresholds
  thresholds:
    allow: 0.3
    challenge: 0.6
    block: 0.8
```

## Monitoring Bot Traffic

### Bot Traffic Dashboard

View bot statistics in the dashboard:

| Metric | Description |
|--------|-------------|
| Total Requests | All requests processed |
| Human Traffic | Confirmed human requests |
| Bot Traffic | Detected bot requests |
| Good Bot Traffic | Allowlisted bot traffic |
| Blocked Bots | Blocked malicious bots |
| CAPTCHA Challenges | Challenges issued |
| CAPTCHA Failures | Failed challenge attempts |

### Bot Alert Configuration

```yaml
alerts:
  - name: high_bot_traffic
    condition: bot_traffic_ratio > 0.3
    severity: warning
    message: "Bot traffic exceeds 30%"

  - name: bot_attack_detected
    condition: blocked_bots_per_minute > 100
    severity: critical
    message: "Possible bot attack in progress"
```

## Integrating with Third-Party Bot Management

### DataDome

```yaml
integrations:
  datadome:
    enabled: true
    api_key: "${DATADOME_API_KEY}"
    js_script_url: "https://cdn.datadome.co/tags.js"
```

### PerimeterX

```yaml
integrations:
  perimeterx:
    enabled: true
    app_id: "${PERIMETERX_APP_ID}"
    sensor_url: "https://collector.perimeterx.net"
```

### Cloudflare Bot Management

```yaml
integrations:
  cloudflare:
    enabled: true
    bot_management:
      enabled: true
      use_cloudflare_score: true
      threshold: 30
```
