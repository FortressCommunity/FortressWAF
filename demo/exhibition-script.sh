#!/usr/bin/env bash
#
# FortressWAF exhibition walkthrough.
#
# Drives a running instance through the story told at the booth: a normal
# request passes, SQLi / XSS / command injection are blocked by named rules,
# and the hits land in the tamper-evident audit log and the compliance report.
# Every step asserts its expected outcome, so a broken demo fails loudly here
# instead of quietly in front of a reviewer.
#
# Usage:
#   # binary started with: -proxy-port 8080 -admin-port 8443  (the default)
#   ./demo/exhibition-script.sh
#
#   # docker compose stack, which publishes the proxy on port 80
#   PROXY_URL=http://localhost ./demo/exhibition-script.sh
#
#   # different host / credentials
#   PROXY_URL=http://waf.local ADMIN_URL=http://waf.local:8443 \
#     ADMIN_PASSWORD=fortress-demo-admin ./demo/exhibition-script.sh

set -uo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ADMIN_URL="${ADMIN_URL:-http://localhost:8443}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-fortress-demo-admin}"
# The bot inspector blocks a bare curl User-Agent as BOT004, which would mask
# every payload check below, so all traffic here presents as a browser.
BROWSER_UA="${BROWSER_UA:-Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36}"

PASS=0
FAIL=0

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
step()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

pass() { PASS=$((PASS + 1)); printf '  %s %s\n' "$(green PASS)" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  %s %s\n' "$(red FAIL)" "$1"; }

# http_status prints the response code for a request. Extra curl arguments
# (for example -d) are passed through.
http_status() {
  local method="$1" url="$2"
  shift 2
  curl -sS -m 10 -A "$BROWSER_UA" -X "$method" -o /dev/null -w '%{http_code}' "$@" "$url"
}

# http_body prints the response body for a request.
http_body() {
  local method="$1" url="$2"
  shift 2
  curl -sS -m 10 -A "$BROWSER_UA" -X "$method" "$@" "$url"
}

# json_field extracts a top-level string or numeric field without requiring jq.
json_field() {
  local field="$1" json="$2"
  printf '%s' "$json" | sed -n "s/.*\"${field}\":\"\{0,1\}\([^,\"}]*\)\"\{0,1\}.*/\1/p" | head -1
}

assert_rule() {
  local label="$1" expected="$2" body="$3" got
  got=$(json_field rule_id "$body")
  if [[ "$got" == "$expected" ]]; then
    pass "$label -> $got"
  else
    fail "$label expected rule $expected, got '${got:-<none>}' ($body)"
  fi
}

assert_not_blocked() {
  local label="$1" status="$2" body="$3"
  if [[ "$status" == "403" || "$body" == *'"action":"block"'* ]]; then
    fail "$label was blocked: $body"
  else
    pass "$label passed through (HTTP $status)"
  fi
}

step "Preflight"
if ! http_body GET "$ADMIN_URL/health" | grep -q '"status":"healthy"'; then
  red "admin API at $ADMIN_URL is not healthy; start FortressWAF before running the demo"
  exit 1
fi
pass "admin API healthy at $ADMIN_URL"
if [[ "$(http_status GET "$PROXY_URL/")" == "000" ]]; then
  red "proxy at $PROXY_URL is not reachable"
  exit 1
fi
pass "proxy reachable at $PROXY_URL"

step "1. A normal browser request is allowed"
status=$(http_status GET "$PROXY_URL/")
body=$(http_body GET "$PROXY_URL/")
assert_not_blocked "GET /" "$status" "$body"

status=$(http_status GET "$PROXY_URL/search?q=please+select+the+blue+option")
body=$(http_body GET "$PROXY_URL/search?q=please+select+the+blue+option")
assert_not_blocked "benign sentence containing 'select'" "$status" "$body"

step "2. Attacks are blocked by named rules"
assert_rule "SQL injection" "SQLI016" "$(http_body GET "$PROXY_URL/search?q=1'%20OR%201=1--")"
assert_rule "Cross-site scripting" "XSS001" \
  "$(http_body GET "$PROXY_URL/search?q=%3Cscript%3Ealert(1)%3C/script%3E")"
assert_rule "Command injection" "RCE001" "$(http_body GET "$PROXY_URL/cmd?c=;id")"

step "3. The bot inspector blocks scanner tooling"
assert_rule "bare curl User-Agent" "BOT004" \
  "$(curl -sS -m 10 "$PROXY_URL/")"

step "4. The audit log records the blocks (hash-chained)"
login_body=$(http_body POST "$ADMIN_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"demo@fortresswaf.local\",\"password\":\"$ADMIN_PASSWORD\"}")
token=$(json_field token "$login_body")
if [[ -z "$token" ]]; then
  fail "could not log in to the admin API: $login_body"
else
  pass "logged in to the admin API"
  audit=$(http_body GET "$ADMIN_URL/api/v1/audit?limit=20" -H "Authorization: Bearer $token")
  if [[ "$audit" == *'"entries"'* && "$audit" == *'"request_blocked"'* ]]; then
    pass "audit log contains request_blocked entries"
  else
    fail "audit log has no request_blocked entries: $audit"
  fi
  if [[ "$audit" == *'"prev_hash":"'* ]]; then
    pass "audit entries are hash-chained (prev_hash present)"
  else
    fail "audit entries are missing the hash chain"
  fi
fi

step "5. Compliance reports what it can actually verify"
assessment=$(http_body GET "$ADMIN_URL/api/v1/compliance/pci-dss/assessment" \
  -H "Authorization: Bearer $token")
compliant=$(json_field compliant_count "$assessment")
automated=$(json_field automated_controls "$assessment")
if [[ "${compliant:-0}" -ge 1 && "${automated:-0}" -ge 1 ]]; then
  pass "PCI-DSS: $compliant auto-verified controls out of $automated automated checks " \
       "(the rest need human evidence)"
else
  fail "unexpected compliance assessment: $assessment"
fi

step "Summary"
printf '  checks passed: %d, failed: %d\n' "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  red "DEMO FAILED"
  exit 1
fi
green "DEMO PASSED"
