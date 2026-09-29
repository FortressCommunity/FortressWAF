#!/usr/bin/env bash
#
# Rebuild and redeploy the FortressWAF stack from the current working tree.
#
# Why this exists as a script rather than a bare `docker compose up`: when a
# service container is recreated, Caddy — which resolves service names by DNS —
# can keep a stale address and start returning 502 for the admin API. That made
# the dashboard look "down" even though its pages loaded. This script recreates
# the services and then restarts Caddy so its resolver cache is fresh, and it
# verifies the full browser path (page + login + API) before declaring success.
#
# Usage:
#   ./scripts/deploy.sh                 # rebuild changed services, redeploy, verify
#   ./scripts/deploy.sh fortresswaf     # rebuild/redeploy only one service
#   SKIP_BUILD=1 ./scripts/deploy.sh    # skip rebuild, just recreate + verify
#
# Public hostnames can be overridden for a different deployment:
#   DASHBOARD_HOST=fort.example.com ADMIN_HOST=admin.example.com ./scripts/deploy.sh

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy"
COMPOSE_FILE="$COMPOSE_DIR/docker-compose.yml"

# docker needs root here (socket is root:docker); use sudo when not already root.
if [ "$(id -u)" -eq 0 ]; then DC=(docker compose); else DC=(sudo docker compose); fi

DASHBOARD_HOST="${DASHBOARD_HOST:-fort.tkjt3yapera.my.id}"
ADMIN_HOST="${ADMIN_HOST:-admin-fort.tkjt3yapera.my.id}"
DEMO_HOST="${DEMO_HOST:-demo.tkjt3yapera.my.id}"

# Admin credentials come from deploy/.env (gitignored) so no secret is hardcoded.
if [ -f "$COMPOSE_DIR/.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$COMPOSE_DIR/.env"; set +a
fi
ADMIN_USER="${ADMIN_USER:-${ADMIN_EMAIL:-admin@localhost}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

# Services built from source in this repo. postgres/caddy/vulnerable-web use
# upstream images and are not rebuilt.
SOURCE_SERVICES=(fortresswaf dashboard ml-engine)

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }
step()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }

FAIL=0
fail() { FAIL=$((FAIL + 1)); red "  FAIL: $1"; }
pass() { green "  ok: $1"; }

# shellcheck disable=SC2086
cd "$COMPOSE_DIR" || { red "cannot cd to $COMPOSE_DIR"; exit 1; }

# Which services to act on: args, or all source services.
if [ "$#" -gt 0 ]; then
  SERVICES=("$@")
else
  SERVICES=("${SOURCE_SERVICES[@]}")
fi

step "1. Prepare runtime config"
# The WAF runs as nonroot (uid 65534) and rewrites the config when a domain is
# added through the console. It must therefore write to a file OWNED by that
# uid -- not the git-tracked deploy/config.yaml, which the operator owns. So the
# tracked file is copied (or refreshed) into deploy/runtime/ and chowned to the
# container user. This step is what makes "add domain" work instead of failing
# with "write config: permission denied".
RUNTIME_DIR="$COMPOSE_DIR/runtime"
mkdir -p "$RUNTIME_DIR"
if [ ! -f "$RUNTIME_DIR/config.yaml" ] || [ "${FORCE_CONFIG_RESET:-0}" = "1" ]; then
  cp "$COMPOSE_DIR/config.yaml" "$RUNTIME_DIR/config.yaml"
  echo "  seeded $RUNTIME_DIR/config.yaml from the tracked config"
else
  echo "  kept existing $RUNTIME_DIR/config.yaml (set FORCE_CONFIG_RESET=1 to reseed)"
fi

# uid 65534 = the distroless nonroot user the WAF image runs as. Both the file
# and its directory must be writable by it: the atomic save writes a temp file
# into the directory, then renames it over config.yaml.
RUN_AS=""
[ "$(id -u)" -ne 0 ] && RUN_AS="sudo"
$RUN_AS chown 65534:65534 "$RUNTIME_DIR" "$RUNTIME_DIR/config.yaml" 2>/dev/null || true
$RUN_AS chmod 775 "$RUNTIME_DIR" 2>/dev/null || true
$RUN_AS chmod 664 "$RUNTIME_DIR/config.yaml" 2>/dev/null || true
pass "runtime config + directory writable by the container user"

step "2. Build"
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo "  SKIP_BUILD=1, skipping image build"
else
  # --no-cache on ml-engine whenever its Python source changed is the caller's
  # job; a plain build is enough day to day.
  if ! "${DC[@]}" build "${SERVICES[@]}"; then
    fail "image build failed"
    exit 1
  fi
  pass "images built: ${SERVICES[*]}"
fi

step "3. Recreate containers"
if ! "${DC[@]}" up -d --no-build "${SERVICES[@]}"; then
  fail "container recreate failed"
  exit 1
fi
pass "containers recreated"

step "4. Restart Caddy (refresh stale service DNS)"
# This is the fix for the 502-after-recreate problem: Caddy caches the address
# of 'fortresswaf'/'dashboard'; a recreate can invalidate it.
if "${DC[@]}" ps caddy >/dev/null 2>&1; then
  "${DC[@]}" restart caddy >/dev/null 2>&1 && pass "caddy restarted" || fail "caddy restart failed"
else
  echo "  no caddy service in this stack, skipping"
fi

step "5. Wait for health"
ok_health=0
for _ in $(seq 1 40); do
  if curl -sS -m 4 -o /dev/null "http://127.0.0.1:8443/health" 2>/dev/null \
     && curl -sS -m 4 -o /dev/null "http://127.0.0.1:3000/" 2>/dev/null; then
    ok_health=1; break
  fi
  sleep 2
done
[ "$ok_health" = "1" ] && pass "waf + dashboard healthy" || fail "services did not become healthy"

# A freshly recreated dashboard (Next.js standalone) can take a few seconds to
# accept connections through Caddy, so the public checks retry rather than take
# one immediate sample.
retry_code() {
  # $1=expected code, $2...=curl args
  local want="$1"; shift
  local code
  for _ in $(seq 1 15); do
    code=$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)
    [ "$code" = "$want" ] && { echo "$code"; return 0; }
    sleep 2
  done
  echo "$code"
  return 1
}

step "6. Verify the browser path end to end"
page=$(retry_code 200 "https://$DASHBOARD_HOST/")
[ "$page" = "200" ] && pass "GET https://$DASHBOARD_HOST/ -> 200" || fail "dashboard page -> $page"

# The admin API is served same-origin under /api/* on the dashboard host, so a
# browsing phone only ever talks to one hostname.
token=$(curl -sS -m 12 -X POST "https://$DASHBOARD_HOST/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  --data-raw "{\"email\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}" 2>/dev/null \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [ -n "$token" ]; then
  pass "admin login (same origin) -> token issued"
  for ep in status audit inspectors domains bans training/status; do
    code=$(curl -sS -m 12 -o /dev/null -w '%{http_code}' \
      -H "Authorization: Bearer $token" \
      "https://$DASHBOARD_HOST/api/v1/$ep" 2>/dev/null)
    [ "$code" = "200" ] && pass "api /$ep -> 200" || fail "api /$ep -> $code"
  done
else
  fail "admin login did not return a token (same-origin API path broken)"
fi

demo=$(curl -sS -m 12 -o /dev/null -w '%{http_code}' "https://$DEMO_HOST/" 2>/dev/null)
{ [ "$demo" = "200" ] || [ "$demo" = "404" ]; } && pass "demo host reachable ($demo)" || fail "demo host -> $demo"

step "Summary"
if [ "$FAIL" -gt 0 ]; then
  red "DEPLOY COMPLETED WITH $FAIL FAILURE(S) — see above"
  exit 1
fi
green "DEPLOY OK — dashboard and admin API reachable"
