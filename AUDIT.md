# FortressWAF — Audit Report

Date: audit run against working tree (branch `fix/benchmark-go-version`, HEAD `fdf8f92`).
Tooling: `go build ./...`, `go vet ./...`, `go test ./...`, `govulncheck ./...`, codebase-memory graph index, manual source review.

## Baseline (all green before changes)

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go test ./...` | pass (all packages) |
| `govulncheck ./...` | 0 reachable vulns in code; 4 in required modules, unreached |
| Dashboard `next build` | not yet re-run in this audit |

The repo is in far better shape than a typical "unfinished" project. The findings below are
real, but most are **code-quality / landmine** issues in dead code rather than live exploits,
because the entire `internal/api` package is never imported by the running binary.

## Findings

### F1 — `internal/api` contains an authentication bypass (dead code) — HIGH
`internal/api/handlers.go:2243`, `internal/api/server.go:137`

```go
// handlers.go Login()
if !valid && len(cfg.Admin.APIKeys) == 0 {
    valid = true            // any credentials accepted when no keys configured
}
```
- `Login` authenticates by comparing the submitted username/password against configured API keys; with zero keys configured every login succeeds.
- `apiKey` comparison in `authMiddleware` uses `==` (not constant time).
- **Impact today: none** — nothing imports `internal/api` (verified: `grep -rn "internal/api"` outside the package is empty), so this server never runs. It is a landmine for anyone who wires it up later. README already labels it dead code.
- **Fix:** delete the package, or repair it (constant-time compare, fail-closed, remove the `len==0 → valid` branch).

### F2 — `rateLimitMiddleware` is a no-op — MEDIUM (dead code)
`internal/api/server.go:175`
```go
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        next.ServeHTTP(w, r)
    })
}
```
Declared, wired into the `/api/v1` chain, does nothing. Same dead-code caveat as F1.

### F3 — Unauthenticated WebSocket echo with `CheckOrigin: true` — MEDIUM (dead code)
`internal/api/server.go:54` (`CheckOrigin: func(r) bool { return true }`) and `:123`
(`s.router.HandleFunc("/ws", s.handleWebSocket)` — registered on the router that has **no**
auth middleware). Cross-Site WebSocket Hijacking plus an open reflection endpoint.
Dead-code caveat as F1.

### F4 — `Server.Broadcast` is an empty function — LOW (dead code)
`internal/api/server.go:309`. Declared API that silently does nothing.

### F5 — Response body inspection is entirely unwired — HIGH (feature not implemented)
`internal/engine/middleware.go:145` (`ResponseInspector.Inspect` returns `nil, nil`) and
`internal/engine/middleware.go:116` (`ResponseWriter` type is defined but never instantiated).
`cmd/proxy/main.go:651` calls `proxy.ServeHTTP(w, r)` directly, so the response writer is never
wrapped and no response bytes are ever captured. README limitation #6 already admits this.
- **This is the single largest "declared but not implemented" gap.** It is realistic to build a
  real data-leakage detector here.

### F6 — ml-engine `/v1/model/retrain` trains on random dummy data, unauthenticated — HIGH
`ml-engine/api/app.py:273`
```python
dummy_anomaly = np.random.randn(100, 38)
anomaly_detector.partial_fit(dummy_anomaly)
```
No auth, no rate limit. Any caller can trigger a "retrain" that actually corrupts the loaded
models with noise and writes them to `models/persisted/*.pkl`. README documents the ML as
heuristic, but this endpoint makes the state worse on demand.

### F7 — ml-engine CORS `allow_origins=["*"]` with `allow_credentials=True` — MEDIUM
`ml-engine/api/app.py:69`. Invalid combination (browsers reject `*` + credentials) and overly
broad for a sidecar that should only be reachable by the proxy.

### F8 — ml-engine reads whole request body with no size cap — MEDIUM (DoS)
`ml-engine/api/app.py:77` `_ = await request.body()`. No `Content-Length` limit; a large POST to
`/v1/inspect` buffers unbounded memory.

### F9 — Dashboard auth token in `localStorage` — MEDIUM
`dashboard/lib/api.ts:14,20` (`localStorage.getItem('fortresswaf_token')`). Any XSS on the
dashboard origin can exfiltrate the admin token. The dashboard is otherwise XSS-clean (the one
`dangerouslySetInnerHTML` at `app/layout.tsx:43` injects a static constant, not user data).

### F10 — Dashboard ships no security headers — MEDIUM
`dashboard/next.config.mjs` sets only `output` and `images`. No CSP, HSTS, `X-Frame-Options`,
or `X-Content-Type-Options`.

### F11 — `go.mod` / whitespace — INFO
`govulncheck` found 4 module-level advisories that are not reachable from the code. No action
required beyond routine dependency bumps.

### Non-findings (verified clean)

- **No committed secrets.** `.env` (containing a real `CODEX_GATEWAY_API_KEY`) is gitignored and
  untracked. `deploy/config.yaml` ships only the documented `fortress-demo-admin` demo key with a
  "CHANGE THIS" note.
- **`cmd/proxy` auth is solid**: constant-time compares (`subtle.ConstantTimeCompare`), fail-closed
  when no keys are configured (`adminAuthMiddleware`), login rate-limited (`newLoginLimiter`),
  CORS restricted to `admin.cors_origins` (echoed origin, never `*` with credentials).
- **Request body is capped** at 10 MB (`internal/engine/engine.go:166`).
- **Docker ports** are bound to `127.0.0.1` (proxy, ml-engine, dashboard); only Caddy is public.

## Remediation plan

1. **F5** — implement real response body inspection (leak detection) and wire it into the request
   path behind the existing `response_inspect` config flag. Add tests.
2. **F6, F7, F8** — guard/demote the retrain endpoint, tighten CORS, cap body size in ml-engine.
3. **F1–F4** — since `internal/api` is dead, remove the whole package (and its now-unused deps) OR
   repair it. Removal eliminates an auth-bypass landmine and shrinks the attack surface.
4. **F9, F10** — move the dashboard token out of `localStorage` and add security headers.
5. Re-run build/vet/test/govulncheck after each change.

## Remediation status (all applied)

| # | Status | What changed |
|---|---|---|
| F5 | **fixed** | New `internal/engine/response_leak.go`: 8 leak rules (LEAK-001..008) with redacted evidence and a bounded 1 MiB scan. `ResponseWriter` rewritten to buffer + defer the origin response so a leak is blocked *before* it reaches the client. Wired into `forwardRequest`; `response_inspect` now enabled in the demo config and listed under `/inspectors`. 15 unit tests + 2 handler tests; verified end-to-end (normal 200, leak 502, 3 MB body streams intact). |
| F6 | **fixed** | `/v1/model/retrain` now returns 501 unless `FORTRESSWAF_ALLOW_PLACEHOLDER_RETRAIN=1`, so it can no longer corrupt models on demand. |
| F7 | **fixed** | ml-engine CORS set to `allow_origins=[]`, `allow_credentials=False` (internal sidecar). |
| F8 | **fixed** | `limit_body_size` middleware rejects `Content-Length > 10 MiB` with 413 before parsing; the redundant full-body read in the logging middleware was dropped. |
| F1–F4 | **fixed** | `internal/api` and its orphaned `internal/rules` dependency deleted (auth bypass, no-op rate limiter, unauthenticated `/ws`, empty `Broadcast` all gone). README + `docs/concepts/components.md` updated. |
| F9 | **mitigated** | Dashboard token moved from `localStorage` to `sessionStorage` (tab-scoped) and the residual caveat documented; the strict CSP below is the actual control. |
| F10 | **fixed** | `dashboard/next.config.mjs` now sends CSP (no remote script origins), HSTS, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Dashboard `next build` passes. |

### Verification after fixes

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass |
| `go test ./...` | pass (added 17 tests) |
| `govulncheck ./...` | 0 reachable vulns |
| `next build` (dashboard) | pass |
| End-to-end leak block | pass (unit + handler + live binary) |
| Large-body passthrough | pass (3 MB byte-intact) |

### Residual, documented (not bugs)

- ML model still untrained (heuristic) — `ml-engine` answers from scoring rules; already in README.
- Rules are still not loaded from `rules/*.yaml` — detection is from built-in inspectors; README limitation #4.
- Dashboard token is JS-readable by design until the admin API issues an httpOnly cookie; the CSP
  closes the realistic XSS path. Documented in README limitation #7.
- FastAPI/pytest could not be executed in this environment (no `pip`/network); the Python changes
  were validated with `py_compile` and the gate logic was unit-checked in isolation.

## Round 2 — demo false positives

Live demo testing surfaced false positives across most detectors. Root causes and fixes:

| Symptom | Root cause | Fix | Test |
|---|---|---|---|
| A phone opening the web app is blocked before it does anything | `protocol` flagged `OPTIONS`/`HEAD`/`PATCH`/`PUT`/`DELETE` as "verb tampering" (PROT010). Browsers send OPTIONS as a CORS preflight on every API call | `NewProtocolAnomaly` now flags only genuinely dangerous verbs (TRACE, TRACK, CONNECT, WebDAV); standard methods pass | `TestFalsePositive_StandardHTTPMethods` |
| Real browsers / HTTP clients blocked as bots | `bot` matched bare substrings: `java` (matched "JavaScript"), `got`, `fetch`, `curl`, `axios`, `okhttp`, plus a `badBots` entry for every generic client | Rewrote `compileBadBotPatterns` to word-boundary-anchored attack-tool signatures only; removed generic clients | `TestFalsePositive_RealBrowserUserAgents`, `TestFalsePositive_CommonHTTPClientsNotBots`, `TestTruePositive_AttackToolsStillBlocked` |
| Contact/signup forms blocked | `honeypotFields` contained `email`, `phone`, `address`, `website`, `url_` — every real form has these | Narrowed the list to conventional decoy names (`hp_`, `honeypot`, `botfield`, …) | `TestFalsePositive_ContactFormFieldsNotHoneypot`, `TestTruePositive_HoneypotFieldStillBlocked` |
| Legit pages blocked as sensitive paths | `api_protect` matched `/admin`, `/config`, `/info`, `/docs` anywhere in the path, so `/blog/administrator-tips`, `/information`, `/configuration`, `/user/admin-profile` were blocked | Anchored every sensitive-path pattern to a whole path segment | `TestFalsePositive_SensitivePathsSegmentAnchored` |
| Normal pages got 502 | `response_inspect` blocked on any content match, including a DSN shown in documentation | Inspector now runs in **monitor mode by default**; blocking requires `response_inspect.block: true` | `TestResponseLeakMonitorByDefault` |
| Block reply was a bare JSON blob | No human-readable block page | Added content negotiation: browsers get a styled HTML `FortressWAF` block page naming the rule; API clients get JSON | e2e `e2e_block.sh` |
| "Data must be real-time" | Dashboard polled every 5–10s | Overview and audit pages now poll every 2s | manual |

New regression suite: `tests/unit/false_positive_regression_test.go`,
`tests/unit/browse_fp_sweep_test.go`, `tests/unit/api_path_fp_test.go`.

### Verification after round 2

| Check | Result |
|---|---|
| `go build` / `go vet` / `go test ./...` | pass |
| Browser + mobile sweep across all enabled inspectors | no blocks |
| Attack tools (sqlmap/nikto/masscan/gobuster/nmap) | still blocked |
| Block page (browser) + JSON (API) live via binary | pass |
| Response leak monitor vs block (`block: true`) | pass |

