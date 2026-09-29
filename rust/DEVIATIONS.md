# Rust Backend — Deviations from the Original Go Implementation

This document records **every place this Rust backend intentionally differs**
from the original Go implementation (which lived under `internal/` and `cmd/`
and has since been removed). Anything not listed here is meant to behave
identically; where behaviour was verified, the test that proves it is named.

The contract: **no silent behaviour changes, no hallucinated logic.** Where
exact parity was impossible or impractical, the difference is listed below with
the reason, and the affected behaviour is either reproduced faithfully
(including the original's bugs) or stubbed behind a trait with a clear TODO.

> **Migration note.** The Go tree (`cmd/`, `internal/`, `tests/*.go`, `go.mod`,
> `go.sum`, `.golangci.yml`, `tools/`, `benchmark.txt`) was deleted. The
> Dockerfile, `Makefile`, CI workflows, `install.sh`, and `.pre-commit-config.yaml`
> now build and lint Rust. This document is what remains of the "work from Go"
> reference: it preserves the behavioural comparison so a difference is never a
> surprise.

---

## 1. Concurrency model

| Go | Rust | Rationale |
|---|---|---|
| `sync.RWMutex` around engine/context fields, background goroutines for cleanup (`go cs.cleanupLoop()`, `go s.cleanupLoop()`, `go d.cleanup()`, …) | `parking_lot::RwLock`/`Mutex`; recurring work exposed as explicit `cleanup()` methods | Rust has no scheduler; callers drive cleanup from a periodic task. The lock semantics and the cleanup predicates are identical. No behaviour depends on cleanup timing for correctness (it only evicts stale entries). |
| `RequestContext` guards `Decisions`/`ThreatScore` with a mutex because inspectors could run concurrently | Plain fields, mutated sequentially | The engine invokes inspectors sequentially for one request in both languages; the lock was never load-bearing within a single inspection. |
| `PerformanceManager.Inspect` runs the inspector in a goroutine and abandons it on `time.After(timeout)` (`PERF_004`). | Inspector runs synchronously; circuit-breaker / worker-cap / failure accounting preserved. **`PERF_004` timeout is not enforced by killing the call.** | A synchronous Rust function cannot be cancelled; spawning a thread per inspection to emulate "abandon" would leak the thread and its work. The timeout value is retained in `Stats`/`timeout_for` for parity. Enforcement happens via the circuit breaker. |

## 2. Interface forcing function: `&mut RequestContext`

Go inspectors mutated `ctx` freely (e.g. the bot detector sets `ctx.IsBot = true`
for a verified good bot; JWT/OAuth set `ctx.UserID`). The Rust `Inspector` trait
therefore takes `&mut RequestContext`. This is a mechanical consequence of Rust's
borrow rules, not a behaviour change.

## 3. Go strings can hold invalid UTF-8; Rust `String` cannot

`PARSER_010` (invalid UTF-8) and `PARSER_012` (overlong UTF-8) inspect the raw
**bytes** of the path/method/headers. Go strings are byte sequences, so these can
fire. A Rust `String` is always valid UTF-8, so the checks could never fire.

**Mitigation:** `HttpRequest` carries `raw_path` and `raw_header` byte vectors,
and `RequestContext.raw_scan_targets` holds the exact byte set Go scanned
(`path`, `method`, real IP, every header key and value). `has_overlong_utf8_bytes`
and the invalid-UTF-8 check operate on those bytes. Tests:
`parser::tests::invalid_utf8_in_raw_path_triggers_parser_010`,
`has_overlong_detects_*`.

## 4. Regex engine: RE2 (Go) vs `regex` (Rust)

The two engines accept slightly different syntax. Two concrete hazards were
found and fixed, not glossed over:

1. **Bare braces.** RE2 treats `{{`, `{%`, `#{`, `${{` in the SSTI rules as
   literals; the Rust `regex` crate rejects a bare `{` as a malformed repetition
   operator. The SSTI patterns were rewritten with escaped braces (`\{\{`, …).
   Without this, SSTI detection would have silently stopped working.
   Test: `rce::tests::ssti_blocked`.
2. **Escapes.** Patterns that in Go relied on `\"` inside a double-quoted
   literal were converted to Rust raw strings (`r#"..."#`) preserving the same
   regex meaning.

Semantics used identically by both engines and therefore unchanged: `(?i)`,
`(?s)`, `(?m)`, `\b`, `\xNN`, `\x{...}`. Where Go used `$` under `(?s)` (end of
text), Rust `$` also matches end of text without `(?m)`.

## 5. `unicode.Is(unicode.C, r)` in the parser hardener

`PARSER_011` guards the unicode-control regex with
`r > MaxASCII && (unicode.Is(unicode.C, r) || r == '\uFFFD')`. Rust's `std` has
no Unicode general-category API. The guard was reproduced by enumerating exactly
the code points for which the combined guard is true (verified against the
Unicode categories):

- `U+00AD`, `U+200B`, `U+200C`, `U+200D`, `U+FEFF` (category Cf) → C
- `U+FFF0`–`U+FFF8` (Cn), `U+FFF9`–`U+FFFB` (Cf) → C
- `U+FFFD` (explicit `r == '\uFFFD'` clause)

Notably `U+2028`/`U+2029` (Zl/Zp) are **excluded**, so `PARSER_011` does not
fire for them — matching Go, where the category guard rejects them.

## 6. Network I/O behind traits

Go used `net/http`, `net.LookupAddr`, and MaxMind readers. These are behind
traits so the crates compile and unit-test without network, and a real
implementation is provided or documented:

| Concern | Go | Rust | Status |
|---|---|---|---|
| JWKS fetch, OAuth introspection, CAPTCHA verify | `net/http` | `JwksFetcher`/`IntrospectClient`/`CaptchaHttp` traits; `UreqFetcher`/`UreqCaptchaHttp` real impls | Real HTTP (`ureq`); tests use fakes |
| Reverse DNS for good-bot verification | `net.LookupAddr` | `ReverseDnsResolver` trait; `NoReverseDns` default | **TODO:** default returns no names, so every good-bot UA is treated as unverified (`BOT002` Challenge) — exactly what Go does when the lookup errors/returns nothing. A production resolver is injected. |
| GeoIP (MaxMind `.mmdb`) | `oschwald/geoip2-golang` | `GeoBackend` trait; `StubBackend` default | **TODO:** stub returns the "not available" record (`XX`/`Unknown`), matching Go when the DB fails to open. |
| WASM runtime | `wazero` | `WasmRuntime`/`WasmModule` traits; `NoWasmRuntime` default | **TODO:** default loads no modules (WASM disabled in shipped config). Behaviour/structure preserved. |
| Outbound SIEM (Splunk/ES), ML client | `net/http` | trait-backed + `ureq` impls | Real HTTP; payload builders are unit-tested |
| TLS termination | `crypto/tls` | `rustls` (`crates/proxy/src/tls.rs`) | Implemented: cert/key load, min version, optional mTLS client verification, ALPN http/1.1 |
| ACME (auto certs) | `golang.org/x/crypto/acme/autocert` | — | **Not implemented.** Supply `tls.cert_file`/`tls.key_file`; provision certs out of band. |
| Prometheus exposition | `promhttp` | `serve_metrics` (separate listener) | Implemented at `prometheus.path` on `prometheus.port` |
| PostgreSQL `initDatabase` ping | `lib/pq` | — | **Not wired.** The original was a goroutine that blocked forever (`<-make(chan struct{})`) doing nothing observable. |

## 7. Go bugs reproduced faithfully (not fixed)

A faithful port must not "improve" behaviour, or it is no longer the same
system. The following are reproduced exactly, and the tests assert the
bug-compatible result:

1. **`checkDuplicateHeaders` (desync) is dead code.** Go iterated
   `ctx.Headers`, a map holding one value per key, so `seen[lower]` can never
   exceed 1 and `DSYNC_008` never fires. Reproduced.
2. **`sprayTracker.usernames` is never populated (credential).** So
   `uniqueUsernames` is always 0 and `CRED004`/`CRED005` never fire.
3. **`AuditLog` license prefix bug (billing).** `Generate` emits
   `FWL-<payload>.<sig>`, but `Validate` decodes `parts[0]` = `"FWL-<payload>"`,
   hashing different bytes than were signed, so a generated token fails its own
   signature check. Reproduced and documented in
   `billing::tests::generate_prepends_prefix_and_validate_matches_go_quirk`.
4. **`ResolveUpstream` port-append condition.** Go appends `site.Port` only when
   the upstream contains **no** `:` — so `http://backend` (which contains `:`
   after the scheme) is left unchanged. Reproduced.
5. **Adaptive `tarpit` sleeps inline** (`time.Sleep`) — a real, intentional
   delay in both languages.
6. **`body/response` size caps and partial-flush semantics** of
   `ResponseWriter` are preserved byte-for-byte, including the
   "report full input as written" behaviour on the flush path.

## 8. Default-vs-merged config

Go's `yaml.Unmarshal(data, cfg)` unmarshals **into a pre-populated default
struct**, so omitted YAML keys keep non-zero Go defaults. serde's
`#[serde(default)]` uses `Type::default()` instead. To preserve behaviour, the
loader parses the user document to a `serde_yaml::Value`, serialises
`default_config()` to another, deep-merges (user wins), then deserialises.
Test: `manager::tests::deep_merge_preserves_nonzero_defaults`.

## 9. Duration parsing in YAML

Go `yaml.v3` unmarshals `time.Duration` from duration strings (`"10s"`) or
integers (nanoseconds). A serde `with = "crate::duration"` helper reproduces
both forms via `humantime`.

## 10. Time representation

Go's `time.Time` JSON is RFC3339. `blocklist::Entry` and `compliance::AuditEntry`
store/emit RFC3339 strings to match. Internal ordering uses `Instant` (sub-second
precision, as Go's `time.Time` comparisons had). The audit hash chain hashes the
RFC3339Nano timestamp string, matching `computeEntryHash`.

## 11. CLI

`cmd/ctl` (cobra) → `fortressctl` (clap); `cmd/proxy` flags → `fortresswaf`
(clap). Flag names, endpoints, output formatting and env fallbacks
(`FORTRESS_API_URL`, `FORTRESS_API_KEY`, `CONFIG_PATH`) are preserved. The
`version` command prints `rustc stable` where Go printed the Go version — the
one intentional output difference.

## 12. `ureq` client semantics

`ureq` returns `Err(Status(code, resp))` for non-2xx by default, whereas Go's
`http.Client` returns the response with no error. The `healthcheck` and `fortressctl`
handle both arms; the health probe treats any non-2xx as failure (exit 1),
matching the Go exit codes (2 usage, 1 failure, 0 success).

## 13. Emitted HTML pages render from a token spine

The two pages the WAF emits — the block page and the challenge interstitial —
were ported byte-for-byte in the first pass, then refactored to render from a
**token spine** (`crates/proxy/src/tokens.rs`), a Rust port of the semantic
layer in `tokens/*.json`. This is a deliberate improvement over the Go pages,
which hardcoded hex colours, an off-scale `padding: 40px`, and a copy issue
(3+ em-dashes):

- **Token discipline.** Pages reference semantic CSS custom properties
  (`var(--surface-page)`, `var(--text-secondary)`, `var(--space-md)`,
  `var(--radius-lg)`, `var(--focus-ring)`, …) — never raw hex. The values match
  the DTCG token files exactly, including the dark overrides.
- **Both modes.** The token block emits `:root` (light),
  `@media (prefers-color-scheme: dark)`, and `:root[data-theme="dark"]`.
- **Accessibility.** A `<main>` landmark with `aria-labelledby`, a lucide inline
  SVG error icon (never emoji), `lang="en"`, a real `<button>` with a
  `:focus-visible` ring, a `prefers-reduced-motion` guard, and `aria-busy` on the
  challenge page.
- **Copy.** Plain-language English with no em-dash flood (the Go page was
  Bahasa Indonesia with repeated em-dashes).

Verified by the deterministic `ui-craft` gates: the rendered block and challenge
pages each score **100/100 (grade A)** on anti-slop, token discipline, and
static accessibility. Tests lock the invariants in
(`base_css_has_no_raw_hex_outside_token_block`,
`base_css_has_no_off_scale_px_in_page_rules`, `token_css_defines_light_and_dark`,
`all_token_names_unique`).

This is the one place the Rust port intentionally produces *different bytes*
than the Go backend; the semantics (status codes, headers, escaping, token
generation) are unchanged.

---

## Verification summary

- `cargo build --release` — clean across the workspace.
- `cargo clippy --workspace` — zero warnings; `cargo fmt --check` — clean.
- `cargo test --workspace` — **288 tests passing, 0 failing.**
- **Attack-corpus parity** (`crates/proxy/tests/attack_corpus.rs`) replays the
  project's own training corpus through the Rust engine and meets every
  documented floor:

  | Category | Blocked | Rate | Floor |
  |---|---|---|---|
  | sql-injection | 268/398 | 67.3% | 65% |
  | xss | 134/135 | 99.3% | 99% |
  | rce | 45/73 | 61.6% | 50% |
  | command-injection | 66/100 | 66.0% | 60% |
  | path-traversal | 65/75 | 86.7% | 50% |
  | lfi | 22/34 | 64.7% | 50% |
  | ssti | 58/91 | 63.7% | 55% |
  | ldap-injection | 81/109 | 74.3% | 70% |
  | xxe | 31/31 | 100.0% | 99% |
  | webshell | 36/45 | 80.0% | 80% |
  | deserialization | 34/35 | 97.1% | 90% |

  Canonical payloads per category are blocked, and the 50-value benign corpus
  produces **zero** false positives.

- **Live end-to-end**: `fortresswaf` starts, serves `/health`, blocks a SQLi
  request with `403` + `X-FortressWAF-Rule: SQLI016`, forwards benign traffic
  (502 when the upstream is down), and serves the authenticated admin API.
