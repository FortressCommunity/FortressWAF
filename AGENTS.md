# AGENTS.md — Working on FortressWAF

This is the entry-point instruction file for AI coding agents. Read it before
making changes. It tells you what this repository is, how to build and test it,
what "done" means here, and the traps that will make you look wrong.

For the full product description, read [README.md](README.md). For every
intentional difference from the original implementation, read
[`rust/DEVIATIONS.md`](rust/DEVIATIONS.md) — it is the source of truth for
"why does this behave differently".

**Deep skill:** [`skills/fortresswaf-rust-backend`](skills/fortresswaf-rust-backend/SKILL.md)
is the long-form version of this file for backend work. This `AGENTS.md` is the
short version every agent should read first.

---

## 1. What this repository is

A self-hosted Web Application Firewall / API security gateway, written in
**Rust**. The backend is a cargo workspace under `rust/`; it is the only backend
(there is no Go code — it was removed).

```text
rust/crates/
  core/       request model + detection Engine + all 25 inspectors
  config/     YAML config: defaults, validation, hot reload
  services/   ratelimit, blocklist, session, geo, reputation, siem, ml,
              tenant, sites, billing, compliance, traincorpus, uaparse
  proxy/      WAF pipeline, admin API, TLS (rustls), hyper servers, binary
  ctl/        fortressctl CLI + healthcheck probe
dashboard/    Next.js management UI (separate; TypeScript)
ml-engine/    Python ML sidecar (separate; not in the request path)
deploy/       docker-compose, config, monitoring, Caddyfile
tests/attack-corpus/   payloads replayed by the parity test
docs/         design documentation (aspirational — see README Known Limitations)
```

**Three binaries:** `fortresswaf` (proxy + admin API + metrics),
`fortressctl` (CLI), `healthcheck` (readiness probe).

**25 inspectors** live in `rust/crates/core/src/inspectors/` (plus
`captcha`/`grpc`/`soap` in `rust/crates/core/src/middleware.rs`).

---

## 2. The one rule that matters most

> **Never state a number or a "pass" you did not measure. Run the command, read
> its real output, report that.**

This repository's documentation has, historically, been held to a high bar of
honesty: Known Limitations in the README lists what does *not* work, and
detection rates are recorded as measured percentages with floors, not "100%".
Match that. If you claim "tests pass", you ran the tests. If you claim a
detection rate, it came out of the corpus test.

---

## 3. Build, test, lint — the only commands you need

Run these from `rust/` (the cargo workspace root). Do not invent other commands;
check `rust/Cargo.toml` first if unsure.

```bash
# Build everything (release)
cargo build --release --locked
#   -> rust/target/release/{fortresswaf,fortressctl,healthcheck}

# Test everything (288 tests, including the attack-corpus parity test)
cargo test --workspace --locked

# Just the detection-parity test, with per-category rates printed
cargo test -p fwaf-proxy --test attack_corpus --locked -- --nocapture

# Lint — BOTH must be clean; CI fails on either
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

From the repository root, the `Makefile` wraps the same commands
(`make build`, `make test`, `make lint-rust`) — prefer these when a contributor
asked for "the make target". `make help` lists all targets.

`--locked` is used everywhere: if you change a dependency, run
`cargo update` / `cargo add` and commit the updated `rust/Cargo.lock` in the
same change.

---

## 4. Definition of done

A change is done only when **all** of these hold (they are exactly what CI runs):

- [ ] `cargo fmt --check` is clean
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` is clean
- [ ] `cargo build --release --locked` succeeds
- [ ] `cargo test --workspace --locked` passes (0 failed)
- [ ] If you touched detection logic, the attack-corpus floors still hold and
      the benign corpus still produces **zero** false positives
- [ ] If you touched the emitted HTML (block page / challenge page), its
      ui-craft score did not regress (see §8)

Do not report success between a failing step and a fix. Run the gate, fix, re-run.

---

## 5. How detection is verified (do not weaken this)

`rust/crates/proxy/tests/attack_corpus.rs` replays the project's own corpus and
asserts a **per-category floor**. It also asserts the benign corpus is not
blocked. If your change lowers a category below its floor, the build fails —
that is the point.

| Category | Floor |
|---|---|
| sql-injection | 65% |
| xss | 99% |
| rce | 50% |
| command-injection | 60% |
| path-traversal | 50% |
| lfi | 50% |
| ssti | 55% |
| ldap-injection | 70% |
| xxe | 99% |
| webshell | 80% |
| deserialization | 90% |

Rule: **never lower a floor to make a test pass.** If a real regression is
found, fix the inspector. If the floor was genuinely wrong, justify it in the
commit message and in `rust/DEVIATIONS.md`.

---

## 6. Adding or changing an inspector

1. Implement the `Inspector` trait in
   `rust/crates/core/src/inspectors/<name>.rs`:

   ```rust
   use crate::action::{Action, Decision};
   use crate::context::RequestContext;
   use crate::engine::{EngineError, Inspector};

   pub struct MyInspector;

   impl Inspector for MyInspector {
       fn name(&self) -> &str { "my_inspector" }
       fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
           // read from ctx; return Ok(Some(decision)) to flag, Ok(None) to pass
           Ok(None)
       }
   }
   ```

2. Register it: add a field to `EngineConfig` and place it in the ordered
   `inspectors` list in `rust/crates/core/src/engine.rs`. **Order matters** —
   the first `Action::Block` short-circuits the pipeline.
3. Wire it from config in `rust/crates/proxy/src/engine_factory.rs`
   (`build_engine_config`).
4. Add unit tests in the same file under `#[cfg(test)]`, and add a
   no-false-positive test on ordinary input where relevant.
5. Add corpus payloads under `ml-engine/training/data/<category>/payloads.txt`
   if the category exists.

Keep rule IDs, scores, and severities stable unless you are deliberately
changing them — they are referenced by the corpus test, the admin API, and the
audit log.

---

## 7. Behaviour parity is intentional — including bugs

This backend is a faithful port. Several *original bugs* are reproduced on
purpose because "fixing" them would change behaviour. Before you "clean
something up", check `rust/DEVIATIONS.md`. If it is listed there, it is
deliberate. Examples: dead duplicate-header detection, an always-zero spray
counter, a license-token prefix quirk. Do not silently change these.

When you *must* diverge, add an entry to `rust/DEVIATIONS.md` explaining what,
why, and the test that pins it.

---

## 8. The emitted HTML pages have a token spine

The WAF emits two pages: the block page and the challenge page
(`rust/crates/proxy/src/pipeline.rs`). They render from a token spine in
`rust/crates/proxy/src/tokens.rs` — **semantic CSS custom properties only, no
raw hex below the token block**, light + dark, WCAG AA, a lucide icon (never
emoji).

If you edit them:

- Reference `var(--…)` tokens; do not hardcode colors or off-scale px.
- Keep the `<main>` landmark, `aria-labelledby`, `:focus-visible` ring, and
  `prefers-reduced-motion` guard.
- Verify with the ui-craft gates (deterministic, not taste):
  render the page and run `score_ui` — it must not regress from **100/A**.

The invariants are locked by tests in `tokens.rs` (`base_css_has_no_raw_hex_*`,
`base_css_has_no_off_scale_px_*`, `token_css_defines_light_and_dark`).

---

## 9. Build infrastructure is Rust end to end

If you change how the project builds, these must move together — a mismatch
breaks CI or the image:

| File | Role |
|---|---|
| `Dockerfile` | `rust:1-slim` builder → `distroless/cc`; `cargo build --release --locked` |
| `Makefile` | wraps cargo; same target names contributors expect |
| `.github/workflows/ci.yml` | fmt + clippy + build + test (Rust), plus Python and frontend |
| `.github/workflows/{benchmark,release,security}.yml` | bench, release packaging, `cargo audit` |
| `install.sh` | detects `cargo`, builds from `rust/` |
| `.pre-commit-config.yaml` | local `cargo fmt` + `cargo clippy` hooks |

There is **no OpenSSL dependency** — TLS is `rustls` (ring), pure Rust.

---

## 10. Running the server

```bash
cargo build --release --locked
./target/release/fortresswaf \
    --config ../deploy/config.yaml --proxy-port 8080 --admin-port 8443
```text

- Plain HTTP unless `tls.enabled: true` with `tls.cert_file` / `tls.key_file`.
  TLS is `rustls`; **there is no ACME auto-provisioning** — supply certs.
- Admin API (and `/health`, `/ready`, `/live`, `/metrics`) is on `--admin-port`.
- Prometheus exposition is on its own listener when `prometheus.enabled`.
- The reverse proxy forwards to each site's `upstream`; an unreachable upstream
  yields `502`.

Smoke test after a change:

```bash
curl -s http://localhost:8443/health                     # {"status":"healthy",...}
curl -s -o /dev/null -w '%{http_code}\n' \
  'http://localhost:8080/search?q=1%27%20OR%20%271%27%3D%271'   # 403
```text

---

## 11. Traps that make agents look wrong here

- **Untracked files that are not yours.** `.claude/`, `.agents/`, `design-systems/`,
  `accessibility/`, `components/`, `frameworks/`, `taste/`, `content/`,
  `CLAUDE.md`, and many `scripts/*` are pre-existing design-system assets. They
  are unrelated to the backend. Do not "clean them up", do not add them to a
  backend PR, and do not treat `CLAUDE.md` as this project's agent file.
- **`docs/` is aspirational.** It describes an intended product (billing,
  multi-tenancy, enterprise tiers) the code does not implement. Trust the
  README and `deploy/config.yaml`.
- **`rules/` is not loaded at runtime.** Detection comes from the built-in
  inspectors only.
- **The ML sidecar is not in the request path** and its bundled model is
  untrained. Do not wire it in without saying so.
- **Some `services/` modules are not wired into the proxy** (`billing`,
  `tenant`, `geo`, `ratelimit`, `reputation`, `session`). They compile; they are
  not features.
- **Do not add `--allow` to silence a lint.** Fix the lint, or (for a
  deliberately Go-shaped construction) document why in the crate's `lib.rs`.
- **Do not build a client or clone the whole `Config` per request.** The proxy
  shares one pooled upstream client on `AppState`, and `Manager::get()` returns
  a cheap `Arc<Config>`. Doing either per request hangs the proxy under load —
  it was a real bug (see `rust/DEVIATIONS.md` §14).

---

## 12. Commits and PRs

- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`). A breaking
  change uses `!` and a `BREAKING CHANGE:` footer.
- Keep a PR focused. One concern per PR; do not bundle unrelated untracked
  assets.
- In the PR body, state the **measured** verification (the actual command output
  lines), not a promise.
- Before opening a PR, run §4 in full and paste the results.

---

## 13. Where to look when unsure

| Question | File |
|---|---|
| What does the product do / not do? | `README.md` (esp. Known Limitations) |
| Why does X differ from the original? | `rust/DEVIATIONS.md` |
| Deep backend workflow for agents | `skills/fortresswaf-rust-backend/SKILL.md` |
| How do I build/run/debug? | `docs/development.md`, `Makefile` |
| How is architecture laid out? | `docs/architecture.md` |
| What are the config fields? | `rust/crates/config/src/types.rs`, `deploy/config.yaml` |
| What rules exist? | `rust/crates/core/src/inspectors/*.rs` (each rule's doc comment) |
| What does CI run? | `.github/workflows/ci.yml` |

When this file and the code disagree, **the code wins** — and then fix this file.
