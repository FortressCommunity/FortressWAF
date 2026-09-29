---
name: fortresswaf-rust-backend
description: Works on the FortressWAF Rust backend correctly — builds, tests, lints, adds or changes detection inspectors, and updates the emitted block/challenge pages, without weakening the detection-parity floors or breaking the token spine. Use whenever a task touches rust/, the WAF engine, inspectors, config, the proxy pipeline, the admin API, or the emitted HTML pages in this repository.
---

# FortressWAF Rust Backend

## Overview

FortressWAF is a self-hosted Web Application Firewall written in **Rust**. The
backend is a cargo workspace under `rust/` and is the only backend (the original
Go implementation was removed). This skill encodes how to change it without
regressing behaviour.

Two properties make this repository unusual, and both punish agents that
improvise:

1. **Detection correctness is measured, not asserted.** A corpus test replays
   ~1,400 payloads and fails if any attack category drops below a documented
   floor, or if any benign payload is blocked. You cannot "make tests pass" by
   weakening this.
2. **The documentation is honest by construction.** The README lists what does
   *not* work. `rust/DEVIATIONS.md` lists every intentional difference from the
   original, including reproduced bugs. Match that bar or your change will look
   wrong even if it compiles.

The authoritative entry point is [`AGENTS.md`](../../AGENTS.md) at the repo
root. This skill is the deep version.

## When to Use

- Adding a new detection inspector, or changing an existing one's matching logic,
  rule IDs, scores, or severities.
- Touching the request pipeline, decision ordering, config loading, the admin
  API, or the proxy servers.
- Editing the emitted block page or challenge page (the token-spine HTML).
- Changing build infrastructure (Dockerfile, Makefile, CI, `install.sh`).
- Any task where someone says "fix", "add detection for", "why does the WAF
  block/not block X", or "update the Rust backend".

**When NOT to use:** the Next.js dashboard (`dashboard/`, TypeScript), the
Python ML sidecar (`ml-engine/`), or the design-system assets (`.claude/`,
`design-systems/`, `CLAUDE.md`) — those are separate and out of scope for this
skill.

## Where things live

```text
rust/crates/core/src/engine.rs        Engine pipeline, decision ordering
rust/crates/core/src/inspectors/*.rs  the 25 inspectors (one file each)
rust/crates/core/src/middleware.rs    captcha / grpc / soap inspectors + ResponseWriter
rust/crates/core/src/context.rs       RequestContext (what inspectors read)
rust/crates/core/src/action.rs        Decision / Action
rust/crates/config/src/types.rs       every config field
rust/crates/proxy/src/engine_factory.rs  config -> Engine wiring
rust/crates/proxy/src/pipeline.rs     WAF request switch + block/challenge pages
rust/crates/proxy/src/tokens.rs       the page token spine
rust/crates/proxy/src/server.rs       hyper proxy/admin/metrics servers
rust/crates/proxy/src/tls.rs          rustls termination
rust/crates/proxy/tests/attack_corpus.rs  the parity gate
rust/DEVIATIONS.md                    every intentional difference
```

## The loop

Run these from `rust/`. They mirror CI exactly.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --release --locked
cargo test --workspace --locked
```

`--locked` everywhere. If you add or change a dependency, commit the updated
`rust/Cargo.lock` in the same change.

### Prove detection parity, explicitly

When you touch any inspector, also run the parity test and read the numbers:

```bash
cargo test -p fwaf-proxy --test attack_corpus --locked -- --nocapture
```

It prints a line per category (`xss blocked 134/135 (99.3%)`) and
`benign corpus: checked 50 values, none blocked`. Report those actual lines.

## Adding an inspector

1. New file in `rust/crates/core/src/inspectors/`, implement the trait:

   ```rust
   use crate::action::{Action, Decision};
   use crate::context::RequestContext;
   use crate::engine::{EngineError, Inspector};

   pub struct MyInspector;

   impl Inspector for MyInspector {
       fn name(&self) -> &str { "my_inspector" }
       fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
           if ctx.path.contains("bad") {
               return Ok(Some(
                   Decision::new(Action::Block, 90.0)
                       .with_rule_id("MY-001")
                       .with_rule_name("My Rule")
                       .with_severity("high")
                       .with_evidence("matched bad path"),
               ));
           }
           Ok(None)
       }
   }
   ```

2. **Order matters.** Add the field to `EngineConfig` and place it in the ordered
   `inspectors` vec in `engine.rs`. The first `Action::Block` short-circuits
   every later inspector, so a greedy inspector early in the list can mask the
   rest.
3. Wire it from config in `engine_factory.rs::build_engine_config`.
4. Unit tests in the same file (`#[cfg(test)]`), including a case that asserts a
   **benign** input is *not* blocked. False positives are the failure mode that
   matters most for a WAF.
5. Add corpus samples under `ml-engine/training/data/<category>/payloads.txt` for
   an existing category.

## Don't do these

- **Don't lower a detection floor** to make `attack_corpus` pass. Fix the
  inspector, or justify the floor change loudly in the commit and in
  `rust/DEVIATIONS.md`.
- **Don't "clean up" a documented quirk.** Several original bugs are reproduced
  on purpose (dead duplicate-header check, always-zero spray counter, license
  prefix quirk). `rust/DEVIATIONS.md` says which. Changing them is a behaviour
  change and must be recorded there.
- **Don't hardcode colors or off-scale px** in the emitted pages — use the
  `var(--…)` token spine. Don't replace a lucide icon with an emoji.
- **Don't build a client, or clone the whole `Config`, per request.** The proxy
  shares one pooled upstream client on `AppState` and `Manager::get()` returns a
  cheap `Arc<Config>`. Constructing either per request exhausts sockets or
  thrashes memory and makes the proxy hang under load (this was a real bug,
  documented in `rust/DEVIATIONS.md` §14).
- **Don't add `#[allow(clippy::…)]`** to silence a lint. Fix it; if the
  construction mirrors the `Go` original deliberately, the crate already allows
  it in `lib.rs` with a comment.
- **Don't touch the untracked design-system assets** (`.claude/`, `design-systems/`,
  `accessibility/`, `components/`, `frameworks/`, `taste/`, `content/`,
  `CLAUDE.md`, most of `scripts/`). They are unrelated to the backend.
- **Don't state a number you didn't measure.** Run the command; report its output.

## Editing the emitted pages

The WAF emits two HTML pages from `pipeline.rs` (`block_page`,
`challenge_page`), styled by the token spine in `tokens.rs`. Invariants, locked
by tests: no raw hex below the token block, only on-scale px, light + dark
token blocks, a `<main>` landmark with `aria-labelledby`, a `:focus-visible`
ring, a `prefers-reduced-motion` guard, and a lucide inline SVG (never emoji).

To verify after a change, render and score with the ui-craft gates — the target
is **100/A**, and it must not regress. The invariants are also enforced by the
tests in `tokens.rs`.

## If you must diverge

This backend is a faithful port. Faithfulness is a feature. When the right
change genuinely differs from the original, add an entry to
`rust/DEVIATIONS.md` with: what differs, why, and the test that pins the new
behaviour. That file is the contract; an undocumented divergence is a bug.

## Verification

Before reporting done, confirm every line is true and paste the real output:

- [ ] `cargo fmt --check` — clean
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` — clean
- [ ] `cargo build --release --locked` — succeeds
- [ ] `cargo test --workspace --locked` — 0 failed
- [ ] if detection changed: `attack_corpus` floors hold, benign corpus still 0
      false positives
- [ ] if pages changed: ui-craft score did not regress (100/A)
- [ ] any intentional behaviour change is recorded in `rust/DEVIATIONS.md`

**Note:** run each command after a change that could affect it; re-running on
unchanged code adds no confidence.

## Common Rationalizations

| Rationalization | Reality |
|---|---|
| "It compiles, so it's fine" | Compiling says nothing about detection accuracy or parity. Run the corpus test. |
| "The floor is too strict, I'll lower it" | The floor exists to catch exactly your regression. Fix the inspector. |
| "This quirk looks like a bug, I'll fix it" | If it's in `DEVIATIONS.md`, it's deliberate. Changing it silently corrupts parity. |
| "I'll add `#[allow]` to get clippy green" | That hides the problem. Fix the lint. |
| "The docs say it does X, so I'll build to X" | `docs/` is aspirational. Trust the README, the config, and the code. |
| "Tests pass" (without running them) | Run them. Report the actual `N passed, 0 failed`. |

## Red Flags

- A detection floor was edited in `attack_corpus.rs`
- clippy/fmt failures "handled" with `#[allow]` or by not running them
- Raw hex or off-scale px in the emitted pages
- A new inspector that blocks ordinary traffic (no benign test added)
- A behaviour change with no `DEVIATIONS.md` entry
- Backend PR touching `.claude/`, `design-systems/`, or other design assets
- A number in a commit or PR that no command produced
