# Project skills for AI agents

These are this repository's **own** skills — instructions for working correctly
on the FortressWAF codebase. They are version-controlled with the code they
describe, so they stay in sync with it.

> Not to be confused with the untracked design-system assets under `.claude/`
> and `.agents/`, which are third-party tooling and are deliberately gitignored.

## Start here

Read [`../AGENTS.md`](../AGENTS.md) first. It is the entry point any agent
should load before touching this repository: what the project is, the exact
build/test/lint commands, the definition of done, and the traps.

## Skills

| Skill | Use when |
|---|---|
| [`fortresswaf-rust-backend`](fortresswaf-rust-backend/SKILL.md) | Working on the Rust backend: inspectors, the engine pipeline, config, the proxy/admin servers, the emitted block/challenge pages, or build infrastructure. |

## Format

Each skill is a directory with a `SKILL.md` whose YAML frontmatter has `name`
and `description`; the description says *when to use it*. The body is Markdown
with `Overview`, `When to Use`, the working process, and a `Verification`
checklist. This matches the format the wider agent ecosystem reads.
