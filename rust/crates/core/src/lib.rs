//! FortressWAF core: request/decision model, the detection engine, and the
//! foundational inspectors' shared types.
//!
//! This crate is a faithful Rust port of the Go packages under
//! `internal/engine`. Behaviour (decision actions, rule IDs, scores, ordering,
//! and edge cases) is preserved deliberately and verified by the tests ported
//! from the Go suite and the attack corpus.

// The inspectors mirror the Go structs field-for-field, which leaves some
// fields unread in Rust (they existed for Go's SetX accessors or JSON output).
// And several Go functions contain deliberate dead assignments (e.g. a score
// increment immediately before a fixed-score return) that are reproduced
// verbatim for behavioural fidelity. Both are intentional; silence the lints
// rather than delete parity information.
#![allow(dead_code)]
#![allow(unused_assignments)]
// Style lints that fire on the deliberately Go-shaped control flow of a
// faithful port (collapsible nested ifs, identical return branches that mirror
// a Go switch, map iteration style). Rewriting them would diverge from the
// reference structure, so they are allowed rather than "fixed".
#![allow(clippy::collapsible_if)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::manual_contains)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::int_plus_one)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::needless_question_mark)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::manual_map)]
#![allow(clippy::match_like_matches_macro)]

pub mod action;
pub mod clientip;
pub mod confidence;
pub mod config_types;
pub mod context;
pub mod counter;
pub mod engine;
pub mod http;
pub mod inspectors;
pub mod middleware;
pub mod performance;
pub mod regex_util;
pub mod shadow;

pub use action::{Action, Decision};
pub use clientip::{parse_trusted_proxies, TrustedProxies};
pub use confidence::ConfidenceScorer;
pub use context::{RequestContext, ResponseContext};
pub use engine::{Engine, EngineConfig, EngineError, Inspector};
pub use http::{HttpRequest, HttpResponse};
