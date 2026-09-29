//! FortressWAF proxy: engine factory, WAF request pipeline, admin API, and the
//! HTTP servers. Faithful port of `cmd/proxy`.

// Style lints that fire on the deliberately Go-shaped structure of a faithful
// port (nested ifs/matches, similar from_str constructors, complex handler
// signatures). Rewriting them would diverge from the reference structure.
#![allow(clippy::collapsible_if)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::single_match)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_question_mark)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::type_complexity)]

pub mod engine_factory;
pub mod handlers;
pub mod loginlimit;
pub mod pipeline;
pub mod server;
pub mod tls;
pub mod tokens;

pub use engine_factory::{build_engine, build_engine_config, build_rewrite_manager};
pub use loginlimit::LoginLimiter;
pub use pipeline::{Metrics, Outcome, PipelineResult};
pub use server::{serve_admin, serve_proxy, AppState};
