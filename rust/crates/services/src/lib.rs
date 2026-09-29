//! FortressWAF services: rate limiting, block list, sessions, reputation,
//! GeoIP, User-Agent parsing, SIEM, ML client, tenants, and sites. Faithful
//! ports of the `internal/*` packages.

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
#![allow(clippy::collapsible_match)]
#![allow(clippy::unnecessary_lazy_evaluations)]

pub mod billing;
pub mod blocklist;
pub mod compliance;
pub mod geo;
pub mod ml;
pub mod ratelimit;
pub mod reputation;
pub mod session;
pub mod siem;
pub mod sites;
pub mod tenant;
pub mod traincorpus;
pub mod uaparse;
