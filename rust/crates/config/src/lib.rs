//! FortressWAF configuration.
//!
//! Faithful port of `internal/config`. See `types.rs`, `defaults.rs`, and
//! `manager.rs` for the ported surfaces.

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

pub mod defaults;
pub mod duration;
pub mod manager;
pub mod types;

pub use defaults::default_config;
pub use manager::{
    default_manager, expand_env_refs, get_config, load, save_to_file, set_default_manager,
    validate, Manager,
};
pub use types::*;
