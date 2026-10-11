//! Built-in detection inspectors.
//!
//! Each module is a faithful port of the corresponding `internal/engine/*.go`
//! file.

pub mod adaptive;
pub mod api_protect;
pub mod auth;
pub mod behavioral;
pub mod bot;
pub mod credential;
pub mod csrf;
pub mod ddos;
pub mod desync;
pub mod ebpf;
pub mod graphql;
pub mod ja3;
pub mod ml_assist;
pub mod mtls;
pub mod open_redirect;
pub mod parser;
pub mod protocol;
pub mod rce;
pub mod response_leak;
pub mod rewrite;
pub mod rule_engine;
pub mod sqli;
pub mod ssrf;
pub mod upload;
pub mod wasm;
pub mod websocket;
pub mod xss;
