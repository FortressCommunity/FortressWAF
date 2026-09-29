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
pub mod ddos;
pub mod desync;
pub mod ebpf;
pub mod graphql;
pub mod ja3;
pub mod mtls;
pub mod parser;
pub mod protocol;
pub mod rce;
pub mod response_leak;
pub mod rewrite;
pub mod sqli;
pub mod upload;
pub mod wasm;
pub mod websocket;
pub mod xss;
