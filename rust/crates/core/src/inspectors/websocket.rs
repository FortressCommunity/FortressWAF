//! WebSocket frame inspection and parsing.
//!
//! Port of `internal/engine/websocket.go`. Rule IDs, scores, framing
//! (opcode parsing, masking, extended lengths) and the per-IP frame stats are
//! preserved exactly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::action::{Action, Decision};
use crate::config_types::WebSocketConfig;
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

// WebSocket opcodes (mirrors github.com/gorilla/websocket constants).
pub const TEXT_MESSAGE: i32 = 1;
pub const BINARY_MESSAGE: i32 = 2;
pub const CLOSE_MESSAGE: i32 = 8;
pub const PING_MESSAGE: i32 = 9;
pub const PONG_MESSAGE: i32 = 10;

#[derive(Debug, Clone)]
pub struct Frame {
    pub r#type: i32,
    pub payload: Vec<u8>,
    pub finished: bool,
    pub seq: i64,
}

#[derive(Default)]
struct FrameStats {
    count: i32,
    bytes: i64,
    last_seen: Option<Instant>,
    types: HashMap<i32, i32>,
}

pub struct WebSocketInspector {
    max_frame_size: i32,
    max_message_size: i32,
    max_depth: i32,
    max_frames_per_min: i32,
    max_bytes_per_min: i32,
    block_on_limit: bool,
    frame_log: Arc<Mutex<HashMap<String, Arc<Mutex<FrameStats>>>>>,
    allowed_types: HashMap<i32, bool>,
    strict_mode: bool,
    enable_ping: bool,
    enable_pong: bool,
    enable_close: bool,
    connection_timeout: Duration,
}

impl WebSocketInspector {
    pub fn new(cfg: WebSocketConfig) -> Self {
        let mut allowed_types = HashMap::new();
        if cfg.allowed_types.is_empty() {
            allowed_types.insert(TEXT_MESSAGE, true);
            allowed_types.insert(BINARY_MESSAGE, true);
        } else {
            for t in cfg.allowed_types {
                allowed_types.insert(t, true);
            }
        }

        WebSocketInspector {
            max_frame_size: cfg.max_frame_size,
            max_message_size: cfg.max_message_size,
            max_depth: cfg.max_depth,
            max_frames_per_min: cfg.max_frames_per_min,
            max_bytes_per_min: cfg.max_bytes_per_min,
            block_on_limit: cfg.block_on_limit,
            frame_log: Arc::new(Mutex::new(HashMap::new())),
            allowed_types,
            strict_mode: cfg.strict_mode,
            enable_ping: cfg.enable_ping,
            enable_pong: cfg.enable_pong,
            enable_close: cfg.enable_close,
            connection_timeout: Duration::from_secs(cfg.connection_timeout_sec.max(0) as u64),
        }
    }

    fn is_websocket(&self, ctx: &RequestContext) -> bool {
        let upgrade = ctx
            .headers
            .get("Upgrade")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        let connection = ctx
            .headers
            .get("Connection")
            .cloned()
            .unwrap_or_default()
            .to_lowercase();
        // Go read "Sec-Websocket-Key"/"Sec-Websocket-Version"; our map is
        // case-insensitive, so the canonical spelling resolves the same value.
        let ws_key = ctx
            .headers
            .get("Sec-WebSocket-Key")
            .cloned()
            .unwrap_or_default();
        let ws_version = ctx
            .headers
            .get("Sec-WebSocket-Version")
            .cloned()
            .unwrap_or_default();

        upgrade.contains("websocket")
            && connection.contains("upgrade")
            && !ws_key.is_empty()
            && ws_version == "13"
    }

    fn get_stats(&self, ip: &str) -> Arc<Mutex<FrameStats>> {
        let stats = {
            let map = self.frame_log.lock();
            map.get(ip).cloned()
        };
        let stats = stats.unwrap_or_else(|| {
            let mut map = self.frame_log.lock();
            map.entry(ip.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(FrameStats::default())))
                .clone()
        });

        // Go: if now.Sub(stats.LastSeen) > time.Minute { Count=0; Bytes=0 }.
        // With the zero time, the subtract is enormous, so the first call
        // resets (a no-op, since both start at zero).
        {
            let mut s = stats.lock();
            let reset = match s.last_seen {
                Some(t) => t.elapsed() > Duration::from_secs(60),
                None => true,
            };
            if reset {
                s.count = 0;
                s.bytes = 0;
            }
        }

        stats
    }

    /// Port of `InspectMessage`.
    pub fn inspect_message(&self, ctx: &RequestContext, frame: &Frame) -> Option<Decision> {
        let stats = self.get_stats(&ctx.real_ip);

        {
            let mut s = stats.lock();
            s.count += 1;
            s.bytes += frame.payload.len() as i64;
            s.last_seen = Some(Instant::now());
            *s.types.entry(frame.r#type).or_insert(0) += 1;
        }

        if frame.r#type == CLOSE_MESSAGE && !self.enable_close {
            return Some(
                Decision::new(Action::Block, 50.0)
                    .with_rule_id("WS-002")
                    .with_rule_name("WebSocket close not allowed")
                    .with_severity("medium"),
            );
        }

        if frame.r#type == PING_MESSAGE && !self.enable_ping {
            return Some(
                Decision::new(Action::Block, 30.0)
                    .with_rule_id("WS-003")
                    .with_rule_name("WebSocket PING not allowed")
                    .with_severity("low"),
            );
        }

        if frame.r#type == PONG_MESSAGE && !self.enable_pong {
            return Some(
                Decision::new(Action::Block, 30.0)
                    .with_rule_id("WS-004")
                    .with_rule_name("WebSocket PONG not allowed")
                    .with_severity("low"),
            );
        }

        if !self
            .allowed_types
            .get(&frame.r#type)
            .copied()
            .unwrap_or(false)
        {
            return Some(
                Decision::new(Action::Block, 75.0)
                    .with_rule_id("WS-005")
                    .with_rule_name("WebSocket message type not allowed")
                    .with_severity("high")
                    .with_evidence(format!("type={}", frame.r#type)),
            );
        }

        if frame.payload.len() as i32 > self.max_frame_size {
            return Some(
                Decision::new(Action::Block, 70.0)
                    .with_rule_id("WS-006")
                    .with_rule_name("WebSocket frame size exceeded")
                    .with_severity("high")
                    .with_evidence(format!(
                        "frame_size={}, limit={}",
                        frame.payload.len(),
                        self.max_frame_size
                    )),
            );
        }

        if self.strict_mode && frame.r#type == TEXT_MESSAGE {
            if let Some(dec) = self.check_injection(&frame.payload) {
                return Some(dec);
            }
        }

        if self.max_depth > 0 && frame.r#type == TEXT_MESSAGE {
            if let Some(dec) = self.check_json_depth(&frame.payload) {
                return Some(dec);
            }
        }

        Some(Decision::new(Action::Allow, 0.0))
    }

    fn check_injection(&self, payload: &[u8]) -> Option<Decision> {
        let patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "eval(",
            "document.",
            "window.",
            "expression(",
            "url(",
            "href=",
        ];
        let lower = String::from_utf8_lossy(payload).to_lowercase();
        for pattern in patterns {
            if lower.contains(pattern) {
                return Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("WS-INJ-001")
                        .with_rule_name("WebSocket injection pattern detected")
                        .with_severity("critical")
                        .with_evidence(format!("pattern={pattern}")),
                );
            }
        }
        None
    }

    fn check_json_depth(&self, payload: &[u8]) -> Option<Decision> {
        let mut nested = 0;
        for &b in payload {
            if b == b'{' || b == b'[' {
                nested += 1;
                if nested > self.max_depth {
                    return Some(
                        Decision::new(Action::Block, 75.0)
                            .with_rule_id("WS-JSON-001")
                            .with_rule_name("WebSocket JSON depth exceeded")
                            .with_severity("high")
                            .with_evidence(format!("depth={nested}, limit={}", self.max_depth)),
                    );
                }
            }
        }
        None
    }

    /// Port of `ParseFrame`. Returns a `Frame` with a freshly-allocated payload
    /// (Go mutated the input slice in place while unmasking; this copies, which
    /// is observably equivalent for callers and avoids aliasing the input).
    pub fn parse_frame(&self, data: &[u8]) -> Result<Frame, String> {
        if data.len() < 2 {
            return Err("frame too small".to_string());
        }

        let first = data[0];
        let fin = first & 0x80 != 0;
        let opcode = (first & 0x0f) as i32;

        let mask = data[1] & 0x80 != 0;
        let mut payload_len = (data[1] & 0x7f) as i64;

        let mut idx: usize = 2;

        if payload_len == 126 {
            if data.len() < 4 {
                return Err("invalid extended length".to_string());
            }
            payload_len = ((data[2] as i64) << 8) | (data[3] as i64);
            idx = 4;
        } else if payload_len == 127 {
            if data.len() < 10 {
                return Err("invalid extended length".to_string());
            }
            payload_len = ((data[2] as i64) << 56)
                | ((data[3] as i64) << 48)
                | ((data[4] as i64) << 40)
                | ((data[5] as i64) << 32)
                | ((data[6] as i64) << 24)
                | ((data[7] as i64) << 16)
                | ((data[8] as i64) << 8)
                | (data[9] as i64);
            idx = 10;
        }

        if mask {
            idx += 4;
        }

        if data.len() < idx + payload_len as usize {
            return Err("unexpected EOF".to_string());
        }

        let mut payload = data[idx..idx + payload_len as usize].to_vec();
        if mask {
            let key = &data[idx - 4..idx];
            for i in 0..payload.len() {
                payload[i] ^= key[i % 4];
            }
        }

        Ok(Frame {
            r#type: opcode,
            payload,
            finished: fin,
            seq: 0,
        })
    }

    /// Port of the `Upgrader.CheckOrigin` logic (origin allow-list).
    pub fn check_origin(&self, origin: &str, allowed_origins: &[String]) -> bool {
        if allowed_origins.is_empty() {
            return true;
        }
        if origin.is_empty() {
            return true;
        }
        for allowed in allowed_origins {
            if origin.eq_ignore_ascii_case(allowed) {
                return true;
            }
            if origin.contains(allowed.as_str()) {
                return true;
            }
        }
        false
    }

    /// Accessor for the configured connection timeout.
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
}

impl Inspector for WebSocketInspector {
    fn name(&self) -> &str {
        "websocket_inspection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !self.is_websocket(ctx) {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        let stats = self.get_stats(&ctx.real_ip);
        let count = stats.lock().count;

        if self.max_frames_per_min > 0 && count > self.max_frames_per_min {
            if self.block_on_limit {
                return Ok(Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("WS-001")
                        .with_rule_name("WebSocket frame rate limit exceeded")
                        .with_severity("high")
                        .with_evidence(format!(
                            "frames_per_min={count}, limit={}",
                            self.max_frames_per_min
                        )),
                ));
            }
            return Ok(Some(
                Decision::new(Action::Monitor, 40.0)
                    .with_rule_id("WS-001")
                    .with_rule_name("WebSocket frame rate limit exceeded")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "frames_per_min={count}, limit={}",
                        self.max_frames_per_min
                    )),
            ));
        }

        Ok(Some(Decision::new(Action::Allow, 0.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ws() -> WebSocketInspector {
        WebSocketInspector::new(WebSocketConfig {
            max_frame_size: 1024,
            max_frames_per_min: 5,
            allowed_types: vec![TEXT_MESSAGE, BINARY_MESSAGE],
            ..Default::default()
        })
    }

    #[test]
    fn non_websocket_allowed() {
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        assert_eq!(
            ws().inspect(&mut ctx).unwrap().unwrap().action,
            Action::Allow
        );
    }

    #[test]
    fn parse_unmasked_text_frame() {
        let w = ws();
        // FIN + text opcode, length 5, "hello"
        let data = [0x81u8, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let frame = w.parse_frame(&data).unwrap();
        assert_eq!(frame.r#type, TEXT_MESSAGE);
        assert!(frame.finished);
        assert_eq!(frame.payload, b"hello");
    }

    #[test]
    fn parse_masked_frame_unmasks() {
        let w = ws();
        let key = [0x01u8, 0x02, 0x03, 0x04];
        let masked: Vec<u8> = b"abcde"
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        let mut data = vec![0x81, 0x85];
        data.extend_from_slice(&key);
        data.extend_from_slice(&masked);
        let frame = w.parse_frame(&data).unwrap();
        assert_eq!(frame.payload, b"abcde");
    }

    #[test]
    fn injection_in_text_frame_blocked() {
        let w = WebSocketInspector::new(WebSocketConfig {
            max_frame_size: 1024,
            allowed_types: vec![TEXT_MESSAGE, BINARY_MESSAGE],
            strict_mode: true,
            ..Default::default()
        });
        let ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let frame = Frame {
            r#type: TEXT_MESSAGE,
            payload: b"<script>alert(1)</script>".to_vec(),
            finished: true,
            seq: 0,
        };
        let dec = w.inspect_message(&ctx, &frame).unwrap();
        assert_eq!(dec.rule_id, "WS-INJ-001");
    }

    #[test]
    fn disallowed_type_blocked() {
        let w = ws();
        let ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let frame = Frame {
            r#type: 3, // reserved/unhandled
            payload: vec![],
            finished: true,
            seq: 0,
        };
        let dec = w.inspect_message(&ctx, &frame).unwrap();
        assert_eq!(dec.rule_id, "WS-005");
    }

    #[test]
    fn frame_too_small_errors() {
        let w = ws();
        assert!(w.parse_frame(&[0x81]).is_err());
    }
}
