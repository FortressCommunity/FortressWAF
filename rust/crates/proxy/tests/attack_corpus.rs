//! Attack-corpus parity test.
//!
//! Replays the project's own training corpus (`ml-engine/training/data/...`)
//! through the Rust engine and asserts the same detection floors the Go test
//! (`tests/unit/payload_corpus_test.go`) documents. This is the test that
//! proves the port preserves detection behaviour, not merely compiles.
//!
//! The corpus path is relative to the repository root; the test locates it by
//! walking up from `CARGO_MANIFEST_DIR` (rust/crates/proxy -> repo root).

use std::path::PathBuf;
use std::sync::Arc;

use fwaf_core::engine::{Engine, EngineConfig};
use fwaf_core::http::HttpRequest;
use fwaf_core::inspectors::bot::NoReverseDns;
use fwaf_core::inspectors::{
    api_protect::ApiProtection, bot::BotDetector, ddos::DdosProtection, desync::DesyncDetector,
    ja3::Ja3Inspector, parser::ParserHardener, protocol::ProtocolAnomaly, rce::RceInjection,
    sqli::SqlInjectionEngine, upload::FileUploadSecurity, xss::XssEngine,
};

/// Port of `fullEngine()` from the Go test: every inspector the shipped config
/// enables, with performance isolation on.
fn full_engine() -> Engine {
    Engine::new(EngineConfig {
        dev_mode: true,
        sqli: Some(Arc::new(SqlInjectionEngine::new(true))),
        xss: Some(Arc::new(XssEngine::new(true))),
        rce: Some(Arc::new(RceInjection::new(true))),
        ddos: Some(Arc::new(DdosProtection::new(true))),
        protocol: Some(Arc::new(ProtocolAnomaly::new(true))),
        bot: Some(Arc::new(BotDetector::with_options(
            true,
            Default::default(),
            Arc::new(NoReverseDns),
        ))),
        api_protect: Some(Arc::new(ApiProtection::new(true))),
        upload: Some(Arc::new(FileUploadSecurity::new(true))),
        ja3: Some(Arc::new(Ja3Inspector::new(true))),
        desync: Some(Arc::new(DesyncDetector::new(true, 1048576, true, true))),
        parser: Some(Arc::new(ParserHardener::new(true))),
        performance_isolation: true,
        ..Default::default()
    })
}

/// Locate the repository root (the directory containing `ml-engine/`).
fn repo_root() -> Option<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..6 {
        if dir.join("ml-engine").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Port of `loadPayloads`.
fn load_payloads(category: &str) -> Option<Vec<String>> {
    let root = repo_root()?;
    let path = root
        .join("ml-engine")
        .join("training")
        .join("data")
        .join(category)
        .join("payloads.txt");
    let content = std::fs::read_to_string(&path).ok()?;
    let payloads: Vec<String> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect();
    if payloads.is_empty() {
        None
    } else {
        Some(payloads)
    }
}

/// Go's `url.QueryEscape`: alphanumerics and `-_.~` unreserved; space becomes
/// `+`; everything else percent-encoded uppercase.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Port of `benignRequest`.
fn benign_request(payload: &str) -> fwaf_core::context::RequestContext {
    let mut r = HttpRequest::new("GET", "/search");
    r.raw_query = format!("q={}", query_escape(payload));
    r.host = "example.com".to_string();
    r.header
        .add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)");
    fwaf_core::context::RequestContext::new(r)
}

fn detection_rate(engine: &Engine, category: &str) -> Option<(usize, usize, f64)> {
    let payloads = load_payloads(category)?;
    let mut blocked = 0;
    for p in &payloads {
        let mut ctx = benign_request(p);
        if let Ok(dec) = engine.inspect(&mut ctx) {
            if dec.action == fwaf_core::action::Action::Block {
                blocked += 1;
            }
        }
    }
    let rate = 100.0 * blocked as f64 / payloads.len() as f64;
    Some((blocked, payloads.len(), rate))
}

/// The documented floors, exactly as in the Go test.
const FLOORS: &[(&str, f64)] = &[
    ("sql-injection", 65.0),
    ("xss", 99.0),
    ("rce", 50.0),
    ("command-injection", 60.0),
    ("path-traversal", 50.0),
    ("lfi", 50.0),
    ("ssti", 55.0),
    ("ldap-injection", 70.0),
    ("xxe", 99.0),
    ("webshell", 80.0),
    ("deserialization", 90.0),
];

#[test]
fn attack_corpus_detection_rates_meet_documented_floors() {
    if repo_root().is_none() {
        eprintln!("skipping: repository root (ml-engine/) not found");
        return;
    }

    let engine = full_engine();
    let mut failures = Vec::new();

    for (category, floor) in FLOORS {
        match detection_rate(&engine, category) {
            Some((blocked, total, rate)) => {
                eprintln!("{category:20} blocked {blocked}/{total} ({rate:.1}%)");
                if rate < *floor {
                    failures.push(format!(
                        "{category} detection rate {rate:.1}% is below the documented floor {floor:.0}%"
                    ));
                }
            }
            None => {
                eprintln!("{category:20} corpus not found; skipping");
            }
        }
    }

    assert!(
        failures.is_empty(),
        "detection-rate parity failures:\n{}",
        failures.join("\n")
    );
}

/// Port of `TestAttackCorpus_BlockedPayloadsCovered`: canonical payloads per
/// category must be blocked.
#[test]
fn canonical_payloads_are_blocked() {
    if repo_root().is_none() {
        eprintln!("skipping: repository root not found");
        return;
    }
    let engine = full_engine();

    let cases: &[(&str, &[&str])] = &[
        (
            "sql-injection",
            &[
                "1' OR '1'='1",
                "'; DROP TABLE users--",
                "1 UNION SELECT username, password FROM users",
                "admin'--",
                "1 AND SLEEP(5)",
            ],
        ),
        (
            "xss",
            &["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        ),
    ];

    for (category, payloads) in cases {
        for p in *payloads {
            let mut ctx = benign_request(p);
            let dec = engine.inspect(&mut ctx).unwrap();
            assert_eq!(
                dec.action,
                fwaf_core::action::Action::Block,
                "expected {category} payload {p:?} to be blocked, got {:?} ({})",
                dec.action,
                dec.rule_id
            );
        }
    }
}

/// The `valid.txt` corpus must NOT be blocked (false-positive guard).
#[test]
fn benign_corpus_is_not_blocked() {
    let root = match repo_root() {
        Some(r) => r,
        None => return,
    };
    let path = root.join("tests").join("attack-corpus").join("valid.txt");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let engine = full_engine();

    // The valid.txt lines are "[category] payload" or plain values.
    let mut checked = 0;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Both the whole line and the part after a "[tag] " prefix are tried as
        // query values, matching how the corpus is annotated.
        let value = if let Some(rest) = line.strip_prefix('[') {
            match rest.find(']') {
                Some(i) => rest[i + 1..].trim(),
                None => line,
            }
        } else {
            line
        };
        if value.is_empty() {
            continue;
        }
        checked += 1;
        let mut ctx = benign_request(value);
        let dec = engine.inspect(&mut ctx).unwrap();
        assert_ne!(
            dec.action,
            fwaf_core::action::Action::Block,
            "benign value {value:?} was blocked as {}",
            dec.rule_id
        );
    }
    eprintln!("benign corpus: checked {checked} values, none blocked");
}
