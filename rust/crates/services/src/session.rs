//! Session tracking.
//!
//! Port of `internal/session/session.go`. Create/get/update/delete, the byUser
//! and byIP indexes, risk scoring, fixation detection, and serialization are
//! preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDecision {
    pub rule_id: String,
    pub action: String,
    pub score: f64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_id: String,
    pub real_ip: String,
    pub user_agent: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub asn: u32,
    pub created_at: i64,
    pub last_seen: i64,
    #[serde(default)]
    pub request_count: i64,
    #[serde(default)]
    pub risk_score: f64,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<SessionDecision>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,

    /// Internal created-at instant (not serialized), for fixation timing.
    #[serde(skip, default = "instant_now")]
    pub created_instant: Instant,
    #[serde(skip, default = "instant_now")]
    pub last_seen_instant: Instant,
}

fn instant_now() -> Instant {
    Instant::now()
}

struct State {
    sessions: HashMap<String, Session>,
    by_user: HashMap<String, String>,
    by_ip: HashMap<String, Vec<String>>,
}

pub struct Store {
    state: Arc<RwLock<State>>,
    ttl: Duration,
}

impl Store {
    /// Port of `NewStore`.
    pub fn new(ttl: Duration) -> Self {
        Store {
            state: Arc::new(RwLock::new(State {
                sessions: HashMap::new(),
                by_user: HashMap::new(),
                by_ip: HashMap::new(),
            })),
            ttl,
        }
    }

    /// Port of `Create`.
    pub fn create(&self, ip: &str, user_agent: &str) -> Session {
        let now = Instant::now();
        let session = Session {
            id: generate_id(),
            user_id: String::new(),
            real_ip: ip.to_string(),
            user_agent: user_agent.to_string(),
            country: String::new(),
            asn: 0,
            created_at: now_unix(),
            last_seen: now_unix(),
            request_count: 0,
            risk_score: 0.0,
            tags: vec![],
            metadata: HashMap::new(),
            blocked: false,
            decisions: vec![],
            fingerprint: String::new(),
            created_instant: now,
            last_seen_instant: now,
        };

        let mut state = self.state.write();
        state
            .by_ip
            .entry(ip.to_string())
            .or_default()
            .push(session.id.clone());
        state.sessions.insert(session.id.clone(), session.clone());
        session
    }

    /// Port of `Get`.
    pub fn get(&self, id: &str) -> Option<Session> {
        self.state.read().sessions.get(id).cloned()
    }

    /// Port of `GetOrCreate`.
    pub fn get_or_create(&self, id: &str, ip: &str, user_agent: &str) -> Session {
        if !id.is_empty() {
            if let Some(session) = self.get(id) {
                self.update_last_seen(id);
                return self.get(id).unwrap_or(session);
            }
        }
        self.create(ip, user_agent)
    }

    fn update_last_seen(&self, id: &str) {
        let mut state = self.state.write();
        if let Some(s) = state.sessions.get_mut(id) {
            s.last_seen = now_unix();
            s.last_seen_instant = Instant::now();
            s.request_count += 1;
        }
    }

    /// Port of `Update`.
    pub fn update(&self, id: &str, f: impl FnOnce(&mut Session)) {
        let mut state = self.state.write();
        if let Some(s) = state.sessions.get_mut(id) {
            f(s);
            s.last_seen = now_unix();
            s.last_seen_instant = Instant::now();
        }
    }

    /// Port of `Delete`.
    pub fn delete(&self, id: &str) {
        let mut state = self.state.write();
        if let Some(session) = state.sessions.remove(id) {
            if state
                .by_user
                .get(&session.user_id)
                .map(|v| v == id)
                .unwrap_or(false)
            {
                state.by_user.remove(&session.user_id);
            }
            if let Some(ips) = state.by_ip.get_mut(&session.real_ip) {
                ips.retain(|sid| sid != id);
                if ips.is_empty() {
                    state.by_ip.remove(&session.real_ip);
                }
            }
        }
    }

    /// Port of `GetByUser`.
    pub fn get_by_user(&self, user_id: &str) -> Option<Session> {
        let state = self.state.read();
        state
            .by_user
            .get(user_id)
            .and_then(|id| state.sessions.get(id))
            .cloned()
    }

    /// Port of `GetByIP`.
    pub fn get_by_ip(&self, ip: &str) -> Vec<Session> {
        let state = self.state.read();
        let ids = state.by_ip.get(ip).cloned().unwrap_or_default();
        ids.iter()
            .filter_map(|id| state.sessions.get(id).cloned())
            .collect()
    }

    /// Port of `AddRiskScore`.
    pub fn add_risk_score(&self, id: &str, score: f64, rule_id: &str, action: &str) {
        let mut state = self.state.write();
        let session = match state.sessions.get_mut(id) {
            Some(s) => s,
            None => return,
        };
        session.risk_score += score;
        session.decisions.push(SessionDecision {
            rule_id: rule_id.to_string(),
            action: action.to_string(),
            score,
            timestamp: now_unix(),
        });
        if session.risk_score > 100.0 {
            session.risk_score = 100.0;
        }
    }

    /// Port of `DetectSessionFixation`.
    pub fn detect_session_fixation(&self, new_session_id: &str, old_session_id: &str) -> bool {
        let _ = new_session_id;
        if !old_session_id.is_empty() {
            if let Some(old) = self.get(old_session_id) {
                if old.created_instant.elapsed() < Duration::from_secs(60) {
                    return true;
                }
            }
        }
        false
    }

    /// Port of `Serialize`.
    pub fn serialize(&self) -> Result<String, String> {
        let state = self.state.read();
        serde_json::to_string(&state.sessions).map_err(|e| e.to_string())
    }

    /// Port of `Deserialize`.
    pub fn deserialize(&self, data: &str) -> Result<(), String> {
        let sessions: HashMap<String, Session> =
            serde_json::from_str(data).map_err(|e| e.to_string())?;
        let mut state = self.state.write();
        state.sessions = sessions.clone();
        state.by_ip.clear();
        state.by_user.clear();
        for (id, session) in &sessions {
            state
                .by_ip
                .entry(session.real_ip.clone())
                .or_default()
                .push(id.clone());
            if !session.user_id.is_empty() {
                state.by_user.insert(session.user_id.clone(), id.clone());
            }
        }
        Ok(())
    }

    /// Port of the `cleanupLoop` body.
    pub fn cleanup(&self) {
        let mut state = self.state.write();
        let ttl = self.ttl;
        let expired: Vec<String> = state
            .sessions
            .iter()
            .filter(|(_, s)| s.last_seen_instant.elapsed() > ttl)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(session) = state.sessions.remove(&id) {
                if state
                    .by_user
                    .get(&session.user_id)
                    .map(|v| v == &id)
                    .unwrap_or(false)
                {
                    state.by_user.remove(&session.user_id);
                }
                if let Some(ips) = state.by_ip.get_mut(&session.real_ip) {
                    ips.retain(|sid| sid != &id);
                    if ips.is_empty() {
                        state.by_ip.remove(&session.real_ip);
                    }
                }
            }
        }
    }

    /// Port of `Count`.
    pub fn count(&self) -> usize {
        self.state.read().sessions.len()
    }

    /// Port of `ActiveUsers`.
    pub fn active_users(&self) -> usize {
        self.state.read().by_user.len()
    }
}

fn generate_id() -> String {
    let mut b = [0u8; 16];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get() {
        let s = Store::new(Duration::from_secs(3600));
        let sess = s.create("1.2.3.4", "curl");
        let got = s.get(&sess.id).unwrap();
        assert_eq!(got.real_ip, "1.2.3.4");
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn get_or_create_reuses_existing() {
        let s = Store::new(Duration::from_secs(3600));
        let sess = s.create("1.2.3.4", "curl");
        let again = s.get_or_create(&sess.id, "1.2.3.4", "curl");
        assert_eq!(again.id, sess.id);
        assert_eq!(again.request_count, 1);
    }

    #[test]
    fn delete_removes_indexes() {
        let s = Store::new(Duration::from_secs(3600));
        let sess = s.create("1.2.3.4", "curl");
        s.delete(&sess.id);
        assert_eq!(s.count(), 0);
        assert!(s.get_by_ip("1.2.3.4").is_empty());
    }

    #[test]
    fn risk_score_capped() {
        let s = Store::new(Duration::from_secs(3600));
        let sess = s.create("1.2.3.4", "curl");
        s.add_risk_score(&sess.id, 150.0, "R", "block");
        assert_eq!(s.get(&sess.id).unwrap().risk_score, 100.0);
    }

    #[test]
    fn serialize_roundtrip() {
        let s = Store::new(Duration::from_secs(3600));
        s.create("1.2.3.4", "curl");
        let data = s.serialize().unwrap();
        let s2 = Store::new(Duration::from_secs(3600));
        s2.deserialize(&data).unwrap();
        assert_eq!(s2.count(), 1);
    }
}
