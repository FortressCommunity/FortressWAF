//! Duration serde helpers.
//!
//! Go's `yaml.v3` unmarshals a `time.Duration` from either a duration string
//! ("10s", "1m30s") or an integer (nanoseconds). These helpers reproduce that:
//! a YAML string is parsed with `humantime`, and a YAML integer is treated as
//! nanoseconds.

use serde::{Deserialize, Deserializer, Serializer};
use std::time::Duration;

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_yaml::Value::deserialize(deserializer)?;
    match v {
        serde_yaml::Value::String(s) => {
            if s.is_empty() {
                return Ok(Duration::ZERO);
            }
            humantime::parse_duration(&s).map_err(D::Error::custom)
        }
        serde_yaml::Value::Number(n) => {
            let nanos = n
                .as_i64()
                .ok_or_else(|| D::Error::custom("duration integer out of range"))?;
            Ok(Duration::from_nanos(nanos.max(0) as u64))
        }
        serde_yaml::Value::Null => Ok(Duration::ZERO),
        other => Err(D::Error::custom(format!(
            "invalid duration value: {other:?}"
        ))),
    }
}

pub fn serialize<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Emit Go-compatible duration strings (e.g. "10s", "1h0m0s" is not exact,
    // but humantime's format matches Go closely enough for round-tripping
    // through a human-authored config).
    serializer.serialize_str(&humantime::format_duration(*d).to_string())
}

/// A module usable with `#[serde(with = "...")]` for `Duration` fields.
pub mod duration_opt {
    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v = Option::<serde_yaml::Value>::deserialize(deserializer)?;
        match v {
            None | Some(serde_yaml::Value::Null) => Ok(None),
            Some(val) => {
                let d: Duration = serde_yaml::from_value(val).map_err(serde::de::Error::custom)?;
                Ok(Some(d))
            }
        }
    }

    pub fn serialize<S>(d: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match d {
            Some(d) => super::serialize(d, serializer),
            None => serializer.serialize_none(),
        }
    }
}
