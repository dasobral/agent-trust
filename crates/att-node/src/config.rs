//! Environment configuration helpers and small shared utilities.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// A required variable.
pub fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing environment variable {name}"))
}

/// An optional variable; empty counts as unset.
pub fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn or_default(name: &str, default: &str) -> String {
    optional(name).unwrap_or_else(|| default.to_owned())
}

pub fn number(name: &str, default: u64) -> Result<u64, String> {
    match optional(name) {
        None => Ok(default),
        Some(text) => text
            .parse()
            .map_err(|_| format!("{name} must be an unsigned integer")),
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Logs one structured line to stderr: `{"ts", "role", "event", ...fields}`.
pub fn log(role: &str, event: &str, fields: Value) {
    let mut line = serde_json::json!({ "ts": unix_now(), "role": role, "event": event });
    if let (Some(line), Value::Object(fields)) = (line.as_object_mut(), fields) {
        line.extend(fields);
    }
    eprintln!("{line}");
}

/// A required lowercase hex field of a JSON object.
pub fn hex_field(value: &Value, key: &str) -> Result<Vec<u8>, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|text| hex::decode(text).ok())
        .ok_or_else(|| format!("malformed: {key}"))
}

pub fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("malformed: {key}"))
}

/// The code that begins an error string (`"read_fenced: detail"` gives `"read_fenced"`).
pub fn error_code(error: &str) -> String {
    let code = error.split(':').next().unwrap_or(error).trim();
    if code.is_empty() {
        "rejected".to_owned()
    } else {
        code.to_owned()
    }
}
