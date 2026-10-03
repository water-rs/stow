//! The Analytics Engine SQL API's `FORMAT JSON` decoding.
//!
//! Every `analytics_engine/sql` reader shares the `{"data": […]}`
//! [`Envelope`]. `FORMAT JSON` quotes 64-bit integers, so `count()` and
//! integer sums (`UInt64` columns) arrive as `"0"` while `Float64`
//! aggregates stay plain JSON numbers. Decode each numeric column
//! through the deserializer matching its column type: [`de_u64`] for
//! `UInt64`, [`de_f64`] for `Float64`.

use serde::Deserialize;

/// The `FORMAT JSON` envelope: result rows arrive under `data`, each an
/// object keyed by the query's column aliases.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    /// One entry per result row.
    pub data: Vec<T>,
}

/// Deserialize a `UInt64` column — `FORMAT JSON` emits it as a quoted
/// string. A plain JSON number is accepted too, for integer columns
/// narrower than the 64-bit quoting threshold.
///
/// # Errors
/// The value is neither a JSON number nor a string containing an
/// unsigned integer.
pub fn de_u64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Integer {
        Plain(u64),
        Quoted(String),
    }
    match Integer::deserialize(deserializer)? {
        Integer::Plain(value) => Ok(value),
        Integer::Quoted(text) => text.parse().map_err(serde::de::Error::custom),
    }
}

/// Deserialize a `Float64` column — `FORMAT JSON` emits it as a plain
/// JSON number; the quoted form is accepted as well.
///
/// # Errors
/// The value is neither a JSON number nor a string containing a float.
pub fn de_f64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        Plain(f64),
        Quoted(String),
    }
    match Number::deserialize(deserializer)? {
        Number::Plain(value) => Ok(value),
        Number::Quoted(text) => text.parse().map_err(serde::de::Error::custom),
    }
}

/// Lossless `Float64 → u64` for callers that consume an estimate as a
/// count: accepts only finite non-negative integral values in range —
/// never clamps a negative or out-of-range aggregate, and reports a
/// fractional estimate rather than silently rounding it.
///
/// # Errors
/// The value is non-finite, negative, fractional, or above `u64::MAX`.
pub fn f64_to_u64_exact(value: f64, what: &str) -> Result<u64, String> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= u64::MAX as f64 {
        Ok(value as u64)
    } else {
        Err(format!(
            "{what}: non-integral or out-of-range estimate {value}"
        ))
    }
}
