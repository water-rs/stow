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

/// Lossless `Float64 → u64` for estimate-as-count callers.
///
/// Accepts only finite non-negative integral values in range — never
/// clamps a negative or out-of-range aggregate, and reports a
/// fractional estimate rather than silently rounding it.
///
/// # Errors
/// The value is non-finite, negative, fractional, or not below
/// `2^64`. `u64::MAX as f64` rounds to exactly `2^64`, so the bound is
/// exclusive — a `2^64` estimate must reject rather than saturate.
// The bounds check above proves `value` finite, non-negative,
// integral, and below `2^64`, so `as u64` is exact; `u64::MAX as f64`
// is the deliberate exclusive bound the doc names.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn f64_to_u64_exact(value: f64, what: &str) -> Result<u64, String> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value < u64::MAX as f64 {
        Ok(value as u64)
    } else {
        Err(format!(
            "{what}: non-integral or out-of-range estimate {value}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, de_f64, de_u64, f64_to_u64_exact};
    use serde::Deserialize;

    /// Exactly `2^64` — the smallest `f64` a saturating `as u64` cast
    /// would accept in error.
    const TWO_POW_64: f64 = 18_446_744_073_709_551_616.0;

    #[test]
    fn exact_conversion_bounds_at_two_pow_64() {
        assert!(f64_to_u64_exact(TWO_POW_64, "t").is_err());
        // The largest `f64` below `2^64` converts losslessly.
        let largest = TWO_POW_64 - 2048.0;
        assert_eq!(
            f64_to_u64_exact(largest, "t"),
            Ok(18_446_744_073_709_549_568)
        );
        assert_eq!(f64_to_u64_exact(0.0, "t"), Ok(0));
        assert_eq!(f64_to_u64_exact(41.0, "t"), Ok(41));
        assert!(f64_to_u64_exact(1.5, "t").is_err());
        assert!(f64_to_u64_exact(-1.0, "t").is_err());
        assert!(f64_to_u64_exact(f64::NAN, "t").is_err());
        assert!(f64_to_u64_exact(f64::INFINITY, "t").is_err());
    }

    /// The quoted-number decoders used for `FORMAT JSON` columns:
    /// `UInt64` arrives `"42"`, `Float64` as `42` — both accept the
    /// other spelling too.
    #[derive(Debug, Deserialize)]
    struct Row {
        #[serde(deserialize_with = "de_u64")]
        count: u64,
        #[serde(deserialize_with = "de_f64")]
        weight: f64,
    }

    #[test]
    fn format_json_decoders_accept_native_column_spellings() {
        let envelope: Envelope<Row> = serde_json::from_str(
            r#"{"data":[{"count":"42","weight":1.5},{"count":7,"weight":"2"}]}"#,
        )
        .expect("envelope");
        assert_eq!(envelope.data[0].count, 42);
        assert!((envelope.data[0].weight - 1.5).abs() < f64::EPSILON);
        assert_eq!(envelope.data[1].count, 7);
        assert!((envelope.data[1].weight - 2.0).abs() < f64::EPSILON);
        assert!(
            serde_json::from_str::<Envelope<Row>>(r#"{"data":[{"count":"x","weight":1.0}]}"#)
                .is_err()
        );
    }
}
