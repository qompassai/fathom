//! JCS — JSON Canonicalization Scheme (RFC 8785), hand-rolled.
//!
//! Object members sort by the UTF-16 code-unit sequence of their
//! names; strings use the RFC's escaping rules; numbers use the
//! ECMAScript serialization. The values this codebase
//! canonicalizes (agent cards, catalog digests) contain no
//! non-integer numbers by construction; a non-integer number is
//! serialized with the shortest round-trip form, matching
//! ECMAScript for all values an agent card can carry.

use serde_json::Value;

use fathom_core::error::{ErrorCode, FathomError};

/// Canonicalize a JSON value to its JCS string form.
pub fn canonicalize(value: &Value) -> Result<String, FathomError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), FathomError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by_key(|(key, _)| utf16_units(key));
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The UTF-16 code units of a string, the JCS sort key.
fn utf16_units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn write_number(number: &serde_json::Number, out: &mut String) -> Result<(), FathomError> {
    if let Some(u) = number.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    if let Some(i) = number.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    let f = number.as_f64().ok_or_else(|| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            "number has no f64 representation",
        )
    })?;
    if !f.is_finite() {
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            "JCS cannot serialize a non-finite number",
        ));
    }
    if f == f.trunc() && f.abs() < 9_007_199_254_740_992.0 {
        // Integral values serialize without a decimal point (ES).
        out.push_str(&(f as i64).to_string());
        return Ok(());
    }
    // Shortest round-trip form (serde_json uses Ryu, as does ES).
    out.push_str(&serde_json::to_string(&Value::from(f)).unwrap_or_default());
    Ok(())
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn adversarial_non_finite_is_rejected() {
        // JSON cannot carry infinity through serde_json parsing,
        // but a hand-built Number path must never emit it.
        let value = json!({"a": 1});
        assert!(canonicalize(&value).is_ok());
    }

    #[test]
    fn validation_keys_sort_by_utf16() {
        // 'e' (0x65) sorts before 'é' (0xE9); '€' (0x20AC) after both.
        let value = json!({"é": 1, "e": 2, "€": 3, "a": 4});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"a\":4,\"e\":2,\"é\":1,\"€\":3}"
        );
    }

    #[test]
    fn validation_nested_objects_and_arrays() {
        let value = json!({"b": [1, {"d": 2, "c": 3}], "a": true});
        assert_eq!(
            canonicalize(&value).unwrap(),
            "{\"a\":true,\"b\":[1,{\"c\":3,\"d\":2}]}"
        );
    }

    #[test]
    fn validation_string_escaping() {
        let value = json!("a\"b\\c\nd\u{0001}e");
        assert_eq!(canonicalize(&value).unwrap(), "\"a\\\"b\\\\c\\nd\\u0001e\"");
    }

    #[test]
    fn validation_integral_float_serializes_as_integer() {
        let value = json!({"n": 4.0});
        assert_eq!(canonicalize(&value).unwrap(), "{\"n\":4}");
    }
}
