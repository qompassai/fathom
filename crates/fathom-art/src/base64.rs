//! Minimal base64 (RFC 4648, standard alphabet, padded) — the
//! lumen document format stores layer PNGs base64-encoded, and
//! this provider needs encode + decode without another
//! dependency. Bounded by the caller's input sizes; invalid
//! input is an error, never a panic.

/// Encode bytes to padded standard base64.
pub fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Decode padded standard base64. Whitespace is rejected (the
/// document format never wraps lines).
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Result<u32, String> {
        match byte {
            b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
            b'a'..=b'z' => Ok(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(byte - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte {byte:#04x}")),
        }
    }
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err("base64 length must be a non-zero multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.as_chunks::<4>().0 {
        let pad = chunk.iter().filter(|b| **b == b'=').count();
        if pad > 2 {
            return Err("base64 has excess padding".to_string());
        }
        let mut acc: u32 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            let digit = if *byte == b'=' {
                if index < 2 {
                    return Err("base64 padding in a data position".to_string());
                }
                0
            } else {
                value(*byte)?
            };
            acc = (acc << 6) | digit;
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_round_trip_all_lengths() {
        for len in 1..=9_usize {
            let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) % 256) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
        assert_eq!(encode(b"fathom"), "ZmF0aG9t");
        assert_eq!(encode(&[0xff, 0xee]), "/+4=");
        assert_eq!(encode(&[0xff]), "/w==");
    }

    #[test]
    fn adversarial_decode_rejects_garbage() {
        assert!(decode("").is_err());
        assert!(decode("abc").is_err());
        assert!(decode("ab$=").is_err());
        assert!(decode("====").is_err());
        assert!(decode("ab===").is_err());
    }
}
