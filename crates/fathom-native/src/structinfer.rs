//! Unknown-format structure inference (`infer_struct`): the
//! layout of a binary format from several sample files of
//! the same kind.
//!
//! One file says little: every byte could be a constant or a
//! value. Several files of one format say a lot: bytes that
//! are the same everywhere are the format, bytes that differ
//! are the data, and a number that follows the file size, a
//! record count, a checksum of the rest, or the length of
//! the text behind it gives its own meaning away. The result
//! is a hypothesis with the evidence per field, plus a
//! Kaitai Struct (.ksy) draft to refine.
//!
//! Method adapted from ReversePort's `re_struct`
//! (`port/src/struct.mjs` in laaielichter/ReversePort, MIT —
//! see the repository NOTICE), following its published
//! behavioral spec (`docs/re-struct.md`) and test
//! expectations. The implementation is estate-authored Rust.
//! Read-only: it decrypts and decompresses nothing.
//!
//! CRC-32 (IEEE) and Adler-32 are implemented here, small
//! and bounded; MD5 is implemented here too (RFC 1321)
//! because the workspace carries no MD5 crate. SHA-1 and
//! SHA-256 come from the workspace `sha1`/`sha2` crates.
//! Every digest is pinned by a known-answer test below.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Coverage, Evidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::registry::Registry;
use serde_json::{Map, Value, json};
use sha1::Digest as _;

type Result<T> = std::result::Result<T, FathomError>;

/// Samples compared in one call; more are reported skipped.
const SAMPLES_MAX: usize = 32;
/// Fields inferred before the walk stops.
const FIELDS_MAX: usize = 200;
/// Default per-sample read bound, in KiB.
const SAMPLE_KB_DEFAULT: u64 = 1024;
/// Largest per-sample read bound, in KiB.
const SAMPLE_KB_MAX: u64 = 64 * 1024;
/// Records read per layout when typing a table's columns.
const RECORD_ROWS_MAX: usize = 4096;

/// The hint every result carries, in the reference's
/// substance: what would make the hypothesis stronger.
const HINT: &str = "A hypothesis from these samples only. A field marked constant may be a value \
    no sample changes: add samples that differ in one known thing (one more item, another name) \
    and run again. offset is a list when the samples are no longer aligned (after a text of \
    different lengths). ksy is a Kaitai Struct draft; record the layout as evidence before \
    acting on it.";

/// One sample file, read up to the caller's bound.
struct Sample {
    /// The canonical path, as displayed in the result.
    file: String,
    /// The file's full size, read or not.
    size: u64,
    /// The bytes read (a prefix of the file when bounded).
    buf: Vec<u8>,
}

/// An integer shape the inference tries, in the reference's
/// order: u4le, u4be, u8le, u2le, u2be (u1 where noted).
#[derive(Clone, Copy)]
struct IntSpec {
    name: &'static str,
    width: usize,
    big_endian: bool,
}

const INT_SPECS: &[IntSpec] = &[
    IntSpec {
        name: "u4le",
        width: 4,
        big_endian: false,
    },
    IntSpec {
        name: "u4be",
        width: 4,
        big_endian: true,
    },
    IntSpec {
        name: "u8le",
        width: 8,
        big_endian: false,
    },
    IntSpec {
        name: "u2le",
        width: 2,
        big_endian: false,
    },
    IntSpec {
        name: "u2be",
        width: 2,
        big_endian: true,
    },
];

const U1_SPEC: IntSpec = IntSpec {
    name: "u1",
    width: 1,
    big_endian: false,
};

fn read_int(buf: &[u8], offset: usize, spec: IntSpec) -> u64 {
    let mut value: u64 = 0;
    if spec.big_endian {
        for index in 0..spec.width {
            value = (value << 8) | u64::from(buf[offset + index]);
        }
    } else {
        for index in (0..spec.width).rev() {
            value = (value << 8) | u64::from(buf[offset + index]);
        }
    }
    value
}

fn spec_by_name(name: &str) -> Option<IntSpec> {
    INT_SPECS.iter().copied().find(|spec| spec.name == name)
}

/// Space-separated lowercase hex, the reference's field
/// rendering.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The reference's printable test: ASCII graphic or tab /
/// LF / CR, and never empty.
fn is_printable(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|byte| (0x20..0x7f).contains(byte) || matches!(byte, 9 | 10 | 13))
}

/// Bytes as a Latin-1 string (one char per byte), the
/// reference's text rendering.
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| *byte as char).collect()
}

fn all_same<T: PartialEq>(values: &[T]) -> bool {
    values.iter().all(|value| *value == values[0])
}

/// Whether every sample has the same byte `delta` past its
/// cursor.
fn same_at(samples: &[Sample], cur: &[usize], delta: usize) -> bool {
    let first = samples[0].buf[cur[0] + delta];
    samples
        .iter()
        .enumerate()
        .all(|(index, sample)| sample.buf[cur[index] + delta] == first)
}

/// Bytes left in the shortest sample, from the cursors.
fn left(samples: &[Sample], cur: &[usize]) -> usize {
    samples
        .iter()
        .enumerate()
        .map(|(index, sample)| sample.buf.len() - cur[index])
        .min()
        .unwrap_or(0)
}

/// IEEE CRC-32 (the zlib polynomial), table-driven.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut table = [0_u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut word = index as u32;
        for _ in 0..8 {
            word = if word & 1 != 0 {
                0xEDB8_8320 ^ (word >> 1)
            } else {
                word >> 1
            };
        }
        *entry = word;
    }
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in bytes {
        crc = table[((crc ^ u32::from(*byte)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Adler-32 (RFC 1950).
pub fn adler32(bytes: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// MD5 (RFC 1321), implemented here because the workspace
/// carries no MD5 crate; pinned by known-answer tests.
pub fn md5_digest(input: &[u8]) -> [u8; 16] {
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const TABLE: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;
    let mut message = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    for chunk in message.as_chunks::<64>().0 {
        let mut words = [0_u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[4 * index],
                chunk[4 * index + 1],
                chunk[4 * index + 2],
                chunk[4 * index + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for index in 0..64 {
            let (f, g) = match index / 16 {
                0 => ((b & c) | (!b & d), index),
                1 => ((d & b) | (!d & c), (5 * index + 1) % 16),
                2 => (b ^ c ^ d, (3 * index + 5) % 16),
                _ => (c ^ (b | !d), (7 * index) % 16),
            };
            let sum = f
                .wrapping_add(a)
                .wrapping_add(TABLE[index])
                .wrapping_add(words[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(SHIFTS[index]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0_u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// A 32-bit checksum over a byte span.
type ChecksumFn = fn(&[u8]) -> u32;

/// A varying number explained by the file itself: its size,
/// a record count, a checksum, a time, or a place in it.
struct Relation {
    values: Vec<u64>,
    role: &'static str,
    note: String,
    stride: Option<u64>,
    extra: Option<u64>,
}

fn relation(
    samples: &[Sample],
    cur: &[usize],
    spec: IntSpec,
    now_seconds: u64,
) -> Option<Relation> {
    let width = spec.width;
    if samples
        .iter()
        .enumerate()
        .any(|(index, sample)| cur[index] + width > sample.buf.len())
    {
        return None;
    }
    let values: Vec<u64> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| read_int(&sample.buf, cur[index], spec))
        .collect();
    if all_same(&values) {
        return None;
    }
    let whole = samples
        .iter()
        .all(|sample| sample.buf.len() as u64 == sample.size);

    // value = size - k: the length of the file, or of what
    // follows a header of k bytes.
    let k = samples[0].size as i128 - values[0] as i128;
    if k >= 0
        && samples
            .iter()
            .enumerate()
            .all(|(index, sample)| sample.size as i128 - values[index] as i128 == k)
    {
        let ends_here = samples
            .iter()
            .enumerate()
            .all(|(index, _)| (cur[index] + width) as i128 == k);
        let note = if k == 0 {
            "the size of the file".to_string()
        } else if ends_here {
            format!(
                "the size of the file minus {k} (what follows a {k}-byte header, which ends right after this field)"
            )
        } else {
            format!("the size of the file minus {k} (what follows a {k}-byte header)")
        };
        return Some(Relation {
            values,
            role: "length",
            note,
            stride: None,
            extra: None,
        });
    }
    // The same against the bytes that follow the field:
    // holds after a text of different lengths too.
    let rest: Vec<i128> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| sample.size as i128 - cur[index] as i128 - width as i128)
        .collect();
    let kr = rest[0] - values[0] as i128;
    if kr >= 0
        && rest
            .iter()
            .enumerate()
            .all(|(index, size)| *size - values[index] as i128 == kr)
    {
        let note = if kr == 0 {
            "the number of bytes after this field, to the end of the file".to_string()
        } else {
            format!("the number of bytes after this field minus {kr}")
        };
        return Some(Relation {
            values,
            role: "length",
            note,
            stride: None,
            extra: None,
        });
    }
    // value * stride + c = what follows: a number of
    // fixed-size records.
    if samples.len() >= 3 {
        let j = values
            .iter()
            .position(|value| *value != values[0])
            .expect("values differ");
        let dv = values[j] as i128 - values[0] as i128;
        let dr = rest[j] - rest[0];
        if dv != 0 && dr % dv == 0 {
            let stride = dr / dv;
            if stride > 1 && stride <= 65536 {
                let c = rest[0] - values[0] as i128 * stride;
                if c >= 0
                    && rest
                        .iter()
                        .enumerate()
                        .all(|(index, size)| values[index] as i128 * stride + c == *size)
                {
                    return Some(Relation {
                        values,
                        role: "count",
                        note: format!(
                            "a count of records of {stride} bytes (count x {stride}{} = the bytes after this field, in every sample)",
                            if c > 0 {
                                format!(" + {c}")
                            } else {
                                String::new()
                            }
                        ),
                        stride: Some(stride as u64),
                        extra: Some(c as u64),
                    });
                }
            }
        }
    }
    // A checksum of the rest, of what came before, or of the
    // whole file with this field zeroed.
    if width == 4 && whole {
        let sums: [(&str, ChecksumFn); 2] = [("CRC-32", crc32_ieee), ("Adler-32", adler32)];
        for (name, sum) in sums {
            for (span_index, what) in [
                "the bytes after this field",
                "the bytes before this field",
                "the whole file with this field set to zero",
            ]
            .iter()
            .enumerate()
            {
                let matched = samples.iter().enumerate().all(|(index, sample)| {
                    let span: Vec<u8> = match span_index {
                        0 => sample.buf[cur[index] + 4..].to_vec(),
                        1 => sample.buf[..cur[index]].to_vec(),
                        _ => {
                            let mut zeroed = sample.buf.clone();
                            zeroed[cur[index]..cur[index] + 4].fill(0);
                            zeroed
                        }
                    };
                    !span.is_empty() && u64::from(sum(&span)) == values[index]
                });
                if matched {
                    return Some(Relation {
                        values,
                        role: "checksum",
                        note: format!("{name} of {what}"),
                        stride: None,
                        extra: None,
                    });
                }
            }
        }
    }
    // A date between 2000 and tomorrow, in seconds or
    // milliseconds. A fifth of all 32-bit values is such a
    // date, so random bytes pass by chance; the samples must
    // also lie close together: within one year for two
    // samples, three years for three or four, ten for more.
    let near: i128 = if samples.len() >= 5 {
        10
    } else if samples.len() >= 3 {
        3
    } else {
        1
    };
    let dates = |unit: i128, lo: i128, hi: i128| -> bool {
        values.iter().all(|value| {
            let value = *value as i128;
            value >= lo && value < hi
        }) && (*values.iter().max().expect("samples exist")
            - *values.iter().min().expect("samples exist")) as i128
            <= near * 366 * 86400 * unit
    };
    let tomorrow = now_seconds as i128 + 86400;
    if width == 4 {
        let as_text = samples
            .iter()
            .enumerate()
            .all(|(index, sample)| is_printable(&sample.buf[cur[index]..cur[index] + width]));
        if !as_text && dates(1, 946_684_800, tomorrow) {
            return Some(Relation {
                values,
                role: "time",
                note: "Unix time in seconds (every sample is a date after 2000, and the dates lie close together)"
                    .to_string(),
                stride: None,
                extra: None,
            });
        }
    }
    if width == 8 && dates(1000, 946_684_800_000, tomorrow * 1000) {
        return Some(Relation {
            values,
            role: "time",
            note: "Unix time in milliseconds (every sample is a date after 2000, and the dates lie close together)"
                .to_string(),
            stride: None,
            extra: None,
        });
    }
    // A place in the file where every sample has the same
    // bytes.
    if width >= 4
        && values.iter().enumerate().all(|(index, value)| {
            *value > (cur[index] + width) as u64 && *value + 4 <= samples[index].buf.len() as u64
        })
    {
        let first = &samples[0].buf[values[0] as usize..values[0] as usize + 4];
        let all_land_same = samples.iter().enumerate().all(|(index, sample)| {
            &sample.buf[values[index] as usize..values[index] as usize + 4] == first
        });
        if all_land_same
            && first.iter().any(|byte| *byte != 0)
            && first.iter().any(|byte| *byte != 0xff)
        {
            let note = if is_printable(first) {
                format!(
                    "an offset into the file: every sample has {} there",
                    serde_json::to_string(&latin1(first)).unwrap_or_default()
                )
            } else {
                format!(
                    "an offset into the file: every sample has {} there",
                    hex_bytes(first)
                )
            };
            return Some(Relation {
                values,
                role: "offset",
                note,
                stride: None,
                extra: None,
            });
        }
    }
    None
}

/// Text with its length in front (u1, u2, or u4), with a
/// different length in at least one sample.
struct PrefixedString {
    len_type: &'static str,
    width: usize,
    lens: Vec<u64>,
    values: Vec<String>,
}

fn prefixed_string(samples: &[Sample], cur: &[usize]) -> Option<PrefixedString> {
    let mut candidates: Vec<IntSpec> = INT_SPECS
        .iter()
        .copied()
        .filter(|spec| spec.width <= 4)
        .collect();
    candidates.push(U1_SPEC);
    for spec in candidates {
        let width = spec.width;
        if samples
            .iter()
            .enumerate()
            .any(|(index, sample)| cur[index] + width > sample.buf.len())
        {
            continue;
        }
        let lens: Vec<u64> = samples
            .iter()
            .enumerate()
            .map(|(index, sample)| read_int(&sample.buf, cur[index], spec))
            .collect();
        if all_same(&lens) || lens.iter().any(|len| *len < 1 || *len > 65535) {
            continue;
        }
        if samples
            .iter()
            .enumerate()
            .any(|(index, sample)| cur[index] + width + lens[index] as usize > sample.buf.len())
        {
            continue;
        }
        let bodies: Vec<&[u8]> = samples
            .iter()
            .enumerate()
            .map(|(index, sample)| {
                &sample.buf[cur[index] + width..cur[index] + width + lens[index] as usize]
            })
            .collect();
        // Trailing NULs are padding some writers count in
        // the length.
        let trimmed: Vec<&[u8]> = bodies
            .iter()
            .map(|body| {
                let mut end = body.len();
                while end > 0 && body[end - 1] == 0 {
                    end -= 1;
                }
                &body[..end]
            })
            .collect();
        if !trimmed.iter().all(|body| is_printable(body)) {
            continue;
        }
        let longest = trimmed.iter().map(|body| body.len()).max().unwrap_or(0);
        if longest < if width == 1 { 4 } else { 3 } {
            continue;
        }
        return Some(PrefixedString {
            len_type: spec.name,
            width,
            lens,
            values: trimmed.iter().map(|body| latin1(body)).collect(),
        });
    }
    None
}

/// NUL-terminated text of different lengths.
struct CString {
    /// Per-sample lengths including the NUL.
    lens: Vec<usize>,
    values: Vec<String>,
}

fn c_string(samples: &[Sample], cur: &[usize]) -> Option<CString> {
    let mut ends = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        let found = sample.buf[cur[index]..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|position| cur[index] + position);
        match found {
            Some(end) if end - cur[index] >= 2 && end - cur[index] <= 1024 => ends.push(end),
            _ => return None,
        }
    }
    let bodies: Vec<&[u8]> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| &sample.buf[cur[index]..ends[index]])
        .collect();
    if !bodies.iter().all(|body| is_printable(body)) {
        return None;
    }
    let lens: Vec<usize> = bodies.iter().map(|body| body.len()).collect();
    if all_same(&lens) || *lens.iter().max().expect("samples exist") < 4 {
        return None;
    }
    Some(CString {
        lens: lens.iter().map(|len| len + 1).collect(),
        values: bodies.iter().map(|body| latin1(body)).collect(),
    })
}

/// Shannon entropy in bits per byte, rounded to two
/// decimals as the reference reports it.
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let mut value = 0.0_f64;
    for count in counts {
        if count > 0 {
            let p = count as f64 / bytes.len() as f64;
            value -= p * p.log2();
        }
    }
    (value * 100.0).round() / 100.0
}

/// A digest or checksum at the very end of the file, over
/// everything before it.
struct Trailer {
    bytes: usize,
    note: String,
}

fn trailer(samples: &[Sample]) -> Option<Trailer> {
    if samples
        .iter()
        .any(|sample| sample.buf.len() as u64 != sample.size)
    {
        return None;
    }
    for (name, width) in [
        ("CRC-32 (little-endian)", 4_usize),
        ("CRC-32 (big-endian)", 4),
        ("Adler-32 (big-endian)", 4),
        ("MD5", 16),
        ("SHA-1", 20),
        ("SHA-256", 32),
    ] {
        let matched = samples.iter().all(|sample| {
            if sample.size <= width as u64 {
                return false;
            }
            let body = &sample.buf[..sample.buf.len() - width];
            let tail = &sample.buf[sample.buf.len() - width..];
            let digest: Vec<u8> = match name {
                "CRC-32 (little-endian)" => crc32_ieee(body).to_le_bytes().to_vec(),
                "CRC-32 (big-endian)" => crc32_ieee(body).to_be_bytes().to_vec(),
                "Adler-32 (big-endian)" => adler32(body).to_be_bytes().to_vec(),
                "MD5" => md5_digest(body).to_vec(),
                "SHA-1" => sha1::Sha1::digest(body).to_vec(),
                _ => sha2::Sha256::digest(body).to_vec(),
            };
            digest == tail
        });
        if matched {
            return Some(Trailer {
                bytes: width,
                note: format!("the last {width} bytes are the {name} of everything before them"),
            });
        }
    }
    None
}

/// One column of a record table.
struct Column {
    offset: u64,
    size: u64,
    col_type: String,
    hex: Option<String>,
    note: Option<String>,
    values: Vec<Value>,
}

impl Column {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("offset".to_string(), json!(self.offset));
        map.insert("size".to_string(), json!(self.size));
        map.insert("type".to_string(), json!(self.col_type));
        if let Some(hex) = &self.hex {
            map.insert("hex".to_string(), json!(hex));
        }
        if let Some(note) = &self.note {
            map.insert("note".to_string(), json!(note));
        }
        if !self.values.is_empty() {
            map.insert("values".to_string(), Value::Array(self.values.clone()));
        }
        Value::Object(map)
    }
}

/// A table of fixed-size records and its columns.
struct Records {
    size: u64,
    read: usize,
    columns: Vec<Column>,
}

impl Records {
    fn to_json(&self) -> Value {
        json!({
            "size": self.size,
            "read": self.read,
            "columns": self.columns.iter().map(Column::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The columns of a table of fixed-size records, from every
/// record of every sample.
fn record_layout(samples: &[Sample], cur: &[usize], counts: &[u64], stride: u64) -> Records {
    let stride = stride as usize;
    let mut rows: Vec<&[u8]> = Vec::new();
    let mut first: HashSet<usize> = HashSet::new();
    for (index, sample) in samples.iter().enumerate() {
        first.insert(rows.len());
        for record in 0..counts[index] {
            if rows.len() >= RECORD_ROWS_MAX {
                break;
            }
            let start = cur[index] + record as usize * stride;
            rows.push(&sample.buf[start..start + stride]);
        }
    }
    let mut columns = Vec::new();
    let mut offset = 0_usize;
    while offset < stride {
        let width = if stride - offset >= 4 { 4 } else { 1 };
        let cells: Vec<&[u8]> = rows
            .iter()
            .map(|row| &row[offset..offset + width])
            .collect();
        if !cells.is_empty() && cells.iter().all(|cell| *cell == cells[0]) {
            let mut end = offset + width;
            while end < stride && rows.iter().all(|row| row[end] == rows[0][end]) {
                end += 1;
            }
            columns.push(Column {
                offset: offset as u64,
                size: (end - offset) as u64,
                col_type: "constant".to_string(),
                hex: Some(hex_bytes(&rows[0][offset..end.min(offset + 16)])),
                note: None,
                values: Vec::new(),
            });
            offset = end;
            continue;
        }
        if width == 4 {
            let ints: Vec<u32> = cells
                .iter()
                .map(|cell| u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]))
                .collect();
            let floats: Vec<f32> = cells
                .iter()
                .map(|cell| f32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]))
                .collect();
            let small = ints.iter().filter(|value| **value < (1 << 24)).count();
            let good_floats = floats
                .iter()
                .filter(|value| {
                    **value == 0.0 || (value.is_finite() && value.abs() > 1e-4 && value.abs() < 1e7)
                })
                .count();
            let rising = ints.len() > samples.len() + 1
                && ints
                    .iter()
                    .enumerate()
                    .all(|(index, value)| first.contains(&index) || *value > ints[index - 1]);
            let mostly_large = (small as f64) < rows.len() as f64 * 0.9;
            let (col_type, note) = if mostly_large && good_floats == rows.len() {
                ("f4le", "every record reads as a sensible float here")
            } else if mostly_large {
                (
                    "u4le",
                    "large values: flags, a hash, an id, or not a little-endian number",
                )
            } else if rising {
                (
                    "u4le",
                    "whole numbers that rise from record to record (an id or an index)",
                )
            } else {
                ("u4le", "whole numbers")
            };
            let values: Vec<Value> = if col_type == "f4le" {
                floats
                    .iter()
                    .take(4)
                    .map(|value| json!((f64::from(*value) * 1000.0).round() / 1000.0))
                    .collect()
            } else {
                ints.iter().take(4).map(|value| json!(*value)).collect()
            };
            columns.push(Column {
                offset: offset as u64,
                size: 4,
                col_type: col_type.to_string(),
                hex: None,
                note: Some(note.to_string()),
                values,
            });
        } else {
            columns.push(Column {
                offset: offset as u64,
                size: 1,
                col_type: "u1".to_string(),
                hex: None,
                note: None,
                values: cells.iter().take(4).map(|cell| json!(cell[0])).collect(),
            });
        }
        offset += width;
    }
    Records {
        size: stride as u64,
        read: rows.len(),
        columns,
    }
}

/// Where a field sits: one offset when the samples are
/// aligned, or one per sample once a text of different
/// lengths has desynchronised them.
#[derive(Clone, Debug)]
enum Offset {
    Single(u64),
    PerSample(Vec<u64>),
}

fn offset_of(cur: &[usize]) -> Offset {
    if all_same(cur) {
        Offset::Single(cur[0] as u64)
    } else {
        Offset::PerSample(cur.iter().map(|cursor| *cursor as u64).collect())
    }
}

/// One inferred field.
#[derive(Clone, Debug)]
struct Field {
    offset: Offset,
    /// `None` renders as `"varies"` (text fields).
    size: Option<u64>,
    field_type: String,
    role: String,
    values: Vec<Value>,
    note: Option<String>,
    hex: Option<String>,
    text: Option<String>,
    entropy: Option<f64>,
    stride: Option<u64>,
    extra: Option<u64>,
    /// The constant bytes themselves, when short enough for
    /// a Kaitai `contents` list.
    const_bytes: Option<Vec<u8>>,
}

impl Field {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "offset".to_string(),
            match &self.offset {
                Offset::Single(at) => json!(*at),
                Offset::PerSample(list) => json!(list),
            },
        );
        map.insert(
            "size".to_string(),
            match self.size {
                Some(size) => json!(size),
                None => json!("varies"),
            },
        );
        map.insert("type".to_string(), json!(self.field_type));
        map.insert("role".to_string(), json!(self.role));
        if let Some(text) = &self.text {
            map.insert("text".to_string(), json!(text));
        }
        if let Some(hex) = &self.hex {
            map.insert("hex".to_string(), json!(hex));
        }
        if !self.values.is_empty() {
            map.insert("values".to_string(), Value::Array(self.values.clone()));
        }
        if let Some(entropy) = self.entropy {
            map.insert("entropy".to_string(), json!(entropy));
        }
        if let Some(note) = &self.note {
            map.insert("note".to_string(), json!(note));
        }
        if let Some(stride) = self.stride {
            map.insert("stride".to_string(), json!(stride));
        }
        if let Some(extra) = self.extra {
            map.insert("extra".to_string(), json!(extra));
        }
        Value::Object(map)
    }
}

/// Where the walk stopped, and why.
struct Rest {
    offset: Offset,
    entropy: Option<f64>,
    note: String,
}

impl Rest {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "offset".to_string(),
            match &self.offset {
                Offset::Single(at) => json!(*at),
                Offset::PerSample(list) => json!(list),
            },
        );
        if let Some(entropy) = self.entropy {
            map.insert("entropy".to_string(), json!(entropy));
        }
        map.insert("note".to_string(), json!(self.note));
        Value::Object(map)
    }
}

/// The whole inference over one sample set.
struct Inference {
    fields: Vec<Field>,
    records: Option<Records>,
    rest: Option<Rest>,
    trailer: Option<Trailer>,
}

/// Walks all samples side by side; each sample has its own
/// cursor, so a text of a different length does not end the
/// comparison.
fn infer(samples: &[Sample], now_seconds: u64) -> Inference {
    let mut cur: Vec<usize> = vec![0; samples.len()];
    let mut fields: Vec<Field> = Vec::new();
    let mut records: Option<Records> = None;
    let mut rest: Option<Rest> = None;

    while fields.len() < FIELDS_MAX {
        let room = left(samples, &cur);
        if room == 0 {
            break;
        }

        // 1. Bytes that are the same in every sample: the
        // format itself.
        let mut run = 0;
        while run < room && same_at(samples, &cur, run) {
            run += 1;
        }
        if run > 0 {
            // A length in big-endian or a count starts with
            // constant zero bytes: give those back when a
            // field starts in them.
            let mut keep = run;
            if run < room {
                for back in (1..=run.min(3)).rev() {
                    let at: Vec<usize> = cur.iter().map(|cursor| cursor + run - back).collect();
                    if !samples
                        .iter()
                        .enumerate()
                        .all(|(index, sample)| sample.buf[at[index]] == 0)
                    {
                        continue;
                    }
                    let be_field = INT_SPECS.iter().any(|spec| {
                        spec.big_endian
                            && spec.width > back
                            && relation(samples, &at, *spec, now_seconds).is_some()
                    });
                    if prefixed_string(samples, &at).is_some() || be_field {
                        keep = run - back;
                        break;
                    }
                }
            }
            if keep > 0 {
                let bytes = &samples[0].buf[cur[0]..cur[0] + keep];
                let zero = bytes.iter().all(|byte| *byte == 0);
                let role = if fields.is_empty() {
                    "magic"
                } else if zero {
                    "padding"
                } else {
                    "constant"
                };
                let mut hex = hex_bytes(&bytes[..keep.min(16)]);
                if keep > 16 {
                    hex.push_str(" …");
                }
                fields.push(Field {
                    offset: offset_of(&cur),
                    size: Some(keep as u64),
                    field_type: "constant".to_string(),
                    role: role.to_string(),
                    values: Vec::new(),
                    note: Some(if zero {
                        "zero in every sample (padding, or a value no sample uses)".to_string()
                    } else {
                        "the same in every sample".to_string()
                    }),
                    hex: Some(hex),
                    text: if is_printable(bytes) {
                        Some(latin1(&bytes[..keep.min(64)]))
                    } else {
                        None
                    },
                    entropy: None,
                    stride: None,
                    extra: None,
                    const_bytes: if keep <= 16 {
                        Some(bytes.to_vec())
                    } else {
                        None
                    },
                });
                for cursor in &mut cur {
                    *cursor += keep;
                }
                continue;
            }
        }

        // 2. Text with its length in front, or ended by a
        // NUL.
        if let Some(ps) = prefixed_string(samples, &cur) {
            fields.push(Field {
                offset: offset_of(&cur),
                size: if all_same(&ps.lens) {
                    Some(ps.width as u64 + ps.lens[0])
                } else {
                    None
                },
                field_type: format!("{} length + text", ps.len_type),
                role: "string".to_string(),
                values: ps.values.iter().take(4).map(|value| json!(value)).collect(),
                note: Some(format!(
                    "a {} length ({}) followed by that many bytes of text",
                    ps.len_type,
                    ps.lens
                        .iter()
                        .take(4)
                        .map(|len| len.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                hex: None,
                text: None,
                entropy: None,
                stride: None,
                extra: None,
                const_bytes: None,
            });
            for (index, cursor) in cur.iter_mut().enumerate() {
                *cursor += ps.width + ps.lens[index] as usize;
            }
            continue;
        }
        if let Some(cs) = c_string(samples, &cur) {
            fields.push(Field {
                offset: offset_of(&cur),
                size: None,
                field_type: "text + NUL".to_string(),
                role: "string".to_string(),
                values: cs.values.iter().take(4).map(|value| json!(value)).collect(),
                note: Some("text that ends with a zero byte".to_string()),
                hex: None,
                text: None,
                entropy: None,
                stride: None,
                extra: None,
                const_bytes: None,
            });
            for (index, cursor) in cur.iter_mut().enumerate() {
                *cursor += cs.lens[index];
            }
            continue;
        }

        // 3. A number the file explains.
        let mut found: Option<(IntSpec, Relation)> = None;
        for spec in INT_SPECS {
            if let Some(relation) = relation(samples, &cur, *spec, now_seconds) {
                found = Some((*spec, relation));
                break;
            }
        }
        if let Some((spec, relation)) = found {
            let is_count = relation.role == "count";
            let count_values = relation.values.clone();
            let count_stride = relation.stride;
            let count_extra = relation.extra;
            fields.push(Field {
                offset: offset_of(&cur),
                size: Some(spec.width as u64),
                field_type: spec.name.to_string(),
                role: relation.role.to_string(),
                values: relation
                    .values
                    .iter()
                    .take(4)
                    .map(|value| json!(*value))
                    .collect(),
                note: Some(relation.note),
                hex: None,
                text: None,
                entropy: None,
                stride: relation.stride,
                extra: relation.extra,
                const_bytes: None,
            });
            for cursor in &mut cur {
                *cursor += spec.width;
            }
            if is_count
                && samples
                    .iter()
                    .all(|sample| sample.buf.len() as u64 == sample.size)
            {
                let stride = count_stride.expect("count relations carry a stride");
                records = Some(record_layout(samples, &cur, &count_values, stride));
                rest = Some(Rest {
                    offset: offset_of(&cur),
                    entropy: None,
                    note: format!(
                        "{stride}-byte records start here (as many as the count says){}; see records for the columns.",
                        match count_extra {
                            Some(extra) if extra > 0 => {
                                format!(", with {extra} more bytes after them")
                            }
                            _ => " and run to the end of the file".to_string(),
                        }
                    ),
                });
                break;
            }
            continue;
        }

        // 4. Bytes that differ and that nothing explains: a
        // value, or the payload.
        let mut vary = 0;
        while vary < room && !same_at(samples, &cur, vary) {
            vary += 1;
        }
        // Short constant gaps inside a block of data are
        // chance, not structure.
        let mut span = vary;
        while span < room {
            let mut gap = 0;
            while span + gap < room && same_at(samples, &cur, span + gap) {
                gap += 1;
            }
            if gap > 3 || span + gap >= room {
                break;
            }
            let mut more = 0;
            while span + gap + more < room && !same_at(samples, &cur, span + gap + more) {
                more += 1;
            }
            if vary < 9 && more < 9 {
                break;
            }
            span += gap + more;
        }
        if span >= 9 {
            let reaches_end = span >= room;
            let mut block: Vec<u8> = Vec::new();
            for (index, sample) in samples.iter().enumerate() {
                block.extend_from_slice(&sample.buf[cur[index]..cur[index] + span.min(4096)]);
            }
            let value = entropy(&block);
            // A short block cannot reach 8 bits per byte: n
            // random bytes give about log2(n) - 0.7 bits
            // (measured), text stays under 5 and base64 near
            // 6.
            let dense = value >= 7.0_f64.min((block.len() as f64).log2() - 1.1);
            if reaches_end {
                let kind = if dense {
                    "high entropy: compressed or encrypted data"
                } else if value < 5.0 {
                    "low entropy: text or sparse records"
                } else {
                    "mixed data: records or media"
                };
                rest = Some(Rest {
                    offset: offset_of(&cur),
                    entropy: Some(value),
                    note: format!(
                        "from here the samples differ to the end ({kind}). Fields inside it need samples that differ in one known thing."
                    ),
                });
                break;
            }
            fields.push(Field {
                offset: offset_of(&cur),
                size: Some(span as u64),
                field_type: "bytes".to_string(),
                role: if dense {
                    "data (compressed, encrypted or a hash)".to_string()
                } else {
                    "data".to_string()
                },
                values: Vec::new(),
                note: Some(format!("{span} bytes that differ between samples")),
                hex: None,
                text: None,
                entropy: Some(value),
                stride: None,
                extra: None,
                const_bytes: None,
            });
            for cursor in &mut cur {
                *cursor += span;
            }
            continue;
        }

        // 5. Small values in little-endian leave constant
        // zero bytes behind them: take those into the
        // number.
        let mut width = if vary <= 1 {
            1
        } else if vary <= 2 {
            2
        } else if vary <= 4 {
            4
        } else {
            8
        };
        if width < 4 {
            let zeros = |delta: usize| {
                delta < room
                    && samples
                        .iter()
                        .enumerate()
                        .all(|(index, sample)| sample.buf[cur[index] + delta] == 0)
            };
            if vary <= 2 && zeros(2) && zeros(3) && (vary == 2 || zeros(1)) {
                width = 4;
            } else if vary == 1 && zeros(1) {
                width = 2;
            }
        }
        width = width.min(room);
        let spec = spec_by_name(&format!("u{width}le"));
        let values: Vec<Value> = match spec {
            Some(spec) => samples
                .iter()
                .enumerate()
                .map(|(index, sample)| json!(read_int(&sample.buf, cur[index], spec)))
                .collect(),
            None if width == 1 => samples
                .iter()
                .enumerate()
                .map(|(index, sample)| json!(sample.buf[cur[index]]))
                .collect(),
            None => samples
                .iter()
                .enumerate()
                .map(|(index, sample)| {
                    json!(hex_bytes(&sample.buf[cur[index]..cur[index] + width]))
                })
                .collect(),
        };
        let small = spec.is_some_and(|spec| {
            samples
                .iter()
                .enumerate()
                .all(|(index, sample)| read_int(&sample.buf, cur[index], spec) < 65536)
        });
        let field_type = if width == 1 {
            "u1".to_string()
        } else if spec.is_some() {
            if small || width == 8 {
                format!("u{width}le")
            } else {
                format!("u{width}")
            }
        } else {
            "bytes".to_string()
        };
        fields.push(Field {
            offset: offset_of(&cur),
            size: Some(width as u64),
            field_type,
            role: "value".to_string(),
            values: values.iter().take(4).cloned().collect(),
            note: Some(if spec.is_some() && !small && width == 4 {
                "a value that differs per sample; the byte order is not clear from these samples (read here as little-endian)"
                    .to_string()
            } else {
                "a value that differs per sample".to_string()
            }),
            hex: None,
            text: None,
            entropy: None,
            stride: None,
            extra: None,
            const_bytes: None,
        });
        for cursor in &mut cur {
            *cursor += width;
        }
    }

    if rest.is_none() && fields.len() >= FIELDS_MAX {
        rest = Some(Rest {
            offset: offset_of(&cur),
            entropy: None,
            note: format!("stopped after {FIELDS_MAX} fields"),
        });
    }
    if rest.is_none()
        && left(samples, &cur) == 0
        && samples
            .iter()
            .enumerate()
            .any(|(index, sample)| cur[index] < sample.buf.len())
    {
        rest = Some(Rest {
            offset: offset_of(&cur),
            entropy: None,
            note: "the shortest sample ends here; the longer ones have more data that nothing can be compared with."
                .to_string(),
        });
    }
    Inference {
        fields,
        records,
        rest,
        trailer: trailer(samples),
    }
}

/// The Kaitai type for an inferred field type: only the
/// reference's two bare widths gain an endianness suffix.
fn ksy_type(field_type: &str) -> &str {
    match field_type {
        "u2" => "u2le",
        "u4" => "u4le",
        other => other,
    }
}

/// Kaitai field names, deduplicated as the reference's:
/// the first use keeps the base name, later uses gain a
/// numeric suffix.
struct NameGen {
    counts: HashMap<String, usize>,
}

impl NameGen {
    fn name(&mut self, base: &str) -> String {
        let count = self.counts.entry(base.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            base.to_string()
        } else {
            format!("{base}_{count}")
        }
    }

    fn count(&self, base: &str) -> usize {
        self.counts.get(base).copied().unwrap_or(0)
    }
}

/// A Kaitai Struct draft of the fields: a starting point to
/// edit, in the format most tools for binary formats read.
fn to_ksy(id: &str, inference: &Inference) -> String {
    let mut out: Vec<String> = vec![
        "meta:".to_string(),
        format!("  id: {id}"),
        "  endian: le".to_string(),
        "doc: |".to_string(),
        "  Draft written by fathom's infer_struct (method adapted from ReversePort's re_struct) from sample files. Every field is a hypothesis:".to_string(),
        "  the doc of a field says what the samples showed. Rename the fields as you learn what they are.".to_string(),
        "seq:".to_string(),
    ];
    let mut names = NameGen {
        counts: HashMap::new(),
    };
    for field in &inference.fields {
        let doc = format!(
            "    doc: {}",
            serde_json::to_string(field.note.as_deref().unwrap_or("")).unwrap_or_default()
        );
        if field.field_type == "constant" {
            let base = match field.role.as_str() {
                "magic" => "magic",
                "padding" => "reserved",
                _ => "const",
            };
            out.push(format!("  - id: {}", names.name(base)));
            match (&field.const_bytes, field.role.as_str()) {
                (Some(bytes), role) if role != "padding" => {
                    let list: Vec<String> =
                        bytes.iter().map(|byte| format!("0x{byte:02x}")).collect();
                    out.push(format!("    contents: [{}]", list.join(", ")));
                }
                _ => out.push(format!("    size: {}", field.size.unwrap_or(0))),
            }
            out.push(doc);
        } else if field.role == "string" && field.field_type.ends_with("length + text") {
            let len_name = names.name("len_text");
            let len_type = field.field_type.split(' ').next().unwrap_or("u4le");
            out.push(format!("  - id: {len_name}"));
            out.push(format!("    type: {len_type}"));
            out.push(format!("  - id: {}", names.name("text")));
            out.push("    type: str".to_string());
            out.push(format!("    size: {len_name}"));
            out.push("    encoding: UTF-8".to_string());
            out.push(doc);
        } else if field.role == "string" {
            out.push(format!("  - id: {}", names.name("text")));
            out.push("    type: strz".to_string());
            out.push("    encoding: UTF-8".to_string());
            out.push(doc);
        } else if field.field_type == "bytes" {
            out.push(format!("  - id: {}", names.name("data")));
            out.push(format!("    size: {}", field.size.unwrap_or(0)));
            out.push(doc);
        } else {
            let base = match field.role.as_str() {
                "length" => "len_body",
                "count" => "num_records",
                "checksum" => "checksum",
                "time" => "timestamp",
                "offset" => "ofs_section",
                _ => "value",
            };
            out.push(format!("  - id: {}", names.name(base)));
            out.push(format!("    type: {}", ksy_type(&field.field_type)));
            out.push(doc);
        }
    }
    if let Some(records) = &inference.records {
        out.push("  - id: records".to_string());
        out.push("    type: record".to_string());
        out.push("    repeat: expr".to_string());
        let repeat = match names.count("num_records") {
            0 => "0".to_string(),
            1 => "num_records".to_string(),
            count => format!("num_records_{count}"),
        };
        out.push(format!("    repeat-expr: {repeat}"));
        out.push("types:".to_string());
        out.push("  record:".to_string());
        out.push("    seq:".to_string());
        for (index, column) in records.columns.iter().enumerate() {
            let base = if column.col_type == "constant" {
                "const"
            } else {
                "col"
            };
            out.push(format!("      - id: {base}_{index}"));
            if column.col_type == "constant" {
                out.push(format!("        size: {}", column.size));
            } else {
                out.push(format!("        type: {}", column.col_type));
            }
            if let Some(note) = &column.note {
                out.push(format!(
                    "        doc: {}",
                    serde_json::to_string(note).unwrap_or_default()
                ));
            }
        }
    } else if let Some(rest) = &inference.rest {
        out.push(format!("  - id: {}", names.name("body")));
        out.push("    size-eos: true".to_string());
        out.push(format!(
            "    doc: {}",
            serde_json::to_string(&rest.note).unwrap_or_default()
        ));
    }
    out.push(String::new());
    out.join("\n")
}

/// The Kaitai id for a sample set, from the first sample's
/// extension (or file name): lowercased, non-`[a-z0-9_]`
/// runs collapsed to one underscore, a leading digit
/// prefixed, `format` when nothing remains.
fn sample_id(file: &str) -> String {
    let path = Path::new(file);
    let raw = match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => ext.to_string(),
        _ => path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_string(),
    };
    let mut id = String::new();
    let mut replaced = false;
    for c in raw.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            id.push(c);
            replaced = false;
        } else if !replaced {
            id.push('_');
            replaced = true;
        }
    }
    if id.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        id.insert(0, '_');
    }
    if id.is_empty() {
        "format".to_string()
    } else {
        id
    }
}

/// Infer the layout of an unknown binary format from 2–32
/// sample files. Every sample path must resolve under a
/// configured target root; inference is read-only and the
/// result is a hypothesis, carried as an inferred finding.
pub fn infer_struct(_registry: &Registry, config: &Config, args: &Value) -> Result<Value> {
    let files_arg = args.get("files").and_then(Value::as_array).ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'files' is required and must be an array of sample file paths",
        )
    })?;
    let mut raw_paths: Vec<&str> = Vec::new();
    for entry in files_arg {
        let Some(path) = entry.as_str() else {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'files' must contain only file path strings",
            ));
        };
        raw_paths.push(path);
    }
    if raw_paths.len() < 2 {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "infer_struct compares samples: give at least 2 files of the same format. Three or more that differ in size find counts and lengths.",
        ));
    }
    let skipped = raw_paths.len().saturating_sub(SAMPLES_MAX);
    raw_paths.truncate(SAMPLES_MAX);
    let max_kb = args
        .get("max_kb")
        .and_then(Value::as_u64)
        .unwrap_or(SAMPLE_KB_DEFAULT)
        .clamp(1, SAMPLE_KB_MAX);
    let limit = max_kb * 1024;

    let mut samples: Vec<Sample> = Vec::new();
    let mut first_path: Option<PathBuf> = None;
    for raw in &raw_paths {
        let path = paths::validate_target(config, Path::new(raw))?;
        let metadata = std::fs::metadata(&path).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot stat sample {}: {error}", path.display()),
            )
        })?;
        if !metadata.is_file() {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("sample {} is not a file", path.display()),
            ));
        }
        let size = metadata.len();
        if size == 0 {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("{raw} is empty."),
            ));
        }
        let mut buf = Vec::new();
        std::fs::File::open(&path)
            .map_err(|error| {
                FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("cannot open sample {}: {error}", path.display()),
                )
            })?
            .take(limit)
            .read_to_end(&mut buf)
            .map_err(|error| {
                FathomError::new(
                    ErrorCode::UnreadableOutput,
                    format!("cannot read sample {}: {error}", path.display()),
                )
            })?;
        if first_path.is_none() {
            first_path = Some(path.clone());
        }
        samples.push(Sample {
            file: path.display().to_string(),
            size,
            buf,
        });
    }

    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let inference = infer(&samples, now_seconds);
    let partial = samples
        .iter()
        .any(|sample| sample.buf.len() as u64 != sample.size);
    let named = inference
        .fields
        .iter()
        .filter(|field| {
            ["length", "count", "checksum", "time", "offset", "string"]
                .contains(&field.role.as_str())
        })
        .count();
    let summary = format!(
        "{} fields before the data starts; {} with a meaning the samples prove (length, count, checksum, time, offset or text).",
        inference.fields.len(),
        named
    );
    let ksy = to_ksy(&sample_id(&samples[0].file), &inference);

    let mut facts = Map::new();
    facts.insert(
        "samples".to_string(),
        Value::Array(
            samples
                .iter()
                .map(|sample| json!({ "file": sample.file, "size": sample.size }))
                .collect(),
        ),
    );
    if skipped > 0 {
        facts.insert("skipped_samples".to_string(), json!(skipped));
    }
    facts.insert("summary".to_string(), json!(summary));
    facts.insert(
        "fields".to_string(),
        Value::Array(inference.fields.iter().map(Field::to_json).collect()),
    );
    if let Some(records) = &inference.records {
        facts.insert("records".to_string(), records.to_json());
    }
    if let Some(rest) = &inference.rest {
        facts.insert("rest".to_string(), rest.to_json());
    }
    if let Some(trailer) = &inference.trailer {
        facts.insert(
            "trailer".to_string(),
            json!({ "bytes": trailer.bytes, "note": trailer.note }),
        );
    }
    if partial {
        facts.insert(
            "partial".to_string(),
            json!(format!(
                "only the first {max_kb} KiB of each sample was read (max_kb); checksums over the whole file were not tried."
            )),
        );
    }
    facts.insert("ksy".to_string(), json!(ksy));
    facts.insert("hint".to_string(), json!(HINT));

    let mut evidence = Evidence::new("infer_struct", "struct_inference");
    if let Some(path) = &first_path {
        match subject_for_file(path) {
            Ok(subject) => evidence.subject = Some(subject),
            Err(error) => evidence.add_unknown(
                "subject identity",
                format!(
                    "the first sample's subject hash was not established ({})",
                    error.message
                ),
            ),
        }
    }
    evidence.add_finding(
        Finding::new(
            "struct_inference",
            Confidence::Inferred,
            Value::Object(facts),
        )
        .with_limitation(
            "inferred layout: a hypothesis from these samples only; a field marked constant may be a value no sample changes",
        ),
    );
    if partial {
        evidence.add_unknown(
            "whole-file checksums",
            format!(
                "only the first {max_kb} KiB of each sample was read (max_kb); checksums and trailers over the whole file were not tried"
            ),
        );
    }
    evidence.coverage = Coverage {
        examined: samples.len() as u64,
        total: samples.len() as u64,
        exhaustive: !partial,
    };
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    /// Lowercase hex with no separators, for digest
    /// comparisons in the known-answer tests.
    fn hex_compact(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-native-struct-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sample(file: &str, buf: Vec<u8>) -> Sample {
        let size = buf.len() as u64;
        Sample {
            file: file.to_string(),
            size,
            buf,
        }
    }

    /// Bytes that look random and are the same in every
    /// run: SHA-256 of `seed:i`, concatenated.
    fn noise(seed: &str, count: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0;
        while out.len() < count {
            out.extend_from_slice(&sha2::Sha256::digest(format!("{seed}:{index}").as_bytes()));
            index += 1;
        }
        out.truncate(count);
        out
    }

    /// "SAVE", version, reserved | body size | CRC-32 of
    /// the body | time, name, count, 12-byte records. The
    /// reference suite's fixture, rebuilt byte for byte.
    fn save_fixture(player: &str, count: u32, time: u32) -> Vec<u8> {
        let mut records = Vec::new();
        for index in 0..count {
            records.extend_from_slice(&(index + 1).to_le_bytes());
            let float = (f64::from(index) * 1.5 + f64::from(time % 7) + 0.25) as f32;
            records.extend_from_slice(&float.to_le_bytes());
            records
                .extend_from_slice(&(index.wrapping_mul(2654435761) | 0x8000_0000).to_le_bytes());
        }
        let name = player.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&time.to_le_bytes());
        body.extend_from_slice(&(name.len() as u32).to_le_bytes());
        body.extend_from_slice(name);
        body.extend_from_slice(&count.to_le_bytes());
        body.extend_from_slice(&records);
        let mut out = Vec::new();
        out.extend_from_slice(b"SAVE");
        out.extend_from_slice(&3_u32.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&((body.len() as u32 + 4).to_le_bytes()));
        out.extend_from_slice(&crc32_ieee(&body).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn save_samples() -> Vec<Sample> {
        vec![
            sample("a.sav", save_fixture("Roel", 3, 1700000000)),
            sample("b.sav", save_fixture("Alexandra", 10, 1710000123)),
            sample("c.sav", save_fixture("Bo", 1, 1722222222)),
            sample("d.sav", save_fixture("Player One", 25, 1733333333)),
        ]
    }

    #[test]
    fn validation_digest_known_answers() {
        // CRC-32 check value (zlib), Adler-32 example (RFC
        // 1950), MD5 vectors (RFC 1321), SHA-1/SHA-256
        // ("abc", FIPS 180 examples).
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(
            hex_compact(&md5_digest(b"")),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
        assert_eq!(
            hex_compact(&md5_digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex_compact(&md5_digest(b"The quick brown fox jumps over the lazy dog")),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(
            hex_compact(&sha1::Sha1::digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex_compact(&sha2::Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn validation_save_fixture_layout() {
        let samples = save_samples();
        let result = infer(&samples, now_seconds());
        assert_eq!(result.fields.len(), 6);
        let fields: Vec<Value> = result.fields.iter().map(Field::to_json).collect();
        let (magic, length, checksum, time, name, count) = (
            &fields[0], &fields[1], &fields[2], &fields[3], &fields[4], &fields[5],
        );
        assert_eq!(magic["offset"], json!(0));
        assert_eq!(magic["size"], json!(12));
        assert_eq!(magic["role"], json!("magic"));
        assert!(
            magic["hex"].as_str().unwrap().starts_with("53 41 56 45 03"),
            "hex was: {magic}"
        );
        assert_eq!(length["offset"], json!(12));
        assert_eq!(length["type"], json!("u4le"));
        assert_eq!(length["role"], json!("length"));
        assert!(
            length["note"]
                .as_str()
                .unwrap()
                .contains("size of the file minus 16"),
            "note was: {length}"
        );
        assert_eq!(checksum["offset"], json!(16));
        assert_eq!(checksum["role"], json!("checksum"));
        assert!(
            checksum["note"]
                .as_str()
                .unwrap()
                .contains("CRC-32 of the bytes after this field"),
            "note was: {checksum}"
        );
        assert_eq!(time["offset"], json!(20));
        assert_eq!(time["role"], json!("time"));
        assert_eq!(name["role"], json!("string"));
        assert_eq!(
            name["values"],
            json!(["Roel", "Alexandra", "Bo", "Player One"])
        );
        // After a text of different lengths every sample has
        // its own offset.
        assert_eq!(count["offset"], json!([32, 37, 30, 38]));
        assert_eq!(count["role"], json!("count"));
        assert_eq!(count["stride"], json!(12));
        assert_eq!(count["values"], json!([3, 10, 1, 25]));
        let records = result.records.as_ref().expect("records were laid out");
        assert_eq!(records.size, 12);
        let col_types: Vec<&str> = records
            .columns
            .iter()
            .map(|column| column.col_type.as_str())
            .collect();
        assert_eq!(col_types, ["u4le", "f4le", "u4le"]);
        assert!(
            records.columns[0].note.as_ref().unwrap().contains("rise"),
            "column note was: {:?}",
            records.columns[0].note
        );
        let ksy = to_ksy("sav", &result);
        assert!(ksy.contains("id: sav\n"), "ksy was:\n{ksy}");
        assert!(ksy.contains("contents: [0x53, 0x41, 0x56, 0x45"));
        assert!(ksy.contains("repeat-expr: num_records"));
        assert!(ksy.contains("type: f4le"));
    }

    #[test]
    fn validation_lvl_fixture_layout() {
        // Big-endian length in front of text, a NUL-ended
        // text, and a SHA-256 trailer: the reference
        // suite's second fixture.
        let make = |title: &str, author: &str, payload: &[u8]| -> Vec<u8> {
            let mut head = vec![0x89, 0x4c, 0x56, 0x4c];
            head.extend_from_slice(&(title.len() as u32).to_be_bytes());
            head.extend_from_slice(title.as_bytes());
            head.extend_from_slice(author.as_bytes());
            head.push(0);
            head.extend_from_slice(&[1, 2, 3, 4]);
            head.extend_from_slice(payload);
            let mut out = head.clone();
            out.extend_from_slice(&sha2::Sha256::digest(&head));
            out
        };
        let samples = vec![
            sample("one.lvl", make("Harbour", "ann", &noise("one", 40))),
            sample(
                "two.lvl",
                make("The long road north", "bartholomew", &noise("two", 90)),
            ),
            sample("three.lvl", make("Pit", "cy", &noise("three", 64))),
        ];
        let result = infer(&samples, now_seconds());
        let fields: Vec<Value> = result.fields.iter().map(Field::to_json).collect();
        assert_eq!(fields[0]["role"], json!("magic"));
        assert_eq!(
            fields[0]["size"],
            json!(4),
            "the zero bytes of the big-endian length are not taken as part of the magic"
        );
        assert_eq!(fields[1]["type"], json!("u4be length + text"));
        assert_eq!(
            fields[1]["values"],
            json!(["Harbour", "The long road north", "Pit"])
        );
        assert_eq!(fields[2]["type"], json!("text + NUL"));
        assert_eq!(fields[2]["values"], json!(["ann", "bartholomew", "cy"]));
        assert_eq!(fields[3]["type"], json!("constant"));
        assert_eq!(fields[3]["hex"], json!("01 02 03 04"));
        let rest = result.rest.as_ref().expect("the walk stops at the payload");
        assert!(
            rest.note.contains("high entropy"),
            "rest note was: {}",
            rest.note
        );
        let trailer = result.trailer.as_ref().expect("a SHA-256 trailer");
        assert!(
            trailer.note.contains("last 32 bytes are the SHA-256"),
            "trailer note was: {}",
            trailer.note
        );
        let ksy = to_ksy("lvl", &result);
        assert!(ksy.contains("type: strz"), "ksy was:\n{ksy}");
    }

    #[test]
    fn validation_md5_trailer_is_found() {
        let make = |body: &[u8]| -> Vec<u8> {
            let mut out = body.to_vec();
            out.extend_from_slice(&md5_digest(body));
            out
        };
        let samples = vec![
            sample("a.bin", make(&[1, 2, 3, 4, 5])),
            sample("b.bin", make(&[9, 8, 7, 6, 5, 4, 3])),
        ];
        let result = infer(&samples, now_seconds());
        let trailer = result.trailer.as_ref().expect("an MD5 trailer");
        assert_eq!(trailer.bytes, 16);
        assert!(trailer.note.contains("MD5"), "note was: {}", trailer.note);
    }

    #[test]
    fn validation_identical_samples_are_one_constant() {
        let samples = vec![
            sample("a.bin", b"HEADER-1234".to_vec()),
            sample("b.bin", b"HEADER-1234".to_vec()),
        ];
        let result = infer(&samples, now_seconds());
        assert_eq!(result.fields.len(), 1);
        assert_eq!(result.fields[0].text.as_deref(), Some("HEADER-1234"));
    }

    #[test]
    fn validation_handler_wraps_the_inference_in_evidence() {
        let root = scratch("handler");
        let names = ["a.sav", "b.sav", "c.sav", "d.sav"];
        let fixtures = [
            save_fixture("Roel", 3, 1700000000),
            save_fixture("Alexandra", 10, 1710000123),
            save_fixture("Bo", 1, 1722222222),
            save_fixture("Player One", 25, 1733333333),
        ];
        let mut paths = Vec::new();
        for (name, bytes) in names.iter().zip(fixtures.iter()) {
            let path = root.join(name);
            std::fs::write(&path, bytes).unwrap();
            paths.push(path.display().to_string());
        }
        let config = config_with_root(&root);
        let registry = Registry::new();
        let args = json!({ "files": paths });
        let value = infer_struct(&registry, &config, &args).unwrap();
        assert_eq!(value["tool"], json!("infer_struct"));
        assert_eq!(value["findings"][0]["confidence"], json!("inferred"));
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["fields"].as_array().unwrap().len(), 6);
        assert!(
            facts["summary"]
                .as_str()
                .unwrap()
                .starts_with("6 fields before the data starts; 5 with a meaning"),
            "summary was: {facts}"
        );
        assert!(facts["ksy"].as_str().unwrap().contains("id: sav"));
        assert!(
            facts["hint"]
                .as_str()
                .unwrap()
                .contains("add samples that differ")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_fewer_than_two_samples_is_invalid_request() {
        let root = scratch("few");
        let file = root.join("a.bin");
        std::fs::write(&file, b"abcdef").unwrap();
        let config = config_with_root(&root);
        let registry = Registry::new();
        let err = infer_struct(
            &registry,
            &config,
            &json!({ "files": [file.display().to_string()] }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(err.message.contains("at least 2 files"), "error was: {err}");
        let err = infer_struct(&registry, &config, &json!({ "files": [] })).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_missing_sample_is_target_unavailable() {
        let root = scratch("missing");
        let present = root.join("a.bin");
        std::fs::write(&present, b"abcdef").unwrap();
        let config = config_with_root(&root);
        let registry = Registry::new();
        let missing = root.join("missing.bin");
        let err = infer_struct(
            &registry,
            &config,
            &json!({ "files": [present.display().to_string(), missing.display().to_string()] }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_sample_outside_roots_is_access_denied() {
        let root = scratch("roots");
        let outside = scratch("outside");
        let first = outside.join("a.bin");
        let second = outside.join("b.bin");
        std::fs::write(&first, b"abcdef").unwrap();
        std::fs::write(&second, b"abcdeg").unwrap();
        let config = config_with_root(&root);
        let registry = Registry::new();
        let err = infer_struct(
            &registry,
            &config,
            &json!({ "files": [first.display().to_string(), second.display().to_string()] }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    #[test]
    fn adversarial_empty_sample_is_invalid_request() {
        let root = scratch("empty");
        let present = root.join("a.bin");
        let empty = root.join("b.bin");
        std::fs::write(&present, b"abcdef").unwrap();
        std::fs::write(&empty, b"").unwrap();
        let config = config_with_root(&root);
        let registry = Registry::new();
        let err = infer_struct(
            &registry,
            &config,
            &json!({ "files": [present.display().to_string(), empty.display().to_string()] }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        assert!(err.message.contains("is empty"), "error was: {err}");
        std::fs::remove_dir_all(&root).ok();
    }
}
