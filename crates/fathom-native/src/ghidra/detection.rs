//! Detection family (fathom Ghidra G1): crypto constants, capability
//! indicators, anti-analysis techniques, and indicators of compromise.
//!
//! Every detector here separates what Ghidra observed (bytes at an
//! address, an imported name, an instruction, a string) from what is
//! inferred from it (an algorithm, a capability, a technique, an IOC
//! class). Observations are reported verbatim; attributions are
//! `inferred` and carry the rule that produced them. Presence of an
//! indicator is a capability hint, never a verdict of intent.

use serde_json::{Value, json};
use std::collections::BTreeSet;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Finding, Subject};
use fathom_core::limits::ADDRESS_QUERY_COUNT_MAX;
use fathom_core::registry::Registry;

use crate::engine::Export;
use crate::ghidra::base;
use crate::ghidra::query::{self, same_subject};
use crate::ghidra::search::pattern_result;
use crate::sections::ExternalLocation;

/// IOCs one call reports at most.
const IOC_COUNT_MAX: usize = 500;

/// IOCs taken from one string at most.
const IOC_PER_STRING_MAX: usize = 32;

/// One known constant: label, algorithm, and its byte pattern.
pub(crate) struct CryptoConstant {
    pub algorithm: &'static str,
    pub label: &'static str,
    pub note: &'static str,
    pub pattern: &'static str,
}

/// The constant table. Every pattern is re-derived from first
/// principles in this module's tests.
pub(crate) const CRYPTO_CONSTANTS: &[CryptoConstant] = &[
    CryptoConstant {
        algorithm: "AES",
        label: "aes_inverse_sbox",
        note: "first 16 bytes of the inverse S-box",
        pattern: "52096ad53036a538bf40a39e81f3d7fb",
    },
    CryptoConstant {
        algorithm: "AES",
        label: "aes_sbox",
        note: "first 16 bytes of the forward S-box",
        pattern: "637c777bf26b6fc53001672bfed7ab76",
    },
    CryptoConstant {
        algorithm: "Blowfish",
        label: "blowfish_p_array_le",
        note: "P-array initial words (hex digits of pi), little-endian",
        pattern: "886a3f24d308a3852e8a191344737003",
    },
    CryptoConstant {
        algorithm: "ChaCha20/Salsa20",
        label: "chacha_sigma",
        note: "\"expand 32-byte k\" constant",
        pattern: "657870616e642033322d62797465206b",
    },
    CryptoConstant {
        algorithm: "CRC-32",
        label: "crc32_table_le",
        note: "first four entries of the reflected 0xEDB88320 table, little-endian",
        pattern: "00000000963007772c610eeeba510999",
    },
    CryptoConstant {
        algorithm: "MD5/SHA-1",
        label: "md5_sha1_init_le",
        note: "initial chaining words shared by MD5 and SHA-1, little-endian",
        pattern: "0123456789abcdeffedcba9876543210",
    },
    CryptoConstant {
        algorithm: "MD5",
        label: "md5_t_table_le",
        note: "first four sine-derived T constants, little-endian",
        pattern: "78a46ad756b7c7e8db702024eecebdc1",
    },
    CryptoConstant {
        algorithm: "SHA-256",
        label: "sha256_h_be",
        note: "initial hash words, big-endian",
        pattern: "6a09e667bb67ae853c6ef372a54ff53a",
    },
    CryptoConstant {
        algorithm: "SHA-256",
        label: "sha256_h_le",
        note: "initial hash words, little-endian",
        pattern: "67e6096a85ae67bb72f36e3c3af54fa5",
    },
    CryptoConstant {
        algorithm: "SHA-256",
        label: "sha256_k_be",
        note: "first four round constants, big-endian",
        pattern: "428a2f9871374491b5c0fbcfe9b5dba5",
    },
    CryptoConstant {
        algorithm: "SHA-256",
        label: "sha256_k_le",
        note: "first four round constants, little-endian",
        pattern: "982f8a4291443771cffbc0b5a5dbb5e9",
    },
    CryptoConstant {
        algorithm: "SHA-512",
        label: "sha512_k_le",
        note: "first two 64-bit round constants, little-endian",
        pattern: "22ae28d7982f8a42cd65ef2391443771",
    },
    CryptoConstant {
        algorithm: "TEA/XTEA (or golden-ratio hashing)",
        label: "tea_delta_le",
        note: "0x9E3779B9; 4 bytes, low specificity: also common in hash mixing",
        pattern: "b979379e",
    },
];

pub fn detect_crypto_constants(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let lines: Vec<String> = CRYPTO_CONSTANTS
        .iter()
        .map(|c| format!("{}\t{}", c.label, c.pattern))
        .collect();
    let (subject, export) = query::run_mode(config, args, "bytes", Some(&lines.join("\n")))?;
    crypto_evidence(subject, &export)
}

fn crypto_evidence(subject: Subject, export: &Export) -> Result<Value, FathomError> {
    let mut evidence = base("detect_crypto_constants", subject);
    let mut partial = false;
    for constant in CRYPTO_CONSTANTS {
        let result = pattern_result(export, constant.label)?;
        if result.pattern != constant.pattern {
            return Err(FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!(
                    "export answers a different pattern for '{}'",
                    constant.label
                ),
            ));
        }
        partial |= result.matches.is_partial() || result.stopped_at_cap;
        if result.matches.rows.is_empty() {
            continue;
        }
        let mut finding = Finding::new(
            "crypto_constant",
            Confidence::Inferred,
            json!({
                "algorithm": constant.algorithm,
                "constant": constant.label,
                "matches": result.matches.rows.iter().map(|m| json!({
                    "address": m.address, "block": m.block, "function": m.function,
                })).collect::<Vec<_>>(),
                "note": constant.note,
                "pattern": constant.pattern,
            }),
        )
        .with_limitation(
            "the bytes at each address are observed; the algorithm is inferred from the \
             constant alone — implementations that compute or obfuscate constants are \
             not found, and unrelated data can coincide",
        );
        for row in &result.matches.rows {
            finding = finding.with_location(row.address.clone());
        }
        evidence.add_finding(finding);
    }
    evidence.coverage.examined = CRYPTO_CONSTANTS.len() as u64;
    evidence.coverage.total = CRYPTO_CONSTANTS.len() as u64;
    evidence.coverage.exhaustive = !partial;
    if partial {
        evidence.add_unknown(
            "matches",
            "some constants matched more often than the match bound retains",
        );
    }
    Ok(evidence.to_value())
}

/// Capability rules: category, imported API base names, and string
/// indicators (case-insensitive substrings).
struct CapabilityRule {
    apis: &'static [&'static str],
    category: &'static str,
    strings: &'static [&'static str],
}

const CAPABILITY_RULES: &[CapabilityRule] = &[
    CapabilityRule {
        apis: &[
            "BCryptEncrypt",
            "CryptAcquireContext",
            "CryptEncrypt",
            "CryptGenKey",
            "EVP_EncryptInit_ex",
        ],
        category: "cryptography_api",
        strings: &[],
    },
    CapabilityRule {
        apis: &["URLDownloadToFile", "URLDownloadToCacheFile"],
        category: "download",
        strings: &[],
    },
    CapabilityRule {
        apis: &["GetAsyncKeyState", "SetWindowsHookEx"],
        category: "input_capture",
        strings: &[],
    },
    CapabilityRule {
        apis: &[
            "HttpSendRequest",
            "InternetOpen",
            "InternetOpenUrl",
            "WSAStartup",
            "WinHttpOpen",
            "connect",
            "getaddrinfo",
            "gethostbyname",
            "socket",
        ],
        category: "network",
        strings: &[],
    },
    CapabilityRule {
        apis: &[
            "ChangeServiceConfig",
            "CreateService",
            "RegCreateKeyEx",
            "RegSetValueEx",
        ],
        category: "persistence",
        strings: &[
            "\\currentversion\\run",
            "/etc/ld.so.preload",
            "/etc/rc.local",
            "crontab",
            "schtasks",
            "systemctl enable",
        ],
    },
    CapabilityRule {
        apis: &[
            "AdjustTokenPrivileges",
            "LookupPrivilegeValue",
            "OpenProcessToken",
            "setgid",
            "setuid",
        ],
        category: "privilege",
        strings: &[],
    },
    CapabilityRule {
        apis: &[
            "CreateProcess",
            "ShellExecute",
            "ShellExecuteEx",
            "WinExec",
            "execl",
            "execlp",
            "execv",
            "execve",
            "execvp",
            "popen",
            "system",
        ],
        category: "process_execution",
        strings: &["/bin/sh -c", "cmd.exe /c", "powershell -"],
    },
    CapabilityRule {
        apis: &[
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "NtUnmapViewOfSection",
            "QueueUserAPC",
            "RtlCreateUserThread",
            "SetThreadContext",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "process_vm_writev",
        ],
        category: "process_injection",
        strings: &[],
    },
    CapabilityRule {
        apis: &[],
        category: "recovery_inhibition",
        strings: &[
            "bcdedit",
            "vssadmin delete shadows",
            "wevtutil cl",
            "wbadmin delete",
        ],
    },
];

/// Name variants an import may carry for one API: the label itself,
/// without `__imp_`/leading underscores, without a Win32 `A`/`W`
/// suffix, and with `Zw` read as `Nt`.
fn api_variants(name: &str) -> Vec<String> {
    let trimmed = name.trim_start_matches("__imp_").trim_start_matches('_');
    let mut out = vec![name.to_string(), trimmed.to_string()];
    if let Some(stem) = trimmed
        .strip_suffix('A')
        .or_else(|| trimmed.strip_suffix('W'))
        && stem.chars().last().is_some_and(|c| c.is_ascii_lowercase())
    {
        out.push(stem.to_string());
    }
    let more: Vec<String> = out
        .iter()
        .filter_map(|v| v.strip_prefix("Zw").map(|rest| format!("Nt{rest}")))
        .collect();
    out.extend(more);
    out
}

fn imported_names(externals: &[ExternalLocation]) -> Vec<(&str, &str)> {
    externals
        .iter()
        .map(|e| {
            let name = if e.original_name.is_empty() {
                e.label.as_str()
            } else {
                e.original_name.as_str()
            };
            (name, e.library.as_str())
        })
        .collect()
}

/// The stated rule for byte-run strings, carried by every finding
/// built on them.
const BYTE_RUN_RULE: &str = "byte_run strings come from a printable-ASCII scan of \
    initialized, non-executable memory (runs inside executable blocks are instruction \
    bytes and are skipped); unterminated literals (Rust, Go) can run into their \
    neighbours, so a value's end is not reliable";

/// Every defined string, then every byte-run string not already at
/// a defined string's address and not inside an executable block:
/// `(address, value, source)`.
fn program_strings(overview: &Export) -> Vec<(&str, &str, &'static str)> {
    let defined: BTreeSet<&str> = overview
        .strings
        .iter()
        .map(|s| s.address.as_str())
        .collect();
    let executable: Vec<((String, u64), (String, u64))> = overview
        .memory_blocks
        .iter()
        .filter(|b| b.execute)
        .filter_map(|b| Some((query::address_key(&b.start)?, query::address_key(&b.end)?)))
        .collect();
    let in_code = |address: &str| {
        query::address_key(address).is_some_and(|key| {
            executable
                .iter()
                .any(|(start, end)| key.0 == start.0 && key.1 >= start.1 && key.1 <= end.1)
        })
    };
    overview
        .strings
        .iter()
        .map(|s| (s.address.as_str(), s.value.as_str(), "defined"))
        .chain(
            overview
                .data_strings
                .iter()
                .filter(|s| !defined.contains(s.address.as_str()) && !in_code(&s.address))
                .map(|s| (s.address.as_str(), s.value.as_str(), "byte_run")),
        )
        .collect()
}

pub fn detect_malware_behaviors(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let (subject, program) = query::run_mode(config, args, "program", None)?;
    let (later, overview) = crate::ghidra::subject_and_export(config, args, "overview", None)?;
    same_subject(&subject, &later)?;
    behavior_evidence(subject, &program, &overview)
}

fn behavior_evidence(
    subject: Subject,
    program: &Export,
    overview: &Export,
) -> Result<Value, FathomError> {
    let mut evidence = base("detect_malware_behaviors", subject);
    let externals = &query::section(&program.program_facts, "program_facts")?.external_locations;
    externals.check("program_facts.external_locations")?;
    let imports = imported_names(&externals.rows);
    let strings = program_strings(overview);
    for rule in CAPABILITY_RULES {
        let api_hits: Vec<Value> = imports
            .iter()
            .filter(|(name, _)| {
                api_variants(name)
                    .iter()
                    .any(|variant| rule.apis.contains(&variant.as_str()))
            })
            .map(|(name, library)| json!({"import": name, "library": library}))
            .collect();
        let string_hits: Vec<Value> = strings
            .iter()
            .filter_map(|(address, value, source)| {
                let lower = value.to_lowercase();
                rule.strings
                    .iter()
                    .find(|needle| lower.contains(*needle))
                    .map(|needle| {
                        json!({
                            "address": address, "indicator": needle, "source": source,
                            "value": value.chars().take(200).collect::<String>(),
                        })
                    })
            })
            .collect();
        if api_hits.is_empty() && string_hits.is_empty() {
            continue;
        }
        let byte_runs = string_hits.iter().any(|h| h["source"] == "byte_run");
        let mut finding = Finding::new(
            "capability",
            Confidence::Inferred,
            json!({
                "category": rule.category,
                "imports": api_hits,
                "strings": string_hits,
            }),
        )
        .with_limitation(
            "imported names and strings are observed; the capability is inferred from \
             a fixed rule table — presence shows a capability, not intent, and benign \
             programs routinely carry these",
        );
        if byte_runs {
            finding = finding.with_limitation(BYTE_RUN_RULE);
        }
        evidence.add_finding(finding);
    }
    evidence.add_unknown(
        "static_code",
        "statically linked or dynamically resolved APIs (GetProcAddress/dlsym) are not \
         matched by import name",
    );
    let partial = externals.is_partial()
        || overview.strings_truncated
        || overview.data_strings_truncated
        || overview.data_strings_scan_capped;
    query::cover(
        &mut evidence,
        externals.rows.len() + strings.len(),
        externals.total + (overview.strings_total + overview.data_strings_total) as u64,
        partial,
    );
    Ok(evidence.to_value())
}

/// Anti-analysis rules over imports, instructions, and strings.
const ANTI_DEBUG_APIS: &[&str] = &[
    "CheckRemoteDebuggerPresent",
    "IsDebuggerPresent",
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "OutputDebugString",
    "ptrace",
];

const TIMING_APIS: &[&str] = &["GetTickCount", "GetTickCount64", "QueryPerformanceCounter"];

/// Instruction terms (export `insns` syntax), what each suggests,
/// and — for low-specificity rules — why a hit is weak evidence.
const ANTI_ANALYSIS_INSTRUCTIONS: &[(&str, &str, Option<&str>)] = &[
    ("m:cpuid", "virtualization/CPU fingerprinting", None),
    ("m:icebp", "debugger trap (ICEBP)", None),
    ("m:int1", "debugger trap (INT1)", None),
    (
        "m:int3",
        "breakpoint trap inside a function body",
        Some(
            "low specificity: compilers emit INT3 as a trap after non-returning calls and \
             as intra-function padding; most hits in compiled code are not anti-debugging",
        ),
    ),
    ("m:rdtsc", "timing check", None),
    ("m:sgdt", "descriptor-table VM check", None),
    ("m:sidt", "descriptor-table VM check", None),
    ("m:sldt", "descriptor-table VM check", None),
    ("m:smsw", "machine-status VM check", None),
    ("t:int 0x2d", "kernel-debugger trap (INT 2D)", None),
];

const ANTI_ANALYSIS_STRINGS: &[(&str, &str)] = &[
    ("/proc/self/status", "self-inspection (TracerPid)"),
    ("ollydbg", "debugger name"),
    ("qemu", "virtual-machine artifact"),
    ("sbiedll", "sandbox artifact (Sandboxie)"),
    ("tracerpid", "debugger check (Linux)"),
    ("vboxguest", "virtual-machine artifact"),
    ("vmware", "virtual-machine artifact"),
    ("wine_get_version", "Wine detection"),
    ("x64dbg", "debugger name"),
];

pub fn find_anti_analysis_techniques(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let terms: Vec<&str> = ANTI_ANALYSIS_INSTRUCTIONS
        .iter()
        .map(|(t, _, _)| *t)
        .collect();
    let (subject, program) = query::run_mode(config, args, "program", None)?;
    let (later, insns) = query::run_mode(config, args, "insns", Some(&terms.join("\n")))?;
    same_subject(&subject, &later)?;
    let (last, overview) = crate::ghidra::subject_and_export(config, args, "overview", None)?;
    same_subject(&subject, &last)?;
    anti_analysis_evidence(subject, &program, &insns, &overview)
}

fn anti_analysis_evidence(
    subject: Subject,
    program: &Export,
    insns: &Export,
    overview: &Export,
) -> Result<Value, FathomError> {
    let mut evidence = base("find_anti_analysis_techniques", subject);
    let externals = &query::section(&program.program_facts, "program_facts")?.external_locations;
    externals.check("program_facts.external_locations")?;
    let search = query::section(&insns.instruction_search, "instruction_search")?;
    search.matches.check("instruction_search.matches")?;
    for (name, library) in imported_names(&externals.rows) {
        let variants = api_variants(name);
        let technique = if variants
            .iter()
            .any(|v| ANTI_DEBUG_APIS.contains(&v.as_str()))
        {
            "debugger detection API"
        } else if variants.iter().any(|v| TIMING_APIS.contains(&v.as_str())) {
            "timing source (usable for debugger timing checks)"
        } else {
            continue;
        };
        evidence.add_finding(
            Finding::new(
                "anti_analysis",
                Confidence::Inferred,
                json!({"import": name, "library": library, "technique": technique}),
            )
            .with_limitation("the import is observed; its anti-analysis use is inferred"),
        );
    }
    let mut outside_functions = 0usize;
    for (term, technique, weak) in ANTI_ANALYSIS_INSTRUCTIONS {
        let hits: Vec<Value> = search
            .matches
            .rows
            .iter()
            .filter(|m| m.term == *term)
            .filter(|m| {
                // INT3 between functions is alignment padding, not a check.
                let padding = *term == "m:int3" && m.function.is_empty();
                outside_functions += usize::from(padding);
                !padding
            })
            .map(|m| json!({"address": m.address, "function": m.function, "text": m.text}))
            .collect();
        if hits.is_empty() {
            continue;
        }
        let mut finding = Finding::new(
            "anti_analysis",
            Confidence::Inferred,
            json!({
                "count": hits.len(),
                "instructions": hits,
                "specificity": if weak.is_some() { "low" } else { "high" },
                "technique": technique,
                "term": term,
            }),
        )
        .with_limitation("the instructions are observed; the technique is inferred");
        if let Some(why) = weak {
            finding = finding.with_limitation(*why);
        }
        for hit in &hits {
            if let Some(address) = hit["address"].as_str() {
                finding = finding.with_location(address.to_string());
            }
        }
        evidence.add_finding(finding);
    }
    for (address, value, source) in program_strings(overview) {
        let lower = value.to_lowercase();
        for (needle, technique) in ANTI_ANALYSIS_STRINGS {
            if lower.contains(needle) {
                let mut finding = Finding::new(
                    "anti_analysis",
                    Confidence::Inferred,
                    json!({
                        "address": address, "indicator": needle, "source": source,
                        "technique": technique,
                        "value": value.chars().take(200).collect::<String>(),
                    }),
                )
                .with_location(address.to_string())
                .with_limitation("the string is observed; its anti-analysis use is inferred");
                if source == "byte_run" {
                    finding = finding.with_limitation(BYTE_RUN_RULE);
                }
                evidence.add_finding(finding);
            }
        }
    }
    if outside_functions > 0 {
        evidence.add_unknown(
            "int3_padding",
            format!(
                "{outside_functions} INT3 instruction(s) outside any function were treated \
                 as alignment padding and not reported"
            ),
        );
    }
    if search.scan_capped || search.matches.is_partial() {
        evidence.add_unknown(
            "instructions",
            "the instruction scan or its matches were truncated at the export bound",
        );
    }
    evidence.add_unknown(
        "instruction_set",
        "instruction rules are x86 mnemonics; other architectures are examined by imports \
         and strings only",
    );
    query::cover(
        &mut evidence,
        search.scanned as usize,
        search.instructions_total,
        search.scan_capped || search.matches.is_partial() || externals.is_partial(),
    );
    Ok(evidence.to_value())
}

/// Top-level domains the domain classifier accepts.
const TLDS: &[&str] = &[
    "biz", "cc", "cf", "cn", "co", "com", "de", "edu", "eu", "fr", "ga", "gov", "gq", "info",
    "int", "io", "jp", "kr", "me", "mil", "ml", "net", "nl", "onion", "org", "pw", "ru", "site",
    "su", "tk", "top", "uk", "us", "ws", "xyz",
];

/// Unix path prefixes worth reporting as IOCs.
const UNIX_PATH_PREFIXES: &[&str] = &[
    "/dev/shm/",
    "/etc/",
    "/proc/",
    "/root/",
    "/tmp/",
    "/var/tmp/",
];

/// Classify IOCs in one string under the rules stated in the
/// finding limitation. Returns `(kind, value)` pairs.
pub(crate) fn scan_iocs(text: &str) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = Vec::new();
    let lower = text.to_ascii_lowercase();
    // URLs first: their hosts are not reported again as domains.
    let mut url_spans: Vec<(usize, usize)> = Vec::new();
    for scheme in ["http://", "https://", "ftp://"] {
        let mut from = 0;
        while let Some(found) = lower[from..].find(scheme) {
            let start = from + found;
            let end = text[start..]
                .find(|c: char| c.is_whitespace() || "\"'<>`|{}\\^".contains(c))
                .map_or(text.len(), |n| start + n);
            if end > start + scheme.len() {
                out.push(("url", text[start..end].to_string()));
                url_spans.push((start, end));
            }
            from = end.max(start + 1);
        }
    }
    let mut offset = 0;
    for token in text.split(|c: char| c.is_whitespace() || "\"'<>`|(){}[],;".contains(c)) {
        let start = offset;
        offset += token.len() + 1;
        if url_spans.iter().any(|(s, e)| start >= *s && start < *e) {
            continue;
        }
        let token = token.trim_matches(|c: char| ".:!?=".contains(c));
        if token.is_empty() {
            continue;
        }
        if let Some(kind) = classify_token(token) {
            out.push((kind, token.to_string()));
        }
        if out.len() >= IOC_PER_STRING_MAX {
            break;
        }
    }
    out.truncate(IOC_PER_STRING_MAX);
    out
}

fn classify_token(token: &str) -> Option<&'static str> {
    let lower = token.to_ascii_lowercase();
    if ["hkey_", "hklm\\", "hkcu\\", "hkcr\\", "hku\\"]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return Some("registry_key");
    }
    let bytes = token.as_bytes();
    if bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
        || token.starts_with("\\\\")
    {
        return Some("windows_path");
    }
    if UNIX_PATH_PREFIXES.iter().any(|p| token.starts_with(p)) {
        return Some("unix_path");
    }
    if let Some((local, domain)) = token.split_once('@') {
        let local_ok = !local.is_empty()
            && local
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c));
        return (local_ok && is_hostname(domain, false)).then_some("email");
    }
    if is_ipv4(token.split(':').next().unwrap_or(token)) {
        return Some("ipv4");
    }
    is_hostname(token, true).then_some("domain")
}

fn is_ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// A dotted hostname. With `curated`, the TLD must be in [`TLDS`];
/// without, any alphabetic TLD of two or more letters passes.
fn is_hostname(text: &str, curated: bool) -> bool {
    let lower = text.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 || lower.len() > 253 {
        return false;
    }
    let labels_ok = labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    });
    let tld = labels[labels.len() - 1];
    let tld_ok = if curated {
        TLDS.contains(&tld)
    } else {
        tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
    };
    labels_ok && tld_ok
}

pub fn extract_iocs_with_context(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let (subject, overview) = crate::ghidra::subject_and_export(config, args, "overview", None)?;
    let addresses = ioc_string_addresses(&overview);
    let context = if addresses.is_empty() {
        None
    } else {
        let (later, export) =
            query::run_mode(config, args, "addresses", Some(&addresses.join("\n")))?;
        same_subject(&subject, &later)?;
        Some(export)
    };
    ioc_evidence(subject, &overview, context.as_ref(), &addresses)
}

/// Canonical addresses of the first IOC-bearing strings, for the
/// one context lookup a call makes.
fn ioc_string_addresses(overview: &Export) -> Vec<String> {
    let mut out = Vec::new();
    for (address, value, _) in program_strings(overview) {
        if out.len() >= ADDRESS_QUERY_COUNT_MAX {
            break;
        }
        if scan_iocs(value).is_empty() {
            continue;
        }
        if let Ok(canonical) = query::parse_address(address)
            && !out.contains(&canonical)
        {
            out.push(canonical);
        }
    }
    out
}

fn ioc_evidence(
    subject: Subject,
    overview: &Export,
    context: Option<&Export>,
    looked_up: &[String],
) -> Result<Value, FathomError> {
    let mut evidence = base("extract_iocs_with_context", subject);
    let mut seen: BTreeSet<(String, &'static str, String)> = BTreeSet::new();
    let mut without_context = 0usize;
    let mut capped = false;
    let strings = program_strings(overview);
    for (address, value, source) in &strings {
        for (kind, ioc) in scan_iocs(value) {
            if !seen.insert((address.to_string(), kind, ioc.clone())) {
                continue;
            }
            if seen.len() > IOC_COUNT_MAX {
                capped = true;
                break;
            }
            let canonical = query::parse_address(address).ok();
            let referenced = match (context, canonical) {
                (Some(export), Some(canonical)) if looked_up.contains(&canonical) => {
                    let row = query::address_row(export, &canonical)?;
                    let refs = query::section(&row.references_to, "addresses.references_to")?;
                    refs.check("addresses.references_to")?;
                    json!(
                        refs.rows
                            .iter()
                            .map(|r| json!({
                                "from": r.from, "function": r.from_function, "type": r.kind,
                            }))
                            .collect::<Vec<_>>()
                    )
                }
                _ => {
                    without_context += 1;
                    Value::Null
                }
            };
            let mut finding = Finding::new(
                "ioc",
                Confidence::Inferred,
                json!({
                    "kind": kind,
                    "referenced_from": referenced,
                    "string_address": address,
                    "string_source": source,
                    "value": ioc,
                }),
            )
            .with_location(address.to_string())
            .with_limitation(
                "the string is observed; the IOC class is inferred by fathom's lexical \
                 rules (URL schemes, dotted-quad IPv4, curated TLDs, registry roots, path \
                 prefixes)",
            );
            if *source == "byte_run" {
                finding = finding.with_limitation(BYTE_RUN_RULE);
            }
            evidence.add_finding(finding);
        }
        if capped {
            break;
        }
    }
    if without_context > 0 {
        evidence.add_unknown(
            "context",
            format!(
                "{without_context} IOC(s) lie in strings beyond the first \
                 {ADDRESS_QUERY_COUNT_MAX} looked up; their referencing code was not examined \
                 (use get_xrefs_to on the string address)"
            ),
        );
    }
    if capped {
        evidence.add_unknown("iocs", format!("stopped at {IOC_COUNT_MAX} IOCs"));
    }
    let partial = capped
        || overview.strings_truncated
        || overview.data_strings_truncated
        || overview.data_strings_scan_capped;
    query::cover(
        &mut evidence,
        strings.len(),
        (overview.strings_total + overview.data_strings_total) as u64,
        partial,
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghidra::query::tests::{PROGRAM, export, program_facts, subject};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn pattern(label: &str) -> &'static str {
        CRYPTO_CONSTANTS
            .iter()
            .find(|c| c.label == label)
            .unwrap()
            .pattern
    }

    fn words_le(words: &[u32]) -> String {
        hex(&words
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>())
    }

    fn words_be(words: &[u32]) -> String {
        hex(&words
            .iter()
            .flat_map(|w| w.to_be_bytes())
            .collect::<Vec<_>>())
    }

    const PRIMES: [f64; 4] = [2.0, 3.0, 5.0, 7.0];

    #[test]
    fn validation_sha256_constants_from_prime_roots() {
        // K: fractional cube roots; H: fractional square roots.
        let k: Vec<u32> = PRIMES
            .iter()
            .map(|p| (p.cbrt().fract() * 4_294_967_296.0) as u32)
            .collect();
        let h: Vec<u32> = PRIMES
            .iter()
            .map(|p| (p.sqrt().fract() * 4_294_967_296.0) as u32)
            .collect();
        assert_eq!(pattern("sha256_k_be"), words_be(&k));
        assert_eq!(pattern("sha256_k_le"), words_le(&k));
        assert_eq!(pattern("sha256_h_be"), words_be(&h));
        assert_eq!(pattern("sha256_h_le"), words_le(&h));
        // SHA-512's constants extend SHA-256's: the high words agree.
        let k512 = u128::from_str_radix(pattern("sha512_k_le"), 16).unwrap();
        let bytes = k512.to_be_bytes();
        let first = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let second = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        assert_eq!((first >> 32) as u32, k[0]);
        assert_eq!((second >> 32) as u32, k[1]);
    }

    #[test]
    fn validation_md5_and_crc_constants_from_definitions() {
        let t: Vec<u32> = (1..=4)
            .map(|i| ((i as f64).sin().abs() * 4_294_967_296.0) as u32)
            .collect();
        assert_eq!(pattern("md5_t_table_le"), words_le(&t));
        assert_eq!(
            pattern("md5_sha1_init_le"),
            words_le(&[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])
        );
        let crc: Vec<u32> = (0..4u32)
            .map(|n| {
                (0..8).fold(n, |c, _| {
                    if c & 1 == 1 {
                        0xEDB8_8320 ^ (c >> 1)
                    } else {
                        c >> 1
                    }
                })
            })
            .collect();
        assert_eq!(pattern("crc32_table_le"), words_le(&crc));
        let delta = (4_294_967_296.0 * (5f64.sqrt() - 1.0) / 2.0) as u32;
        assert_eq!(pattern("tea_delta_le"), words_le(&[delta]));
        assert_eq!(pattern("chacha_sigma"), hex(b"expand 32-byte k"));
    }

    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0u8;
        while b != 0 {
            if b & 1 == 1 {
                product ^= a;
            }
            let carry = a & 0x80 != 0;
            a <<= 1;
            if carry {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        product
    }

    fn sbox(x: u8) -> u8 {
        let inv = if x == 0 {
            0
        } else {
            (1..=255u8).find(|b| gf_mul(x, *b) == 1).unwrap()
        };
        inv ^ inv.rotate_left(1)
            ^ inv.rotate_left(2)
            ^ inv.rotate_left(3)
            ^ inv.rotate_left(4)
            ^ 0x63
    }

    #[test]
    fn validation_aes_sboxes_from_gf256() {
        let forward: Vec<u8> = (0..16u8).map(sbox).collect();
        assert_eq!(pattern("aes_sbox"), hex(&forward));
        let inverse: Vec<u8> = (0..16u8)
            .map(|y| (0..=255u8).find(|x| sbox(*x) == y).unwrap())
            .collect();
        assert_eq!(pattern("aes_inverse_sbox"), hex(&inverse));
    }

    /// Hex digit `d` (0-based, after the point) of pi by BBP.
    fn pi_hex_digit(d: u64) -> u8 {
        fn series(j: u64, d: u64) -> f64 {
            let mut sum = 0.0;
            for k in 0..=d {
                let r = 8 * k + j;
                let mut power = 1u64;
                for _ in 0..(d - k) {
                    power = power * 16 % r;
                }
                sum = (sum + power as f64 / r as f64).fract();
            }
            for k in (d + 1)..(d + 20) {
                sum += 16f64.powi(-((k - d) as i32)) / (8 * k + j) as f64;
            }
            sum.fract()
        }
        let x = (4.0 * series(1, d) - 2.0 * series(4, d) - series(5, d) - series(6, d)).fract();
        let x = if x < 0.0 { x + 1.0 } else { x };
        (x * 16.0) as u8
    }

    #[test]
    fn validation_blowfish_p_array_from_pi_digits() {
        let digits: Vec<u8> = (0..32).map(pi_hex_digit).collect();
        let words: Vec<u32> = digits
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u32, |w, d| (w << 4) | u32::from(*d)))
            .collect();
        assert_eq!(pattern("blowfish_p_array_le"), words_le(&words));
    }

    #[test]
    fn adversarial_constant_table_is_well_formed() {
        let mut labels = BTreeSet::new();
        for constant in CRYPTO_CONSTANTS {
            assert!(
                labels.insert(constant.label),
                "duplicate {}",
                constant.label
            );
            assert_eq!(
                crate::ghidra::search::normalize_pattern(constant.pattern).unwrap(),
                constant.pattern
            );
            assert!(!constant.label.contains('\t') && !constant.label.contains('\n'));
        }
        assert!(CRYPTO_CONSTANTS.len() <= fathom_core::limits::BYTE_PATTERN_COUNT_MAX);
        let sorted: Vec<&str> = CRYPTO_CONSTANTS.iter().map(|c| c.label).collect();
        let mut expected = sorted.clone();
        expected.sort_unstable();
        assert_eq!(sorted, expected, "table is alphabetical");
    }

    fn bytes_export(hits: &[(&str, &str)]) -> Export {
        let patterns: Vec<String> = CRYPTO_CONSTANTS
            .iter()
            .map(|c| {
                let rows: Vec<String> = hits
                    .iter()
                    .filter(|(label, _)| *label == c.label)
                    .map(|(_, address)| {
                        format!(r#"{{"address": "{address}", "block": ".rodata", "function": ""}}"#)
                    })
                    .collect();
                format!(
                    r#"{{"label": "{}", "pattern": "{}", "stopped_at_cap": false,
                        "matches": {{"rows": [{}], "total": {}, "truncated": false}}}}"#,
                    c.label,
                    c.pattern,
                    rows.join(","),
                    rows.len()
                )
            })
            .collect();
        export(
            "bytes",
            &format!(r#""byte_search": {{"patterns": [{}]}}"#, patterns.join(",")),
        )
    }

    #[test]
    fn validation_crypto_hits_are_inferred_with_observed_addresses() {
        let export = bytes_export(&[("aes_sbox", "00104000")]);
        let value = crypto_evidence(subject(), &export).unwrap();
        let findings = value["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["confidence"], "inferred");
        assert_eq!(findings[0]["facts"]["algorithm"], "AES");
        assert_eq!(findings[0]["locations"][0], "00104000");
    }

    #[test]
    fn adversarial_export_missing_a_constant_is_an_integrity_error() {
        let export = export(
            "bytes",
            r#""byte_search": {"patterns": [{"label": "aes_sbox",
                "pattern": "637c777bf26b6fc53001672bfed7ab76", "stopped_at_cap": false,
                "matches": {"rows": [], "total": 0, "truncated": false}}]}"#,
        );
        let error = crypto_evidence(subject(), &export).unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn validation_api_variants_cover_suffixes_and_zw() {
        let variants = api_variants("__imp_CreateProcessW");
        assert!(variants.contains(&"CreateProcess".to_string()));
        assert!(api_variants("ZwCreateThreadEx").contains(&"NtCreateThreadEx".to_string()));
        // An upper-case final letter of a real name is not a suffix.
        assert!(!api_variants("GetDC").contains(&"GetD".to_string()));
    }

    fn overview(strings: &[(&str, &str)]) -> Export {
        let rows: Vec<String> = strings
            .iter()
            .map(|(a, v)| format!(r#"{{"address": "{a}", "value": "{v}"}}"#))
            .collect();
        let doc = format!(
            r#"{{{PROGRAM}, "strings": [{}], "strings_total": {}}}"#,
            rows.join(","),
            rows.len()
        );
        crate::engine::parse_export(doc.as_bytes()).unwrap()
    }

    const EXTERNALS: &str = r#"{"rows": [
        {"address": "", "external_address": "EXTERNAL:1", "is_function": true,
         "label": "WriteProcessMemory", "library": "KERNEL32.DLL", "library_path": "",
         "original_name": "", "source": "IMPORTED"},
        {"address": "", "external_address": "EXTERNAL:2", "is_function": true,
         "label": "IsDebuggerPresent", "library": "KERNEL32.DLL", "library_path": "",
         "original_name": "", "source": "IMPORTED"},
        {"address": "", "external_address": "EXTERNAL:3", "is_function": true,
         "label": "puts", "library": "libc.so.6", "library_path": "",
         "original_name": "", "source": "IMPORTED"}], "total": 3, "truncated": false}"#;

    #[test]
    fn validation_capabilities_from_imports_and_strings() {
        let program = program_facts(&[("external_locations", EXTERNALS)]);
        let strings = overview(&[(
            "00105000",
            "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        )]);
        let value = behavior_evidence(subject(), &program, &strings).unwrap();
        let categories: Vec<&str> = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["facts"]["category"].as_str().unwrap())
            .collect();
        assert_eq!(categories, vec!["persistence", "process_injection"]);
        assert!(
            value["findings"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["confidence"] == "inferred")
        );
    }

    #[test]
    fn adversarial_benign_program_yields_no_capabilities_but_states_limits() {
        let program = program_facts(&[]);
        let value = behavior_evidence(subject(), &program, &overview(&[])).unwrap();
        assert!(value["findings"].as_array().unwrap().is_empty());
        assert_eq!(value["unknowns"][0]["aspect"], "static_code");
    }

    #[test]
    fn validation_anti_analysis_skips_int3_padding() {
        let program = program_facts(&[("external_locations", EXTERNALS)]);
        let insns = export(
            "insns",
            r#""instruction_search": {"instructions_total": 50, "scanned": 50,
                "scan_capped": false, "terms": [],
                "matches": {"rows": [
                    {"address": "00101000", "function": "check", "mnemonic": "RDTSC",
                     "term": "m:rdtsc", "text": "RDTSC"},
                    {"address": "00101ff0", "function": "", "mnemonic": "INT3",
                     "term": "m:int3", "text": "INT3"},
                    {"address": "00101010", "function": "check", "mnemonic": "INT3",
                     "term": "m:int3", "text": "INT3"}], "total": 3, "truncated": false}}"#,
        );
        let strings = overview(&[("00106000", "VBoxGuest")]);
        let value = anti_analysis_evidence(subject(), &program, &insns, &strings).unwrap();
        let techniques: Vec<&str> = value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["facts"]["technique"].as_str().unwrap())
            .collect();
        assert_eq!(
            techniques,
            vec![
                "debugger detection API",
                "breakpoint trap inside a function body",
                "timing check",
                "virtual-machine artifact"
            ]
        );
        // The in-function INT3 is reported, but marked low-specificity;
        // the one between functions is padding and only counted.
        assert_eq!(value["findings"][1]["facts"]["specificity"], "low");
        assert_eq!(value["findings"][1]["facts"]["count"], 1);
        assert_eq!(value["findings"][2]["facts"]["specificity"], "high");
        assert_eq!(value["unknowns"][0]["aspect"], "int3_padding");
    }

    #[test]
    fn validation_ioc_scanner_classes() {
        let found = scan_iocs(
            "GET http://evil.example.com/a?b=1 from 10.0.0.255:8080 mail ops@corp.net \
             key HKLM\\Software\\Run path C:\\Windows\\x.dll /tmp/.x c2.badhost.ru",
        );
        let kinds: Vec<(&str, &str)> = found.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert!(kinds.contains(&("url", "http://evil.example.com/a?b=1")));
        assert!(kinds.contains(&("ipv4", "10.0.0.255:8080")));
        assert!(kinds.contains(&("email", "ops@corp.net")));
        assert!(kinds.contains(&("registry_key", "HKLM\\Software\\Run")));
        assert!(kinds.contains(&("windows_path", "C:\\Windows\\x.dll")));
        assert!(kinds.contains(&("unix_path", "/tmp/.x")));
        assert!(kinds.contains(&("domain", "c2.badhost.ru")));
        // The URL's host is not double-reported as a domain.
        assert!(!kinds.contains(&("domain", "evil.example.com")));
    }

    #[test]
    fn adversarial_ioc_scanner_rejects_lookalikes() {
        for text in [
            "libc.so.6",
            "ld-linux-x86-64.so.2",
            "version 1.2.3",
            "999.1.1.1",
            "1.2.3.4.5",
            "a@b",
            "@corp.net",
            "-bad.com",
            "GLIBC_2.34",
            "http://",
        ] {
            assert!(
                scan_iocs(text).is_empty(),
                "flagged {text:?}: {:?}",
                scan_iocs(text)
            );
        }
        let flood = "1.1.1.1 ".repeat(100);
        assert_eq!(scan_iocs(&flood).len(), IOC_PER_STRING_MAX);
    }

    #[test]
    fn validation_iocs_carry_referencing_functions() {
        let strings = overview(&[("00107000", "https://c2.example.com/beacon")]);
        let addresses = ioc_string_addresses(&strings);
        assert_eq!(addresses, vec!["107000".to_string()]);
        let context = export(
            "addresses",
            r#""addresses": [{"query": "107000", "valid": true, "address": "00107000",
                "in_memory": true,
                "references_to": {"rows": [{"from": "00101234", "from_function": "beacon",
                    "type": "DATA"}], "total": 1, "truncated": false},
                "references_from": {"rows": [], "total": 0, "truncated": false}}]"#,
        );
        let value = ioc_evidence(subject(), &strings, Some(&context), &addresses).unwrap();
        let facts = &value["findings"][0]["facts"];
        assert_eq!(facts["kind"], "url");
        assert_eq!(facts["referenced_from"][0]["function"], "beacon");
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_byte_runs_inside_code_are_not_strings() {
        // Live-fixture finding: string immediates in instructions
        // ("/proc/se" + opcode byte) surfaced as bogus IOCs.
        let doc = format!(
            r#"{{{PROGRAM},
            "memory_blocks": [
                {{"name": ".text", "start": "00101000", "end": "00101fff", "size": 4096,
                  "read": true, "write": false, "execute": true, "initialized": true}},
                {{"name": ".rodata", "start": "00102000", "end": "00102fff", "size": 4096,
                  "read": true, "write": false, "execute": false, "initialized": true}}],
            "data_strings": [
                {{"address": "00101234", "value": "/proc/seH"}},
                {{"address": "00102010", "value": "/tmp/payload"}}],
            "data_strings_total": 2}}"#
        );
        let overview = crate::engine::parse_export(doc.as_bytes()).unwrap();
        let strings = program_strings(&overview);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].0, "00102010");
        let value = ioc_evidence(subject(), &overview, None, &[]).unwrap();
        let limitations = value["findings"][0]["limitations"].as_array().unwrap();
        assert!(limitations.iter().any(|l| l == BYTE_RUN_RULE));
    }

    #[test]
    fn adversarial_iocs_beyond_lookup_say_context_was_not_examined() {
        let strings = overview(&[("00107000", "https://c2.example.com/beacon")]);
        let value = ioc_evidence(subject(), &strings, None, &[]).unwrap();
        assert!(value["findings"][0]["facts"]["referenced_from"].is_null());
        assert_eq!(value["unknowns"][0]["aspect"], "context");
    }
}
