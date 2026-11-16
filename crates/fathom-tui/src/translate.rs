//! The Translate stage's deterministic half (D-1560): a text
//! inventory of the target plus the translation manifest
//! skeleton.
//!
//! Extraction is bounded and honest: candidate text-bearing
//! files are decoded as UTF-8 / UTF-16 (BOM-sniffed); files
//! that decode neither way are counted as undecoded — legacy
//! encodings such as Shift-JIS are a named unknown, not a
//! guess. Detection is script-first with a marker heuristic
//! for Latin scripts. The translation itself is model work
//! and lands in rung 2; in rung 1 every manifest entry's
//! `english` is null, which says exactly that.

use crate::config::{Language, SourceLanguageMode, TextDirection, TranslateConfig};
use crate::error::WorkflowError;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// File extensions treated as text-bearing, alphabetical.
pub const TEXT_EXTENSIONS: [&str; 14] = [
    "csv", "ini", "json", "ks", "lua", "po", "resx", "rpy", "strings", "tsv", "txt", "xml", "yaml",
    "yml",
];

/// Most files the inventory walk will visit.
pub const WALK_FILES_MAX: usize = 20_000;
/// Deepest directory nesting the walk follows.
pub const WALK_DEPTH_MAX: usize = 32;
/// Most bytes read from one candidate file.
pub const FILE_BYTES_MAX: u64 = 1_048_576;
/// Most strings extracted from one file.
pub const FILE_STRINGS_MAX: usize = 10_000;
/// Most characters kept per extracted string.
pub const STRING_CHARS_MAX: usize = 512;
/// Most entries written into the manifest. Strings past the
/// cap are still counted in the summary; `truncated` says so.
pub const MANIFEST_ENTRIES_MAX: usize = 4_096;
/// Deepest JSON nesting walked for string values.
pub const JSON_DEPTH_MAX: usize = 32;

/// The language a string was classified as. Detection can
/// decline (`Undetermined`); a forced source-language mode
/// never rewrites the detected value on the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextLanguage {
    /// A `Language` was determined.
    Known(Language),
    /// No signal cleared the detection threshold.
    Undetermined,
}

impl TextLanguage {
    /// Machine name for the manifest.
    pub fn name(self) -> &'static str {
        match self {
            TextLanguage::Known(language) => language.name(),
            TextLanguage::Undetermined => "undetermined",
        }
    }

    /// Script direction of the classification.
    pub fn direction(self) -> TextDirection {
        match self {
            TextLanguage::Known(language) => language.direction(),
            TextLanguage::Undetermined => TextDirection::Ltr,
        }
    }
}

/// One manifest entry: a string awaiting translation.
#[derive(Clone, Debug, Serialize)]
pub struct ManifestEntry {
    /// Script direction of the classified language.
    pub direction: &'static str,
    /// The English translation; null until a provider runs
    /// (rung 2). Null is the honest rung-1 state.
    pub english: Option<String>,
    /// Stable id within the run: `s000001`, `s000002`, …
    pub id: String,
    /// The language the manifest assigns (forced mode wins).
    pub language: &'static str,
    /// The language detection found, recorded even when a
    /// forced mode overrides `language`.
    pub detected_language: &'static str,
    /// Where the string came from.
    pub provenance: EntryProvenance,
    /// The source text, bounded to `STRING_CHARS_MAX` chars.
    pub source_text: String,
}

/// Where one string was found.
#[derive(Clone, Debug, Serialize)]
pub struct EntryProvenance {
    /// Target-relative path of the source file.
    pub file: String,
    /// Extraction kind: "json-value", "line", or "po-msgid".
    pub kind: &'static str,
}

/// The manifest's summary block.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ManifestSummary {
    /// Strings counted per classified language.
    pub by_language: BTreeMap<String, usize>,
    /// Candidate files successfully decoded and scanned.
    pub files_scanned: usize,
    /// Candidate files that were not UTF-8/UTF-16 decodable.
    pub files_undecoded: usize,
    /// All strings counted (may exceed the entries written).
    pub strings_total: usize,
    /// True when the entry cap dropped strings from the list.
    pub truncated: bool,
}

/// `translation-manifest.json`: the Translate stage's record.
#[derive(Clone, Debug, Serialize)]
pub struct TranslationManifest {
    /// False when the operator toggled translation off.
    pub enabled: bool,
    /// Recorded entries (bounded; see `summary.truncated`).
    pub entries: Vec<ManifestEntry>,
    /// Source-language mode: "auto" or "fixed:<language>".
    pub mode: String,
    /// Counts over everything the inventory saw.
    pub summary: ManifestSummary,
}

impl TranslationManifest {
    /// The manifest for a disabled translation stage: written
    /// anyway, so the run record is uniform.
    pub fn disabled(mode: SourceLanguageMode) -> TranslationManifest {
        TranslationManifest {
            enabled: false,
            entries: Vec::new(),
            mode: mode.name(),
            summary: ManifestSummary::default(),
        }
    }

    /// Strings counted for one language (0 when absent).
    pub fn count_for(&self, language_name: &str) -> usize {
        self.summary
            .by_language
            .get(language_name)
            .copied()
            .unwrap_or(0)
    }
}

/// Run the inventory over `target` and build the manifest.
///
/// # Errors
/// Only on filesystem failures while walking; an unreadable
/// entry is counted and skipped, never fatal — the census
/// stage has already proven the tree readable in outline.
pub fn run_inventory(
    target: &Path,
    config: &TranslateConfig,
) -> Result<TranslationManifest, WorkflowError> {
    if !config.enabled {
        return Ok(TranslationManifest::disabled(config.mode));
    }
    let candidates = collect_candidates(target);
    let mut manifest = TranslationManifest {
        enabled: true,
        entries: Vec::new(),
        mode: config.mode.name(),
        summary: ManifestSummary::default(),
    };
    let mut next_id: u64 = 0;
    for file in &candidates {
        let bytes = match read_bounded(file) {
            Some(bytes) => bytes,
            None => continue,
        };
        let Some(text) = decode_text(&bytes) else {
            manifest.summary.files_undecoded += 1;
            continue;
        };
        manifest.summary.files_scanned += 1;
        let relative = relative_display(target, file);
        for (kind, raw) in extract_strings(file, &text) {
            let cleaned = raw.trim();
            if !is_candidate_string(cleaned) {
                continue;
            }
            let bounded: String = cleaned.chars().take(STRING_CHARS_MAX).collect();
            let detected = detect_language(&bounded);
            let assigned = match config.mode {
                SourceLanguageMode::Auto => detected,
                SourceLanguageMode::Fixed(language) => TextLanguage::Known(language),
            };
            manifest.summary.strings_total += 1;
            *manifest
                .summary
                .by_language
                .entry(assigned.name().to_string())
                .or_insert(0) += 1;
            if manifest.entries.len() < MANIFEST_ENTRIES_MAX {
                next_id += 1;
                manifest.entries.push(ManifestEntry {
                    direction: assigned.direction().name(),
                    english: None,
                    id: format!("s{next_id:06}"),
                    language: assigned.name(),
                    detected_language: detected.name(),
                    provenance: EntryProvenance {
                        file: relative.clone(),
                        kind,
                    },
                    source_text: bounded,
                });
            } else {
                manifest.summary.truncated = true;
            }
        }
    }
    Ok(manifest)
}

/// Classify one string's language. Script shares decide first
/// (Arabic, Hangul, kana, Han); Latin script falls to marker
/// scoring; no signal → `Undetermined`, except plain-ASCII
/// Latin text, which passes through as English.
pub fn detect_language(text: &str) -> TextLanguage {
    let mut arabic: u64 = 0;
    let mut han: u64 = 0;
    let mut hangul: u64 = 0;
    let mut kana: u64 = 0;
    let mut latin: u64 = 0;
    let mut letters: u64 = 0;
    for ch in text.chars() {
        if !ch.is_alphabetic() {
            continue;
        }
        letters += 1;
        match ch {
            '\u{0600}'..='\u{06FF}' | '\u{0750}'..='\u{077F}' => arabic += 1,
            '\u{3040}'..='\u{30FF}' => kana += 1,
            '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}' => han += 1,
            '\u{AC00}'..='\u{D7AF}' | '\u{1100}'..='\u{11FF}' => hangul += 1,
            _ if is_latin(ch) => latin += 1,
            _ => {}
        }
    }
    if letters == 0 {
        return TextLanguage::Undetermined;
    }
    let share = |count: u64| count * 2 >= letters;
    if share(arabic) {
        return TextLanguage::Known(Language::Arabic);
    }
    if share(hangul) {
        return TextLanguage::Known(Language::Korean);
    }
    if kana > 0 && share(kana + han) {
        return TextLanguage::Known(Language::Japanese);
    }
    if share(han) {
        return TextLanguage::Known(Language::Chinese);
    }
    if share(latin) {
        return detect_latin(text);
    }
    TextLanguage::Undetermined
}

fn is_latin(ch: char) -> bool {
    matches!(ch,
        'A'..='Z' | 'a'..='z'
        | '\u{00C0}'..='\u{024F}'
        | '\u{1E00}'..='\u{1EFF}')
}

/// Marker scoring for Latin-script strings: characteristic
/// function words and diacritics vote; the highest score above
/// zero wins. Ties and silence resolve to English when the
/// text is plain ASCII, else `Undetermined`.
fn detect_latin(text: &str) -> TextLanguage {
    let lower = text.to_lowercase();
    let mut english: i64 = 0;
    let mut italian: i64 = 0;
    let mut spanish: i64 = 0;
    for word in lower.split(|ch: char| !ch.is_alphabetic()) {
        match word {
            "and" | "are" | "for" | "start" | "the" | "this" | "with" | "you" | "your" => {
                english += 1
            }
            "che" | "della" | "delle" | "gli" | "il" | "nel" | "nella" | "per" | "salvare"
            | "vuoi" => italian += 1,
            "con" | "de" | "el" | "en" | "guardar" | "la" | "las" | "los" | "para" | "quieres"
            | "una" => spanish += 1,
            _ => {}
        }
    }
    for ch in lower.chars() {
        match ch {
            'ñ' | '¿' | '¡' => spanish += 2,
            'à' | 'è' | 'ì' | 'ò' => italian += 1,
            'á' | 'é' | 'í' | 'ó' | 'ú' => {
                spanish += 1;
                italian += 1;
            }
            _ => {}
        }
    }
    let best = english.max(italian).max(spanish);
    if best > 0 {
        if spanish == best && spanish > italian {
            return TextLanguage::Known(Language::Spanish);
        }
        if italian == best && italian > spanish {
            return TextLanguage::Known(Language::Italian);
        }
        if english == best {
            return TextLanguage::Known(Language::English);
        }
    }
    if text.is_ascii() {
        TextLanguage::Known(Language::English)
    } else {
        TextLanguage::Undetermined
    }
}

/// Collect candidate text files under `target`: iterative
/// walk, no symlink following, bounded in files and depth,
/// returned sorted by path for a deterministic manifest.
fn collect_candidates(target: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(target.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if found.len() >= WALK_FILES_MAX {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
        entries.sort();
        for path in entries {
            let Ok(file_type) = path.symlink_metadata().map(|meta| meta.file_type()) else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if depth < WALK_DEPTH_MAX {
                    stack.push((path, depth + 1));
                }
            } else if file_type.is_file() && is_text_candidate(&path) {
                found.push(path);
                if found.len() >= WALK_FILES_MAX {
                    break;
                }
            }
        }
    }
    found.sort();
    found
}

fn is_text_candidate(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| TEXT_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(FILE_BYTES_MAX + 1).read_to_end(&mut bytes).ok()?;
    bytes.truncate(FILE_BYTES_MAX as usize);
    Some(bytes)
}

/// Decode as UTF-8, or UTF-16 when a BOM says so. Anything
/// else returns None (counted as undecoded by the caller).
fn decode_text(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec()).ok();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, u16::from_be_bytes);
    }
    String::from_utf8(bytes.to_vec()).ok()
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Option<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| unit(*pair))
        .collect();
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

/// Extract candidate strings from one decoded file, tagged
/// with the extraction kind. Bounded per file.
fn extract_strings(path: &Path, text: &str) -> Vec<(&'static str, String)> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();
    let mut out: Vec<(&'static str, String)> = Vec::new();
    match extension.as_str() {
        "json" => {
            if let Ok(value) = serde_json::from_str::<Value>(text) {
                collect_json_strings(&value, &mut out);
            } else {
                collect_lines(text, "line", &mut out);
            }
        }
        "po" => {
            for line in text.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("msgid") {
                    let quoted = rest.trim().trim_matches('"');
                    if !quoted.is_empty() {
                        out.push(("po-msgid", quoted.to_string()));
                    }
                }
                if out.len() >= FILE_STRINGS_MAX {
                    break;
                }
            }
        }
        _ => collect_lines(text, "line", &mut out),
    }
    out
}

fn collect_lines(text: &str, kind: &'static str, out: &mut Vec<(&'static str, String)>) {
    for line in text.lines() {
        out.push((kind, line.to_string()));
        if out.len() >= FILE_STRINGS_MAX {
            break;
        }
    }
}

/// Iterative JSON string-value collection with a depth cap —
/// target files are untrusted, so no recursion.
fn collect_json_strings(root: &Value, out: &mut Vec<(&'static str, String)>) {
    let mut stack: Vec<(&Value, usize)> = vec![(root, 0)];
    while let Some((value, depth)) = stack.pop() {
        if out.len() >= FILE_STRINGS_MAX {
            return;
        }
        match value {
            Value::String(text) => out.push(("json-value", text.clone())),
            Value::Array(items) if depth < JSON_DEPTH_MAX => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            Value::Object(map) if depth < JSON_DEPTH_MAX => {
                for item in map.values() {
                    stack.push((item, depth + 1));
                }
            }
            _ => {}
        }
    }
}

/// A string is worth translating when it has at least two
/// characters and at least one letter.
fn is_candidate_string(text: &str) -> bool {
    text.chars().count() >= 2 && text.chars().any(|ch| ch.is_alphabetic())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_of_the_six_languages() {
        assert_eq!(
            detect_language("开始游戏并读取存档"),
            TextLanguage::Known(Language::Chinese)
        );
        assert_eq!(
            detect_language("ゲームを開始します"),
            TextLanguage::Known(Language::Japanese)
        );
        assert_eq!(
            detect_language("게임을 시작하고 저장합니다"),
            TextLanguage::Known(Language::Korean)
        );
        assert_eq!(
            detect_language("¿Quieres guardar la partida?"),
            TextLanguage::Known(Language::Spanish)
        );
        assert_eq!(
            detect_language("ابدأ اللعبة واحفظ تقدمك"),
            TextLanguage::Known(Language::Arabic)
        );
        assert_eq!(
            detect_language("Vuoi salvare la partita?"),
            TextLanguage::Known(Language::Italian)
        );
    }

    #[test]
    fn english_passes_through() {
        assert_eq!(
            detect_language("Start the game and save your progress"),
            TextLanguage::Known(Language::English)
        );
    }

    #[test]
    fn japanese_wins_when_kana_accompanies_han() {
        // Kanji alone would read Chinese; the kana decide.
        assert_eq!(
            detect_language("設定を開きます"),
            TextLanguage::Known(Language::Japanese)
        );
    }

    #[test]
    fn arabic_records_rtl() {
        let detected = detect_language("احفظ اللعبة");
        assert_eq!(detected.direction(), TextDirection::Rtl);
        assert_eq!(detected.name(), "arabic");
    }

    #[test]
    fn no_signal_is_undetermined_not_a_guess() {
        assert_eq!(detect_language("1234 !!!"), TextLanguage::Undetermined);
        assert_eq!(
            detect_language("Ωμέγα αλφάβητο"),
            TextLanguage::Undetermined
        );
    }

    fn fixture_game(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fathom-tui-translate-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("data")).expect("fixture dirs");
        root
    }

    #[test]
    fn inventory_builds_a_manifest_with_counts() {
        let root = fixture_game("counts");
        std::fs::write(
            root.join("data").join("script.rpy"),
            "label start:\n    \"ゲームを開始します\"\n    \"Start the game\"\n",
        )
        .expect("rpy");
        std::fs::write(
            root.join("data").join("ui.json"),
            "{\"title\": \"开始游戏\", \"hint\": \"Save the game\"}",
        )
        .expect("json");
        std::fs::write(root.join("data").join("blob.bin"), [0xFF, 0x00, 0xFE]).expect("bin");
        let manifest = run_inventory(&root, &TranslateConfig::default()).expect("inventory");
        assert!(manifest.enabled);
        assert_eq!(manifest.summary.files_scanned, 2);
        assert!(
            manifest.count_for("japanese") >= 1,
            "{:?}",
            manifest.summary
        );
        assert!(manifest.count_for("chinese") >= 1);
        assert!(manifest.count_for("english") >= 1);
        assert!(!manifest.entries.is_empty());
        assert!(manifest.entries.iter().all(|entry| entry.english.is_none()));
        assert_eq!(manifest.entries[0].id, "s000001");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn undecoded_files_are_counted_not_dropped_silently() {
        let root = fixture_game("undecoded");
        // Invalid UTF-8 in a .txt file: counted as undecoded.
        std::fs::write(
            root.join("legacy.txt"),
            [0x83, 0x65, 0x83, 0x58, 0x83, 0x67],
        )
        .expect("txt");
        let manifest = run_inventory(&root, &TranslateConfig::default()).expect("inventory");
        assert_eq!(manifest.summary.files_undecoded, 1);
        assert_eq!(manifest.summary.files_scanned, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn toggle_off_skips_the_stage_cleanly() {
        let root = fixture_game("off");
        std::fs::write(root.join("a.txt"), "Start the game\n").expect("txt");
        let config = TranslateConfig {
            enabled: false,
            mode: SourceLanguageMode::Auto,
        };
        let manifest = run_inventory(&root, &config).expect("inventory");
        assert!(!manifest.enabled);
        assert!(manifest.entries.is_empty());
        assert_eq!(manifest.summary.strings_total, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn forced_mode_assigns_but_detection_stays_on_record() {
        let root = fixture_game("forced");
        std::fs::write(root.join("a.txt"), "Start the game and save\n").expect("txt");
        let config = TranslateConfig {
            enabled: true,
            mode: SourceLanguageMode::Fixed(Language::Spanish),
        };
        let manifest = run_inventory(&root, &config).expect("inventory");
        let entry = manifest.entries.first().expect("one entry");
        assert_eq!(entry.language, "spanish");
        assert_eq!(entry.detected_language, "english");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manifest_serializes_with_null_english() {
        let root = fixture_game("serde");
        std::fs::write(root.join("a.txt"), "ابدأ اللعبة الآن\n").expect("txt");
        let manifest = run_inventory(&root, &TranslateConfig::default()).expect("inventory");
        let text = serde_json::to_string(&manifest).expect("serialize");
        assert!(text.contains("\"english\":null"), "{text}");
        assert!(text.contains("\"direction\":\"rtl\""), "{text}");
        assert!(text.contains("\"detected_language\":\"arabic\""), "{text}");
        let _ = std::fs::remove_dir_all(&root);
    }
}
