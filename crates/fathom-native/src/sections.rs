//! Read-core export sections (fathom Ghidra G1). Each Ghidra mode
//! writes one top-level section; every array inside is a
//! [`Bounded`] collection, so truncation is data, not silence
//! (SPEC §6). Row fields are required: a poisoned or truncated
//! export fails to parse and surfaces as
//! `evidence_integrity_mismatch`, never as a half-filled answer.

use serde::{Deserialize, Serialize};

use fathom_core::error::{ErrorCode, FathomError};

/// A capped collection as the export script writes it.
#[derive(Debug, Deserialize)]
pub struct Bounded<T> {
    pub rows: Vec<T>,
    pub total: u64,
    pub truncated: bool,
}

impl<T> Bounded<T> {
    /// Whether rows were dropped. The script's flag is not trusted
    /// alone: the counts decide too.
    pub fn is_partial(&self) -> bool {
        self.truncated || self.total > self.rows.len() as u64
    }

    /// Reject a self-contradicting section (more rows than the
    /// claimed total): the export was altered or is corrupt.
    pub fn check(&self, section: &str) -> Result<(), FathomError> {
        if (self.rows.len() as u64) > self.total {
            return Err(FathomError::new(
                ErrorCode::EvidenceIntegrityMismatch,
                format!(
                    "export section '{section}' holds {} rows but claims a total of {}",
                    self.rows.len(),
                    self.total
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct AddressFacts {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub block: String,
    #[serde(default)]
    pub bytes: String,
    #[serde(default)]
    pub code_unit: Option<CodeUnitFacts>,
    #[serde(default)]
    pub comments: Vec<AddressComment>,
    #[serde(default)]
    pub context_after: Vec<ContextRow>,
    #[serde(default)]
    pub context_at: Option<ContextRow>,
    #[serde(default)]
    pub context_before: Vec<ContextRow>,
    #[serde(default)]
    pub data: Option<DataRegion>,
    #[serde(default)]
    pub function: Option<FunctionRef>,
    #[serde(default)]
    pub in_memory: bool,
    pub query: String,
    #[serde(default)]
    pub references_from: Option<Bounded<RefFrom>>,
    #[serde(default)]
    pub references_to: Option<Bounded<RefTo>>,
    #[serde(default)]
    pub symbols: Vec<AddressSymbol>,
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddressComment {
    pub text: String,
    pub text_truncated: bool,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct AddressSymbol {
    pub name: String,
    pub namespace: String,
    pub primary: bool,
    pub source: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct Analysis {
    pub analyzed: bool,
    pub analyzed_option_present: bool,
}

#[derive(Debug, Deserialize)]
pub struct Analyzer {
    pub enabled: bool,
    pub is_default: bool,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct BasicBlock {
    pub destinations: Vec<BlockEdge>,
    pub end: String,
    pub size: u64,
    pub start: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockEdge {
    pub flow_type: String,
    pub to: String,
}

#[derive(Debug, Deserialize)]
pub struct Bookmark {
    pub address: String,
    pub category: String,
    pub comment: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct BuiltinType {
    pub length: i64,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ByteMatch {
    pub address: String,
    pub block: String,
    pub function: String,
}

#[derive(Debug, Deserialize)]
pub struct BytePatternResult {
    pub label: String,
    pub matches: Bounded<ByteMatch>,
    pub pattern: String,
    pub stopped_at_cap: bool,
}

#[derive(Debug, Deserialize)]
pub struct ByteSearch {
    pub patterns: Vec<BytePatternResult>,
}

#[derive(Debug, Deserialize)]
pub struct CallGraph {
    pub functions: Bounded<CallNode>,
}

#[derive(Debug, Deserialize)]
pub struct CallNode {
    pub address: String,
    pub callees: Vec<String>,
    pub callees_truncated: bool,
    pub classification: String,
    pub is_entry_point: bool,
    pub name: String,
    pub references_to: u64,
}

#[derive(Debug, Deserialize)]
pub struct CallingConvention {
    pub is_default: bool,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Category {
    pub data_type_count: u64,
    pub path: String,
    pub subcategory_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct ClassMember {
    pub address: String,
    pub class: String,
    pub name: String,
    pub source: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct CodeGap {
    pub end: String,
    pub first_instruction: String,
    pub first_non_padding: String,
    pub has_defined_data: bool,
    pub has_instructions: bool,
    pub size: u64,
    pub start: String,
}

#[derive(Debug, Deserialize)]
pub struct CodeUnitFacts {
    #[serde(default)]
    pub data_type: Option<String>,
    #[serde(default)]
    pub defined: Option<bool>,
    pub kind: String,
    pub length: u64,
    pub start: String,
    pub text: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Comment {
    pub address: String,
    pub text: String,
    pub text_truncated: bool,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct Component {
    pub comment: String,
    pub length: i64,
    pub name: String,
    pub offset: i64,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct ContextRow {
    pub address: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct DataComponent {
    pub path: String,
    pub start: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct DataItem {
    pub address: String,
    pub label: String,
    pub length: u64,
    pub references_to: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct DataRegion {
    #[serde(default)]
    pub component: Option<DataComponent>,
    pub component_count: u64,
    pub defined: bool,
    pub label: String,
    pub length: u64,
    pub offset: i64,
    pub references_to: u64,
    pub start: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct DataTypeRow {
    pub alignment: i64,
    #[serde(default)]
    pub base: Option<String>,
    pub category: String,
    #[serde(default)]
    pub components: Option<Bounded<Component>>,
    pub description: String,
    #[serde(default)]
    pub element_count: Option<i64>,
    pub kind: String,
    pub length: i64,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub prototype: Option<String>,
    #[serde(default)]
    pub values: Option<Bounded<EnumValue>>,
}

#[derive(Debug, Deserialize)]
pub struct DecompileRow {
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub c: Option<String>,
    pub candidates: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
    pub found: bool,
    #[serde(default)]
    pub function: Option<crate::engine::FunctionInfo>,
    #[serde(rename = "match")]
    pub matched_via: String,
    pub query: String,
    #[serde(default)]
    pub truncated: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct Detail {
    #[serde(default)]
    pub blocks: Option<Bounded<BasicBlock>>,
    #[serde(default)]
    pub callees: Vec<FunctionRefClassified>,
    #[serde(default)]
    pub callers: Vec<FunctionRef>,
    pub candidates: Vec<String>,
    #[serde(default)]
    pub comments: Option<Bounded<Comment>>,
    #[serde(default)]
    pub doc: Option<FunctionDoc>,
    pub found: bool,
    #[serde(default)]
    pub function: Option<crate::engine::FunctionInfo>,
    #[serde(default)]
    pub high: Option<HighFunction>,
    #[serde(default)]
    pub instructions: Option<Bounded<DetailInstruction>>,
    #[serde(default)]
    pub labels: Option<Bounded<Label>>,
    #[serde(default)]
    pub locals: Option<Bounded<VariableRow>>,
    #[serde(rename = "match")]
    pub matched_via: String,
    #[serde(default)]
    pub parameters: Option<Bounded<VariableRow>>,
    #[serde(default)]
    pub pcode_ops_retained: u64,
    #[serde(default)]
    pub pcode_ops_total: u64,
    #[serde(default)]
    pub plate_comment: String,
    #[serde(default)]
    pub plate_comment_truncated: bool,
    pub query: String,
    #[serde(default)]
    pub references_to: Option<Bounded<RefTo>>,
    #[serde(default)]
    pub strings_referenced: Option<Bounded<StringReference>>,
}

#[derive(Debug, Deserialize)]
pub struct DetailInstruction {
    pub address: String,
    pub bytes: String,
    pub fallthrough: String,
    pub flow_type: String,
    pub flows: Vec<String>,
    pub mnemonic: String,
    pub pcode: Vec<RawPcodeOp>,
    pub references_from: Vec<RefFrom>,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct Disassembly {
    #[serde(default)]
    pub consumed: u64,
    #[serde(default)]
    pub in_memory: bool,
    #[serde(default)]
    pub instructions: Vec<PseudoInstruction>,
    pub query: String,
    #[serde(default)]
    pub requested_length: u64,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub stopped: String,
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct EntryPoint {
    pub address: String,
    pub is_function: bool,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Deserialize)]
pub struct ExternalLocation {
    pub address: String,
    pub external_address: String,
    pub is_function: bool,
    pub label: String,
    pub library: String,
    pub library_path: String,
    pub original_name: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct FunctionDoc {
    pub address: String,
    pub body_size: u64,
    pub classification: String,
    pub comment_addresses: u64,
    pub default_named_parameters: u64,
    pub local_count: u64,
    pub name: String,
    pub name_source: String,
    pub parameter_count: u64,
    pub plate_comment: bool,
    pub repeatable_comment: bool,
    pub return_type: String,
    pub signature: String,
    pub signature_source: String,
    pub tags: Vec<String>,
    pub undefined_typed_variables: u64,
}

#[derive(Debug, Deserialize)]
pub struct FunctionRef {
    pub address: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct FunctionRefClassified {
    pub address: String,
    pub classification: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct FunctionTag {
    pub comment: String,
    pub name: String,
    pub use_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct HighFunction {
    pub available: bool,
    #[serde(default)]
    pub ops: Option<Bounded<HighOp>>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub symbols: Option<Bounded<HighSymbol>>,
}

#[derive(Debug, Deserialize)]
pub struct HighOp {
    pub address: String,
    pub inputs: Vec<Option<VarnodeRow>>,
    pub op: String,
    pub output: Option<VarnodeRow>,
    pub time: u64,
}

#[derive(Debug, Deserialize)]
pub struct HighSymbol {
    pub name: String,
    pub parameter: bool,
    pub storage: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct InstructionMatch {
    pub address: String,
    pub function: String,
    pub mnemonic: String,
    pub term: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct InstructionSearch {
    pub instructions_total: u64,
    pub matches: Bounded<InstructionMatch>,
    pub scan_capped: bool,
    pub scanned: u64,
    pub terms: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Label {
    pub address: String,
    pub name: String,
    pub primary: bool,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct Namespace {
    pub full_name: String,
    pub member_count: u64,
    pub name: String,
    pub parent: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct OptionGroup {
    pub name: String,
    pub option_count: u64,
}

#[derive(Debug, Deserialize)]
pub struct OptionRow {
    pub group: String,
    pub is_default: bool,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
    pub value_readable: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProgramFacts {
    pub analysis: Analysis,
    pub analyzers: Bounded<Analyzer>,
    pub bookmarks: Bounded<Bookmark>,
    pub calling_conventions: Vec<CallingConvention>,
    pub class_members: Bounded<ClassMember>,
    pub code_gaps: Bounded<CodeGap>,
    pub comments: Bounded<Comment>,
    pub data_items: Bounded<DataItem>,
    pub entry_points: Bounded<EntryPoint>,
    pub external_locations: Bounded<ExternalLocation>,
    pub function_docs: Bounded<FunctionDoc>,
    pub function_tags: Bounded<FunctionTag>,
    pub namespaces: Bounded<Namespace>,
    pub option_groups: Bounded<OptionGroup>,
    pub options: Bounded<OptionRow>,
    pub project: ProjectFacts,
    pub properties: Bounded<PropertyRow>,
    pub property_maps: Bounded<PropertyMap>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectFacts {
    pub available: bool,
    pub files: Bounded<ProjectFile>,
    pub folders: Bounded<ProjectFolder>,
    pub name: String,
    pub program_path: String,
}

#[derive(Debug, Deserialize)]
pub struct ProjectFile {
    pub content_type: String,
    pub path: String,
    pub read_only: bool,
    pub version: i64,
}

#[derive(Debug, Deserialize)]
pub struct ProjectFolder {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct PropertyMap {
    pub name: String,
    pub size: u64,
    pub value_class: String,
}

#[derive(Debug, Deserialize)]
pub struct PropertyRow {
    pub address: String,
    pub map: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct PseudoInstruction {
    pub address: String,
    pub bytes: String,
    pub length: u64,
    pub listing_instruction: bool,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct RawPcodeOp {
    pub inputs: Vec<String>,
    pub op: String,
    pub output: String,
}

#[derive(Debug, Deserialize)]
pub struct RefFrom {
    pub to: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct RefTo {
    pub from: String,
    pub from_function: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Deserialize)]
pub struct StringReference {
    pub address: String,
    pub from: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct Types {
    pub builtins: Bounded<BuiltinType>,
    pub categories: Bounded<Category>,
    pub data_types: Bounded<DataTypeRow>,
    pub pointer_size: u64,
}

#[derive(Debug, Deserialize)]
pub struct VariableRow {
    pub first_use_offset: i64,
    pub name: String,
    pub ordinal: i64,
    pub source: String,
    pub storage: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub type_length: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VarnodeRow {
    pub constant: bool,
    pub high: String,
    pub id: i64,
    pub offset: i64,
    pub size: u64,
    pub space: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_section_with_more_rows_than_total_is_rejected() {
        let section: Bounded<ContextRow> = serde_json::from_str(
            r#"{"rows":[{"address":"1000","text":"RET"}],"total":0,"truncated":false}"#,
        )
        .unwrap();
        let error = section.check("context").unwrap_err();
        assert_eq!(error.code, ErrorCode::EvidenceIntegrityMismatch);
    }

    #[test]
    fn adversarial_truncation_is_derived_from_counts_not_the_flag() {
        // A poisoned flag that hides dropped rows is overruled.
        let section: Bounded<ContextRow> = serde_json::from_str(
            r#"{"rows":[{"address":"1000","text":"RET"}],"total":5,"truncated":false}"#,
        )
        .unwrap();
        assert!(section.is_partial());
        assert!(section.check("context").is_ok());
    }

    #[test]
    fn validation_complete_section_is_not_partial() {
        let section: Bounded<ContextRow> = serde_json::from_str(
            r#"{"rows":[{"address":"1000","text":"RET"}],"total":1,"truncated":false}"#,
        )
        .unwrap();
        assert!(!section.is_partial());
    }
}
