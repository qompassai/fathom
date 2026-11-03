//! Unity MonoBehaviour field expansion (BQ-2): reconstruct
//! each MonoScript class's serialized field layout from the
//! title's Managed DLLs (ECMA-335 metadata, read by
//! `fathom_managed::schema`) and decode every MonoBehaviour
//! payload against its class layout into named field values.
//!
//! The census rung counts MonoBehaviours without reading
//! their script data (shipped builds carry no type trees);
//! this module is the reader that replaces the missing trees.
//! The serialization rules are corpus-derived and were proven
//! by exact byte consumption against an independent prototype
//! decoder before this port existed:
//!
//! - a field is serialized iff it is not static / literal /
//!   NotSerialized, carries no [NonSerialized], and is public
//!   or [SerializeField] or [SerializeReference]; fields of
//!   structs in `UnityEngine.*` assemblies serialize
//!   regardless of access (native-backed value types);
//! - base-class fields come first, root first, stopping
//!   below UnityEngine.MonoBehaviour (the fixed header the
//!   census already consumes); generic bases carry a VAR
//!   substitution into the base definition's fields;
//! - bool is a 4-byte 0/1 value; a byte field of a reference
//!   type occupies a 4-byte slot; inside value types bytes
//!   pack; a PPtr is 12 bytes (i32 file, i64 path, the i64
//!   not 8-aligned); strings and arrays align the stream to
//!   4 after their variable-length data; alignment is
//!   min(natural, 4) throughout;
//! - [SerializeReference] fields carry only i64 reference
//!   ids in the field stream; the referenced objects live in
//!   a block at the end of the root object (i32 marker 2,
//!   i32 count, then per entry an i64 id, three aligned
//!   type-name strings, and the object's field data against
//!   the named concrete class);
//! - types whose serialized form is written by Unity's
//!   native side (their managed class carries only an m_Ptr)
//!   are refused by name unless a corpus-derived layout
//!   below reconstructs them; a native-backed type with a
//!   corpus-proven fixed size but no derivable decomposition
//!   (Gradient) decodes as a named opaque blob, so a
//!   differently-sized instance refuses by mismatch.
//!
//! Exact consumption is the law: a decoder that does not
//! consume exactly the payload byte count refuses the
//! object by naming the construct — never a partial decode,
//! never a silent drop. Canonical value encoding (shared
//! with the prototype so per-object digests compare
//! exactly): bool is a JSON bool; char is its code point;
//! floats are `{"@r4": hex}` / `{"@r8": hex}` IEEE-bit
//! strings; a PPtr is `{"@pptr": [file, path]}`; a managed
//! reference is `{"@ref": {assembly, data, type}}`; a raw
//! field is `{"@raw": hex}`; an opaque blob is
//! `{"@opaque": type, "len": n, "hex": hex}`.

use serde_json::{Map, Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex};
use fathom_core::limits::{ARCHIVE_TARGET_BYTES_MAX, UNITY_MB_FILES_MAX, UNITY_MB_OBJECTS_MAX};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use fathom_managed::schema::{
    AssemblySchema, SigKind, SigType, TypeToken, parse_field_signature, parse_schema, parse_type,
};

use crate::unity::{
    CLASS_MONO_BEHAVIOUR, CLASS_MONO_SCRIPT, MbSource, MbSourceLoad, ScriptIdentity,
    bundle_serialized_nodes, parse_mb_header, parse_mono_script, parse_serialized_file_capped,
    parse_sf_externals, payload_slice, walk_mb_candidates,
};

/// Decoded objects whose full values are retained in the
/// expansion record (digests are computed for every decoded
/// object regardless).
const DECODED_VALUES_RETAINED_MAX: usize = 4096;
/// Per-object rows retained in the expansion record; counts
/// stay exact past the cap, the omission is named.
const OBJECT_ROWS_RETAINED_MAX: usize = 100_000;
/// Tree rows flatten to this depth at most (a recursive
/// class would otherwise flatten forever; decoding itself
/// is bounded by payload bytes, not by this cap).
const TREE_FLATTEN_DEPTH_MAX: usize = 32;
/// VALUES the decoder bounds (mirroring the prototype):
/// nesting depth, array element count, string byte count,
/// and managed-reference entry count.
const DECODE_DEPTH_MAX: usize = 64;
const ARRAY_COUNT_MAX: i32 = 1_000_000;
const REF_ENTRY_COUNT_MAX: i32 = 100_000;
const STRING_BYTES_MAX: i32 = 16 * 1024 * 1024;
/// Layout-builder recursion bound (generic chains and
/// nested class expansion).
const TYPE_DEPTH_MAX: i32 = 24;

/// ECMA-335 table ids this module addresses directly.
const TABLE_FIELD: usize = 4;
const TABLE_TYPE_DEF: usize = 2;
const TABLE_TYPE_REF: usize = 1;
const TABLE_TYPE_SPEC: usize = 27;

/// Field attribute flags (ECMA-335 II.23.1.5).
const FIELD_ACCESS_MASK: u16 = 0x0007;
const FIELD_PUBLIC: u16 = 0x0006;
const FIELD_LITERAL: u16 = 0x0040;
const FIELD_NOT_SERIALIZED: u16 = 0x0080;
const FIELD_STATIC: u16 = 0x0010;
/// TypeDef flags (ECMA-335 II.23.1.15).
const TYPE_EXPLICIT_LAYOUT: u32 = 0x10;
const TYPE_INTERFACE: u32 = 0x20;
const TYPE_LAYOUT_MASK: u32 = 0x18;

/// Chain levels whose fields are the fixed MonoBehaviour
/// header, already consumed before expansion starts.
const HEADER_TYPES: [&str; 4] = ["Behaviour", "Component", "MonoBehaviour", "Object"];
/// Assemblies whose types Unity never serializes from
/// managed declarations.
const FRAMEWORK_PREFIXES: [&str; 4] = ["Microsoft", "System", "mscorlib", "netstandard"];

/// One named refusal: the construct that could not be
/// decoded, with a detail string. Layout construction and
/// payload decoding share the type; a refusal is a counted
/// fact in the expansion record, never a silent drop.
#[derive(Clone, Debug)]
struct ExpandError {
    construct: &'static str,
    detail: String,
}

type XResult<T> = Result<T, ExpandError>;

fn refusal(construct: &'static str, detail: impl Into<String>) -> ExpandError {
    ExpandError {
        construct,
        detail: detail.into(),
    }
}

impl ExpandError {
    /// The prototype's rendering: `construct: detail`,
    /// truncated by the caller where the prototype truncated.
    fn render(&self) -> String {
        format!("{}: {}", self.construct, self.detail)
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn align_up(offset: i64, align: i64) -> i64 {
    if align <= 1 {
        return offset;
    }
    (offset + align - 1) / align * align
}

fn type_display(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xF) as usize] as char);
    }
    out
}

/// Primitive leaf facts by ECMA signature name: (tree type
/// name, byte size, alignment). bool is a 4-byte 0/1 value
/// in this serialization (corpus-proven).
fn prim_info(name: &str) -> Option<(&'static str, i64, i64)> {
    Some(match name {
        "bool" => ("bool", 4, 4),
        "char" => ("UInt16", 2, 2),
        "i1" => ("SInt8", 1, 1),
        "i2" => ("SInt16", 2, 2),
        "i4" => ("int", 4, 4),
        "i8" => ("SInt64", 8, 4),
        "r4" => ("float", 4, 4),
        "r8" => ("double", 8, 4),
        "u1" => ("UInt8", 1, 1),
        "u2" => ("UInt16", 2, 2),
        "u4" => ("unsigned int", 4, 4),
        "u8" => ("UInt64", 8, 4),
        _ => return None,
    })
}

/// A generic substitution: (is method-var, index) -> type.
/// Signature tokens stay assembly-relative through
/// substitution, exactly as parsed.
type Subst = BTreeMap<(bool, u32), SigType>;

fn substitute(sig: &SigType, subst: &Subst) -> SigType {
    match &sig.kind {
        SigKind::Array { elem, rank } => SigType {
            assembly: sig.assembly,
            kind: SigKind::Array {
                elem: Box::new(substitute(elem, subst)),
                rank: *rank,
            },
        },
        SigKind::ByRef(elem) => SigType {
            assembly: sig.assembly,
            kind: SigKind::ByRef(Box::new(substitute(elem, subst))),
        },
        SigKind::GenericInst { args, base } => SigType {
            assembly: sig.assembly,
            kind: SigKind::GenericInst {
                args: args.iter().map(|arg| substitute(arg, subst)).collect(),
                base: base.clone(),
            },
        },
        SigKind::MVar(index) => subst
            .get(&(true, *index))
            .cloned()
            .unwrap_or_else(|| sig.clone()),
        SigKind::Ptr(elem) => SigType {
            assembly: sig.assembly,
            kind: SigKind::Ptr(Box::new(substitute(elem, subst))),
        },
        SigKind::SzArray(elem) => SigType {
            assembly: sig.assembly,
            kind: SigKind::SzArray(Box::new(substitute(elem, subst))),
        },
        SigKind::Var(index) => subst
            .get(&(false, *index))
            .cloned()
            .unwrap_or_else(|| sig.clone()),
        _ => sig.clone(),
    }
}

/// The class a class node expands: assembly index, TypeDef
/// index (row id - 1), and the generic substitution the
/// node was reached with, if any.
#[derive(Clone)]
struct ClassRef {
    assembly: usize,
    subst: Option<Subst>,
    typedef: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum NodeKind {
    Array,
    Class,
    Enum,
    Explicit,
    Opaque,
    PPtr,
    Prim,
    Raw,
    Ref,
    RefArray,
    String,
}

impl NodeKind {
    fn as_str(self) -> &'static str {
        match self {
            NodeKind::Array => "array",
            NodeKind::Class => "class",
            NodeKind::Enum => "enum",
            NodeKind::Explicit => "explicit",
            NodeKind::Opaque => "opaque",
            NodeKind::PPtr => "pptr",
            NodeKind::Prim => "prim",
            NodeKind::Raw => "raw",
            NodeKind::Ref => "ref",
            NodeKind::RefArray => "refarray",
            NodeKind::String => "string",
        }
    }
}

/// One node of a reconstructed type tree. Class fields
/// resolve lazily (memoized through `resolved`) so
/// recursive types terminate in the layout, and the
/// decoder's payload depth bounds their expansion.
struct Node {
    align: Cell<i64>,
    class_ref: Option<ClassRef>,
    elem: Option<Rc<Node>>,
    kind: NodeKind,
    members: Vec<(u32, FieldLayout)>,
    prim: Option<&'static str>,
    resolved: RefCell<Option<Rc<Vec<FieldLayout>>>>,
    size: Cell<i64>,
    type_name: String,
    underlying: Option<&'static str>,
}

impl Node {
    fn new(type_name: String, kind: NodeKind, size: i64, align: i64) -> Node {
        Node {
            align: Cell::new(align),
            class_ref: None,
            elem: None,
            kind,
            members: Vec::new(),
            prim: None,
            resolved: RefCell::new(None),
            size: Cell::new(size),
            type_name,
            underlying: None,
        }
    }

    fn prim(type_name: &'static str, prim: &'static str, size: i64, align: i64) -> Node {
        let mut node = Node::new(type_name.to_string(), NodeKind::Prim, size, align);
        node.prim = Some(prim);
        node
    }
}

#[derive(Clone)]
struct FieldLayout {
    name: String,
    node: Rc<Node>,
}

/// The fixed byte size of a field list: each field aligned
/// then sized, in order; -1 when any member is variable.
fn fixed_size(fields: &[FieldLayout]) -> i64 {
    let mut offset: i64 = 0;
    for field in fields {
        let size = field.node.size.get();
        if size < 0 {
            return -1;
        }
        offset = align_up(offset, field.node.align.get()) + size;
    }
    offset
}

/// A TypeDefOrRef token resolved against the whole Managed
/// set: a definition, an unresolved reference (named, with
/// its scope assembly), or a TypeSpec row.
enum Resolved {
    Def(usize, usize),
    Ref {
        name: String,
        namespace: String,
        scope: Option<String>,
    },
    TypeSpec(usize, usize),
}

/// All assemblies of one title's Managed set, cross-indexed.
/// Name lookup follows the prototype: a same-name assembly
/// later in file order wins `by_name`; a (namespace, name)
/// pair's first definition wins `global_types`.
struct TypeIndex {
    assemblies: Vec<AssemblySchema>,
    by_name: HashMap<String, usize>,
    global_types: HashMap<(String, String), (usize, usize)>,
}

impl TypeIndex {
    fn new(assemblies: Vec<AssemblySchema>) -> TypeIndex {
        let mut by_name = HashMap::new();
        let mut global_types = HashMap::new();
        for (asm_index, assembly) in assemblies.iter().enumerate() {
            if !assembly.name.is_empty() {
                by_name.insert(assembly.name.clone(), asm_index);
            }
            for (td_index, type_def) in assembly.type_defs.iter().enumerate() {
                if type_def.name == "<Module>" {
                    continue;
                }
                global_types
                    .entry((type_def.namespace.clone(), type_def.name.clone()))
                    .or_insert((asm_index, td_index));
            }
        }
        TypeIndex {
            assemblies,
            by_name,
            global_types,
        }
    }

    fn resolve_token(&self, asm_index: usize, token: TypeToken) -> Option<Resolved> {
        if token.row == 0 {
            return None;
        }
        let assembly = &self.assemblies[asm_index];
        match token.table {
            TABLE_TYPE_DEF => {
                if (1..=assembly.type_defs.len()).contains(&token.row) {
                    Some(Resolved::Def(asm_index, token.row - 1))
                } else {
                    None
                }
            }
            TABLE_TYPE_REF => {
                let type_ref = assembly.type_refs.get(token.row - 1)?;
                if let Some(hit) = self
                    .global_types
                    .get(&(type_ref.namespace.clone(), type_ref.name.clone()))
                {
                    return Some(Resolved::Def(hit.0, hit.1));
                }
                Some(Resolved::Ref {
                    name: type_ref.name.clone(),
                    namespace: type_ref.namespace.clone(),
                    scope: type_ref.scope_assembly.clone(),
                })
            }
            TABLE_TYPE_SPEC => Some(Resolved::TypeSpec(asm_index, token.row)),
            _ => None,
        }
    }

    fn extends_of(&self, asm_index: usize, td_index: usize) -> Option<Resolved> {
        let (table, row) = self.assemblies[asm_index].type_defs[td_index].extends?;
        self.resolve_token(
            asm_index,
            TypeToken {
                row,
                table,
            },
        )
    }

    /// Resolved bases in leaf-to-root order; the walk stops
    /// after the first base that is not a definition.
    fn walk_bases(&self, asm_index: usize, td_index: usize) -> Vec<Resolved> {
        let mut out = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let (mut cur_asm, mut cur_td) = (asm_index, td_index);
        loop {
            if !seen.insert((cur_asm, cur_td)) {
                return out;
            }
            let Some(base) = self.extends_of(cur_asm, cur_td) else {
                return out;
            };
            let next = match &base {
                Resolved::Def(next_asm, next_td) => Some((*next_asm, *next_td)),
                _ => None,
            };
            out.push(base);
            let Some((next_asm, next_td)) = next else {
                return out;
            };
            cur_asm = next_asm;
            cur_td = next_td;
        }
    }

    fn reaches_type(
        &self,
        asm_index: usize,
        td_index: usize,
        namespace: &str,
        name: &str,
    ) -> bool {
        let type_def = &self.assemblies[asm_index].type_defs[td_index];
        if type_def.namespace == namespace && type_def.name == name {
            return true;
        }
        for base in self.walk_bases(asm_index, td_index) {
            match base {
                Resolved::Def(base_asm, base_td) => {
                    let base_def = &self.assemblies[base_asm].type_defs[base_td];
                    if base_def.namespace == namespace && base_def.name == name {
                        return true;
                    }
                }
                Resolved::Ref {
                    name: ref_name,
                    namespace: ref_namespace,
                    ..
                } => return ref_namespace == namespace && ref_name == name,
                Resolved::TypeSpec(..) => return false,
            }
        }
        false
    }

    fn base_is_named(
        &self,
        asm_index: usize,
        td_index: usize,
        namespace: &str,
        name: &str,
    ) -> bool {
        match self.extends_of(asm_index, td_index) {
            Some(Resolved::Def(base_asm, base_td)) => {
                let base_def = &self.assemblies[base_asm].type_defs[base_td];
                base_def.namespace == namespace && base_def.name == name
            }
            Some(Resolved::Ref {
                name: ref_name,
                namespace: ref_namespace,
                ..
            }) => ref_namespace == namespace && ref_name == name,
            _ => false,
        }
    }

    fn is_delegate(&self, asm_index: usize, td_index: usize) -> bool {
        self.reaches_type(asm_index, td_index, "System", "MulticastDelegate")
    }

    fn is_enum(&self, asm_index: usize, td_index: usize) -> bool {
        self.base_is_named(asm_index, td_index, "System", "Enum")
    }

    fn is_object_derived(&self, asm_index: usize, td_index: usize) -> bool {
        self.reaches_type(asm_index, td_index, "UnityEngine", "Object")
    }

    fn is_struct(&self, asm_index: usize, td_index: usize) -> bool {
        self.base_is_named(asm_index, td_index, "System", "ValueType")
    }
}

/// One native-layout field spec: the serialized shape of a
/// type whose stream layout is Unity's own, corpus-derived.
enum NativeSpec {
    Array(&'static NativeSpec),
    Prim(&'static str),
    Raw(i64),
    Str,
    Type(&'static str, &'static str),
}

static KEYFRAME_SPEC: NativeSpec = NativeSpec::Type("UnityEngine", "Keyframe");
static ANIMATION_CURVE_FIELDS: &[(&str, NativeSpec)] = &[
    ("m_Curve", NativeSpec::Array(&KEYFRAME_SPEC)),
    ("m_PreInfinity", NativeSpec::Prim("i4")),
    ("m_PostInfinity", NativeSpec::Prim("i4")),
    ("m_RotationOrder", NativeSpec::Prim("i4")),
];
static GUI_SETTINGS_FIELDS: &[(&str, NativeSpec)] = &[
    ("m_DoubleClickSelectsWord", NativeSpec::Prim("bool")),
    ("m_TripleClickSelectsLine", NativeSpec::Prim("bool")),
    ("m_CursorColor", NativeSpec::Type("UnityEngine", "Color")),
    ("m_CursorFlashSpeed", NativeSpec::Prim("r4")),
    ("m_SelectionColor", NativeSpec::Type("UnityEngine", "Color")),
];
static GUI_STYLE_FIELDS: &[(&str, NativeSpec)] = &[
    ("m_Name", NativeSpec::Str),
    ("m_Normal", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_Hover", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_Active", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_Focused", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_OnNormal", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_OnHover", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_OnActive", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_OnFocused", NativeSpec::Type("UnityEngine", "GUIStyleState")),
    ("m_Border", NativeSpec::Type("UnityEngine", "RectOffset")),
    ("m_Padding", NativeSpec::Type("UnityEngine", "RectOffset")),
    ("m_Margin", NativeSpec::Type("UnityEngine", "RectOffset")),
    ("m_Overflow", NativeSpec::Type("UnityEngine", "RectOffset")),
    ("m_Font", NativeSpec::Type("UnityEngine", "Font")),
    // The remaining 44 bytes (image position, alignment,
    // wrap/clipping flags, content offset, fixed size, font
    // size/style, rich text, stretch flags) are size-proven
    // but their per-field attribution resisted derivation
    // from the default skin's near-uniform values; they are
    // carried as a named raw field rather than guessed names.
    ("m_NativeTail", NativeSpec::Raw(44)),
];
static GUI_STYLE_STATE_FIELDS: &[(&str, NativeSpec)] = &[
    ("m_Background", NativeSpec::Type("UnityEngine", "Texture2D")),
    ("m_TextColor", NativeSpec::Type("UnityEngine", "Color")),
];
static RECT_OFFSET_FIELDS: &[(&str, NativeSpec)] = &[
    ("m_Left", NativeSpec::Prim("i4")),
    ("m_Right", NativeSpec::Prim("i4")),
    ("m_Top", NativeSpec::Prim("i4")),
    ("m_Bottom", NativeSpec::Prim("i4")),
];

/// Types whose serialized form is written by Unity's native
/// side and does not match their managed field declarations
/// (the managed class only carries an IntPtr). Layouts here
/// are corpus-observed: field names follow the managed
/// property surface; order and sizes are proven by exact
/// consumption.
fn native_layout(namespace: &str, name: &str) -> Option<&'static [(&'static str, NativeSpec)]> {
    match (namespace, name) {
        ("UnityEngine", "AnimationCurve") => Some(ANIMATION_CURVE_FIELDS),
        ("UnityEngine", "GUISettings") => Some(GUI_SETTINGS_FIELDS),
        ("UnityEngine", "GUIStyle") => Some(GUI_STYLE_FIELDS),
        ("UnityEngine", "GUIStyleState") => Some(GUI_STYLE_STATE_FIELDS),
        ("UnityEngine", "RectOffset") => Some(RECT_OFFSET_FIELDS),
        _ => None,
    }
}

/// Native-backed types whose serialized size is fixed and
/// corpus-proven across every observed instance, but whose
/// internal field decomposition resisted derivation. They
/// decode as opaque blobs of exactly this size; any
/// instance of a different size refuses by consumption
/// mismatch, so the claim stays falsifiable.
fn opaque_layout(namespace: &str, name: &str) -> Option<i64> {
    match (namespace, name) {
        ("UnityEngine", "Gradient") => Some(164),
        _ => None,
    }
}

/// Builds per-class serialized layouts over a `TypeIndex`.
/// Field lists are cached per definition (failures too, so
/// a refused class refuses identically everywhere).
struct LayoutBuilder<'a> {
    class_cache:
        RefCell<HashMap<(usize, usize), XResult<(Rc<Vec<FieldLayout>>, Rc<Vec<(String, String)>>)>>>,
    depth: Cell<i32>,
    index: &'a TypeIndex,
}

impl<'a> LayoutBuilder<'a> {
    fn new(index: &'a TypeIndex) -> LayoutBuilder<'a> {
        LayoutBuilder {
            class_cache: RefCell::new(HashMap::new()),
            depth: Cell::new(0),
            index,
        }
    }

    fn assembly(&self, asm_index: usize) -> &'a AssemblySchema {
        &self.index.assemblies[asm_index]
    }

    fn has_attr(&self, asm_index: usize, table: usize, row: usize, full_name: &str) -> bool {
        self.assembly(asm_index)
            .attributes
            .get(&(table, row))
            .is_some_and(|names| names.iter().any(|name| name == full_name))
    }

    /// Corpus rule: [Serializable] is nearly absent even on
    /// types Unity plainly serializes. What Unity does not
    /// serialize is framework runtime types, so everything
    /// outside framework assemblies expands.
    fn is_serializable_type(&self, asm_index: usize, _td_index: usize) -> bool {
        let name = &self.assembly(asm_index).name;
        !FRAMEWORK_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
    }

    /// Whether one field is serialized, and if not, the
    /// recorded reason. Check order mirrors the prototype.
    fn field_serialized(
        &self,
        asm_index: usize,
        field_row: usize,
        flags: u16,
        in_struct: bool,
    ) -> Result<(), &'static str> {
        if flags & FIELD_STATIC != 0 {
            return Err("static field");
        }
        if flags & FIELD_LITERAL != 0 {
            return Err("literal field");
        }
        if flags & FIELD_NOT_SERIALIZED != 0 {
            return Err("NotSerialized field flag");
        }
        if self.has_attr(
            asm_index,
            TABLE_FIELD,
            field_row,
            "System.NonSerializedAttribute",
        ) {
            return Err("[NonSerialized]");
        }
        if in_struct && self.assembly(asm_index).name.starts_with("UnityEngine.") {
            // Corpus rule, engine assemblies only: fields of
            // a native-backed value type are written
            // regardless of access or [SerializeField]
            // (LayerMask.m_Mask is private, unmarked,
            // serialized). Managed structs in package/user
            // assemblies follow the ordinary rule.
            return Ok(());
        }
        if self.has_attr(
            asm_index,
            TABLE_FIELD,
            field_row,
            "UnityEngine.SerializeReference",
        ) {
            // Corpus rule: [SerializeReference] alone implies
            // the field is serialized, even private without
            // [SerializeField].
            return Ok(());
        }
        if flags & FIELD_ACCESS_MASK != FIELD_PUBLIC
            && !self.has_attr(
                asm_index,
                TABLE_FIELD,
                field_row,
                "UnityEngine.SerializeField",
            )
        {
            return Err("non-public without [SerializeField]");
        }
        Ok(())
    }

    /// The inheritance chain of one definition, root first,
    /// each level carrying the generic substitution it was
    /// reached with. Header types are included; the caller
    /// skips them.
    fn chain_with_subst(
        &self,
        asm_index: usize,
        td_index: usize,
        subst: Option<&Subst>,
    ) -> XResult<Vec<(usize, usize, Option<Subst>)>> {
        let mut levels: Vec<(usize, usize, Option<Subst>)> = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();
        let (mut cur_asm, mut cur_td, mut cur_subst) = (asm_index, td_index, subst.cloned());
        loop {
            if !seen.insert((cur_asm, cur_td)) {
                break;
            }
            levels.push((cur_asm, cur_td, cur_subst.clone()));
            let Some(base) = self.index.extends_of(cur_asm, cur_td) else {
                break;
            };
            match base {
                Resolved::Def(base_asm, base_td) => {
                    cur_asm = base_asm;
                    cur_td = base_td;
                    cur_subst = None;
                }
                Resolved::Ref { .. } => break,
                Resolved::TypeSpec(spec_asm, spec_row) => {
                    let blob = self
                        .assembly(spec_asm)
                        .type_specs
                        .get(spec_row - 1)
                        .cloned()
                        .unwrap_or_default();
                    let (gsig, _) = parse_type(&blob, 0, spec_asm).map_err(|error| {
                        refusal("base typespec undecodable", error.message.clone())
                    })?;
                    let SigKind::GenericInst { args, base } = &gsig.kind else {
                        break;
                    };
                    let (base_asm_tok, base_token) = match &base.kind {
                        SigKind::Class(token) | SigKind::ValueType(token) => {
                            (base.assembly, *token)
                        }
                        _ => break,
                    };
                    let Some(Resolved::Def(next_asm, next_td)) =
                        self.index.resolve_token(base_asm_tok, base_token)
                    else {
                        return Err(refusal("generic base unresolved", ""));
                    };
                    let outer: Subst = cur_subst.clone().unwrap_or_default();
                    let mut new_subst: Subst = BTreeMap::new();
                    for (i, arg) in args.iter().enumerate() {
                        new_subst.insert((false, u32::try_from(i).unwrap_or(u32::MAX)), substitute(arg, &outer));
                    }
                    cur_asm = next_asm;
                    cur_td = next_td;
                    cur_subst = Some(new_subst);
                }
            }
        }
        levels.reverse();
        Ok(levels)
    }

    fn native_node(&self, spec: &NativeSpec, field_name: &str) -> XResult<Node> {
        match spec {
            NativeSpec::Array(elem) => {
                let elem_node = self.native_node(elem, field_name)?;
                let mut node = Node::new("Array".to_string(), NodeKind::Array, -1, 4);
                node.elem = Some(Rc::new(elem_node));
                Ok(node)
            }
            NativeSpec::Prim(prim) => {
                let (type_name, size, align) =
                    prim_info(prim).ok_or_else(|| refusal("native layout spec unhandled", *prim))?;
                Ok(Node::prim(type_name, prim, size, align))
            }
            NativeSpec::Raw(size) => Ok(Node::new("raw".to_string(), NodeKind::Raw, *size, 4)),
            NativeSpec::Str => Ok(Node::new("string".to_string(), NodeKind::String, -1, 4)),
            NativeSpec::Type(namespace, name) => {
                let display = type_display(namespace, name);
                let Some(&(hit_asm, hit_td)) = self.index.global_types.get(&(
                    (*namespace).to_string(),
                    (*name).to_string(),
                )) else {
                    return Err(refusal("native layout type unresolved", display));
                };
                self.node_for_class(hit_asm, hit_td, field_name, None, None)?
                    .ok_or_else(|| refusal("native layout type not serialized", display))
            }
        }
    }

    fn native_fields(
        &self,
        asm_index: usize,
        td_index: usize,
    ) -> XResult<Option<Vec<FieldLayout>>> {
        let type_def = &self.assembly(asm_index).type_defs[td_index];
        let Some(spec) = native_layout(&type_def.namespace, &type_def.name) else {
            return Ok(None);
        };
        let mut fields = Vec::new();
        for (field_name, field_spec) in spec {
            fields.push(FieldLayout {
                name: (*field_name).to_string(),
                node: Rc::new(self.native_node(field_spec, field_name)?),
            });
        }
        Ok(Some(fields))
    }

    /// The serialized fields of one class definition (with
    /// the generic substitution it was reached with), plus
    /// the skipped fields and their reasons.
    fn class_fields(
        &self,
        asm_index: usize,
        td_index: usize,
        subst: Option<&Subst>,
    ) -> XResult<(Rc<Vec<FieldLayout>>, Rc<Vec<(String, String)>>)> {
        let cacheable = subst.is_none();
        if cacheable {
            if let Some(cached) = self.class_cache.borrow().get(&(asm_index, td_index)) {
                return cached.clone();
            }
        }
        self.depth.set(self.depth.get() + 1);
        if self.depth.get() > TYPE_DEPTH_MAX {
            self.depth.set(self.depth.get() - 1);
            return Err(refusal("type recursion over depth bound", ""));
        }
        let result = self.class_fields_inner(asm_index, td_index, subst);
        self.depth.set(self.depth.get() - 1);
        if cacheable {
            self.class_cache
                .borrow_mut()
                .insert((asm_index, td_index), result.clone());
        }
        result
    }

    fn class_fields_inner(
        &self,
        asm_index: usize,
        td_index: usize,
        subst: Option<&Subst>,
    ) -> XResult<(Rc<Vec<FieldLayout>>, Rc<Vec<(String, String)>>)> {
        if let Some(native) = self.native_fields(asm_index, td_index)? {
            return Ok((Rc::new(native), Rc::new(Vec::new())));
        }
        let mut fields: Vec<FieldLayout> = Vec::new();
        let mut skipped: Vec<(String, String)> = Vec::new();
        let mut leaf_stat: Option<(usize, usize, bool)> = None;
        for (level_asm, level_td, level_subst) in
            self.chain_with_subst(asm_index, td_index, subst)?
        {
            let level_def = &self.assembly(level_asm).type_defs[level_td];
            if level_def.namespace == "UnityEngine" && HEADER_TYPES.contains(&level_def.name.as_str()) {
                continue;
            }
            let in_struct = self.index.is_struct(level_asm, level_td);
            let level_start = fields.len();
            let mut level_own = 0usize;
            let mut level_ptr = false;
            for field_row in level_def.field_begin..level_def.field_end {
                let field = &self.assembly(level_asm).fields[field_row - 1];
                if field.flags & FIELD_STATIC != 0 {
                    continue;
                }
                level_own += 1;
                if field.name == "m_Ptr" {
                    level_ptr = true;
                }
            }
            for field_row in level_def.field_begin..level_def.field_end {
                let field = &self.assembly(level_asm).fields[field_row - 1];
                let mut sig =
                    parse_field_signature(&field.signature, level_asm).map_err(|error| {
                        refusal(
                            "field signature undecodable",
                            format!("{}: {}", field.name, error.message),
                        )
                    })?;
                if let Some(level_subst) = &level_subst {
                    sig = substitute(&sig, level_subst);
                }
                if let Err(reason) =
                    self.field_serialized(level_asm, field_row, field.flags, in_struct)
                {
                    skipped.push((field.name.clone(), reason.to_string()));
                    continue;
                }
                if self.has_attr(
                    level_asm,
                    TABLE_FIELD,
                    field_row,
                    "UnityEngine.SerializeReference",
                ) {
                    // [SerializeReference]: the field stream
                    // carries only i64 reference ids; the
                    // objects live in a block at the end of
                    // the root object. The static type may be
                    // an interface, so the node is built from
                    // the signature shape alone; the concrete
                    // class comes from the block entry.
                    fields.push(FieldLayout {
                        name: field.name.clone(),
                        node: Rc::new(self.ref_node(&sig, &field.name)?),
                    });
                    continue;
                }
                let Some(node) = self.node_for_type(level_asm, &sig, &field.name)? else {
                    skipped.push((
                        field.name.clone(),
                        "field type not serialized by Unity".to_string(),
                    ));
                    continue;
                };
                if !in_struct && node.kind == NodeKind::Prim && matches!(node.prim, Some("u1" | "i1")) {
                    // Corpus rule (TMP_FontAsset.italicStyle /
                    // tabSize, two fonts agreeing): a byte
                    // field of a reference type occupies a
                    // 4-byte slot, like bool. Inside value
                    // types bytes pack.
                    node.size.set(4);
                    node.align.set(4);
                }
                fields.push(FieldLayout {
                    name: field.name.clone(),
                    node: Rc::new(node),
                });
            }
            if level_asm == asm_index && level_td == td_index {
                leaf_stat = Some((level_own, fields.len() - level_start, level_ptr));
            }
        }
        if let Some((own, serialized, has_ptr)) = leaf_stat {
            if own > 0 && serialized == 0 && has_ptr {
                // Native-backed type: the managed declaration
                // carries only the m_Ptr handle and
                // NotSerialized mirrors; the stream layout is
                // the engine's own and has not been
                // reconstructed. Refuse by name, do not guess.
                let leaf = &self.assembly(asm_index).type_defs[td_index];
                return Err(refusal(
                    "native-serialized type without managed layout",
                    type_display(&leaf.namespace, &leaf.name),
                ));
            }
        }
        Ok((Rc::new(fields), Rc::new(skipped)))
    }

    fn node_for_type(
        &self,
        asm_index: usize,
        sig: &SigType,
        field_name: &str,
    ) -> XResult<Option<Node>> {
        match &sig.kind {
            SigKind::Array { .. } | SigKind::ByRef(_) | SigKind::Ptr(_) => Ok(None),
            SigKind::Class(token) | SigKind::ValueType(token) => {
                match self.index.resolve_token(sig.assembly, *token) {
                    None => Err(refusal("unresolved type token", field_name)),
                    Some(Resolved::Def(def_asm, def_td)) => {
                        self.node_for_class(def_asm, def_td, field_name, None, None)
                    }
                    Some(Resolved::Ref {
                        name,
                        namespace,
                        ..
                    }) => Err(refusal(
                        "unresolved type reference",
                        format!("{} ({field_name})", type_display(&namespace, &name)),
                    )),
                    Some(Resolved::TypeSpec(..)) => {
                        Err(refusal("typespec type token", field_name))
                    }
                }
            }
            SigKind::GenericInst { .. } => self.node_for_genericinst(asm_index, sig, field_name),
            SigKind::MVar(_) | SigKind::Var(_) => {
                Err(refusal("unsubstituted generic parameter", field_name))
            }
            SigKind::Prim(name) => match *name {
                "object" | "void" | "i" | "u" => Ok(None),
                "string" => Ok(Some(Node::new(
                    "string".to_string(),
                    NodeKind::String,
                    -1,
                    4,
                ))),
                _ => {
                    let (type_name, size, align) = prim_info(name)
                        .ok_or_else(|| refusal("signature kind unhandled", *name))?;
                    Ok(Some(Node::prim(type_name, name, size, align)))
                }
            },
            SigKind::SzArray(elem) => {
                let Some(elem_node) = self.node_for_type(asm_index, elem, field_name)? else {
                    return Ok(None);
                };
                let mut node = Node::new("Array".to_string(), NodeKind::Array, -1, 4);
                node.elem = Some(Rc::new(elem_node));
                Ok(Some(node))
            }
        }
    }

    fn node_for_genericinst(
        &self,
        asm_index: usize,
        sig: &SigType,
        field_name: &str,
    ) -> XResult<Option<Node>> {
        let SigKind::GenericInst { args, base } = &sig.kind else {
            return Err(refusal("signature kind unhandled", field_name));
        };
        let token = match &base.kind {
            SigKind::Class(token) | SigKind::ValueType(token) => *token,
            _ => return Err(refusal("genericinst over non-class base", field_name)),
        };
        match self.index.resolve_token(base.assembly, token) {
            None => Err(refusal("unresolved generic base", field_name)),
            Some(Resolved::Ref {
                name,
                namespace,
                ..
            }) => {
                if name == "List`1" && namespace == "System.Collections.Generic" {
                    self.list_node(asm_index, args, field_name)
                } else if matches!(name.as_str(), "Dictionary`2" | "HashSet`1")
                    && namespace == "System.Collections.Generic"
                {
                    Ok(None)
                } else {
                    Err(refusal(
                        "unresolved generic type reference",
                        format!("{} ({field_name})", type_display(&namespace, &name)),
                    ))
                }
            }
            Some(Resolved::TypeSpec(..)) => Err(refusal("generic base is a typespec", field_name)),
            Some(Resolved::Def(def_asm, def_td)) => {
                let def = &self.assembly(def_asm).type_defs[def_td];
                let full = type_display(&def.namespace, &def.name);
                if full == "System.Collections.Generic.List`1" {
                    return self.list_node(asm_index, args, field_name);
                }
                if matches!(
                    full.as_str(),
                    "System.Collections.Generic.Dictionary`2" | "System.Collections.Generic.HashSet`1"
                ) {
                    return Ok(None);
                }
                let mut subst: Subst = BTreeMap::new();
                for (i, arg) in args.iter().enumerate() {
                    subst.insert((false, u32::try_from(i).unwrap_or(u32::MAX)), arg.clone());
                }
                let display = def.name.split('`').next().unwrap_or(&def.name).to_string();
                self.node_for_class(def_asm, def_td, field_name, Some(&subst), Some(display))
            }
        }
    }

    fn list_node(
        &self,
        asm_index: usize,
        args: &[SigType],
        field_name: &str,
    ) -> XResult<Option<Node>> {
        if args.len() != 1 {
            return Err(refusal("List arity", field_name));
        }
        let Some(elem_node) = self.node_for_type(asm_index, &args[0], field_name)? else {
            return Ok(None);
        };
        let mut node = Node::new("vector".to_string(), NodeKind::Array, -1, 4);
        node.elem = Some(Rc::new(elem_node));
        Ok(Some(node))
    }

    /// The node for a [SerializeReference] field, built from
    /// the signature shape alone: an array/list shape carries
    /// a list of ids, a class shape a single id.
    fn ref_node(&self, sig: &SigType, field_name: &str) -> XResult<Node> {
        let refarray = || Node::new("managedref[]".to_string(), NodeKind::RefArray, -1, 4);
        let single = || Node::new("managedref".to_string(), NodeKind::Ref, -1, 4);
        match &sig.kind {
            SigKind::SzArray(_) => Ok(refarray()),
            SigKind::Class(_) | SigKind::ValueType(_) => Ok(single()),
            SigKind::GenericInst { base, .. } => {
                let token = match &base.kind {
                    SigKind::Class(token) | SigKind::ValueType(token) => *token,
                    _ => return Ok(single()),
                };
                match self.index.resolve_token(base.assembly, token) {
                    Some(Resolved::Def(def_asm, def_td)) => {
                        let def = &self.assembly(def_asm).type_defs[def_td];
                        if type_display(&def.namespace, &def.name)
                            == "System.Collections.Generic.List`1"
                        {
                            return Ok(refarray());
                        }
                        Ok(single())
                    }
                    Some(Resolved::Ref { name, namespace, .. }) => {
                        if name == "List`1" && namespace == "System.Collections.Generic" {
                            return Ok(refarray());
                        }
                        Ok(single())
                    }
                    _ => Ok(single()),
                }
            }
            _ => Err(refusal(
                "[SerializeReference] on non-reference type",
                field_name,
            )),
        }
    }

    fn node_for_class(
        &self,
        asm_index: usize,
        td_index: usize,
        _field_name: &str,
        subst: Option<&Subst>,
        display: Option<String>,
    ) -> XResult<Option<Node>> {
        let type_def = &self.assembly(asm_index).type_defs[td_index];
        if self.index.is_enum(asm_index, td_index) {
            let underlying = self.enum_underlying(asm_index, td_index)?;
            let (_type_name, size, align) = prim_info(underlying)
                .ok_or_else(|| refusal("signature kind unhandled", underlying))?;
            let mut node = Node::new(
                type_display(&type_def.namespace, &type_def.name),
                NodeKind::Enum,
                size,
                align,
            );
            node.underlying = Some(underlying);
            return Ok(Some(node));
        }
        if self.index.is_object_derived(asm_index, td_index) {
            return Ok(Some(Node::new(
                format!("PPtr<{}>", type_def.name),
                NodeKind::PPtr,
                12,
                4,
            )));
        }
        if self.index.is_delegate(asm_index, td_index) {
            return Ok(None);
        }
        if type_def.flags & TYPE_INTERFACE != 0 {
            return Ok(None);
        }
        if !self.is_serializable_type(asm_index, td_index) {
            return Ok(None);
        }
        if subst.is_none() {
            if let Some(size) = opaque_layout(&type_def.namespace, &type_def.name) {
                return Ok(Some(Node::new(
                    display.unwrap_or_else(|| type_def.name.clone()),
                    NodeKind::Opaque,
                    size,
                    4,
                )));
            }
            if let Some(node) = self.explicit_node(asm_index, td_index, display.clone())? {
                return Ok(Some(node));
            }
        }
        let mut node = Node::new(
            display.unwrap_or_else(|| type_def.name.clone()),
            NodeKind::Class,
            -1,
            4,
        );
        node.class_ref = Some(ClassRef {
            assembly: asm_index,
            subst: subst.cloned(),
            typedef: td_index,
        });
        Ok(Some(node))
    }

    /// A node for an explicit-layout struct (FieldLayout
    /// table): union members share storage, so the serialized
    /// form is the storage bytes read once. The emitted
    /// members are the finest-grained tiling of the storage
    /// (Color32 -> r, g, b, a, not the overlapping rgba word).
    fn explicit_node(
        &self,
        asm_index: usize,
        td_index: usize,
        display: Option<String>,
    ) -> XResult<Option<Node>> {
        let assembly = self.assembly(asm_index);
        let type_def = &assembly.type_defs[td_index];
        if type_def.flags & TYPE_LAYOUT_MASK != TYPE_EXPLICIT_LAYOUT {
            return Ok(None);
        }
        let mut raw: Vec<(u32, String, Node)> = Vec::new();
        for field_row in type_def.field_begin..type_def.field_end {
            let Some(&offset) = assembly.field_layouts.get(&field_row) else {
                continue;
            };
            let field = &assembly.fields[field_row - 1];
            if field.flags & (FIELD_STATIC | FIELD_LITERAL | FIELD_NOT_SERIALIZED) != 0 {
                continue;
            }
            let sig = parse_field_signature(&field.signature, asm_index).map_err(|error| {
                refusal(
                    "field signature undecodable",
                    format!("{}: {}", field.name, error.message),
                )
            })?;
            let Some(node) = self.node_for_type(asm_index, &sig, &field.name)? else {
                continue;
            };
            if node.size.get() < 0 {
                return Err(refusal(
                    "explicit layout member has variable size",
                    field.name.clone(),
                ));
            }
            raw.push((offset, field.name.clone(), node));
        }
        if raw.is_empty() {
            return Ok(None);
        }
        raw.sort_by_key(|(offset, _name, node)| (*offset, node.size.get()));
        let mut covered: Vec<(i64, i64)> = Vec::new();
        let mut members: Vec<(u32, FieldLayout)> = Vec::new();
        for (offset, name, node) in raw {
            let start = i64::from(offset);
            let end = start + node.size.get();
            if covered
                .iter()
                .any(|(s, e)| start < *e && *s < end)
            {
                continue;
            }
            covered.push((start, end));
            members.push((
                offset,
                FieldLayout {
                    name,
                    node: Rc::new(node),
                },
            ));
        }
        let size = assembly
            .class_layouts
            .get(&(td_index + 1))
            .map(|size| i64::from(*size))
            .unwrap_or_else(|| covered.iter().map(|(_s, e)| *e).max().unwrap_or(0));
        let align = members
            .iter()
            .map(|(_off, field)| field.node.align.get())
            .max()
            .unwrap_or(1);
        let mut node = Node::new(
            display.unwrap_or_else(|| type_def.name.clone()),
            NodeKind::Explicit,
            size,
            align,
        );
        node.members = members;
        Ok(Some(node))
    }

    /// Resolve (and memoize on the node) a class node's
    /// fields, fixed size, and alignment.
    fn class_node_fields(&self, node: &Node) -> XResult<Rc<Vec<FieldLayout>>> {
        let Some(class_ref) = &node.class_ref else {
            return Ok(node
                .resolved
                .borrow()
                .clone()
                .unwrap_or_else(|| Rc::new(Vec::new())));
        };
        if let Some(fields) = node.resolved.borrow().clone() {
            return Ok(fields);
        }
        let (fields, _skipped) = self.class_fields(
            class_ref.assembly,
            class_ref.typedef,
            class_ref.subst.as_ref(),
        )?;
        node.size.set(fixed_size(&fields));
        node.align.set(
            fields
                .iter()
                .map(|field| field.node.align.get())
                .max()
                .unwrap_or(1),
        );
        *node.resolved.borrow_mut() = Some(fields.clone());
        Ok(fields)
    }

    fn enum_underlying(&self, asm_index: usize, td_index: usize) -> XResult<&'static str> {
        let assembly = self.assembly(asm_index);
        let type_def = &assembly.type_defs[td_index];
        for field_row in type_def.field_begin..type_def.field_end {
            let field = &assembly.fields[field_row - 1];
            if field.name == "value__" {
                let sig = parse_field_signature(&field.signature, asm_index).map_err(|error| {
                    refusal(
                        "field signature undecodable",
                        format!("{}: {}", field.name, error.message),
                    )
                })?;
                if let SigKind::Prim(name) = sig.kind {
                    if prim_info(name).is_some() {
                        return Ok(name);
                    }
                }
                return Ok("i4");
            }
        }
        Ok("i4")
    }
}

/// A payload cursor. Every read is bounds-checked; an
/// overrun is the named refusal `unexpected end of payload`.
struct Cursor<'a> {
    bytes: &'a [u8],
    little: bool,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn need(&self, count: usize) -> XResult<()> {
        if self.pos + count > self.bytes.len() {
            return Err(refusal(
                "unexpected end of payload",
                format!("at {} need {count} of {}", self.pos, self.bytes.len()),
            ));
        }
        Ok(())
    }

    fn align(&mut self, align: i64) {
        self.pos = usize::try_from(align_up(
            i64::try_from(self.pos).unwrap_or(i64::MAX),
            align,
        ))
        .unwrap_or(self.pos);
    }

    fn read_bytes(&mut self, count: usize) -> XResult<&'a [u8]> {
        self.need(count)?;
        let out = &self.bytes[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn read_raw<const N: usize>(&mut self) -> XResult<[u8; N]> {
        let raw = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(raw);
        Ok(out)
    }

    fn read_i8(&mut self) -> XResult<i8> {
        Ok(i8::from_le_bytes(self.read_raw::<1>()?))
    }

    fn read_u8(&mut self) -> XResult<u8> {
        Ok(self.read_raw::<1>()?[0])
    }

    fn read_i16(&mut self) -> XResult<i16> {
        let raw = self.read_raw::<2>()?;
        Ok(if self.little {
            i16::from_le_bytes(raw)
        } else {
            i16::from_be_bytes(raw)
        })
    }

    fn read_u16(&mut self) -> XResult<u16> {
        let raw = self.read_raw::<2>()?;
        Ok(if self.little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    }

    fn read_i32(&mut self) -> XResult<i32> {
        let raw = self.read_raw::<4>()?;
        Ok(if self.little {
            i32::from_le_bytes(raw)
        } else {
            i32::from_be_bytes(raw)
        })
    }

    fn read_u32(&mut self) -> XResult<u32> {
        let raw = self.read_raw::<4>()?;
        Ok(if self.little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }

    fn read_i64(&mut self) -> XResult<i64> {
        let raw = self.read_raw::<8>()?;
        Ok(if self.little {
            i64::from_le_bytes(raw)
        } else {
            i64::from_be_bytes(raw)
        })
    }

    fn read_u64(&mut self) -> XResult<u64> {
        let raw = self.read_raw::<8>()?;
        Ok(if self.little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    }

    /// A length-prefixed UTF-8 string, stream aligned to 4
    /// after its bytes (the shape of every serialized string
    /// in this format).
    fn read_string(&mut self) -> XResult<String> {
        self.align(4);
        let len = self.read_i32()?;
        if !(0..=STRING_BYTES_MAX).contains(&len) {
            return Err(refusal("string length out of bounds", len.to_string()));
        }
        let raw = self.read_bytes(usize::try_from(len).unwrap_or(0))?;
        let text = String::from_utf8(raw.to_vec())
            .map_err(|error| refusal("string not valid UTF-8", error.to_string()))?;
        self.align(4);
        Ok(text)
    }
}

/// Whether a class tree statically contains a
/// [SerializeReference] field: only then does the root
/// object carry a managed-reference block.
fn tree_has_refs(builder: &LayoutBuilder, node: &Node, seen: &mut HashSet<usize>) -> bool {
    if !seen.insert(node as *const Node as usize) {
        return false;
    }
    match node.kind {
        NodeKind::Ref | NodeKind::RefArray => true,
        NodeKind::Array => node
            .elem
            .as_deref()
            .is_some_and(|elem| tree_has_refs(builder, elem, seen)),
        NodeKind::Explicit => node
            .members
            .iter()
            .any(|(_off, field)| tree_has_refs(builder, &field.node, seen)),
        NodeKind::Class => match builder.class_node_fields(node) {
            Ok(fields) => fields
                .iter()
                .any(|field| tree_has_refs(builder, &field.node, seen)),
            Err(_) => false,
        },
        _ => false,
    }
}

/// One managed-reference block entry: the concrete object's
/// decoded field data under its named type.
struct RefEntry {
    assembly: String,
    data: Value,
    type_name: String,
}

/// Walks class layouts over payload bytes. See the module
/// docs for the exact-consumption law.
struct Decoder<'a> {
    builder: &'a LayoutBuilder<'a>,
    entries: BTreeMap<i64, RefEntry>,
}

impl<'a> Decoder<'a> {
    fn new(builder: &'a LayoutBuilder<'a>) -> Decoder<'a> {
        Decoder {
            builder,
            entries: BTreeMap::new(),
        }
    }

    fn decode_object(&mut self, root: &Node, data: &[u8], little: bool) -> XResult<Value> {
        self.entries.clear();
        let mut cursor = Cursor {
            bytes: data,
            little,
            pos: 0,
        };
        let value = self.decode_class_fields(root, &mut cursor, 0)?;
        if tree_has_refs(self.builder, root, &mut HashSet::new()) {
            self.decode_ref_block(&mut cursor)?;
        }
        if cursor.pos != data.len() {
            return Err(refusal(
                "byte consumption mismatch",
                format!("consumed {} of {}", cursor.pos, data.len()),
            ));
        }
        self.resolve_refs(value, &HashSet::new())
    }

    /// The managed-reference block at the end of a root
    /// object (corpus-derived format): i32 marker (2), i32
    /// entry count, then per entry an i64 id, three aligned
    /// strings (class, namespace, assembly), and the object's
    /// field data decoded against the named concrete class.
    fn decode_ref_block(&mut self, cursor: &mut Cursor) -> XResult<()> {
        let marker = cursor.read_i32()?;
        if marker != 2 {
            return Err(refusal(
                "managed-reference block marker mismatch",
                marker.to_string(),
            ));
        }
        let count = cursor.read_i32()?;
        if !(0..=REF_ENTRY_COUNT_MAX).contains(&count) {
            return Err(refusal(
                "managed-reference count out of bounds",
                count.to_string(),
            ));
        }
        for _ in 0..count {
            let rid = cursor.read_i64()?;
            let class = cursor.read_string()?;
            let namespace = cursor.read_string()?;
            let assembly_name = cursor.read_string()?;
            let node = self.ref_class_node(&assembly_name, &namespace, &class)?;
            let data = self.decode_class_fields(&node, cursor, 1)?;
            self.entries.insert(
                rid,
                RefEntry {
                    assembly: assembly_name,
                    data,
                    type_name: type_display(&namespace, &class),
                },
            );
        }
        Ok(())
    }

    fn ref_class_node(&self, assembly_name: &str, namespace: &str, class: &str) -> XResult<Node> {
        let index = self.builder.index;
        let mut found: Option<(usize, usize)> = None;
        if let Some(&asm_index) = index.by_name.get(assembly_name) {
            let assembly = &index.assemblies[asm_index];
            for (td_index, type_def) in assembly.type_defs.iter().enumerate() {
                if type_def.namespace == namespace && type_def.name == class {
                    found = Some((asm_index, td_index));
                    break;
                }
            }
        }
        if found.is_none() {
            found = index
                .global_types
                .get(&(namespace.to_string(), class.to_string()))
                .copied();
        }
        let Some((asm_index, td_index)) = found else {
            return Err(refusal(
                "managed reference type not found",
                format!("{} ({assembly_name})", type_display(namespace, class)),
            ));
        };
        let mut node = Node::new(type_display(namespace, class), NodeKind::Class, -1, 1);
        node.class_ref = Some(ClassRef {
            assembly: asm_index,
            subst: None,
            typedef: td_index,
        });
        Ok(node)
    }

    /// Substitute decoded block entries for the
    /// `{"@managedref": rid}` placeholders. Id -1 is null; a
    /// cycle keeps the placeholder (the reference graph is
    /// data, not a decode failure).
    fn resolve_refs(&self, value: Value, busy: &HashSet<i64>) -> XResult<Value> {
        match value {
            Value::Object(map) => {
                if map.len() == 1 && map.contains_key("@managedref") {
                    let rid = map
                        .get("@managedref")
                        .and_then(Value::as_i64)
                        .unwrap_or(i64::MIN);
                    if rid == -1 {
                        return Ok(Value::Null);
                    }
                    let Some(entry) = self.entries.get(&rid) else {
                        return Err(refusal("managed reference without entry", rid.to_string()));
                    };
                    if busy.contains(&rid) {
                        return Ok(json!({"@managedref": rid}));
                    }
                    let mut next_busy = busy.clone();
                    next_busy.insert(rid);
                    let entry_value = json!({
                        "assembly": entry.assembly,
                        "data": entry.data,
                        "type": entry.type_name,
                    });
                    let resolved = self.resolve_refs(entry_value, &next_busy)?;
                    return Ok(json!({"@ref": resolved}));
                }
                let mut out = Map::new();
                for (key, item) in map {
                    out.insert(key, self.resolve_refs(item, busy)?);
                }
                Ok(Value::Object(out))
            }
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    out.push(self.resolve_refs(item, busy)?);
                }
                Ok(Value::Array(out))
            }
            other => Ok(other),
        }
    }

    fn decode_class_fields(
        &self,
        node: &Node,
        cursor: &mut Cursor,
        depth: usize,
    ) -> XResult<Value> {
        if depth > DECODE_DEPTH_MAX {
            return Err(refusal("nesting depth over bound", ""));
        }
        let fields = self.builder.class_node_fields(node)?;
        let mut out = Map::new();
        for field in fields.iter() {
            let value = self.decode_node(&field.node, cursor, depth)?;
            out.insert(field.name.clone(), value);
        }
        Ok(Value::Object(out))
    }

    fn decode_node(&self, node: &Node, cursor: &mut Cursor, depth: usize) -> XResult<Value> {
        match node.kind {
            NodeKind::Prim => self.decode_prim(node.prim.unwrap_or(""), cursor, node.size.get()),
            NodeKind::Enum => self.decode_prim(node.underlying.unwrap_or("i4"), cursor, -1),
            NodeKind::PPtr => {
                cursor.align(4);
                let file_id = cursor.read_i32()?;
                let path_id = cursor.read_i64()?;
                Ok(json!({"@pptr": [file_id, path_id]}))
            }
            NodeKind::String => Ok(Value::String(cursor.read_string()?)),
            NodeKind::Array => {
                cursor.align(4);
                let count = cursor.read_i32()?;
                if !(0..=ARRAY_COUNT_MAX).contains(&count) {
                    return Err(refusal("array count out of bounds", count.to_string()));
                }
                if depth + 1 > DECODE_DEPTH_MAX {
                    return Err(refusal("nesting depth over bound", ""));
                }
                let elem = node
                    .elem
                    .as_ref()
                    .ok_or_else(|| refusal("node kind unhandled", "array without element"))?;
                let mut out = Vec::new();
                for _ in 0..count {
                    out.push(self.decode_node(elem, cursor, depth + 1)?);
                }
                cursor.align(4);
                Ok(Value::Array(out))
            }
            NodeKind::Ref => {
                cursor.align(4);
                let rid = cursor.read_i64()?;
                Ok(json!({"@managedref": rid}))
            }
            NodeKind::RefArray => {
                cursor.align(4);
                let count = cursor.read_i32()?;
                if !(0..=ARRAY_COUNT_MAX).contains(&count) {
                    return Err(refusal("array count out of bounds", count.to_string()));
                }
                let mut out = Vec::new();
                for _ in 0..count {
                    cursor.align(4);
                    let rid = cursor.read_i64()?;
                    out.push(json!({"@managedref": rid}));
                }
                cursor.align(4);
                Ok(Value::Array(out))
            }
            NodeKind::Class => {
                cursor.align(node.align.get());
                self.decode_class_fields(node, cursor, depth + 1)
            }
            NodeKind::Raw => {
                cursor.align(node.align.get());
                let size = usize::try_from(node.size.get()).unwrap_or(0);
                let raw = cursor.read_bytes(size)?;
                Ok(json!({"@raw": hex_encode(raw)}))
            }
            NodeKind::Opaque => {
                cursor.align(node.align.get());
                let size = usize::try_from(node.size.get()).unwrap_or(0);
                let raw = cursor.read_bytes(size)?;
                Ok(json!({
                    "@opaque": node.type_name,
                    "hex": hex_encode(raw),
                    "len": node.size.get(),
                }))
            }
            NodeKind::Explicit => {
                cursor.align(node.align.get());
                let start = cursor.pos;
                let mut out = Map::new();
                for (offset, field) in &node.members {
                    cursor.pos = start + usize::try_from(*offset).unwrap_or(0);
                    let value = self.decode_node(&field.node, cursor, depth + 1)?;
                    out.insert(field.name.clone(), value);
                }
                cursor.pos = start + usize::try_from(node.size.get()).unwrap_or(0);
                Ok(Value::Object(out))
            }
        }
    }

    fn decode_prim(&self, prim: &str, cursor: &mut Cursor, width: i64) -> XResult<Value> {
        match prim {
            "bool" => {
                cursor.align(4);
                let value = cursor.read_i32()?;
                if value != 0 && value != 1 {
                    return Err(refusal("bool value out of range", value.to_string()));
                }
                Ok(Value::Bool(value == 1))
            }
            "char" => {
                cursor.align(2);
                Ok(json!(cursor.read_u16()?))
            }
            "i1" => {
                if width == 4 {
                    cursor.align(4);
                    Ok(json!(cursor.read_i32()?))
                } else {
                    Ok(json!(cursor.read_i8()?))
                }
            }
            "u1" => {
                if width == 4 {
                    cursor.align(4);
                    Ok(json!(cursor.read_u32()?))
                } else {
                    Ok(json!(cursor.read_u8()?))
                }
            }
            "i2" => {
                cursor.align(2);
                Ok(json!(cursor.read_i16()?))
            }
            "u2" => {
                cursor.align(2);
                Ok(json!(cursor.read_u16()?))
            }
            "i4" => {
                cursor.align(4);
                Ok(json!(cursor.read_i32()?))
            }
            "u4" => {
                cursor.align(4);
                Ok(json!(cursor.read_u32()?))
            }
            "i8" => {
                cursor.align(4);
                Ok(json!(cursor.read_i64()?))
            }
            "u8" => {
                cursor.align(4);
                Ok(json!(cursor.read_u64()?))
            }
            "r4" => {
                cursor.align(4);
                let bits = cursor.read_u32()?;
                Ok(json!({"@r4": format!("{bits:08x}")}))
            }
            "r8" => {
                cursor.align(4);
                let bits = cursor.read_u64()?;
                Ok(json!({"@r8": format!("{bits:016x}")}))
            }
            _ => Err(refusal("prim kind unhandled", prim)),
        }
    }
}

/// Canonical JSON for value digests: keys sorted, compact
/// separators, strings escaped the way Python's
/// `json.dumps(ensure_ascii=False)` escapes them, so a
/// digest here and a digest from the independent prototype
/// name the same bytes iff the values agree.
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_canonical_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_string(key, out);
                out.push(':');
                if let Some(item) = map.get(*key) {
                    write_canonical(item, out);
                }
            }
            out.push('}');
        }
    }
}

fn write_canonical_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn value_digest(value: &Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

/// Flatten a class tree into report rows (level, type,
/// name, byte size, kind), depth-capped; a layout error
/// while flattening refuses the class, as in the prototype.
fn flatten_tree(
    builder: &LayoutBuilder,
    node: &Node,
    level: usize,
    name: &str,
    out: &mut Vec<Value>,
) -> XResult<()> {
    let mut size = node.size.get();
    if node.kind == NodeKind::Class {
        builder.class_node_fields(node)?;
        size = node.size.get();
    }
    out.push(json!({
        "byte_size": size,
        "kind": node.kind.as_str(),
        "level": level,
        "name": name,
        "type": node.type_name,
    }));
    if level >= TREE_FLATTEN_DEPTH_MAX {
        return Ok(());
    }
    match node.kind {
        NodeKind::Array => {
            if let Some(elem) = &node.elem {
                flatten_tree(builder, elem, level + 1, "data", out)?;
            }
        }
        NodeKind::Class => {
            let fields = builder.class_node_fields(node)?;
            for field in fields.iter() {
                flatten_tree(builder, &field.node, level + 1, &field.name, out)?;
            }
        }
        NodeKind::Explicit => {
            for (_offset, field) in &node.members {
                flatten_tree(builder, &field.node, level + 1, &field.name, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Resolve a MonoScript identity to a definition: the
/// named assembly first, then the global index, then a
/// nested-class name (`Outer/Inner`) by its inner half.
fn find_typedef(
    index: &TypeIndex,
    assembly_name: &str,
    namespace: &str,
    class_name: &str,
) -> Option<(usize, usize)> {
    if let Some(&asm_index) = index.by_name.get(assembly_name) {
        let assembly = &index.assemblies[asm_index];
        for (td_index, type_def) in assembly.type_defs.iter().enumerate() {
            if type_def.namespace == namespace && type_def.name == class_name {
                return Some((asm_index, td_index));
            }
        }
    }
    if let Some(hit) = index
        .global_types
        .get(&(namespace.to_string(), class_name.to_string()))
    {
        return Some(*hit);
    }
    if let Some((_outer, inner)) = class_name.split_once('/') {
        if let Some(hit) = index
            .global_types
            .get(&(namespace.to_string(), inner.to_string()))
        {
            return Some(*hit);
        }
    }
    None
}

/// Per-source parse retained between the expansion's two
/// passes (script registry first, behaviours second),
/// mirroring the census's source handling.
struct ExpandParsed {
    container: &'static str,
    display: String,
    externals: Vec<String>,
    key: String,
    loose_path: Option<PathBuf>,
    summary: crate::unity::SfSummary,
}

/// One script class's expansion state: its record row and,
/// when reconstructed, the root node objects decode against.
struct ClassEntry {
    info: Value,
    node: Option<Node>,
}

fn build_class_entry(index: &TypeIndex, builder: &LayoutBuilder, identity: &ScriptIdentity) -> ClassEntry {
    let mut info = Map::new();
    info.insert("assembly".to_string(), json!(identity.assembly));
    info.insert("class".to_string(), json!(identity.class));
    info.insert("namespace".to_string(), json!(identity.namespace));
    let Some((asm_index, td_index)) = find_typedef(
        index,
        &identity.assembly,
        &identity.namespace,
        &identity.class,
    ) else {
        info.insert("status".to_string(), json!("refused"));
        info.insert(
            "construct".to_string(),
            json!("class not found in Managed metadata"),
        );
        return ClassEntry {
            info: Value::Object(info),
            node: None,
        };
    };
    let type_def = &index.assemblies[asm_index].type_defs[td_index];
    let display = type_display(&type_def.namespace, &type_def.name);
    let mut root = Node::new(display.clone(), NodeKind::Class, -1, 1);
    root.class_ref = Some(ClassRef {
        assembly: asm_index,
        subst: None,
        typedef: td_index,
    });
    match builder.class_fields(asm_index, td_index, None) {
        Ok((fields, skipped)) => {
            root.size.set(fixed_size(&fields));
            root.align.set(
                fields
                    .iter()
                    .map(|field| field.node.align.get())
                    .max()
                    .unwrap_or(1),
            );
            *root.resolved.borrow_mut() = Some(fields.clone());
            let mut tree: Vec<Value> = Vec::new();
            if let Err(error) = flatten_tree(builder, &root, 0, &display, &mut tree) {
                info.insert("status".to_string(), json!("refused"));
                info.insert("construct".to_string(), json!(error.construct));
                info.insert(
                    "detail".to_string(),
                    json!(truncate_chars(&error.render(), 120)),
                );
                return ClassEntry {
                    info: Value::Object(info),
                    node: None,
                };
            }
            info.insert("status".to_string(), json!("reconstructed"));
            info.insert("field_count".to_string(), json!(fields.len()));
            let skipped_rows: Vec<Value> = skipped
                .iter()
                .filter(|(_name, reason)| reason != "static field" && reason != "literal field")
                .map(|(name, reason)| json!({"name": name, "reason": reason}))
                .collect();
            info.insert("skipped_fields".to_string(), json!(skipped_rows));
            info.insert("tree".to_string(), json!(tree));
            ClassEntry {
                info: Value::Object(info),
                node: Some(root),
            }
        }
        Err(error) => {
            info.insert("status".to_string(), json!("refused"));
            info.insert("construct".to_string(), json!(error.construct));
            info.insert(
                "detail".to_string(),
                json!(truncate_chars(&error.render(), 120)),
            );
            ClassEntry {
                info: Value::Object(info),
                node: None,
            }
        }
    }
}

/// Load one title's Managed DLL schemas in file-name order.
/// Unparseable DLLs are named notes, never silent skips; a
/// PE without CLI metadata is a note too (it carries no
/// managed types).
fn load_managed_schemas(target: &Path) -> (Vec<AssemblySchema>, Vec<String>) {
    let managed_dir = target.join("Managed");
    let mut dll_paths: Vec<PathBuf> = Vec::new();
    if managed_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&managed_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "dll") {
                    dll_paths.push(path);
                }
            }
        }
    }
    dll_paths.sort();
    let mut assemblies = Vec::new();
    let mut notes = Vec::new();
    for path in dll_paths {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read(&path) {
            Ok(bytes) => match parse_schema(&bytes) {
                Ok(Some(schema)) => assemblies.push(schema),
                Ok(None) => notes.push(format!("{name}: PE carries no CLI metadata")),
                Err(error) => {
                    notes.push(format!("{name}: {}", truncate_chars(&error.message, 80)));
                }
            },
            Err(error) => notes.push(format!("{name}: {}", truncate_chars(&error.to_string(), 80))),
        }
    }
    (assemblies, notes)
}

/// Expand the MonoBehaviours of one Unity data directory:
/// reconstruct each script class's serialized layout from
/// the directory's Managed DLLs and decode every payload
/// against its layout, exactly consuming its bytes or
/// refusing it by named construct.
#[allow(clippy::too_many_lines)]
pub fn expand_unity_monobehaviours(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let metadata = std::fs::metadata(&target).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat target {}: {error}", target.display()),
        )
    })?;
    if !metadata.is_dir() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "expand_unity_monobehaviours target {} is not a directory",
                target.display()
            ),
        ));
    }
    let target_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (schemas, dll_notes) = load_managed_schemas(&target);
    let assembly_names: Vec<String> = {
        let mut names: Vec<String> = schemas
            .iter()
            .map(|schema| {
                if schema.name.is_empty() {
                    "?".to_string()
                } else {
                    schema.name.clone()
                }
            })
            .collect();
        names.sort();
        names
    };
    let index = TypeIndex::new(schemas);
    let builder = LayoutBuilder::new(&index);
    let mut decoder = Decoder::new(&builder);

    let (candidates, walk_capped, walk_unreadable) = walk_mb_candidates(&target);
    // Expand candidates into sources (loose files + bundle
    // nodes). Bundle bytes are decoded once and kept: the
    // expansion walks its sources twice.
    let mut sources: Vec<MbSource> = Vec::new();
    let mut bundle_cache: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut failed: Vec<Value> = Vec::new();
    for candidate in &candidates {
        let rel = candidate
            .strip_prefix(&target)
            .unwrap_or(candidate)
            .display()
            .to_string();
        let name = candidate
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_bundle = std::fs::File::open(candidate)
            .and_then(|mut f| {
                use std::io::Read as _;
                let mut sig = [0u8; 8];
                f.read_exact(&mut sig).map(|()| sig)
            })
            .map(|sig| &sig == b"UnityFS\0")
            .unwrap_or(false);
        if is_bundle {
            match bundle_serialized_nodes(candidate) {
                Ok(nodes) => {
                    for (node_path, bytes) in nodes {
                        let display = format!("{rel}!{node_path}");
                        let key = node_path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or(&node_path)
                            .to_string();
                        bundle_cache.insert(display.clone(), bytes);
                        sources.push(MbSource {
                            key,
                            display,
                            container: "bundle_node",
                            load: MbSourceLoad::BundleNode,
                        });
                    }
                }
                Err(reason) => failed.push(json!({"error": reason, "source": rel})),
            }
        } else {
            sources.push(MbSource {
                key: name,
                display: rel,
                container: "serialized_file",
                load: MbSourceLoad::Loose(candidate.clone()),
            });
        }
    }
    if sources.is_empty() {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "no readable SerializedFiles under {} ({} candidate file(s), {} failed)",
                target.display(),
                candidates.len(),
                failed.len()
            ),
        ));
    }
    let load_bytes = |source: &MbSource,
                      bundle_cache: &BTreeMap<String, Vec<u8>>|
     -> Result<Vec<u8>, String> {
        match &source.load {
            MbSourceLoad::Loose(path) => {
                let size = std::fs::metadata(path)
                    .map_err(|error| format!("cannot stat file: {error}"))?
                    .len();
                if size > ARCHIVE_TARGET_BYTES_MAX {
                    return Err(format!(
                        "file declares {size} bytes, over ARCHIVE_TARGET_BYTES_MAX ({ARCHIVE_TARGET_BYTES_MAX})"
                    ));
                }
                std::fs::read(path).map_err(|error| format!("cannot read file: {error}"))
            }
            MbSourceLoad::BundleNode => bundle_cache
                .get(&source.display)
                .cloned()
                .ok_or_else(|| "bundle node bytes were not retained".to_string()),
        }
    };
    // Pass 1: parse every source and build the script
    // registry — (file base name, path id) -> identity.
    let mut parsed: Vec<ExpandParsed> = Vec::new();
    let mut registry: BTreeMap<(String, i64), ScriptIdentity> = BTreeMap::new();
    let mut script_anomalies: Vec<String> = Vec::new();
    let mut script_anomaly_count: u64 = 0;
    for source in &sources {
        let bytes = match load_bytes(source, &bundle_cache) {
            Ok(bytes) => bytes,
            Err(reason) => {
                failed.push(json!({"error": reason, "source": source.display}));
                continue;
            }
        };
        let summary = match parse_serialized_file_capped(&bytes, UNITY_MB_OBJECTS_MAX) {
            Ok(summary) => summary,
            Err(error) => {
                failed.push(json!({"error": error.message, "source": source.display}));
                continue;
            }
        };
        let externals = match parse_sf_externals(&bytes) {
            Ok(externals) => externals,
            Err(error) => {
                failed.push(json!({"error": error.message, "source": source.display}));
                continue;
            }
        };
        for payload in &summary.payloads {
            if payload.class_id != CLASS_MONO_SCRIPT {
                continue;
            }
            let Some(slice) = payload_slice(&bytes, &summary, payload) else {
                script_anomaly_count += 1;
                if script_anomalies.len() < 100 {
                    script_anomalies.push(format!(
                        "{}: MonoScript {} payload lies outside the file bytes",
                        source.display, payload.path_id
                    ));
                }
                continue;
            };
            match parse_mono_script(slice, summary.little) {
                Ok(identity) => {
                    let reg_key = (source.key.clone(), payload.path_id);
                    if let Some(existing) = registry.get(&reg_key) {
                        if *existing != identity {
                            script_anomaly_count += 1;
                            if script_anomalies.len() < 100 {
                                script_anomalies.push(format!(
                                    "{}: MonoScript {} redeclared with a different identity; the first stands",
                                    source.display, payload.path_id
                                ));
                            }
                        }
                    } else {
                        registry.insert(reg_key, identity);
                    }
                }
                Err(reason) => {
                    script_anomaly_count += 1;
                    if script_anomalies.len() < 100 {
                        script_anomalies.push(format!(
                            "{}: MonoScript {} does not parse ({reason})",
                            source.display, payload.path_id
                        ));
                    }
                }
            }
        }
        parsed.push(ExpandParsed {
            container: source.container,
            display: source.display.clone(),
            externals,
            key: source.key.clone(),
            loose_path: match &source.load {
                MbSourceLoad::Loose(path) => Some(path.clone()),
                MbSourceLoad::BundleNode => None,
            },
            summary,
        });
    }
    // Pass 2: expand the MonoBehaviours of every parsed
    // source against the completed registry.
    let mut class_entries: BTreeMap<ScriptIdentity, ClassEntry> = BTreeMap::new();
    let mut decoded: u64 = 0;
    let mut file_rows: Vec<Value> = Vec::new();
    let mut objects: Vec<Value> = Vec::new();
    let mut objects_omitted: u64 = 0;
    let mut refusal_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut refused: u64 = 0;
    let mut total_monobehaviours: u64 = 0;
    let mut truncated_files: Vec<String> = Vec::new();
    let mut value_samples: Vec<Value> = Vec::new();
    fn retain_object_row(objects: &mut Vec<Value>, row: Value) {
        if objects.len() < OBJECT_ROWS_RETAINED_MAX {
            objects.push(row);
        }
    }
    for source in &parsed {
        let bytes = match &source.loose_path {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            },
            None => match bundle_cache.get(&source.display) {
                Some(bytes) => bytes.clone(),
                None => continue,
            },
        };
        let mut file_behaviours: u64 = 0;
        let mut file_decoded: u64 = 0;
        let mut file_refused: u64 = 0;
        for payload in &source.summary.payloads {
            if payload.class_id != CLASS_MONO_BEHAVIOUR {
                continue;
            }
            file_behaviours += 1;
            total_monobehaviours += 1;
            let mut record = Map::new();
            record.insert("file".to_string(), json!(source.key));
            record.insert("path_id".to_string(), json!(payload.path_id));
            let mut refuse = |record: &mut Map<String, Value>,
                              refusal_counts: &mut BTreeMap<String, u64>,
                              file_refused: &mut u64,
                              refused: &mut u64,
                              construct: String,
                              detail: Option<String>| {
                record.insert("status".to_string(), json!("refused"));
                record.insert("construct".to_string(), json!(construct.clone()));
                if let Some(detail) = detail {
                    record.insert("detail".to_string(), json!(detail));
                }
                *refusal_counts.entry(construct).or_insert(0) += 1;
                *file_refused += 1;
                *refused += 1;
            };
            let Some(slice) = payload_slice(&bytes, &source.summary, payload) else {
                refuse(
                    &mut record,
                    &mut refusal_counts,
                    &mut file_refused,
                    &mut refused,
                    "payload lies outside the file bytes".to_string(),
                    None,
                );
                retain_object_row(&mut objects, Value::Object(record));
                continue;
            };
            let header = match parse_mb_header(slice, source.summary.little) {
                Ok(header) => header,
                Err(reason) => {
                    refuse(
                        &mut record,
                        &mut refusal_counts,
                        &mut file_refused,
                        &mut refused,
                        "header parse failure".to_string(),
                        Some(truncate_chars(&reason, 80)),
                    );
                    retain_object_row(&mut objects, Value::Object(record));
                    continue;
                }
            };
            record.insert("object_name".to_string(), json!(header.name));
            if header.script_path == 0 {
                refuse(
                    &mut record,
                    &mut refusal_counts,
                    &mut file_refused,
                    &mut refused,
                    "null script reference".to_string(),
                    None,
                );
                retain_object_row(&mut objects, Value::Object(record));
                continue;
            }
            let target_key = if header.script_file == 0 {
                Some(source.key.clone())
            } else if header.script_file > 0 {
                source
                    .externals
                    .get(usize::try_from(header.script_file - 1).unwrap_or(usize::MAX))
                    .cloned()
            } else {
                None
            };
            let identity = target_key.and_then(|key| registry.get(&(key, header.script_path)));
            let Some(identity) = identity else {
                refuse(
                    &mut record,
                    &mut refusal_counts,
                    &mut file_refused,
                    &mut refused,
                    "script reference unresolved".to_string(),
                    None,
                );
                retain_object_row(&mut objects, Value::Object(record));
                continue;
            };
            let identity = identity.clone();
            record.insert(
                "class".to_string(),
                json!(format!(
                    "{}:{}.{}",
                    identity.assembly, identity.namespace, identity.class
                )),
            );
            if !class_entries.contains_key(&identity) {
                let entry = build_class_entry(&index, &builder, &identity);
                class_entries.insert(identity.clone(), entry);
            }
            let entry = class_entries.get(&identity).ok_or_else(|| {
                FathomError::new(ErrorCode::InvalidRequest, "class entry vanished")
            })?;
            let Some(root) = &entry.node else {
                let construct = entry
                    .info
                    .get("construct")
                    .and_then(Value::as_str)
                    .unwrap_or("class tree refused")
                    .to_string();
                refuse(
                    &mut record,
                    &mut refusal_counts,
                    &mut file_refused,
                    &mut refused,
                    format!("class tree refused: {construct}"),
                    None,
                );
                retain_object_row(&mut objects, Value::Object(record));
                continue;
            };
            let data = &slice[slice.len() - header.payload_bytes..];
            match decoder.decode_object(root, data, source.summary.little) {
                Ok(value) => {
                    record.insert("status".to_string(), json!("decoded"));
                    record.insert("consumed".to_string(), json!(data.len()));
                    record.insert("digest".to_string(), json!(value_digest(&value)));
                    if value_samples.len() < DECODED_VALUES_RETAINED_MAX {
                        value_samples.push(json!({
                            "file": source.key,
                            "path_id": payload.path_id,
                            "values": value,
                        }));
                    }
                    decoded += 1;
                    file_decoded += 1;
                }
                Err(error) => {
                    let construct = error.construct.to_string();
                    refuse(
                        &mut record,
                        &mut refusal_counts,
                        &mut file_refused,
                        &mut refused,
                        construct,
                        Some(truncate_chars(&error.render(), 120)),
                    );
                }
            }
            retain_object_row(&mut objects, Value::Object(record));
        }
        file_rows.push(json!({
            "container": source.container,
            "decoded": file_decoded,
            "monobehaviours": file_behaviours,
            "objects_total": source.summary.object_count,
            "objects_truncated": source.summary.objects_truncated,
            "refused": file_refused,
            "source": source.display,
        }));
        if source.summary.objects_truncated {
            truncated_files.push(source.display.clone());
        }
    }
    objects_omitted = total_monobehaviours.saturating_sub(objects.len() as u64);
    let classes: Vec<Value> = class_entries
        .values()
        .map(|entry| entry.info.clone())
        .collect();
    let refusals_by_construct: Value = json!(refusal_counts
        .iter()
        .map(|(construct, count)| (construct.clone(), json!(count)))
        .collect::<Map<String, Value>>());
    let record = json!({
        "assemblies": assembly_names,
        "classes": classes,
        "decoded": decoded,
        "dll_notes": dll_notes,
        "files": file_rows,
        "files_examined": parsed.len(),
        "files_failed": failed,
        "monoscript_anomalies": script_anomalies,
        "monoscript_anomaly_count": script_anomaly_count,
        "objects": objects,
        "objects_omitted": objects_omitted,
        "refusals_by_construct": refusals_by_construct,
        "refused": refused,
        "root": target_name,
        "total_monobehaviours": total_monobehaviours,
        "value_samples": value_samples,
    });
    // Retention binds to the expansion record's own hash.
    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let key = sha256_hex(canonical.as_bytes());
    let (digest, retention_note) =
        match proof::retain_export(config, &key, "unity_monobehaviour_expansion", &record) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = record.clone();
    facts["export_digest"] = match &digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    let mut evidence = Evidence::new("expand_unity_monobehaviours", "unity");
    evidence.add_finding(Finding::new(
        "unity_monobehaviour_expansion",
        Confidence::Observed,
        facts,
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "expansion retention failed ({note}); the expansion facts stand, but no proof can bind this run"
            ),
        );
    }
    if !failed.is_empty() {
        evidence.add_unknown(
            "sources",
            format!(
                "{} source(s) could not be expanded: {}",
                failed.len(),
                failed
                    .iter()
                    .map(|row| format!("{} ({})", row["source"], row["error"]))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
    }
    if !dll_notes.is_empty() {
        evidence.add_unknown(
            "managed assemblies",
            format!(
                "{} Managed DLL(s) carried no usable schema: {}",
                dll_notes.len(),
                dll_notes.join("; ")
            ),
        );
    }
    let unresolved_total = refusal_counts
        .get("script reference unresolved")
        .copied()
        .unwrap_or(0);
    if unresolved_total > 0 {
        evidence.add_unknown(
            "script references",
            format!(
                "{unresolved_total} MonoBehaviour(s) reference a MonoScript that is not in the expanded files; they are counted under refusals_by_construct, never dropped"
            ),
        );
    }
    if script_anomaly_count > 0 {
        evidence.add_unknown(
            "payload anomalies",
            format!(
                "{script_anomaly_count} MonoScript payload(s) did not parse; they are named in the expansion record and counted in its totals"
            ),
        );
    }
    if !truncated_files.is_empty() {
        evidence.add_unknown(
            "object rows",
            format!(
                "object rows were truncated at UNITY_MB_OBJECTS_MAX in: {}; counts for those files are a floor, not a total",
                truncated_files.join(", ")
            ),
        );
    }
    if objects_omitted > 0 {
        evidence.add_unknown(
            "object rows retained",
            format!(
                "{objects_omitted} per-object row(s) were omitted past OBJECT_ROWS_RETAINED_MAX ({OBJECT_ROWS_RETAINED_MAX}); decoded/refused counts stay exact"
            ),
        );
    }
    if walk_capped {
        evidence.add_unknown(
            "walk coverage",
            format!(
                "the directory walk stopped at UNITY_MB_FILES_MAX ({UNITY_MB_FILES_MAX}) candidate files; counts are a floor, not a total"
            ),
        );
    }
    if walk_unreadable > 0 {
        evidence.add_unknown(
            "walk coverage",
            format!("{walk_unreadable} directory entries could not be read and are uncounted"),
        );
    }
    evidence.coverage.examined = parsed.len() as u64;
    evidence.coverage.total = sources.len() as u64;
    evidence.coverage.exhaustive =
        evidence.coverage.examined == evidence.coverage.total && evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_managed::schema::{FieldSchema, TypeDefSchema, TypeRefSchema};

    fn type_ref(name: &str, namespace: &str) -> TypeRefSchema {
        TypeRefSchema {
            name: name.to_string(),
            namespace: namespace.to_string(),
            scope_assembly: Some("mscorlib".to_string()),
        }
    }

    /// One assembly "Asm" whose TypeDef row 1 is `Widget` in
    /// namespace `Game`, extending the TypeRef named by
    /// `base` (namespace, name). Fields are (flags, name,
    /// signature blob); attributes map field row -> names.
    fn fixture_assembly(
        base: (&str, &str),
        fields: Vec<(u16, &str, Vec<u8>)>,
        attributes: Vec<(usize, &str)>,
    ) -> AssemblySchema {
        let mut attrs: BTreeMap<(usize, usize), Vec<String>> = BTreeMap::new();
        for (row, name) in attributes {
            attrs.insert((TABLE_FIELD, row), vec![name.to_string()]);
        }
        AssemblySchema {
            assembly_refs: vec!["mscorlib".to_string()],
            attributes: attrs,
            class_layouts: BTreeMap::new(),
            field_layouts: BTreeMap::new(),
            fields: fields
                .iter()
                .map(|(flags, name, sig)| FieldSchema {
                    flags: *flags,
                    name: (*name).to_string(),
                    signature: sig.clone(),
                })
                .collect(),
            name: "Asm".to_string(),
            type_defs: vec![TypeDefSchema {
                extends: Some((TABLE_TYPE_REF, 1)),
                field_begin: 1,
                field_end: fields.len() + 1,
                flags: 0,
                method_begin: 1,
                method_end: 1,
                name: "Widget".to_string(),
                namespace: "Game".to_string(),
            }],
            type_refs: vec![type_ref(base.1, base.0)],
            type_specs: Vec::new(),
        }
    }

    fn sig_i4() -> Vec<u8> {
        vec![0x06, 0x08]
    }

    fn sig_string() -> Vec<u8> {
        vec![0x06, 0x0E]
    }

    fn sig_u1() -> Vec<u8> {
        vec![0x06, 0x05]
    }

    fn class_node(fields: Vec<FieldLayout>) -> Node {
        let node = Node::new("Widget".to_string(), NodeKind::Class, -1, 1);
        *node.resolved.borrow_mut() = Some(Rc::new(fields));
        node
    }

    fn field(name: &str, node: Node) -> FieldLayout {
        FieldLayout {
            name: name.to_string(),
            node: Rc::new(node),
        }
    }

    /// A builder over an empty index for decoder tests whose
    /// nodes are all hand-built (the index is leaked; test
    /// processes are short-lived).
    fn empty_builder() -> LayoutBuilder<'static> {
        let index: &'static TypeIndex = Box::leak(Box::new(TypeIndex::new(Vec::new())));
        LayoutBuilder::new(index)
    }

    #[test]
    fn validation_layout_field_selection() {
        let assembly = fixture_assembly(
            ("System", "Object"),
            vec![
                (FIELD_PUBLIC, "count", sig_i4()),
                (0, "label", sig_string()),
                (0, "hidden", sig_i4()),
                (FIELD_PUBLIC | FIELD_STATIC, "shared", sig_i4()),
            ],
            vec![(2, "UnityEngine.SerializeField")],
        );
        let index = TypeIndex::new(vec![assembly]);
        let builder = LayoutBuilder::new(&index);
        let (fields, skipped) = builder.class_fields(0, 0, None).unwrap();
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["count", "label"]);
        let reasons: Vec<(&str, &str)> = skipped
            .iter()
            .map(|(n, r)| (n.as_str(), r.as_str()))
            .collect();
        assert_eq!(
            reasons,
            vec![
                ("hidden", "non-public without [SerializeField]"),
                ("shared", "static field"),
            ]
        );
    }

    #[test]
    fn validation_class_byte_field_widens_to_four() {
        let assembly = fixture_assembly(
            ("System", "Object"),
            vec![(FIELD_PUBLIC, "tab", sig_u1())],
            Vec::new(),
        );
        let index = TypeIndex::new(vec![assembly]);
        let builder = LayoutBuilder::new(&index);
        let (fields, _skipped) = builder.class_fields(0, 0, None).unwrap();
        assert_eq!(fields[0].node.size.get(), 4);
        assert_eq!(fields[0].node.align.get(), 4);
    }

    #[test]
    fn validation_struct_byte_field_packs() {
        let assembly = fixture_assembly(
            ("System", "ValueType"),
            vec![(FIELD_PUBLIC, "r", sig_u1())],
            Vec::new(),
        );
        let index = TypeIndex::new(vec![assembly]);
        let builder = LayoutBuilder::new(&index);
        let (fields, _skipped) = builder.class_fields(0, 0, None).unwrap();
        assert_eq!(fields[0].node.size.get(), 1);
    }

    #[test]
    fn adversarial_native_ptr_class_refused_by_name() {
        // m_Ptr's signature is native int (ET_I = 0x18), a
        // type Unity does not serialize from declarations.
        let assembly = fixture_assembly(
            ("System", "Object"),
            vec![(0, "m_Ptr", vec![0x06, 0x18])],
            Vec::new(),
        );
        let index = TypeIndex::new(vec![assembly]);
        let builder = LayoutBuilder::new(&index);
        let Err(error) = builder.class_fields(0, 0, None) else {
            panic!("native m_Ptr class must refuse by name");
        };
        assert_eq!(
            error.construct,
            "native-serialized type without managed layout"
        );
        assert_eq!(error.detail, "Game.Widget");
    }

    #[test]
    fn adversarial_unsubstituted_generic_parameter() {
        let builder = empty_builder();
        let sig = SigType {
            assembly: 0,
            kind: SigKind::Var(0),
        };
        let Err(error) = builder.node_for_type(0, &sig, "items") else {
            panic!("unsubstituted generic parameter must refuse by name");
        };
        assert_eq!(error.construct, "unsubstituted generic parameter");
    }

    #[test]
    fn validation_decode_exact_values() {
        let builder = empty_builder();
        let mut decoder = Decoder::new(&builder);
        let root = class_node(vec![
            field("hp", Node::prim("int", "i4", 4, 4)),
            field("name", Node::new("string".to_string(), NodeKind::String, -1, 4)),
            field("alive", Node::prim("bool", "bool", 4, 4)),
        ]);
        let mut data = Vec::new();
        data.extend_from_slice(&42_i32.to_le_bytes());
        data.extend_from_slice(&3_i32.to_le_bytes());
        data.extend_from_slice(b"imp");
        data.push(0);
        data.extend_from_slice(&1_i32.to_le_bytes());
        let value = decoder.decode_object(&root, &data, true).unwrap();
        assert_eq!(
            value,
            json!({"alive": true, "hp": 42, "name": "imp"})
        );
    }

    #[test]
    fn adversarial_decode_trailing_byte_refused() {
        let builder = empty_builder();
        let mut decoder = Decoder::new(&builder);
        let root = class_node(vec![field("hp", Node::prim("int", "i4", 4, 4))]);
        let mut data = 42_i32.to_le_bytes().to_vec();
        data.push(0);
        let error = decoder.decode_object(&root, &data, true).unwrap_err();
        assert_eq!(error.construct, "byte consumption mismatch");
        assert_eq!(error.detail, "consumed 4 of 5");
    }

    #[test]
    fn adversarial_decode_truncated_string_refused() {
        let builder = empty_builder();
        let mut decoder = Decoder::new(&builder);
        let root = class_node(vec![field(
            "name",
            Node::new("string".to_string(), NodeKind::String, -1, 4),
        )]);
        let mut data = Vec::new();
        data.extend_from_slice(&10_i32.to_le_bytes());
        data.extend_from_slice(b"ab");
        let error = decoder.decode_object(&root, &data, true).unwrap_err();
        assert_eq!(error.construct, "unexpected end of payload");
    }

    #[test]
    fn adversarial_decode_bool_out_of_range_refused() {
        let builder = empty_builder();
        let mut decoder = Decoder::new(&builder);
        let root = class_node(vec![field("alive", Node::prim("bool", "bool", 4, 4))]);
        let data = 7_i32.to_le_bytes().to_vec();
        let error = decoder.decode_object(&root, &data, true).unwrap_err();
        assert_eq!(error.construct, "bool value out of range");
    }

    #[test]
    fn adversarial_decode_negative_array_count_refused() {
        let builder = empty_builder();
        let mut decoder = Decoder::new(&builder);
        let mut array_node = Node::new("Array".to_string(), NodeKind::Array, -1, 4);
        array_node.elem = Some(Rc::new(Node::prim("int", "i4", 4, 4)));
        let root = class_node(vec![field("values", array_node)]);
        let data = (-1_i32).to_le_bytes().to_vec();
        let error = decoder.decode_object(&root, &data, true).unwrap_err();
        assert_eq!(error.construct, "array count out of bounds");
    }

    #[test]
    fn validation_canonical_json_matches_prototype_encoding() {
        let value = json!({
            "@r4": "3f800000",
            "label": "café \"quoted\"\nline",
            "nums": [1, -2, 3],
            "nested": {"b": 1, "a": [true, null]},
        });
        let canonical = canonical_json(&value);
        assert_eq!(
            canonical,
            "{\"@r4\":\"3f800000\",\"label\":\"café \\\"quoted\\\"\\nline\",\"nested\":{\"a\":[true,null],\"b\":1},\"nums\":[1,-2,3]}"
        );
        assert_eq!(value_digest(&value), sha256_hex(canonical.as_bytes()));
    }

    #[test]
    fn validation_managed_reference_block_roundtrip() {
        // Assembly "Asm" with class Game.Thing { public i4 v }.
        let mut assembly = fixture_assembly(
            ("System", "Object"),
            vec![(FIELD_PUBLIC, "v", sig_i4())],
            Vec::new(),
        );
        assembly.type_defs[0].name = "Thing".to_string();
        let index = TypeIndex::new(vec![assembly]);
        let builder = LayoutBuilder::new(&index);
        let mut decoder = Decoder::new(&builder);
        let root = class_node(vec![field(
            "link",
            Node::new("managedref".to_string(), NodeKind::Ref, -1, 4),
        )]);
        let mut data = Vec::new();
        data.extend_from_slice(&5_i64.to_le_bytes()); // rid
        data.extend_from_slice(&2_i32.to_le_bytes()); // block marker
        data.extend_from_slice(&1_i32.to_le_bytes()); // entry count
        data.extend_from_slice(&5_i64.to_le_bytes()); // entry rid
        for text in ["Thing", "Game", "Asm"] {
            data.extend_from_slice(&i32::try_from(text.len()).unwrap().to_le_bytes());
            data.extend_from_slice(text.as_bytes());
            while data.len() % 4 != 0 {
                data.push(0);
            }
        }
        data.extend_from_slice(&7_i32.to_le_bytes()); // Thing.v
        let value = decoder.decode_object(&root, &data, true).unwrap();
        assert_eq!(
            value,
            json!({"link": {"@ref": {
                "assembly": "Asm",
                "data": {"v": 7},
                "type": "Game.Thing",
            }}})
        );
    }
}
