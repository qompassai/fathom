//! Clean-room Unity Texture2D codec (D-1654 rungs 1-2).
//!
//! Scope: decode Texture2D objects whose TextureFormat is
//! DXT1 (10, BC1) or DXT5 (12, BC3) — rung 1 — or one of
//! the uncompressed formats of rung 2 (Alpha8 1, ARGB4444
//! 2, RGB24 3, RGBA32 4, ARGB32 5, RGB565 7, RGBA4444 13,
//! RGBAHalf 17, RFloat 18, RGBAFloat 20, R8 63) into RGBA
//! pixels, end to end: serialized object bytes -> metadata
//! + image-data placement -> per-mip-level RGBA buffers.
//!
//! Spec provenance (implementation inputs, nothing else):
//! - Microsoft, "Block Compression (Direct3D 10)": the BC1 and
//!   BC3 sections (4x4 blocks; RGB565 endpoints; the four-color
//!   interpolation color_2 = 2/3*c0 + 1/3*c1, color_3 =
//!   1/3*c0 + 2/3*c1; the three-color form color_2 =
//!   1/2*c0 + 1/2*c1 with color_3 transparent; the BC3 alpha
//!   tables with six interpolated values when alpha_0 >
//!   alpha_1 and four plus the 0/255 pair otherwise) and
//!   "Virtual Size versus Physical Size" (levels below 4x4 are
//!   still stored as one padded block).
//! - Microsoft, "Texture Block Compression in Direct3D 11":
//!   BC1 = DXT1 (8 bytes per block), BC3 = DXT5 (16 bytes).
//! - Khronos GL_EXT_texture_compression_s3tc: cross-reference
//!   for the endpoint-ordering rule (color_0 > color_1 selects
//!   the four-color form) and the RGB565 bit layout.
//! - Unity's public TextureFormat documentation: the format
//!   codes and the uncompressed channel layouts (byte and
//!   nibble order follow the format name's channel order;
//!   the 16-bit formats are little-endian). IEEE 754 for
//!   the half and float channels.
//! - Texture2D serialized layouts: estate measurement only
//!   (D-1654 rung 0 census): one layout is pinned per Unity
//!   generator version and validated by the size-arithmetic
//!   check (expected mip-chain bytes == recorded complete
//!   image size); layouts are never raced per object. The
//!   field block between the mip count and the image-data
//!   length, and the StreamingInfo tail (offset, size, path),
//!   were measured from held titles' object bytes in the
//!   census follow-up probes recorded in the rung record.
//!
//! Conventions the public documents do not state were
//! pinned by the differential against the oracle, never
//! assumed (rung 2 record): the vertical flip (rung 1);
//! Alpha8 decodes as black under the recorded alpha;
//! the plain RGB565 expansion is shift-only, unlike the
//! BC endpoints' bit replication; float channels clamp
//! to [0, 1], scale by 255, and truncate.
//!
//! AssetRipper is a black-box test oracle only (differential
//! fixtures); no decoder implementation was consulted.
//!
//! Boundaries (stated, never silent): Crunch-wrapped formats
//! (28/29) and every still-unsupported format (the BC7 /
//! BC6H / BC4 / BC5 family, ETC, ASTC, and the tail) are
//! rejected by the decoder with a typed error; R8 decodes
//! from the documented layout but carries no differential
//! fixture yet (its only census carriers are
//! bundle-resident or in an unwalked title — rung 2
//! record); streamed image data is resolved by the
//! caller supplying the resource (.resS) bytes — this module
//! never touches the filesystem for image data; the
//! `decode_unity_textures` tool resolves streamed data only
//! for loose SerializedFiles whose resource file is a sibling
//! of the .assets file (bundle `archive:/` resource paths are
//! reported, not resolved).

use serde_json::{Value, json};
use std::fmt;
use std::path::{Path, PathBuf};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::{TEXTURE_DIMENSION_MAX, UNITY_EXTRACT_BYTES_MAX, UNITY_OBJECTS_MAX};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

use crate::unity::parse_serialized_file_capped;

/// TextureFormat code for DXT1 (Unity public enum documentation).
pub const TEXTURE_FORMAT_DXT1: i32 = 10;
/// TextureFormat code for DXT5 (Unity public enum documentation).
pub const TEXTURE_FORMAT_DXT5: i32 = 12;
/// TextureFormat code for Alpha8 (Unity public enum documentation).
pub const TEXTURE_FORMAT_ALPHA8: i32 = 1;
/// TextureFormat code for ARGB4444 (Unity public enum documentation).
pub const TEXTURE_FORMAT_ARGB4444: i32 = 2;
/// TextureFormat code for RGB24 (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGB24: i32 = 3;
/// TextureFormat code for RGBA32 (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGBA32: i32 = 4;
/// TextureFormat code for ARGB32 (Unity public enum documentation).
pub const TEXTURE_FORMAT_ARGB32: i32 = 5;
/// TextureFormat code for RGB565 (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGB565: i32 = 7;
/// TextureFormat code for RGBA4444 (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGBA4444: i32 = 13;
/// TextureFormat code for RGBAHalf (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGBAHALF: i32 = 17;
/// TextureFormat code for RFloat (Unity public enum documentation).
pub const TEXTURE_FORMAT_RFLOAT: i32 = 18;
/// TextureFormat code for RGBAFloat (Unity public enum documentation).
pub const TEXTURE_FORMAT_RGBAFLOAT: i32 = 20;
/// TextureFormat code for R8 (Unity public enum documentation).
pub const TEXTURE_FORMAT_R8: i32 = 63;
/// Class id of Texture2D in a SerializedFile.
const CLASS_TEXTURE_2D: i64 = 28;
/// Largest decoded RGBA output one decode may produce.
pub const DECODED_BYTES_MAX: usize = 268_435_456;
/// Largest image-data payload one texture may carry here
/// (the estate extract budget bounds files end to end).
pub const IMAGE_DATA_BYTES_MAX: usize = 536_870_912;
/// Trailing zero padding tolerated after the StreamingInfo
/// path (measured maximum on held titles: 28 bytes).
const TRAILING_PAD_BYTES_MAX: usize = 64;
/// SerializedFiles the decode tool visits in one run.
const TOOL_FILES_MAX: usize = 512;
/// Directory depth the decode tool walks below its target.
const TOOL_WALK_DEPTH_MAX: usize = 8;

/// A typed codec failure. Expected bad input lands here,
/// never in a panic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextureError {
    /// The payload ends before a required field or block.
    Truncated { context: &'static str },
    /// A dimension is zero or above the texture bound.
    InvalidDimensions { width: i32, height: i32 },
    /// The mip count cannot belong to the dimensions.
    InvalidMipCount { mip_count: i32 },
    /// The format code is outside the documented enum window.
    InvalidFormatCode { code: i32 },
    /// Recorded complete image size disagrees with the
    /// size arithmetic for the format and dimensions.
    ImageSizeMismatch { recorded: i64, expected: u64 },
    /// The image-data length is neither zero (streamed) nor
    /// the recorded complete image size (inline).
    InvalidImageDataLength {
        length: i64,
        complete_image_size: i32,
    },
    /// The StreamingInfo tail disagrees with the metadata
    /// (wrong size, missing path, nonzero inline stream...).
    InvalidStreamingInfo { context: &'static str },
    /// Non-zero or oversized trailing bytes after the object.
    InvalidTrailingBytes { count: usize },
    /// The format is not one this codec decodes.
    UnsupportedFormat { code: i32 },
    /// No layout is pinned for this Unity generator version.
    UnsupportedLayout { version: String },
    /// A decode would exceed a named bound.
    LimitExceeded { context: &'static str },
    /// Streamed data was required but not supplied, or the
    /// supplied resource does not cover the recorded range.
    ResourceUnavailable { context: &'static str },
}

impl fmt::Display for TextureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TextureError::Truncated { context } => write!(f, "truncated: {context}"),
            TextureError::InvalidDimensions { width, height } => {
                write!(f, "invalid dimensions {width}x{height}")
            }
            TextureError::InvalidMipCount { mip_count } => {
                write!(f, "invalid mip count {mip_count}")
            }
            TextureError::InvalidFormatCode { code } => {
                write!(f, "invalid TextureFormat code {code}")
            }
            TextureError::ImageSizeMismatch { recorded, expected } => write!(
                f,
                "complete image size {recorded} != expected mip-chain size {expected}"
            ),
            TextureError::InvalidImageDataLength {
                length,
                complete_image_size,
            } => write!(
                f,
                "image data length {length} is neither 0 nor {complete_image_size}"
            ),
            TextureError::InvalidStreamingInfo { context } => {
                write!(f, "invalid streaming info: {context}")
            }
            TextureError::InvalidTrailingBytes { count } => {
                write!(f, "invalid trailing bytes: {count}")
            }
            TextureError::UnsupportedFormat { code } => {
                write!(
                    f,
                    "unsupported TextureFormat code {code} (supported: DXT1/DXT5 \
                     and the rung 2 uncompressed family)"
                )
            }
            TextureError::UnsupportedLayout { version } => {
                write!(f, "no pinned Texture2D layout for Unity version {version}")
            }
            TextureError::LimitExceeded { context } => {
                write!(f, "limit exceeded: {context}")
            }
            TextureError::ResourceUnavailable { context } => {
                write!(f, "resource unavailable: {context}")
            }
        }
    }
}

impl std::error::Error for TextureError {}

/// The pixel formats this codec decodes: the block
/// formats of rung 1 (DXT1/DXT5) and the uncompressed
/// family of rung 2. Channel layouts are Unity's public
/// TextureFormat documentation: byte and nibble order
/// follow the format name's channel order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelFormat {
    /// DXT1 (TextureFormat 10): 8 bytes per 4x4 block.
    Bc1,
    /// DXT5 (TextureFormat 12): 16 bytes per 4x4 block.
    Bc3,
    /// Alpha8 (TextureFormat 1): one alpha byte per pixel.
    Alpha8,
    /// ARGB4444 (TextureFormat 2): little-endian 16-bit,
    /// nibbles A, R, G, B from the high nibble down.
    Argb4444,
    /// RGB24 (TextureFormat 3): bytes R, G, B per pixel.
    Rgb24,
    /// RGBA32 (TextureFormat 4): bytes R, G, B, A per pixel.
    Rgba32,
    /// ARGB32 (TextureFormat 5): bytes A, R, G, B per pixel.
    Argb32,
    /// RGB565 (TextureFormat 7): little-endian 16-bit
    /// R5 G6 B5 (the BC endpoint layout).
    Rgb565,
    /// RGBA4444 (TextureFormat 13): little-endian 16-bit,
    /// nibbles R, G, B, A from the high nibble down.
    Rgba4444,
    /// RGBAHalf (TextureFormat 17): four IEEE 754 half
    /// floats (R, G, B, A) per pixel, 8 bytes.
    RgbaHalf,
    /// RFloat (TextureFormat 18): one IEEE 754 float
    /// (red) per pixel.
    RFloat,
    /// RGBAFloat (TextureFormat 20): four IEEE 754 floats
    /// (R, G, B, A) per pixel, 16 bytes.
    RgbaFloat,
    /// R8 (TextureFormat 63): one red byte per pixel.
    R8,
}

impl PixelFormat {
    /// Map a TextureFormat code to a decodable format.
    pub fn from_format_code(code: i32) -> Result<PixelFormat, TextureError> {
        match code {
            TEXTURE_FORMAT_DXT1 => Ok(PixelFormat::Bc1),
            TEXTURE_FORMAT_DXT5 => Ok(PixelFormat::Bc3),
            TEXTURE_FORMAT_ALPHA8 => Ok(PixelFormat::Alpha8),
            TEXTURE_FORMAT_ARGB4444 => Ok(PixelFormat::Argb4444),
            TEXTURE_FORMAT_RGB24 => Ok(PixelFormat::Rgb24),
            TEXTURE_FORMAT_RGBA32 => Ok(PixelFormat::Rgba32),
            TEXTURE_FORMAT_ARGB32 => Ok(PixelFormat::Argb32),
            TEXTURE_FORMAT_RGB565 => Ok(PixelFormat::Rgb565),
            TEXTURE_FORMAT_RGBA4444 => Ok(PixelFormat::Rgba4444),
            TEXTURE_FORMAT_RGBAHALF => Ok(PixelFormat::RgbaHalf),
            TEXTURE_FORMAT_RFLOAT => Ok(PixelFormat::RFloat),
            TEXTURE_FORMAT_RGBAFLOAT => Ok(PixelFormat::RgbaFloat),
            TEXTURE_FORMAT_R8 => Ok(PixelFormat::R8),
            _ => Err(TextureError::UnsupportedFormat { code }),
        }
    }

    /// The TextureFormat code of this format.
    pub fn format_code(self) -> i32 {
        match self {
            PixelFormat::Bc1 => TEXTURE_FORMAT_DXT1,
            PixelFormat::Bc3 => TEXTURE_FORMAT_DXT5,
            PixelFormat::Alpha8 => TEXTURE_FORMAT_ALPHA8,
            PixelFormat::Argb4444 => TEXTURE_FORMAT_ARGB4444,
            PixelFormat::Rgb24 => TEXTURE_FORMAT_RGB24,
            PixelFormat::Rgba32 => TEXTURE_FORMAT_RGBA32,
            PixelFormat::Argb32 => TEXTURE_FORMAT_ARGB32,
            PixelFormat::Rgb565 => TEXTURE_FORMAT_RGB565,
            PixelFormat::Rgba4444 => TEXTURE_FORMAT_RGBA4444,
            PixelFormat::RgbaHalf => TEXTURE_FORMAT_RGBAHALF,
            PixelFormat::RFloat => TEXTURE_FORMAT_RFLOAT,
            PixelFormat::RgbaFloat => TEXTURE_FORMAT_RGBAFLOAT,
            PixelFormat::R8 => TEXTURE_FORMAT_R8,
        }
    }

    /// Bytes per pixel for the uncompressed formats;
    /// `None` for the block-compressed formats, whose
    /// storage unit is the 4x4 block.
    pub fn bytes_per_pixel(self) -> Option<usize> {
        match self {
            PixelFormat::Bc1 | PixelFormat::Bc3 => None,
            PixelFormat::Alpha8 | PixelFormat::R8 => Some(1),
            PixelFormat::Argb4444 | PixelFormat::Rgb565 | PixelFormat::Rgba4444 => Some(2),
            PixelFormat::Rgb24 => Some(3),
            PixelFormat::Rgba32 | PixelFormat::Argb32 | PixelFormat::RFloat => Some(4),
            PixelFormat::RgbaHalf => Some(8),
            PixelFormat::RgbaFloat => Some(16),
        }
    }

    /// Bytes per 4x4 block for the block-compressed
    /// formats; `None` for the uncompressed formats.
    pub fn block_bytes(self) -> Option<usize> {
        match self {
            PixelFormat::Bc1 => Some(8),
            PixelFormat::Bc3 => Some(16),
            _ => None,
        }
    }

    /// Short name for records.
    pub fn name(self) -> &'static str {
        match self {
            PixelFormat::Bc1 => "DXT1",
            PixelFormat::Bc3 => "DXT5",
            PixelFormat::Alpha8 => "Alpha8",
            PixelFormat::Argb4444 => "ARGB4444",
            PixelFormat::Rgb24 => "RGB24",
            PixelFormat::Rgba32 => "RGBA32",
            PixelFormat::Argb32 => "ARGB32",
            PixelFormat::Rgb565 => "RGB565",
            PixelFormat::Rgba4444 => "RGBA4444",
            PixelFormat::RgbaHalf => "RGBAHalf",
            PixelFormat::RFloat => "RFloat",
            PixelFormat::RgbaFloat => "RGBAFloat",
            PixelFormat::R8 => "R8",
        }
    }
}

/// One serialized Texture2D layout, pinned per Unity era by
/// the rung 0 census (never raced per object).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextureLayout {
    /// Unity 5.x - 2017.1: fields directly after the name.
    Legacy,
    /// Unity 2017.4 - 2019.x: 8 prefix bytes, no mips-stripped.
    Legacy8,
    /// Unity 2020.x - 2022.x: 8 prefix bytes + mips-stripped.
    Modern,
    /// Unity 6000.x: 4 prefix bytes + mips-stripped.
    Unity6,
}

impl TextureLayout {
    /// Pin the layout for a SerializedFile generator version
    /// (the census era map). `None` = unmeasured era, a typed
    /// boundary for the caller, never a guess.
    pub fn pinned_for_generator_version(version: &str) -> Option<TextureLayout> {
        if version == "0.0.0" {
            // Measured in the census: files reporting 0.0.0
            // size-check as modern (296/296 exact).
            return Some(TextureLayout::Modern);
        }
        let mut parts = version.split('.');
        let major: i64 = parts.next()?.parse().ok()?;
        let minor: i64 = parts.next().unwrap_or("0").parse().ok()?;
        match (major, minor) {
            (5, _) | (2017, 0..=1) => Some(TextureLayout::Legacy),
            (2017, _) | (2018, _) | (2019, _) => Some(TextureLayout::Legacy8),
            (2020, _) | (2021, _) | (2022, _) => Some(TextureLayout::Modern),
            (6000, _) => Some(TextureLayout::Unity6),
            _ => None,
        }
    }

    /// Record name for manifests and the rung record.
    pub fn name(self) -> &'static str {
        match self {
            TextureLayout::Legacy => "legacy",
            TextureLayout::Legacy8 => "legacy8",
            TextureLayout::Modern => "modern",
            TextureLayout::Unity6 => "unity6",
        }
    }

    /// Bytes between the name and the width field.
    fn prefix_skip_bytes(self) -> usize {
        match self {
            TextureLayout::Legacy => 0,
            TextureLayout::Legacy8 | TextureLayout::Modern => 8,
            TextureLayout::Unity6 => 4,
        }
    }

    /// Whether an m_MipsStripped field sits between the
    /// complete image size and the format code.
    fn has_mips_stripped(self) -> bool {
        matches!(self, TextureLayout::Modern | TextureLayout::Unity6)
    }

    /// I32 words between the mip count and the image-data
    /// length (texture settings + state fields; measured per
    /// era from held titles' object bytes, rung record).
    fn tail_settings_words(self) -> usize {
        match self {
            TextureLayout::Legacy => 9,
            TextureLayout::Legacy8 => 12,
            TextureLayout::Modern => 13,
            TextureLayout::Unity6 => 15,
        }
    }

    /// Byte width of the StreamingInfo offset field.
    fn stream_offset_bytes(self) -> usize {
        match self {
            TextureLayout::Legacy | TextureLayout::Legacy8 => 4,
            TextureLayout::Modern | TextureLayout::Unity6 => 8,
        }
    }
}

/// Where a texture's image data lives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImagePlacement {
    /// Inline in the object payload (`m_ImageData`).
    Inline(Vec<u8>),
    /// In an external resource file (`.resS`), at a byte
    /// offset, with the resource path as recorded.
    Streamed {
        /// Byte offset inside the resource file.
        offset: u64,
        /// Byte count (== the complete image size).
        size: u32,
        /// The recorded resource path (e.g.
        /// `resources.assets.resS`, or an `archive:/` path
        /// for bundle-resident files).
        path: String,
    },
}

/// A parsed Texture2D object: metadata plus image-data
/// placement. Pixel decode is a separate step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Texture2dObject {
    /// The object's `m_Name`.
    pub name: String,
    /// Base-level width in pixels.
    pub width: u32,
    /// Base-level height in pixels.
    pub height: u32,
    /// The recorded `m_CompleteImageSize` (full mip chain).
    pub complete_image_size: u32,
    /// The raw TextureFormat code.
    pub format_code: i32,
    /// Number of mip levels in the chain.
    pub mip_count: u32,
    /// The pinned layout this object was parsed under.
    pub layout: TextureLayout,
    /// Inline bytes or the streaming location.
    pub placement: ImagePlacement,
}

/// A bounded cursor over one object payload.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    little: bool,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], little: bool) -> Cursor<'a> {
        Cursor {
            bytes,
            position: 0,
            little,
        }
    }

    fn read_i32(&mut self, context: &'static str) -> Result<i32, TextureError> {
        let raw = self
            .bytes
            .get(
                self.position
                    ..self
                        .position
                        .checked_add(4)
                        .ok_or(TextureError::LimitExceeded {
                            context: "offset arithmetic",
                        })?,
            )
            .ok_or(TextureError::Truncated { context })?;
        self.position += 4;
        Ok(if self.little {
            i32::from_le_bytes(raw.try_into().unwrap())
        } else {
            i32::from_be_bytes(raw.try_into().unwrap())
        })
    }

    fn read_u32(&mut self, context: &'static str) -> Result<u32, TextureError> {
        Ok(self.read_i32(context)? as u32)
    }

    fn skip(&mut self, count: usize, context: &'static str) -> Result<(), TextureError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(TextureError::LimitExceeded {
                context: "offset arithmetic",
            })?;
        if end > self.bytes.len() {
            return Err(TextureError::Truncated { context });
        }
        self.position = end;
        Ok(())
    }

    fn read_bytes(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<&'a [u8], TextureError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(TextureError::LimitExceeded {
                context: "offset arithmetic",
            })?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(TextureError::Truncated { context })?;
        self.position = end;
        Ok(slice)
    }

    /// Read a length-prefixed, 4-aligned serialized string
    /// (the SerializedFile string rule the census walk uses).
    fn read_string(&mut self, context: &'static str) -> Result<String, TextureError> {
        let field_start = self.position;
        let length = self.read_i32(context)?;
        if length < 0 {
            return Err(TextureError::Truncated { context });
        }
        let length = usize::try_from(length).map_err(|_| TextureError::LimitExceeded {
            context: "string length",
        })?;
        if length > self.bytes.len() {
            return Err(TextureError::Truncated { context });
        }
        let content = self.read_bytes(length, context)?;
        let text = String::from_utf8(content.to_vec()).map_err(|_| TextureError::Truncated {
            context: "string is not UTF-8",
        })?;
        // Strings are padded to a 4-byte boundary.
        let field_len = 4usize
            .checked_add(length)
            .ok_or(TextureError::LimitExceeded {
                context: "offset arithmetic",
            })?;
        let aligned_len = field_len
            .checked_add(3)
            .ok_or(TextureError::LimitExceeded {
                context: "offset arithmetic",
            })?
            / 4
            * 4;
        let target = field_start
            .checked_add(aligned_len)
            .ok_or(TextureError::LimitExceeded {
                context: "offset arithmetic",
            })?
            .min(self.bytes.len());
        self.position = target;
        Ok(text)
    }
}

/// Expected byte size of one mip level: whole 4x4
/// blocks for the block formats, an exact pixel count
/// times the bytes per pixel for the uncompressed
/// formats (no row padding in either family).
pub fn level_byte_size(format: PixelFormat, width: u32, height: u32) -> u64 {
    if let Some(bytes_per_pixel) = format.bytes_per_pixel() {
        return u64::from(width) * u64::from(height) * bytes_per_pixel as u64;
    }
    // Block formats: exactly one of the two size views is
    // `Some` per format by construction; a format with
    // neither would size to 0 and fail the caller's
    // size-arithmetic check as a typed mismatch.
    let block_bytes = format.block_bytes().unwrap_or(0) as u64;
    let blocks_x = u64::from(width.div_ceil(4));
    let blocks_y = u64::from(height.div_ceil(4));
    blocks_x * blocks_y * block_bytes
}

/// Dimensions of one mip level (halved, floored at 1).
pub fn level_dimensions(width: u32, height: u32, level: u32) -> (u32, u32) {
    ((width >> level).max(1), (height >> level).max(1))
}

/// Expected byte size of a full mip chain — the census
/// size-arithmetic check, reused as a parse-time invariant.
pub fn expected_image_size(format: PixelFormat, width: u32, height: u32, mip_count: u32) -> u64 {
    let mut total: u64 = 0;
    for level in 0..mip_count {
        let (w, h) = level_dimensions(width, height, level);
        total += level_byte_size(format, w, h);
    }
    total
}

/// Parse one Texture2D object payload under its era's
/// pinned layout. Validates dimensions, format window, mip
/// count, the size-arithmetic identity for supported formats, the
/// image-data length, and the StreamingInfo tail. Any
/// disagreement is a typed error — layouts are never raced.
pub fn parse_texture2d_object(
    payload: &[u8],
    little: bool,
    layout: TextureLayout,
) -> Result<Texture2dObject, TextureError> {
    let mut cursor = Cursor::new(payload, little);
    let name = cursor.read_string("texture name")?;
    cursor.skip(layout.prefix_skip_bytes(), "layout prefix")?;
    let width = cursor.read_i32("width")?;
    let height = cursor.read_i32("height")?;
    let complete_image_size = cursor.read_i32("complete image size")?;
    if layout.has_mips_stripped() {
        let _mips_stripped = cursor.read_i32("mips stripped")?;
    }
    let format_code = cursor.read_i32("format")?;
    let mip_count = cursor.read_i32("mip count")?;
    if !(0..=128).contains(&format_code) {
        return Err(TextureError::InvalidFormatCode { code: format_code });
    }
    if complete_image_size < 0 {
        return Err(TextureError::ImageSizeMismatch {
            recorded: i64::from(complete_image_size),
            expected: 0,
        });
    }
    if !(1..=TEXTURE_DIMENSION_MAX).contains(&width)
        || !(1..=TEXTURE_DIMENSION_MAX).contains(&height)
    {
        return Err(TextureError::InvalidDimensions { width, height });
    }
    let max_mips = 32 - (width.max(height) as u32).leading_zeros();
    if mip_count < 1 || mip_count as u32 > max_mips {
        return Err(TextureError::InvalidMipCount { mip_count });
    }
    let width_u = width as u32;
    let height_u = height as u32;
    let mip_count_u = mip_count as u32;
    if let Ok(format) = PixelFormat::from_format_code(format_code) {
        let expected = expected_image_size(format, width_u, height_u, mip_count_u);
        if expected != complete_image_size as u64 {
            return Err(TextureError::ImageSizeMismatch {
                recorded: i64::from(complete_image_size),
                expected,
            });
        }
    }
    cursor.skip(layout.tail_settings_words() * 4, "texture settings tail")?;
    let image_length = cursor.read_i32("image data length")?;
    let placement = if image_length == complete_image_size && image_length > 0 {
        let count = usize::try_from(image_length).map_err(|_| TextureError::LimitExceeded {
            context: "image data length",
        })?;
        if count > IMAGE_DATA_BYTES_MAX {
            return Err(TextureError::LimitExceeded {
                context: "image data bytes",
            });
        }
        let data = cursor.read_bytes(count, "inline image data")?.to_vec();
        let (offset, size, path) = read_streaming_info(&mut cursor, layout)?;
        if offset != 0 || size != 0 {
            return Err(TextureError::InvalidStreamingInfo {
                context: "inline texture carries a non-empty stream",
            });
        }
        let _ = path;
        ImagePlacement::Inline(data)
    } else if image_length == 0 {
        let (offset, size, path) = read_streaming_info(&mut cursor, layout)?;
        if size != complete_image_size as u32 {
            return Err(TextureError::InvalidStreamingInfo {
                context: "stream size != complete image size",
            });
        }
        if path.is_empty() {
            return Err(TextureError::InvalidStreamingInfo {
                context: "streamed texture names no resource path",
            });
        }
        ImagePlacement::Streamed { offset, size, path }
    } else {
        return Err(TextureError::InvalidImageDataLength {
            length: i64::from(image_length),
            complete_image_size,
        });
    };
    // Object payloads may carry zero padding after the
    // StreamingInfo (measured); anything else is a misparse.
    let trailing = payload.len() - cursor.position;
    if trailing > TRAILING_PAD_BYTES_MAX || payload[cursor.position..].iter().any(|byte| *byte != 0)
    {
        return Err(TextureError::InvalidTrailingBytes { count: trailing });
    }
    Ok(Texture2dObject {
        name,
        width: width_u,
        height: height_u,
        complete_image_size: complete_image_size as u32,
        format_code,
        mip_count: mip_count_u,
        layout,
        placement,
    })
}

/// Read the StreamingInfo tail: offset (era width), size,
/// then the resource path string.
fn read_streaming_info(
    cursor: &mut Cursor<'_>,
    layout: TextureLayout,
) -> Result<(u64, u32, String), TextureError> {
    let offset = if layout.stream_offset_bytes() == 8 {
        let low = u64::from(cursor.read_u32("stream offset")?);
        let high = u64::from(cursor.read_u32("stream offset")?);
        low | (high << 32)
    } else {
        u64::from(cursor.read_u32("stream offset")?)
    };
    let size = cursor.read_u32("stream size")?;
    let path = cursor.read_string("stream path")?;
    Ok((offset, size, path))
}

impl Texture2dObject {
    /// The full image-data bytes (the whole mip chain):
    /// inline bytes directly, streamed bytes sliced out of
    /// the caller-supplied resource file contents.
    pub fn image_data<'a>(&'a self, resource: Option<&'a [u8]>) -> Result<&'a [u8], TextureError> {
        match &self.placement {
            ImagePlacement::Inline(data) => Ok(data),
            ImagePlacement::Streamed { offset, size, .. } => {
                let resource = resource.ok_or(TextureError::ResourceUnavailable {
                    context: "streamed texture needs its resource bytes",
                })?;
                let start = usize::try_from(*offset).map_err(|_| TextureError::LimitExceeded {
                    context: "stream offset",
                })?;
                let end = start
                    .checked_add(*size as usize)
                    .ok_or(TextureError::LimitExceeded {
                        context: "stream range",
                    })?;
                resource
                    .get(start..end)
                    .ok_or(TextureError::ResourceUnavailable {
                        context: "stream range lies outside the resource",
                    })
            }
        }
    }

    /// Decode every mip level to RGBA, in chain order.
    /// `resource` is required iff the texture is streamed.
    pub fn decode_rgba(&self, resource: Option<&[u8]>) -> Result<Vec<DecodedLevel>, TextureError> {
        let format = PixelFormat::from_format_code(self.format_code)?;
        let data = self.image_data(resource)?;
        decode_mip_chain(format, data, self.width, self.height, self.mip_count)
    }
}

/// One decoded mip level: RGBA pixels in stored row order
/// (row 0 is the first row in the image data; orientation
/// against display order is a container convention the
/// differential harness pins, not a codec choice).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedLevel {
    /// Level width in pixels.
    pub width: u32,
    /// Level height in pixels.
    pub height: u32,
    /// RGBA bytes, `width * height * 4`, stored row order.
    pub rgba: Vec<u8>,
}

/// Decode a full mip chain of image data. The data length
/// must equal the expected chain size exactly.
pub fn decode_mip_chain(
    format: PixelFormat,
    data: &[u8],
    width: u32,
    height: u32,
    mip_count: u32,
) -> Result<Vec<DecodedLevel>, TextureError> {
    if width == 0
        || height == 0
        || width > TEXTURE_DIMENSION_MAX as u32
        || height > TEXTURE_DIMENSION_MAX as u32
    {
        return Err(TextureError::InvalidDimensions {
            width: width as i32,
            height: height as i32,
        });
    }
    let expected = expected_image_size(format, width, height, mip_count);
    if data.len() as u64 != expected {
        return Err(TextureError::ImageSizeMismatch {
            recorded: data.len() as i64,
            expected,
        });
    }
    let mut levels = Vec::with_capacity(mip_count as usize);
    let mut offset: usize = 0;
    for level in 0..mip_count {
        let (level_w, level_h) = level_dimensions(width, height, level);
        let size = usize::try_from(level_byte_size(format, level_w, level_h)).map_err(|_| {
            TextureError::LimitExceeded {
                context: "level size",
            }
        })?;
        let slice = data
            .get(offset..offset + size)
            .ok_or(TextureError::Truncated {
                context: "mip level data",
            })?;
        levels.push(decode_level(format, slice, level_w, level_h)?);
        offset += size;
    }
    Ok(levels)
}

/// Decode one mip level's image data to RGBA. The data
/// length must equal the level's expected byte size.
pub fn decode_level(
    format: PixelFormat,
    data: &[u8],
    width: u32,
    height: u32,
) -> Result<DecodedLevel, TextureError> {
    let expected = level_byte_size(format, width, height);
    if data.len() as u64 != expected {
        return Err(TextureError::ImageSizeMismatch {
            recorded: data.len() as i64,
            expected,
        });
    }
    let pixel_count =
        (width as usize)
            .checked_mul(height as usize)
            .ok_or(TextureError::LimitExceeded {
                context: "pixel count",
            })?;
    let output_bytes = pixel_count
        .checked_mul(4)
        .ok_or(TextureError::LimitExceeded {
            context: "output size",
        })?;
    if output_bytes > DECODED_BYTES_MAX {
        return Err(TextureError::LimitExceeded {
            context: "decoded bytes",
        });
    }
    let mut rgba = vec![0_u8; output_bytes];
    match format {
        PixelFormat::Bc1 | PixelFormat::Bc3 => {
            decode_block_level(format, data, width, height, &mut rgba);
        }
        _ => decode_plain_level(format, data, &mut rgba),
    }
    Ok(DecodedLevel {
        width,
        height,
        rgba,
    })
}

/// Decode one mip level of a block format into `rgba`
/// (the rung 1 path: per-block decode, then copy out the
/// visible texels of each padded 4x4 block).
fn decode_block_level(format: PixelFormat, data: &[u8], width: u32, height: u32, rgba: &mut [u8]) {
    let block_bytes = match format {
        PixelFormat::Bc1 => 8,
        PixelFormat::Bc3 => 16,
        _ => return,
    };
    let blocks_x = width.div_ceil(4) as usize;
    for block_y in 0..height.div_ceil(4) as usize {
        for block_x in 0..blocks_x {
            let block_index = block_y * blocks_x + block_x;
            let start = block_index * block_bytes;
            let block = &data[start..start + block_bytes];
            let mut pixels = [0_u8; 64];
            if format == PixelFormat::Bc1 {
                decode_color_block(block, false, &mut pixels);
            } else {
                decode_bc3_block(block, &mut pixels);
            }
            // Copy the block's visible texels (levels whose
            // dimensions are not multiples of 4 are padded;
            // the padding texels are not part of the level).
            for texel_y in 0..4_usize {
                let y = block_y * 4 + texel_y;
                if y >= height as usize {
                    break;
                }
                for texel_x in 0..4_usize {
                    let x = block_x * 4 + texel_x;
                    if x >= width as usize {
                        break;
                    }
                    let source = (texel_y * 4 + texel_x) * 4;
                    let target = (y * width as usize + x) * 4;
                    rgba[target..target + 4].copy_from_slice(&pixels[source..source + 4]);
                }
            }
        }
    }
}

/// Decode one mip level of an uncompressed format into
/// `rgba`. The caller has checked `data.len()` equals
/// `width * height * bytes_per_pixel`, so the exact-size
/// chunk iterators below cover every pixel exactly.
/// Channel conventions the differential pins are stated
/// per format in the rung 2 record: single-channel
/// formats carry their value in the named channel with
/// the remaining color channels 0 (R8 in red, Alpha8 in
/// alpha over black), and float channels convert by
/// clamping to [0, 1], scaling by 255, and truncating.
fn decode_plain_level(format: PixelFormat, data: &[u8], rgba: &mut [u8]) {
    match format {
        PixelFormat::Rgba32 => rgba.copy_from_slice(data),
        PixelFormat::Argb32 => {
            for (source, target) in data
                .as_chunks::<4>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                target[0] = source[1];
                target[1] = source[2];
                target[2] = source[3];
                target[3] = source[0];
            }
        }
        PixelFormat::Rgb24 => {
            for (source, target) in data
                .as_chunks::<3>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                target[0] = source[0];
                target[1] = source[1];
                target[2] = source[2];
                target[3] = 255;
            }
        }
        PixelFormat::Alpha8 => {
            for (source, target) in data.iter().zip(rgba.as_chunks_mut::<4>().0.iter_mut()) {
                target[0] = 0;
                target[1] = 0;
                target[2] = 0;
                target[3] = *source;
            }
        }
        PixelFormat::Rgb565 => {
            for (source, target) in data
                .as_chunks::<2>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let [red, green, blue] =
                    expand_565_plain(u16::from_le_bytes([source[0], source[1]]));
                target[0] = red;
                target[1] = green;
                target[2] = blue;
                target[3] = 255;
            }
        }
        PixelFormat::Argb4444 => {
            for (source, target) in data
                .as_chunks::<2>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let value = u16::from_le_bytes([source[0], source[1]]);
                target[0] = expand_4444(value >> 8);
                target[1] = expand_4444(value >> 4);
                target[2] = expand_4444(value);
                target[3] = expand_4444(value >> 12);
            }
        }
        PixelFormat::Rgba4444 => {
            for (source, target) in data
                .as_chunks::<2>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let value = u16::from_le_bytes([source[0], source[1]]);
                target[0] = expand_4444(value >> 12);
                target[1] = expand_4444(value >> 8);
                target[2] = expand_4444(value >> 4);
                target[3] = expand_4444(value);
            }
        }
        PixelFormat::R8 => {
            for (source, target) in data.iter().zip(rgba.as_chunks_mut::<4>().0.iter_mut()) {
                target[0] = *source;
                target[1] = 0;
                target[2] = 0;
                target[3] = 255;
            }
        }
        PixelFormat::RgbaHalf => {
            for (source, target) in data
                .as_chunks::<8>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let pixel: [u8; 4] = std::array::from_fn(|channel| {
                    let bits = u16::from_le_bytes([source[channel * 2], source[channel * 2 + 1]]);
                    float_to_byte(half_to_f32(bits))
                });
                target.copy_from_slice(&pixel);
            }
        }
        PixelFormat::RFloat => {
            for (source, target) in data
                .as_chunks::<4>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let value = f32::from_le_bytes([source[0], source[1], source[2], source[3]]);
                target[0] = float_to_byte(value);
                target[1] = 0;
                target[2] = 0;
                target[3] = 255;
            }
        }
        PixelFormat::RgbaFloat => {
            for (source, target) in data
                .as_chunks::<16>()
                .0
                .iter()
                .zip(rgba.as_chunks_mut::<4>().0.iter_mut())
            {
                let pixel: [u8; 4] = std::array::from_fn(|channel| {
                    let start = channel * 4;
                    float_to_byte(f32::from_le_bytes([
                        source[start],
                        source[start + 1],
                        source[start + 2],
                        source[start + 3],
                    ]))
                });
                target.copy_from_slice(&pixel);
            }
        }
        PixelFormat::Bc1 | PixelFormat::Bc3 => {}
    }
}

/// Expand one RGB565 value on the *plain* RGB565 path:
/// shift-only expansion (red/blue << 3, green << 2, no
/// bit replication). The rung 2 differential pinned
/// this against the oracle for the plain format; the
/// BC endpoint path keeps bit replication
/// (`expand_565`), which rung 1 pinned on its own
/// fixtures. The two conversions genuinely differ —
/// at the maximum value, shift gives (248, 252, 248)
/// where replication gives (255, 255, 255).
fn expand_565_plain(value: u16) -> [u8; 3] {
    let red5 = (value >> 11) & 0x1f;
    let green6 = (value >> 5) & 0x3f;
    let blue5 = value & 0x1f;
    [(red5 << 3) as u8, (green6 << 2) as u8, (blue5 << 3) as u8]
}

/// Expand one 4-bit channel to 8 bits (bit replication:
/// `n -> (n << 4) | n`).
fn expand_4444(nibble: u16) -> u8 {
    let nibble = nibble & 0x0f;
    ((nibble << 4) | nibble) as u8
}

/// Widen one IEEE 754 half-precision float to f32. The
/// widening is exact: every half value (subnormals,
/// infinities, NaNs included) is representable in f32.
fn half_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exponent = i32::from((bits >> 10) & 0x1f);
    let fraction = u32::from(bits & 0x03ff);
    if exponent == 0 {
        if fraction == 0 {
            return f32::from_bits(sign);
        }
        // Subnormal half: shift the fraction until its
        // leading bit reaches the implicit position.
        let mut shift = 0_u32;
        let mut significand = fraction;
        while significand & 0x0400 == 0 {
            significand <<= 1;
            shift += 1;
        }
        significand &= 0x03ff;
        // Value exponent is -14 - shift; the f32 field
        // adds the 127 bias.
        return f32::from_bits(sign | ((113 - shift) << 23) | (significand << 13));
    }
    if exponent == 31 {
        // Infinity or NaN; the fraction rides along so a
        // NaN stays a NaN through the widening.
        return f32::from_bits(sign | (0xff << 23) | (fraction << 13));
    }
    // Normal: rebias the exponent (-15 half bias, +127
    // f32 bias) and widen the fraction field.
    f32::from_bits(sign | (((exponent + 112) as u32) << 23) | (fraction << 13))
}

/// Convert one float channel to a byte: NaN reads as 0,
/// the value clamps to [0, 1], scales by 255, and
/// truncates (the conversion the rung 2 differential
/// pinned against the oracle on 144 RGBAHalf lightmaps:
/// the rounding variant missed on essentially every
/// non-extreme texel, the truncating variant is exact).
fn float_to_byte(value: f32) -> u8 {
    if value.is_nan() {
        return 0;
    }
    (value.clamp(0.0, 1.0) * 255.0) as u8
}

/// Expand one RGB565 endpoint to 8-bit channels (bit
/// replication, the S3TC cross-reference rule).
fn expand_565(value: u16) -> [u8; 3] {
    let red5 = (value >> 11) & 0x1f;
    let green6 = (value >> 5) & 0x3f;
    let blue5 = value & 0x1f;
    [
        ((red5 << 3) | (red5 >> 2)) as u8,
        ((green6 << 2) | (green6 >> 4)) as u8,
        ((blue5 << 3) | (blue5 >> 2)) as u8,
    ]
}

/// Build the four-color palette for one color block.
/// `force_four_color` is the BC3 rule: its color block is
/// always decoded in the four-color form, whatever the
/// endpoint order (Microsoft BC3 section: the color data
/// uses the BC1 layout with the four-color form).
fn color_palette(color_0: u16, color_1: u16, force_four_color: bool) -> [[u8; 4]; 4] {
    let first = expand_565(color_0);
    let second = expand_565(color_1);
    let mut palette = [[0_u8; 4]; 4];
    palette[0] = [first[0], first[1], first[2], 255];
    palette[1] = [second[0], second[1], second[2], 255];
    if force_four_color || color_0 > color_1 {
        for channel in 0..3 {
            palette[2][channel] =
                ((2 * u16::from(first[channel]) + u16::from(second[channel])) / 3) as u8;
            palette[3][channel] =
                ((u16::from(first[channel]) + 2 * u16::from(second[channel])) / 3) as u8;
        }
        palette[2][3] = 255;
        palette[3][3] = 255;
    } else {
        for channel in 0..3 {
            palette[2][channel] =
                ((u16::from(first[channel]) + u16::from(second[channel])) / 2) as u8;
        }
        palette[2][3] = 255;
        palette[3] = [0, 0, 0, 0];
    }
    palette
}

/// Decode one 8-byte color block (BC1 form) into 16 RGBA
/// pixels (row-major, 64 bytes).
fn decode_color_block(block: &[u8], force_four_color: bool, out: &mut [u8; 64]) {
    debug_assert!(block.len() >= 8);
    let color_0 = u16::from_le_bytes([block[0], block[1]]);
    let color_1 = u16::from_le_bytes([block[2], block[3]]);
    let palette = color_palette(color_0, color_1, force_four_color);
    let indices = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
    for pixel in 0..16_usize {
        let index = ((indices >> (pixel * 2)) & 0x3) as usize;
        out[pixel * 4..pixel * 4 + 4].copy_from_slice(&palette[index]);
    }
}

/// Decode one 16-byte BC3 block: the 8-byte interpolated
/// alpha block, then the 8-byte color block (four-color
/// form always).
fn decode_bc3_block(block: &[u8], out: &mut [u8; 64]) {
    debug_assert!(block.len() >= 16);
    let alpha_0 = block[0];
    let alpha_1 = block[1];
    let mut alphas = [0_u8; 8];
    alphas[0] = alpha_0;
    alphas[1] = alpha_1;
    if alpha_0 > alpha_1 {
        for (index, slot) in alphas.iter_mut().enumerate().skip(2) {
            *slot = (((8 - index) * usize::from(alpha_0) + (index - 1) * usize::from(alpha_1)) / 7)
                as u8;
        }
    } else {
        for (index, slot) in alphas.iter_mut().enumerate().skip(2).take(4) {
            *slot = (((6 - index) * usize::from(alpha_0) + (index - 1) * usize::from(alpha_1)) / 5)
                as u8;
        }
        alphas[6] = 0;
        alphas[7] = 255;
    }
    let mut alpha_bits: u64 = 0;
    for (position, byte) in block[2..8].iter().enumerate() {
        alpha_bits |= u64::from(*byte) << (position * 8);
    }
    decode_color_block(&block[8..16], true, out);
    for pixel in 0..16_usize {
        let index = ((alpha_bits >> (pixel * 3)) & 0x7) as usize;
        out[pixel * 4 + 3] = alphas[index];
    }
}

/// Decode every supported-format Texture2D in the loose
/// SerializedFiles under a target directory (or a single
/// .assets target) into per-level `.rgba` files plus a JSON
/// manifest. Observe-class: default-deny, named in
/// allow_tools. Streamed textures resolve only against a
/// sibling resource file; bundle targets and `archive:/`
/// stream paths are recorded as unsupported, never guessed.
pub fn decode_unity_textures(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let out_dir = paths::validate_output_dir(config, Path::new(require_str(args, "output_dir")?))?;
    std::fs::create_dir_all(&out_dir).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot create output dir: {error}"),
        )
    })?;
    let mut files: Vec<PathBuf> = Vec::new();
    if target.is_file() {
        files.push(target.clone());
    } else {
        collect_assets_files(&target, 0, &mut files)?;
    }
    files.sort();
    let mut entries: Vec<Value> = Vec::new();
    let mut written_bytes: u64 = 0;
    let mut decoded: u64 = 0;
    let mut unsupported: u64 = 0;
    for file in &files {
        let bytes = std::fs::read(file).map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot read {}: {error}", file.display()),
            )
        })?;
        let summary = match parse_serialized_file_capped(&bytes, UNITY_OBJECTS_MAX) {
            Ok(summary) => summary,
            Err(_) => continue,
        };
        let version = summary.unity_version.clone().unwrap_or_default();
        let layout = TextureLayout::pinned_for_generator_version(&version);
        // Resource bytes are loaded lazily, once per file,
        // only if a streamed texture names a sibling.
        let mut resource_cache: Vec<(String, Vec<u8>)> = Vec::new();
        for payload in &summary.payloads {
            if payload.class_id != CLASS_TEXTURE_2D {
                continue;
            }
            let Some(slice) = object_slice(&summary, &bytes, payload.byte_start, payload.byte_size)
            else {
                continue;
            };
            let mut entry = json!({
                "file": file.display().to_string(),
                "path_id": payload.path_id,
                "unity_version": version,
            });
            let Some(layout) = layout else {
                entry["status"] = json!("unsupported_layout");
                unsupported += 1;
                entries.push(entry);
                continue;
            };
            entry["layout"] = json!(layout.name());
            match parse_texture2d_object(slice, summary.little, layout) {
                Ok(object) => {
                    entry["name"] = json!(object.name);
                    entry["format"] = json!(object.format_code);
                    entry["width"] = json!(object.width);
                    entry["height"] = json!(object.height);
                    entry["mip_count"] = json!(object.mip_count);
                    let resource = match resolve_resource(&object, file, &mut resource_cache) {
                        Ok(resource) => resource,
                        Err(note) => {
                            entry["status"] = json!("resource_unavailable");
                            entry["note"] = json!(note);
                            unsupported += 1;
                            entries.push(entry);
                            continue;
                        }
                    };
                    match object.decode_rgba(resource.as_deref()) {
                        Ok(levels) => {
                            let mut level_entries = Vec::new();
                            for (index, level) in levels.iter().enumerate() {
                                let file_name = format!(
                                    "{}_{}_l{}.rgba",
                                    safe_component(&object.name, payload.path_id),
                                    payload.path_id,
                                    index
                                );
                                let size = level.rgba.len() as u64;
                                if written_bytes + size > UNITY_EXTRACT_BYTES_MAX {
                                    return Err(FathomError::new(
                                        ErrorCode::ResourceConstraint,
                                        "decode output budget exhausted",
                                    ));
                                }
                                std::fs::write(out_dir.join(&file_name), &level.rgba).map_err(
                                    |error| {
                                        FathomError::new(
                                            ErrorCode::TargetUnavailable,
                                            format!("cannot write {file_name}: {error}"),
                                        )
                                    },
                                )?;
                                written_bytes += size;
                                level_entries.push(json!({
                                    "file": file_name,
                                    "width": level.width,
                                    "height": level.height,
                                    "sha256": sha256_hex(&level.rgba),
                                }));
                            }
                            entry["levels"] = json!(level_entries);
                            entry["status"] = json!("decoded");
                            decoded += 1;
                        }
                        Err(error) => {
                            entry["status"] = json!("unsupported_format");
                            entry["note"] = json!(error.to_string());
                            unsupported += 1;
                        }
                    }
                }
                Err(error) => {
                    entry["status"] = json!("parse_failed");
                    entry["note"] = json!(error.to_string());
                    unsupported += 1;
                }
            }
            entries.push(entry);
        }
    }
    Ok(json!({
        "target": target.display().to_string(),
        "files": files.len(),
        "textures_decoded": decoded,
        "textures_unsupported": unsupported,
        "bytes_written": written_bytes,
        "entries": entries,
    }))
}

/// Slice one object's payload out of its SerializedFile
/// bytes (the same range arithmetic the extract lane uses).
fn object_slice<'a>(
    summary: &crate::unity::SfSummary,
    bytes: &'a [u8],
    byte_start: u64,
    byte_size: u32,
) -> Option<&'a [u8]> {
    let start = usize::try_from(summary.data_offset.checked_add(byte_start)?).ok()?;
    let end = start.checked_add(byte_size as usize)?;
    bytes.get(start..end)
}

/// Collect `.assets` files below a directory, bounded.
fn collect_assets_files(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
) -> Result<(), FathomError> {
    if depth > TOOL_WALK_DEPTH_MAX || out.len() >= TOOL_FILES_MAX {
        return Ok(());
    }
    let read = std::fs::read_dir(dir).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot list {}: {error}", dir.display()),
        )
    })?;
    let mut children: Vec<PathBuf> = read.flatten().map(|entry| entry.path()).collect();
    children.sort();
    for child in children {
        if child.is_dir() {
            collect_assets_files(&child, depth + 1, out)?;
        } else if child
            .extension()
            .map(|ext| ext.eq_ignore_ascii_case("assets"))
            .unwrap_or(false)
            && out.len() < TOOL_FILES_MAX
        {
            out.push(child);
        }
    }
    Ok(())
}

/// Resolve a streamed texture's resource bytes from the
/// sibling file next to its SerializedFile. Inline textures
/// need nothing. `archive:/` paths (bundle-resident) are a
/// stated boundary: they name no sibling file.
fn resolve_resource(
    object: &Texture2dObject,
    sf_file: &Path,
    cache: &mut Vec<(String, Vec<u8>)>,
) -> Result<Option<Vec<u8>>, String> {
    let ImagePlacement::Streamed { path, .. } = &object.placement else {
        return Ok(None);
    };
    if path.contains(':') || (path.contains('/') && !path.ends_with(".resS")) {
        return Err(format!("stream path {path} is not a sibling resource"));
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    if let Some((_, bytes)) = cache.iter().find(|(name, _)| name == base) {
        return Ok(Some(bytes.clone()));
    }
    let resource_path = sf_file.with_file_name(base);
    let bytes = std::fs::read(&resource_path)
        .map_err(|error| format!("cannot read resource {base}: {error}"))?;
    cache.push((base.to_string(), bytes.clone()));
    Ok(Some(bytes))
}

/// Reduce a texture name to one safe file-name component
/// (mirrors the extract lane's rule).
fn safe_component(name: &str, path_id: i64) -> String {
    let out: String = name
        .chars()
        .take(96)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out.chars().all(|c| c == '.') {
        return format!("texture2d_{path_id}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- validation: block decode against the spec ----

    fn block_with_palette_indices(color_0: u16, color_1: u16, indices: u32) -> [u8; 8] {
        let mut block = [0_u8; 8];
        block[0..2].copy_from_slice(&color_0.to_le_bytes());
        block[2..4].copy_from_slice(&color_1.to_le_bytes());
        block[4..8].copy_from_slice(&indices.to_le_bytes());
        block
    }

    #[test]
    fn validation_bc1_four_color_interpolation() {
        // color_0 = pure red (0xF800), color_1 = pure blue
        // (0x001F); color_0 > color_1 selects four colors.
        // Indices: pixel0 -> 0, pixel1 -> 1, pixel2 -> 2,
        // pixel3 -> 3, the rest -> 0.
        let block = block_with_palette_indices(0xF800, 0x001F, 0b11_10_01_00);
        let level = decode_level(PixelFormat::Bc1, &block, 4, 4).unwrap();
        assert_eq!(&level.rgba[0..4], &[255, 0, 0, 255]);
        assert_eq!(&level.rgba[4..8], &[0, 0, 255, 255]);
        // (2*255 + 0)/3 = 170, (2*0 + 255)/3 = 85.
        assert_eq!(&level.rgba[8..12], &[170, 0, 85, 255]);
        // (255 + 2*0)/3 = 85, (0 + 2*255)/3 = 170.
        assert_eq!(&level.rgba[12..16], &[85, 0, 170, 255]);
    }

    #[test]
    fn validation_bc1_three_color_and_transparent() {
        // color_0 (black, 0x0000) <= color_1 (white,
        // 0xFFFF): three colors + transparent.
        let block = block_with_palette_indices(0x0000, 0xFFFF, 0b11_10_01_00);
        let level = decode_level(PixelFormat::Bc1, &block, 4, 4).unwrap();
        assert_eq!(&level.rgba[0..4], &[0, 0, 0, 255]);
        assert_eq!(&level.rgba[4..8], &[255, 255, 255, 255]);
        // (0 + 255)/2 = 127 per channel (integer division).
        assert_eq!(&level.rgba[8..12], &[127, 127, 127, 255]);
        assert_eq!(&level.rgba[12..16], &[0, 0, 0, 0]);
    }

    #[test]
    fn validation_bc3_alpha_tables_both_orders() {
        // Alpha endpoints 255 > 0: six interpolated values
        // (6*255)/7 = 218, (5*255)/7 = 182, (4*255)/7 = 145,
        // (3*255)/7 = 109, (2*255)/7 = 72, (255)/7 = 36.
        let mut block = [0_u8; 16];
        block[0] = 255;
        block[1] = 0;
        // Alpha indices for pixels 0..8: 0,1,2,3,4,5,6,7
        // packed 3 bits each, little-endian.
        let mut bits: u64 = 0;
        for pixel in 0..8_u64 {
            bits |= pixel << (pixel * 3);
        }
        block[2..8].copy_from_slice(&bits.to_le_bytes()[0..6]);
        // Color block: solid endpoints so RGB is uniform.
        block[8..10].copy_from_slice(&0xF800_u16.to_le_bytes());
        block[10..12].copy_from_slice(&0xF800_u16.to_le_bytes());
        let level = decode_level(PixelFormat::Bc3, &block, 4, 4).unwrap();
        let alphas: Vec<u8> = (0..8).map(|i| level.rgba[i * 4 + 3]).collect();
        assert_eq!(alphas, vec![255, 0, 218, 182, 145, 109, 72, 36]);
        // Reversed endpoints (0 <= 255): four interpolated
        // values plus the 0 / 255 pair at indices 6 / 7.
        block[0] = 0;
        block[1] = 255;
        let level = decode_level(PixelFormat::Bc3, &block, 4, 4).unwrap();
        let alphas: Vec<u8> = (0..8).map(|i| level.rgba[i * 4 + 3]).collect();
        assert_eq!(alphas, vec![0, 255, 51, 102, 153, 204, 0, 255]);
    }

    #[test]
    fn validation_bc3_color_ignores_endpoint_order() {
        // In BC3 the color block always uses the four-color
        // form, even with color_0 <= color_1.
        let mut block = [0_u8; 16];
        block[0] = 255; // alpha endpoints: opaque everywhere
        block[1] = 255;
        block[8..10].copy_from_slice(&0x0000_u16.to_le_bytes());
        block[10..12].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        // Pixel 0 uses index 3 -> (0 + 2*255)/3 = 170.
        block[12..16].copy_from_slice(&0b11_u32.to_le_bytes());
        let level = decode_level(PixelFormat::Bc3, &block, 4, 4).unwrap();
        assert_eq!(&level.rgba[0..4], &[170, 170, 170, 255]);
    }

    #[test]
    fn validation_non_multiple_of_four_dimensions_clip() {
        // A 5x3 BC1 texture is stored as 2x1 blocks; only
        // the 15 visible texels land in the output.
        let block = block_with_palette_indices(0xF800, 0xF800, 0);
        let mut data = Vec::new();
        data.extend_from_slice(&block);
        data.extend_from_slice(&block);
        let level = decode_level(PixelFormat::Bc1, &data, 5, 3).unwrap();
        assert_eq!(level.rgba.len(), 5 * 3 * 4);
        assert!(
            level
                .rgba
                .as_chunks::<4>()
                .0
                .iter()
                .all(|px| *px == [255, 0, 0, 255])
        );
    }

    #[test]
    fn validation_mip_chain_sizes_and_levels() {
        // 8x8 DXT1, 4 levels: 32 + 8 + 8 + 8 = 56 bytes.
        assert_eq!(expected_image_size(PixelFormat::Bc1, 8, 8, 4), 56);
        let data = vec![0_u8; 56];
        let levels = decode_mip_chain(PixelFormat::Bc1, &data, 8, 8, 4).unwrap();
        assert_eq!(levels.len(), 4);
        assert_eq!((levels[3].width, levels[3].height), (1, 1));
    }

    #[test]
    fn validation_layout_pinning_era_map() {
        assert_eq!(
            TextureLayout::pinned_for_generator_version("5.6.5f1"),
            Some(TextureLayout::Legacy)
        );
        assert_eq!(
            TextureLayout::pinned_for_generator_version("2017.1.1f1"),
            Some(TextureLayout::Legacy)
        );
        assert_eq!(
            TextureLayout::pinned_for_generator_version("2019.4.40f1c1"),
            Some(TextureLayout::Legacy8)
        );
        assert_eq!(
            TextureLayout::pinned_for_generator_version("2021.3.13f1c1"),
            Some(TextureLayout::Modern)
        );
        assert_eq!(
            TextureLayout::pinned_for_generator_version("6000.3.5f2"),
            Some(TextureLayout::Unity6)
        );
        assert_eq!(
            TextureLayout::pinned_for_generator_version("0.0.0"),
            Some(TextureLayout::Modern)
        );
        assert_eq!(TextureLayout::pinned_for_generator_version("4.6.0f1"), None);
        assert_eq!(TextureLayout::pinned_for_generator_version("garbage"), None);
    }

    // ---- validation: object parse (synthetic payloads) ----

    /// Build a synthetic Texture2D object payload under one
    /// layout: name, prefix, fields, settings tail, image
    /// data (inline) or a stream tail.
    fn synthetic_object(
        layout: TextureLayout,
        format: i32,
        width: i32,
        height: i32,
        mip_count: i32,
        image: &[u8],
        streamed: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let name = b"Synth";
        out.extend_from_slice(&(name.len() as i32).to_le_bytes());
        out.extend_from_slice(name);
        out.push(0); // align 5+4=9 -> 12
        out.extend_from_slice(&[0_u8; 2]);
        assert_eq!(out.len(), 12);
        out.extend_from_slice(&vec![0_u8; layout.prefix_skip_bytes()]);
        let pixel_format = PixelFormat::from_format_code(format).unwrap();
        let complete =
            expected_image_size(pixel_format, width as u32, height as u32, mip_count as u32) as i32;
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&complete.to_le_bytes());
        if layout.has_mips_stripped() {
            out.extend_from_slice(&0_i32.to_le_bytes());
        }
        out.extend_from_slice(&format.to_le_bytes());
        out.extend_from_slice(&mip_count.to_le_bytes());
        out.extend_from_slice(&vec![0_u8; layout.tail_settings_words() * 4]);
        if streamed {
            out.extend_from_slice(&0_i32.to_le_bytes());
            match layout.stream_offset_bytes() {
                8 => out.extend_from_slice(&64_u64.to_le_bytes()),
                _ => out.extend_from_slice(&64_u32.to_le_bytes()),
            }
            out.extend_from_slice(&complete.to_le_bytes());
            let path = b"resources.assets.resS";
            out.extend_from_slice(&(path.len() as i32).to_le_bytes());
            out.extend_from_slice(path);
            out.extend_from_slice(&[0_u8; 3]); // align 21 -> 24
        } else {
            out.extend_from_slice(&(image.len() as i32).to_le_bytes());
            out.extend_from_slice(image);
            match layout.stream_offset_bytes() {
                8 => out.extend_from_slice(&0_u64.to_le_bytes()),
                _ => out.extend_from_slice(&0_u32.to_le_bytes()),
            }
            out.extend_from_slice(&0_i32.to_le_bytes());
            out.extend_from_slice(&0_i32.to_le_bytes());
        }
        out
    }

    #[test]
    fn validation_parse_inline_and_streamed_objects() {
        for layout in [
            TextureLayout::Legacy,
            TextureLayout::Legacy8,
            TextureLayout::Modern,
            TextureLayout::Unity6,
        ] {
            let image = vec![0_u8; 32]; // 8x8 DXT1, 1 mip
            let payload = synthetic_object(layout, 10, 8, 8, 1, &image, false);
            let object = parse_texture2d_object(&payload, true, layout).unwrap();
            assert_eq!(object.name, "Synth");
            assert_eq!(object.placement, ImagePlacement::Inline(image.clone()));
            let levels = object.decode_rgba(None).unwrap();
            assert_eq!(levels.len(), 1);

            let payload = synthetic_object(layout, 10, 8, 8, 1, &[], true);
            let object = parse_texture2d_object(&payload, true, layout).unwrap();
            match &object.placement {
                ImagePlacement::Streamed { offset, size, path } => {
                    assert_eq!(*offset, 64);
                    assert_eq!(*size, 32);
                    assert_eq!(path, "resources.assets.resS");
                }
                other => panic!("expected streamed placement, got {other:?}"),
            }
            let mut resource = vec![0_u8; 64];
            resource.extend_from_slice(&image);
            let data = object.image_data(Some(&resource)).unwrap();
            assert_eq!(data, &image[..]);
        }
    }

    // ---- validation: the rung 2 uncompressed family ----

    #[test]
    fn validation_rgba32_identity_and_argb32_swizzle() {
        // Two pixels whose channel values are all distinct,
        // so any byte-order error shows.
        let level =
            decode_level(PixelFormat::Rgba32, &[10, 20, 30, 40, 50, 60, 70, 80], 2, 1).unwrap();
        assert_eq!(level.rgba, vec![10, 20, 30, 40, 50, 60, 70, 80]);
        // ARGB32 stores A first: [40, 10, 20, 30] decodes to
        // R=10, G=20, B=30, A=40.
        let level =
            decode_level(PixelFormat::Argb32, &[40, 10, 20, 30, 80, 50, 60, 70], 2, 1).unwrap();
        assert_eq!(level.rgba, vec![10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn validation_rgb24_alpha_fill() {
        let level = decode_level(PixelFormat::Rgb24, &[1, 2, 3, 4, 5, 6], 2, 1).unwrap();
        assert_eq!(level.rgba, vec![1, 2, 3, 255, 4, 5, 6, 255]);
    }

    #[test]
    fn validation_alpha8_and_r8_channel_conventions() {
        // Alpha8: black under the recorded alpha (the
        // convention the rung 2 differential pinned on
        // 323 real textures).
        let level = decode_level(PixelFormat::Alpha8, &[7, 200], 2, 1).unwrap();
        assert_eq!(level.rgba, vec![0, 0, 0, 7, 0, 0, 0, 200]);
        // R8: the value rides in red; green/blue are 0.
        let level = decode_level(PixelFormat::R8, &[7, 200], 2, 1).unwrap();
        assert_eq!(level.rgba, vec![7, 0, 0, 255, 200, 0, 0, 255]);
    }

    #[test]
    fn validation_rgb565_expansion() {
        // The plain-format expansion is shift-only (the
        // rung 2 differential pin): pure red 0xF800 ->
        // 31<<3 = 248, pure green 0x07E0 -> 63<<2 = 252,
        // and the mid value 0x8410 (R5=16, G6=32, B5=16)
        // -> (128, 128, 128).
        let mut data = Vec::new();
        for value in [0xF800_u16, 0x07E0, 0x8410] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let level = decode_level(PixelFormat::Rgb565, &data, 3, 1).unwrap();
        assert_eq!(
            level.rgba,
            vec![248, 0, 0, 255, 0, 252, 0, 255, 128, 128, 128, 255]
        );
    }

    #[test]
    fn validation_4444_nibble_orders() {
        // Nibble expansion is bit replication: 0x1 -> 0x11
        // (17), 0x2 -> 0x22 (34), 0x3 -> 0x33 (51),
        // 0xF -> 0xFF (255).
        // ARGB4444 0xF123: A=F, R=1, G=2, B=3.
        let level = decode_level(PixelFormat::Argb4444, &0xF123_u16.to_le_bytes(), 1, 1).unwrap();
        assert_eq!(level.rgba, vec![17, 34, 51, 255]);
        // RGBA4444 0x123F: R=1, G=2, B=3, A=F.
        let level = decode_level(PixelFormat::Rgba4444, &0x123F_u16.to_le_bytes(), 1, 1).unwrap();
        assert_eq!(level.rgba, vec![17, 34, 51, 255]);
        // The two orders disagree on a value like 0x1234:
        // ARGB reads A=1,R=2,G=3,B=4; RGBA reads R=1,G=2,
        // B=3,A=4 (0x4 -> 0x44 = 68).
        let argb = decode_level(PixelFormat::Argb4444, &0x1234_u16.to_le_bytes(), 1, 1).unwrap();
        let rgba = decode_level(PixelFormat::Rgba4444, &0x1234_u16.to_le_bytes(), 1, 1).unwrap();
        assert_eq!(argb.rgba, vec![34, 51, 68, 17]);
        assert_eq!(rgba.rgba, vec![17, 34, 51, 68]);
    }

    #[test]
    fn validation_float_channel_conversion() {
        // RGBAHalf pixel: R=1.0 (0x3C00), G=0.5 (0x3800),
        // B=0.0, A=1.0. 0.5 * 255 = 127.5 truncates to
        // 127 (the rung 2 differential pin).
        let mut data = Vec::new();
        for half in [0x3C00_u16, 0x3800, 0x0000, 0x3C00] {
            data.extend_from_slice(&half.to_le_bytes());
        }
        let level = decode_level(PixelFormat::RgbaHalf, &data, 1, 1).unwrap();
        assert_eq!(level.rgba, vec![255, 127, 0, 255]);
        // RFloat clamps out-of-range values: 2.5 -> 255,
        // -1.0 -> 0.
        let mut data = Vec::new();
        data.extend_from_slice(&2.5_f32.to_le_bytes());
        data.extend_from_slice(&(-1.0_f32).to_le_bytes());
        let level = decode_level(PixelFormat::RFloat, &data, 2, 1).unwrap();
        assert_eq!(level.rgba, vec![255, 0, 0, 255, 0, 0, 0, 255]);
        // RGBAFloat under the truncation rule: 0.25*255
        // = 63.75 -> 63, 0.5*255 = 127.5 -> 127,
        // 0.75*255 = 191.25 -> 191.
        let mut data = Vec::new();
        for value in [0.25_f32, 0.5, 0.75, 1.0] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let level = decode_level(PixelFormat::RgbaFloat, &data, 1, 1).unwrap();
        assert_eq!(level.rgba, vec![63, 127, 191, 255]);
    }

    #[test]
    fn validation_half_widening_exact_values() {
        assert_eq!(half_to_f32(0x3C00), 1.0);
        assert_eq!(half_to_f32(0x3800), 0.5);
        assert_eq!(half_to_f32(0xC000), -2.0);
        assert_eq!(half_to_f32(0x0000), 0.0);
        assert_eq!(half_to_f32(0x7C00), f32::INFINITY);
        // Largest subnormal half: (1023/1024) * 2^-14.
        assert_eq!(half_to_f32(0x03FF), 1023.0 / 1024.0 * 2.0_f32.powi(-14));
        // Smallest subnormal half: 2^-24.
        assert_eq!(half_to_f32(0x0001), 2.0_f32.powi(-24));
        assert!(half_to_f32(0x7E00).is_nan());
    }

    #[test]
    fn validation_plain_mip_chain_sizes() {
        // RGBA32 8x8, 4 levels: 256 + 64 + 16 + 4 = 340.
        assert_eq!(expected_image_size(PixelFormat::Rgba32, 8, 8, 4), 340);
        // RGB565 5x3, 2 levels: 30 + (2*1*2) = 34 (odd
        // dimensions halve by the shared level rule).
        assert_eq!(expected_image_size(PixelFormat::Rgb565, 5, 3, 2), 34);
        let data = vec![0_u8; 340];
        let levels = decode_mip_chain(PixelFormat::Rgba32, &data, 8, 8, 4).unwrap();
        assert_eq!(levels.len(), 4);
        assert_eq!(levels[3].rgba.len(), 4);
    }

    #[test]
    fn validation_parse_plain_format_objects() {
        // RGBA32 inline under the modern layout; the
        // parse-time size identity now covers plain
        // formats too.
        let image = vec![9_u8; 8 * 8 * 4];
        let payload = synthetic_object(TextureLayout::Modern, 4, 8, 8, 1, &image, false);
        let object = parse_texture2d_object(&payload, true, TextureLayout::Modern).unwrap();
        assert_eq!(object.format_code, 4);
        let levels = object.decode_rgba(None).unwrap();
        assert_eq!(levels[0].rgba.len(), 256);
        // RGB565 streamed under legacy8.
        let image = vec![0_u8; 8 * 8 * 2];
        let payload = synthetic_object(TextureLayout::Legacy8, 7, 8, 8, 1, &[], true);
        let object = parse_texture2d_object(&payload, true, TextureLayout::Legacy8).unwrap();
        let mut resource = vec![0_u8; 64];
        resource.extend_from_slice(&image);
        let levels = object.decode_rgba(Some(&resource)).unwrap();
        assert_eq!(levels[0].rgba.len(), 256);
    }

    // ---- adversarial: typed errors, never panics ----

    #[test]
    fn adversarial_truncated_block_data() {
        assert!(matches!(
            decode_level(PixelFormat::Bc1, &[0_u8; 7], 4, 4),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
        assert!(matches!(
            decode_level(PixelFormat::Bc3, &[0_u8; 15], 4, 4),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
        assert!(matches!(
            decode_level(PixelFormat::Bc1, &[0_u8; 9], 4, 4),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
    }

    #[test]
    fn adversarial_format_and_dimension_mismatch() {
        // BC1-sized buffer offered as BC3.
        assert!(decode_level(PixelFormat::Bc3, &[0_u8; 8], 4, 4).is_err());
        assert!(matches!(
            decode_level(PixelFormat::Bc1, &[0_u8; 64], 0, 4),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
        assert!(PixelFormat::from_format_code(28).is_err()); // DXT1Crunched
        assert!(PixelFormat::from_format_code(25).is_err()); // BC7: later rung
        assert!(PixelFormat::from_format_code(47).is_err()); // ETC2_RGBA8: later rung
    }

    #[test]
    fn adversarial_plain_format_wrong_lengths() {
        // Every uncompressed format rejects a level buffer
        // one byte short and one byte long: the size
        // arithmetic is exact, never padded or truncated.
        for format in [
            PixelFormat::Alpha8,
            PixelFormat::Argb4444,
            PixelFormat::Rgb24,
            PixelFormat::Rgba32,
            PixelFormat::Argb32,
            PixelFormat::Rgb565,
            PixelFormat::Rgba4444,
            PixelFormat::RgbaHalf,
            PixelFormat::RFloat,
            PixelFormat::RgbaFloat,
            PixelFormat::R8,
        ] {
            let exact = level_byte_size(format, 4, 4) as usize;
            assert!(matches!(
                decode_level(format, &vec![0_u8; exact - 1], 4, 4),
                Err(TextureError::ImageSizeMismatch { .. })
            ));
            assert!(matches!(
                decode_level(format, &vec![0_u8; exact + 1], 4, 4),
                Err(TextureError::ImageSizeMismatch { .. })
            ));
            // A chain one byte short fails the same way.
            assert!(decode_mip_chain(format, &vec![0_u8; exact - 1], 4, 4, 1).is_err());
        }
    }

    #[test]
    fn adversarial_plain_object_size_lie() {
        // A recorded complete image size that disagrees
        // with the format arithmetic is a typed mismatch
        // for plain formats now (rung 1 checked BC only).
        let image = vec![0_u8; 8 * 8 * 4];
        let mut payload = synthetic_object(TextureLayout::Modern, 4, 8, 8, 1, &image, false);
        // Complete-size field offset: name(12) + prefix(8)
        // + width(4) + height(4) under the modern layout.
        let size_offset = 12 + 8 + 8;
        payload[size_offset..size_offset + 4].copy_from_slice(&999_i32.to_le_bytes());
        assert!(matches!(
            parse_texture2d_object(&payload, true, TextureLayout::Modern),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
    }

    #[test]
    fn adversarial_float_specials_never_panic() {
        // NaN, infinities, and negative floats decode to
        // defined bytes (NaN -> 0, +inf -> 255, -inf -> 0)
        // rather than panicking or saturating arbitrarily.
        let mut data = Vec::new();
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.5] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let level = decode_level(PixelFormat::RFloat, &data, 4, 1).unwrap();
        let reds: Vec<u8> = (0..4).map(|i| level.rgba[i * 4]).collect();
        assert_eq!(reds, vec![0, 255, 0, 0]);
        // Half NaN (0x7E00), +infinity (0x7C00),
        // -infinity (0xFC00), and zero as the four
        // channels of one RGBAHalf pixel ride the same
        // rule.
        let mut data = Vec::new();
        for half in [0x7E00_u16, 0x7C00, 0xFC00, 0x0000] {
            data.extend_from_slice(&half.to_le_bytes());
        }
        let level = decode_level(PixelFormat::RgbaHalf, &data, 1, 1).unwrap();
        assert_eq!(level.rgba, vec![0, 255, 0, 0]);
    }

    #[test]
    fn adversarial_object_parse_truncation_sweep() {
        // DXT5 8x8 is 64 bytes of image data.
        let image = vec![0_u8; 64];
        let payload = synthetic_object(TextureLayout::Modern, 12, 8, 8, 1, &image, false);
        for cut in 0..payload.len() {
            // Every strict prefix must error, never panic.
            assert!(
                parse_texture2d_object(&payload[..cut], true, TextureLayout::Modern).is_err(),
                "cut {cut} parsed"
            );
        }
    }

    #[test]
    fn adversarial_object_rejects_size_lie_and_bad_length() {
        let image = vec![0_u8; 32];
        let mut payload = synthetic_object(TextureLayout::Legacy8, 10, 8, 8, 1, &image, false);
        // Corrupt the recorded complete image size (the
        // field sits after name(12) + prefix(8) + w + h).
        let size_offset = 12 + 8 + 8;
        payload[size_offset..size_offset + 4].copy_from_slice(&999_i32.to_le_bytes());
        assert!(matches!(
            parse_texture2d_object(&payload, true, TextureLayout::Legacy8),
            Err(TextureError::ImageSizeMismatch { .. })
        ));
        // Wrong pinned layout for the same bytes: a typed
        // failure, not a phantom decode.
        let payload = synthetic_object(TextureLayout::Legacy8, 10, 8, 8, 1, &image, false);
        assert!(parse_texture2d_object(&payload, true, TextureLayout::Modern).is_err());
    }

    #[test]
    fn adversarial_stream_range_outside_resource() {
        let payload = synthetic_object(TextureLayout::Legacy8, 10, 8, 8, 1, &[], true);
        let object = parse_texture2d_object(&payload, true, TextureLayout::Legacy8).unwrap();
        assert!(matches!(
            object.image_data(Some(&[0_u8; 16])),
            Err(TextureError::ResourceUnavailable { .. })
        ));
        assert!(matches!(
            object.image_data(None),
            Err(TextureError::ResourceUnavailable { .. })
        ));
    }
}
#[cfg(test)]
mod corpus_tests {
    use super::*;
    use std::path::PathBuf;

    /// The differential harness (D-1654 rungs 1-2): every
    /// fixture in `tests/fixtures/texture_codec/` is a real
    /// Texture2D extracted from a held title (provenance in
    /// the manifest), decoded by this codec and compared
    /// byte-for-byte against the AssetRipper-exported oracle
    /// RGBA buffer under the pinned orientation convention:
    /// the oracle equals the codec's base level flipped
    /// vertically (Unity's stored row 0 is the bottom row).
    /// The bar is bit-exact on every fixture. Rung 2's
    /// channel conventions were pinned by its scratch
    /// differential (1,381 textures, zero mismatches)
    /// before these fixtures were selected: Alpha8 is
    /// black under the alpha, plain RGB565 expands
    /// shift-only (the BC endpoints keep bit replication),
    /// and float channels convert by truncation. The two
    /// RFloat fixtures are also the unity6 layout's first
    /// differential validation. R8 has no fixture: its
    /// only census carriers are bundle-resident or in a
    /// title whose walk was not completed (rung record).
    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("texture_codec")
    }

    fn flip_vertical(rgba: &[u8], width: u32, height: u32) -> Vec<u8> {
        let row = width as usize * 4;
        let mut out = Vec::with_capacity(rgba.len());
        for y in (0..height as usize).rev() {
            out.extend_from_slice(&rgba[y * row..(y + 1) * row]);
        }
        out
    }

    #[test]
    fn corpus_differential_bit_exact() {
        let dir = fixtures_dir();
        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        let fixtures = manifest["fixtures"].as_array().unwrap();
        assert!(
            fixtures.len() >= 24,
            "fixture set shrank: {}",
            fixtures.len()
        );
        let mut per_format: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for fixture in fixtures {
            let id = fixture["id"].as_str().unwrap();
            let format =
                PixelFormat::from_format_code(fixture["format"].as_i64().unwrap() as i32).unwrap();
            let width = fixture["width"].as_u64().unwrap() as u32;
            let height = fixture["height"].as_u64().unwrap() as u32;
            let mip_count = fixture["mip_count"].as_u64().unwrap() as u32;
            let data = std::fs::read(dir.join(format!("{id}.data"))).unwrap();
            let oracle = std::fs::read(dir.join(format!("{id}.rgba"))).unwrap();
            assert_eq!(
                sha256_hex(&data),
                fixture["data_sha256"].as_str().unwrap(),
                "{id}: raw data hash drifted from the manifest"
            );
            assert_eq!(
                sha256_hex(&oracle),
                fixture["oracle_sha256"].as_str().unwrap(),
                "{id}: oracle hash drifted from the manifest"
            );
            let levels = decode_mip_chain(format, &data, width, height, mip_count)
                .unwrap_or_else(|error| panic!("{id}: chain decode failed: {error}"));
            assert_eq!(levels.len() as u32, mip_count, "{id}: level count");
            let flipped = flip_vertical(&levels[0].rgba, width, height);
            assert_eq!(
                flipped, oracle,
                "{id}: base level is not bit-exact against the oracle under the pinned flip"
            );
            *per_format.entry(format.name().to_string()).or_default() += 1;
        }
        assert!(
            per_format["DXT1"] >= 12,
            "DXT1 fixtures: {}",
            per_format["DXT1"]
        );
        assert!(
            per_format["DXT5"] >= 12,
            "DXT5 fixtures: {}",
            per_format["DXT5"]
        );
        // Rung 2 floors, at the committed counts.
        for (name, floor) in [
            ("RGBA32", 8),
            ("ARGB32", 6),
            ("RGB24", 6),
            ("Alpha8", 6),
            ("ARGB4444", 2),
            ("RGB565", 6),
            ("RGBAHalf", 1),
            ("RGBAFloat", 2),
            ("RFloat", 2),
        ] {
            let count = per_format.get(name).copied().unwrap_or(0);
            assert!(count >= floor, "{name} fixtures: {count} < {floor}");
        }
    }
}
