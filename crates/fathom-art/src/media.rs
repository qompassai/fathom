//! Media decoding and animation facts.
//!
//! GIF timing is read by walking the GIF block stream directly
//! (graphic-control delays + the NETSCAPE2.0 loop extension) —
//! the same hand-parsed discipline fathom-managed applies to
//! ECMA-335 — so durations and loop behavior trace to bytes in
//! the file, not to a decoder's interpretation. Pixel frames
//! come from the `image` crate; motion is the mean absolute RGB
//! delta between consecutive frames as the decoder composites
//! them.

use std::io::Cursor;

use image::codecs::gif::GifDecoder;
use image::{AnimationDecoder, ImageFormat, RgbaImage};

/// Total pixels in one frame at most (decode bound).
pub const PIXELS_MAX: u64 = 33_554_432;
/// Animation frames examined at most.
pub const FRAMES_MAX: usize = 1024;

/// GIF loop behavior from the NETSCAPE2.0 extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopBehavior {
    /// Loop count 0: loops forever.
    Infinite,
    /// Loop count n (extension present).
    Iterations(u16),
    /// No loop extension: plays once.
    PlayOnce,
}

/// Timing grammar of an animated asset.
#[derive(Clone, Debug)]
pub struct AnimationFacts {
    /// Per-frame durations in milliseconds, file order.
    pub durations_ms: Vec<u32>,
    /// Frames the decoder produced.
    pub frame_count: usize,
    /// True when the frame cap stopped the examination.
    pub frames_truncated: bool,
    /// Loop behavior from the file's extension block.
    pub loop_behavior: LoopBehavior,
    /// Mean absolute RGB delta (0..=1) into each frame after
    /// the first; `len == frame_count - 1` (or fewer when the
    /// timing parse and the decoder disagree on frame count).
    pub motion_per_transition: Vec<f64>,
}

/// Sprite-sheet grid geometry from transparent gutters.
#[derive(Clone, Copy, Debug)]
pub struct SheetGeometry {
    /// Cell size in pixels.
    pub cell_height: u32,
    pub cell_width: u32,
    /// Grid dimensions in cells.
    pub columns: u32,
    pub rows: u32,
}

/// One decoded asset.
pub struct DecodedArt {
    /// Animation facts for GIF; `None` for stills.
    pub animation: Option<AnimationFacts>,
    /// "gif" | "jpeg" | "png".
    pub format: &'static str,
    /// The first frame, RGBA.
    pub first_frame: RgbaImage,
    /// Detected sheet geometry, when transparent gutters
    /// divide the first frame periodically.
    pub sheet: Option<SheetGeometry>,
    /// Why animation facts are absent for a GIF whose timing
    /// could not be established, when that happens.
    pub timing_unknown: Option<String>,
}

/// Decode an asset's bytes. Errors are plain messages; the
/// caller maps them to evidence error codes.
pub fn decode_art(bytes: &[u8]) -> Result<DecodedArt, String> {
    let format =
        image::guess_format(bytes).map_err(|e| format!("cannot identify image format: {e}"))?;
    match format {
        ImageFormat::Gif => decode_gif(bytes),
        ImageFormat::Jpeg => decode_still(bytes, ImageFormat::Jpeg, "jpeg"),
        ImageFormat::Png => decode_still(bytes, ImageFormat::Png, "png"),
        other => Err(format!(
            "unsupported image format {other:?}; this provider reads PNG, JPEG, and GIF"
        )),
    }
}

fn check_pixels(width: u32, height: u32) -> Result<(), String> {
    let pixels = u64::from(width) * u64::from(height);
    if pixels > PIXELS_MAX {
        return Err(format!(
            "image is {width}x{height} ({pixels} pixels); the bound is {PIXELS_MAX}"
        ));
    }
    Ok(())
}

fn decode_still(
    bytes: &[u8],
    format: ImageFormat,
    name: &'static str,
) -> Result<DecodedArt, String> {
    let image = image::load_from_memory_with_format(bytes, format)
        .map_err(|e| format!("cannot decode {name}: {e}"))?;
    check_pixels(image.width(), image.height())?;
    let frame = image.to_rgba8();
    let sheet = detect_sheet(&frame);
    Ok(DecodedArt {
        animation: None,
        format: name,
        first_frame: frame,
        sheet,
        timing_unknown: None,
    })
}

fn decode_gif(bytes: &[u8]) -> Result<DecodedArt, String> {
    let timing = parse_gif_timing(bytes);
    let decoder =
        GifDecoder::new(Cursor::new(bytes)).map_err(|e| format!("cannot decode gif: {e}"))?;
    let mut frames = decoder.into_frames();
    let first = frames
        .next()
        .ok_or_else(|| "gif contains no frames".to_string())?
        .map_err(|e| format!("cannot decode gif frame 0: {e}"))?;
    let first_frame = first.into_buffer();
    check_pixels(first_frame.width(), first_frame.height())?;
    let mut previous = first_frame.clone();
    let mut frame_count = 1_usize;
    let mut truncated = false;
    let mut motion: Vec<f64> = Vec::new();
    for frame in frames {
        if frame_count >= FRAMES_MAX {
            truncated = true;
            break;
        }
        let frame = frame.map_err(|e| format!("cannot decode gif frame {frame_count}: {e}"))?;
        let buffer = frame.into_buffer();
        motion.push(mean_abs_delta(&previous, &buffer));
        previous = buffer;
        frame_count += 1;
    }
    let sheet = detect_sheet(&first_frame);
    let (animation, timing_unknown) = match timing {
        Ok((durations_ms, loop_behavior)) => {
            let motion = if durations_ms.len() == frame_count {
                motion
            } else {
                // Decoder and block stream disagree on the frame
                // count: durations still trace to the file, but
                // pairing them with motion would be a guess.
                Vec::new()
            };
            (
                Some(AnimationFacts {
                    durations_ms,
                    frame_count,
                    frames_truncated: truncated,
                    loop_behavior,
                    motion_per_transition: motion,
                }),
                None,
            )
        }
        Err(reason) => (None, Some(reason)),
    };
    Ok(DecodedArt {
        animation,
        format: "gif",
        first_frame,
        sheet,
        timing_unknown,
    })
}

/// Mean absolute per-channel RGB delta between two frames over
/// their overlapping region, normalized to 0..=1.
fn mean_abs_delta(a: &RgbaImage, b: &RgbaImage) -> f64 {
    let width = a.width().min(b.width());
    let height = a.height().min(b.height());
    if width == 0 || height == 0 {
        return 0.0;
    }
    // Sample on a stride when frames are large: the metric is a
    // shape descriptor, and the stride keeps it bounded.
    let stride = ((u64::from(width) * u64::from(height)) / 65_536).max(1) as u32;
    let mut sum = 0_u64;
    let mut samples = 0_u64;
    let mut y = 0_u32;
    while y < height {
        let mut x = 0_u32;
        while x < width {
            let pa = a.get_pixel(x, y);
            let pb = b.get_pixel(x, y);
            for channel in 0..3 {
                sum += u64::from(pa[channel].abs_diff(pb[channel]));
            }
            samples += 1;
            x += stride;
        }
        y += stride;
    }
    if samples == 0 {
        return 0.0;
    }
    sum as f64 / (samples * 3 * 255) as f64
}

/// Walk the GIF block stream for graphic-control delays and
/// the NETSCAPE2.0 / ANIMEXTS1.0 loop count. Returns
/// (durations_ms, loop behavior).
pub fn parse_gif_timing(bytes: &[u8]) -> Result<(Vec<u32>, LoopBehavior), String> {
    if bytes.len() < 13 || (&bytes[0..6] != b"GIF87a" && &bytes[0..6] != b"GIF89a") {
        return Err("not a GIF87a/GIF89a stream".to_string());
    }
    let packed = bytes[10];
    let mut pos = 13_usize;
    if packed & 0x80 != 0 {
        pos += 3 * (1 << ((packed & 0x07) + 1));
    }
    let mut durations: Vec<u32> = Vec::new();
    let mut loop_behavior = LoopBehavior::PlayOnce;
    let mut pending_delay: Option<u32> = None;
    while pos < bytes.len() {
        match bytes[pos] {
            0x3B => break, // trailer
            0x21 => {
                // Extension: label, then data sub-blocks.
                if pos + 1 >= bytes.len() {
                    return Err("truncated extension".to_string());
                }
                let label = bytes[pos + 1];
                let mut cursor = pos + 2;
                if label == 0xF9 {
                    // Graphic control: block size 4, delay at +2.
                    if cursor >= bytes.len() || bytes[cursor] != 4 || cursor + 5 > bytes.len() {
                        return Err("malformed graphic control extension".to_string());
                    }
                    let centiseconds = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
                    pending_delay = Some(u32::from(centiseconds) * 10);
                }
                if label == 0xFF {
                    // Application extension: 8-byte id + 3-byte auth.
                    if cursor >= bytes.len() || bytes[cursor] != 11 || cursor + 12 > bytes.len() {
                        return Err("malformed application extension".to_string());
                    }
                    let app = &bytes[cursor + 1..cursor + 12];
                    if app == b"NETSCAPE2.0" || app == b"ANIMEXTS1.0" {
                        // First sub-block: 03 01 <loop lo> <loop hi>.
                        let sub = cursor + 12;
                        if sub + 4 < bytes.len() && bytes[sub] == 3 && bytes[sub + 1] == 1 {
                            let count = u16::from_le_bytes([bytes[sub + 2], bytes[sub + 3]]);
                            loop_behavior = if count == 0 {
                                LoopBehavior::Infinite
                            } else {
                                LoopBehavior::Iterations(count)
                            };
                        }
                    }
                }
                // Skip sub-blocks: size byte + payload, 0 ends.
                loop {
                    if cursor >= bytes.len() {
                        return Err("truncated extension body".to_string());
                    }
                    let size = usize::from(bytes[cursor]);
                    cursor += 1 + size;
                    if size == 0 {
                        break;
                    }
                }
                pos = cursor;
            }
            0x2C => {
                // Image descriptor: 9 bytes, optional local
                // color table, LZW minimum code size, sub-blocks.
                durations.push(pending_delay.take().unwrap_or(0));
                if pos + 10 > bytes.len() {
                    return Err("truncated image descriptor".to_string());
                }
                let local_packed = bytes[pos + 9];
                let mut cursor = pos + 10;
                if local_packed & 0x80 != 0 {
                    cursor += 3 * (1 << ((local_packed & 0x07) + 1));
                }
                cursor += 1; // LZW minimum code size
                loop {
                    if cursor >= bytes.len() {
                        return Err("truncated image data".to_string());
                    }
                    let size = usize::from(bytes[cursor]);
                    cursor += 1 + size;
                    if size == 0 {
                        break;
                    }
                }
                pos = cursor;
            }
            other => return Err(format!("unknown GIF block {other:#04x} at offset {pos}")),
        }
        if durations.len() > FRAMES_MAX {
            return Err(format!("gif declares more than {FRAMES_MAX} frames"));
        }
    }
    if durations.is_empty() {
        return Err("gif stream declares no image blocks".to_string());
    }
    Ok((durations, loop_behavior))
}

/// Runs of equal consecutive durations: (duration_ms, frames).
pub fn holds(durations_ms: &[u32]) -> Vec<(u32, usize)> {
    let mut runs: Vec<(u32, usize)> = Vec::new();
    for duration in durations_ms {
        match runs.last_mut() {
            Some((last, count)) if *last == *duration => *count += 1,
            _ => runs.push((*duration, 1)),
        }
    }
    runs
}

/// Easing shape from the motion curve: where the cumulative
/// motion sits at the midpoint of the transition sequence.
/// `linear` when the curve tracks the diagonal, `ease_in` when
/// motion is back-loaded, `ease_out` when front-loaded,
/// `ease_in_out` when both ends are quiet and the middle is
/// loud, `irregular` when one transition dominates.
pub fn classify_easing(motion: &[f64]) -> &'static str {
    let total: f64 = motion.iter().sum();
    if motion.is_empty() || total <= 0.0 {
        return "irregular";
    }
    if motion.iter().any(|m| *m / total > 0.8) {
        return "irregular";
    }
    let midpoint = motion.len() / 2;
    let before: f64 = motion[..midpoint].iter().sum::<f64>() / total;
    let quarter: f64 = motion[..motion.len() / 4].iter().sum::<f64>() / total;
    if before < 0.35 {
        "ease_in"
    } else if before > 0.65 {
        "ease_out"
    } else if quarter < 0.15 && before > 0.4 {
        "ease_in_out"
    } else {
        "linear"
    }
}

/// Detect a sprite-sheet grid: fully transparent gutter bands
/// dividing the first frame into uniform cells in both axes.
/// Anything else is not established (None).
pub fn detect_sheet(frame: &RgbaImage) -> Option<SheetGeometry> {
    let (columns, cell_width) = axis_grid(frame, true)?;
    let (rows, cell_height) = axis_grid(frame, false)?;
    Some(SheetGeometry {
        cell_height,
        cell_width,
        columns,
        rows,
    })
}

/// One axis of the sheet grid: (cells, cell size). The axis
/// must be divided by one or more fully transparent gutter
/// bands of uniform width into segments of one uniform cell
/// size (>= 8 px) — the first and last segments included.
fn axis_grid(frame: &RgbaImage, horizontal: bool) -> Option<(u32, u32)> {
    let extent = if horizontal {
        frame.width()
    } else {
        frame.height()
    };
    let cross = if horizontal {
        frame.height()
    } else {
        frame.width()
    };
    if extent < 16 || cross == 0 {
        return None;
    }
    let line_clear = |index: u32| -> bool {
        (0..cross).all(|other| {
            let pixel = if horizontal {
                frame.get_pixel(index, other)
            } else {
                frame.get_pixel(other, index)
            };
            pixel[3] < 128
        })
    };
    // Gutter bands as (start, width) pairs.
    let mut bands: Vec<(u32, u32)> = Vec::new();
    let mut index = 0_u32;
    while index < extent {
        if line_clear(index) {
            let start = index;
            while index < extent && line_clear(index) {
                index += 1;
            }
            bands.push((start, index - start));
        } else {
            index += 1;
        }
    }
    if bands.is_empty() {
        return None;
    }
    let gutter = bands[0].1;
    if !bands.iter().all(|(_, width)| *width == gutter) {
        return None;
    }
    // Segments between bands must all be one uniform cell size.
    let mut segments: Vec<u32> = Vec::new();
    let mut cursor = 0_u32;
    for (start, width) in &bands {
        segments.push(start - cursor);
        cursor = start + width;
    }
    segments.push(extent - cursor);
    let cell = segments[0];
    if cell < 8 || !segments.iter().all(|segment| *segment == cell) {
        return None;
    }
    Some((segments.len() as u32, cell))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::gif::{GifEncoder, Repeat};
    use image::{Frame, Rgba};

    fn gif_bytes(durations_centis: &[u16], repeat: Repeat) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut bytes);
            encoder.set_repeat(repeat).unwrap();
            for (index, centis) in durations_centis.iter().enumerate() {
                let shade = (index as u8) * 30 + 10;
                let image = RgbaImage::from_pixel(8, 8, Rgba([shade, shade, shade, 255]));
                let delay = image::Delay::from_saturating_duration(
                    std::time::Duration::from_millis(u64::from(*centis) * 10),
                );
                encoder
                    .encode_frame(Frame::from_parts(image, 0, 0, delay))
                    .unwrap();
            }
        }
        bytes
    }

    #[test]
    fn validation_gif_timing_round_trips() {
        // 14, 42, 46, 46, 62 cs — the POV lean-in shape in
        // miniature, infinite loop.
        let bytes = gif_bytes(&[14, 42, 46, 46, 62], Repeat::Infinite);
        let (durations, looping) = parse_gif_timing(&bytes).unwrap();
        assert_eq!(durations, vec![140, 420, 460, 460, 620]);
        assert_eq!(looping, LoopBehavior::Infinite);
        assert_eq!(
            holds(&durations),
            vec![(140, 1), (420, 1), (460, 2), (620, 1)]
        );
        let art = decode_art(&bytes).unwrap();
        let animation = art.animation.expect("animation facts");
        assert_eq!(animation.frame_count, 5);
        assert_eq!(animation.durations_ms, durations);
    }

    #[test]
    fn validation_easing_classes() {
        assert_eq!(classify_easing(&[0.1, 0.2, 0.3, 0.4]), "ease_in");
        assert_eq!(classify_easing(&[0.4, 0.3, 0.2, 0.1]), "ease_out");
        assert_eq!(classify_easing(&[0.25, 0.25, 0.25, 0.25]), "linear");
        assert_eq!(classify_easing(&[0.9, 0.05, 0.05]), "irregular");
        assert_eq!(classify_easing(&[]), "irregular");
    }

    #[test]
    fn adversarial_non_gif_timing_rejected() {
        assert!(parse_gif_timing(b"PNG....").is_err());
        assert!(parse_gif_timing(&[0x47, 0x49, 0x46, 0x38]).is_err());
        assert!(decode_art(b"definitely not an image").is_err());
    }

    #[test]
    fn validation_sheet_geometry_detected() {
        // 34x34: two 16px cells separated by 2px gutters in
        // both axes (16 + 2 + 16 = 34).
        let mut image = RgbaImage::from_pixel(34, 34, Rgba([200, 30, 30, 255]));
        for y in 0..34 {
            for x in 0..34 {
                if (16..18).contains(&x) || (16..18).contains(&y) {
                    image.put_pixel(x, y, Rgba([0, 0, 0, 0]));
                }
            }
        }
        let sheet = detect_sheet(&image).expect("grid");
        assert_eq!(sheet.columns, 2);
        assert_eq!(sheet.rows, 2);
        assert_eq!(sheet.cell_width, 16);
        assert_eq!(sheet.cell_height, 16);
        // A solid portrait has no gutters: not a sheet.
        let portrait = RgbaImage::from_pixel(34, 34, Rgba([10, 20, 30, 255]));
        assert!(detect_sheet(&portrait).is_none());
    }
}
