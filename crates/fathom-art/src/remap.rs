//! Native palette remap: the deterministic, analysis-adjacent
//! transform. Every opaque pixel is rewritten to its nearest
//! palette color (or only on an exact match, in exact mode);
//! alpha is preserved and transparent pixels pass through
//! untouched. No grading, no rendering decisions — arithmetic.

use image::RgbaImage;

use crate::spec::ALPHA_OPAQUE_MIN;

/// Remap outcome counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemapCounts {
    /// Pixels left unchanged because no palette color matched
    /// (exact mode only).
    pub unmapped: usize,
    /// Pixels rewritten to a palette color.
    pub mapped: usize,
    /// Non-opaque pixels passed through untouched.
    pub alpha_skipped: usize,
}

/// Parse `#RRGGBB` palette entries (1..=256 of them).
pub fn parse_palette(values: &[String]) -> Result<Vec<[u8; 3]>, String> {
    if values.is_empty() || values.len() > 256 {
        return Err(format!(
            "palette must list 1..=256 colors, got {}",
            values.len()
        ));
    }
    let mut palette = Vec::with_capacity(values.len());
    for value in values {
        let hex = value.strip_prefix('#').unwrap_or(value);
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("palette entry '{value}' is not #RRGGBB"));
        }
        let packed = u32::from_str_radix(hex, 16)
            .map_err(|e| format!("palette entry '{value}' does not parse: {e}"))?;
        palette.push([(packed >> 16) as u8, (packed >> 8) as u8, packed as u8]);
    }
    Ok(palette)
}

/// Format one palette color as `#RRGGBB`.
pub fn palette_hex(rgb: [u8; 3]) -> String {
    format!("#{:02X}{:02X}{:02X}", rgb[0], rgb[1], rgb[2])
}

fn nearest(palette: &[[u8; 3]], rgb: [u8; 3]) -> [u8; 3] {
    let mut best = palette[0];
    let mut best_distance = u32::MAX;
    for candidate in palette {
        let distance = (0..3)
            .map(|channel| {
                let delta = i32::from(rgb[channel]) - i32::from(candidate[channel]);
                (delta * delta) as u32
            })
            .sum();
        if distance < best_distance {
            best_distance = distance;
            best = *candidate;
        }
    }
    best
}

/// Remap one frame. In exact mode a pixel changes only when its
/// RGB equals a palette entry; otherwise nearest wins.
pub fn remap_frame(
    frame: &RgbaImage,
    palette: &[[u8; 3]],
    exact: bool,
) -> (RgbaImage, RemapCounts) {
    assert!(!palette.is_empty(), "palette validated non-empty");
    let mut out = frame.clone();
    let mut counts = RemapCounts::default();
    for (pixel, target) in frame.pixels().zip(out.pixels_mut()) {
        if pixel[3] < ALPHA_OPAQUE_MIN {
            counts.alpha_skipped += 1;
            continue;
        }
        let rgb = [pixel[0], pixel[1], pixel[2]];
        if exact {
            if palette.contains(&rgb) {
                counts.mapped += 1;
            } else {
                counts.unmapped += 1;
                continue;
            }
        } else {
            let mapped = nearest(palette, rgb);
            if mapped != rgb {
                counts.mapped += 1;
            } else {
                counts.unmapped += 1;
            }
            target[0] = mapped[0];
            target[1] = mapped[1];
            target[2] = mapped[2];
        }
    }
    (out, counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    #[test]
    fn validation_nearest_remap_counts() {
        let mut image = RgbaImage::new(3, 1);
        image.put_pixel(0, 0, Rgba([250, 10, 10, 255]));
        image.put_pixel(1, 0, Rgba([10, 10, 250, 255]));
        image.put_pixel(2, 0, Rgba([0, 0, 0, 0]));
        let palette = parse_palette(&["#FF0000".to_string(), "#0000FF".to_string()]).unwrap();
        let (out, counts) = remap_frame(&image, &palette, false);
        assert_eq!(out.get_pixel(0, 0), &Rgba([255, 0, 0, 255]));
        assert_eq!(out.get_pixel(1, 0), &Rgba([0, 0, 255, 255]));
        assert_eq!(counts.mapped, 2);
        assert_eq!(counts.alpha_skipped, 1);
    }

    #[test]
    fn validation_exact_remap_leaves_nonmembers() {
        let image = RgbaImage::from_pixel(2, 1, Rgba([128, 128, 128, 255]));
        let palette = parse_palette(&["#FF0000".to_string()]).unwrap();
        let (out, counts) = remap_frame(&image, &palette, true);
        assert_eq!(counts.mapped, 0);
        assert_eq!(counts.unmapped, 2);
        assert_eq!(out.get_pixel(0, 0), &Rgba([128, 128, 128, 255]));
    }

    #[test]
    fn adversarial_palette_rejected() {
        assert!(parse_palette(&[]).is_err());
        assert!(parse_palette(&["red".to_string()]).is_err());
        assert!(parse_palette(&["#12345".to_string()]).is_err());
        assert!(parse_palette(&["#GGGGGG".to_string()]).is_err());
        assert!(parse_palette(&vec!["#000000".to_string(); 257]).is_err());
    }
}
