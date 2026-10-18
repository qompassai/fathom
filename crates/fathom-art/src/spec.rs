//! Style measurement: every number in a style spec is computed
//! from decoded pixels by the functions here — nothing is
//! estimated from filenames, metadata, or priors.
//!
//! Vocabulary: a pixel is *opaque* when alpha >= 128. Palette and
//! grade statistics describe opaque pixels only (a sprite's
//! transparent surround is not its style); the transparent share
//! is reported separately as `alpha_fraction`. Sampling is a
//! fixed row-major stride — deterministic, never random.

use std::collections::HashSet;

use image::RgbaImage;
use serde_json::{Value, json};

/// Pixels sampled at most for palette/grade statistics.
pub const SAMPLE_PIXELS_MAX: usize = 262_144;
/// Exact unique-color count cap; beyond it the count is reported
/// as capped, not exact.
pub const UNIQUE_COLORS_MAX: usize = 65_536;
/// Alpha at or above this counts a pixel as opaque.
pub const ALPHA_OPAQUE_MIN: u8 = 128;
/// Horizontal neighbour pairs examined at most for the
/// gradient/edge fractions.
pub const PAIR_CHECKS_MAX: usize = 4_194_304;

/// One palette cluster: centroid color + share of sampled
/// opaque pixels assigned to it.
#[derive(Clone, Debug)]
pub struct PaletteEntry {
    /// Share of sampled opaque pixels in this cluster (0..=1).
    pub coverage: f64,
    /// `#RRGGBB` rendering of the centroid.
    pub hex: String,
    /// Centroid RGB.
    pub rgb: [u8; 3],
}

/// Everything measured from one still frame.
#[derive(Clone, Debug)]
pub struct FrameSpec {
    /// Fraction of all pixels that are not opaque (0..=1).
    pub alpha_fraction: f64,
    /// p95-p05 of HSL lightness over sampled opaque pixels.
    pub contrast: f64,
    /// Fraction of examined neighbour pairs with a large
    /// lightness step (>= 48 of 255 levels).
    pub edge_density: f64,
    /// Fraction of examined neighbour pairs with a small
    /// non-zero lightness step (1..=8 of 255 levels) — the
    /// smooth-shading signature.
    pub gradient_fraction: f64,
    /// Distinct lightness levels (of 256) holding >= 0.1% of
    /// sampled opaque pixels.
    pub lightness_levels_present: usize,
    /// Lightness percentiles over sampled opaque pixels.
    pub lightness_p05: f64,
    pub lightness_p50: f64,
    pub lightness_p95: f64,
    /// Circular mean hue in degrees over chromatic sampled
    /// pixels (saturation >= 0.05, weighted by saturation);
    /// `None` when the frame has no chromatic pixels.
    pub mean_hue_deg: Option<f64>,
    /// Mean HSL lightness over sampled opaque pixels.
    pub mean_lightness: f64,
    /// Mean HSL saturation over sampled opaque pixels.
    pub mean_saturation: f64,
    /// Median-cut palette clusters, coverage-descending.
    pub palette: Vec<PaletteEntry>,
    /// Opaque pixels actually sampled for palette/grade stats.
    pub sampled_pixels: usize,
    /// Rule-based shading classification (see
    /// [`classify_shading`]).
    pub shading_model: &'static str,
    /// Exact distinct RGB count over opaque pixels, unless the
    /// cap fired (`unique_colors_capped`).
    pub unique_colors: usize,
    /// True when the unique count stopped at the cap.
    pub unique_colors_capped: bool,
}

/// RGB → HSL. Returns (hue degrees or None when achromatic,
/// saturation, lightness), components in 0..=1 except hue.
pub fn rgb_to_hsl(red: u8, green: u8, blue: u8) -> (Option<f64>, f64, f64) {
    let r = f64::from(red) / 255.0;
    let g = f64::from(green) / 255.0;
    let b = f64::from(blue) / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let lightness = (max + min) / 2.0;
    if (max - min).abs() < f64::EPSILON {
        return (None, 0.0, lightness);
    }
    let delta = max - min;
    let saturation = if lightness > 0.5 {
        delta / (2.0 - max - min)
    } else {
        delta / (max + min)
    };
    let hue = if max == r {
        60.0 * (((g - b) / delta) % 6.0)
    } else if max == g {
        60.0 * ((b - r) / delta + 2.0)
    } else {
        60.0 * ((r - g) / delta + 4.0)
    };
    (Some((hue + 360.0) % 360.0), saturation, lightness)
}

/// Deterministic median-cut clustering over RGB samples.
/// Boxes split on their widest channel at the median until
/// `clusters` boxes exist or no box can split further.
pub fn median_cut(samples: &[[u8; 3]], clusters: usize) -> Vec<([u8; 3], usize)> {
    assert!(clusters >= 1, "cluster count comes from a validated arg");
    if samples.is_empty() {
        return Vec::new();
    }
    let mut boxes: Vec<Vec<[u8; 3]>> = vec![samples.to_vec()];
    while boxes.len() < clusters {
        // Split the box with the widest channel range (ties:
        // the largest box, then the first) — fully deterministic.
        let mut best: Option<(usize, usize, usize)> = None; // (range, len, box idx)
        let mut best_channel = 0_usize;
        for (index, pixels) in boxes.iter().enumerate() {
            if pixels.len() < 2 {
                continue;
            }
            for channel in 0..3 {
                let lo = pixels.iter().map(|p| p[channel]).min().unwrap_or(0);
                let hi = pixels.iter().map(|p| p[channel]).max().unwrap_or(0);
                let range = usize::from(hi - lo);
                let candidate = (range, pixels.len(), index);
                if range > 0 && best.is_none_or(|b| candidate > b) {
                    best = Some(candidate);
                    best_channel = channel;
                }
            }
        }
        let Some((_, _, index)) = best else { break };
        let mut pixels = boxes.swap_remove(index);
        pixels.sort_unstable_by_key(|p| p[best_channel]);
        let mid = pixels.len() / 2;
        let right = pixels.split_off(mid);
        boxes.push(pixels);
        boxes.push(right);
    }
    let mut result: Vec<([u8; 3], usize)> = boxes
        .iter()
        .filter(|pixels| !pixels.is_empty())
        .map(|pixels| {
            let mut sums = [0_u64; 3];
            for pixel in pixels {
                for channel in 0..3 {
                    sums[channel] += u64::from(pixel[channel]);
                }
            }
            let n = pixels.len() as u64;
            let centroid = [
                (sums[0] / n) as u8,
                (sums[1] / n) as u8,
                (sums[2] / n) as u8,
            ];
            (centroid, pixels.len())
        })
        .collect();
    result.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    result
}

/// The shading classification rule (stated verbatim in the
/// tool's limitation text so consumers can judge it):
/// `flat` when the frame uses <= 16 distinct opaque colors;
/// `cel` when lightness collapses to <= 8 populated levels and
/// smooth gradients are rare; `soft` when smooth gradients are
/// common; `mixed` otherwise.
pub fn classify_shading(
    unique_colors: usize,
    lightness_levels_present: usize,
    gradient_fraction: f64,
) -> &'static str {
    if unique_colors <= 16 {
        "flat"
    } else if lightness_levels_present <= 8 && gradient_fraction < 0.25 {
        "cel"
    } else if gradient_fraction >= 0.25 {
        "soft"
    } else {
        "mixed"
    }
}

fn percentile(histogram: &[u64; 256], total: u64, fraction: f64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let target = (fraction * total as f64).ceil() as u64;
    let mut seen = 0_u64;
    for (level, count) in histogram.iter().enumerate() {
        seen += count;
        if seen >= target.max(1) {
            return level as f64 / 255.0;
        }
    }
    1.0
}

/// Measure one decoded frame. `palette_colors` is validated by
/// the caller (1..=16).
pub fn measure_frame(frame: &RgbaImage, palette_colors: usize) -> FrameSpec {
    let total_pixels = (frame.width() as usize) * (frame.height() as usize);
    let mut opaque: Vec<[u8; 3]> = Vec::new();
    let mut unique: HashSet<u32> = HashSet::new();
    let mut unique_capped = false;
    let mut transparent = 0_usize;
    for pixel in frame.pixels() {
        if pixel[3] < ALPHA_OPAQUE_MIN {
            transparent += 1;
            continue;
        }
        if !unique_capped {
            let packed =
                (u32::from(pixel[0]) << 16) | (u32::from(pixel[1]) << 8) | u32::from(pixel[2]);
            unique.insert(packed);
            if unique.len() >= UNIQUE_COLORS_MAX {
                unique_capped = true;
            }
        }
        opaque.push([pixel[0], pixel[1], pixel[2]]);
    }
    let alpha_fraction = if total_pixels == 0 {
        0.0
    } else {
        transparent as f64 / total_pixels as f64
    };

    // Deterministic stride sample for palette/grade statistics.
    let stride = opaque.len().div_ceil(SAMPLE_PIXELS_MAX).max(1);
    let sampled: Vec<[u8; 3]> = opaque.iter().step_by(stride).copied().collect();

    let mut histogram = [0_u64; 256];
    let mut hue_x = 0.0_f64;
    let mut hue_y = 0.0_f64;
    let mut saturation_sum = 0.0_f64;
    let mut lightness_sum = 0.0_f64;
    for pixel in &sampled {
        let (hue, saturation, lightness) = rgb_to_hsl(pixel[0], pixel[1], pixel[2]);
        saturation_sum += saturation;
        lightness_sum += lightness;
        histogram[(lightness * 255.0).round() as usize] += 1;
        if let Some(degrees) = hue.filter(|_| saturation >= 0.05) {
            let radians = degrees.to_radians();
            hue_x += radians.cos() * saturation;
            hue_y += radians.sin() * saturation;
        }
    }
    let sampled_count = sampled.len().max(1) as f64;
    let levels_present = histogram
        .iter()
        .filter(|count| **count as f64 >= 0.001 * sampled_count)
        .count();
    let mean_hue_deg = if hue_x == 0.0 && hue_y == 0.0 {
        None
    } else {
        Some((hue_y.atan2(hue_x).to_degrees() + 360.0) % 360.0)
    };

    let (gradient_fraction, edge_density) = pair_fractions(frame);
    let palette = median_cut(&sampled, palette_colors)
        .iter()
        .map(|(rgb, count)| PaletteEntry {
            coverage: *count as f64 / sampled_count,
            hex: format!("#{:02X}{:02X}{:02X}", rgb[0], rgb[1], rgb[2]),
            rgb: *rgb,
        })
        .collect();
    let unique_colors = unique.len();
    FrameSpec {
        alpha_fraction,
        contrast: percentile(&histogram, sampled.len() as u64, 0.95)
            - percentile(&histogram, sampled.len() as u64, 0.05),
        edge_density,
        gradient_fraction,
        lightness_levels_present: levels_present,
        lightness_p05: percentile(&histogram, sampled.len() as u64, 0.05),
        lightness_p50: percentile(&histogram, sampled.len() as u64, 0.50),
        lightness_p95: percentile(&histogram, sampled.len() as u64, 0.95),
        mean_hue_deg,
        mean_lightness: lightness_sum / sampled_count,
        mean_saturation: saturation_sum / sampled_count,
        palette,
        sampled_pixels: sampled.len(),
        shading_model: classify_shading(unique_colors, levels_present, gradient_fraction),
        unique_colors,
        unique_colors_capped: unique_capped,
    }
}

/// (gradient_fraction, edge_density) over horizontally adjacent
/// opaque pairs, on a bounded set of rows and pairs.
fn pair_fractions(frame: &RgbaImage) -> (f64, f64) {
    let (width, height) = (frame.width(), frame.height());
    if width < 2 || height == 0 {
        return (0.0, 0.0);
    }
    let row_stride = (height / 1024).max(1);
    let mut pairs = 0_usize;
    let mut gradient = 0_usize;
    let mut edge = 0_usize;
    let mut y = 0_u32;
    'rows: while y < height {
        let mut previous: Option<i32> = None;
        for x in 0..width {
            if pairs >= PAIR_CHECKS_MAX {
                break 'rows;
            }
            let pixel = frame.get_pixel(x, y);
            if pixel[3] < ALPHA_OPAQUE_MIN {
                previous = None;
                continue;
            }
            let (_, _, lightness) = rgb_to_hsl(pixel[0], pixel[1], pixel[2]);
            let level = (lightness * 255.0).round() as i32;
            if let Some(before) = previous {
                let delta = (level - before).abs();
                pairs += 1;
                if (1..=8).contains(&delta) {
                    gradient += 1;
                } else if delta >= 48 {
                    edge += 1;
                }
            }
            previous = Some(level);
        }
        y += row_stride;
    }
    if pairs == 0 {
        return (0.0, 0.0);
    }
    (gradient as f64 / pairs as f64, edge as f64 / pairs as f64)
}

/// The JSON form of a frame spec, shared by the analysis tool
/// and the lumen bridge's before/after comparison.
pub fn frame_spec_json(spec: &FrameSpec) -> Value {
    json!({
        "alpha_fraction": round4(spec.alpha_fraction),
        "contrast": round4(spec.contrast),
        "edge_density": round4(spec.edge_density),
        "gradient_fraction": round4(spec.gradient_fraction),
        "lightness_levels_present": spec.lightness_levels_present,
        "lightness_p05": round4(spec.lightness_p05),
        "lightness_p50": round4(spec.lightness_p50),
        "lightness_p95": round4(spec.lightness_p95),
        "mean_hue_deg": spec.mean_hue_deg.map(round2),
        "mean_lightness": round4(spec.mean_lightness),
        "mean_saturation": round4(spec.mean_saturation),
        "palette": spec.palette.iter().map(|entry| json!({
            "coverage": round4(entry.coverage),
            "hex": entry.hex,
            "rgb": entry.rgb,
        })).collect::<Vec<_>>(),
        "sampled_pixels": spec.sampled_pixels,
        "shading_model": spec.shading_model,
        "unique_colors": spec.unique_colors,
        "unique_colors_capped": spec.unique_colors_capped,
    })
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    fn solid(width: u32, height: u32, rgba: [u8; 4]) -> RgbaImage {
        RgbaImage::from_pixel(width, height, Rgba(rgba))
    }

    #[test]
    fn validation_two_color_palette_is_exact() {
        // Left half red, right half blue: two clusters, 50/50.
        let mut image = solid(16, 16, [255, 0, 0, 255]);
        for y in 0..16 {
            for x in 8..16 {
                image.put_pixel(x, y, Rgba([0, 0, 255, 255]));
            }
        }
        let spec = measure_frame(&image, 8);
        assert_eq!(spec.unique_colors, 2);
        assert_eq!(spec.palette.len(), 2);
        assert_eq!(spec.palette[0].coverage, 0.5);
        assert_eq!(spec.shading_model, "flat");
        assert_eq!(spec.alpha_fraction, 0.0);
    }

    #[test]
    fn validation_hsl_primaries() {
        let (hue, saturation, lightness) = rgb_to_hsl(255, 0, 0);
        assert_eq!(hue, Some(0.0));
        assert_eq!(saturation, 1.0);
        assert_eq!(lightness, 0.5);
        let (hue, _, _) = rgb_to_hsl(128, 128, 128);
        assert_eq!(hue, None);
    }

    #[test]
    fn validation_gradient_ramp_reads_soft() {
        // A smooth 256-step lightness ramp: every adjacent pair
        // is a small gradient step — the soft signature.
        let mut image = RgbaImage::new(256, 8);
        for y in 0..8 {
            for x in 0..256 {
                let level = x as u8;
                image.put_pixel(x, y, Rgba([level, level, level, 255]));
            }
        }
        let spec = measure_frame(&image, 8);
        assert!(
            spec.gradient_fraction > 0.9,
            "gradient: {}",
            spec.gradient_fraction
        );
        assert_eq!(spec.shading_model, "soft");
    }

    #[test]
    fn validation_classifier_rule_table() {
        assert_eq!(classify_shading(10, 200, 0.9), "flat");
        assert_eq!(classify_shading(500, 6, 0.05), "cel");
        assert_eq!(classify_shading(500, 40, 0.40), "soft");
        assert_eq!(classify_shading(500, 40, 0.10), "mixed");
    }

    #[test]
    fn adversarial_transparent_pixels_are_not_style() {
        // A fully transparent frame has no style to measure: the
        // palette is empty and hue is absent, not invented.
        let image = solid(8, 8, [255, 0, 0, 0]);
        let spec = measure_frame(&image, 8);
        assert_eq!(spec.alpha_fraction, 1.0);
        assert!(spec.palette.is_empty());
        assert_eq!(spec.mean_hue_deg, None);
        assert_eq!(spec.unique_colors, 0);
    }
}
