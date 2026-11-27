//! Still-media census and hand-animation discernment.
//!
//! The census is a fixed standard, not a menu: one image is
//! downscaled to [`DOWNSCALE_WIDTH`] px wide by area-weighted
//! box sampling (alpha composited over black, the PIL
//! `convert("RGB")` semantics the Sloane determination's
//! measurements used), and its unique colours and mean
//! horizontal gradient are counted there. At that size the
//! determination's bar is numeric: the banked references carry
//! 33k–42k unique colours and gradient 9–13 per channel;
//! pass 1's frame carries 3,976 and 4.37. A census that cannot
//! reproduce that gap from the files alone is not measuring
//! what the determination measured.
//!
//! The discernment is a pure function over census facts: the
//! same reading comes out of a file (chained through the
//! census) or out of a census object supplied by the caller.
//! It reports what a still can determine — register evidence,
//! implied accent tracks, the shading depth a drawn
//! reproduction must hold — and names what it cannot
//! (timing, phases, travel path) as gaps, never as guesses.

use std::collections::HashSet;

use image::RgbaImage;
use serde_json::{Value, json};

use crate::spec::{self, FrameSpec};

/// Width of the standard downscale, in pixels.
pub const DOWNSCALE_WIDTH: u32 = 256;
/// Height cap of the standard downscale; past it the scale is
/// height-bound instead, so a tall strip cannot make the
/// census unbounded.
pub const DOWNSCALE_HEIGHT_MAX: u32 = 4096;
/// Lightness bands in the tonal partition.
pub const TONAL_BANDS: usize = 16;
/// A tonal band is populated at this share of sampled opaque
/// pixels or more.
pub const BAND_POPULATED_MIN: f64 = 0.005;
/// Family floor from the Sloane determination's gate G3: a
/// drawn reproduction must measure at least this many unique
/// colours at the standard downscale...
pub const FAMILY_FLOOR_UNIQUE_COLOURS: usize = 12_000;
/// ...and at least this mean gradient, to sit in the banked
/// references' family.
pub const FAMILY_FLOOR_GRADIENT: f64 = 6.0;
/// Blush load at or above this is strong overwhelmed-family
/// evidence (calibrated on the determination's witness set:
/// the five banked references against pass 1's frame).
pub const BLUSH_STRONG: f64 = 0.05;
/// Blush load at or above this (and below strong) reads
/// flustered.
pub const BLUSH_MODERATE: f64 = 0.015;
/// Below this blush load, and below the specular floor, the
/// register evidence is negligible.
pub const BLUSH_NEGLIGIBLE: f64 = 0.002;
/// Specular share at or above this implies the specular/tear
/// accent track.
pub const SPECULAR_TRACK_MIN: f64 = 0.001;
/// Hair-mass share at or above this implies the loose-strand
/// hair accent track.
pub const HAIR_TRACK_MIN: f64 = 0.10;

/// The facts both tools share: everything the discernment
/// reads, whether measured here from a file or parsed from a
/// caller-supplied census object.
#[derive(Clone, Debug)]
pub struct CensusFacts {
    /// Fraction of all pixels that are not opaque (0..=1).
    pub alpha_fraction: f64,
    /// Share of sampled opaque pixels in the blush colour
    /// family (hue 345..=360 or 0..=25 degrees, saturation
    /// >= 0.25, lightness 0.30..=0.80).
    pub blush_load: f64,
    /// Mean gradient at the standard downscale (0..=255 per
    /// channel).
    pub gradient_256w: f64,
    /// Share of sampled opaque pixels in the warm-brown hair
    /// family (hue 12..=48 degrees, saturation >= 0.18,
    /// lightness 0.08..=0.55).
    pub hair_mass_share: f64,
    /// Populated tonal bands above the median band.
    pub highlight_steps: usize,
    /// Circular mean hue in degrees, when the frame has
    /// chromatic pixels.
    pub mean_hue_deg: Option<f64>,
    /// Mean HSL saturation over sampled opaque pixels.
    pub mean_saturation: f64,
    /// Rule-classified shading model (flat / cel / soft /
    /// mixed), per `spec::classify_shading`.
    pub shading_model: String,
    /// Populated tonal bands below the median band.
    pub shadow_steps: usize,
    /// Share of sampled opaque pixels at lightness >= 0.93 —
    /// the glossy-specular signature.
    pub specular_share: f64,
    /// Populated tonal bands in total.
    pub tonal_steps: usize,
    /// Exact distinct RGB count at the standard downscale.
    pub unique_colours_256w: usize,
}

/// Everything measured from one decoded still: the shared
/// facts plus the census-only detail (palette, percentiles).
#[derive(Clone, Debug)]
pub struct StillFacts {
    /// Height of the standard downscale the census counted.
    pub downscale_height: u32,
    /// Width of the standard downscale the census counted.
    pub downscale_width: u32,
    /// The shared census facts.
    pub facts: CensusFacts,
    /// Lightness percentiles over sampled opaque pixels.
    pub lightness_p05: f64,
    pub lightness_p50: f64,
    pub lightness_p95: f64,
    /// Mean HSL lightness over sampled opaque pixels.
    pub mean_lightness: f64,
    /// Median-cut palette anchors, coverage-descending.
    pub palette: Vec<spec::PaletteEntry>,
    /// Opaque pixels sampled for palette/grade statistics.
    pub sampled_pixels: usize,
}

/// Area-weighted box downscale to the standard size: width
/// [`DOWNSCALE_WIDTH`] unless the frame is already narrower
/// or the height cap binds. A frame already at or under the
/// standard is returned unchanged. Fully deterministic: the
/// same pixels always produce the same downscale.
pub fn downscale_to_standard(frame: &RgbaImage) -> RgbaImage {
    let (width, height) = (frame.width(), frame.height());
    if width == 0 || height == 0 {
        return frame.clone();
    }
    let mut out_w = DOWNSCALE_WIDTH.min(width);
    let mut out_h = ((u64::from(height) * u64::from(out_w)) / u64::from(width)).max(1) as u32;
    if out_h > DOWNSCALE_HEIGHT_MAX {
        out_h = DOWNSCALE_HEIGHT_MAX;
        out_w = ((u64::from(width) * u64::from(out_h)) / u64::from(height)).max(1) as u32;
    }
    if out_w == width && out_h == height {
        return frame.clone();
    }
    let scale_x = f64::from(width) / f64::from(out_w);
    let scale_y = f64::from(height) / f64::from(out_h);
    let mut out = RgbaImage::new(out_w, out_h);
    for oy in 0..out_h {
        let y0 = f64::from(oy) * scale_y;
        let y1 = y0 + scale_y;
        for ox in 0..out_w {
            let x0 = f64::from(ox) * scale_x;
            let x1 = x0 + scale_x;
            let mut sums = [0.0_f64; 4];
            let mut total = 0.0_f64;
            let mut sy = y0.floor() as u32;
            while (sy as f64) < y1 && sy < height {
                let wy = (y1.min(f64::from(sy + 1)) - y0.max(f64::from(sy))).max(0.0);
                let mut sx = x0.floor() as u32;
                while (sx as f64) < x1 && sx < width {
                    let wx = (x1.min(f64::from(sx + 1)) - x0.max(f64::from(sx))).max(0.0);
                    let weight = wx * wy;
                    if weight > 0.0 {
                        let pixel = frame.get_pixel(sx, sy);
                        for channel in 0..4 {
                            sums[channel] += f64::from(pixel[channel]) * weight;
                        }
                        total += weight;
                    }
                    sx += 1;
                }
                sy += 1;
            }
            if total > 0.0 {
                let mut rgba = [0_u8; 4];
                for channel in 0..4 {
                    rgba[channel] = (sums[channel] / total).round() as u8;
                }
                out.put_pixel(ox, oy, image::Rgba(rgba));
            }
        }
    }
    out
}

/// Composite one pixel over black: the downscale census reads
/// RGB the way PIL's `convert("RGB")` does, so a transparent
/// pixel contributes black, not its stored colour.
fn composite_over_black(pixel: image::Rgba<u8>) -> [u8; 3] {
    let alpha = u32::from(pixel[3]);
    [
        (u32::from(pixel[0]) * alpha / 255) as u8,
        (u32::from(pixel[1]) * alpha / 255) as u8,
        (u32::from(pixel[2]) * alpha / 255) as u8,
    ]
}

/// (unique colours, mean per-channel gradient, width,
/// height) of the standard downscale, over composited RGB.
fn downscale_census(frame: &RgbaImage) -> (usize, f64, u32, u32) {
    let small = downscale_to_standard(frame);
    let (width, height) = (small.width(), small.height());
    let mut unique: HashSet<u32> = HashSet::new();
    let mut gradient_sum = 0_u64;
    let mut pairs = 0_u64;
    for y in 0..height {
        let mut previous: Option<[u8; 3]> = None;
        for x in 0..width {
            let rgb = composite_over_black(*small.get_pixel(x, y));
            unique.insert((u32::from(rgb[0]) << 16) | (u32::from(rgb[1]) << 8) | u32::from(rgb[2]));
            if let Some(before) = previous {
                for channel in 0..3 {
                    gradient_sum += u64::from(rgb[channel].abs_diff(before[channel]));
                }
                pairs += 1;
            }
            previous = Some(rgb);
        }
    }
    let gradient = if pairs == 0 {
        0.0
    } else {
        gradient_sum as f64 / (pairs * 3) as f64
    };
    (unique.len(), gradient, small.width(), small.height())
}

/// Tonal bands and colour-zone proxies over sampled opaque
/// pixels (the `spec` stride discipline: deterministic,
/// capped at `spec::SAMPLE_PIXELS_MAX`).
struct ZoneStats {
    blush_load: f64,
    hair_mass_share: f64,
    highlight_steps: usize,
    shadow_steps: usize,
    specular_share: f64,
    tonal_steps: usize,
}

fn zone_stats(frame: &RgbaImage) -> ZoneStats {
    let mut opaque: Vec<[u8; 3]> = Vec::new();
    for pixel in frame.pixels() {
        if pixel[3] >= spec::ALPHA_OPAQUE_MIN {
            opaque.push([pixel[0], pixel[1], pixel[2]]);
        }
    }
    let stride = opaque.len().div_ceil(spec::SAMPLE_PIXELS_MAX).max(1);
    let sampled: Vec<[u8; 3]> = opaque.iter().step_by(stride).copied().collect();
    let total = sampled.len().max(1) as f64;

    let mut histogram = [0_u64; 256];
    let mut bands = [0_u64; TONAL_BANDS];
    let mut blush = 0_u64;
    let mut hair = 0_u64;
    let mut specular = 0_u64;
    for pixel in &sampled {
        let (hue, saturation, lightness) = spec::rgb_to_hsl(pixel[0], pixel[1], pixel[2]);
        histogram[(lightness * 255.0).round() as usize] += 1;
        bands[((lightness * TONAL_BANDS as f64) as usize).min(TONAL_BANDS - 1)] += 1;
        if lightness >= 0.93 {
            specular += 1;
        }
        if let Some(degrees) = hue {
            if (degrees >= 345.0 || degrees <= 25.0)
                && saturation >= 0.25
                && (0.30..=0.80).contains(&lightness)
            {
                blush += 1;
            }
            if (12.0..=48.0).contains(&degrees)
                && saturation >= 0.18
                && (0.08..=0.55).contains(&lightness)
            {
                hair += 1;
            }
        }
    }
    // Median lightness level from the histogram (the p50
    // rule of `spec`'s percentile, restated for the band
    // split): shadow bands sit below it, highlight above.
    let target = (0.5 * total).ceil() as u64;
    let mut seen = 0_u64;
    let mut median_level = 255.0_f64;
    for (level, count) in histogram.iter().enumerate() {
        seen += count;
        if seen >= target.max(1) {
            median_level = level as f64;
            break;
        }
    }
    let populated = |band: usize| bands[band] as f64 >= BAND_POPULATED_MIN * total;
    let mut tonal_steps = 0_usize;
    let mut shadow_steps = 0_usize;
    let mut highlight_steps = 0_usize;
    for band in 0..TONAL_BANDS {
        if !populated(band) {
            continue;
        }
        tonal_steps += 1;
        let centre = (band as f64 + 0.5) * 255.0 / TONAL_BANDS as f64;
        if centre < median_level {
            shadow_steps += 1;
        } else if centre > median_level {
            highlight_steps += 1;
        }
    }
    ZoneStats {
        blush_load: blush as f64 / total,
        hair_mass_share: hair as f64 / total,
        highlight_steps,
        shadow_steps,
        specular_share: specular as f64 / total,
        tonal_steps,
    }
}

/// Measure one decoded still. `palette_colors` is validated
/// by the caller (1..=16).
pub fn measure_still(frame: &RgbaImage, palette_colors: usize) -> StillFacts {
    let measured: FrameSpec = spec::measure_frame(frame, palette_colors);
    let (unique_colours_256w, gradient_256w, downscale_width, downscale_height) =
        downscale_census(frame);
    let zones = zone_stats(frame);
    StillFacts {
        downscale_height,
        downscale_width,
        facts: CensusFacts {
            alpha_fraction: measured.alpha_fraction,
            blush_load: zones.blush_load,
            gradient_256w,
            hair_mass_share: zones.hair_mass_share,
            highlight_steps: zones.highlight_steps,
            mean_hue_deg: measured.mean_hue_deg,
            mean_saturation: measured.mean_saturation,
            shading_model: measured.shading_model.to_string(),
            shadow_steps: zones.shadow_steps,
            specular_share: zones.specular_share,
            tonal_steps: zones.tonal_steps,
            unique_colours_256w,
        },
        lightness_p05: measured.lightness_p05,
        lightness_p50: measured.lightness_p50,
        lightness_p95: measured.lightness_p95,
        mean_lightness: measured.mean_lightness,
        palette: measured.palette,
        sampled_pixels: measured.sampled_pixels,
    }
}

/// The accent tracks a still implies, each with its basis:
/// `measured` (a census quantity crossed a stated floor) or
/// `doctrine` (the determination's held-cel minimum for any
/// portrait base, §3.5 — stated, not measured).
#[derive(Clone, Debug)]
pub struct TrackReading {
    /// doctrine | measured
    pub basis: &'static str,
    /// Whether the still implies the track.
    pub implied: bool,
    /// blink | breath | expression_travel | hair_strands |
    /// specular_tear
    pub track: &'static str,
}

/// The shading depth a drawn reproduction must hold.
#[derive(Clone, Debug)]
pub struct ReproductionDepth {
    /// Whether the still itself meets the family floor.
    pub meets_family_floor: bool,
    /// The requirement word for the reproduction's shading
    /// stack, from the still's shading model.
    pub requirement: &'static str,
    /// Highlight steps the reproduction must hold.
    pub required_highlight_steps: usize,
    /// Shadow steps the reproduction must hold.
    pub required_shadow_steps: usize,
}

/// One discernment: register, tracks, reproduction depth,
/// and the named gaps (aspect, reason) a still cannot close.
#[derive(Clone, Debug)]
pub struct Discernment {
    /// The accent tracks the still implies.
    pub accent_tracks: Vec<TrackReading>,
    /// (aspect, reason) pairs for the envelope's unknowns.
    pub gaps: Vec<(String, String)>,
    /// neutral_warm | flustered | overwhelmed | undetermined
    pub register_state: &'static str,
    /// The shading depth a reproduction must hold.
    pub reproduction: ReproductionDepth,
}

/// The register rule (stated verbatim in the tool's
/// limitation text): strong blush load reads overwhelmed;
/// moderate reads flustered; negligible blush and specular
/// with a warm cast reads neutral_warm; anything else is
/// undetermined — the tool does not invent a state the
/// colour-zone evidence does not carry.
fn register_state(facts: &CensusFacts) -> &'static str {
    if facts.blush_load >= BLUSH_STRONG {
        "overwhelmed"
    } else if facts.blush_load >= BLUSH_MODERATE {
        "flustered"
    } else if facts.blush_load < BLUSH_NEGLIGIBLE && facts.specular_share < SPECULAR_TRACK_MIN {
        match facts.mean_hue_deg {
            Some(hue) if (10.0..=60.0).contains(&hue) || facts.mean_saturation >= 0.10 => {
                "neutral_warm"
            }
            _ => "undetermined",
        }
    } else {
        "undetermined"
    }
}

/// Discern how to hand-animate a still from its census
/// facts. Pure: the same facts always produce the same
/// reading.
pub fn discern(facts: &CensusFacts) -> Discernment {
    let register = register_state(facts);
    let hair_implied = facts.hair_mass_share >= HAIR_TRACK_MIN;
    let specular_implied = facts.specular_share >= SPECULAR_TRACK_MIN;
    let travel_measured = matches!(register, "flustered" | "overwhelmed");
    let accent_tracks = vec![
        TrackReading {
            basis: "doctrine",
            implied: true,
            track: "blink",
        },
        TrackReading {
            basis: "doctrine",
            implied: true,
            track: "breath",
        },
        TrackReading {
            basis: if travel_measured {
                "measured"
            } else {
                "doctrine"
            },
            implied: travel_measured || register == "neutral_warm",
            track: "expression_travel",
        },
        TrackReading {
            basis: "measured",
            implied: hair_implied,
            track: "hair_strands",
        },
        TrackReading {
            basis: "measured",
            implied: specular_implied,
            track: "specular_tear",
        },
    ];
    let requirement = match facts.shading_model.as_str() {
        "soft" => "multi_step_soft",
        "mixed" => "multi_step_mixed",
        "cel" => "cel_steps",
        _ => "flat",
    };
    let mut gaps: Vec<(String, String)> = vec![
        (
            "cadence_and_timing".to_string(),
            "a still carries no timing: frame durations, holds, and exposure \
             choices cannot be discerned from one image"
                .to_string(),
        ),
        (
            "blink_phase_behaviour".to_string(),
            "blink timing and phase are motion properties; the still implies \
             the track, never its exposures"
                .to_string(),
        ),
        (
            "expression_travel_path".to_string(),
            "which chart states a loop visits, in what order, and with what \
             holds is a drawing decision; the still fixes at most the state \
             it sits in"
                .to_string(),
        ),
        (
            "face_geometry_and_expression_semantics".to_string(),
            "register is read from colour-zone and tonal evidence only; face \
             geometry and expression semantics are not measured here and \
             remain with the drawing-side Step-0 lock and per-state gates"
                .to_string(),
        ),
    ];
    if hair_implied {
        gaps.push((
            "hair_sway_phase".to_string(),
            "the still implies loose strands but cannot determine their sway \
             phase, period, or offset from the breath track"
                .to_string(),
        ));
    }
    if register == "overwhelmed" {
        gaps.push((
            "register_spent_distinction".to_string(),
            "the spent state is not separable from overwhelmed in a single \
             still; both share the colour-zone evidence this reading uses"
                .to_string(),
        ));
    }
    if register == "undetermined" {
        gaps.push((
            "register_state".to_string(),
            "the colour-zone evidence is mixed or weak: no chart state is \
             claimed for this still"
                .to_string(),
        ));
    }
    Discernment {
        accent_tracks,
        gaps,
        register_state: register,
        reproduction: ReproductionDepth {
            meets_family_floor: facts.unique_colours_256w >= FAMILY_FLOOR_UNIQUE_COLOURS
                && facts.gradient_256w >= FAMILY_FLOOR_GRADIENT,
            requirement,
            required_highlight_steps: facts.highlight_steps,
            required_shadow_steps: facts.shadow_steps,
        },
    }
}

/// The JSON form of the register finding's facts.
pub fn register_json(facts: &CensusFacts, reading: &Discernment) -> Value {
    json!({
        "blush_load": round4(facts.blush_load),
        "mean_saturation": round4(facts.mean_saturation),
        "specular_share": round4(facts.specular_share),
        "state": reading.register_state,
    })
}

/// The JSON form of the accent-tracks finding's facts.
pub fn tracks_json(reading: &Discernment) -> Value {
    json!({
        "tracks": reading.accent_tracks.iter().map(|track| json!({
            "basis": track.basis,
            "implied": track.implied,
            "track": track.track,
        })).collect::<Vec<_>>(),
    })
}

/// The JSON form of the shading-depth finding's facts.
pub fn depth_json(facts: &CensusFacts, reading: &Discernment) -> Value {
    json!({
        "family_floor": {
            "min_mean_gradient_256w": FAMILY_FLOOR_GRADIENT,
            "min_unique_colours_256w": FAMILY_FLOOR_UNIQUE_COLOURS,
        },
        "meets_family_floor": reading.reproduction.meets_family_floor,
        "requirement": reading.reproduction.requirement,
        "required_highlight_steps": reading.reproduction.required_highlight_steps,
        "required_shadow_steps": reading.reproduction.required_shadow_steps,
        "still_mean_gradient_256w": round2(facts.gradient_256w),
        "still_unique_colours_256w": facts.unique_colours_256w,
    })
}

/// Parse census facts from a caller-supplied census object:
/// either the `census_media_file` evidence envelope (facts
/// are read from its media_census / tonal / register_evidence
/// findings) or a flat object carrying the same fields.
/// Every failure names the field or finding that is missing
/// or out of range — a malformed census is a named refusal,
/// never a partial reading.
pub fn facts_from_json(value: &Value) -> Result<CensusFacts, String> {
    let facts = if let Some(findings) = value.get("findings").and_then(Value::as_array) {
        let find = |kind: &str| -> Result<&Value, String> {
            findings
                .iter()
                .find(|finding| finding["kind"] == kind)
                .map(|finding| &finding["facts"])
                .ok_or_else(|| format!("census envelope has no '{kind}' finding"))
        };
        let census = find("media_census")?;
        let tonal = find("tonal")?;
        let zones = find("register_evidence")?;
        CensusFacts {
            alpha_fraction: req_f64(zones, "alpha_fraction")?,
            blush_load: req_f64(zones, "blush_load")?,
            gradient_256w: req_f64(census, "mean_gradient_256w")?,
            hair_mass_share: req_f64(zones, "hair_mass_share")?,
            highlight_steps: req_usize(tonal, "highlight_steps")?,
            mean_hue_deg: tonal.get("mean_hue_deg").and_then(Value::as_f64),
            mean_saturation: req_f64(tonal, "mean_saturation")?,
            shading_model: req_string(tonal, "shading_model")?,
            shadow_steps: req_usize(tonal, "shadow_steps")?,
            specular_share: req_f64(zones, "specular_share")?,
            tonal_steps: req_usize(tonal, "tonal_steps")?,
            unique_colours_256w: req_usize(census, "unique_colours_256w")?,
        }
    } else {
        CensusFacts {
            alpha_fraction: req_f64(value, "alpha_fraction")?,
            blush_load: req_f64(value, "blush_load")?,
            gradient_256w: req_f64(value, "mean_gradient_256w")?,
            hair_mass_share: req_f64(value, "hair_mass_share")?,
            highlight_steps: req_usize(value, "highlight_steps")?,
            mean_hue_deg: value.get("mean_hue_deg").and_then(Value::as_f64),
            mean_saturation: req_f64(value, "mean_saturation")?,
            shading_model: req_string(value, "shading_model")?,
            shadow_steps: req_usize(value, "shadow_steps")?,
            specular_share: req_f64(value, "specular_share")?,
            tonal_steps: req_usize(value, "tonal_steps")?,
            unique_colours_256w: req_usize(value, "unique_colours_256w")?,
        }
    };
    validate_facts(&facts)?;
    Ok(facts)
}

fn req_f64(object: &Value, key: &str) -> Result<f64, String> {
    object
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("census field '{key}' is missing or not a number"))
}

fn req_usize(object: &Value, key: &str) -> Result<usize, String> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .ok_or_else(|| format!("census field '{key}' is missing or not an unsigned integer"))
}

fn req_string(object: &Value, key: &str) -> Result<String, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("census field '{key}' is missing or not a string"))
}

fn validate_facts(facts: &CensusFacts) -> Result<(), String> {
    for (key, share) in [
        ("alpha_fraction", facts.alpha_fraction),
        ("blush_load", facts.blush_load),
        ("hair_mass_share", facts.hair_mass_share),
        ("mean_saturation", facts.mean_saturation),
        ("specular_share", facts.specular_share),
    ] {
        if !(0.0..=1.0).contains(&share) {
            return Err(format!("census field '{key}' is {share}, outside 0..=1"));
        }
    }
    if !(0.0..=255.0).contains(&facts.gradient_256w) {
        return Err(format!(
            "census field 'mean_gradient_256w' is {}, outside 0..=255",
            facts.gradient_256w
        ));
    }
    if !matches!(
        facts.shading_model.as_str(),
        "flat" | "cel" | "soft" | "mixed"
    ) {
        return Err(format!(
            "census field 'shading_model' is '{}', not flat / cel / soft / mixed",
            facts.shading_model
        ));
    }
    Ok(())
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

    fn facts(
        blush: f64,
        specular: f64,
        hair: f64,
        unique: usize,
        gradient: f64,
        model: &str,
    ) -> CensusFacts {
        CensusFacts {
            alpha_fraction: 0.0,
            blush_load: blush,
            gradient_256w: gradient,
            hair_mass_share: hair,
            highlight_steps: 3,
            mean_hue_deg: Some(30.0),
            mean_saturation: 0.4,
            shading_model: model.to_string(),
            shadow_steps: 4,
            specular_share: specular,
            tonal_steps: 9,
            unique_colours_256w: unique,
        }
    }

    /// A smooth two-axis ramp: colour varies along both
    /// axes, so the downscale carries tens of thousands of
    /// colours at small per-step deltas — the rich signature.
    fn ramp(width: u32, height: u32) -> RgbaImage {
        let mut image = RgbaImage::new(width, height);
        for y in 0..height {
            for x in 0..width {
                let tx = x as f64 / (width - 1) as f64;
                let ty = y as f64 / (height - 1) as f64;
                image.put_pixel(
                    x,
                    y,
                    Rgba([
                        (255.0 * tx) as u8,
                        (255.0 * ty) as u8,
                        (255.0 * (tx + ty) / 2.0) as u8,
                        255,
                    ]),
                );
            }
        }
        image
    }

    #[test]
    fn validation_downscale_hits_standard_width() {
        let image = ramp(1024, 1280);
        let small = downscale_to_standard(&image);
        assert_eq!(small.width(), DOWNSCALE_WIDTH);
        assert_eq!(small.height(), 320);
        // Deterministic: a second downscale is byte-identical.
        let again = downscale_to_standard(&image);
        assert_eq!(small.as_raw(), again.as_raw());
        // A frame already under the standard is untouched.
        let tiny = ramp(100, 80);
        assert_eq!(downscale_to_standard(&tiny).as_raw(), tiny.as_raw());
    }

    #[test]
    fn validation_rich_ramp_beats_flat_fill() {
        // The determination's headline, in miniature: a rich
        // ramp carries orders of magnitude more colours at
        // the downscale than a flat fill, at higher gradient.
        let rich = measure_still(&ramp(512, 512), 8);
        assert!(rich.facts.unique_colours_256w > 5_000);
        assert!(rich.facts.gradient_256w > 0.25);
        let flat = measure_still(
            &RgbaImage::from_pixel(512, 512, Rgba([200, 120, 90, 255])),
            8,
        );
        assert_eq!(flat.facts.unique_colours_256w, 1);
        assert_eq!(flat.facts.gradient_256w, 0.0);
        assert_eq!(flat.facts.tonal_steps, 1);
        assert_eq!(flat.facts.shading_model, "flat");
    }

    #[test]
    fn validation_discernment_rule_table() {
        // Strong blush + specular + hair mass + rich census:
        // the overwhelmed reading with every track implied.
        let reading = discern(&facts(0.12, 0.01, 0.30, 36_000, 10.0, "soft"));
        assert_eq!(reading.register_state, "overwhelmed");
        assert!(reading.reproduction.meets_family_floor);
        assert_eq!(reading.reproduction.requirement, "multi_step_soft");
        assert!(
            reading.accent_tracks.iter().all(|track| track.implied),
            "tracks: {:?}",
            reading.accent_tracks
        );
        assert!(
            reading
                .gaps
                .iter()
                .any(|(aspect, _)| aspect == "register_spent_distinction")
        );
        // Moderate blush reads flustered; the floor fails on
        // a flat census and the requirement follows the model.
        let reading = discern(&facts(0.03, 0.0, 0.0, 3_976, 4.37, "mixed"));
        assert_eq!(reading.register_state, "flustered");
        assert!(!reading.reproduction.meets_family_floor);
        assert_eq!(reading.reproduction.requirement, "multi_step_mixed");
        let hair = reading
            .accent_tracks
            .iter()
            .find(|track| track.track == "hair_strands")
            .expect("hair track");
        assert!(!hair.implied);
    }

    #[test]
    fn validation_facts_round_trip_through_flat_json() {
        let flat = json!({
            "alpha_fraction": 0.0,
            "blush_load": 0.12,
            "hair_mass_share": 0.30,
            "highlight_steps": 3,
            "mean_gradient_256w": 10.0,
            "mean_hue_deg": 30.0,
            "mean_saturation": 0.4,
            "shading_model": "soft",
            "shadow_steps": 4,
            "specular_share": 0.01,
            "tonal_steps": 9,
            "unique_colours_256w": 36_000,
        });
        let parsed = facts_from_json(&flat).unwrap();
        assert_eq!(parsed.unique_colours_256w, 36_000);
        assert_eq!(discern(&parsed).register_state, "overwhelmed");
        // The envelope form reads the same facts out of the
        // census tool's findings.
        let envelope = json!({
            "findings": [
                {"kind": "media_census", "facts": {
                    "mean_gradient_256w": 10.0, "unique_colours_256w": 36_000}},
                {"kind": "tonal", "facts": {
                    "highlight_steps": 3, "mean_hue_deg": 30.0,
                    "mean_saturation": 0.4, "shading_model": "soft",
                    "shadow_steps": 4, "tonal_steps": 9}},
                {"kind": "register_evidence", "facts": {
                    "alpha_fraction": 0.0, "blush_load": 0.12,
                    "hair_mass_share": 0.30, "specular_share": 0.01}},
            ],
        });
        let parsed = facts_from_json(&envelope).unwrap();
        assert_eq!(parsed.blush_load, 0.12);
        assert_eq!(parsed.shading_model, "soft");
    }

    #[test]
    fn adversarial_census_json_missing_field_is_named() {
        let error = facts_from_json(&json!({"blush_load": 0.1})).unwrap_err();
        assert!(error.contains("alpha_fraction"), "error: {error}");
        let error = facts_from_json(&json!({
            "alpha_fraction": 0.0, "blush_load": 1.5, "hair_mass_share": 0.0,
            "highlight_steps": 0, "mean_gradient_256w": 0.0,
            "mean_saturation": 0.0, "shading_model": "soft",
            "shadow_steps": 0, "specular_share": 0.0, "tonal_steps": 0,
            "unique_colours_256w": 0,
        }))
        .unwrap_err();
        assert!(error.contains("blush_load"), "error: {error}");
    }

    #[test]
    fn adversarial_no_register_content_is_undetermined() {
        // A flat blue-grey still: no blush, no specular, no
        // warm cast. The reading must not invent a state.
        let mut f = facts(0.0, 0.0, 0.0, 40, 0.5, "flat");
        f.mean_hue_deg = Some(210.0);
        f.mean_saturation = 0.05;
        let reading = discern(&f);
        assert_eq!(reading.register_state, "undetermined");
        assert!(
            reading
                .gaps
                .iter()
                .any(|(aspect, _)| aspect == "register_state")
        );
        let travel = reading
            .accent_tracks
            .iter()
            .find(|track| track.track == "expression_travel")
            .expect("travel track");
        assert!(!travel.implied);
    }

    #[test]
    fn adversarial_transparent_frame_has_no_zones() {
        // Fully transparent: no opaque pixels, so every zone
        // share is zero — reported, never invented.
        let image = RgbaImage::from_pixel(64, 64, Rgba([255, 100, 100, 0]));
        let still = measure_still(&image, 8);
        assert_eq!(still.facts.alpha_fraction, 1.0);
        assert_eq!(still.facts.blush_load, 0.0);
        assert_eq!(still.facts.specular_share, 0.0);
        assert_eq!(still.facts.hair_mass_share, 0.0);
        assert_eq!(still.facts.tonal_steps, 0);
    }
}
