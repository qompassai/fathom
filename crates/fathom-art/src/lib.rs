//! Art/animation style provider (SPEC §9.5).
//!
//! The split this provider enforces, per the commission:
//! fathom *measures* style and performs deterministic,
//! analysis-adjacent transforms (palette remap) natively;
//! anything that grades or renders goes through lumen
//! (`apply_style_via_lumen`), and the bridge closes the loop by
//! re-measuring lumen's output against the reference spec.
//! Every descriptor in every finding traces to a measurement
//! in `spec`/`media` — observed, derived (with the rule stated
//! as a limitation), or declared unknown.

#![forbid(unsafe_code)]

pub mod base64;
pub mod lumen;
pub mod media;
pub mod remap;
pub mod spec;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, require_str};

use media::LoopBehavior;

/// Input size bound for art targets (bytes). Image decode is
/// the memory risk, and 64 MiB of compressed image is far past
/// any sprite or portrait this provider serves; the pixel bound
/// in `media` is the second wall.
pub const ART_BYTES_MAX: u64 = 64 * 1024 * 1024;
/// Default palette clusters when the caller does not ask.
pub const PALETTE_COLORS_DEFAULT: u64 = 8;
/// Palette clusters a caller may request at most.
pub const PALETTE_COLORS_MAX: u64 = 16;

/// Register the art provider's tools.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "analyze_art_style",
            ToolClass::Read,
            "art",
            "Measured style spec of an image or GIF: palette, grade statistics, \
             shading model, animation timing grammar, sheet geometry",
            analyze_schema(),
        ),
        Arc::new(analyze_art_style),
    );
    registry.register(
        descriptor(
            "apply_style_via_lumen",
            ToolClass::Execute,
            "art",
            "Grade an image with lumen's style engine (stdio MCP style_apply) and \
             verify the output against an optional reference style spec",
            lumen_schema(),
        ),
        Arc::new(apply_style_via_lumen),
    );
    registry.register(
        descriptor(
            "remap_palette",
            ToolClass::Execute,
            "art",
            "Native deterministic palette remap of an image (nearest or exact) \
             to a supplied palette or another asset's measured palette",
            remap_schema(),
        ),
        Arc::new(remap_palette),
    );
}

fn analyze_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "palette_colors": {
                "type": "integer", "minimum": 1, "maximum": 16,
                "description": "Palette clusters to extract (default 8)",
            },
            "target": {"type": "string", "description": "Path under a configured target root"},
        },
        "required": ["target"],
        "additionalProperties": false,
    })
}

fn remap_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["exact", "nearest"], "description": "Default nearest"},
            "output": {"type": "string", "description": "Output file name (.png), written under the state dir"},
            "palette": {
                "type": "array", "items": {"type": "string"},
                "description": "#RRGGBB entries (1..=256); mutually exclusive with palette_from",
            },
            "palette_from": {"type": "string", "description": "Art target whose measured palette to use"},
            "target": {"type": "string", "description": "Path under a configured target root"},
        },
        "required": ["output", "target"],
        "additionalProperties": false,
    })
}

fn lumen_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "lumen_program": {"type": "string", "description": "Lumen binary name; must be in allow_programs"},
            "output": {"type": "string", "description": "Output file name (.png), written under the state dir"},
            "preset": {"type": "string", "description": "Lumen style preset name (see lumen style_list)"},
            "reference": {"type": "string", "description": "Optional art target whose style spec the output is verified against"},
            "strength": {"type": "number", "minimum": 0.0, "maximum": 1.0, "description": "Grade strength (default 1.0)"},
            "target": {"type": "string", "description": "Path under a configured target root"},
        },
        "required": ["lumen_program", "output", "preset", "target"],
        "additionalProperties": false,
    })
}

fn palette_colors_arg(args: &Value) -> Result<usize, FathomError> {
    match args.get("palette_colors") {
        None => Ok(PALETTE_COLORS_DEFAULT as usize),
        Some(value) => {
            let count = value.as_u64().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    "argument 'palette_colors' must be an integer",
                )
            })?;
            if count == 0 || count > PALETTE_COLORS_MAX {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("argument 'palette_colors' must be 1..={PALETTE_COLORS_MAX}"),
                ));
            }
            Ok(count as usize)
        }
    }
}

/// Validate a target and read its bytes under the art bound.
fn read_art_target(config: &Config, target: &str) -> Result<(PathBuf, Vec<u8>), FathomError> {
    let path = paths::validate_target(config, Path::new(target))?;
    let metadata = std::fs::metadata(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat target: {e}"),
        )
        .with_target(target.to_string())
    })?;
    if metadata.len() > ART_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "art target is {} bytes; the bound is {ART_BYTES_MAX}",
                metadata.len()
            ),
        )
        .with_target(target.to_string()));
    }
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
        .with_target(target.to_string())
    })?;
    Ok((path, bytes))
}

fn decode(bytes: &[u8], target: &str) -> Result<media::DecodedArt, FathomError> {
    media::decode_art(bytes).map_err(|message| {
        let code = if message.starts_with("unsupported image format") {
            ErrorCode::UnsupportedTarget
        } else {
            ErrorCode::ExecutionFailure
        };
        FathomError::new(code, message).with_target(target.to_string())
    })
}

/// An output name must be a bare `.png` file name; outputs live
/// under a state subdir, never at a caller-chosen path.
fn validate_output_name(output: &str) -> Result<(), FathomError> {
    let bad = output.is_empty()
        || output == "."
        || output == ".."
        || output.contains('/')
        || output.contains('\\')
        || !output.to_lowercase().ends_with(".png");
    if bad {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("output '{output}' must be a bare .png file name"),
        ));
    }
    Ok(())
}

fn write_png(frame: &image::RgbaImage, path: &Path) -> Result<(), FathomError> {
    frame
        .save_with_format(path, image::ImageFormat::Png)
        .map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot write output {}: {e}", path.display()),
            )
        })
}

fn analyze_art_style(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let palette_colors = palette_colors_arg(args)?;
    let (path, bytes) = read_art_target(config, target)?;
    let subject = subject_for_file(&path)?;
    let art = decode(&bytes, target)?;
    let measured = spec::measure_frame(&art.first_frame, palette_colors);

    let mut evidence = Evidence::new("analyze_art_style", "art");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.add_finding(Finding::new(
        "artwork",
        Confidence::Observed,
        json!({
            "format": art.format,
            "frames": art.animation.as_ref().map_or(1, |a| a.frame_count),
            "height": art.first_frame.height(),
            "width": art.first_frame.width(),
        }),
    ));
    evidence.add_finding(
        Finding::new(
            "palette",
            Confidence::Observed,
            json!({
                "colors": measured.palette.iter().map(|entry| json!({
                    "coverage": (entry.coverage * 10_000.0).round() / 10_000.0,
                    "hex": entry.hex,
                    "rgb": entry.rgb,
                })).collect::<Vec<_>>(),
                "sampled_pixels": measured.sampled_pixels,
                "unique_colors": measured.unique_colors,
                "unique_colors_capped": measured.unique_colors_capped,
            }),
        )
        .with_limitation(
            "median-cut clusters over opaque pixels (alpha >= 128), sampled on a \
             deterministic stride when the frame exceeds the sample bound; \
             transparent pixels are not part of the palette",
        ),
    );
    evidence.add_finding(
        Finding::new(
            "grade",
            Confidence::Derived,
            json!({
                "contrast": (measured.contrast * 10_000.0).round() / 10_000.0,
                "lightness_levels_present": measured.lightness_levels_present,
                "lightness_p05": (measured.lightness_p05 * 10_000.0).round() / 10_000.0,
                "lightness_p50": (measured.lightness_p50 * 10_000.0).round() / 10_000.0,
                "lightness_p95": (measured.lightness_p95 * 10_000.0).round() / 10_000.0,
                "mean_hue_deg": measured.mean_hue_deg.map(|h| (h * 100.0).round() / 100.0),
                "mean_lightness": (measured.mean_lightness * 10_000.0).round() / 10_000.0,
                "mean_saturation": (measured.mean_saturation * 10_000.0).round() / 10_000.0,
            }),
        )
        .with_limitation(
            "HSL statistics over sampled opaque pixels; hue is the \
             saturation-weighted circular mean and is null when the frame \
             has no chromatic pixels",
        ),
    );
    evidence.add_finding(
        Finding::new(
            "shading",
            Confidence::Derived,
            json!({
                "alpha_fraction": (measured.alpha_fraction * 10_000.0).round() / 10_000.0,
                "edge_density": (measured.edge_density * 10_000.0).round() / 10_000.0,
                "gradient_fraction": (measured.gradient_fraction * 10_000.0).round() / 10_000.0,
                "model": measured.shading_model,
            }),
        )
        .with_limitation(
            "classification rule: flat when <= 16 distinct opaque colors; cel \
             when lightness occupies <= 8 populated levels and smooth-gradient \
             neighbour pairs are < 25%; soft when such pairs are >= 25%; \
             mixed otherwise",
        ),
    );
    if let Some(animation) = &art.animation {
        let total_ms: u64 = animation.durations_ms.iter().map(|d| u64::from(*d)).sum();
        evidence.add_finding(Finding::new(
            "animation",
            Confidence::Observed,
            json!({
                "durations_ms": animation.durations_ms,
                "frame_count": animation.frame_count,
                "frames_truncated": animation.frames_truncated,
                "holds": media::holds(&animation.durations_ms).iter().map(|(d, n)| json!({
                    "duration_ms": d, "frames": n,
                })).collect::<Vec<_>>(),
                "loop": match animation.loop_behavior {
                    LoopBehavior::Infinite => json!("infinite"),
                    LoopBehavior::Iterations(n) => json!({"iterations": n}),
                    LoopBehavior::PlayOnce => json!("play_once"),
                },
                "total_ms": total_ms,
            }),
        ));
        if !animation.motion_per_transition.is_empty() {
            evidence.add_finding(
                Finding::new(
                    "motion",
                    Confidence::Derived,
                    json!({
                        "easing": media::classify_easing(&animation.motion_per_transition),
                        "motion_per_transition": animation.motion_per_transition.iter()
                            .map(|m| (m * 10_000.0).round() / 10_000.0)
                            .collect::<Vec<_>>(),
                    }),
                )
                .with_limitation(
                    "motion is the mean absolute RGB delta between consecutive \
                     frames as decoded; easing is classified from where the \
                     cumulative motion curve sits at its midpoint",
                ),
            );
        }
        if animation.frames_truncated {
            evidence.coverage.exhaustive = false;
        }
    }
    if let Some(reason) = &art.timing_unknown {
        evidence.add_unknown("animation_timing", reason.clone());
    }
    match &art.sheet {
        Some(sheet) => {
            evidence.add_finding(
                Finding::new(
                    "sheet",
                    Confidence::Derived,
                    json!({
                        "basis": "transparent_gutters",
                        "cell_height": sheet.cell_height,
                        "cell_width": sheet.cell_width,
                        "columns": sheet.columns,
                        "rows": sheet.rows,
                    }),
                )
                .with_limitation(
                    "grid inferred only from fully transparent gutter bands \
                     that divide both axes into uniform cells",
                ),
            );
        }
        None => {
            if measured.alpha_fraction > 0.01 {
                evidence.add_unknown(
                    "sheet_geometry",
                    "the frame has transparency but no periodic transparent \
                     gutters; a sheet grid cannot be established from gutters",
                );
            }
        }
    }
    Ok(evidence.to_value())
}

fn remap_palette(_: &Registry, config: &Config, args: &Value) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let output = require_str(args, "output")?;
    validate_output_name(output)?;
    let exact = match args.get("mode").and_then(Value::as_str) {
        None | Some("nearest") => false,
        Some("exact") => true,
        Some(other) => {
            return Err(FathomError::new(
                ErrorCode::InvalidRequest,
                format!("mode '{other}' is not 'nearest' or 'exact'"),
            ));
        }
    };
    let palette = resolve_palette(config, args)?;
    let (path, bytes) = read_art_target(config, target)?;
    let subject = subject_for_file(&path)?;
    let art = decode(&bytes, target)?;
    let (out_frame, counts) = remap::remap_frame(&art.first_frame, &palette, exact);
    let out_dir = paths::state_subdir(config, "art-output")?;
    let out_path = out_dir.join(output);
    write_png(&out_frame, &out_path)?;
    let out_subject = subject_for_file(&out_path)?;

    let mut evidence = Evidence::new("remap_palette", "art");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.add_finding(
        Finding::new(
            "remap",
            Confidence::Observed,
            json!({
                "alpha_skipped": counts.alpha_skipped,
                "mapped": counts.mapped,
                "mode": if exact { "exact" } else { "nearest" },
                "output_bytes": out_subject.size_bytes,
                "output_path": out_path.display().to_string(),
                "output_sha256": out_subject.sha256,
                "palette": palette.iter().map(|rgb| remap::palette_hex(*rgb)).collect::<Vec<_>>(),
                "unmapped": counts.unmapped,
            }),
        )
        .with_limitation(
            "nearest mode measures distance in RGB space; exact mode leaves \
             non-member pixels unchanged and counts them as unmapped; \
             transparent pixels are never rewritten",
        ),
    );
    Ok(evidence.to_value())
}

/// The palette for a remap: an explicit list, or the measured
/// palette of another art target. Exactly one source.
fn resolve_palette(config: &Config, args: &Value) -> Result<Vec<[u8; 3]>, FathomError> {
    let explicit = args.get("palette");
    let from = args.get("palette_from").and_then(Value::as_str);
    match (explicit, from) {
        (Some(_), Some(_)) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "give exactly one of 'palette' and 'palette_from'",
        )),
        (None, None) => Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "one of 'palette' or 'palette_from' is required",
        )),
        (Some(raw), None) => {
            let values: Vec<String> = raw
                .as_array()
                .ok_or_else(|| {
                    FathomError::new(
                        ErrorCode::InvalidRequest,
                        "argument 'palette' must be an array of #RRGGBB strings",
                    )
                })?
                .iter()
                .map(|entry| {
                    entry.as_str().map(str::to_string).ok_or_else(|| {
                        FathomError::new(
                            ErrorCode::InvalidRequest,
                            "argument 'palette' must be an array of #RRGGBB strings",
                        )
                    })
                })
                .collect::<Result<_, _>>()?;
            remap::parse_palette(&values)
                .map_err(|message| FathomError::new(ErrorCode::InvalidRequest, message))
        }
        (None, Some(source)) => {
            let palette_colors = palette_colors_arg(args)?;
            let (_, bytes) = read_art_target(config, source)?;
            let art = decode(&bytes, source)?;
            let measured = spec::measure_frame(&art.first_frame, palette_colors);
            if measured.palette.is_empty() {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("palette source '{source}' has no opaque pixels to measure"),
                ));
            }
            Ok(measured.palette.iter().map(|entry| entry.rgb).collect())
        }
    }
}

fn apply_style_via_lumen(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target = require_str(args, "target")?;
    let preset = require_str(args, "preset")?;
    let output = require_str(args, "output")?;
    let program = require_str(args, "lumen_program")?;
    validate_output_name(output)?;
    if !config.allow_programs.iter().any(|name| name == program) {
        return Err(FathomError::new(
            ErrorCode::AccessDenied,
            format!("lumen program '{program}' is not in allow_programs"),
        )
        .with_remediation(
            "Add the lumen program name to allow_programs in the config to permit the bridge.",
        ));
    }
    let strength = match args.get("strength") {
        None => 1.0,
        Some(value) => value.as_f64().ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                "argument 'strength' must be a number",
            )
        })?,
    };
    if !(0.0..=1.0).contains(&strength) {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            "argument 'strength' must be within 0.0..=1.0",
        ));
    }
    let palette_colors = palette_colors_arg(args)?;
    let (path, bytes) = read_art_target(config, target)?;
    let subject = subject_for_file(&path)?;
    let art = decode(&bytes, target)?;
    let spec_in = spec::measure_frame(&art.first_frame, palette_colors);

    // Scratch project: the input document, lumen's project root.
    let scratch_root = paths::state_subdir(config, "art-lumen")?;
    let scratch = scratch_root.join(&subject.sha256[..16]);
    std::fs::create_dir_all(&scratch).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot create lumen scratch dir: {e}"),
        )
    })?;
    let palette_rgba: Vec<[u8; 4]> = spec_in
        .palette
        .iter()
        .map(|entry| [entry.rgb[0], entry.rgb[1], entry.rgb[2], 255])
        .collect();
    let doc = lumen::build_doc_json(&art.first_frame, &palette_rgba)
        .map_err(|message| FathomError::new(ErrorCode::ExecutionFailure, message))?;
    std::fs::write(
        scratch.join("input.lumen.json"),
        serde_json::to_vec(&doc).map_err(|e| {
            FathomError::new(
                ErrorCode::ExecutionFailure,
                format!("cannot encode doc: {e}"),
            )
        })?,
    )
    .map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("cannot write input doc: {e}"),
        )
    })?;

    let (mut client, styles) =
        lumen::LumenClient::connect(program, &scratch).map_err(lumen_error)?;
    let style_names: Vec<&str> = styles.iter().map(|(name, _)| name.as_str()).collect();
    if !style_names.contains(&preset) {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "lumen offers no preset '{preset}'; available: {}",
                style_names.join(", ")
            ),
        ));
    }
    let saved = client
        .style_apply("input.lumen.json", "graded.lumen.json", preset, strength)
        .map_err(lumen_error)?;
    let graded_bytes = std::fs::read(scratch.join("graded.lumen.json")).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("lumen reported success ({saved}) but the graded doc is unreadable: {e}"),
        )
    })?;
    let graded_doc: Value = serde_json::from_slice(&graded_bytes).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!("graded doc does not parse: {e}"),
        )
    })?;
    let out_frame = lumen::composite_doc(&graded_doc)
        .map_err(|message| FathomError::new(ErrorCode::ExecutionFailure, message))?;
    let out_dir = paths::state_subdir(config, "art-output")?;
    let out_path = out_dir.join(output);
    write_png(&out_frame, &out_path)?;
    let out_subject = subject_for_file(&out_path)?;
    let spec_out = spec::measure_frame(&out_frame, palette_colors);

    let mut evidence = Evidence::new("apply_style_via_lumen", "art");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    evidence.add_finding(Finding::new(
        "lumen_session",
        Confidence::Observed,
        json!({
            "preset": preset,
            "program": program,
            "protocol_version": client.protocol_version,
            "server_name": client.server_name,
            "strength": strength,
            "styles_available": styles.len(),
        }),
    ));
    evidence.add_finding(Finding::new(
        "conversion",
        Confidence::Observed,
        json!({
            "graded_doc": scratch.join("graded.lumen.json").display().to_string(),
            "input_doc": scratch.join("input.lumen.json").display().to_string(),
            "output_bytes": out_subject.size_bytes,
            "output_path": out_path.display().to_string(),
            "output_sha256": out_subject.sha256,
            "style_input": spec::frame_spec_json(&spec_in),
            "style_output": spec::frame_spec_json(&spec_out),
        }),
    ));
    match args.get("reference").and_then(Value::as_str) {
        Some(reference) => {
            let (_, ref_bytes) = read_art_target(config, reference)?;
            let ref_art = decode(&ref_bytes, reference)?;
            let spec_ref = spec::measure_frame(&ref_art.first_frame, palette_colors);
            let checks = lumen::verify_against(&spec_out, &spec_ref);
            let within = checks.iter().all(|check| check.ok != Some(false));
            evidence.add_finding(Finding::new(
                "verification",
                Confidence::Derived,
                json!({
                    "checks": checks.iter().map(|check| json!({
                        "delta": check.delta.map(|d| (d * 10_000.0).round() / 10_000.0),
                        "name": check.name,
                        "ok": check.ok,
                        "tolerance": check.tolerance,
                    })).collect::<Vec<_>>(),
                    "reference": reference,
                    "within_tolerance": within,
                }),
            ));
            for check in &checks {
                if check.ok == Some(false) {
                    evidence.add_unknown(
                        "style_closeness",
                        format!(
                            "output {} differs from the reference by {:.4}, beyond \
                             the stated tolerance {}",
                            check.name,
                            check.delta.unwrap_or_default(),
                            check.tolerance
                        ),
                    );
                }
            }
        }
        None => {
            evidence.add_unknown(
                "style_closeness",
                "no reference target was supplied; the conversion was applied \
                 and the output measured, but closeness to a target style was \
                 not established",
            );
            evidence.add_unknown(
                "preset_parameters",
                "lumen's style_list reports preset names and descriptions only; \
                 the preset's numeric grade parameters are lumen-internal and \
                 are not claimed here",
            );
        }
    }
    Ok(evidence.to_value())
}

/// Map a bridge failure to an evidence error: a timeout keeps
/// its own code, everything else is an execution failure whose
/// message names the failing step.
fn lumen_error(message: String) -> FathomError {
    if message.contains("did not answer") {
        FathomError::new(ErrorCode::ProviderTimeout, message)
    } else {
        FathomError::new(ErrorCode::ExecutionFailure, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    fn config(root: &Path, allow: &[&str], programs: &[&str]) -> Config {
        Config::from_file_form(ConfigFile {
            allow_programs: Some(programs.iter().map(|s| s.to_string()).collect()),
            allow_tools: Some(allow.iter().map(|s| s.to_string()).collect()),
            state_dir: Some(root.join("state")),
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fathom-art-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validation_analyze_solid_png() {
        let root = scratch("analyze");
        let image = image::RgbaImage::from_pixel(10, 10, image::Rgba([255, 0, 0, 255]));
        image
            .save_with_format(root.join("red.png"), image::ImageFormat::Png)
            .unwrap();
        let value = analyze_art_style(
            &Registry::new(),
            &config(&root, &[], &[]),
            &json!({"target": root.join("red.png").display().to_string()}),
        )
        .unwrap();
        let findings = value["findings"].as_array().unwrap();
        let palette = findings
            .iter()
            .find(|f| f["kind"] == "palette")
            .expect("palette finding");
        assert_eq!(palette["facts"]["colors"][0]["hex"], "#FF0000");
        assert_eq!(value["status"], "complete");
    }

    #[test]
    fn adversarial_output_name_rejected() {
        assert!(validate_output_name("../escape.png").is_err());
        assert!(validate_output_name("nested/out.png").is_err());
        assert!(validate_output_name("no-extension").is_err());
        assert!(validate_output_name("fine.png").is_ok());
    }

    #[test]
    fn adversarial_lumen_program_not_allowlisted() {
        let root = scratch("lumen-gate");
        let image = image::RgbaImage::from_pixel(4, 4, image::Rgba([9, 9, 9, 255]));
        image
            .save_with_format(root.join("in.png"), image::ImageFormat::Png)
            .unwrap();
        let error = apply_style_via_lumen(
            &Registry::new(),
            &config(&root, &["apply_style_via_lumen"], &[]),
            &json!({
                "lumen_program": "lumen",
                "output": "out.png",
                "preset": "ukiyo_e",
                "target": root.join("in.png").display().to_string(),
            }),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::AccessDenied);
    }

    /// A dependency-free fake lumen: pure-stdlib python that
    /// speaks just enough MCP stdio to answer initialize and
    /// tools/call, swapping the R and B channels of the layer
    /// PNG (a deterministic, exactly predictable "grade").
    const FAKE_LUMEN: &str = r##"
import base64, io, json, os, struct, sys, zlib

def read_png(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, size = 8, b"", None
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos+4])[0]; typ = data[pos+4:pos+8]
        chunk = data[pos+8:pos+8+ln]; pos += 12 + ln
        if typ == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", chunk[:10])
            assert depth == 8 and ctype == 6, (depth, ctype)
            size = (w, h)
        elif typ == b"IDAT":
            idat += chunk
        elif typ == b"IEND":
            break
    raw = zlib.decompress(idat)
    w, h = size; stride = w * 4
    rows, prev = [], bytearray(h and stride or 0)
    prev = bytearray(stride)
    for y in range(h):
        f = raw[y*(stride+1)]; line = bytearray(raw[y*(stride+1)+1:(y+1)*(stride+1)])
        if f == 1:
            for i in range(4, stride): line[i] = (line[i] + line[i-4]) & 0xff
        elif f == 2:
            for i in range(stride): line[i] = (line[i] + prev[i]) & 0xff
        elif f == 3:
            for i in range(stride):
                a = line[i-4] if i >= 4 else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xff
        elif f == 4:
            for i in range(stride):
                a = line[i-4] if i >= 4 else 0; b = prev[i]; c = prev[i-4] if i >= 4 else 0
                p = a + b - c; pa, pb, pc = abs(p-a), abs(p-b), abs(p-c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xff
        rows.append(bytes(line)); prev = line
    return w, h, rows

def write_png(w, h, rows):
    def chunk(typ, payload):
        c = struct.pack(">I", len(payload)) + typ + payload
        return c + struct.pack(">I", zlib.crc32(typ + payload) & 0xffffffff)
    raw = b"".join(b"\x00" + r for r in rows)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))

root = os.environ["LUMEN_PROJECT_ROOT"]
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18",
                  "capabilities": {}, "serverInfo": {"name": "fake-lumen"}}
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
    elif method == "tools/call":
        name = msg["params"]["name"]; args = msg["params"].get("arguments", {})
        if name == "style_list":
            payload = {"styles": [{"name": "swap_rb", "description": "fake grade"}]}
        elif name == "style_apply":
            with open(os.path.join(root, args["doc"])) as fh:
                doc = json.load(fh)
            layer = doc["layers"][0]
            w, h, rows = read_png(base64.b64decode(layer["png_base64"]))
            swapped = []
            for row in rows:
                buf = bytearray(row)
                for i in range(0, len(buf), 4):
                    buf[i], buf[i+2] = buf[i+2], buf[i]
                swapped.append(bytes(buf))
            layer["png_base64"] = base64.b64encode(write_png(w, h, swapped)).decode()
            with open(os.path.join(root, args["output"]), "w") as fh:
                json.dump(doc, fh)
            payload = {"path": args["output"], "width": w, "height": h,
                       "layers": 1, "frames": 1}
        else:
            payload = {"error": "unknown tool"}
        text = json.dumps(payload)
        result = {"content": [{"type": "text", "text": text}], "isError": False}
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
"##;

    #[test]
    fn validation_lumen_bridge_closed_loop() {
        let root = scratch("lumen-loop");
        // Input: solid red. The fake grade swaps R/B, so the
        // exactly-known output is solid blue — which is also
        // the reference, so verification must pass.
        let red = image::RgbaImage::from_pixel(12, 12, image::Rgba([255, 0, 0, 255]));
        red.save_with_format(root.join("in.png"), image::ImageFormat::Png)
            .unwrap();
        let blue = image::RgbaImage::from_pixel(12, 12, image::Rgba([0, 0, 255, 255]));
        blue.save_with_format(root.join("reference.png"), image::ImageFormat::Png)
            .unwrap();
        let script = root.join("fake_lumen.py");
        std::fs::write(&script, FAKE_LUMEN).unwrap();
        // The handler spawns the program as a single path, so
        // the fake runs through an exec wrapper script.
        let wrapper = root.join("fake-lumen");
        std::fs::write(
            &wrapper,
            format!("#!/bin/sh\nexec python3 \"{}\"\n", script.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let value = apply_style_via_lumen(
            &Registry::new(),
            &config(
                &root,
                &["apply_style_via_lumen"],
                &[wrapper.to_str().unwrap()],
            ),
            &json!({
                "lumen_program": wrapper.display().to_string(),
                "output": "graded.png",
                "preset": "swap_rb",
                "reference": root.join("reference.png").display().to_string(),
                "target": root.join("in.png").display().to_string(),
            }),
        )
        .unwrap();
        let findings = value["findings"].as_array().unwrap();
        let session = findings
            .iter()
            .find(|f| f["kind"] == "lumen_session")
            .expect("session finding");
        assert_eq!(session["facts"]["protocol_version"], "2025-06-18");
        assert_eq!(session["facts"]["server_name"], "fake-lumen");
        let verification = findings
            .iter()
            .find(|f| f["kind"] == "verification")
            .expect("verification finding");
        assert_eq!(verification["facts"]["within_tolerance"], true);
        assert_eq!(value["status"], "complete");
        let out_path = root.join("state").join("art-output").join("graded.png");
        let out = image::load_from_memory(&std::fs::read(&out_path).unwrap())
            .unwrap()
            .to_rgba8();
        assert_eq!(out.get_pixel(0, 0), &image::Rgba([0, 0, 255, 255]));
    }
}
