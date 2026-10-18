//! The lumen bridge: conversion by lumen's grade engine, never
//! by a second engine inside fathom.
//!
//! Fathom's side of the line is format conversion + transport:
//! it wraps the analyzed image in a single-layer lumen document
//! (the `.lumen.json` stored form: layers as base64 PNG), spawns
//! lumen's stdio MCP server in a scratch project root, asks for
//! `style_list` (and refuses presets the server does not offer),
//! calls `style_apply`, and reads the graded document back. The
//! caller re-analyzes the result and compares it to the target
//! spec — the closed RE loop lives in the tool handler.
//!
//! The client is the same bounded NDJSON shape phlow uses:
//! reader thread + channel, frame cap, per-call timeouts,
//! child killed on drop. Errors are plain messages; the handler
//! maps them to evidence codes.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use image::{ImageFormat, RgbaImage};
use serde_json::{Value, json};

use crate::base64;
use crate::spec::FrameSpec;

/// Protocol version this client offers. The server's answer is
/// recorded in evidence; any non-empty version is accepted
/// (lumen's rmcp server answers its own), so a version bump on
/// the lumen side surfaces as data, not a silent failure.
pub const OFFERED_PROTOCOL_VERSION: &str = "2025-06-18";
/// Inbound frame bound (a style result is small; the graded
/// document travels by file, not by frame).
pub const FRAME_BYTES_MAX: usize = 16 * 1024 * 1024;
/// Frames skipped while awaiting a response id (notifications
/// and unrelated traffic) at most.
pub const SKIPPED_FRAMES_MAX: usize = 1024;
/// Per-call timeout for style operations.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);
/// Lumen document format version (doc.rs `DOC_VERSION`).
pub const DOC_VERSION: u32 = 1;

/// Build the single-layer lumen document for one frame. The
/// stored form (verified against lumen's doc.rs): version,
/// width, height, layers[{name, visible, opacity, blend,
/// png_base64}], frames[{duration_ms, layer_mods[{offset_x,
/// offset_y, opacity_mult, scale}]}], tags, palette (RGBA rows).
pub fn build_doc_json(frame: &RgbaImage, palette: &[[u8; 4]]) -> Result<Value, String> {
    let mut png: Vec<u8> = Vec::new();
    frame
        .write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|e| format!("cannot encode layer PNG: {e}"))?;
    Ok(json!({
        "frames": [{
            "duration_ms": 100,
            "layer_mods": [{
                "offset_x": 0,
                "offset_y": 0,
                "opacity_mult": 1.0,
                "scale": 1.0,
            }],
        }],
        "height": frame.height(),
        "layers": [{
            "blend": "normal",
            "name": "base",
            "opacity": 1.0,
            "png_base64": base64::encode(&png),
            "visible": true,
        }],
        "palette": palette,
        "tags": [],
        "version": DOC_VERSION,
        "width": frame.width(),
    }))
}

/// Composite a stored lumen document's layers (source-over, in
/// document order) into one RGBA frame.
pub fn composite_doc(doc: &Value) -> Result<RgbaImage, String> {
    let width = doc["width"]
        .as_u64()
        .ok_or_else(|| "document has no width".to_string())? as u32;
    let height = doc["height"]
        .as_u64()
        .ok_or_else(|| "document has no height".to_string())? as u32;
    let layers = doc["layers"]
        .as_array()
        .ok_or_else(|| "document has no layers".to_string())?;
    if layers.is_empty() {
        return Err("document has zero layers".to_string());
    }
    let mut canvas = RgbaImage::new(width, height);
    for layer in layers {
        if layer["visible"].as_bool() == Some(false) {
            continue;
        }
        let encoded = layer["png_base64"]
            .as_str()
            .ok_or_else(|| "layer has no png_base64".to_string())?;
        let bytes = base64::decode(encoded)?;
        let image = image::load_from_memory_with_format(&bytes, ImageFormat::Png)
            .map_err(|e| format!("cannot decode layer PNG: {e}"))?
            .to_rgba8();
        let opacity = layer["opacity"].as_f64().unwrap_or(1.0).clamp(0.0, 1.0) as f32;
        for (x, y, source) in image.enumerate_pixels() {
            if x >= width || y >= height {
                continue;
            }
            let target = canvas.get_pixel_mut(x, y);
            let source_alpha = f32::from(source[3]) / 255.0 * opacity;
            let target_alpha = f32::from(target[3]) / 255.0;
            let out_alpha = source_alpha + target_alpha * (1.0 - source_alpha);
            if out_alpha <= 0.0 {
                *target = image::Rgba([0, 0, 0, 0]);
                continue;
            }
            for channel in 0..3 {
                let blended = (f32::from(source[channel]) * source_alpha
                    + f32::from(target[channel]) * target_alpha * (1.0 - source_alpha))
                    / out_alpha;
                target[channel] = blended.round() as u8;
            }
            target[3] = (out_alpha * 255.0).round() as u8;
        }
    }
    Ok(canvas)
}

/// One verification check: measured delta vs the stated
/// tolerance. `ok == None` means the check does not apply
/// (e.g. hue when either side is achromatic).
#[derive(Clone, Debug)]
pub struct VerificationCheck {
    /// Absolute delta, when applicable.
    pub delta: Option<f64>,
    /// Descriptor name.
    pub name: &'static str,
    /// Within tolerance / violated / not applicable.
    pub ok: Option<bool>,
    /// The stated tolerance.
    pub tolerance: f64,
}

/// Tolerances for the closed loop (stated in evidence, so a
/// reader can judge the claim): lightness/saturation are HSL
/// fractions, hue is degrees, palette distance is Euclidean
/// RGB units (0..~441).
pub const TOLERANCE_HUE_DEG: f64 = 12.0;
pub const TOLERANCE_LIGHTNESS: f64 = 0.08;
pub const TOLERANCE_PALETTE_DISTANCE: f64 = 24.0;
pub const TOLERANCE_SATURATION: f64 = 0.08;

/// Coverage-weighted mean distance from each reference palette
/// centroid to its nearest output centroid.
pub fn palette_distance(output: &FrameSpec, reference: &FrameSpec) -> Option<f64> {
    if output.palette.is_empty() || reference.palette.is_empty() {
        return None;
    }
    let mut weighted = 0.0_f64;
    let mut total = 0.0_f64;
    for entry in &reference.palette {
        let nearest = output
            .palette
            .iter()
            .map(|candidate| {
                (0..3)
                    .map(|channel| {
                        let delta =
                            f64::from(entry.rgb[channel]) - f64::from(candidate.rgb[channel]);
                        delta * delta
                    })
                    .sum::<f64>()
                    .sqrt()
            })
            .fold(f64::MAX, f64::min);
        weighted += nearest * entry.coverage;
        total += entry.coverage;
    }
    if total <= 0.0 {
        return None;
    }
    Some(weighted / total)
}

/// Compare an output spec to a reference spec.
pub fn verify_against(output: &FrameSpec, reference: &FrameSpec) -> Vec<VerificationCheck> {
    let hue_delta = match (output.mean_hue_deg, reference.mean_hue_deg) {
        (Some(a), Some(b)) => {
            let raw = (a - b).abs();
            Some(raw.min(360.0 - raw))
        }
        _ => None,
    };
    let checks = vec![
        VerificationCheck {
            delta: hue_delta,
            name: "mean_hue_deg",
            ok: hue_delta.map(|d| d <= TOLERANCE_HUE_DEG),
            tolerance: TOLERANCE_HUE_DEG,
        },
        VerificationCheck {
            delta: Some((output.mean_lightness - reference.mean_lightness).abs()),
            name: "mean_lightness",
            ok: Some(
                (output.mean_lightness - reference.mean_lightness).abs() <= TOLERANCE_LIGHTNESS,
            ),
            tolerance: TOLERANCE_LIGHTNESS,
        },
        VerificationCheck {
            delta: Some((output.mean_saturation - reference.mean_saturation).abs()),
            name: "mean_saturation",
            ok: Some(
                (output.mean_saturation - reference.mean_saturation).abs() <= TOLERANCE_SATURATION,
            ),
            tolerance: TOLERANCE_SATURATION,
        },
        VerificationCheck {
            delta: palette_distance(output, reference),
            name: "palette_distance",
            ok: palette_distance(output, reference).map(|d| d <= TOLERANCE_PALETTE_DISTANCE),
            tolerance: TOLERANCE_PALETTE_DISTANCE,
        },
    ];
    checks
}

/// A live session with one lumen stdio server.
pub struct LumenClient {
    child: Child,
    lines: mpsc::Receiver<std::io::Result<String>>,
    next_id: u64,
    /// The server's protocol version from `initialize`.
    pub protocol_version: String,
    /// `serverInfo.name` from `initialize`.
    pub server_name: Option<String>,
    stdin: ChildStdin,
}

impl LumenClient {
    /// Spawn `program` with `LUMEN_PROJECT_ROOT=project_root`,
    /// run `initialize`, and fetch the style list. Returns the
    /// client plus the offered (name, description) styles.
    pub fn connect(
        program: &str,
        project_root: &Path,
    ) -> Result<(LumenClient, Vec<(String, String)>), String> {
        let mut command = Command::new(program);
        command
            .env("LUMEN_PROJECT_ROOT", project_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot spawn lumen program '{program}': {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "lumen child has no stdin".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "lumen child has no stdout".to_string())?;
        let (sender, receiver) = mpsc::channel::<std::io::Result<String>>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });
        let mut client = LumenClient {
            child,
            lines: receiver,
            next_id: 1,
            protocol_version: String::new(),
            server_name: None,
            stdin,
        };
        let init = client.request(
            "initialize",
            json!({
                "capabilities": {},
                "clientInfo": {"name": "fathom-art", "version": env!("CARGO_PKG_VERSION")},
                "protocolVersion": OFFERED_PROTOCOL_VERSION,
            }),
        )?;
        client.protocol_version = init["protocolVersion"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "lumen initialize answer has no protocolVersion".to_string())?
            .to_string();
        client.server_name = init["serverInfo"]["name"].as_str().map(str::to_string);
        client.notify("notifications/initialized", json!({}))?;
        let listed = client.call_tool("style_list", json!({}))?;
        let mut styles = Vec::new();
        if let Some(entries) = listed["styles"].as_array() {
            for entry in entries {
                if let (Some(name), Some(description)) =
                    (entry["name"].as_str(), entry["description"].as_str())
                {
                    styles.push((name.to_string(), description.to_string()));
                }
            }
        }
        if styles.is_empty() {
            return Err("lumen style_list reported no styles".to_string());
        }
        Ok((client, styles))
    }

    /// Call `style_apply`; returns the parsed DocSaved result.
    pub fn style_apply(
        &mut self,
        doc: &str,
        output: &str,
        style: &str,
        strength: f64,
    ) -> Result<Value, String> {
        self.call_tool(
            "style_apply",
            json!({
                "doc": doc,
                "output": output,
                "strength": strength,
                "style": style,
            }),
        )
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        let result = self.request("tools/call", json!({"arguments": arguments, "name": name}))?;
        if result["isError"].as_bool() == Some(true) {
            let text = result["content"][0]["text"]
                .as_str()
                .unwrap_or("tool error");
            return Err(format!("lumen tool {name} failed: {text}"));
        }
        let text = result["content"][0]["text"]
            .as_str()
            .ok_or_else(|| format!("lumen tool {name} returned no text content"))?;
        serde_json::from_str(text)
            .map_err(|e| format!("lumen tool {name} returned non-JSON text: {e}"))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        let frame = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.write_frame(&frame)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.write_frame(&frame)?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        let mut skipped = 0_usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!(
                    "lumen did not answer {method} within {}s",
                    CALL_TIMEOUT.as_secs()
                ));
            }
            let line = self
                .lines
                .recv_timeout(remaining)
                .map_err(|_| format!("lumen channel closed awaiting {method}"))?
                .map_err(|e| format!("lumen stdout read failed: {e}"))?;
            if line.len() > FRAME_BYTES_MAX {
                return Err("lumen frame exceeds the frame bound".to_string());
            }
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                skipped += 1;
                if skipped > SKIPPED_FRAMES_MAX {
                    return Err("lumen sent too many unparseable frames".to_string());
                }
                continue;
            };
            if message["id"].as_u64() != Some(id) {
                skipped += 1;
                if skipped > SKIPPED_FRAMES_MAX {
                    return Err("lumen sent too many unrelated frames".to_string());
                }
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(format!("lumen answered {method} with an error: {error}"));
            }
            return Ok(message["result"].clone());
        }
    }

    fn write_frame(&mut self, frame: &Value) -> Result<(), String> {
        let mut text =
            serde_json::to_string(frame).map_err(|e| format!("cannot encode request: {e}"))?;
        text.push('\n');
        self.stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot write to lumen stdin: {e}"))?;
        self.stdin
            .flush()
            .map_err(|e| format!("cannot flush lumen stdin: {e}"))
    }
}

impl Drop for LumenClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgba;

    #[test]
    fn validation_doc_shape_and_composite_round_trip() {
        let frame = RgbaImage::from_pixel(4, 3, Rgba([200, 40, 40, 255]));
        let doc = build_doc_json(&frame, &[[200, 40, 40, 255]]).unwrap();
        assert_eq!(doc["version"], DOC_VERSION);
        assert_eq!(doc["width"], 4);
        assert_eq!(doc["layers"].as_array().unwrap().len(), 1);
        assert_eq!(
            doc["frames"][0]["layer_mods"].as_array().unwrap().len(),
            doc["layers"].as_array().unwrap().len()
        );
        let composited = composite_doc(&doc).unwrap();
        assert_eq!(composited.dimensions(), (4, 3));
        assert_eq!(composited.get_pixel(2, 2), &Rgba([200, 40, 40, 255]));
    }

    #[test]
    fn adversarial_composite_rejects_bad_docs() {
        assert!(composite_doc(&json!({"width": 2, "height": 2, "layers": []})).is_err());
        assert!(
            composite_doc(&json!({
                "width": 2, "height": 2,
                "layers": [{"png_base64": "!!!not-base64!!!", "visible": true}],
            }))
            .is_err()
        );
    }
}
