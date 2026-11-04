# Media capture lane — Danbooru → quarantine → observation records

**Programme:** D-878 (Owner-directed 2026-11-03). Fathom stays a
clean-room reverse-engineering MCP (Tiger Style, Ghidra/NSA
discipline); this lane is media RE: screened capture, measurement,
and grammar extraction over visible media. It is not a downloader
for assets — captured media is evidence, and it never leaves the
quarantine.

## Tools (provider: video; class: observe; both default-deny)

| Tool | What it does |
| --- | --- |
| `capture_danbooru_media` | Verifies the D-555/D-874 screen verdict for one post id (and the screen record's SHA-256 when stated) **before any network byte moves**; fetches post metadata, then the media, into the named quarantine; writes a `danbooru-capture/1` provenance record. |
| `observe_captured_media` | Re-verifies a capture (record digest + media hash), then writes a `media-observation/1` record with four classes: motion, character, object, audio. |

Server surface note (Rule 1): fathom's full catalog is a
multi-provider RE surface that predates the 25-tool soft budget
and already exceeds it by design record in SPEC.md; this lane
adds exactly two tools to the existing video provider rather
than standing up a second server for one workflow. The split
candidate, if the lane grows, is a dedicated media-RE server
carrying these two tools plus the YouTube ingest family.

## Law

- **Screening is fail-closed and pre-download.** Excluded posts
  are never captured (typed refusal `screen_excluded`);
  unscreened posts are never captured (`screen_missing`);
  malformed screens and hash mismatches refuse typed. The
  screen record must live inside the quarantine.
- **Quarantine.** Media lives only under a directory named
  `danbooru-re` beneath a configured target root. No pipe, game
  tree, dataset, or training path may read from it. Observation
  records are the only exit.
- **Records, not media, cross into the pipes.** Specs,
  measurements, grammar, vocabulary only. Recreation is
  re-performance by estate-original characters (D-555).
- **Audio is silent.** Waveform/spectral/tempo descriptors are
  computed from decoded samples as files and numbers; nothing is
  played; primo null-sink discipline is untouched (this lane
  opens no audio device at all).
- **Lane stamps.** Every record carries origin
  (`danbooru-reference`), lane, and content label. Act content is
  NSFW-lane only; mechanics classes may serve both lanes;
  unclassified defaults NSFW (the classifier: anything not
  plainly safe-rated and free of explicit tags is NSFW).
- **Rate discipline.** At most one Danbooru request per 2 s
  (fixed gap between the metadata and media requests); HTTP 429
  stops the capture with a typed refusal; no retries.

## Bounds

- One post per capture call; media ≤ 512 MiB
  (`CAPTURE_MEDIA_BYTES_MAX`); metadata ≤ 1 MiB.
- Observation samples ≤ 1,024 frames at ≤ 12 fps on a 96×54
  grayscale grid (`OBSERVE_*` constants); audio is decoded mono
  8 kHz for descriptors.
- What lane v1 cannot measure is an unknown on the record, not
  a claim: no face-segmentation or body-landmark estimator, so
  expression states are tag-anchored (estate face-state
  vocabulary, F-05/F-06/F-07) and proportions are media-level.

## Records

- `danbooru-capture/1` — provenance: post id, stated MD5, media
  SHA-256 + size, screen pointer (path + SHA-256 + verdict),
  capture time, lane stamps, record digest.
- `media-observation/1` — the four classes plus unknowns,
  producer block, and record digest. Pipe-side emitters
  (`media_capture_emit` 1.0.0 in both pipe sets) verify the
  digest and the CLEARED screen stamp before consuming a record.
