# fathom audio-RE lane (D-989): format briefs must be grounded in a reference parser before coding

origin_lane: qompassai/fathom
content_label: sfw

Three lessons from building the FSB5/CRI/MV audio-RE lane
(2026-11-04), each proven against corpus ground truth:

1. The commissioning briefs FSB5 sample-header layout
   (codec at bits 1-4 with a Vorbis=12 map, samples at
   bits 30-63) was wrong. The published layout
   (vgmstream fsb5.c, matching FMOD_SOUND_FORMAT) has
   the codec as the header u32 at 0x18 (15 = Vorbis),
   frequency index at bits 1-4, channels code at bits
   5-6, data offset at bits 7-33, samples at bits
   34-63, and an extra-flag chain (channels/rate/loop
   records). A ten-minute probe against the specimens
   numbers (samples = header >> 34 exactly, x12 banks)
   caught it before the parser was written. Rule: a
   format brief is a hypothesis; the reference
   implementation plus specimen arithmetic is the
   authority, in that order.
2. A Unity .resource is not one FSB5 bank: it is N
   banks concatenated, exactly tiling the file by
   header-declared sizes (Hypno Rhythm sharedassets0:
   12 banks; sharedassets1: 3). Any single-bank parser
   or external decoder fails on the raw file
   (vgmstream: "FSB5: wrong size ... (re-rip)").
   Container iteration by declared size is part of
   the format, not an edge case.
3. CRI LoopFlag in the ACB WaveformTable uses 2 (not
   1) for the looping waveforms: exactly the two
   LoopFlag=2 rows (BGM id 1, SE id 27) are the two
   full-stream loops an independent decoder reports.
   A flag whose polarity is assumed (1 = on) would
   have inverted the loop map.

Evidence: branch pax/fathom-audio-re-20261104 in
fathom; run artifacts under primo
~/.local/share/pax/fathom-audio-re-tier1/ (census and
extract manifests cross-checked against vgmstream
r2168 metadata and decoded-WAV hashes, 12/12 hash
matches); sandbox report at
~/workspace/fathom-audio-re-20261104/build-report.md.
