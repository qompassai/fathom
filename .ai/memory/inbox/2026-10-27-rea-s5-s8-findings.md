# REA S5–S8 reader findings (2026-10-27)

Durable format facts proven against real streams while
building the S5–S8 readers; keep with the readers.

- **CPython marshal writes code-object scalar fields as raw
  LE i32s with no type tag** — only the object fields (code,
  consts, names, …) are tagged marshal values. A reader that
  treats argcount as a tagged value desynchronises the whole
  stream. Proven with a tracer run over genuine CPython 3.12
  compiler output (consumed exactly 1554/1554 bytes). 3.11+
  code objects have 16 fields and **drop nlocals** (derived
  from localsplusnames/kinds). `python.rs::code_field_kinds`.
- **PyInstaller PYZ TOC shape varies**: current PyInstaller
  (6.x) marshals a *list* of `(name, (type, offset, length))`
  tuples; older releases used a dict. Readers must accept
  both and refuse anything else. Proven against an archive
  written by PyInstaller 6.22.3's own CArchiveWriter /
  ZlibArchiveWriter.
- **PyInstaller cookie probing must not size-gate itself
  out**: a tail window larger than the file must degrade to
  reading the whole file, or small archives (and test
  stubs) never classify. Fixed in `artifact.rs` probe and
  verified live through `inspect_artifact`.
- **goblin 0.10 has no public `NoteIterator::new`** — ELF
  note sections are iterated by hand (bounds from the
  program/section headers) in `gpu.rs::iter_notes`.
- **NativeAOT `Rh*` exports come in two families**:
  `Rhp<Upper>…` (lowercase p) and `Rh<Upper>…`. A shape rule
  that requires an uppercase third character rejects the
  whole `Rhp` family (`RhpNewFast`, `RhpNewArray`, …).
  `native_aot.rs::is_runtime_export`.
- **BEAM ETF tag 80 is the compressed term** (1-byte tag +
  4-byte size + zlib). Any LitT walker must handle it or
  every real literal table desynchronises.
