# 4. SCCA v30/31 scope and the generalized run-counter shift

Date: 2026-07-24
Status: Accepted

## Context

The decompressed prefetch payload is the classic `SCCA` structure, whose
`FileInformation` block layout differs by version: 17 (XP), 23 (Vista/7), 26
(Win8.1), 30 (Win10), 31 (Win11). The two mainstream modern targets — and the
Case 001 validation corpus — are Win10/11 (v30/31). Their `FileInformation`
layout is a single shared shape; the older versions are genuinely different
structures.

A second wrinkle: newer Windows 10 builds **shifted the run-counter field back 8
bytes**. The independent oracle `windowsprefetch` reads only the legacy offset
and therefore reports run count `0` for these files (`docs/validation.md`) — a
real bug, not a matter of taste, since `AUDIODG.EXE`'s eight distinct last-run
timestamps prove it ran ≥ 8 times.

## Decision

1. **Support SCCA v30 and v31 only.** `parse_decompressed()`
   (`core/src/lib.rs`) returns `PrefetchError::UnsupportedVersion(version)` —
   carrying the actual version found — for anything else, rather than silently
   misparsing an older layout. The error's doc names the unsupported versions.
2. **Handle the run-counter shift as a general rule, not a per-file special
   case.** The field at `FileInfo+120` is zero in the pre-shift layout; when it
   is non-zero the count lives at `FileInfo+116`, otherwise at `FileInfo+124`.
   The parser derives the offset from that structural signal
   (`if rd_u32(scca, fi+120) == 0 { +124 } else { +116 }`), so every file in the
   shifted class is handled by construction — the No-Special-Cases discipline.

## Consequences

- prefetch-forensic reports the **correct** run counts (1 / 8 / 1 on the Case
  001 files) where `windowsprefetch` reports `0` — validated as *more* correct
  than that oracle (`docs/validation.md`).
- Feeding a pre-Win10 (`17/23/26`) prefetch fails loud with the exact version
  byte, rather than emitting wrong fields — the "show the unrecognized value"
  robustness rule. Extending to those layouts is a bounded future change (a new
  `FileInformation` offset table), not a rewrite.

## Alternatives considered

- **Branch on the specific filename/size to pick the run-count offset** —
  rejected; that games the visible fixtures and breaks on the next file. The
  `FileInfo+120` structural test generalizes to the whole shifted-layout class.
