# 2. Clean-room [MS-XCA] Xpress-Huffman decoder in its own reusable crate

Date: 2026-07-24
Status: Accepted

## Context

Windows 8.1/10/11 store prefetch as a `MAM\x04` container wrapping an
Xpress-Huffman ([MS-XCA]) compressed `SCCA` payload. Every mainstream prefetch
tool — PECmd/EZ-Prefetch, WinPrefetchView, `windowsprefetch` — decompresses that
payload by calling the Windows API `RtlDecompressBufferEx`, so **they only run on
Windows** (documented in `README.md` and `docs/validation.md`). An examiner
working from a Linux/macOS workstation cannot use them against a Win10+ `.pf`.

No mature pure-Rust [MS-XCA] Xpress-Huffman crate existed when this was built, so
the codec had to be written. The fleet also needs the same codec elsewhere —
`hiberfil.sys`, SMB3, and registry-hive decompression all use MAM/Xpress-Huffman.

## Decision

1. Write a **clean-room [MS-XCA] Xpress-Huffman decoder** (commit `9348a80`),
   validated against the spec and an independent oracle rather than ported from
   any GPL/Windows source.
2. **Extract it into its own crate, `xpress-huffman`** (commit `e236a30`;
   `core/src/lib.rs` calls `xpress_huffman::decompress`), so the fleet reuses one
   audited codec across prefetch / hiberfil / SMB3 / registry rather than N
   copies — the "prefer our own crates" + DRY-via-search-first disciplines.
3. Depend on the **published crates.io release** (`xpress-huffman = "0.1"` in
   `[workspace.dependencies]`), having moved off the earlier git pin once it was
   published (commit `451377a`; `bdeafcc` records the git-vs-path CI history).
4. `prefetch-core::decompress()` owns only the thin MAM framing — 3-byte `MAM`
   signature, the `0x04` Xpress-Huffman compression byte, the little-endian
   decompressed-size field — and passes an already-raw `SCCA` file (Win7 and
   earlier) straight through.

## Consequences

- prefetch-forensic parses Win10/11 prefetch on **Linux and macOS**, which the
  `RtlDecompressBufferEx`-based tools cannot — the headline differentiator.
- The decompressor is validated **byte-for-byte** against Fox-IT's independent
  `dissect.util` [MS-XCA] implementation on the real Case 001 files
  (`docs/validation.md`) — a hand-rolled codec that ships only with an
  independent oracle, per the roll-your-own-codec exception.
- A bug fixed in `xpress-huffman` benefits every fleet consumer at once.

## Alternatives considered

- **Call `RtlDecompressBufferEx`** — rejected; Windows-only, defeating the whole
  cross-platform premise.
- **Inline the codec inside `prefetch-core`** — rejected; the same codec is
  needed by several fleet repos, so it belongs in a shared crate, not copied.

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
