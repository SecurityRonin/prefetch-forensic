# 3. `forbid(unsafe)` and panic-free bounds-checked parsing

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse **untrusted, attacker-controllable** input: a `.pf` file's MAM
header lengths and every SCCA offset/count come straight from the file and can
lie. The fleet Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`) requires
such parsers to never panic, never read out of bounds, and never trust a length
field. Unlike the container readers that need one bounded `mmap` (ewf,
memory-forensic → `unsafe_code = "deny"` + a per-site allow), prefetch reads
in-memory byte slices and needs no `unsafe` at all.

## Decision

1. **`#![forbid(unsafe_code)]`** in both `core/src/lib.rs` and
   `forensic/src/lib.rs`, backed by `unsafe_code = "forbid"` in
   `[workspace.lints.rust]` — the strongest, provable "no place a crafted input
   can corrupt memory," and the earned `unsafe forbidden` README badge.
2. **Panic-free by lint:** `[workspace.lints.clippy]` denies `unwrap_used` and
   `expect_used` (with `correctness`/`suspicious` denied); `clippy.toml`
   re-permits unwrap/expect only inside tests.
3. **Every field read is bounds-checked:** `rd_u32`/`rd_i64`/`rd_utf16_z`
   (`core/src/lib.rs`) return `Option` via `slice::get(..)` and are mapped to a
   typed `PrefetchError::TruncatedRecord`; `parse_filenames`/`parse_volumes`
   degrade to an empty `Vec` on an out-of-range offset (a per-record miss, not a
   bootstrap failure) instead of panicking.
4. **Allocation-bomb guard:** the header's volume count is capped at
   `MAX_VOLUMES = 64` before any allocation (`volume_count.min(MAX_VOLUMES)`).

## Consequences

- A truncated/hostile `.pf` yields a typed error or a gracefully-empty field,
  never a panic — proven by the `truncated_filename_and_volume_offsets_degrade_gracefully`
  and `parse_decompressed_rejects_short_and_unsigned` tests.
- The crate is a strict `forbid(unsafe)` crate, so `rg 'allow(unsafe_code)'`
  returns nothing — no bounded-unsafe audit surface to track.

## Notes on scope

`prefetch-core` hand-rolls its three tiny reader helpers rather than depending
on the fleet's `safe-read` crate. The reads are fixed-width, `get(..)`-checked,
and fuzz/oracle-validated, so they are panic-safe as written; whether to route
them through `safe-read` for fleet DRY was not decided in the available history.
*Rationale reconstructed from structure; original intent not recovered in
available history.*
