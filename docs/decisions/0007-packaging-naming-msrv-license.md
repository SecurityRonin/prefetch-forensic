# 7. Packaging: crate naming, MSRV floor, Apache-2.0

Date: 2026-07-24
Status: Accepted

## Context

This is a Pattern-A single-format repo (one reader, one analyzer), so the fleet
naming grammar and MSRV/toolchain and licensing policies all apply. Three
packaging decisions are load-bearing and worth recording.

## Decision

1. **Crate names follow the Pattern-A grammar.** The reader is `prefetch-core`
   and the analyzer is `prefetch-forensic` (`core/Cargo.toml`,
   `forensic/Cargo.toml`); the repo is named after the analyzer. No `[lib] name`
   override is set, so the reader imports as `prefetch_core` — the bare
   `prefetch` import path is not claimed. The examiner-facing binary follows the
   `<x>4n6` convention: `prefetch4n6` (`forensic/src/bin/prefetch4n6.rs`, added
   in commit `3a494ef`, "consistent with shimcache4n6/amcache4n6").
2. **MSRV floor `1.85`, dev toolchain pinned `1.96.0`.**
   `[workspace.package] rust-version = "1.85"` is the downstream-facing promise
   both members inherit; `rust-toolchain.toml` pins the build/fmt/clippy
   toolchain to `1.96.0` (commit `319b28f`, fleet toolchain policy). The two are
   deliberately separate: develop on current stable, promise only the floor.
3. **Apache-2.0, single source of truth in `LICENSE`.** Relicensed MIT →
   Apache-2.0 (commit `c258b39`, fleet standard for its explicit patent grant);
   `[workspace.package] license = "Apache-2.0"`, the README carries the badge,
   and there is no `## License` prose section.

## Consequences

- Names are settled and consistent with the fleet, so cross-repo readers know
  where the reader/analyzer/binary live.
- The published `prefetch-core` reader carries a stable `1.85` compatibility
  floor for third-party reuse, independent of the drifting dev-toolchain pin.
- `deny.toml`'s license allow-list admits Apache-2.0 and the permissive set the
  dependency graph needs.

## Notes on scope

The specific `1.85` floor (higher than the fleet's usual `1.75`/`1.80` library
floor) is most plausibly the highest MSRV among the transitive dependencies
(`xpress-huffman`, `forensicnomicon`, `jiff`) at adoption time, but the history
does not record which dep set it. *Rationale reconstructed from structure;
original intent not recovered in available history.*
