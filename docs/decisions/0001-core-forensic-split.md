# 1. Reader/analyzer split — `prefetch-core` + `prefetch-forensic`

Date: 2026-07-24
Status: Accepted

## Context

The repo parses Windows Prefetch (`.pf`) files and grades a small set of
execution anomalies. Two audiences want different things from that code:

- a developer who needs only the raw execution facts (what ran, when, from
  where) to feed their own pipeline, and
- an examiner who wants graded findings and a runnable CLI.

The SecurityRonin fleet standard (`ronin-issen/CLAUDE.md` → "Crate-structure
standard — reader/analyzer split") mandates one workspace repo named
`<x>-forensic` with two members: a `core/` reader crate and a `forensic/`
analyzer crate, so a third party can link the reader without pulling the
finding/report stack, and the analyzer can see the raw structure the reader
exposes.

## Decision

Ship two crates from one workspace (`Cargo.toml` `members = ["core", "forensic"]`):

1. **`prefetch-core`** (`core/src/lib.rs`) — the reader. `decompress()` +
   `parse()`/`parse_decompressed()` turn a `.pf` file into `PrefetchInfo`
   (executable, run count, last-8 run times, volumes, loaded files). No
   findings, no severity, no MITRE.
2. **`prefetch-forensic`** (`forensic/src/lib.rs`) — the analyzer.
   `execution_record()` extracts the evidence and `audit()` emits graded
   `PrefetchAnomaly` values; `audit_bytes()` is the one-call headline entry
   point. It depends on `prefetch-core` (workspace dep, `forensic/Cargo.toml`).

The analyzer builds *on* `prefetch-core` rather than lower down because
`PrefetchInfo` already exposes everything the two current findings need (the
loaded-file list and the executable name); there is no slack/deleted-record
structure an auditor must reach past the reader to see.

## Consequences

- A downstream consumer that only wants execution facts links `prefetch-core`
  (one dependency: `xpress-huffman`) and never compiles `forensicnomicon`.
- The crates version independently: `prefetch-core` is `0.1.0`, the analyzer is
  ahead (`forensic/Cargo.toml` `version = "0.4.0"`); `version` is deliberately
  not hoisted to `[workspace.package]` (see the comment in the root `Cargo.toml`).
- Matches the fleet reference layout (`ntfs-forensic`, `vmdk-forensic`, …), so
  the two-crate shape is predictable across repos.

## Alternatives considered

- **One crate with a `findings` feature** — rejected; it forces
  `forensicnomicon` onto reader-only consumers and blurs the reader/analyzer
  boundary the fleet standardized on.
