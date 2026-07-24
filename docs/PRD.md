# prefetch-forensic — Product Requirements

*Reverse-written from the shipped code, README, and git history (2026-07-24).
Every current-state claim below is grounded in a same-session read of `core/src/`,
`forensic/src/`, and `docs/validation.md`. The load-bearing decisions live as
ADRs [0001](decisions/0001-core-forensic-split.md)–[0007](decisions/0007-packaging-naming-msrv-license.md)
under [`docs/decisions/`](decisions/).*

## Executive Summary

prefetch-forensic proves **what ran on a Windows box — and when, how often, and
from where — straight from `.pf` files, on any OS.** It ships two crates and one
binary: `prefetch-core` (the reader), `prefetch-forensic` (the analyzer), and
`prefetch4n6` (the CLI an examiner runs, `cargo install prefetch-forensic`).

The differentiator: every mainstream prefetch tool (PECmd/EZ-Prefetch,
WinPrefetchView, `windowsprefetch`) decompresses Win10+ prefetch through the
Windows API `RtlDecompressBufferEx`, so they **only run on Windows**.
prefetch-forensic carries its own clean-room [MS-XCA] Xpress-Huffman decoder (the
`xpress-huffman` crate), so it parses Windows prefetch on **Linux and macOS** too
([ADR 0002](decisions/0002-clean-room-xpress-huffman-crate.md)).

It leads with **execution evidence** (unambiguous, always returned) and adds only
**two high-precision findings** on top, so it stays quiet on benign prefetch —
including the real Case 001 implant `coreupdater.exe`
([ADR 0006](decisions/0006-high-precision-evidence-first-findings.md)). Findings
are observations, never verdicts.

## 1. Problem

An examiner reconstructing an intrusion needs to establish **execution**: did a
given program run on this host, how many times, at what times, and from what
path? Windows Prefetch answers all four, but two things get in the way:

1. **Win10/11 prefetch is compressed** with a MAM/Xpress-Huffman wrapper, and the
   common tooling offloads that decompression to a Windows-only API — so an
   analyst on a Linux or macOS workstation, or in an automated cross-platform
   pipeline, cannot parse a modern `.pf` at all.
2. **Naive anomaly grading misleads.** A tool that flags every unfamiliar
   `System32` binary raises false positives on legitimately-novel names and
   trains examiners to ignore it.

## 2. Users and use cases

- **DFIR analyst / incident responder** running `prefetch4n6 *.pf` on collected
  prefetch to get a per-executable "ran Nx, last <time>, from <path>" line plus
  any graded masquerade/staging findings — on whatever OS their workstation runs.
- **Fleet orchestration (Issen) and other Rust tools** linking
  `prefetch-forensic` for `audit_bytes()` → `(ExecutionRecord, Vec<PrefetchAnomaly>)`,
  with findings emitted as the shared `forensicnomicon::report` model
  ([ADR 0005](decisions/0005-knowledge-and-report-from-forensicnomicon.md)).
- **Developers** who want only raw execution facts, linking `prefetch-core` alone
  (one dependency) for `parse()` → `PrefetchInfo`.

## 3. What it does (current behavior)

- **Decompress** a `MAM\x04` Xpress-Huffman container to raw `SCCA`, or pass a
  raw (Win7-era) `SCCA` file through unchanged (`prefetch_core::decompress`).
- **Parse** SCCA v30 (Win10) / v31 (Win11) into `PrefetchInfo`: executable name,
  run count, up to eight most-recent run times (FILETIME), volume serial + device
  path, and the loaded-file list (`prefetch_core::parse`). The Win10 run-counter
  byte-shift is handled as a general structural rule
  ([ADR 0004](decisions/0004-scca-v30-v31-scope-and-run-count-shift.md)).
- **Extract execution evidence** — `ExecutionRecord` (executable, run count,
  last-run FILETIMEs, resolved image path, first volume serial, loaded-file
  count) — always.
- **Grade two high-precision anomalies:**

  | Code | Severity | MITRE | Fires when |
  |---|---|---|---|
  | `PREFETCH-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | a `System32`-only binary name ran from outside `System32`/`SysWOW64` |
  | `PREFETCH-SUSPICIOUS-EXEC-PATH` | Medium | T1204 | the image ran from a known malware-staging directory |

- **Render** via `prefetch4n6`: one line per file, optional `--files`
  loaded-file count, FILETIME rendered as ISO-8601 UTC (via `jiff`), findings
  printed with severity + note; a missing/undecodable file fails loud with a
  non-zero exit.

## 4. Scope / non-goals

**In scope:** SCCA v30/31 (Win10/11) read-only parsing; cross-platform
MAM/Xpress-Huffman decompression; execution evidence; the two findings above.

**Non-goals:**

- **Older SCCA layouts (17/23/26 — XP/Vista/7/8.1).** Rejected loudly with the
  version byte, not misparsed ([ADR 0004](decisions/0004-scca-v30-v31-scope-and-run-count-shift.md)).
- **Writing / repairing prefetch.** Read-only by construction; `forbid(unsafe)`,
  no panics ([ADR 0003](decisions/0003-forbid-unsafe-panic-free-readers.md)).
- **Verdicts.** Prefetch establishes that a program ran; whether that is
  malicious is a correlation/tribunal question, not one this tool answers.
- **A broad heuristic finding set.** Precision over recall by design
  ([ADR 0006](decisions/0006-high-precision-evidence-first-findings.md)).
- **Prefetch collection/acquisition.** It consumes `.pf` bytes an examiner
  already has.

## 5. Artifact family

Windows Prefetch (`.pf`): the `MAM\x04` Xpress-Huffman container and the `SCCA`
v30/v31 structure — executable base name, run count, last-8 run FILETIMEs,
`VolumeInformation` (serial + device path + creation time), and the loaded-file
list. Prefetch is a [P]-disk PARSER artifact in the fleet layer model; it accepts
`&[u8]` and imports no container/filesystem crate.

## 6. Success criteria & validation

Correctness is proven against **two independent, externally-authored oracles** on
the real **Stolen Szechuan Sauce** (Case 001) Win10 prefetch — not on
self-authored fixtures ([`docs/validation.md`](validation.md)):

- **Decompression** is **byte-for-byte identical** (SHA-256) to Fox-IT's
  `dissect.util` [MS-XCA] implementation, on files Windows itself compressed.
- **SCCA fields** match Adam Witt's `windowsprefetch` — and prefetch-forensic is
  *more* correct on run count (reports 1/8/1 where `windowsprefetch` reports 0,
  because it applies the Win10 counter shift).
- **No false positive** on `coreupdater.exe` (System32, novel name): full
  execution evidence, zero findings.

The bar for shipping: `forbid(unsafe)` + panic-free lints green, the oracle
cross-check passing, and the CLI `--version`/usage contract intact.

## 7. Related

- **`xpress-huffman`** — the reusable clean-room [MS-XCA] codec this repo depends
  on (also used for hiberfil / SMB3 / registry decompression across the fleet).
- **`forensicnomicon`** — the KNOWLEDGE leaf supplying the system-binary /
  staging-path lists and the `report` model.
- Fleet-siblings by convention: the other `<x>4n6` execution-artifact CLIs
  (`shimcache4n6`, `amcache4n6`).

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
