# prefetch-forensic

[![Crates.io: prefetch-core](https://img.shields.io/crates/v/prefetch-core.svg?label=prefetch-core)](https://crates.io/crates/prefetch-core)
[![Crates.io: prefetch-forensic](https://img.shields.io/crates/v/prefetch-forensic.svg?label=prefetch-forensic)](https://crates.io/crates/prefetch-forensic)
[![Docs.rs](https://docs.rs/prefetch-forensic/badge.svg)](https://docs.rs/prefetch-forensic)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa.svg)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/prefetch-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/prefetch-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security advisories](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

**Prove what ran on a Windows box — and when, how often, and from where — straight from `.pf` files, on any OS.** A panic-free-by-construction prefetch reader (`MAM`/Xpress-Huffman + SCCA v30/31) plus an analyzer that grades masquerading and suspicious-location execution.

## Run it

```console
$ cargo install prefetch-forensic          # installs the prefetch4n6 binary
$ prefetch4n6 COREUPDATER.EXE-157C54BB.pf AUDIODG.EXE-AB22E9A6.pf
COREUPDATER.EXE  ran 1x  last 2020-09-19T03:40:49Z  from \VOLUME{01d68d85e0da1e22-b0e0e8ff}\WINDOWS\SYSTEM32\COREUPDATER.EXE
AUDIODG.EXE  ran 8x  last 2020-09-19T05:18:45Z  from \VOLUME{01d68d85e0da1e22-b0e0e8ff}\WINDOWS\SYSTEM32\AUDIODG.EXE
```

`--files` adds each executable's loaded-file count. As a library it's one call:

```rust
// Execution evidence + graded findings, from a raw .pf file.
let (rec, findings) = prefetch_forensic::audit_bytes(&std::fs::read("COREUPDATER.EXE-157C54BB.pf")?)?;
println!("{} ran {}x, last {:?}, from {:?}",
         rec.executable, rec.run_count, rec.last_run_filetimes.first(), rec.image_path);
// → COREUPDATER.EXE ran 1x, last 132449604494103203, from \…\SYSTEM32\COREUPDATER.EXE
```

Most prefetch tools (PECmd, WinPrefetchView, windowsprefetch) decompress Win10+ prefetch by calling the Windows API `RtlDecompressBufferEx` — so they only run **on Windows**. prefetch-forensic carries its own clean-room [MS-XCA] Xpress-Huffman decoder ([`xpress-huffman`](https://github.com/SecurityRonin/xpress-huffman)), so it parses Windows prefetch on **Linux and macOS** too.

## Two crates

| Crate | Role |
|---|---|
| **`prefetch-core`** | the reader: `MAM`/Xpress-Huffman decompression + SCCA v30/31 parsing → `PrefetchInfo` (executable, run count, last-8 run times, volume serial/path, loaded files). No findings. |
| **`prefetch-forensic`** | the analyzer: `execution_record()` (the evidence) + `audit()` → graded `forensicnomicon` findings. |

```toml
[dependencies]
prefetch-forensic = "0.1"   # pulls in prefetch-core
```

## What the analyzer flags

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `PREFETCH-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | a System32-only binary name (`svchost.exe`, `lsass.exe`, …) was loaded from outside `System32`/`SysWOW64` |
| `PREFETCH-SUSPICIOUS-EXEC-PATH` | Medium | T1204 | the image ran from a malware-staging directory (Temp, Downloads, `$Recycle.Bin`, PerfLogs, …) |

High precision by design: a normal `System32` program — including the real Case 001 malware `coreupdater.exe`, which the attacker planted *in* System32 under a novel name — yields its execution evidence but **no false-positive finding**. Prefetch alone establishes that it ran; whether that is malicious is a correlation/tribunal question. Findings are observations, never verdicts.

## Trust, but verify

- **`#![forbid(unsafe_code)]`**, no `unwrap`/`expect`/panic in production — every SCCA offset and length is bounds-checked.
- **Validated against independent external oracles** on the real **Stolen Szechuan Sauce** (Case 001) malware prefetch: the decompressor is byte-for-byte identical to Fox-IT's `dissect.util`, and the parsed SCCA fields match Adam Witt's `windowsprefetch`. See [`docs/validation.md`](docs/validation.md).

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/

---

[Privacy Policy](https://securityronin.github.io/prefetch-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/prefetch-forensic/terms/) · © 2026 Security Ronin Ltd
