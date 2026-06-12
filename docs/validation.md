# Validation

## Summary

prefetch-forensic is validated against **two independent, externally-authored
oracles**, run on the real **Stolen Szechuan Sauce** (Case 001) Windows 10
prefetch files — not on synthetic fixtures we built ourselves (Doer-Checker).
The two oracles cover the two halves of the pipeline:

| Stage | Independent oracle | Result |
|---|---|---|
| `MAM`/Xpress-Huffman **decompression** | Fox-IT [`dissect.util`](https://github.com/fox-it/dissect.util) `lzxpress_huffman` (a separate [MS-XCA] implementation) | **byte-for-byte identical** (SHA-256) |
| **SCCA field** parsing (exe, run count, serial, files) | Adam Witt [`windowsprefetch`](https://github.com/PoorBillionaire/Windows-Prefetch-Parser) | **fields match** |

Plus the strongest possible check on the decompressor: the test vectors were
compressed by **Windows itself**, so a faithful inflate to the container's
declared length with a valid `SCCA` structure is independent proof.

## Why these oracles (and not PECmd)

PECmd / EZ-Prefetch, Prefetch-Browser, and windowsprefetch all delegate Win10+
decompression to the Windows API `RtlDecompressBufferEx`, so none of them runs as
an oracle off-Windows. `dissect.util` is a pure-Python [MS-XCA] decoder and
`windowsprefetch`'s SCCA field parsers run on already-decompressed bytes — so both
work cross-platform and are genuinely independent of our implementation.

## Results

Files: `COREUPDATER.EXE-157C54BB.pf` (the malware), `AUDIODG.EXE-AB22E9A6.pf`,
`AM_DELTA.EXE-78CA83B0.pf` — all Win10 SCCA v30, from the Case 001 Desktop image.

| File | Decompress (vs dissect.util) | Executable | Volume serial | Loaded files | Version |
|---|---|---|---|---|---|
| COREUPDATER | ✅ byte-identical | ✅ `COREUPDATER.EXE` | ✅ `B0E0E8FF` | ✅ 51 | ✅ 30 |
| AUDIODG | ✅ byte-identical | ✅ `AUDIODG.EXE` | ✅ `B0E0E8FF` | ✅ 79 | ✅ 30 |
| AM_DELTA | ✅ byte-identical | ✅ `AM_DELTA.EXE` | ✅ `B0E0E8FF` | ✅ 13 | ✅ 30 |

### Run count — where prefetch-forensic is *more* correct than the oracle

windowsprefetch reports **run count 0** for all three files; prefetch-forensic
(like PECmd / EZ-Prefetch) reports **1 / 8 / 1**. The divergence is a known
windowsprefetch limitation: it reads the legacy run-counter offset and does not
apply the 8-byte counter shift that newer Windows 10 builds introduced.
AUDIODG's eight distinct last-run timestamps confirm it ran ≥ 8 times — so `0` is
wrong and `8` is right. prefetch-forensic handles the shift generally (not as a
special case): when the field at `FileInfo+120` is non-zero, the count is read
from `FileInfo+116` instead of `+124`.

## Reproduce

```bash
# 1. emit prefetch-core's parse + decompressed payloads
cargo run --example pf_dump -p prefetch-core /tmp/pf_scca > /tmp/pf_rust.jsonl

# 2. cross-check against both independent oracles
python3 -m venv /tmp/pf_oracle
/tmp/pf_oracle/bin/pip install dissect.util windowsprefetch
/tmp/pf_oracle/bin/python scripts/validate_oracles.py     # prints PASS
```

`scripts/validate_oracles.py` decompresses each file with `dissect.util` (diffed
byte-for-byte against prefetch-core's output) and drives `windowsprefetch`'s v30
field parsers on the result, comparing every field.

## The malware's execution evidence

The headline forensic output for the Case 001 implant, straight from its `.pf`:

> **`COREUPDATER.EXE`** ran **1×**, last on **2020-09-19** (`FILETIME`
> 132449604494103203), from **`\…\WINDOWS\SYSTEM32\COREUPDATER.EXE`** on volume
> serial **`B0E0E8FF`**, loading **51** files (`NTDLL.DLL`, `KERNEL32.DLL`, …).

The analyzer raises **no** anomaly on it: a novel name in `System32` is not, by
prefetch alone, suspicious. That is the correct, high-precision result — the
implant's maliciousness is established by *correlation* (memory injection, C2),
not by prefetch in isolation.

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
