# Test data

Single repo-root `tests/data/` (fleet standard). These three small, public-case
Windows 10 prefetch files are committed so the `include_bytes!` parser tests and
the external-oracle validation build everywhere. Cross-reference the fleet
catalog: `issen/docs/corpus-catalog.md`.

All three are from the **Stolen Szechuan Sauce** DFIR case (Case 001), Desktop
image — Win10 SCCA v30, `MAM\x04` (Xpress-Huffman) wrapped.

- **Writeup**: https://thedfirreport.com/2020/11/30/stolen-szechuan-sauce/
- **Dataset**: https://github.com/dlcowen/TheStolenSzechuanSauce

#### COREUPDATER.EXE-157C54BB.pf

- **Identity**: prefetch for the Case 001 implant `coreupdater.exe` (Meterpreter).
- **MD5**: `d3db6935c7ad9f93964b0893997af049`
- **Notable**: decompresses to 24316 bytes; run count 1; last run 2020-09-19;
  loaded from `\…\WINDOWS\SYSTEM32\COREUPDATER.EXE`; volume serial `B0E0E8FF`; 51 files.

#### AUDIODG.EXE-AB22E9A6.pf

- **MD5**: `18bcdd9d31865769309053816e812811`
- **Notable**: run count 8 (exercises the Win10 run-counter shift), 8 last-run times, 79 files.

#### AM_DELTA.EXE-78CA83B0.pf

- **MD5**: `0d48c5b117a3c9e71b66d51fad454354`
- **Notable**: smallest fixture; 6948 decompressed bytes; 13 files.

Provenance confirmed by parsing the artifacts, not just the filenames (Doer-Checker):
all three decompress byte-for-byte identically to Fox-IT dissect.util and their
SCCA fields match windowsprefetch (see `docs/validation.md`).
