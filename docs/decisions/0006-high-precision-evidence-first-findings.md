# 6. Evidence first, high-precision findings second

Date: 2026-07-24
Status: Accepted

## Context

Prefetch's primary forensic value is **execution evidence**: it proves a program
ran, how many times, when (the last eight runs), from where, and what it loaded.
That evidence is valuable on its own and is unambiguous. Anomaly grading, by
contrast, is where a prefetch tool can do harm: a noisy analyzer that flags every
unfamiliar `System32` name would have raised a false positive on the real Case
001 implant `coreupdater.exe` — which the attacker planted *inside* `System32`
under a novel name — teaching examiners to distrust the tool. Findings are
observations, never verdicts; whether an execution is malicious is a
correlation/tribunal question.

## Decision

1. **Always return the execution evidence.** `execution_record()`
   (`forensic/src/lib.rs`) yields the `ExecutionRecord` (executable, run count,
   last-run FILETIMEs, resolved image path, volume serial, loaded-file count)
   unconditionally; `audit_bytes()` returns it alongside any findings.
2. **Ship exactly two high-precision findings**, each firing only on a genuinely
   anomalous structural pattern:
   - `PREFETCH-SYSTEM-BINARY-RELOCATED` (High, `Concealment`, `T1036.005`) — a
     `forensicnomicon` system-binary name whose traced image path is not under
     `System32`/`SysWOW64`.
   - `PREFETCH-SUSPICIOUS-EXEC-PATH` (Medium, `Threat`, `T1204`) — the image ran
     from a `forensicnomicon` staging directory.
3. **Stay quiet on benign prefetch.** A normal `System32` program — including a
   novel-named one — yields evidence but no finding. The
   `coreupdater_yields_execution_evidence_and_no_fp` test locks this in: the real
   malware produces its full `ExecutionRecord` and an **empty** anomaly list.
4. Findings are phrased "consistent with masquerading / suspicious execution,"
   never as a verdict (the `note()` strings and the module docs).

## Consequences

- The tool is trustworthy: no false positive on the hardest real case in the
  validation corpus, at the cost of not flagging the implant (correctly — its
  maliciousness is established by memory injection / C2 correlation, not
  prefetch).
- The finding-code contract is small and stable (`PREFETCH-…` SCREAMING-KEBAB);
  new detections get new codes rather than re-grading a shipped one.

## Alternatives considered

- **Score every execution (e.g. entropy of the name, unfamiliar binaries)** —
  rejected; low precision, and it would misfire on `coreupdater.exe` in
  `System32`, the exact false positive this design avoids.
