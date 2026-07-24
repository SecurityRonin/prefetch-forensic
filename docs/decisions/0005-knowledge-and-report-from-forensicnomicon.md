# 5. DFIR knowledge and the report model come from `forensicnomicon`

Date: 2026-07-24
Status: Accepted

## Context

The analyzer needs two kinds of shared DFIR knowledge: the set of Windows
system-binary names that should only ever live in `System32` (to detect
relocation), and the set of malware-staging directories (Temp, Downloads,
`$Recycle.Bin`, PerfLogs, …). Baking those lists into `prefetch-forensic` would
duplicate knowledge every analyzer in the fleet needs and let the copies drift.
Separately, every fleet analyzer must emit its findings as the one normalized
`forensicnomicon::report` model so ORCHESTRATION (Issen) renders them uniformly.

`forensicnomicon` is the fleet's zero-dependency KNOWLEDGE leaf — the correct
place for both the shared lists and the report vocabulary — and the dependency
arrow must point *down* onto it.

## Decision

1. **Source the masquerade/suspicious-path knowledge from `forensicnomicon`**
   (commit `02fb118`). `audit()` (`forensic/src/lib.rs`) calls
   `forensicnomicon::processes::is_system32_binary(name)` and
   `forensicnomicon::heuristics::paths::is_suspicious_exec_path(path)` instead of
   an inline allow-list.
2. **Emit findings via `forensicnomicon::report`.** `PrefetchAnomaly` keeps its
   typed domain enum and `impl Observation` (severity/category/code/note/mitre/
   subjects); `to_finding()` assembles the canonical `Finding` under a `Source`
   tagged `analyzer = "prefetch-forensic"` — the fleet producer pattern.
3. Track the current `forensicnomicon` major: the dep is `forensicnomicon = "1"`
   (`[workspace.dependencies]`), reached via the `0.4 → 0.5 → 0.11 → 1.0` bumps
   in the git history (commits `426c4af`, `cd49a5e`, `cd8f651`).

## Consequences

- The system-binary baseline and staging-directory list stay correct and shared:
  fixing one entry in `forensicnomicon` fixes every analyzer.
- prefetch findings drop straight into an Issen `Report` beside NTFS / registry /
  EVTX findings with no bespoke adapter.
- The dependency direction stays clean: analyzer → KNOWLEDGE leaf, never the
  reverse.

## Alternatives considered

- **Hardcode the two lists in `prefetch-forensic`** — rejected; duplicates
  fleet-wide DFIR knowledge and drifts, and would re-emit a bespoke finding type
  Issen cannot render uniformly.
