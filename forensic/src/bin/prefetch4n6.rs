//! `prefetch4n6` — read Windows Prefetch (`.pf`) files and print the execution evidence (what
//! ran, how many times, when, from where) plus graded findings.
//!
//! Decoding + analysis live in the `prefetch_forensic` / `prefetch_core` libraries; this binary
//! reads each file and renders [`prefetch_forensic::audit_bytes`].
#![forbid(unsafe_code)]

use std::process::ExitCode;

use forensicnomicon::report::Observation;
use prefetch_forensic::{audit_bytes, ExecutionRecord, PrefetchAnomaly};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let files = args.iter().any(|a| a == "--files");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if paths.is_empty() {
        eprintln!("usage: prefetch4n6 <file.pf>...  [--files]   (--files lists loaded-file count)");
        return ExitCode::from(2);
    }

    let mut exit = ExitCode::SUCCESS;
    for path in paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("prefetch4n6: {path}: {e}");
                exit = ExitCode::FAILURE;
                continue;
            }
        };
        match audit_bytes(&bytes) {
            Ok((record, anomalies)) => print_record(&record, &anomalies, files),
            Err(e) => {
                eprintln!("prefetch4n6: {path}: {e:?}");
                exit = ExitCode::FAILURE;
            }
        }
    }
    exit
}

fn print_record(record: &ExecutionRecord, anomalies: &[PrefetchAnomaly], files: bool) {
    let last = record
        .last_run_filetimes
        .first()
        .and_then(|&ft| filetime_to_iso(ft))
        .unwrap_or_else(|| "-".to_string());
    println!(
        "{}  ran {}x  last {last}  from {}",
        record.executable,
        record.run_count,
        record.image_path.as_deref().unwrap_or("?")
    );
    if files {
        println!("  loaded files: {}", record.loaded_file_count);
    }
    for a in anomalies {
        let sev = a
            .severity()
            .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
        println!("  [{sev}] {}", a.code());
        println!("    {}", a.note());
    }
}

/// Convert a Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC) to an ISO-8601 UTC string.
///
/// Returns `None` for the `0` sentinel Windows writes when a time is not set — it is an
/// absent timestamp, not midnight on 1601-01-01, and must render as `-` rather than a date.
fn filetime_to_iso(filetime: i64) -> Option<String> {
    if filetime == 0 {
        return None;
    }
    // 11 644 473 600 s between 1601-01-01 and the Unix epoch.
    let unix_secs = filetime / 10_000_000 - 11_644_473_600;
    jiff::Timestamp::from_second(unix_secs)
        .ok()
        .map(|t| t.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// FILETIME `0` is the Windows "not set" sentinel, not 1601-01-01. It must
    /// have no rendering at all, so `print_record`'s `-` fallback engages —
    /// otherwise an unset timestamp is reported as a real-looking run time.
    #[test]
    fn unset_filetime_has_no_rendering() {
        assert_eq!(filetime_to_iso(0), None);
    }

    /// A genuine FILETIME still renders (COREUPDATER.EXE's recorded run).
    #[test]
    fn real_filetime_renders_as_iso() {
        assert_eq!(
            filetime_to_iso(132_449_604_494_103_203).unwrap(),
            "2020-09-19T03:40:49Z"
        );
    }
}
