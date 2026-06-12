//! Windows **Prefetch** forensic analyzer.
//!
//! Prefetch's primary forensic value is **execution evidence**: it proves a
//! program ran, how many times, when (the last eight runs), from where, and what
//! it loaded. [`execution_record`] extracts that evidence; [`audit`] adds a small
//! set of *high-precision* graded findings — a Windows system-binary name loaded
//! from outside `System32` (masquerading) and execution from a known-suspicious
//! directory.
//!
//! Findings are observations, never verdicts: prefetch establishes that
//! `coreupdater.exe` ran from `System32` at a given time — whether that is
//! malicious is a correlation/tribunal question, not one prefetch answers alone.
//!
//! Built on [`prefetch_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use prefetch_core::{PrefetchError, PrefetchInfo};

/// The execution evidence a single prefetch file establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRecord {
    /// Executable base name (as Windows recorded it, upper-cased).
    pub executable: String,
    /// Number of recorded executions.
    pub run_count: u32,
    /// Up to eight most-recent run times, as raw Windows `FILETIME` values.
    pub last_run_filetimes: Vec<i64>,
    /// The executable's own on-disk path (the loaded file whose name matches the
    /// executable), if present in the loaded-file list.
    pub image_path: Option<String>,
    /// Serial of the first referenced volume, if any.
    pub volume_serial: Option<u32>,
    /// Number of files loaded during the traced runs.
    pub loaded_file_count: usize,
}

/// A graded prefetch finding. Each variant is a *high-precision* triage signal —
/// it stays quiet on benign prefetch (e.g. a normal `System32` program) and fires
/// only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefetchAnomaly {
    /// A Windows system-binary *name* whose traced image path is not under
    /// `System32`/`SysWOW64` — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// Where it was actually loaded from.
        image_path: String,
    },
    /// The program executed from a directory that is a common staging ground for
    /// malware (Temp, Downloads, `$Recycle.Bin`, …) — `T1204`.
    SuspiciousExecutionPath {
        /// Executable base name.
        executable: String,
        /// The suspicious load path.
        image_path: String,
    },
}

/// Windows binaries that legitimately run only from `System32` / `SysWOW64`.
/// A copy of any of these under another path is the classic masquerade. (Source:
/// MITRE T1036.005; the DFIR "system-binary" baseline.)
const SYSTEM32_BINARIES: &[&str] = &[
    "SVCHOST.EXE",
    "LSASS.EXE",
    "SERVICES.EXE",
    "CSRSS.EXE",
    "SMSS.EXE",
    "WININIT.EXE",
    "WINLOGON.EXE",
    "TASKHOSTW.EXE",
    "DLLHOST.EXE",
    "CONHOST.EXE",
    "RUNDLL32.EXE",
    "SPOOLSV.EXE",
    "LSAISO.EXE",
];

/// Directory fragments that are common malware staging grounds — the DFIR
/// "execution from an unusual location" triage rule (SANS/13Cubed). Matched
/// case-insensitively as a substring of the load path.
const SUSPICIOUS_DIRS: &[&str] = &[
    r"\TEMP\",
    r"\WINDOWS\TEMP\",
    r"\APPDATA\LOCAL\TEMP\",
    r"\DOWNLOADS\",
    r"\USERS\PUBLIC\",
    r"\$RECYCLE.BIN\",
    r"\PERFLOGS\",
];

/// Extract the execution evidence from parsed prefetch info.
#[must_use]
pub fn execution_record(_info: &PrefetchInfo) -> ExecutionRecord {
    // RED: not yet implemented.
    ExecutionRecord {
        executable: String::new(),
        run_count: 0,
        last_run_filetimes: Vec::new(),
        image_path: None,
        volume_serial: None,
        loaded_file_count: 0,
    }
}

/// The executable's own load path: the loaded file whose name ends with the
/// executable's base name.
fn image_path_of(info: &PrefetchInfo) -> Option<String> {
    let exe = info.executable.to_uppercase();
    info.filenames
        .iter()
        .find(|f| f.to_uppercase().ends_with(&exe))
        .cloned()
}

/// Audit parsed prefetch info for graded anomalies (may be empty — benign
/// prefetch yields no findings).
#[must_use]
pub fn audit(_info: &PrefetchInfo) -> Vec<PrefetchAnomaly> {
    // RED: not yet implemented.
    Vec::new()
}

/// Parse and audit a prefetch file (`MAM`-compressed or raw `SCCA`) in one call:
/// returns the execution evidence and any graded anomalies. This is the headline
/// entry point.
pub fn audit_bytes(
    file_bytes: &[u8],
) -> Result<(ExecutionRecord, Vec<PrefetchAnomaly>), PrefetchError> {
    let info = prefetch_core::parse(file_bytes)?;
    Ok((execution_record(&info), audit(&info)))
}

impl Observation for PrefetchAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            PrefetchAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            PrefetchAnomaly::SuspiciousExecutionPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            PrefetchAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            PrefetchAnomaly::SuspiciousExecutionPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            PrefetchAnomaly::SystemBinaryRelocated { .. } => "PREFETCH-SYSTEM-BINARY-RELOCATED",
            PrefetchAnomaly::SuspiciousExecutionPath { .. } => "PREFETCH-SUSPICIOUS-EXEC-PATH",
        }
    }

    fn note(&self) -> String {
        match self {
            PrefetchAnomaly::SystemBinaryRelocated { name, image_path } => format!(
                "{name} is a Windows system binary, but prefetch traced its image load \
                 from {image_path} — consistent with masquerading."
            ),
            PrefetchAnomaly::SuspiciousExecutionPath {
                executable,
                image_path,
            } => format!(
                "{executable} executed from {image_path}, a directory commonly used to \
                 stage malware — consistent with suspicious execution."
            ),
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            PrefetchAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            PrefetchAnomaly::SuspiciousExecutionPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path) = match self {
            PrefetchAnomaly::SystemBinaryRelocated { name, image_path } => (name, image_path),
            PrefetchAnomaly::SuspiciousExecutionPath {
                executable,
                image_path,
            } => (executable, image_path),
        };
        vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.clone(),
            label: Some(name.clone()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &PrefetchAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "prefetch-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const COREUPDATER: &[u8] = include_bytes!("../../tests/data/COREUPDATER.EXE-157C54BB.pf");

    /// Real malware prefetch: the execution evidence is recovered, and — because
    /// coreupdater ran from System32 under a novel name — NO false-positive
    /// anomaly fires. (Its maliciousness is a correlation finding, not prefetch's.)
    #[test]
    fn coreupdater_yields_execution_evidence_and_no_fp() {
        let (rec, anomalies) = audit_bytes(COREUPDATER).unwrap();
        assert_eq!(rec.executable, "COREUPDATER.EXE");
        assert_eq!(rec.run_count, 1);
        assert_eq!(rec.last_run_filetimes, vec![132_449_604_494_103_203]);
        assert_eq!(rec.volume_serial, Some(0xB0E0_E8FF));
        assert_eq!(rec.loaded_file_count, 51);
        assert!(rec
            .image_path
            .unwrap()
            .ends_with(r"\SYSTEM32\COREUPDATER.EXE"));
        assert!(
            anomalies.is_empty(),
            "System32 + novel name must not raise an anomaly: {anomalies:?}"
        );
    }

    fn info_with(exe: &str, image_path: &str) -> PrefetchInfo {
        PrefetchInfo {
            version: 30,
            executable: exe.to_string(),
            run_count: 2,
            last_run_times: vec![1],
            volumes: Vec::new(),
            filenames: vec![image_path.to_string()],
        }
    }

    #[test]
    fn masqueraded_system_binary_is_high() {
        let info = info_with("SVCHOST.EXE", r"\VOLUME{x}\WINDOWS\TEMP\SVCHOST.EXE");
        let anomalies = audit(&info);
        // Both a relocated system binary AND a suspicious dir (\TEMP\).
        assert!(anomalies
            .iter()
            .any(|a| matches!(a, PrefetchAnomaly::SystemBinaryRelocated { .. })));
        let f = to_finding(
            anomalies
                .iter()
                .find(|a| matches!(a, PrefetchAnomaly::SystemBinaryRelocated { .. }))
                .unwrap(),
            "Desktop",
        );
        assert_eq!(f.severity, Some(Severity::High));
        assert_eq!(f.code, "PREFETCH-SYSTEM-BINARY-RELOCATED");
        assert_eq!(f.category, Category::Concealment);
    }

    #[test]
    fn legit_system_binary_in_system32_is_clean() {
        let info = info_with("SVCHOST.EXE", r"\VOLUME{x}\WINDOWS\SYSTEM32\SVCHOST.EXE");
        assert!(audit(&info).is_empty());
    }

    #[test]
    fn execution_from_downloads_is_medium_threat() {
        let info = info_with("INVOICE.EXE", r"\VOLUME{x}\USERS\BOB\DOWNLOADS\INVOICE.EXE");
        let anomalies = audit(&info);
        let a = anomalies
            .iter()
            .find(|a| matches!(a, PrefetchAnomaly::SuspiciousExecutionPath { .. }))
            .expect("downloads path should be flagged");
        let f = to_finding(a, "Desktop");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Threat);
        assert_eq!(f.code, "PREFETCH-SUSPICIOUS-EXEC-PATH");
        assert!(f.note.contains("INVOICE.EXE"));
    }

    #[test]
    fn no_image_path_yields_no_anomaly() {
        // Loaded-file list without the executable itself → nothing to locate.
        let info = info_with("FOO.EXE", r"\VOLUME{x}\WINDOWS\SYSTEM32\NTDLL.DLL");
        assert!(audit(&info).is_empty());
    }
}
