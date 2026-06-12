//! Emit, as JSON, prefetch-core's decompressed-payload and parsed
//! [`PrefetchInfo`] fields for each fixture — consumed by the external-oracle
//! validation harness (`docs/validation.md`). One JSON object per line; also
//! writes each decompressed payload to `<out_dir>/<name>.scca` for a
//! byte-for-byte diff against an independent decompressor.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::path::PathBuf;

/// Minimal FNV-free SHA-256 via the `sha2`-free route is overkill here; instead
/// emit a hex of the payload length + a simple checksum the harness can match.
/// We print the raw length and a hex digest computed by the harness side, so
/// here we only need the length and the parsed fields; for the byte-identity
/// check we also dump the full decompressed bytes to a sibling .scca file.
fn main() {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/pf_scca".to_string());
    std::fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    for name in [
        "COREUPDATER.EXE-157C54BB.pf",
        "AUDIODG.EXE-AB22E9A6.pf",
        "AM_DELTA.EXE-78CA83B0.pf",
    ] {
        let p = root.join("tests/data").join(name);
        let raw = std::fs::read(&p).expect("read fixture");
        let scca = prefetch_core::decompress(&raw).expect("decompress");
        // Write the decompressed payload so the harness can diff it against its
        // own (dissect.util) decompression byte-for-byte.
        std::fs::write(PathBuf::from(&out_dir).join(format!("{name}.scca")), &scca)
            .expect("write scca");

        let info = prefetch_core::parse(&raw).expect("parse");
        let files: Vec<String> = info.filenames.iter().map(|f| escape(f)).collect();
        let vols: Vec<String> = info
            .volumes
            .iter()
            .map(|v| {
                format!(
                    "{{\"serial\":{},\"device_path\":\"{}\",\"creation_time\":{}}}",
                    v.serial,
                    escape(&v.device_path),
                    v.creation_time
                )
            })
            .collect();
        println!(
            "{{\"file\":\"{}\",\"scca_len\":{},\"version\":{},\"executable\":\"{}\",\"run_count\":{},\"last_run_times\":{:?},\"filenames_count\":{},\"filenames\":[{}],\"volumes\":[{}]}}",
            name,
            scca.len(),
            info.version,
            escape(&info.executable),
            info.run_count,
            info.last_run_times,
            info.filenames.len(),
            files.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(","),
            vols.join(",")
        );
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
}
