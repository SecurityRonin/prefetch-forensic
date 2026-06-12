//! Pure-Rust, read-only Windows **Prefetch** (`.pf`) reader.
//!
//! Windows 8.1/10/11 store prefetch compressed with a `MAM` (Xpress-Huffman)
//! wrapper; the decompressed payload is the classic `SCCA` structure. This crate
//! decodes both, cross-platform, with no Windows API dependency.
//!
//! - [`decompress`] — MAM wrapper → raw SCCA bytes (Xpress-Huffman via the
//!   [`xpress_huffman`] crate).
//! - [`parse`] — full SCCA v30/31 → [`PrefetchInfo`].

#![forbid(unsafe_code)]

/// Errors decoding a prefetch file.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefetchError {
    /// Input is shorter than the smallest valid header.
    TooShort,
    /// Not a recognized prefetch container (`MAM`/Xpress-Huffman or raw `SCCA`).
    BadSignature,
    /// The MAM/Xpress-Huffman payload failed to decompress.
    Decompress(xpress_huffman::Error),
    /// SCCA format version not supported by this parser (the `u32` is the version
    /// found). Win10/11 (30/31) are supported; XP/Vista/7/8.1 (17/23/26) are not
    /// yet — their `FileInformation` block has a different layout.
    UnsupportedVersion(u32),
    /// An offset/length field in the SCCA payload pointed past the buffer.
    TruncatedRecord,
}

const MAM_SIGNATURE: &[u8; 3] = b"MAM";
/// MAM compression byte for Xpress-Huffman (`COMPRESSION_FORMAT_XPRESS_HUFF`).
const MAM_XPRESS_HUFFMAN: u8 = 0x04;
/// Decompressed SCCA payload signature. It sits at byte offset 4 — the SCCA
/// header is `[u32 version][b"SCCA"]…` (version values: 17 XP, 23 Vista/7,
/// 26 Win8.1, 30 Win10, 31 Win11).
pub const SCCA_SIGNATURE: &[u8; 4] = b"SCCA";
/// Byte offset of [`SCCA_SIGNATURE`] within the decompressed payload.
pub const SCCA_SIGNATURE_OFFSET: usize = 4;

/// Decompress a (possibly MAM-wrapped) prefetch file into its raw `SCCA` bytes.
///
/// Recognizes the Win8.1+ `MAM\x04` Xpress-Huffman container (4-byte signature +
/// 4-byte little-endian decompressed size, then the compressed stream) and passes
/// an already-raw `SCCA` file through unchanged (Win7 and earlier).
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, PrefetchError> {
    if data.len() < 8 {
        return Err(PrefetchError::TooShort);
    }
    // A raw (uncompressed, Win7-era) prefetch IS the SCCA structure: a u32
    // version at offset 0 and the SCCA signature at offset 4. Pass it through.
    if &data[SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4] == SCCA_SIGNATURE {
        return Ok(data.to_vec());
    }
    if &data[0..3] != MAM_SIGNATURE || data[3] != MAM_XPRESS_HUFFMAN {
        return Err(PrefetchError::BadSignature);
    }
    let decompressed_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    xpress_huffman::decompress(&data[8..], decompressed_size).map_err(PrefetchError::Decompress)
}

// --- SCCA structure parsing (v30/31 — Win10/11) ---------------------------

/// A volume referenced by a prefetch file's `VolumeInformation` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// Device path, e.g. `\VOLUME{01d68d85e0da1e22-b0e0e8ff}`.
    pub device_path: String,
    /// Volume serial number (the 32-bit value Windows formats as 8 hex digits).
    pub serial: u32,
    /// Volume creation time, as a raw Windows `FILETIME` (100 ns ticks since 1601).
    pub creation_time: i64,
}

/// The forensically-salient contents of a Windows prefetch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchInfo {
    /// SCCA format version (30 = Win10, 31 = Win11).
    pub version: u32,
    /// The executable's base name (upper-cased by Windows), e.g. `COREUPDATER.EXE`.
    pub executable: String,
    /// Number of times the program has been run.
    pub run_count: u32,
    /// Up to eight most-recent run times, newest first, as raw `FILETIME` values.
    pub last_run_times: Vec<i64>,
    /// Volumes the program touched.
    pub volumes: Vec<VolumeInfo>,
    /// Files (full volume-relative paths) loaded during the traced runs.
    pub filenames: Vec<String>,
}

/// Read a little-endian `u32` at `off`, or `None` if it would run past `d`.
fn rd_u32(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Read a little-endian `i64` at `off`, or `None` if it would run past `d`.
fn rd_i64(d: &[u8], off: usize) -> Option<i64> {
    d.get(off..off + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        i64::from_le_bytes(a)
    })
}

/// Decode a UTF-16LE string of `byte_len` bytes at `off`, truncated at the first
/// NUL. `None` if the range runs past `d`.
fn rd_utf16_z(d: &[u8], off: usize, byte_len: usize) -> Option<String> {
    let s = d.get(off..off + byte_len)?;
    let units: Vec<u16> = s
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Parse a prefetch file (`MAM`-compressed or raw `SCCA`) into [`PrefetchInfo`].
///
/// Supports SCCA versions 30 (Win10) and 31 (Win11); other versions yield
/// [`PrefetchError::UnsupportedVersion`].
pub fn parse(file_bytes: &[u8]) -> Result<PrefetchInfo, PrefetchError> {
    let scca = decompress(file_bytes)?;
    parse_decompressed(&scca)
}

/// SCCA `FileInformation` block starts right after the 84-byte header.
const FILE_INFO_OFFSET: usize = 84;
/// Largest volume count we will trust from the header (allocation-bomb guard).
const MAX_VOLUMES: u32 = 64;

/// Parse an already-decompressed SCCA payload (version 30/31).
pub fn parse_decompressed(scca: &[u8]) -> Result<PrefetchInfo, PrefetchError> {
    if scca.len() < FILE_INFO_OFFSET {
        return Err(PrefetchError::TooShort);
    }
    if scca.get(4..8) != Some(SCCA_SIGNATURE.as_slice()) {
        return Err(PrefetchError::BadSignature);
    }
    let version = rd_u32(scca, 0).ok_or(PrefetchError::TooShort)?;
    if version != 30 && version != 31 {
        return Err(PrefetchError::UnsupportedVersion(version));
    }

    // Header: executable name is UTF-16, 60 bytes at offset 16.
    let executable = rd_utf16_z(scca, 16, 60).ok_or(PrefetchError::TruncatedRecord)?;

    // FileInformation fields are relative to FILE_INFO_OFFSET.
    let fi = FILE_INFO_OFFSET;
    let filename_off = rd_u32(scca, fi + 16).ok_or(PrefetchError::TruncatedRecord)? as usize;
    let filename_sz = rd_u32(scca, fi + 20).ok_or(PrefetchError::TruncatedRecord)? as usize;
    let volumes_off = rd_u32(scca, fi + 24).ok_or(PrefetchError::TruncatedRecord)? as usize;
    let volume_count = rd_u32(scca, fi + 28).ok_or(PrefetchError::TruncatedRecord)?;

    // Last run times: eight FILETIMEs at fi+44; keep the non-zero leading run.
    let mut last_run_times = Vec::with_capacity(8);
    for i in 0..8 {
        match rd_i64(scca, fi + 44 + i * 8) {
            Some(t) if t > 0 => last_run_times.push(t),
            _ => break,
        }
    }

    // Run count: newer Win10 builds shifted the counter back 8 bytes. The field
    // at fi+120 is zero in the old layout; when non-zero, the count lives at
    // fi+116 instead of fi+124.
    let run_count = if rd_u32(scca, fi + 120).unwrap_or(0) == 0 {
        rd_u32(scca, fi + 124).unwrap_or(0)
    } else {
        rd_u32(scca, fi + 116).unwrap_or(0)
    };

    let filenames = parse_filenames(scca, filename_off, filename_sz);
    let volumes = parse_volumes(scca, volumes_off, volume_count.min(MAX_VOLUMES));

    Ok(PrefetchInfo {
        version,
        executable,
        run_count,
        last_run_times,
        volumes,
        filenames,
    })
}

/// Split the NUL-separated UTF-16LE filename strings block into paths.
fn parse_filenames(scca: &[u8], off: usize, size: usize) -> Vec<String> {
    let Some(block) = scca.get(off..off.saturating_add(size)) else {
        return Vec::new();
    };
    let units: Vec<u16> = block
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse `count` 96-byte volume records starting at `vol_off`.
fn parse_volumes(scca: &[u8], vol_off: usize, count: u32) -> Vec<VolumeInfo> {
    let mut out = Vec::with_capacity(count as usize);
    for j in 0..count as usize {
        let rec = vol_off + j * 96;
        let (Some(dev_off), Some(dev_nchar), Some(ct), Some(serial)) = (
            rd_u32(scca, rec).map(|v| v as usize),
            rd_u32(scca, rec + 4).map(|v| v as usize),
            rd_i64(scca, rec + 8),
            rd_u32(scca, rec + 16),
        ) else {
            break;
        };
        let device_path = rd_utf16_z(scca, vol_off + dev_off, dev_nchar * 2).unwrap_or_default();
        out.push(VolumeInfo {
            device_path,
            serial,
            creation_time: ct,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // A real Win10 MAM-compressed prefetch file (Case 001 Desktop): the malware's
    // own prefetch. Header `MAM\x04` + decompressed size 0x5efc = 24316.
    const COREUPDATER: &[u8] = include_bytes!("../../tests/data/COREUPDATER.EXE-157C54BB.pf");
    const AUDIODG: &[u8] = include_bytes!("../../tests/data/AUDIODG.EXE-AB22E9A6.pf");

    #[test]
    fn mam_header_rejects_non_prefetch() {
        // 8+ bytes, neither SCCA nor MAM\x04 → BadSignature.
        assert_eq!(
            decompress(b"NOPE\x00\x00\x00\x00").err(),
            Some(PrefetchError::BadSignature)
        );
        // wrong MAM compression byte → BadSignature.
        assert_eq!(
            decompress(b"MAM\x02\x00\x00\x00\x00").err(),
            Some(PrefetchError::BadSignature)
        );
        // shorter than the 8-byte MAM header → TooShort.
        assert_eq!(decompress(b"MA").err(), Some(PrefetchError::TooShort));
    }

    #[test]
    fn raw_scca_passes_through() {
        // A raw (Win7-era) prefetch: u32 version at 0, SCCA at offset 4.
        let mut raw = 23u32.to_le_bytes().to_vec();
        raw.extend_from_slice(b"SCCA");
        raw.extend_from_slice(&[0u8; 20]);
        assert_eq!(decompress(&raw).unwrap(), raw);
    }

    /// The load-bearing oracle: decompressing the REAL malware prefetch must yield
    /// the exact declared size and a valid `SCCA` payload.
    #[test]
    fn decompresses_real_win10_prefetch_to_scca() {
        // header: MAM\x04 + LE u32 size
        assert_eq!(&COREUPDATER[0..3], b"MAM");
        assert_eq!(COREUPDATER[3], 0x04);
        let declared = u32::from_le_bytes([
            COREUPDATER[4],
            COREUPDATER[5],
            COREUPDATER[6],
            COREUPDATER[7],
        ]) as usize;

        // decompressed length must match the MAM header.
        let out = decompress(COREUPDATER).unwrap();
        assert_eq!(out.len(), declared);
        // SCCA header: [u32 version][b"SCCA"]. The malware ran on the Win10
        // Desktop → version 30.
        assert_eq!(
            &out[SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4],
            SCCA_SIGNATURE
        );
        assert_eq!(u32::from_le_bytes([out[0], out[1], out[2], out[3]]), 30);
    }

    #[test]
    fn decompresses_second_real_prefetch() {
        let out = decompress(AUDIODG).unwrap();
        assert_eq!(
            &out[SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4],
            SCCA_SIGNATURE
        );
    }

    /// Ground truth from the real malware prefetch (probed from the decompressed
    /// SCCA v30 payload): the executable, a single run, its run time, the one
    /// volume's serial/path, and the 51 accessed files.
    #[test]
    fn parses_real_coreupdater_scca() {
        let info = parse(COREUPDATER).unwrap();
        assert_eq!(info.version, 30);
        assert_eq!(info.executable, "COREUPDATER.EXE");
        assert_eq!(info.run_count, 1);
        assert_eq!(info.last_run_times, vec![132_449_604_494_103_203]);
        assert_eq!(info.volumes.len(), 1);
        assert_eq!(info.volumes[0].serial, 0xB0E0_E8FF);
        assert_eq!(
            info.volumes[0].device_path,
            r"\VOLUME{01d68d85e0da1e22-b0e0e8ff}"
        );
        assert_eq!(info.filenames.len(), 51);
        assert!(info.filenames.iter().any(|f| f.ends_with("NTDLL.DLL")));
        assert!(info
            .filenames
            .iter()
            .any(|f| f.ends_with("COREUPDATER.EXE")));
    }

    /// AUDIODG ran 8 times: the Win10 run-counter shift must resolve to 8, with
    /// all 8 last-run timestamps recovered.
    #[test]
    fn parses_audiodg_run_count_and_times() {
        let info = parse(AUDIODG).unwrap();
        assert_eq!(info.run_count, 8);
        assert_eq!(info.last_run_times.len(), 8);
        assert_eq!(info.last_run_times[0], 132_449_663_254_875_727);
        assert_eq!(info.filenames.len(), 79);
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        // A raw SCCA payload claiming version 23 (Vista/7) — unsupported layout.
        let mut p = vec![0u8; 256];
        p[0..4].copy_from_slice(&23u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        assert_eq!(parse(&p).err(), Some(PrefetchError::UnsupportedVersion(23)));
    }

    fn put16(buf: &mut [u8], off: usize, s: &str) {
        for (i, u) in s.encode_utf16().enumerate() {
            buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
    }

    /// Build a minimal valid SCCA v30 payload: one volume, one filename.
    /// `old_run_count`: leave `FileInfo+120` zero so the count is read from `+124`
    /// (the pre-shift Win10 layout); otherwise use the shifted `+116`.
    fn build_scca(old_run_count: bool) -> Vec<u8> {
        let mut p = vec![0u8; 84 + 224];
        p[0..4].copy_from_slice(&30u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        put16(&mut p, 16, "X.EXE");

        let fname = r"\VOL\X.EXE";
        let mut fbytes = vec![0u8; (fname.encode_utf16().count() + 1) * 2];
        put16(&mut fbytes, 0, fname); // trailing NUL already zeroed
        let fname_off = p.len();
        p.extend_from_slice(&fbytes);

        let vol_off = p.len();
        let dev = r"\VOLUME{abcd}";
        let dev_nchar = dev.encode_utf16().count();
        let mut vol = vec![0u8; 96];
        vol[0..4].copy_from_slice(&96u32.to_le_bytes()); // device-name offset (rel)
        vol[4..8].copy_from_slice(&(dev_nchar as u32).to_le_bytes());
        vol[8..16].copy_from_slice(&123i64.to_le_bytes()); // creation time
        vol[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // serial
        p.extend_from_slice(&vol);
        let mut dbytes = vec![0u8; dev_nchar * 2];
        put16(&mut dbytes, 0, dev);
        p.extend_from_slice(&dbytes);
        let vol_size = (p.len() - vol_off) as u32;

        let fi = FILE_INFO_OFFSET;
        p[fi + 16..fi + 20].copy_from_slice(&(fname_off as u32).to_le_bytes());
        p[fi + 20..fi + 24].copy_from_slice(&(fbytes.len() as u32).to_le_bytes());
        p[fi + 24..fi + 28].copy_from_slice(&(vol_off as u32).to_le_bytes());
        p[fi + 28..fi + 32].copy_from_slice(&1u32.to_le_bytes());
        p[fi + 32..fi + 36].copy_from_slice(&vol_size.to_le_bytes());
        p[fi + 44..fi + 52].copy_from_slice(&1000i64.to_le_bytes()); // one run time
        if old_run_count {
            p[fi + 124..fi + 128].copy_from_slice(&5u32.to_le_bytes());
        } else {
            p[fi + 120..fi + 124].copy_from_slice(&3u32.to_le_bytes());
            p[fi + 116..fi + 120].copy_from_slice(&7u32.to_le_bytes());
        }
        p
    }

    #[test]
    fn parses_synthetic_scca_old_and_new_run_count() {
        let info = parse_decompressed(&build_scca(true)).unwrap();
        assert_eq!(info.executable, "X.EXE");
        assert_eq!(info.run_count, 5); // FileInfo+124 (old layout)
        assert_eq!(info.last_run_times, vec![1000]);
        assert_eq!(info.volumes.len(), 1);
        assert_eq!(info.volumes[0].serial, 0xDEAD_BEEF);
        assert_eq!(info.volumes[0].device_path, r"\VOLUME{abcd}");
        assert_eq!(info.filenames, vec![r"\VOL\X.EXE".to_string()]);

        let shifted = parse_decompressed(&build_scca(false)).unwrap();
        assert_eq!(shifted.run_count, 7); // FileInfo+116 (shifted layout)
    }

    #[test]
    fn parse_decompressed_rejects_short_and_unsigned() {
        assert_eq!(
            parse_decompressed(&[0u8; 50]).err(),
            Some(PrefetchError::TooShort)
        );
        // ≥84 bytes but no SCCA at offset 4.
        assert_eq!(
            parse_decompressed(&[0u8; 100]).err(),
            Some(PrefetchError::BadSignature)
        );
    }

    #[test]
    fn truncated_filename_and_volume_offsets_degrade_gracefully() {
        let fi = FILE_INFO_OFFSET;
        let mut p = build_scca(true);
        let past = (p.len() as u32) + 1000;
        p[fi + 16..fi + 20].copy_from_slice(&past.to_le_bytes()); // filenames off past EOF
        assert!(parse_decompressed(&p).unwrap().filenames.is_empty());

        let mut q = build_scca(true);
        q[fi + 24..fi + 28].copy_from_slice(&past.to_le_bytes()); // volumes off past EOF
        assert!(parse_decompressed(&q).unwrap().volumes.is_empty());
    }
}
