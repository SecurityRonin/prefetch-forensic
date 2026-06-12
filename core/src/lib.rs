//! Pure-Rust, read-only Windows **Prefetch** (`.pf`) reader.
//!
//! Windows 8.1/10/11 store prefetch compressed with a `MAM` (Xpress-Huffman)
//! wrapper; the decompressed payload is the classic `SCCA` structure. This crate
//! decodes both, cross-platform, with no Windows API dependency.
//!
//! - [`decompress`] — MAM wrapper + Xpress-Huffman ([MS-XCA] §2.2.4) → raw SCCA bytes.

#![forbid(unsafe_code)]

/// Errors decoding a prefetch file.
#[derive(Debug, PartialEq, Eq)]
pub enum PrefetchError {
    /// Input is shorter than the smallest valid header.
    TooShort,
    /// Not a recognized prefetch container (`MAM`/Xpress-Huffman or raw `SCCA`).
    BadSignature,
    /// The Huffman code-tree block was truncated.
    TruncatedTree,
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
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, PrefetchError> {
    if data.len() >= 4 && &data[0..4] == SCCA_SIGNATURE {
        return Ok(data.to_vec()); // already-uncompressed (Win7) prefetch
    }
    if data.len() < 8 {
        return Err(PrefetchError::TooShort);
    }
    if &data[0..3] != MAM_SIGNATURE || data[3] != MAM_XPRESS_HUFFMAN {
        return Err(PrefetchError::BadSignature);
    }
    // RED: Xpress-Huffman decompressor not yet implemented.
    Ok(Vec::new())
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
        assert_eq!(decompress(b"NOPE\x00\x00\x00\x00").err(), Some(PrefetchError::BadSignature));
        // wrong MAM compression byte → BadSignature.
        assert_eq!(decompress(b"MAM\x02\x00\x00\x00\x00").err(), Some(PrefetchError::BadSignature));
        // shorter than the 8-byte MAM header → TooShort.
        assert_eq!(decompress(b"MA").err(), Some(PrefetchError::TooShort));
    }

    #[test]
    fn raw_scca_passes_through() {
        let mut raw = b"SCCA".to_vec();
        raw.extend_from_slice(&[0u8; 20]);
        assert_eq!(decompress(&raw).unwrap(), raw);
    }

    /// The load-bearing oracle: decompressing the REAL malware prefetch must yield
    /// the exact declared size and a valid `SCCA` payload.
    #[test]
    fn decompresses_real_win10_prefetch_to_scca() {
        assert_eq!(&COREUPDATER[0..3], b"MAM");
        assert_eq!(COREUPDATER[3], 0x04);
        let declared = u32::from_le_bytes([
            COREUPDATER[4],
            COREUPDATER[5],
            COREUPDATER[6],
            COREUPDATER[7],
        ]) as usize;

        let out = decompress(COREUPDATER).unwrap();
        assert_eq!(out.len(), declared, "decompressed length must match the MAM header");
        // SCCA header: [u32 version][b"SCCA"]. The malware ran on the Win10
        // Desktop → version 30.
        assert_eq!(
            &out[SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4],
            SCCA_SIGNATURE,
            "payload must carry the SCCA signature at offset 4"
        );
        assert_eq!(
            u32::from_le_bytes([out[0], out[1], out[2], out[3]]),
            30,
            "Win10 prefetch format version"
        );
    }

    #[test]
    fn decompresses_second_real_prefetch() {
        let out = decompress(AUDIODG).unwrap();
        assert_eq!(&out[SCCA_SIGNATURE_OFFSET..SCCA_SIGNATURE_OFFSET + 4], SCCA_SIGNATURE);
    }
}
