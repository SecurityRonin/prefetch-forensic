//! Pure-Rust, read-only Windows **Prefetch** (`.pf`) reader.
//!
//! Windows 8.1/10/11 store prefetch compressed with a `MAM` (Xpress-Huffman)
//! wrapper; the decompressed payload is the classic `SCCA` structure. This crate
//! decodes both, cross-platform, with no Windows API dependency.
//!
//! - [`decompress`] — MAM wrapper + Xpress-Huffman ([MS-XCA] §2.2.4) → raw SCCA bytes.
//!
//! The Xpress-Huffman decoder is reimplemented clean-room from the Microsoft Open
//! Specification [MS-XCA] (the algorithm; structure cross-checked against Fox-IT's
//! `dissect.util` reference) — no code copied. References: <https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-XCA/[MS-XCA].pdf>.

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
///
/// Recognizes the Win8.1+ `MAM\x04` Xpress-Huffman container (4-byte signature +
/// 4-byte little-endian decompressed size, then the compressed stream) and passes
/// an already-raw `SCCA` file through unchanged (Win7 and earlier).
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
    let decompressed_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let out = xpress_huffman_decompress(&data[8..], decompressed_size)?;
    Ok(out)
}

// --- Xpress-Huffman ([MS-XCA] §2.2.4) -------------------------------------

/// One Huffman tree node (index-based; no allocation per child).
#[derive(Clone, Copy)]
struct Node {
    children: [usize; 2],
    is_leaf: bool,
    symbol: u16,
}
const NONE: usize = usize::MAX;

/// Build the per-block Huffman decode tree from its 256-byte code-length table
/// (512 symbols, 4 bits each: byte k holds symbol 2k in the low nibble, 2k+1 in
/// the high nibble). Canonical-code assignment per [MS-XCA].
fn build_tree(buf: &[u8]) -> Result<Vec<Node>, PrefetchError> {
    if buf.len() < 256 {
        return Err(PrefetchError::TruncatedTree);
    }
    let mut nodes = vec![
        Node {
            children: [NONE, NONE],
            is_leaf: false,
            symbol: 0,
        };
        1024
    ];

    // (code_length, symbol), then stable-sorted by (length, symbol).
    let mut symbols: Vec<(u8, u16)> = Vec::with_capacity(512);
    for (i, &c) in buf.iter().enumerate().take(256) {
        symbols.push((c & 0x0F, (i * 2) as u16));
        symbols.push((c >> 4, (i * 2 + 1) as u16));
    }
    symbols.sort_unstable();

    let start = symbols.iter().take_while(|(len, _)| *len == 0).count();

    let mut mask: u32 = 0;
    let mut bits: u32 = 1;
    let mut tree_index = 1usize;

    for &(length, symbol) in symbols.iter().take(512).skip(start) {
        let length = u32::from(length);
        {
            let node = &mut nodes[tree_index];
            node.symbol = symbol;
            node.is_leaf = true;
        }
        mask = mask.wrapping_shl(length.wrapping_sub(bits));
        bits = length;
        tree_index = add_leaf(&mut nodes, tree_index, mask, bits);
        mask = mask.wrapping_add(1);
    }
    Ok(nodes)
}

/// Splice leaf node `idx` into the tree along the path described by `mask`/`bits`,
/// creating internal nodes as needed. Returns the next free node index.
fn add_leaf(nodes: &mut [Node], idx: usize, mask: u32, bits: u32) -> usize {
    let mut cur = 0usize;
    let mut i = idx + 1;
    let mut bits = bits;
    while bits > 1 {
        bits -= 1;
        let childidx = ((mask >> bits) & 1) as usize;
        if nodes[cur].children[childidx] == NONE {
            nodes[cur].children[childidx] = i;
            nodes[i].is_leaf = false;
            i += 1;
        }
        cur = nodes[cur].children[childidx];
    }
    nodes[cur].children[(mask & 1) as usize] = idx;
    i
}

/// Bit reader over the compressed stream: a 32-bit window refilled 16 bits at a
/// time from little-endian source words, with a byte cursor shared with the
/// extended-length / extra-offset byte reads (they interleave, per [MS-XCA]).
struct BitStream<'a> {
    data: &'a [u8],
    pos: usize,
    mask: u32,
    bits: i32,
}

impl BitStream<'_> {
    /// Read one 16-bit little-endian word; EOF pads like Python `read(2).rjust(2)`
    /// (a lone trailing byte becomes the high byte). Advances the cursor by the
    /// bytes actually available (≤ 2).
    fn read16(&mut self) -> u32 {
        let avail = self.data.len().saturating_sub(self.pos);
        let v = match avail {
            0 => 0,
            1 => u32::from(self.data[self.pos]) << 8,
            _ => u32::from(u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]])),
        };
        self.pos += avail.min(2);
        v
    }

    fn init(&mut self) {
        self.mask = (self.read16() << 16).wrapping_add(self.read16());
        self.bits = 32;
    }

    fn lookup(&self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.mask >> (32 - n)
        }
    }

    fn skip(&mut self, n: i32) {
        self.mask = self.mask.wrapping_shl(n as u32);
        self.bits -= n;
        if self.bits < 16 {
            self.mask = self.mask.wrapping_add(self.read16() << (16 - self.bits));
            self.bits += 16;
        }
    }

    fn read_byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    /// Walk the Huffman tree one bit at a time to a leaf symbol.
    fn decode(&mut self, nodes: &[Node]) -> u16 {
        let mut node = 0usize;
        while !nodes[node].is_leaf {
            let bit = self.lookup(1) as usize;
            self.skip(1);
            let next = nodes[node].children[bit];
            if next == NONE {
                return 0; // cov:unreachable: a valid tree always reaches a leaf
            }
            node = next;
        }
        nodes[node].symbol
    }
}

/// Decompress an Xpress-Huffman stream to `expected` bytes ([MS-XCA] §2.2.4):
/// a sequence of 64 KiB blocks, each prefixed by its own 256-byte Huffman table.
fn xpress_huffman_decompress(data: &[u8], expected: usize) -> Result<Vec<u8>, PrefetchError> {
    let mut dst: Vec<u8> = Vec::with_capacity(expected);
    let mut bs = BitStream {
        data,
        pos: 0,
        mask: 0,
        bits: 0,
    };

    while bs.pos < data.len() && dst.len() < expected {
        let tree = build_tree(&data[bs.pos..])?;
        bs.pos += 256;
        bs.init();

        let mut chunk: usize = 0;
        while chunk < 65536 && bs.pos < data.len() && dst.len() < expected {
            let symbol = bs.decode(&tree);
            if symbol < 256 {
                dst.push(symbol as u8);
                chunk += 1;
                continue;
            }
            let symbol = symbol - 256;
            let mut length = u32::from(symbol & 0x0F);
            let offset_bits = u32::from(symbol >> 4);
            let offset = (1usize << offset_bits) + bs.lookup(offset_bits) as usize;
            if length == 15 {
                length = u32::from(bs.read_byte()) + 15;
                if length == 270 {
                    length = bs.read16();
                }
            }
            bs.skip(offset_bits as i32);
            length += 3;

            if offset == 0 || offset > dst.len() {
                return Err(PrefetchError::BadSignature); // cov:unreachable: valid stream
            }
            let mut remaining = length as usize;
            while remaining > 0 {
                let from = dst.len() - offset;
                let n = remaining.min(offset);
                for k in 0..n {
                    let b = dst[from + k];
                    dst.push(b);
                }
                remaining -= n;
            }
            chunk += length as usize;
        }
    }
    Ok(dst)
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
        // header: MAM\x04 + LE u32 size
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
