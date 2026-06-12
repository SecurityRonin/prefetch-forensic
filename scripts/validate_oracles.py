#!/usr/bin/env python3
"""External-oracle validation for prefetch-core.

Two independent oracles, both run on the real Case 001 (Stolen Szechuan Sauce)
prefetch files:

  1. dissect.util.lzxpress_huffman (Fox-IT) -- an independent [MS-XCA]
     Xpress-Huffman decompressor. Byte-for-byte diff vs prefetch-core's output.
  2. windowsprefetch (Adam Witt) -- an independent SCCA parser. Its v30 field
     parsers run on the (independently) decompressed bytes; fields compared to
     prefetch-core's parse.
"""
import hashlib
import io
import json
import os
import struct
import sys
import tempfile

from dissect.util.compression import lzxpress_huffman
from windowsprefetch import Prefetch

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(REPO, "tests", "data")
SCCA_DIR = os.environ.get("PF_SCCA_DIR", "/tmp/pf_scca")
RUST_JSONL = os.environ.get("PF_RUST_JSONL", "/tmp/pf_rust.jsonl")
FILES = [
    "COREUPDATER.EXE-157C54BB.pf",
    "AUDIODG.EXE-AB22E9A6.pf",
    "AM_DELTA.EXE-78CA83B0.pf",
]


def dissect_decompress(path):
    """Decompress a MAM-wrapped prefetch via dissect.util (independent)."""
    with open(path, "rb") as f:
        blob = f.read()
    assert blob[:3] == b"MAM", "not MAM"
    size = struct.unpack_from("<I", blob, 4)[0]
    out = lzxpress_huffman.decompress(io.BytesIO(blob[8:]))
    return out[:size]


def windowsprefetch_v30(scca_bytes):
    """Drive windowsprefetch's own v30 field parsers on already-decompressed
    SCCA bytes (bypassing its Windows-only decompressor)."""
    with tempfile.NamedTemporaryFile(suffix=".scca", delete=False) as t:
        t.write(scca_bytes)
        t.flush()
        tmp = t.name
    # windowsprefetch only reaches its v30 sequence through the MAM path; invoke
    # the same sequence directly on the decompressed file.
    p = Prefetch.__new__(Prefetch)
    p.pFileName = tmp
    with open(tmp, "rb") as f:
        p.parseHeader(f)
        p.fileInformation26(f)
        p.metricsArray23(f)
        p.traceChainsArray30(f)
        p.volumeInformation30(f)
        p.getTimeStamps(p.lastRunTime)
        p.directoryStrings(f)
        p.getFilenameStrings(f)
    return p


def main():
    rust = {}
    with open(RUST_JSONL) as f:
        for line in f:
            o = json.loads(line)
            rust[o["file"]] = o

    all_ok = True
    rows = []
    for name in FILES:
        path = os.path.join(DATA, name)
        r = rust[name]

        # Oracle 1: independent decompressor, byte-for-byte.
        scca = dissect_decompress(path)
        rust_scca = open(os.path.join(SCCA_DIR, f"{name}.scca"), "rb").read()
        decompress_match = scca == rust_scca
        dissect_sha = hashlib.sha256(scca).hexdigest()[:16]
        rust_sha = hashlib.sha256(rust_scca).hexdigest()[:16]

        # Oracle 2: independent field parser.
        p = windowsprefetch_v30(scca)
        wp_exe = p.executableName.rstrip("\x00").strip()
        wp_runcount = p.runCount  # NB: pre-Win10-shift offset (known limitation)
        wp_files = [s for s in p.resources if s]
        wp_files_count = len(wp_files)
        wp_serial = int(p.volSerialNumber, 16) if isinstance(p.volSerialNumber, str) else p.volSerialNumber

        exe_match = wp_exe.upper() == r["executable"].upper()
        files_match = wp_files_count == r["filenames_count"]
        serial_match = bool(r["volumes"]) and wp_serial == r["volumes"][0]["serial"]
        ver_match = p.version == r["version"]

        # Run count: windowsprefetch reads the legacy offset and does NOT apply
        # the newer-Win10 8-byte counter shift, so it under-reports. prefetch-core
        # (like PECmd/EZ-Prefetch) applies the shift. Reported, not gated.
        rc_match = wp_runcount == r["run_count"]

        ok = decompress_match and exe_match and files_match and serial_match and ver_match
        all_ok = all_ok and ok
        rows.append(dict(
            name=name,
            decompress_match=decompress_match,
            dissect_sha=dissect_sha, rust_sha=rust_sha,
            scca_len_rust=r["scca_len"], scca_len_dissect=len(scca),
            exe_rust=r["executable"], exe_wp=wp_exe, exe_match=exe_match,
            rc_rust=r["run_count"], rc_wp=wp_runcount, rc_match=rc_match,
            files_rust=r["filenames_count"], files_wp=wp_files_count, files_match=files_match,
            serial_rust=r["volumes"][0]["serial"] if r["volumes"] else None,
            serial_wp=wp_serial, serial_match=bool(serial_match),
            ok=ok,
        ))

    print(json.dumps(rows, indent=2))
    print("\n=== SUMMARY ===")
    for row in rows:
        print(f"{row['name']:32s} decompress={'OK' if row['decompress_match'] else 'FAIL'} "
              f"exe={'OK' if row['exe_match'] else 'FAIL'} "
              f"runcount={'OK' if row['rc_match'] else 'FAIL'} "
              f"files={'OK' if row['files_match'] else 'FAIL'} "
              f"serial={'OK' if row['serial_match'] else 'FAIL'}")
    print(f"\nALL: {'PASS' if all_ok else 'FAIL'}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
