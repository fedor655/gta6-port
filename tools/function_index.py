#!/usr/bin/env python3
"""Build a function index from the PE exception directory (.pdata).

Every RUNTIME_FUNCTION is 12 bytes: begin RVA, end RVA, unwind-info RVA.
On x64 unwind-info is either an .xdata RVA (low bit 0) or a chained
UNWIND_INFO in .pdata itself (low bit 1).

Usage:
    python -I tools/function_index.py C:\\gta6\\EXE\\game_scarlett_master.exe --json reports/functions.json
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_report import PE


def unwind_flags(pe, unwind_rva):
    """Decode the first UNWIND_INFO byte when it lives in .xdata."""
    if unwind_rva & 1:
        return {"chained": True}
    off = pe.rva_to_off(unwind_rva)
    if off is None or off + 4 > len(pe.data):
        return {}
    version_flags, prolog_size, count_codes, frame = struct.unpack_from("<BBBB", pe.data, off)
    return {
        "version": version_flags & 0x7,
        "flags": version_flags >> 3,
        "handler": bool(version_flags & 0x4),
        "uhandler": bool(version_flags & 0x8),
        "prolog_size": prolog_size,
        "count_codes": count_codes,
        "frame_register": frame & 0xF,
        "frame_offset": (frame >> 4) * 16,
    }


def hotness_hint(pe, begin, end):
    """Cheap proxy for how likely a function is code rather than a thunk."""
    size = end - begin
    if size <= 16:
        return "thunk"
    if size <= 64:
        return "small"
    return "body"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("exe")
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--limit", type=int, default=0, help="only keep N functions")
    ap.add_argument("--stats", action="store_true", help="print histogram only")
    args = ap.parse_args(argv)

    with open(args.exe, "rb") as f:
        data = f.read()
    pe = PE(data)
    ent = pe.dir("exception")
    off = pe.rva_to_off(ent["rva"])
    count = ent["size"] // 12
    funcs = []
    total_bytes = 0
    hist = {"thunk": 0, "small": 0, "body": 0}
    histogram = {}
    prev_end = None
    overlaps = 0
    nonmonotonic = 0
    for k in range(count):
        begin, end, unwind = struct.unpack_from("<III", data, off + 12 * k)
        if end <= begin:
            nonmonotonic += 1
        if prev_end is not None and begin < prev_end:
            overlaps += 1
        prev_end = end
        size = end - begin
        total_bytes += size
        hint = hotness_hint(pe, begin, end)
        hist[hint] += 1
        bucket = (size // 64) * 64
        histogram[bucket] = histogram.get(bucket, 0) + 1
        if len(funcs) < args.limit or not args.limit:
            funcs.append({
                "index": k,
                "rva": begin,
                "end": end,
                "size": size,
                "unwind_rva": unwind,
                "kind": hint,
            })

    report = {
        "table": {"rva": ent["rva"], "bytes": ent["size"]},
        "count": count,
        "total_code_bytes": total_bytes,
        "overlaps": overlaps,
        "nonmonotonic": nonmonotonic,
        "kinds": hist,
        "size_histogram_64b": {str(k): v for k, v in sorted(histogram.items())},
        "functions": funcs,
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1)
            f.write("\n")

    print(f"functions   {count}  ({total_bytes} bytes of code)")
    print(f"kinds       {hist}")
    print(f"overlaps    {overlaps}   non-monotonic {nonmonotonic}")
    print(f"largest     {max(histogram)}-byte bucket: {histogram[max(histogram)]} functions")
    if args.json:
        print(f"json        {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
