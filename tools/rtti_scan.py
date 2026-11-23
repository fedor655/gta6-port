#!/usr/bin/env python3
"""Recover the MSVC RTTI class map (names, hierarchy, vftables) from a PE image.

Structures (x64, /GR):
  TypeDescriptor         { void *vfptr; void *spare; char name[]; }
  CompleteObjectLocator  { u32 signature=1; u32 offset; u32 cdOffset;
                           u32 pTypeDescriptor; u32 pClassDescriptor; u32 pSelf; }
  ClassHierarchyDescriptor { u32 signature=1; u32 attributes;
                             u32 numBaseClasses; u32 pBaseClassArray; }
  BaseClassArray         { u32 pBaseClassDescriptor[]; terminated by 0; }
  BaseClassDescriptor    { u32 pTypeDescriptor; u32 numContainedBases;
                           int mdisp, pdisp, vdisp; u32 attributes;
                           u32 pClassDescriptor; }

Usage:
    python -I tools/rtti_scan.py C:\\gta6\\EXE\\game_scarlett_master.exe --json reports/rtti.json
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_report import PE

TD_MAGIC = (b".?AV", b".?AU", b".?AW")


def demangle_msvc(name):
    """Turn '.?AVCFoo@Bar@@' into 'Bar::CFoo' (best effort, no templates)."""
    if not name.startswith(".?A"):
        return name
    body = name[3:]
    if body.startswith("V"):
        body = body[1:]
    parts = []
    for token in body.split("@"):
        if not token:
            break
        parts.append(token)
    parts.reverse()
    return "::".join(parts) if parts else name


def file_off_to_rva(pe, off):
    for s in pe.sections:
        if s["raw_pointer"] <= off < s["raw_pointer"] + s["raw_size"]:
            return s["rva"] + (off - s["raw_pointer"])
    return None


def scan_type_descriptors(pe):
    data = pe.data
    out = {}
    image_end = pe.opt["image_base"] + pe.opt["size_of_image"]
    for sec in pe.sections:
        lo = sec["raw_pointer"]
        hi = lo + sec["raw_size"]
        for magic in TD_MAGIC:
            pos = data.find(magic, lo, hi)
            while pos >= 0:
                td_off = pos - 16
                end = data.find(b"\0", pos)
                if end < 0 or end - pos > 4096:
                    pos = data.find(magic, pos + 1, hi)
                    continue
                name = data[pos:end].decode("latin-1", "replace")
                if td_off >= lo:
                    (vfptr, spare) = struct.unpack_from("<QQ", data, td_off)
                    rva = file_off_to_rva(pe, td_off)
                    if (rva is not None and len(name) > 4 and
                            pe.opt["image_base"] <= vfptr < image_end):
                        out[rva] = {"name": name, "demangled": demangle_msvc(name),
                                    "td_rva": rva, "vfptr": vfptr}
                pos = data.find(magic, pos + 1, hi)
    return out


def read_class_hierarchy(pe, rva):
    off = pe.rva_to_off(rva)
    if off is None:
        return None
    sig, attrs, nbase, array_rva = struct.unpack_from("<IIII", pe.data, off)
    if sig != 1:
        return None
    bases = []
    aoff = pe.rva_to_off(array_rva)
    if aoff is None:
        return {"attributes": attrs, "base_count": nbase, "bases": bases}
    for k in range(min(nbase, 64)):
        (bcd_rva,) = struct.unpack_from("<I", pe.data, aoff + 4 * k)
        if not bcd_rva:
            break
        boff = pe.rva_to_off(bcd_rva)
        if boff is None:
            break
        td_rva, ncont, mdisp, pdisp, vdisp, battrs, chd_rva = \
            struct.unpack_from("<IIiiiII", pe.data, boff)
        bases.append({"td_rva": td_rva, "num_contained": ncont,
                      "mdisp": mdisp, "pdisp": pdisp, "vdisp": vdisp,
                      "attributes": battrs})
    return {"attributes": attrs, "base_count": nbase, "bases": bases}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("exe")
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--list", action="store_true", help="print every class")
    args = ap.parse_args(argv)

    with open(args.exe, "rb") as f:
        data = f.read()
    pe = PE(data)
    tds = scan_type_descriptors(pe)
    print(f"type descriptors   {len(tds)}")

    # Complete object locators: self-referencing 24-byte records.
    locators = []
    cols_by_class = {}
    seen = set()
    for sec in pe.sections:
        lo = sec["raw_pointer"]
        hi = lo + sec["raw_size"]
        for p in range(lo, hi - 24, 4):
            sig, offset, cd, td_rva, chd_rva, pself = struct.unpack_from("<IIIIII", data, p)
            if sig != 1 or offset != 0 or cd != 0:
                continue
            rva = sec["rva"] + (p - lo)
            if pself != rva or td_rva not in tds:
                continue
            if rva in seen:
                continue
            seen.add(rva)
            entry = {"col_rva": rva, "td_rva": td_rva, "chd_rva": chd_rva,
                     "name": tds[td_rva]["demangled"], "mangled": tds[td_rva]["name"]}
            locators.append(entry)
            cols_by_class.setdefault(td_rva, []).append(rva)
    print(f"object locators    {len(locators)}")

    # Hierarchy: only for classes with a locator (cheap, avoids garbage).
    classes = []
    for entry in locators:
        chd = read_class_hierarchy(pe, entry["chd_rva"])
        base_names = [tds[b["td_rva"]]["demangled"] for b in (chd or {}).get("bases", [])
                      if b["td_rva"] in tds and b["num_contained"] == 0]
        classes.append({
            "name": entry["name"],
            "mangled": entry["mangled"],
            "td_rva": entry["td_rva"],
            "col_rva": entry["col_rva"],
            "vftables": [hex(pe.opt["image_base"] + r) for r in cols_by_class[entry["td_rva"]]],
            "base_count": (chd or {}).get("base_count", 0),
            "direct_bases": sorted(set(n for n in base_names if n != entry["name"])),
        })

    roots = [c for c in classes if not c["direct_bases"]]
    report = {
        "type_descriptors": len(tds),
        "locators": len(locators),
        "classes": len(classes),
        "roots": len(roots),
        "names_sample": sorted(c["name"] for c in classes)[:20],
        "classes_data": sorted(classes, key=lambda c: c["name"]),
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
            f.write("\n")

    print(f"classes            {len(classes)} ({len(roots)} without a base)")
    for c in sorted(classes, key=lambda c: -len(c["vftables"]))[:10]:
        print(f"  {len(c['vftables']):>4} vft  {c['name']}")
    if args.list:
        for c in sorted(classes, key=lambda c: c["name"]):
            print(c["name"])
    if args.json:
        print(f"json               {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
