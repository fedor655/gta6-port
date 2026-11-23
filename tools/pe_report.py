#!/usr/bin/env python3
"""Derive structural facts from a PE image without external dependencies.

Usage:
    python -I tools/pe_report.py C:\\gta6\\EXE\\game_scarlett_master.exe --json reports/exe-facts.json

The report contains only derived facts (sizes, counts, names of imported
libraries and their functions, PDB path, section table). No code, data or
resources are copied out of the image.
"""

import argparse
import hashlib
import json
import struct
import sys

IMAGE_FILE_MACHINE = {
    0x014C: "i386",
    0x8664: "x86-64",
    0xAA64: "arm64",
    0x01C4: "armnt",
}
SUBSYSTEM = {
    0: "unknown", 1: "native", 2: "windows-gui", 3: "windows-cui",
    7: "posix-cui", 9: "windows-ce", 10: "efi-app",
}
DIRECTORY_NAMES = [
    "export", "import", "resource", "exception", "certificate",
    "basereloc", "debug", "architecture", "globalptr", "tls",
    "loadconfig", "boundimport", "iat", "delayimport", "clr", "reserved",
]
SECTION_FLAGS = [
    (0x00000020, "code"), (0x00000040, "initialized-data"),
    (0x00000080, "uninitialized-data"), (0x02000000, "discardable"),
    (0x04000000, "not-cached"), (0x08000000, "not-paged"),
    (0x10000000, "shared"), (0x20000000, "executable"),
    (0x40000000, "readable"), (0x80000000, "writable"),
]
RELOC_TYPES = {0: "absolute", 1: "high", 2: "low", 3: "highlow", 4: "highadj",
               5: "mips-jump", 7: "thumb-mov32", 8: "mips-jump16", 9: "mips-jump16",
               10: "dir64"}


class PE:
    def __init__(self, data):
        self.data = data
        self.dos = self._dos_header()
        self.pe_off = self.dos["e_lfanew"]
        self._file_header()
        self._optional_header()
        self._sections()
        self._rich_header()

    # -- headers ---------------------------------------------------------
    def _dos_header(self):
        d = self.data
        if d[:2] != b"MZ":
            raise ValueError("not an MZ image")
        (e_lfanew,) = struct.unpack_from("<I", d, 0x3C)
        return {
            "magic": "MZ",
            "e_lfanew": e_lfanew,
            "dos_stub_bytes": e_lfanew - 0x40,
            "dos_stub_head": d[0x40:min(e_lfanew, 0x40 + 64)].decode("latin-1", "replace"),
        }

    def _file_header(self):
        d = self.data
        off = self.pe_off
        if d[off:off + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        (machine, nsec, timestamp, _, _, opt_size,
         characteristics) = struct.unpack_from("<HHIIIHH", d, off + 4)
        self.machine = machine
        self.nsec = nsec
        self.timestamp = timestamp
        self.opt_size = opt_size
        self.characteristics = characteristics
        self.file_header = {
            "machine": IMAGE_FILE_MACHINE.get(machine, hex(machine)),
            "machine_id": hex(machine),
            "number_of_sections": nsec,
            "timestamp": timestamp,
            "optional_header_size": opt_size,
            "characteristics": hex(characteristics),
            "is_dll": bool(characteristics & 0x2000),
            "is_system": bool(characteristics & 0x1000),
            "is_executable_image": bool(characteristics & 0x0002),
            "large_address_aware": bool(characteristics & 0x0020),
        }

    def _optional_header(self):
        d = self.data
        off = self.pe_off + 24
        magic = struct.unpack_from("<H", d, off)[0]
        if magic == 0x10B:
            fmt = "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII"
        elif magic == 0x20B:
            fmt = "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"
        else:
            raise ValueError(f"unknown optional header magic {magic:#x}")
        vals = struct.unpack_from(fmt, d, off)
        names = ["magic", "major_linker", "minor_linker", "code_size",
                 "initialized_data_size", "uninitialized_data_size",
                 "entry_point", "base_of_code"]
        i = 0
        opt = {}
        for n in names:
            opt[n] = vals[i]
            i += 1
        if magic == 0x20B:
            opt["image_base"] = vals[i]
            i += 1
        else:
            opt["image_base"] = vals[i]
            i += 1
        for n in ["section_alignment", "file_alignment", "major_os",
                  "minor_os", "major_image", "minor_image", "major_subsystem",
                  "minor_subsystem", "win32_version", "size_of_image",
                  "size_of_headers", "checksum", "subsystem",
                  "dll_characteristics", "size_of_stack_reserve",
                  "size_of_stack_commit", "size_of_heap_reserve",
                  "size_of_heap_commit", "loader_flags", "number_of_dirs"]:
            opt[n] = vals[i]
            i += 1
        opt["magic"] = hex(magic)
        opt["subsystem"] = SUBSYSTEM.get(opt["subsystem"], opt["subsystem"])
        opt["dll_characteristics"] = hex(opt["dll_characteristics"])
        dirs = []
        dd_off = off + (0x70 if magic == 0x20B else 0x60)
        for k in range(min(opt["number_of_dirs"], 16)):
            va, size = struct.unpack_from("<II", d, dd_off + 8 * k)
            dirs.append({"name": DIRECTORY_NAMES[k], "rva": va, "size": size})
        self.opt = opt
        self.dirs = dirs
        self.dd_off = dd_off
        self.opt_off = off

    def _sections(self):
        d = self.data
        off = self.opt_off + self.opt_size
        raw = []
        for k in range(self.nsec):
            name, vsize, va, rsize, rptr, _, _, _, _, chars = \
                struct.unpack_from("<8sIIIIIIHHI", d, off + 40 * k)
            flags = [label for bit, label in SECTION_FLAGS if chars & bit]
            raw.append({
                "name": name.rstrip(b"\0").decode("latin-1"),
                "rva": va,
                "virtual_size": vsize,
                "raw_pointer": rptr,
                "raw_size": rsize,
                "characteristics": hex(chars),
                "flags": flags,
                "entropy_hint": "n/a",
            })
        self.sections = raw

    def _rich_header(self):
        d = self.data
        end = self.dos["e_lfanew"]
        idx = d.rfind(b"Rich", 0, end)
        if idx < 0:
            self.rich = None
            return
        (key,) = struct.unpack_from("<I", d, idx + 4)
        start = d.rfind(b"DanS", 0, idx)
        entries = []
        if start >= 0:
            p = start + 16
            while p + 8 <= idx:
                compid, count = struct.unpack_from("<II", d, p)
                compid ^= key
                count ^= key
                entries.append({
                    "product_id": compid >> 16,
                    "build": compid & 0xFFFF,
                    "count": count,
                })
                p += 8
        self.rich = {"key": f"{key:#010x}", "entries": entries,
                     "checksum": f"{idx and struct.unpack_from('<I', d, idx + 8)[0]:#010x}"}

    # -- rva helpers -----------------------------------------------------
    def rva_to_off(self, rva):
        for s in self.sections:
            if s["rva"] <= rva < s["rva"] + max(s["virtual_size"], s["raw_size"]):
                return s["raw_pointer"] + (rva - s["rva"])
        return None

    def cstr(self, rva):
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.data.find(b"\0", off)
        if end < 0:
            return None
        return self.data[off:end].decode("latin-1", "replace")

    def dir(self, name):
        for entry in self.dirs:
            if entry["name"] == name:
                return entry
        return {"rva": 0, "size": 0}

    # -- directories -----------------------------------------------------
    def imports(self):
        out = []
        ent = self.dir("import")
        if not ent["rva"]:
            return out
        off = self.rva_to_off(ent["rva"])
        while True:
            ilt, ts, fwd, name_rva, iat = struct.unpack_from("<IIIII", self.data, off)
            if not (ilt or name_rva or iat):
                break
            dll = self.cstr(name_rva) or "?"
            funcs = []
            thunk_rva = ilt or iat
            toff = self.rva_to_off(thunk_rva)
            while toff is not None:
                (val,) = struct.unpack_from("<Q", self.data, toff)
                if val == 0:
                    break
                if val & (1 << 63):
                    funcs.append({"ordinal": val & 0xFFFF})
                else:
                    fo = self.rva_to_off(val & 0x7FFFFFFF)
                    if fo is not None:
                        (hint,) = struct.unpack_from("<H", self.data, fo)
                        fname = self.cstr((val & 0x7FFFFFFF) + 2) or "?"
                        funcs.append({"name": fname, "hint": hint})
                toff += 8
            out.append({
                "dll": dll,
                "timestamp": ts,
                "iat_rva": iat,
                "functions": funcs,
                "function_count": len(funcs),
            })
            off += 20
        return out

    def delay_imports(self):
        out = []
        ent = self.dir("delayimport")
        if not ent["rva"]:
            return out
        off = self.rva_to_off(ent["rva"])
        while True:
            attrs, name_rva, _, iat, int_rva, _, _ = struct.unpack_from("<IIIIIII", self.data, off)
            if not (name_rva or iat or int_rva):
                break
            out.append({
                "dll": self.cstr(name_rva) or "?",
                "attributes": hex(attrs),
                "iat_rva": iat,
                "int_rva": int_rva,
            })
            off += 32
        return out

    def exports(self):
        ent = self.dir("export")
        if not ent["rva"]:
            return {"count": 0, "names": []}
        off = self.rva_to_off(ent["rva"])
        _, _, _, _, _, base, nfuncs, nnames, aof, aon, aoord = \
            struct.unpack_from("<IIHHIIIIIII", self.data, off)
        names = []
        noff = self.rva_to_off(aon)
        for k in range(min(nnames, 64)):
            (nrva,) = struct.unpack_from("<I", self.data, noff + 4 * k)
            names.append(self.cstr(nrva))
        return {"count": nfuncs, "base": base, "names": names[:64]}

    def exceptions(self):
        ent = self.dir("exception")
        count = ent["size"] // 12 if ent["size"] else 0
        first = []
        if ent["rva"] and count:
            off = self.rva_to_off(ent["rva"])
            for k in range(min(count, 5)):
                begin, end, unwind = struct.unpack_from("<III", self.data, off + 12 * k)
                first.append({"begin": hex(begin), "end": hex(end), "unwind": hex(unwind)})
        return {"table_rva": hex(ent["rva"]), "bytes": ent["size"],
                "runtime_functions": count, "first": first}

    def relocations(self):
        ent = self.dir("basereloc")
        blocks = 0
        by_type = {}
        if ent["rva"] and ent["size"]:
            off = self.rva_to_off(ent["rva"])
            end = off + ent["size"]
            p = off
            while p + 8 <= end:
                page, block_size = struct.unpack_from("<II", self.data, p)
                if block_size < 8:
                    break
                blocks += 1
                n = (block_size - 8) // 2
                for k in range(n):
                    (entry,) = struct.unpack_from("<H", self.data, p + 8 + 2 * k)
                    t = entry >> 12
                    by_type[t] = by_type.get(t, 0) + 1
                p += block_size
        named = {RELOC_TYPES.get(k, str(k)): v for k, v in by_type.items()}
        return {"blocks": blocks, "entries": sum(by_type.values()), "by_type": named}

    def debug(self):
        ent = self.dir("debug")
        out = []
        if ent["rva"] and ent["size"]:
            off = self.rva_to_off(ent["rva"])
            n = ent["size"] // 28
            for k in range(n):
                (chars, ts, maj, minr, typ, size, addr, ptr) = \
                    struct.unpack_from("<IIHHIIII", self.data, off + 28 * k)
                item = {"type": typ, "timestamp": ts,
                        "major": maj, "minor": minr, "size": size}
                if typ == 2 and ptr:
                    sig = self.data[ptr:ptr + 4]
                    if sig == b"RSDS":
                        (guid1, guid2, guid3) = struct.unpack_from("<IHH", self.data, ptr + 4)
                        guid4 = self.data[ptr + 12:ptr + 20]
                        (age,) = struct.unpack_from("<I", self.data, ptr + 20)
                        item["guid"] = "%08X-%04X-%04X-%s" % (
                            guid1, guid2, guid3, guid4.hex().upper())
                        item["age"] = age
                        item["pdb_path"] = self.cstr_bytes(self.data, ptr + 24)
                    elif sig == b"NB10":
                        item["pdb_path"] = self.cstr_bytes(self.data, ptr + 16)
                out.append(item)
        return out

    @staticmethod
    def cstr_bytes(data, off):
        end = data.find(b"\0", off)
        return data[off:end].decode("latin-1", "replace") if end >= 0 else None

    def tls(self):
        ent = self.dir("tls")
        if not ent["rva"]:
            return None
        off = self.rva_to_off(ent["rva"])
        start, end, index, callbacks = struct.unpack_from("<QQQI", self.data, off)
        ncb = 0
        if callbacks:
            cboff = self.rva_to_off(callbacks - self.opt["image_base"])
            while cboff is not None:
                (cb,) = struct.unpack_from("<Q", self.data, cboff + 8 * ncb)
                if not cb:
                    break
                ncb += 1
        return {"start_va": hex(start), "end_va": hex(end), "index_addr": hex(index),
                "callbacks": ncb}

    def load_config(self):
        ent = self.dir("loadconfig")
        if not ent["rva"]:
            return None
        size = ent["size"]
        off = self.rva_to_off(ent["rva"])
        raw = self.data[off:off + min(size, 0x140)]
        out = {"size": size}
        if size >= 0x70:
            (sec_count,) = struct.unpack_from("<I", raw, 0x44)
            (guard_flags,) = struct.unpack_from("<H", raw, 0x46)
            (guard_cf,) = struct.unpack_from("<I", raw, 0x48)
            out.update({"security_cookie": hex(struct.unpack_from("<Q", raw, 0x58)[0]),
                        "se_handler_count": sec_count,
                        "guard_flags": hex(guard_flags),
                        "guard_cf_check": bool(guard_cf)})
        return out

    def resources(self):
        ent = self.dir("resource")
        if not ent["rva"]:
            return {"types": 0, "entries": 0}
        base = ent["rva"]
        off = self.rva_to_off(base)
        types = 0
        entries = 0

        def walk(node_rva, level, root):
            nonlocal types, entries
            noff = self.rva_to_off(node_rva)
            named, ids = struct.unpack_from("<HH", self.data, noff)
            n = named + ids
            for k in range(n):
                name, target = struct.unpack_from("<II", self.data, noff + 16 + 8 * k)
                if target & 0x80000000:
                    walk(base + (target & 0x7FFFFFFF), level + 1, root)
                elif level == 0:
                    entries += 1

        named, ids = struct.unpack_from("<HH", self.data, off)
        types = named + ids
        for k in range(types):
            _, target = struct.unpack_from("<II", self.data, off + 16 + 8 * k)
            if target & 0x80000000:
                entries += 1
        return {"types": types, "entries": entries}

    def scan_ascii(self, min_len=4):
        data = self.data
        run = 0
        count = 0
        total = 0
        best = 0
        for byte in data:
            if 32 <= byte < 127:
                run += 1
            else:
                if run >= min_len:
                    count += 1
                    total += run
                    best = max(best, run)
                run = 0
        return {"strings_min_%d" % min_len: count, "bytes_in_strings": total,
                "longest": best}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("exe")
    ap.add_argument("--json", metavar="PATH", help="write the report as JSON")
    ap.add_argument("--imports", action="store_true", help="list every imported function")
    args = ap.parse_args(argv)

    with open(args.exe, "rb") as f:
        data = f.read()
    pe = PE(data)

    sha = hashlib.sha256(data).hexdigest()
    imports = pe.imports()
    report = {
        "file": {
            "name": args.exe.replace("\\", "/").rsplit("/", 1)[-1],
            "size": len(data),
            "sha256": sha,
        },
        "dos": pe.dos,
        "file_header": pe.file_header,
        "optional_header": pe.opt,
        "sections": pe.sections,
        "directories": pe.dirs,
        "rich_header": pe.rich,
        "exports": pe.exports(),
        "imports": imports,
        "delay_imports": pe.delay_imports(),
        "exception": pe.exceptions(),
        "relocations": pe.relocations(),
        "debug": pe.debug(),
        "tls": pe.tls(),
        "load_config": pe.load_config(),
        "resources": pe.resources(),
        "strings": pe.scan_ascii(),
        "summary": {
            "imported_dlls": len(imports),
            "imported_functions": sum(i["function_count"] for i in imports),
            "runtime_functions": (pe.exceptions()["runtime_functions"]),
        },
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=1, ensure_ascii=False)
            f.write("\n")

    print(f"file        {report['file']['name']}  {len(data)} bytes")
    print(f"sha256      {sha}")
    print(f"machine     {report['file_header']['machine']}  "
          f"sections={pe.nsec}  subsystem={pe.opt['subsystem']}")
    print(f"image       {pe.opt['size_of_image']} bytes  "
          f"image_base={pe.opt['image_base']:#x}  entry={pe.opt['entry_point']:#x}")
    print(f"imports     {report['summary']['imported_dlls']} DLLs, "
          f"{report['summary']['imported_functions']} functions")
    for imp in imports:
        print(f"  {imp['dll']:<44} {imp['function_count']:>5}")
        if args.imports:
            for fn in imp["functions"]:
                name = fn.get("name") or f"#{fn['ordinal']}"
                print(f"      {name}")
    exc = report["exception"]
    print(f"functions   {exc['runtime_functions']} .pdata runtime functions "
          f"({exc['bytes']} bytes)")
    rel = report["relocations"]
    print(f"relocs      {rel['blocks']} blocks, {rel['entries']} entries {rel['by_type']}")
    print(f"strings     {report['strings']['strings_min_4']} (longest {report['strings']['longest']})")
    for dbg in report["debug"]:
        print(f"debug       type={dbg['type']} {dbg.get('pdb_path')}")
    if args.json:
        print(f"json        {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
