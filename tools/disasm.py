#!/usr/bin/env python3
"""Disassemble a window of code around an RVA of the game executable.

    python -I tools/disasm.py <exe> 0x55DC7F4 --count 40
    python -I tools/disasm.py <exe> 0x56A1EC8 --bytes 96 --no-colour

Needs `capstone` (pip install capstone); it is analysis-only, nothing is
written into the repository.
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_report import PE


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("exe")
    ap.add_argument("rva", help="start RVA, decimal or 0x-prefixed hex")
    ap.add_argument("--count", type=int, default=30, help="instructions to show")
    ap.add_argument("--bytes", type=int, default=0, help="exact byte window instead")
    args = ap.parse_args(argv)

    with open(args.exe, "rb") as f:
        data = f.read()
    pe = PE(data)
    rva = int(args.rva, 0)
    off = pe.rva_to_off(rva)
    if off is None:
        print("rva not mapped to file")
        return 1
    try:
        import capstone
    except ImportError:
        print("pip install capstone")
        return 1
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    window = data[off:off + (args.bytes or args.count * 8 + 64)]
    printed = 0
    for insn in md.disasm(window, pe.opt["image_base"] + rva):
        target = ""
        if insn.operands and insn.operands[-1].type == capstone.x86.X86_OP_IMM:
            imm = insn.operands[-1].imm
            if pe.opt["image_base"] <= imm < pe.opt["image_base"] + pe.opt["size_of_image"]:
                target = "  ; -> rva 0x%X" % (imm - pe.opt["image_base"])
        if insn.mnemonic in ("call", "jmp") and insn.operands:
            target = target or "  ; -> 0x%X" % insn.operands[0].imm
        print("%016X  %-24s %-8s %s%s" % (insn.address, insn.bytes.hex(), insn.mnemonic,
                                          insn.op_str, target))
        printed += 1
        if args.bytes and insn.address - (pe.opt["image_base"] + rva) >= args.bytes:
            break
        if not args.bytes and printed >= args.count:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
