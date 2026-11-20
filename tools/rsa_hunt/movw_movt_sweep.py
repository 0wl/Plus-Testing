#!/usr/bin/env python3
"""
Strings in SWAP ELF are built with MOVW/MOVT immediate pairs (PIC-style).
Sweep .text with Capstone, track per-register last MOVW/MOVT, flag any
register that now holds one of our target string VAs.
"""
import struct, os, capstone, collections

ELF = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..",
      "extracted", "swap", "tsd", "bin", "swap", "tsd.mibstd2.system.swap"))

TARGETS = {
    0x0017c044: "RSA calculation failed",
    0x0017a88f: "signature is invalid",
    0x0017a8a4: "signature is valid",
    0x0017c2be: "no signature section found in elf file",
    0x0017c361: "SHA-1 hash algorithm not supported by now",
    0x001099f1: "skip_signature_check_flag",
    0x0017e5b1: "Skip signature check: ",
    0x0017a84e: "checking signature of FEC, using",
    0x0017ccfc: "EscSha1_ApplyPadding",
    0x0017cc84: "EscRsaFe_FromLongFe",
    0x0017cc07: "ext.cryptolib/lib/src/rsa.c",
}


def parse_elf(buf):
    assert buf[:4] == b"\x7fELF"
    e_phoff = struct.unpack_from("<I", buf, 0x1c)[0]
    e_phentsz = struct.unpack_from("<H", buf, 0x2a)[0]
    e_phnum = struct.unpack_from("<H", buf, 0x2c)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsz
        p_type, p_offset, p_vaddr, _, p_filesz, _, p_flags, _ = \
            struct.unpack_from("<IIIIIIII", buf, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz, p_flags))
    return segs


def sweep(buf, segs):
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    md.detail = True
    text_segs = [(v, o, s) for v, o, s, f in segs if f & 1]
    hits = []
    for va, off, sz in text_segs:
        data = buf[off:off+sz]
        regs = {}  # reg -> (low16, high16)
        for insn in md.disasm(data, va):
            if insn.mnemonic.startswith("movw"):
                # format: movw rN, #imm
                ops = insn.op_str.split(",")
                if len(ops) == 2 and ops[1].strip().startswith("#"):
                    rd = ops[0].strip()
                    try:
                        imm = int(ops[1].strip().lstrip("#"), 0)
                    except ValueError:
                        continue
                    regs[rd] = (imm, 0)
            elif insn.mnemonic.startswith("movt"):
                ops = insn.op_str.split(",")
                if len(ops) == 2 and ops[1].strip().startswith("#"):
                    rd = ops[0].strip()
                    try:
                        imm_hi = int(ops[1].strip().lstrip("#"), 0)
                    except ValueError:
                        continue
                    lo, _ = regs.get(rd, (0, 0))
                    full = (imm_hi << 16) | lo
                    if full in TARGETS:
                        hits.append((insn.address, rd, full))
                    regs[rd] = (lo, imm_hi)
    return hits


def main():
    buf = open(ELF, "rb").read()
    segs = parse_elf(buf)
    hits = sweep(buf, segs)
    by_va = collections.defaultdict(list)
    for addr, rd, val in hits:
        by_va[val].append((addr, rd))
    for val, label in TARGETS.items():
        lst = by_va.get(val, [])
        if not lst:
            print(f"[-] no MOVW/MOVT pair reaches 0x{val:08x} ({label})")
            continue
        print(f"[+] 0x{val:08x} ({label}) reached from {len(lst)} site(s):")
        for addr, rd in lst[:5]:
            print(f"      MOVT {rd} completes @ PC 0x{addr:08x}")


if __name__ == "__main__":
    main()
